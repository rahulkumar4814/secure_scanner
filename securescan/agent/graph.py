"""LangGraph agent that orchestrates the whole scan.

    prepare_source -> detect_languages -> run_scanners -> normalize -> prioritize
        -> retrieve_policy -> recommend_fixes -> build_report --(pending Critical/High & interactive)--> human_approval
                                                    ^                                                      |
                                                    +------------------------------------------------------+
Human-in-the-loop uses LangGraph `interrupt()`; state is checkpointed in SQLite, so a scan can wait for
approval across server restarts and is resumed with `Command(resume=decisions)`.
"""
from __future__ import annotations

import json
import logging
import shutil
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, TypedDict

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from .. import store
from ..config import get_settings
from ..llm import FixAdvisor
from ..models import Finding, ScanRequest, Severity
from ..normalizer import normalize as normalize_outputs
from ..prioritizer import prioritize as prioritize_findings
from ..prioritizer import summarize
from ..rag import get_policy_store
from ..reports import write_reports
from ..scanners import ScanOutput, detect_languages as detect_langs, run_all
from ..security import check_repo_limits, redact, run_tool, validate_git_url, validate_local_path

log = logging.getLogger("securescan.agent")
APPROVAL_LEVELS = {Severity.CRITICAL.value, Severity.HIGH.value}


class ScanState(TypedDict, total=False):
    scan_id: str
    request: dict
    interactive: bool          # False in CI: no human available, approvals stay pending
    actor: str
    workdir: str
    cleanup: bool
    languages: list[str]
    tools: list[dict]          # tool name, status, duration, error (raw output is stored on disk)
    findings: list[dict]
    policy_context: dict       # finding id -> policy excerpts
    rag_mode: str
    model: str
    summary: dict
    approval_log: list[dict]
    reports: dict
    errors: list[str]


def _progress(state: ScanState, step: str, status: str = "running") -> None:
    store.write_meta(state["scan_id"], status=status, step=step)


def _findings(state: ScanState) -> list[Finding]:
    return [Finding.model_validate(f) for f in state.get("findings", [])]


def _dump(findings: list[Finding]) -> list[dict]:
    return [f.model_dump(mode="json") for f in findings]


def _remove_tree(path: Path) -> None:
    """Delete a cloned repo. git marks pack files read-only, which breaks rmtree on Windows."""
    import os
    import stat

    def _retry(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)

    if path.exists():
        if sys.version_info >= (3, 12):
            shutil.rmtree(path, onexc=_retry)
        else:
            shutil.rmtree(path, onerror=_retry)


# ------------------------------------------------------------------------ nodes
def prepare_source(state: ScanState) -> dict:
    _progress(state, "prepare_source")
    req = ScanRequest.model_validate(state["request"])
    if req.source_type == "local":
        path = validate_local_path(req.target)
        return {"workdir": str(path), "cleanup": False}
    url = validate_git_url(req.target)
    work = Path(tempfile.mkdtemp(prefix=f"ss_{state['scan_id'][:8]}_", dir=get_settings().data_dir))
    args = ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never",
            "-c", "core.symlinks=false", "clone", "--depth", "1", "--no-recurse-submodules", "--single-branch"]
    if req.git_ref:
        args += ["--branch", req.git_ref]
    args += ["--", url, str(work / "repo")]
    res = run_tool(args, timeout=300)
    if res.returncode != 0:
        _remove_tree(work)
        raise RuntimeError(f"git clone failed: {redact(res.stderr.strip())[-300:]}")
    check_repo_limits(work / "repo")
    return {"workdir": str(work / "repo"), "cleanup": True}


def detect_languages(state: ScanState) -> dict:
    _progress(state, "detect_languages")
    langs = sorted(detect_langs(Path(state["workdir"])))
    return {"languages": langs}


def run_scanners(state: ScanState) -> dict:
    _progress(state, "run_scanners")
    outputs = run_all(Path(state["workdir"]), set(state["languages"]))
    raw_dir = store.scan_dir(state["scan_id"]) / "raw"
    raw_dir.mkdir(exist_ok=True)
    tools = []
    for o in outputs:
        status = "skipped" if o.skipped else ("error" if o.error and o.raw is None else "ok")
        if o.raw is not None:
            (raw_dir / f"{o.tool}.json").write_text(redact(json.dumps(o.raw)), encoding="utf-8")
        tools.append({"tool": o.tool, "status": status, "duration": round(o.duration, 1),
                      "error": redact(o.error)[:500], "meta": o.meta})
    return {"tools": tools}


def normalize(state: ScanState) -> dict:
    _progress(state, "normalize")
    raw_dir = store.scan_dir(state["scan_id"]) / "raw"
    outputs = []
    for t in state["tools"]:
        p = raw_dir / f"{t['tool']}.json"
        if p.exists():
            outputs.append(ScanOutput(t["tool"], json.loads(p.read_text(encoding="utf-8"))))
    try:
        findings = normalize_outputs(outputs, Path(state["workdir"]))
    finally:
        if state.get("cleanup"):  # snippets are captured; remove the cloned repo
            _remove_tree(Path(state["workdir"]).parent)
    return {"findings": _dump(findings)}


def prioritize(state: ScanState) -> dict:
    _progress(state, "prioritize")
    findings = prioritize_findings(_findings(state))
    return {"findings": _dump(findings), "summary": summarize(findings)}


def _needs_fix(f: Finding, rank: int) -> bool:
    return f.priority.value in APPROVAL_LEVELS or rank < get_settings().llm_max_findings


def retrieve_policy(state: ScanState) -> dict:
    _progress(state, "retrieve_policy")
    ps = get_policy_store()
    ctx = {}
    for i, f in enumerate(_findings(state)):
        if _needs_fix(f, i):
            ctx[f.id] = [{"section": d.metadata.get("section"), "text": d.page_content} for d in ps.retrieve(f)]
    return {"policy_context": ctx, "rag_mode": ps.mode}


def recommend_fixes(state: ScanState) -> dict:
    _progress(state, "recommend_fixes")
    from langchain_core.documents import Document

    advisor = FixAdvisor(state.get("model") or None)
    limit = get_settings().llm_max_findings
    findings = _findings(state)
    llm_calls = 0
    for i, f in enumerate(findings):
        if not _needs_fix(f, i):
            continue
        docs = [Document(page_content=d["text"], metadata={"section": d["section"]})
                for d in state["policy_context"].get(f.id, [])]
        # The LLM writes code fixes (SAST / secrets). Dependency upgrades are factual (fixed version comes from
        # the advisory), so they use the deterministic recommender - faster and no risk of a hallucinated version.
        if f.category != "SCA" and llm_calls < limit:
            fix = advisor.recommend(f, docs)
            llm_calls += 1
        else:
            from ..llm import fallback_fix
            from ..rag import PolicyStore
            fix = fallback_fix(f, PolicyStore.references(docs))
        if f.priority.value in APPROVAL_LEVELS:
            fix.approval = "pending_approval"
        f.fix = fix
        store.write_meta(state["scan_id"], step=f"recommend_fixes ({i + 1}/{len(findings)})")
    return {"findings": _dump(findings)}


def build_report(state: ScanState) -> dict:
    _progress(state, "build_report")
    findings = _findings(state)
    pending = sum(1 for f in findings if f.fix and f.fix.approval == "pending_approval")
    reports = write_reports(state, findings)
    status = "awaiting_approval" if pending and state.get("interactive") else "completed"
    store.write_meta(state["scan_id"], status=status, step="done" if status == "completed" else "human_approval",
                     summary=state.get("summary"), pending_approvals=pending,
                     reports={k: True for k in reports}, completed_at=time.time())
    return {"reports": reports}


def human_approval(state: ScanState) -> dict:
    findings = _findings(state)
    pending = [f for f in findings if f.fix and f.fix.approval == "pending_approval"]
    # Pause here. The API resumes the graph with the approver's decisions.
    decisions: Any = interrupt({"pending": [{"id": f.id, "title": f.title, "priority": f.priority.value}
                                            for f in pending]})
    store.write_meta(state["scan_id"], status="running", step="applying_approvals")
    by_id = {d["finding_id"]: d for d in decisions.get("decisions", [])}
    actor = decisions.get("actor", "unknown")
    log_entries = list(state.get("approval_log", []))
    for f in findings:
        d = by_id.get(f.id)
        if d and f.fix and f.fix.approval == "pending_approval":
            f.fix.approval = "approved" if d["approved"] else "rejected"
            f.fix.approved_by = actor
            f.fix.approval_comment = redact(d.get("comment", ""))[:500]
            log_entries.append({"finding_id": f.id, "decision": f.fix.approval, "by": actor,
                                "comment": f.fix.approval_comment, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    return {"findings": _dump(findings), "approval_log": log_entries}


def _after_report(state: ScanState) -> str:
    pending = any(f.get("fix") and f["fix"]["approval"] == "pending_approval" for f in state.get("findings", []))
    return "human_approval" if pending and state.get("interactive") else END


# ------------------------------------------------------------------------ graph
def build_graph(checkpointer=None):
    g = StateGraph(ScanState)
    for name, fn in [("prepare_source", prepare_source), ("detect_languages", detect_languages),
                     ("run_scanners", run_scanners), ("normalize", normalize), ("prioritize", prioritize),
                     ("retrieve_policy", retrieve_policy), ("recommend_fixes", recommend_fixes),
                     ("build_report", build_report), ("human_approval", human_approval)]:
        g.add_node(name, fn)
    g.add_edge(START, "prepare_source")
    g.add_edge("prepare_source", "detect_languages")
    g.add_edge("detect_languages", "run_scanners")
    g.add_edge("run_scanners", "normalize")
    g.add_edge("normalize", "prioritize")
    g.add_edge("prioritize", "retrieve_policy")
    g.add_edge("retrieve_policy", "recommend_fixes")
    g.add_edge("recommend_fixes", "build_report")
    g.add_conditional_edges("build_report", _after_report, ["human_approval", END])
    g.add_edge("human_approval", "build_report")
    return g.compile(checkpointer=checkpointer)


_graph = None


def get_graph():
    global _graph
    if _graph is None:
        conn = sqlite3.connect(get_settings().data_dir / "checkpoints.sqlite", check_same_thread=False)
        _graph = build_graph(SqliteSaver(conn))
    return _graph


def _config(scan_id: str) -> dict:
    return {"configurable": {"thread_id": scan_id}, "recursion_limit": 50}


def start_scan(scan_id: str, request: ScanRequest, model: str | None, actor: str, interactive: bool) -> None:
    existing = store.read_meta(scan_id) or {}
    store.write_meta(scan_id, status="running", step="queued", actor=actor, source_type=request.source_type,
                     target=request.target, model=model or "policy-fallback", interactive=interactive,
                     created_at=existing.get("created_at") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    try:
        get_graph().invoke({"scan_id": scan_id, "request": request.model_dump(), "model": model or "",
                            "interactive": interactive, "actor": actor, "approval_log": [], "errors": []},
                           _config(scan_id))
    except Exception as exc:
        log.exception("scan %s failed", scan_id)
        store.write_meta(scan_id, status="failed", step="error", error=redact(str(exc))[:500])
        raise


def resume_with_decisions(scan_id: str, decisions: list[dict], actor: str) -> None:
    get_graph().invoke(Command(resume={"decisions": decisions, "actor": actor}), _config(scan_id))


def is_waiting_for_approval(scan_id: str) -> bool:
    snap = get_graph().get_state(_config(scan_id))
    return bool(snap and snap.next and "human_approval" in snap.next)
