"""SecureScan AI command line - used locally and in CI/CD pipelines.

  python -m securescan.cli scan <path> [--model llama3.2] [--no-llm] [--fail-on high] [--out reports/]
  python -m securescan.cli scan <path> --approve       # interactive human approval in the terminal
  python -m securescan.cli models                      # list Ollama models
  python -m securescan.cli gen-key                     # create an API key + its SHA-256 hash
  python -m securescan.cli serve                       # start the web UI / API

Exit codes: 0 = below threshold, 1 = findings at/above --fail-on, 2 = scan error.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import uuid
from pathlib import Path

SEV_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _configure_for_local(target: Path, exclude: str | None) -> None:
    # The CLI operator is trusted: the scan root is exactly the path they asked for.
    os.environ["SECURESCAN_ALLOWED_SCAN_ROOT"] = str(target)
    if exclude:
        os.environ["SECURESCAN_EXCLUDE_DIRS"] = exclude
    from .config import get_settings
    get_settings.cache_clear()


def choose_model(requested: str | None, no_llm: bool) -> str | None:
    from .llm import list_models, resolve_model

    if no_llm:
        return None
    models = list_models()
    if not models:
        print("[i] Ollama not reachable / no models installed -> policy-based fix recommendations.")
        return None
    if requested:
        return resolve_model(requested)
    from .config import get_settings
    if get_settings().ollama_model in models:
        return get_settings().ollama_model
    if sys.stdin.isatty():
        print("Available Ollama models:")
        for i, m in enumerate(models, 1):
            print(f"  {i}. {m}")
        choice = input(f"Select model [1-{len(models)}] (Enter = 1, 0 = no LLM): ").strip() or "1"
        if choice == "0":
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(models):
            return models[int(choice) - 1]
        return resolve_model(choice)
    return models[0]


def _terminal_approvals(scan_id: str) -> None:
    from .agent import is_waiting_for_approval, resume_with_decisions
    from .store import report_path

    while is_waiting_for_approval(scan_id):
        report = json.loads(report_path(scan_id, "json").read_text(encoding="utf-8"))
        decisions = []
        for f in report["findings"]:
            fix = f.get("fix") or {}
            if fix.get("approval") != "pending_approval":
                continue
            print("\n" + "=" * 90)
            print(f"[{f['priority']}] {f['title']}  ({f['file']}:{f['line']})")
            print(f"Recommendation: {fix['summary']}")
            if fix.get("fixed_code"):
                print("Proposed fix:\n" + "\n".join("    " + ln for ln in fix["fixed_code"].splitlines()))
            print(f"Policy: {', '.join(fix.get('policy_references', []))}")
            ans = input("Approve this fix? [y]es / [n]o / [s]kip: ").strip().lower()
            if ans in {"y", "n"}:
                comment = input("Comment (optional): ").strip()
                decisions.append({"finding_id": f["id"], "approved": ans == "y", "comment": comment})
        if not decisions:
            print("No decisions made; remaining fixes stay pending.")
            return
        resume_with_decisions(scan_id, decisions, actor=f"cli:{os.getenv('USERNAME') or os.getenv('USER') or 'user'}")


def to_sarif(report: dict) -> dict:
    """SARIF 2.1.0 so findings show up in GitHub code scanning (Security tab)."""
    level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
    rules, results = {}, []
    for f in report["findings"]:
        rid = f"{f['tool']}/{f['rule_id']}"
        rules.setdefault(rid, {"id": rid, "name": f["rule_id"][:100], "shortDescription": {"text": f["title"][:200]},
                               "properties": {"tags": [f["category"], *f.get("cwe", [])],
                                              "security-severity": str(round(f["risk_score"] / 10, 1))}})
        msg = f["title"]
        if f.get("fix"):
            msg += f"\nRecommendation: {f['fix']['summary']}"
        results.append({"ruleId": rid, "level": level[f["priority"]], "message": {"text": msg[:2000]},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"] or "."},
                                                            "region": {"startLine": max(f.get("line") or 1, 1)}}}]})
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "SecureScan AI", "informationUri": "https://example.com/securescan",
                                          "rules": list(rules.values())}}, "results": results}]}


def _step_summary(report: dict, out: Path) -> None:
    path = os.getenv("GITHUB_STEP_SUMMARY")
    bp = report["summary"]["by_priority"]
    md = ["## SecureScan AI results", "", "| Critical | High | Medium | Low |", "|---|---|---|---|",
          f"| {bp['CRITICAL']} | {bp['HIGH']} | {bp['MEDIUM']} | {bp['LOW']} |", "",
          f"Pending human approval (Critical/High fixes): **{report['approvals']['pending']}**", "",
          "| Priority | Title | Location |", "|---|---|---|"]
    for f in report["findings"][:25]:
        md.append(f"| {f['priority']} | {f['title'][:80].replace('|', '/')} | `{f['file']}:{f['line']}` |")
    text = "\n".join(md) + "\n"
    (out / "securescan-summary.md").write_text(text, encoding="utf-8")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(text)


def cmd_scan(args) -> int:
    target = Path(args.path).resolve()
    if not target.is_dir():
        print(f"error: {target} is not a directory", file=sys.stderr)
        return 2
    _configure_for_local(target, args.exclude)
    from . import store
    from .agent import start_scan
    from .models import ScanRequest
    from .reports import write_to
    from .security import audit

    model = choose_model(args.model, args.no_llm)
    scan_id = uuid.uuid4().hex
    store.write_meta(scan_id, status="queued")
    print(f"[*] SecureScan AI  scan={scan_id}  target={target}  model={model or 'none (policy fallback)'}")
    audit("scan.start", actor="cli", target=str(target), scan_id=scan_id, model=model or "")
    try:
        start_scan(scan_id, ScanRequest(source_type="local", target=str(target), use_llm=bool(model)),
                   model, actor="cli", interactive=args.approve)
    except Exception as exc:
        print(f"[!] scan failed: {exc}", file=sys.stderr)
        return 2
    if args.approve:
        _terminal_approvals(scan_id)

    report_json = store.report_path(scan_id, "json")
    report = json.loads(report_json.read_text(encoding="utf-8"))
    out = Path(args.out).resolve()
    write_to(report_json, out)
    (out / "securescan-report.sarif").write_text(json.dumps(to_sarif(report), indent=1), encoding="utf-8")
    _step_summary(report, out)

    for t in report["tools"]:
        print(f"    {t['tool']:<10} {t['status']:<8} {t['duration']:>6}s {t['error'][:80]}")
    bp = report["summary"]["by_priority"]
    print(f"[*] Findings: {report['summary']['total']}  CRITICAL={bp['CRITICAL']} HIGH={bp['HIGH']} "
          f"MEDIUM={bp['MEDIUM']} LOW={bp['LOW']}   pending approvals={report['approvals']['pending']}")
    print(f"[*] Reports written to {out}")
    audit("scan.complete", actor="cli", scan_id=scan_id, total=report["summary"]["total"])

    if args.fail_on == "none":
        return 0
    threshold = SEV_ORDER.index(args.fail_on.upper())
    worst = max((SEV_ORDER.index(f["priority"]) for f in report["findings"]), default=-1)
    if worst >= threshold:
        print(f"[!] Failing build: findings at or above {args.fail_on.upper()}")
        return 1
    return 0


def cmd_models(_args) -> int:
    from .llm import list_models
    models = list_models()
    print("\n".join(models) if models else "No Ollama models found (is `ollama serve` running?)")
    return 0


def cmd_gen_key(args) -> int:
    from .security import hash_key
    key = secrets.token_urlsafe(32)
    print(f"API key (give to the user/CI secret store, shown once): {key}")
    print(f"SHA-256 hash (put in SECURESCAN_{args.role.upper()}_KEY_HASHES): {hash_key(key)}")
    return 0


def cmd_serve(args) -> int:
    import uvicorn
    from .config import get_settings
    s = get_settings()
    uvicorn.run("securescan.web.app:app", host=args.host or s.host, port=args.port or s.port,
                proxy_headers=False, server_header=False)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="securescan", description="SecureScan AI - SAST/SCA/secrets scanner")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a local repository")
    s.add_argument("path")
    s.add_argument("--model", help="Ollama model name (asked interactively if omitted on a TTY)")
    s.add_argument("--no-llm", action="store_true", help="use deterministic policy-based recommendations")
    s.add_argument("--fail-on", default="critical", choices=["critical", "high", "medium", "low", "none"])
    s.add_argument("--out", default="securescan-reports")
    s.add_argument("--exclude", help="comma-separated extra directories to skip")
    s.add_argument("--approve", action="store_true", help="review Critical/High fixes interactively")
    s.set_defaults(fn=cmd_scan)
    sub.add_parser("models", help="list installed Ollama models").set_defaults(fn=cmd_models)
    g = sub.add_parser("gen-key", help="generate an API key and its hash")
    g.add_argument("--role", default="scanner", choices=["viewer", "scanner", "approver"])
    g.set_defaults(fn=cmd_gen_key)
    v = sub.add_parser("serve", help="run the web UI / API")
    v.add_argument("--host")
    v.add_argument("--port", type=int)
    v.set_defaults(fn=cmd_serve)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
