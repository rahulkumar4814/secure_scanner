"""JSON and PDF report generation."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from .. import __version__, store
from ..models import Finding
from .pdf import render_pdf


def build_report_dict(state: dict, findings: list[Finding]) -> dict:
    meta = store.read_meta(state["scan_id"]) or {}
    report = {
        "report_version": "1.0",
        "generator": f"SecureScan AI {__version__}",
        "scan": {
            "id": state["scan_id"],
            "target": state["request"]["target"],
            "source_type": state["request"]["source_type"],
            "git_ref": state["request"].get("git_ref"),
            "languages": state.get("languages", []),
            "started_by": state.get("actor"),
            "created_at": meta.get("created_at"),
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "ai_model": state.get("model") or "none (policy-based fallback)",
            "rag_mode": state.get("rag_mode", ""),
        },
        "tools": state.get("tools", []),
        "summary": state.get("summary", {}),
        "approvals": {
            "pending": sum(1 for f in findings if f.fix and f.fix.approval == "pending_approval"),
            "approved": sum(1 for f in findings if f.fix and f.fix.approval == "approved"),
            "rejected": sum(1 for f in findings if f.fix and f.fix.approval == "rejected"),
            "log": state.get("approval_log", []),
        },
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    # Integrity hash over the canonical content lets consumers detect tampering.
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    report["integrity_sha256"] = hashlib.sha256(canonical).hexdigest()
    return report


def write_reports(state: dict, findings: list[Finding]) -> dict[str, str]:
    report = build_report_dict(state, findings)
    json_path = store.report_path(state["scan_id"], "json")
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    pdf_path = store.report_path(state["scan_id"], "pdf")
    render_pdf(report, pdf_path)
    return {"json": str(json_path), "pdf": str(pdf_path)}


def write_to(report_json: Path, out_dir: Path) -> None:
    """Copy reports to a user-chosen directory (used by the CLI for CI artifacts)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    data = json.loads(report_json.read_text(encoding="utf-8"))
    (out_dir / "securescan-report.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    render_pdf(data, out_dir / "securescan-report.pdf")
