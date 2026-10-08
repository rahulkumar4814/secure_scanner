"""Scan metadata store (one directory per scan under data/scans/<uuid>/)."""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from .config import get_settings
from .security import validate_scan_id

_lock = threading.Lock()


def scan_dir(scan_id: str) -> Path:
    validate_scan_id(scan_id)
    d = get_settings().data_dir / "scans" / scan_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_meta(scan_id: str, **fields) -> dict:
    with _lock:
        path = scan_dir(scan_id) / "meta.json"
        meta = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"id": scan_id}
        meta.update(fields)
        meta["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        tmp.replace(path)
        return meta


def read_meta(scan_id: str) -> dict | None:
    path = get_settings().data_dir / "scans" / validate_scan_id(scan_id) / "meta.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def list_scans(limit: int = 50) -> list[dict]:
    root = get_settings().data_dir / "scans"
    metas = []
    for d in root.iterdir() if root.exists() else []:
        m = d / "meta.json"
        if m.exists():
            try:
                metas.append(json.loads(m.read_text(encoding="utf-8")))
            except json.JSONDecodeError:
                continue
    return sorted(metas, key=lambda m: m.get("created_at", ""), reverse=True)[:limit]


def report_path(scan_id: str, kind: str) -> Path:
    if kind not in {"json", "pdf"}:
        raise ValueError("invalid report type")
    return scan_dir(scan_id) / f"report.{kind}"
