"""Scanner adapters. Each adapter runs one tool via the sandboxed runner and returns raw JSON.
Normalization into the shared Finding schema lives in securescan.normalizer."""
from __future__ import annotations

import json
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

from ..config import BASE_DIR, get_settings
from ..security import run_tool

_DEFAULT_EXCLUDES = ["node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build", ".pytest_cache",
                     ".mypy_cache", ".tox"]


def excluded_dirs(root: Path | None = None) -> list[str]:
    extra = [d.strip() for d in get_settings().exclude_dirs.split(",") if d.strip()]
    dirs = _DEFAULT_EXCLUDES + extra
    # Never exclude a directory that is part of the scan target's own path (e.g. scanning samples/app
    # while "samples" is excluded) - tools inside a git repo match against repo-relative paths.
    return [d for d in dirs if root is None or d not in root.resolve().parts]
LOCAL_SEMGREP_RULES = BASE_DIR / "rules" / "semgrep"


@dataclass
class ScanOutput:
    tool: str
    raw: object = None
    error: str = ""
    duration: float = 0.0
    skipped: bool = False
    meta: dict = field(default_factory=dict)


def tool_available(name: str) -> bool:
    if name == "pip-audit":
        try:
            import pip_audit  # noqa: F401
            return True
        except ImportError:
            return shutil.which("pip-audit") is not None
    return shutil.which(name) is not None


def _parse_json(text: str):
    text = text.strip()
    return json.loads(text) if text else None


# ----------------------------------------------------------------------- SAST
def run_semgrep(path: Path, languages: set[str]) -> ScanOutput:
    if not tool_available("semgrep"):
        return ScanOutput("semgrep", error="semgrep not installed", skipped=True)
    configs: list[str] = []
    if "python" in languages:
        configs += ["p/python", "p/flask", "p/django"]
    if "node" in languages:
        configs += ["p/javascript", "p/nodejs", "p/nodejsscan"]
    configs += ["p/owasp-top-ten"]
    args = ["semgrep", "scan", "--json", "--quiet", "--metrics=off", "--disable-version-check",
            "--timeout", "30", "--max-target-bytes", "1000000"]
    for c in configs:
        args += ["--config", c]
    if LOCAL_SEMGREP_RULES.is_dir():
        args += ["--config", str(LOCAL_SEMGREP_RULES)]
    for d in excluded_dirs(path):
        args += ["--exclude", d]
    args += ["--", "."]  # relative to cwd=path, so excludes never match the root itself
    res = run_tool(args, cwd=path)
    if res.returncode not in (0, 1) or res.timed_out:
        # Registry unreachable (offline CI)? fall back to the bundled local rules only.
        if LOCAL_SEMGREP_RULES.is_dir() and not res.timed_out:
            args = ["semgrep", "scan", "--json", "--quiet", "--metrics=off", "--disable-version-check",
                    "--config", str(LOCAL_SEMGREP_RULES), "--", "."]
            res2 = run_tool(args, cwd=path)
            if res2.returncode in (0, 1):
                return ScanOutput("semgrep", _parse_json(res2.stdout), duration=res.duration + res2.duration,
                                  error="registry rules unavailable - used bundled offline rules only",
                                  meta={"mode": "offline-local-rules"})
        return ScanOutput("semgrep", error=res.stderr[-500:], duration=res.duration)
    try:
        return ScanOutput("semgrep", _parse_json(res.stdout), duration=res.duration,
                          meta={"configs": configs})
    except json.JSONDecodeError:
        return ScanOutput("semgrep", error="invalid JSON from semgrep", duration=res.duration)


# ------------------------------------------------------------------------ SCA
def run_pip_audit(path: Path) -> ScanOutput:
    """Audit pinned requirement files WITHOUT installing them (--no-deps --disable-pip),
    so a malicious setup.py in the scanned repo is never executed."""
    if not tool_available("pip-audit"):
        return ScanOutput("pip-audit", error="pip-audit not installed", skipped=True)
    skip = set(excluded_dirs(path))
    req_files = [p for p in path.rglob("requirements*.txt") if not skip & set(p.relative_to(path).parts)]
    if not req_files:
        return ScanOutput("pip-audit", skipped=True, error="no requirements*.txt found")
    combined: dict = {"dependencies": [], "files": []}
    errors, total = [], 0.0
    for req in req_files[:20]:
        args = [sys.executable, "-m", "pip_audit", "-r", str(req), "--no-deps", "--disable-pip",
                "-f", "json", "--progress-spinner", "off"]
        res = run_tool(args, cwd=path)
        total += res.duration
        try:
            data = _parse_json(res.stdout) or {}
            rel = req.relative_to(path).as_posix()
            for dep in data.get("dependencies", []):
                dep["_file"] = rel
                combined["dependencies"].append(dep)
            combined["files"].append(rel)
        except json.JSONDecodeError:
            errors.append(f"{req.name}: {res.stderr.strip()[-300:]}")
    return ScanOutput("pip-audit", combined, error="; ".join(errors), duration=total)


def run_trivy(path: Path) -> ScanOutput:
    if not tool_available("trivy"):
        return ScanOutput("trivy", error="trivy not installed", skipped=True)
    args = ["trivy", "fs", "--scanners", "vuln", "--format", "json", "--quiet", "--timeout", "10m"]
    for d in excluded_dirs(path):
        args += ["--skip-dirs", f"**/{d}"]
    args += ["--", "."]  # relative to cwd=path, so excludes never match the root itself
    res = run_tool(args, cwd=path)
    if res.returncode != 0:
        return ScanOutput("trivy", error=res.stderr[-500:], duration=res.duration)
    try:
        return ScanOutput("trivy", _parse_json(res.stdout), duration=res.duration)
    except json.JSONDecodeError:
        return ScanOutput("trivy", error="invalid JSON from trivy", duration=res.duration)


# -------------------------------------------------------------------- Secrets
def run_gitleaks(path: Path) -> ScanOutput:
    """Secrets are redacted by gitleaks itself (--redact) and again by our normalizer."""
    if not tool_available("gitleaks"):
        return ScanOutput("gitleaks", error="gitleaks not installed", skipped=True)
    # gitleaks has no --exclude flag: generate a config that extends the default rules (and the repo's own
    # .gitleaks.toml, if any) with a path allow-list for the excluded directories.
    import re
    import tempfile

    repo_cfg = path / ".gitleaks.toml"
    extend = f"path = {json.dumps(str(repo_cfg))}" if repo_cfg.is_file() else "useDefault = true"
    patterns = ", ".join(json.dumps(rf"(^|[\\/]){re.escape(d)}[\\/]") for d in excluded_dirs(path))
    cfg_text = f"[extend]\n{extend}\n\n[allowlist]\ndescription = \"SecureScan excluded dirs\"\npaths = [{patterns}]\n"
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False, encoding="utf-8") as cfg:
        cfg.write(cfg_text)
    args = ["gitleaks", "dir", "--no-banner", "--redact", "--exit-code", "0", "--config", cfg.name,
            "--report-format", "json", "--report-path", "-", "--log-level", "error", "."]
    try:  # run inside the repo with "." so reported paths (and the allow-list) are relative to the scan root
        res = run_tool(args, cwd=path)
    finally:
        Path(cfg.name).unlink(missing_ok=True)
    if res.returncode != 0:
        return ScanOutput("gitleaks", error=res.stderr[-500:], duration=res.duration)
    try:
        return ScanOutput("gitleaks", _parse_json(res.stdout) or [], duration=res.duration)
    except json.JSONDecodeError:
        return ScanOutput("gitleaks", error="invalid JSON from gitleaks", duration=res.duration)


def detect_languages(path: Path) -> set[str]:
    langs: set[str] = set()
    skip = set(excluded_dirs(path))
    for p in path.rglob("*"):
        if skip & set(p.relative_to(path).parts):
            continue
        name = p.name.lower()
        if name.endswith(".py") or name in {"requirements.txt", "pyproject.toml", "pipfile", "setup.py"}:
            langs.add("python")
        elif name.endswith((".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx")) or name == "package.json":
            langs.add("node")
        if langs == {"python", "node"}:
            break
    return langs


def run_all(path: Path, languages: set[str]) -> list[ScanOutput]:
    from concurrent.futures import ThreadPoolExecutor

    jobs = {"semgrep": lambda: run_semgrep(path, languages), "trivy": lambda: run_trivy(path),
            "gitleaks": lambda: run_gitleaks(path)}
    if "python" in languages:
        jobs["pip-audit"] = lambda: run_pip_audit(path)
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {name: pool.submit(fn) for name, fn in jobs.items()}
        return [f.result() for f in futures.values()]


__all__ = ["ScanOutput", "run_all", "detect_languages", "tool_available", "get_settings"]
