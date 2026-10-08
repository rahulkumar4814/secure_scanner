"""Security primitives: key hashing, secret redaction, input validation, safe subprocess
execution and audit logging. Everything that touches untrusted input goes through here."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from .config import get_settings

log = logging.getLogger("securescan")

# --------------------------------------------------------------------------- keys
ROLE_ORDER = {"viewer": 1, "scanner": 2, "approver": 3}


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def role_for_key(raw_key: str | None) -> str | None:
    """Return the highest role whose stored hash matches the key (constant-time compare)."""
    if not raw_key or len(raw_key) > 256:
        return None
    digest = hash_key(raw_key)
    best: str | None = None
    for role, hashes in get_settings().role_hashes().items():
        for h in hashes:
            if hmac.compare_digest(digest, h) and (best is None or ROLE_ORDER[role] > ROLE_ORDER[best]):
                best = role
    return best


def has_role(actual: str | None, required: str) -> bool:
    return actual is not None and ROLE_ORDER.get(actual, 0) >= ROLE_ORDER[required]


def verify_github_signature(body: bytes, signature_header: str | None) -> bool:
    secret = get_settings().github_webhook_secret
    if not secret or not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


# --------------------------------------------------------------------- redaction
_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"sk_(live|test)_[A-Za-z0-9]{16,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    # key = "value" style assignments of password/secret/token/api key
    re.compile(r"""(?i)((?:pass(?:word|wd)?|secret|token|api[_-]?key|auth|credential)[\w-]*\s*[:=]\s*['"])([^'"\n]{4,})(['"])"""),
]


def redact(text: str) -> str:
    """Mask anything that looks like a credential before it is stored, shown or sent to an LLM."""
    if not text:
        return text
    for pat in _SECRET_PATTERNS:
        if pat.groups >= 3:
            text = pat.sub(lambda m: f"{m.group(1)}***REDACTED***{m.group(3)}", text)
        else:
            text = pat.sub("***REDACTED***", text)
    return text


# ------------------------------------------------------------- input validation
_GIT_URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+?(\.git)?/?$")
_SCAN_ID_RE = re.compile(r"^[0-9a-f]{32}$")


class ValidationError(ValueError):
    pass


def validate_local_path(target: str) -> Path:
    """Resolve the path and make sure it stays inside the allowed scan root (no traversal / symlink escape)."""
    root = get_settings().allowed_scan_root.resolve()
    candidate = Path(target)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()
    if resolved != root and root not in resolved.parents:
        raise ValidationError("Path is outside the allowed scan root")
    if not resolved.is_dir():
        raise ValidationError("Path does not exist or is not a directory")
    return resolved


def validate_git_url(url: str) -> str:
    """Only https URLs on allow-listed hosts; no credentials, ports, query strings (SSRF guard)."""
    if not _GIT_URL_RE.match(url):
        raise ValidationError("Only https://<host>/<owner>/<repo> git URLs are allowed")
    parsed = urlparse(url)
    if parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment:
        raise ValidationError("Git URL must not contain credentials, ports, query or fragment")
    if (parsed.hostname or "").lower() not in get_settings().git_hosts:
        raise ValidationError("Git host is not in the allow-list")
    return url


def validate_scan_id(scan_id: str) -> str:
    if not _SCAN_ID_RE.match(scan_id):
        raise ValidationError("Invalid scan id")
    return scan_id


def check_repo_limits(path: Path) -> None:
    s = get_settings()
    files, size = 0, 0
    for p in path.rglob("*"):
        if ".git" in p.parts:
            continue
        if p.is_file() and not p.is_symlink():
            files += 1
            size += p.stat().st_size
            if files > s.max_repo_files or size > s.max_repo_mb * 1024 * 1024:
                raise ValidationError("Repository exceeds configured size limits")


# ------------------------------------------------------------- safe subprocess
@dataclass
class ToolResult:
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False


_ENV_ALLOW = {"PATH", "SYSTEMROOT", "TEMP", "TMP", "HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA",
              "PATHEXT", "COMSPEC", "LANG", "LC_ALL", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
              "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "TRIVY_CACHE_DIR", "SEMGREP_RULES_CACHE"}


def run_tool(args: list[str], cwd: Path | None = None, timeout: int | None = None,
             extra_env: dict[str, str] | None = None) -> ToolResult:
    """Run an external tool with an argument list (never a shell), a timeout and a minimal env.
    API keys and other app secrets are NOT inherited by child processes."""
    env = {k: v for k, v in os.environ.items() if k.upper() in _ENV_ALLOW}
    env.update({"PYTHONIOENCODING": "utf-8", "SEMGREP_SEND_METRICS": "off", "GIT_TERMINAL_PROMPT": "0"})
    env.update(extra_env or {})
    timeout = timeout or get_settings().tool_timeout_seconds
    start = time.monotonic()
    try:
        proc = subprocess.run(args, cwd=cwd, env=env, capture_output=True, timeout=timeout,
                              shell=False, check=False, stdin=subprocess.DEVNULL)
        return ToolResult(proc.returncode, proc.stdout.decode("utf-8", "replace"),
                          proc.stderr.decode("utf-8", "replace"), time.monotonic() - start)
    except subprocess.TimeoutExpired:
        return ToolResult(-1, "", f"timeout after {timeout}s", time.monotonic() - start, True)
    except FileNotFoundError:
        return ToolResult(-2, "", f"tool not found: {args[0]}", time.monotonic() - start)


# --------------------------------------------------------------------- auditing
_audit_logger: logging.Logger | None = None


def audit(event: str, actor: str = "system", ip: str = "-", **details) -> None:
    """Append a structured, secret-free audit record (JSON lines)."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = logging.getLogger("securescan.audit")
        _audit_logger.setLevel(logging.INFO)
        _audit_logger.propagate = False
        handler = logging.FileHandler(get_settings().data_dir / "audit.log", encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        _audit_logger.addHandler(handler)
    record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event,
              "actor": actor, "ip": ip, **{k: redact(str(v)) for k, v in details.items()}}
    _audit_logger.info(json.dumps(record))
