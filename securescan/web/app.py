"""FastAPI application: interactive UI + REST API + GitHub webhook.

Security controls implemented here:
  * AuthN: API key (X-API-Key) or signed HttpOnly/SameSite=Strict session cookie after login
  * AuthZ: RBAC viewer < scanner < approver, enforced per route (deny by default)
  * CSRF : cookie-authenticated state changes require the custom X-Requested-With header
  * Rate limiting (stricter on login), request body size cap, concurrent scan cap
  * Security headers (CSP without inline script, HSTS, frame-ancestors none, nosniff ...)
  * Webhook HMAC-SHA256 verification, generic error responses, audit logging
"""
from __future__ import annotations

import json
import logging
import secrets
import threading
import time
import uuid
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

from .. import __version__, store
from ..agent import is_waiting_for_approval, resume_with_decisions, start_scan
from ..config import get_settings
from ..llm import list_models, resolve_model
from ..models import ApprovalRequest, ScanRequest
from ..rag import get_policy_store, reload_policy_store
from ..scanners import tool_available
from ..security import (ValidationError, audit, has_role, role_for_key, validate_git_url, validate_local_path,
                        validate_scan_id, verify_github_signature)

log = logging.getLogger("securescan.web")
settings = get_settings()
HERE = Path(__file__).parent

app = FastAPI(title="SecureScan AI", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)

_session_secret = settings.session_secret or secrets.token_urlsafe(48)
if not settings.session_secret:
    log.warning("SECURESCAN_SESSION_SECRET not set - using an ephemeral secret (sessions reset on restart)")

executor = ThreadPoolExecutor(max_workers=settings.max_concurrent_scans, thread_name_prefix="scan")
_active: set[str] = set()
_active_lock = threading.Lock()


# --------------------------------------------------------------- middleware
_buckets: dict[str, deque] = defaultdict(deque)
_bucket_lock = threading.Lock()


def _rate_limited(key: str, limit: int, window: float = 60.0) -> bool:
    now = time.monotonic()
    with _bucket_lock:
        q = _buckets[key]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= limit:
            return True
        q.append(now)
        return False


CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    ip = request.client.host if request.client else "-"
    # Body size cap (DoS)
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > settings.max_body_bytes:
        return JSONResponse({"detail": "Request too large"}, status_code=413)
    if request.url.path.startswith("/api/") and _rate_limited(f"all:{ip}", settings.rate_limit_per_minute):
        return JSONResponse({"detail": "Too many requests"}, status_code=429)
    response = await call_next(request)
    h = response.headers
    h["Content-Security-Policy"] = CSP
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "no-referrer"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["Cross-Origin-Resource-Policy"] = "same-origin"
    h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.url.path.startswith("/api/"):
        h["Cache-Control"] = "no-store"
    return response


app.add_middleware(SessionMiddleware, secret_key=_session_secret, session_cookie="ss_session",
                   max_age=settings.session_max_age, same_site="strict", https_only=settings.https_only_cookies)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    log.exception("Unhandled error on %s", request.url.path)
    return JSONResponse({"detail": "Internal error"}, status_code=500)  # never leak stack traces


# ----------------------------------------------------------------- auth / RBAC
class Principal(BaseModel):
    name: str
    role: str
    via: str


def current_principal(request: Request) -> Principal | None:
    key = request.headers.get("x-api-key")
    if key:
        role = role_for_key(key)
        return Principal(name=f"apikey:{role}", role=role, via="api-key") if role else None
    role = request.session.get("role")
    if role:
        if time.time() - request.session.get("login_at", 0) > settings.session_max_age:
            request.session.clear()
            return None
        return Principal(name=request.session.get("name", role), role=role, via="session")
    return None


def require(role: str):
    def dep(request: Request) -> Principal:
        p = current_principal(request)
        if p is None:
            raise HTTPException(401, "Authentication required")
        if not has_role(p.role, role):
            audit("authz.denied", actor=p.name, ip=_ip(request), path=request.url.path, required=role)
            raise HTTPException(403, "Insufficient role")
        # CSRF: browser (cookie) requests that change state must carry the custom header.
        if p.via == "session" and request.method not in {"GET", "HEAD", "OPTIONS"}:
            if request.headers.get("x-requested-with") != "SecureScan":
                raise HTTPException(403, "CSRF check failed")
        return p
    return dep


def _ip(request: Request) -> str:
    return request.client.host if request.client else "-"


class LoginBody(BaseModel):
    api_key: str = Field(min_length=8, max_length=256)
    name: str = Field(default="", max_length=60, pattern=r"^[A-Za-z0-9 ._@-]*$")


@app.post("/api/auth/login")
def login(body: LoginBody, request: Request):
    ip = _ip(request)
    if _rate_limited(f"login:{ip}", 10):
        raise HTTPException(429, "Too many login attempts")
    if request.headers.get("x-requested-with") != "SecureScan":
        raise HTTPException(403, "CSRF check failed")
    role = role_for_key(body.api_key)
    if not role:
        audit("auth.login_failed", ip=ip)
        raise HTTPException(401, "Invalid API key")
    request.session.clear()
    name = body.name.strip() or role
    request.session.update({"role": role, "name": f"{name} ({role})", "login_at": time.time()})
    audit("auth.login", actor=name, ip=ip, role=role)
    return {"name": request.session["name"], "role": role}


@app.post("/api/auth/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}


@app.get("/api/auth/me")
def me(request: Request):
    p = current_principal(request)
    if not p:
        raise HTTPException(401, "Not logged in")
    return p.model_dump()


# ------------------------------------------------------------------- info
@app.get("/api/health")
def health():
    return {"status": "ok", "version": __version__}


@app.get("/api/status")
def status(_: Principal = Depends(require("viewer"))):
    models = list_models()
    ps = get_policy_store()
    return {"tools": {t: tool_available(t) for t in ["semgrep", "pip-audit", "trivy", "gitleaks", "git"]},
            "ollama": bool(models), "models": models, "default_model": settings.ollama_model,
            "rag_mode": ps.mode, "policy_chunks": len(ps.docs), "allowed_git_hosts": sorted(settings.git_hosts)}


@app.get("/api/models")
def models(_: Principal = Depends(require("viewer"))):
    return {"models": list_models(), "default": settings.ollama_model}


@app.get("/api/targets")
def targets(_: Principal = Depends(require("viewer"))):
    """Directories the UI may offer for local scans (children of the allowed scan root)."""
    root = settings.allowed_scan_root.resolve()
    dirs = sorted(p.name for p in root.iterdir() if p.is_dir() and not p.name.startswith(".")) if root.is_dir() else []
    return {"root": root.name, "targets": dirs}


# ------------------------------------------------------------------- scans
def _submit(scan_id: str, req: ScanRequest, model: str | None, actor: str, interactive: bool = True):
    with _active_lock:
        if len(_active) >= settings.max_concurrent_scans * 3:
            raise HTTPException(429, "Scan queue is full, try again later")
        _active.add(scan_id)

    def job():
        try:
            start_scan(scan_id, req, model, actor, interactive)
        except Exception:
            pass  # status already recorded as failed
        finally:
            with _active_lock:
                _active.discard(scan_id)

    store.write_meta(scan_id, status="queued", step="queued", actor=actor, target=req.target,
                     source_type=req.source_type, created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    executor.submit(job)


@app.post("/api/scans", status_code=202)
def create_scan(req: ScanRequest, request: Request, p: Principal = Depends(require("scanner"))):
    try:
        if req.source_type == "local":
            validate_local_path(req.target)
        else:
            validate_git_url(req.target)
        model = resolve_model(req.model) if req.use_llm else None
    except (ValidationError, ValueError) as exc:
        raise HTTPException(400, str(exc))
    scan_id = uuid.uuid4().hex
    _submit(scan_id, req, model, p.name)
    audit("scan.start", actor=p.name, ip=_ip(request), scan_id=scan_id, target=req.target, model=model or "")
    return {"id": scan_id, "model": model}


@app.get("/api/scans")
def get_scans(_: Principal = Depends(require("viewer"))):
    return {"scans": store.list_scans()}


def _load(scan_id: str) -> dict:
    try:
        validate_scan_id(scan_id)
    except ValidationError:
        raise HTTPException(400, "Invalid scan id")
    meta = store.read_meta(scan_id)
    if not meta:
        raise HTTPException(404, "Scan not found")
    return meta


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str, _: Principal = Depends(require("viewer"))):
    meta = _load(scan_id)
    path = store.report_path(scan_id, "json")
    report = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
    return {"meta": meta, "report": report}


@app.get("/api/scans/{scan_id}/report.{kind}")
def download(scan_id: str, kind: str, request: Request, p: Principal = Depends(require("viewer"))):
    _load(scan_id)
    if kind not in {"json", "pdf"}:
        raise HTTPException(404, "Unknown report type")
    path = store.report_path(scan_id, kind)
    if not path.exists():
        raise HTTPException(404, "Report not ready")
    audit("report.download", actor=p.name, ip=_ip(request), scan_id=scan_id, kind=kind)
    media = "application/pdf" if kind == "pdf" else "application/json"
    return FileResponse(path, media_type=media, filename=f"securescan-{scan_id[:8]}.{kind}")


@app.post("/api/scans/{scan_id}/approvals")
def approve(scan_id: str, body: ApprovalRequest, request: Request, p: Principal = Depends(require("approver"))):
    _load(scan_id)
    if not is_waiting_for_approval(scan_id):
        raise HTTPException(409, "Scan is not waiting for approval")
    decisions = [d.model_dump() for d in body.decisions]
    store.write_meta(scan_id, status="running", step="applying_approvals")
    for d in decisions:
        audit("fix.approval", actor=p.name, ip=_ip(request), scan_id=scan_id, finding=d["finding_id"],
              decision="approved" if d["approved"] else "rejected")
    resume_with_decisions(scan_id, decisions, p.name)
    return {"ok": True, "meta": store.read_meta(scan_id)}


@app.post("/api/policies/reload")
def reload_policies(request: Request, p: Principal = Depends(require("approver"))):
    ps = reload_policy_store()
    audit("policy.reload", actor=p.name, ip=_ip(request), chunks=len(ps.docs))
    return {"mode": ps.mode, "chunks": len(ps.docs)}


# ------------------------------------------------------------------- webhook
@app.post("/api/webhook/github", status_code=202)
async def github_webhook(request: Request):
    """Triggered by GitHub on every push. Verifies X-Hub-Signature-256 before doing anything."""
    body = await request.body()
    ip = _ip(request)
    if not verify_github_signature(body, request.headers.get("x-hub-signature-256")):
        audit("webhook.rejected", ip=ip, reason="bad signature")
        raise HTTPException(401, "Invalid signature")
    event = request.headers.get("x-github-event", "")
    if event == "ping":
        return {"ok": True, "pong": True}
    if event != "push":
        return {"ok": True, "ignored": event}
    try:
        payload = json.loads(body)
        repo_url = validate_git_url(payload["repository"]["clone_url"])
        ref = payload.get("ref", "")
        branch = ref.removeprefix("refs/heads/") if ref.startswith("refs/heads/") else None
        if payload.get("deleted"):
            return {"ok": True, "ignored": "branch deleted"}
        req = ScanRequest(source_type="git", target=repo_url, git_ref=branch, use_llm=bool(settings.ollama_model))
        model = resolve_model(settings.ollama_model) if settings.ollama_model else None
    except (KeyError, ValueError, ValidationError) as exc:
        audit("webhook.invalid", ip=ip, reason=str(exc)[:200])
        raise HTTPException(400, "Unsupported or invalid push payload")
    scan_id = uuid.uuid4().hex
    pusher = (payload.get("pusher") or {}).get("name", "unknown")
    _submit(scan_id, req, model, f"github:{pusher}")
    audit("webhook.scan", actor=f"github:{pusher}", ip=ip, scan_id=scan_id, repo=repo_url, ref=ref,
          commit=payload.get("after", ""))
    return {"ok": True, "scan_id": scan_id}


# ------------------------------------------------------------------- UI
app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")


@app.get("/", response_class=HTMLResponse)
def index():
    return HTMLResponse((HERE / "templates" / "index.html").read_text(encoding="utf-8"))
