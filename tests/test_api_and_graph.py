import hashlib
import hmac
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from securescan.scanners import ScanOutput
from tests.conftest import TEST_KEYS
from tests.test_pipeline import GITLEAKS, PIP_AUDIT, SEMGREP, TRIVY


@pytest.fixture(scope="module")
def client():
    from securescan.web.app import app
    return TestClient(app)


def H(role):
    return {"X-API-Key": TEST_KEYS[role]}


def test_security_headers(client):
    r = client.get("/")
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_authn_and_rbac(client):
    assert client.get("/api/scans").status_code == 401
    assert client.get("/api/scans", headers={"X-API-Key": "nope-nope"}).status_code == 401
    assert client.get("/api/scans", headers=H("viewer")).status_code == 200
    body = {"source_type": "local", "target": "vulnerable-app", "use_llm": False}
    assert client.post("/api/scans", json=body, headers=H("viewer")).status_code == 403


def test_input_validation(client):
    r = client.post("/api/scans", json={"source_type": "local", "target": "../securescan"}, headers=H("scanner"))
    assert r.status_code == 400
    r = client.post("/api/scans", json={"source_type": "git", "target": "https://10.0.0.1/a/b"}, headers=H("scanner"))
    assert r.status_code == 400
    assert client.get("/api/scans/not-a-scan-id", headers=H("viewer")).status_code == 400


def test_session_login_and_csrf(client):
    assert client.post("/api/auth/login", json={"api_key": TEST_KEYS["scanner"]}).status_code == 403  # no CSRF header
    r = client.post("/api/auth/login", json={"api_key": TEST_KEYS["scanner"]}, headers={"X-Requested-With": "SecureScan"})
    assert r.status_code == 200
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    # cookie-authenticated state change without the custom header is rejected
    r = client.post("/api/scans", json={"source_type": "local", "target": "vulnerable-app"})
    assert r.status_code == 403
    client.post("/api/auth/logout", headers={"X-Requested-With": "SecureScan"})


def test_webhook_requires_signature(client):
    body = json.dumps({"zen": "x"}).encode()
    assert client.post("/api/webhook/github", content=body, headers={"X-GitHub-Event": "ping"}).status_code == 401
    sig = "sha256=" + hmac.new(b"test-webhook-secret", body, hashlib.sha256).hexdigest()
    r = client.post("/api/webhook/github", content=body, headers={"X-GitHub-Event": "ping", "X-Hub-Signature-256": sig})
    assert r.status_code == 202


def _fake_outputs(monkeypatch, outputs):
    from securescan.agent import graph as g
    monkeypatch.setattr(g, "run_all", lambda path, langs: outputs)
    return g


def test_graph_human_in_the_loop(monkeypatch):
    """Full LangGraph run with fake scanner output: pauses for approval, resumes, writes reports."""
    from securescan import store
    from securescan.models import ScanRequest

    g = _fake_outputs(monkeypatch, [ScanOutput("semgrep", SEMGREP), ScanOutput("trivy", TRIVY),
                                    ScanOutput("pip-audit", PIP_AUDIT), ScanOutput("gitleaks", GITLEAKS)])
    scan_id = uuid.uuid4().hex
    g.start_scan(scan_id, ScanRequest(source_type="local", target="vulnerable-app", use_llm=False),
                 None, actor="pytest", interactive=True)
    assert store.read_meta(scan_id)["status"] == "awaiting_approval"
    assert g.is_waiting_for_approval(scan_id)

    report = json.loads(store.report_path(scan_id, "json").read_text())
    pending = [f["id"] for f in report["findings"] if f["fix"] and f["fix"]["approval"] == "pending_approval"]
    assert pending
    # partial decision -> graph pauses again for the rest
    g.resume_with_decisions(scan_id, [{"finding_id": pending[0], "approved": False, "comment": "no"}], "approver1")
    assert g.is_waiting_for_approval(scan_id)
    g.resume_with_decisions(scan_id, [{"finding_id": i, "approved": True, "comment": "ok"} for i in pending[1:]],
                            "approver2")

    report = json.loads(store.report_path(scan_id, "json").read_text())
    assert store.read_meta(scan_id)["status"] == "completed"
    assert report["approvals"]["rejected"] == 1
    assert report["approvals"]["approved"] == len(pending) - 1 and report["approvals"]["pending"] == 0
    assert store.report_path(scan_id, "pdf").read_bytes().startswith(b"%PDF")
    assert len(report["integrity_sha256"]) == 64


def test_ci_mode_never_blocks(monkeypatch):
    from securescan import store
    from securescan.models import ScanRequest

    g = _fake_outputs(monkeypatch, [ScanOutput("gitleaks", GITLEAKS)])
    scan_id = uuid.uuid4().hex
    g.start_scan(scan_id, ScanRequest(source_type="local", target="vulnerable-app", use_llm=False),
                 None, actor="ci", interactive=False)
    assert store.read_meta(scan_id)["status"] == "completed"
    report = json.loads(store.report_path(scan_id, "json").read_text())
    assert report["approvals"]["pending"] == 1  # recorded as pending; the pipeline is not blocked
