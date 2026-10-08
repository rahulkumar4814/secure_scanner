import hashlib
import hmac

import pytest

from securescan.security import (ValidationError, has_role, redact, role_for_key, validate_git_url,
                                 validate_local_path, validate_scan_id, verify_github_signature)
from tests.conftest import TEST_KEYS


def test_role_for_key_and_hierarchy():
    assert role_for_key(TEST_KEYS["viewer"]) == "viewer"
    assert role_for_key(TEST_KEYS["approver"]) == "approver"
    assert role_for_key("wrong-key") is None
    assert role_for_key("x" * 1000) is None
    assert has_role("approver", "scanner") and not has_role("viewer", "scanner")


@pytest.mark.parametrize("text", [
    'password = "SuperSecret123"', "token: 'abcd1234efgh'", "AKIAABCDEFGHIJKLMNOP",
    "ghp_" + "a" * 36, "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
])
def test_redact_masks_secrets(text):
    out = redact(text)
    assert "REDACTED" in out
    assert "SuperSecret123" not in out and "MIIEow" not in out


def test_local_path_traversal_blocked():
    assert validate_local_path("vulnerable-app").name == "vulnerable-app"
    for bad in ["../securescan", "..", "C:\\Windows", "/etc", "vulnerable-app/../../securescan"]:
        with pytest.raises(ValidationError):
            validate_local_path(bad)


@pytest.mark.parametrize("url", [
    "http://github.com/a/b", "https://169.254.169.254/a/b", "https://evil.com/a/b", "file:///etc/passwd",
    "https://user:pw@github.com/a/b", "https://github.com:8443/a/b", "https://github.com/a/b?x=1",
    "ext::sh -c touch% /tmp/pwned", "https://github.com/a/b;rm -rf",
])
def test_git_url_rejected(url):
    with pytest.raises(ValidationError):
        validate_git_url(url)


def test_git_url_allowed():
    assert validate_git_url("https://github.com/owner/repo.git")


def test_scan_id_validation():
    validate_scan_id("a" * 32)
    with pytest.raises(ValidationError):
        validate_scan_id("../../etc/passwd")


def test_webhook_signature():
    body = b'{"a":1}'
    sig = "sha256=" + hmac.new(b"test-webhook-secret", body, hashlib.sha256).hexdigest()
    assert verify_github_signature(body, sig)
    assert not verify_github_signature(body + b" ", sig)
    assert not verify_github_signature(body, None)
    assert not verify_github_signature(body, "sha1=abc")


def test_ollama_must_be_local():
    from securescan.config import Settings
    with pytest.raises(ValueError):
        Settings(ollama_base_url="https://api.example.com")
