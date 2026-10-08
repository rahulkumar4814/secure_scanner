"""Test configuration: isolated data dir, generated test keys, no real scanners or LLM required."""
import hashlib
import os
import secrets
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_tmp = Path(tempfile.mkdtemp(prefix="securescan-test-"))

TEST_KEYS = {r: f"test_{r}_{secrets.token_hex(8)}" for r in ("viewer", "scanner", "approver")}
for role, key in TEST_KEYS.items():
    os.environ[f"SECURESCAN_{role.upper()}_KEY_HASHES"] = hashlib.sha256(key.encode()).hexdigest()
os.environ["SECURESCAN_DATA_DIR"] = str(_tmp / "data")
os.environ["SECURESCAN_ALLOWED_SCAN_ROOT"] = str(ROOT / "samples")
os.environ["SECURESCAN_GITHUB_WEBHOOK_SECRET"] = "test-webhook-secret"
os.environ["SECURESCAN_SESSION_SECRET"] = "test-session-secret-" + secrets.token_hex(8)
os.environ["SECURESCAN_OLLAMA_BASE_URL"] = "http://127.0.0.1:9"  # unreachable -> deterministic fallback
os.environ["SECURESCAN_OLLAMA_MODEL"] = ""
