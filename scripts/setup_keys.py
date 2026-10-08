"""Generate demo API keys for the three roles and write their HASHES to .env.

The plaintext keys are printed once so you can sign in to the UI / configure CI.
Only SHA-256 hashes are stored on the server. Re-run to rotate all keys.
"""
import hashlib
import secrets
from pathlib import Path

ENV = Path(__file__).resolve().parent.parent / ".env"
EXAMPLE = ENV.with_name(".env.example")

values = {}
print("Save these keys now - they are not stored anywhere:\n")
for role in ("viewer", "scanner", "approver"):
    key = f"ss_{role}_{secrets.token_urlsafe(24)}"
    values[f"SECURESCAN_{role.upper()}_KEY_HASHES"] = hashlib.sha256(key.encode()).hexdigest()
    print(f"  {role:<9} {key}")
values["SECURESCAN_SESSION_SECRET"] = secrets.token_urlsafe(48)
values["SECURESCAN_GITHUB_WEBHOOK_SECRET"] = secrets.token_hex(32)

lines = (ENV if ENV.exists() else EXAMPLE).read_text(encoding="utf-8").splitlines()
out = []
for line in lines:
    k = line.split("=", 1)[0].strip()
    out.append(f"{k}={values.pop(k)}" if k in values else line)
out += [f"{k}={v}" for k, v in values.items()]
ENV.write_text("\n".join(out) + "\n", encoding="utf-8")
print(f"\nHashes, session secret and webhook secret written to {ENV}")
print("GitHub webhook secret is in .env (SECURESCAN_GITHUB_WEBHOOK_SECRET) - copy it into the GitHub webhook form.")
