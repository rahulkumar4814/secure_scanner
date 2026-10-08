# Company Secure Coding Policy (v1.0)

> Sample policy for the SecureScan AI demo. Replace it with your organization's policy. Any `.md`,
> `.txt` or `.pdf` file in the `policies/` folder is indexed for RAG.

## SCP-01 Secrets Management
SCP-01.1 Credentials, API keys, tokens, private keys and passwords MUST NOT be committed to source control.
SCP-01.2 Secrets MUST be loaded at runtime from environment variables or the approved secrets manager
(e.g. HashiCorp Vault, AWS Secrets Manager, Azure Key Vault).
SCP-01.3 Any secret that has been committed MUST be treated as compromised: rotate it immediately,
revoke the old value, and purge it from git history.
SCP-01.4 Python: use `os.environ["NAME"]` or `os.getenv("NAME")`. Node.js: use `process.env.NAME`.
Template files such as `.env.example` contain placeholders only.

## SCP-02 Injection Prevention (SQL, NoSQL, OS command, code)
SCP-02.1 SQL queries MUST use parameterized queries or an ORM. String concatenation, f-strings,
`%` formatting or template literals that build SQL from user input are forbidden.
Python example: `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`.
Node example: `db.query("SELECT * FROM users WHERE id = $1", [userId])`.
SCP-02.2 OS commands MUST NOT be built from user input. Python: use `subprocess.run([...], shell=False)`
with an argument list and never `os.system` or `shell=True`. Node: use `child_process.execFile` or
`spawn` with an argument array and never `exec` with concatenated input.
SCP-02.3 `eval`, `exec`, `new Function`, `vm.runInNewContext` and similar dynamic code execution on
untrusted data are forbidden.
SCP-02.4 Input MUST be validated against an allow-list (type, length, format, range) at the trust boundary.

## SCP-03 Cross-Site Scripting (XSS) and Output Encoding
SCP-03.1 All output rendered to HTML MUST be context-encoded. Use template engines with auto-escaping
(Jinja2 autoescape, React JSX). Do not use `Markup()`, `|safe`, `dangerouslySetInnerHTML` or
`innerHTML` with untrusted data.
SCP-03.2 Set a Content-Security-Policy header that disallows inline script.

## SCP-04 Insecure Deserialization
SCP-04.1 `pickle`, `marshal`, `shelve`, `yaml.load` (without SafeLoader) and `node-serialize` MUST NOT be
used on untrusted input. Use JSON, or `yaml.safe_load`.

## SCP-05 Cryptography
SCP-05.1 MD5 and SHA-1 MUST NOT be used for security purposes. Use SHA-256 or stronger. Hash passwords
with bcrypt, scrypt or Argon2.
SCP-05.2 Use the `secrets` module (Python) or `crypto.randomBytes` (Node) for tokens, never `random`
or `Math.random`.
SCP-05.3 TLS certificate verification MUST NOT be disabled (`verify=False`,
`rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`).

## SCP-06 Third-Party Dependencies
SCP-06.1 Dependencies MUST be pinned (requirements.txt with `==`, package-lock.json committed).
SCP-06.2 Dependencies with known Critical or High vulnerabilities MUST be upgraded to a fixed version
within 7 days (Critical) or 30 days (High). Medium: 90 days.
SCP-06.3 If no fix exists, a documented risk acceptance approved by the security team is required,
with compensating controls.
SCP-06.4 Every push MUST be scanned in CI. Builds with Critical findings MUST fail.

## SCP-07 Authentication, Session and Access Control
SCP-07.1 Session cookies MUST be `HttpOnly`, `Secure`, and `SameSite=Lax` or `Strict`.
SCP-07.2 Every endpoint MUST enforce authorization on the server side (deny by default).
SCP-07.3 Flask/Django/Express apps MUST NOT run with debug mode enabled in production
(`app.run(debug=True)`, `DEBUG = True`).
SCP-07.4 JWTs MUST be verified with an explicit algorithm allow-list. `algorithms=["none"]` and
`verify=False` are forbidden.

## SCP-08 File and Path Handling
SCP-08.1 File paths built from user input MUST be normalized and checked to stay inside an allowed base
directory (prevents path traversal, CWE-22).
SCP-08.2 Archive extraction MUST check every member path (prevents zip slip).

## SCP-09 Server-Side Request Forgery (SSRF)
SCP-09.1 Outbound requests to user-supplied URLs MUST use a host allow-list and block internal/link-local
address ranges.

## SCP-10 Logging and Error Handling
SCP-10.1 Do not log secrets, tokens, passwords or full personal data.
SCP-10.2 Do not return stack traces or internal errors to clients.

## SCP-11 Prototype Pollution (Node.js)
SCP-11.1 Do not merge untrusted objects recursively into plain objects. Block the keys `__proto__`,
`constructor` and `prototype`, or use `Object.create(null)` / `Map`.

## SCP-12 Remediation Governance
SCP-12.1 Fixes for Critical and High findings MUST be reviewed and approved by an authorized approver
before they are merged.
SCP-12.2 AI-generated fixes are recommendations. A human MUST review them, and they MUST pass tests
before merge.
