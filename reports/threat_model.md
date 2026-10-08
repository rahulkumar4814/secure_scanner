# SecureScan AI — Threat Model (STRIDE)

| | |
|---|---|
| **System** | SecureScan AI v1.0.0 (FastAPI + LangGraph + Ollama SAST/SCA/secret scanner) |
| **Method** | STRIDE per element and per trust boundary |
| **Sources reviewed** | `securescan/**` (web/app.py, security.py, agent/graph.py, scanners, normalizer, llm.py, rag, reports, cli.py), `.github/workflows/securescan.yml`, `Dockerfile`, `docker-compose.yml`, `scripts/*`, `docs/ARCHITECTURE.md`, `README.md` |
| **Date** | 2026-10-07 |

**Evidence legend:** each threat is marked **Confirmed** (the weakness exists in the current code or
configuration, verified by reading it) or **Hypothetical** (a plausible attack path that depends on
preconditions not shown in the code). Risk is a qualitative rating of likelihood × impact for the
documented deployment.

---

## 1. Executive summary

The application already has a solid baseline. It uses hashed API keys with RBAC, a strict CSP,
CSRF protection, path and SSRF validation, shell-free subprocesses, secret redaction, a local-only
LLM with no tools, and human approval for Critical/High fixes.

The most significant remaining risks are not classic web vulnerabilities. They are **integrity
threats against the scan result itself**. This matters because SecureScan is used as a CI gate:
whoever can make the scanner report "clean" can ship vulnerable code.

| # | Top risk | Threat IDs | Status |
|---|---|---|---|
| 1 | The scanned repository can **suppress its own findings** through tool config files it controls (`.gitleaks.toml`, `.trivyignore`, `trivy.yaml`, `.semgrepignore`, inline `nosemgrep` / `gitleaks:allow`) | T-001 | Confirmed |
| 2 | The CI workflow **runs code from the scanned repo** whenever that repo contains `securescan/cli.py`, and pulls the scanner itself from an **unpinned** branch HEAD | T-002, T-003 | Confirmed |
| 3 | **Approval accountability is weak.** Keys are shared per role, the display name is typed by the user, there is no separation of duties, and the report "integrity hash" is unkeyed | T-005, T-006, T-007 | Confirmed |
| 4 | **Sensitive vulnerability intelligence** (source snippets and exploitable findings) is stored unencrypted, kept indefinitely, and visible to every viewer across all repositories | T-012, T-013, T-014 | Confirmed |
| 5 | **Availability:** rate limiting breaks behind a reverse proxy, scans are long-running, and webhook scans are dropped when the queue is full | T-009, T-019, T-020 | Confirmed |

No Critical-rated threat was found for the documented deployment, which is a single host bound to
localhost behind a TLS proxy. T-001 to T-003 become **Critical** if SecureScan is used as a
mandatory merge gate across many teams.

---

## 2. Architecture overview (as built)

```
                      ┌──────────────────────── SecureScan host / container ────────────────────────────┐
 [Browser]──TB1──────►│ FastAPI (uvicorn)                                                                  │
 [CI / CLI]──TB2─────►│  middleware: rate-limit · body cap · headers   auth: API key | session cookie     │
 [GitHub]──TB3───────►│  /api/webhook/github (HMAC)                    RBAC viewer<scanner<approver       │
                      │        │                                                                           │
                      │        ▼                                                                           │
                      │  LangGraph agent ──TB7──► Ollama :11434 (no auth, localhost) ── models on disk     │
                      │   │      │   └── RAG: policies/*.md (trusted input)                                │
                      │   │      └──TB6──► data/: scans/*/{meta,report,raw}, checkpoints.sqlite, audit.log│
                      │   └──TB4──► subprocess: git · semgrep · trivy · gitleaks · pip-audit               │
                      │                 │  (process UNTRUSTED repo content; TB10: read repo config files)  │
                      └─────────────────┼──────────────────────────────────────────────────────────────────┘
                                        └──TB8──► Internet: github.com (clone), semgrep.dev registry,
                                                   Trivy DB (ghcr.io), OSV/PyPI (pip-audit)
 CI runner (GitHub Actions) ──TB9──► clones SECURESCAN_REPO, pip install, downloads trivy/gitleaks, docker ollama
```

---

## 3. Missing information

None of the following is documented. Each item affects the risk ratings, so the corresponding
controls were **not assumed to exist**.

| # | Missing information | Why it matters |
|---|---|---|
| M1 | Production hosting (VM, Kubernetes, PaaS), network zones, egress policy | Determines exposure of the API, of Ollama :11434, and of the clone/egress paths |
| M2 | Reverse proxy / TLS configuration (none is provided in the repo) | All transport security and the client-IP-based rate limiting depend on it |
| M3 | Identity model: how many humans, who holds the approver key, any IdP/SSO | Drives the spoofing and repudiation ratings (T-005, T-011) |
| M4 | Data classification of scanned repositories (internal / customer / regulated) | Drives the impact of T-012 to T-014 |
| M5 | Retention, backup and encryption requirements for `data/` | No retention is implemented |
| M6 | How private repositories are accessed (deploy key, PAT, credential helper) | Introduces a new credential asset that isn't modeled |
| M7 | Whether the CI workflow is optional (per team) or a mandated gate (required workflow / ruleset) | Raises T-001 to T-004 from High to Critical |
| M8 | Log shipping / SIEM / alerting | Without it, the audit log is only local (T-008) |
| M9 | Whether one instance or several run (multiple workers or replicas) | The in-memory rate limiter, the ephemeral session secret and the SQLite checkpointer all assume a single process |
| M10 | Change control for `policies/` and `rules/semgrep/` | These files steer the LLM and the detection logic (T-016, T-024) |

---

## 4. Assets

| ID | Asset | Location | C | I | A | Notes |
|---|---|---|---|---|---|---|
| A1 | Source code of scanned repositories | Temporary clone in `data/ss_*` (deleted after the normalize step), local scan root | **H** | M | L | Snippets persist in reports |
| A2 | Findings and reports (vulnerability intelligence) | `data/scans/<id>/report.{json,pdf}`, `raw/*.json`, `checkpoints.sqlite`, SARIF in GitHub | **H** | **H** | M | A roadmap of exploitable bugs; its integrity drives the CI gate |
| A3 | API keys (viewer / scanner / approver) | Plaintext with users and in the CI secret store; SHA-256 hashes in `.env` | **H** | **H** | M | The approver key is the most privileged |
| A4 | Session secret, GitHub webhook secret | `.env` / process env | **H** | **H** | L | Session forgery, forged webhooks |
| A5 | Approval decisions and audit trail | `report.json` → `approvals.log`, `data/audit.log` | M | **H** | M | Accountability for accepting fixes |
| A6 | Secure-coding policy (RAG corpus) | `policies/` | L | **H** | M | Steers LLM output |
| A7 | LLM models and prompts/responses | Ollama model store; prompts in memory | M | **H** | M | Prompts contain code snippets |
| A8 | Scanner binaries, rules, vulnerability DBs | PATH, `rules/semgrep`, Trivy cache, Semgrep registry | L | **H** | **H** | Detection integrity |
| A9 | CI pipeline identity (`GITHUB_TOKEN`, runner) | GitHub Actions | M | **H** | M | `security-events: write`, checkout content |
| A10 | Scan service availability | Executor (2 workers), queue (6) | L | L | **H** | Push-triggered gating |

---

## 5. Trust boundaries and their controls

| TB | Boundary | Authentication | Authorization | Other controls | Gaps |
|---|---|---|---|---|---|
| TB1 | Browser → FastAPI | API key at login → signed HttpOnly, SameSite=Strict cookie (1 h) | RBAC per route | CSP, CSRF header, rate limit, body cap | No MFA/SSO; no server-side session revocation; `Secure` flag off by default (T-010, T-011) |
| TB2 | CI / CLI / API client → FastAPI | `X-API-Key` (SHA-256 hash, constant-time compare) | RBAC | Rate limit | Keys shared per role, long-lived, no expiry (T-005) |
| TB3 | GitHub → webhook | HMAC-SHA256 `X-Hub-Signature-256` | None beyond the signature (any github.com repo in the payload) | Host allow-list on `clone_url` | No replay protection, no repo allow-list (T-018) |
| TB4 | App → scanner subprocesses (untrusted content) | n/a | n/a | No shell, argument lists, timeouts, minimal env, hooks/submodules/symlinks off, size limits | Runs in the same container/user as the API; parsers handle hostile input (T-022) |
| TB5 | App → Ollama | **None** (Ollama API has no auth) | None | Config forces a local URL | Any local process can use or replace models (T-017) |
| TB6 | App → `data/` file system | OS permissions only | n/a | UUID paths, scan-id validation | No encryption, retention or tamper-evidence (T-007, T-008, T-012) |
| TB7 | Agent → LLM output (untrusted) | n/a | LLM has no tools | Code fenced, secrets redacted, JSON schema, quality gate, human approval for Critical/High | Fix content can still be manipulated (T-015) |
| TB8 | App → Internet | TLS (system trust store) | n/a | Git host allow-list, https only | Live, unpinned Semgrep registry rules; silent offline downgrade (T-024) |
| TB9 | CI runner → SecureScan code and tools | n/a | `contents: read`, `security-events: write` | Actions pinned by SHA, tool checksums | SecureScan repo unpinned; self-detection heuristic (T-002, T-003) |
| TB10 | Scanned repo content → scanner configuration | n/a | n/a | — | **Repo can configure its own scanner** (T-001) |

---

## 6. Threat register

| Threat ID | Component | STRIDE Category | Threat | Impact | Mitigation | Status | Risk |
|-----------|-----------|-----------------|--------|--------|------------|--------|------|
| T-001 | Scanner adapters (TB10) | Tampering | The scanned repo suppresses its own findings: `run_gitleaks` deliberately extends the repo's `.gitleaks.toml`; Trivy runs with `cwd=repo` and so reads the repo's `trivy.yaml` and `.trivyignore`; Semgrep honors `.semgrepignore` and `# nosemgrep`; Gitleaks honors `gitleaks:allow` | Vulnerable code or committed secrets pass the CI gate; reports look clean | Run tools with `cwd` outside the repo; pass SecureScan-owned `--config` / `--ignorefile`; `semgrep --disable-nosem`; `gitleaks --ignore-gitleaks-allow` (or report each suppression); stop extending the repo `.gitleaks.toml` unless the repo is allow-listed; add a "suppressions used" section to reports | Confirmed | **High** (Critical if mandated gate) |
| T-002 | CI workflow (TB9) | Elevation of Privilege / Tampering | The workflow treats any repo that contains `securescan/cli.py` as SecureScan itself and runs *that repo's* `securescan.cli`, so a target repo can ship a fake scanner that always exits 0 | The gate is bypassed, and repo-controlled code runs with the job's token (`security-events: write`) | Detect self-scanning by `github.repository` (an exact name), not by a file; always run the scanner from a separate, pinned checkout or image | Confirmed | **High** |
| T-003 | CI workflow (TB9) | Tampering (supply chain) | `SECURESCAN_REPO` is cloned at the default-branch HEAD (`--depth 1`, no ref pin); `requirements.txt` is installed without hashes | One compromise of the SecureScan repo or a PyPI package executes in every consumer pipeline and can falsify results | Pin to a signed tag or commit SHA (or publish a digest-pinned container / reusable workflow); `pip install --require-hashes`; verify tag signatures | Confirmed | **High** |
| T-004 | CI workflow config | Tampering | The default `SECURESCAN_EXCLUDE_DIRS` is `samples,tests` for **every** consumer repo, and excluded directory names match at any depth | Developers (or attackers) can hide production code under a `tests/` or `samples/` directory | No default excludes for consumer repos; take excludes only from a central policy; record the effective excludes in the report | Confirmed | Medium |
| T-005 | AuthN / approvals | Repudiation | Keys are per role, not per person (`setup_keys.py` makes one approver key); the actor is `apikey:<role>` or a self-typed display name (`LoginBody.name`) | A decision on a Critical fix can't be attributed to an individual, and any approver can impersonate another by name | Per-user keys with a key ID recorded in the audit log, or OIDC/SSO; take the display name from the identity, not from user input | Confirmed | **High** |
| T-006 | Approval workflow | Elevation of Privilege | No separation of duties: the same principal can start a scan, approve its fixes, and bulk-approve everything shown in one click; no second approver for Critical | A single compromised or careless account accepts all Critical fixes, defeating SCP-12.1 | Forbid self-approval of scans you started; require two-person approval for Critical; confirm bulk actions and limit them to non-Critical | Confirmed | Medium |
| T-007 | Reports | Tampering | `integrity_sha256` is an unkeyed hash stored inside the same JSON; `cli.write_to` re-renders the PDF from JSON without verifying it | Anyone with file or artifact access can change findings or approvals and recompute the hash; the hash gives false assurance | HMAC-SHA256 with a server-held key, or a detached signature (Sigstore/cosign); verify before rendering or serving | Confirmed | Medium |
| T-008 | Audit log | Repudiation / Tampering | `data/audit.log` is a local plain file: no rotation, no forwarding, no hash chain. Report **views** (`GET /api/scans/{id}`), logouts and policy-file changes are not audited | Actions can be denied or logs edited by anyone with host access; unbounded log growth | Ship to a SIEM / append-only store; hash-chain the records; audit report reads; rotate logs | Confirmed | Medium |
| T-009 | Rate limiter | Denial of Service | Buckets are per `request.client.host`, in memory, per process, with `proxy_headers=False`. Behind the README's recommended TLS proxy, every user shares the proxy's IP | One client can trigger 429s for all users; the login throttle becomes a global lockout; limits reset on restart or differ per worker | Trust `X-Forwarded-For` only from the known proxy (`forwarded_allow_ips`); key buckets by principal; use a shared store (Redis) or rate-limit at the proxy | Confirmed (in documented deployment) | Medium |
| T-010 | Session management | Spoofing | Sessions are client-side signed cookies: logout only clears the browser copy, revoking a key doesn't end its sessions, the `Secure` flag is off by default, and the session secret is ephemeral if unset (it breaks with several workers) | A stolen cookie is valid for up to 1 hour even after logout or key rotation | Server-side session store with revocation; tie sessions to a key ID and invalidate on rotation; `https_only_cookies=true` by default in production; refuse to start without `SESSION_SECRET` | Confirmed | Medium |
| T-011 | Authentication | Spoofing | Static bearer keys with no expiry, no MFA and no IdP; the approver key in CI or password stores is a single factor | A key leak gives full scanner or approver capability until someone manually rotates it | SSO/OIDC with MFA for UI users; short-lived, scoped tokens for CI; key expiry and rotation policy | Confirmed (design gap) | Medium |
| T-012 | Data store (`data/`) | Information Disclosure | Reports, raw tool output and `checkpoints.sqlite` hold code snippets and exploitable vulnerability details, unencrypted at rest with **no retention or deletion** | A host, backup or volume compromise exposes a vulnerability map of every repo scanned | Encrypt the volume; set a retention TTL with secure deletion; minimize stored snippets; restrict file permissions | Confirmed | Medium |
| T-013 | Authorization model | Information Disclosure | There is no per-project scoping: any `viewer` can list and download every scan, including CLI scans (the CLI writes to the same `data/`) | Users see vulnerabilities in repositories they have no access to | Project/team ownership on scans; filter `list_scans` and all reads by ownership; keep CLI output separate from the server store | Confirmed | Medium |
| T-014 | Redaction | Information Disclosure | SAST snippets (±4 lines) are redacted only by the regex list in `security.redact`. Secret formats it doesn't recognise (custom tokens, DSNs without a keyword) survive into reports, PDFs, SARIF uploaded to GitHub, and the LLM prompt | Secrets leak to report readers and GitHub code scanning | Mask every line that Gitleaks flagged in all findings; add entropy-based redaction; strip snippets from SARIF | Confirmed (weakness); exploitation Hypothetical | Medium |
| T-015 | LLM fix generation (TB7) | Tampering | Repo content (comments, strings) carries a prompt injection that steers the *fix*, e.g. a subtly backdoored "fix" or "no change required". Small local models follow fencing unreliably | An approver accepts a malicious or ineffective fix, believing it's policy-backed | Show fixes as a diff against the original; re-scan the proposed code with Semgrep before display; mark AI text clearly; require tests (SCP-12.2); add an injection-heuristic flag | Hypothetical (one canary resisted in testing) | Medium |
| T-016 | RAG policy store | Tampering | Policy chunks are placed in the prompt as trusted guidance, without fencing or integrity checks; anyone able to write to `policies/` (or the mounted volume) can poison the guidance; `POST /api/policies/reload` takes effect immediately | Systematically unsafe advice that appears policy-compliant | Version-control `policies/` with review and signing; hash-pin the corpus and show the policy version in reports; treat policy text as data in the prompt | Confirmed (trust assumption) | Low |
| T-017 | Ollama runtime (TB5) | Spoofing / Tampering | The Ollama API has no authentication; any local process (or any container on the compose network) can pull or replace a model with the same name, or read prompts; the compose file uses `ollama/ollama:latest` | Poisoned model output, or disclosure of the code snippets sent in prompts | Isolate Ollama on a dedicated internal network or a socket; pin the image and model digests; verify the model digest before use (`/api/show`) | Hypothetical (needs host or network foothold) | Medium |
| T-018 | Webhook (TB3) | Spoofing / DoS | No replay protection (`X-GitHub-Delivery` isn't tracked, no timestamp window) and no repository allow-list beyond the host check | A captured signed delivery can be replayed to trigger repeated scans | Store and reject duplicate delivery IDs; allow-list the repositories; verify the `X-GitHub-Hook-ID` | Confirmed | Low |
| T-019 | Scan queue / webhook | Denial of Service | When 6 scans are active, `_submit` returns 429; GitHub doesn't retry webhooks automatically, so push scans are **silently skipped**; the queue lives in memory and is lost on restart | Pushes go unscanned during bursts, with no alert | Persistent job queue (DB/Redis) with retry; alert on dropped events; record "not scanned" status in a GitHub check | Confirmed | Medium |
| T-020 | Scan engine | Denial of Service | Repo size is checked only *after* the clone (up to 300 s); each tool may run 600 s; up to 10 LLM calls × 120 s. With 2 workers, one `scanner` user can tie up the service with large public github.com repos | Legitimate scans are starved | Per-principal scan quotas; pre-clone size check through the GitHub API; total per-scan time budget; separate LLM worker pool | Confirmed | Medium |
| T-021 | Scanner parsers (TB4) | Elevation of Privilege | The Semgrep, Trivy and Gitleaks parsers process attacker-controlled files in the **same container and user** as the API, which can read `.env`-derived settings, `data/` and the session secret in memory | A parser RCE becomes full compromise of the scan service and all reports | Run scanners in an ephemeral sandbox (separate container, no network, read-only mount, seccomp/gVisor) with only the result passed back | Hypothetical (no known CVE in pinned versions) | Medium |
| T-022 | Build & runtime supply chain | Tampering | Base image `python:3.12-slim` and `ollama/ollama:latest` aren't digest-pinned; Python deps aren't hash-pinned; `install_tools.sh` downloads the checksums from the same release as the binaries (no signature check) | A compromised upstream ships into the scanner image | Digest-pin the images; `--require-hashes`; verify cosign/GPG signatures for Trivy and Gitleaks; SBOM plus a self-scan of the image | Confirmed | Medium |
| T-023 | Semgrep registry (TB8) | Tampering / DoS | Registry rules are fetched live (unpinned). If egress is blocked or tampered with, Semgrep **silently falls back** to the 12 bundled rules; the scan still reports `ok` and the CLI exit code can be 0 | Detection coverage drops sharply without anyone noticing; the gate passes | Vendor pinned rule snapshots; make the fallback a visible warning and a non-zero exit in CI (`--strict`); record the rule-set hash in the report | Confirmed | Medium |
| T-024 | Transport | Information Disclosure | The app serves plain HTTP; TLS depends on a reverse proxy that isn't provided or documented (M2). The HSTS header is ineffective without TLS | Keys and session cookies are exposed in transit if the service is deployed without the proxy | Ship a reference proxy config (Caddy/nginx) with TLS 1.2+; refuse non-local binds unless `https_only_cookies=true`; document mTLS for CI clients | Confirmed (gap) | Medium |
| T-025 | Approval endpoint | Tampering | Concurrent approvals: both requests pass `is_waiting_for_approval` and each call `resume_with_decisions` on the same thread with no lock, so the second can apply stale decisions to a new interrupt | Inconsistent approval state or audit trail | Per-scan lock or optimistic version check (checkpoint ID) before resuming | Hypothetical | Low |
| T-026 | API error handling | Information Disclosure | `create_scan` returns exception text to the caller (e.g. the installed-model list, path-validation details) | Minor reconnaissance by authenticated users | Return generic messages and log details server-side | Confirmed | Low |
| T-027 | Logout / rate-limit memory | DoS | `/api/auth/logout` has no CSRF header check (SameSite=Strict mitigates it); the bucket dictionary grows without bound per client IP | Forced logout in edge cases; slow memory growth | Require the CSRF header on logout; evict idle buckets | Confirmed | Low |

**Additional threats considered and found adequately mitigated** (residual risk is low):
- **Command injection.** Argument lists everywhere, no `shell=True`, and `git_ref` limited by a regex.
- **Path traversal on local scans.** `validate_local_path` resolves the path and checks containment; snippet reads check containment too.
- **SSRF through git URLs.** https only, host allow-list, credentials, ports and queries rejected, `protocol.file.allow=never`.
- **XSS.** The UI renders only with `textContent`, under a strict CSP with no inline script; PDF text is XML-escaped.
- **Malicious `setup.py`.** pip-audit runs with `--no-deps --disable-pip`, so nothing from the repo is installed or executed.
- **Webhook forgery.** HMAC-SHA256 with a constant-time compare.
- **Brute-forcing API keys.** Keys are 256-bit random and login is rate-limited.
- **SQL injection.** There is no SQL built from input; SQLite is used only by the LangGraph checkpointer.

---

## 7. Detailed attack scenarios (High-risk threats)

### T-001: The repository disables its own scan
- **Component:** `securescan/scanners/__init__.py` (`run_gitleaks`, `run_trivy`, `run_semgrep`)
- **Category:** Tampering
- **Scenario:**
  1. A developer under deadline pressure (or a malicious insider) commits `.trivyignore` listing CVE IDs, a `.gitleaks.toml` with `[allowlist] paths = ['.*']`, and `# nosemgrep` on the vulnerable lines.
  2. On push, SecureScan runs each tool with `cwd=<repo>`. Trivy loads `.trivyignore` and `trivy.yaml` from the working directory by default; `run_gitleaks` explicitly `extend`s the repo's `.gitleaks.toml`; Semgrep honors `nosemgrep`.
  3. The report shows 0 findings and the build passes.
- **Preconditions:** The ability to commit to the scanned repo, which is the normal position of any developer.
- **Impact:** Vulnerable dependencies, injection flaws and committed secrets reach production; the security team is misled.
- **Existing controls:** None specific. Suppressions aren't reported.
- **Mitigations:** See the register. Priority action: run tools from a neutral `cwd`, with explicit SecureScan-owned config and ignore files and the `--disable-nosem` / `--ignore-gitleaks-allow` flags. Then implement an *approved suppressions* file owned by the security team, and report every suppression found in the repo as an INFO finding.

### T-002 / T-003: CI scanner substitution and supply chain
- **Component:** `.github/workflows/securescan.yml`, step "Get SecureScan AI"
- **Category:** Elevation of Privilege / Tampering
- **Scenario A (T-002):** The target repo adds a file `securescan/cli.py` containing `import sys; sys.exit(0)`. The workflow sees the file, sets `SECURESCAN_HOME=$GITHUB_WORKSPACE`, installs the repo's `requirements.txt` and runs the repo's fake CLI. The gate always passes, and arbitrary code runs with the job token.
- **Scenario B (T-003):** An attacker who obtains write access to the SecureScan repo (or a typosquatted or compromised PyPI dependency) pushes a change. Every consumer pipeline clones HEAD on its next push and executes it.
- **Preconditions:** A: commit access to the target repo. B: compromise of the SecureScan repo, a maintainer, or an unpinned upstream.
- **Impact:** Every pipeline's results are falsified; the integrity of the code-scanning alerts that the token is allowed to upload is lost.
- **Existing controls:** Actions are pinned by SHA; `permissions` follow least privilege; `persist-credentials: false`.
- **Mitigations:** Detect self-scanning by `github.repository == '<org>/securescan-ai'`. Pin `SECURESCAN_REPO` to a commit SHA or signed tag, or distribute a digest-pinned container image or a reusable workflow referenced by SHA. Use hash-pinned requirements.

### T-005 / T-006: Unattributable and unchecked approvals
- **Component:** `/api/auth/login`, `/api/scans/{id}/approvals`, `scripts/setup_keys.py`
- **Category:** Repudiation / Elevation of Privilege
- **Scenario:** Three engineers share the one approver key. One of them signs in with the display name "SecurityLead" and bulk-approves all 46 Critical/High fixes of a scan they started themselves. The report shows "approved by SecurityLead (approver)". Nobody can determine who actually acted.
- **Preconditions:** Possession of the shared approver key.
- **Impact:** The approval control required by SCP-12.1 is ineffective, and there's no accountability during incident review.
- **Existing controls:** RBAC on the approval endpoint; an audit record per decision (but only with the self-asserted or role name).
- **Mitigations:** Per-user identities (OIDC/SSO, or per-user keys with a key ID in the audit log); an identity-derived display name; no self-approval; two approvers for Critical; a confirmation step for bulk actions.

---

## 8. Security control evaluation

| Control area | Rating | Evidence | Gap / recommendation |
|---|---|---|---|
| Authentication | Partial | Hashed keys, constant-time compare, HttpOnly + SameSite=Strict cookie, login throttle | Shared role keys, no MFA/SSO, no expiry, no server-side revocation (T-005, T-010, T-011) |
| Authorization | Partial | RBAC on every route, server-side, deny by default | No project/tenant scoping; no separation of duties (T-006, T-013) |
| Input validation | Strong | Pydantic schemas, path containment, git URL allow-list, UUID and model allow-list | Repo-supplied *tool configuration* isn't treated as input (T-001) |
| Encryption in transit | Weak / undocumented | HSTS header only | No TLS in the app and no reference proxy (T-024) |
| Encryption at rest | Missing | — | `data/` holds sensitive findings in plaintext (T-012) |
| Network segmentation | Partial | Ollama not published in compose; API bound to localhost | Scanners, API and Ollama share one trust zone (T-017, T-021) |
| API security | Strong | CSP, CSRF header, no docs exposed, generic 500 errors, body cap | Minor error-text leakage; logout CSRF (T-026, T-027) |
| Logging & monitoring | Partial | Structured JSON audit of logins, scans, approvals, webhooks, denials | Local only; not tamper-evident; reads not audited; no alerting (T-008) |
| Secrets management | Partial | Hashes only, `.env` git-ignored, child processes get a minimal env, double redaction | Plaintext `.env` on the host; regex-based redaction misses formats (T-014) |
| Rate limiting / DoS | Partial | Per-IP limits, concurrency cap, per-tool timeouts | Broken behind a proxy; webhook drops; long scans (T-009, T-019, T-020) |
| Least privilege | Partial | Non-root container, `cap_drop: ALL`, read-only root FS, least-privilege CI token | Scanners run with API privileges; CI executes repo-chosen code (T-002, T-021) |
| AI / LLM safety | Partial | Local model, no tools, fenced untrusted input, JSON schema, quality gate, human approval | Fix manipulation possible; RAG corpus trusted; unauthenticated Ollama (T-015 to T-017) |
| Supply chain | Partial | Pinned versions, actions pinned by SHA, binary checksums, self-scan clean | Unpinned SecureScan clone, images and registry rules; no hashes or signatures (T-003, T-022, T-023) |
| Result integrity | Weak | Unkeyed SHA-256 in the report | Repo-controlled suppression and an unsigned report (T-001, T-007) |

---

## 9. Prioritized remediation plan

| Priority | Action | Threats | Effort |
|---|---|---|---|
| P1 (now) | Neutral `cwd` plus SecureScan-owned `--config` / `--ignorefile`; `--disable-nosem`, `--ignore-gitleaks-allow`; report suppressions | T-001 | S |
| P1 | Fix CI self-detection (`github.repository`); pin `SECURESCAN_REPO` to a SHA or signed tag; `--require-hashes` | T-002, T-003 | S |
| P1 | Remove the default `samples,tests` excludes for consumer repos; make Semgrep's fallback to offline rules visible and failing in CI | T-004, T-023 | S |
| P2 (next) | Per-user identity (OIDC or per-user keys with a key ID); identity-derived names; no self-approval; two-person approval for Critical | T-005, T-006, T-011 | M |
| P2 | HMAC-signed reports, verified before render/serve; hash-chained audit log shipped to a SIEM; audit report reads | T-007, T-008 | M |
| P2 | Proxy-aware, per-principal rate limiting; persistent job queue with retry; per-user scan quota; pre-clone size check | T-009, T-019, T-020 | M |
| P2 | Server-side sessions with revocation; secure cookies by default in production; refuse to start without `SESSION_SECRET` | T-010 | S |
| P3 (planned) | Project-scoped authorization; encryption at rest and a retention TTL; stronger redaction (mask Gitleaks lines everywhere) | T-012, T-013, T-014 | M |
| P3 | Sandbox scanners in ephemeral containers; isolate Ollama; digest-pin images and models; signature-verify tool downloads | T-017, T-021, T-022 | L |
| P3 | Show fixes as diffs re-scanned by Semgrep; versioned, signed policy corpus with its version in reports | T-015, T-016 | M |
| P4 | Webhook delivery-ID dedup and repo allow-list; per-scan approval lock; generic errors; CSRF on logout | T-018, T-025, T-026, T-027 | S |

*Effort: S < 1 day, M = 1–5 days, L > 1 week.*

---

## 10. Assumptions and out of scope

- The threats were modeled against the code and configuration in this repository as of 2026-10-07; no production deployment was available for review (see M1 and M2).
- Vulnerabilities inside third-party tools (Semgrep, Trivy, Gitleaks, Ollama, FastAPI) are covered only as classes of risk (T-021, T-022), not as specific CVEs.
- Physical security, OS hardening of the host, and GitHub organization settings are out of scope.
- No architecture changes have been made. All mitigations above are recommendations that need approval before implementation.
