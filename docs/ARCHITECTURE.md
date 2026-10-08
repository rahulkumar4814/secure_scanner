# SecureScan AI — Secure Architecture & Build Plan

## 1. Goal

An AI agent that scans a **Python / Node.js** source repository for known
vulnerabilities, normalizes and prioritizes the results, recommends code fixes
grounded in the **company secure-coding policy (RAG)**, asks a **human to approve
fixes for Critical/High** findings, and produces **JSON + PDF** reports. It runs
from an interactive web UI, a CLI, and a CI/CD pipeline (every `push` to GitHub).

## 2. High-level architecture

```
                 ┌──────────────────────────── Trust boundary: SecureScan host ───────────────────────────┐
 Browser (UI) ──►│ FastAPI                                                                                 │
 CI (CLI/API) ──►│  ├─ Security middleware: headers/CSP · rate-limit · body-size cap · audit log           │
 GitHub webhook─►│  ├─ AuthN/AuthZ: API keys (hashed, RBAC viewer/scanner/approver) · session cookie       │
                 │  │               · HMAC-SHA256 webhook signature                                        │
                 │  └─ Routes: /api/scans · /api/models · /api/scans/{id}/approve · /webhook/github       │
                 │                       │                                                                 │
                 │                       ▼                                                                 │
                 │  LangGraph agent (state machine, checkpointed)                                          │
                 │   prepare_source → detect_languages → run_scanners → normalize → prioritize             │
                 │   → retrieve_policy (RAG) → recommend_fixes (LLM) → human_approval (interrupt) → report  │
                 │        │                    │                         │                                 │
                 │        ▼                    ▼                         ▼                                 │
                 │  Sandboxed subprocesses   Policy store (RAG)     Ollama (localhost only)                │
                 │  semgrep · pip-audit      policies/*.md → chunks  model chosen at runtime               │
                 │  trivy  · gitleaks        BM25 / Ollama embeds    (GET /api/tags)                       │
                 │  (no shell, timeouts,                                                                    │
                 │   clean env, read-only)                                                                  │
                 │                       ▼                                                                 │
                 │  Report store: data/scans/<uuid>/ {report.json, report.pdf}                             │
                 └─────────────────────────────────────────────────────────────────────────────────────────┘
```

### Agent graph (LangGraph)

| Node | Responsibility |
|---|---|
| `prepare_source` | Validate the target: local path inside `ALLOWED_SCAN_ROOT`, or an `https://` git URL on an allow-listed host → shallow clone with hooks disabled, into a temp dir. |
| `detect_languages` | Find Python (`*.py`, `requirements*.txt`, `pyproject.toml`) and Node (`package.json`, lockfiles). |
| `run_scanners` | Run applicable tools: **Semgrep** (SAST), **pip-audit** (Python SCA), **Trivy** (SCA for npm and pip), **Gitleaks** (secrets, `--redact`). |
| `normalize` | Convert every tool's output into one `Finding` schema and de-duplicate across tools (e.g. the same CVE reported by pip-audit and Trivy). |
| `prioritize` | Compute a risk score from severity, CVSS, fix availability, category (secret > SCA > SAST), and confidence. Map to Critical/High/Medium/Low. |
| `retrieve_policy` | RAG: for each top finding, retrieve the matching sections of the company secure-coding policy. |
| `recommend_fixes` | Local LLM (Ollama) writes a fix that cites the retrieved policy. Code is passed as *untrusted data*, secrets are redacted, and the output must be strict JSON. Falls back to deterministic policy-based advice if no LLM is available. |
| `human_approval` | `interrupt()` pauses the graph when Critical/High fixes exist. A user with the **approver** role approves or rejects each fix, then the graph resumes. In CI, these fixes are marked `pending_approval`. |
| `report` | Write JSON and PDF reports with the approval status of each fix. |

## 3. Security controls by layer

| Layer | Threat | Control |
|---|---|---|
| **Network / transport** | Eavesdropping, exposure | Binds to `127.0.0.1` by default; TLS goes on a reverse proxy; HSTS header; Ollama is only reached on localhost. |
| **Authentication** | Unauthorized use | API keys are stored only as SHA-256 hashes in env and compared in constant time. The UI logs in once and gets a signed, `HttpOnly`, `SameSite=Strict` session cookie. GitHub webhooks are verified with HMAC-SHA256 (`X-Hub-Signature-256`). |
| **Authorization** | Privilege misuse | RBAC: `viewer` (read reports), `scanner` (start scans), `approver` (approve or reject Critical/High fixes). Approval is enforced on the server. |
| **Web / API** | XSS, clickjacking, CSRF | Strict CSP with no inline script; `X-Frame-Options: DENY`; `nosniff`; the UI renders with `textContent` only. Requests that change state need the SameSite cookie plus a custom header, which blocks CSRF. |
| **Input validation** | Path traversal, SSRF, injection | Pydantic schemas; local paths are resolved and must stay inside `ALLOWED_SCAN_ROOT`; git URLs must be `https` on an allow-listed host and match a strict regex; scan IDs must be UUIDs; model names are checked against Ollama's model list. |
| **Execution** | Command injection, malicious repos | Subprocesses take argument lists (never `shell=True`), with timeouts and a minimal environment. Clones run with `core.hooksPath` disabled, `--depth 1`, and `--no-recurse-submodules`. Scanned code is never executed. Repo size and file count are capped. |
| **DoS** | Resource exhaustion | Per-client rate limits, request body size cap, limit on concurrent scans, per-tool timeout. |
| **AI / LLM** | Prompt injection, data leakage | The LLM runs locally (no code leaves the host) and has no tools or actions, so it can only produce text. Snippets are fenced and labeled untrusted; secrets are redacted before prompting; output is parsed as JSON against a schema; fixes for Critical/High findings need a human to approve them before anyone treats them as approved. |
| **Data** | Secret exposure, tampering | Gitleaks `--redact`, plus a second redaction pass on every snippet. Reports go under `data/` with UUID file names. Each report carries a SHA-256 integrity hash. No secrets are logged. |
| **Audit** | Repudiation | A structured audit log (`data/audit.log`) records every login, scan, approval and webhook: who, what, when, and from which IP. |
| **Supply chain** | Vulnerable dependencies | Pinned `requirements.txt`, and the CI workflow scans this repository with itself. |
| **Container** | Escape, persistence | Non-root user, `read_only` root filesystem, `cap_drop: ALL`, `no-new-privileges`, tmpfs for scratch space. |

## 4. Build plan

1. Project skeleton, configuration (`pydantic-settings`), and security primitives.
2. Scanner adapters and the sandboxed subprocess runner.
3. Normalizer and prioritizer.
4. RAG policy store and the sample company secure-coding policy.
5. LLM layer (dynamic Ollama model) with a deterministic fallback.
6. LangGraph agent with human-in-the-loop interrupt and checkpointing.
7. JSON and PDF report generators.
8. FastAPI app (auth, RBAC, webhook, API) and the interactive UI.
9. CLI for CI/CD, with exit codes based on a severity threshold.
10. GitHub Actions workflow, Dockerfile, docker-compose.
11. Deliberately vulnerable sample repo, tests, README.
