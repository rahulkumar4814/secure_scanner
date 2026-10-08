# SecureScan AI

An AI agent that scans **Python** and **Node.js** source repositories for known vulnerabilities. It
combines SAST, SCA and secret scanning, normalizes and prioritizes the results, and recommends code
fixes based on your **company secure-coding policy (RAG)**. A **human must approve** fixes for
Critical/High findings. Results come out as **JSON / PDF / SARIF** reports. It runs from a web UI, a
CLI, or your **CI/CD pipeline on every push**.

| Capability | How |
|---|---|
| SAST | **Semgrep** (registry rulesets + bundled offline rules in `rules/semgrep/`) |
| SCA | **pip-audit** (Python) + **Trivy** (npm and pip lockfiles), merged and de-duplicated |
| Secret scanning | **Gitleaks** (secrets are redacted everywhere) |
| Orchestration | **LangGraph** state machine with checkpointing and a human-in-the-loop `interrupt()` |
| AI | **LangChain** + **Ollama**, local only. The model is picked **at runtime** from what's installed |
| RAG | Company policy in `policies/` (`.md`/`.txt`/`.pdf`), with BM25 or Ollama-embedding retrieval |
| UI / API | **FastAPI** with an interactive single-page UI |
| Reports | JSON (with SHA-256 integrity hash), PDF, SARIF (GitHub Security tab), Markdown summary |
| CI/CD | GitHub Actions workflow + GitHub push webhook + generic CLI with exit codes |

---

## 1. Architecture

```
 Browser UI / CI CLI / GitHub webhook
            │  (API key or session cookie · RBAC · CSRF · rate-limit · HMAC webhook)
            ▼
        FastAPI ──► LangGraph agent (checkpointed in SQLite)
                     prepare_source → detect_languages → run_scanners → normalize → prioritize
                     → retrieve_policy (RAG) → recommend_fixes (LLM) → build_report ⇄ human_approval
                         │                         │                          │
             sandboxed subprocesses        policies/*.md index       Ollama on localhost
             semgrep · pip-audit           (BM25 / embeddings)       model chosen at runtime
             trivy · gitleaks
```

The full secure design (threats, and the controls at each layer) is in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

### How the agent works, step by step

1. **prepare_source**: checks that a local path stays inside `ALLOWED_SCAN_ROOT`, or shallow-clones an
   allow-listed `https://` git URL with git hooks and submodules disabled.
2. **detect_languages**: looks for Python and Node.js files and manifests.
3. **run_scanners**: runs Semgrep, Trivy, Gitleaks and pip-audit in parallel, with timeouts and no shell.
4. **normalize**: converts every tool's output into one `Finding` schema. The same CVE reported by
   pip-audit and Trivy becomes **one** finding (`detected_by: [trivy, pip-audit]`).
5. **prioritize**: gives each finding a risk score (0-100) from severity/CVSS, category (a leaked
   secret ranks above SCA, which ranks above SAST), high-impact CWE, fix availability, and how many
   tools confirmed it. The score maps to Critical/High/Medium/Low.
6. **retrieve_policy**: pulls the relevant sections of your secure-coding policy for each finding (RAG).
7. **recommend_fixes**: the local LLM writes a fix for SAST and secret findings that cites the policy
   (e.g. `SCP-02.1`). Dependency upgrades use the fixed version from the advisory (deterministic, so the
   LLM can't hallucinate a version). With no LLM available, it falls back to vetted policy examples.
8. **build_report**: writes JSON, PDF and SARIF reports.
9. **human_approval**: Critical/High fixes are marked `pending_approval`, and the graph **pauses**.
   An *approver* approves or rejects each fix in the UI (or in the terminal with `--approve`). The graph
   resumes and regenerates the reports with the decisions, who made them, and their comments. In CI
   there is no human, so these fixes stay `pending_approval` and the build is gated by `--fail-on`.

---

## 2. Quick start (local, about 10 minutes)

### Prerequisites

| Tool | Install |
|---|---|
| Python 3.11+ | https://python.org |
| Semgrep, pip-audit | installed by `pip install -r requirements.txt` |
| Trivy | `winget install AquaSecurity.Trivy` · `brew install trivy` · Linux: `scripts/install_tools.sh` |
| Gitleaks | `winget install Gitleaks.Gitleaks` · `brew install gitleaks` · Linux: `scripts/install_tools.sh` |
| Ollama (optional, for AI fixes) | https://ollama.com, then `ollama pull llama3.2:3b` |

### Step 1: install

```bash
python -m venv .venv
```
Activate it with `.venv\Scripts\activate` (Windows) or `source .venv/bin/activate` (macOS/Linux), then:
```bash
pip install -r requirements-dev.txt
```

### Step 2: create API keys (three roles)

```bash
python scripts/setup_keys.py
```
This prints a **viewer**, a **scanner** and an **approver** key **once**, and writes only their
SHA-256 hashes (plus a session secret and a webhook secret) to `.env`. Keep the keys in your password
manager. `.env` is git-ignored. Re-run the script to rotate all keys.

| Role | Can do |
|---|---|
| viewer | see scans and download reports |
| scanner | everything a viewer can do, plus start scans |
| approver | everything a scanner can do, plus approve or reject Critical/High fixes and reload policies |

### Step 3: start the UI

```bash
python -m securescan.cli serve
```
Open http://127.0.0.1:8000 and sign in with the **approver** key.

### Step 4: run the demo scan

1. **New scan**: choose `samples/vulnerable-app`, a deliberately vulnerable Flask + Express app.
2. Pick an **AI model**. The list comes live from Ollama. Or choose *No LLM* for fast policy-based fixes.
3. Click **Run security scan** and watch the agent pipeline move step by step.
4. In **Results**: look at the summary cards, filter findings, expand one to see the redacted code
   snippet, the AI fix and the policy references.
5. **Human approval**: choose Approve or Reject on Critical/High fixes (there are bulk buttons), add a
   comment, then **Submit decisions**. The reports are regenerated with your name and decision.
6. Download the **JSON** and **PDF** reports.

The demo app also contains a *prompt-injection canary*: a code comment telling the AI to "ignore
previous instructions". SecureScan treats code as data, so the canary has no effect.

### Step 5 (optional): CLI

```bash
python -m securescan.cli models
```
```bash
python -m securescan.cli scan samples/vulnerable-app --fail-on high --out securescan-reports
```
```bash
python -m securescan.cli scan samples/vulnerable-app --model llama3.2:3b --approve
```
- With no `--model` in a terminal, the CLI lists the installed Ollama models and **asks** which one to use.
- `--approve` lets you approve or reject Critical/High fixes interactively in the terminal.
- Exit codes: `0` = OK, `1` = findings at or above `--fail-on`, `2` = scan error.
- Outputs: `securescan-report.json`, `.pdf`, `.sarif`, `securescan-summary.md`.

### Run the tests

```bash
python -m pytest -q
```
The 34 tests cover redaction, path traversal, SSRF, RBAC, CSRF, webhook HMAC, prompt-injection
fencing, normalization and dedup, RAG, and the full LangGraph run with pause and resume for approval.

---

## 3. CI/CD integration (easy guide)

The full guide is in [docs/CICD_GUIDE.md](docs/CICD_GUIDE.md). The same guide is in the UI under the
**CI/CD guide** tab.

### Option A: GitHub Actions (scan on every push)

1. Copy [`.github/workflows/securescan.yml`](.github/workflows/securescan.yml) into your repository.
2. In your repo, go to **Settings → Secrets and variables → Actions → Variables** and add:
   - `SECURESCAN_REPO`: git URL of this SecureScan project (not needed when scanning SecureScan itself).
   - `SECURESCAN_MODEL` (optional): e.g. `llama3.2:3b` to get AI fixes in CI. Leave it empty for
     fast deterministic fixes.
   - `SECURESCAN_EXCLUDE_DIRS` (optional): e.g. `tests,fixtures`.
3. Push. Every push and pull request then:
   - runs all four scanners,
   - **fails the build** on Critical findings (change `FAIL_ON` to `high` for a stricter gate),
   - uploads **SARIF** to the GitHub **Security → Code scanning** tab,
   - uploads the JSON/PDF reports as a build **artifact**, and writes a summary to the job page.

### Option B: GitHub webhook to the SecureScan server

1. Run the server where GitHub can reach it, behind TLS (see §5).
2. In GitHub, go to **Settings → Webhooks → Add webhook**:
   - Payload URL: `https://<your-host>/api/webhook/github`
   - Content type: `application/json`
   - Secret: the `SECURESCAN_GITHUB_WEBHOOK_SECRET` value from `.env`
   - Events: **Just the push event**
3. Every push now triggers a scan of that branch. It appears under **Scans**, and approvers review the
   Critical/High fixes in the UI. The signature is verified with HMAC-SHA256, and unsigned calls are
   rejected and logged.

### Other CI systems (GitLab CI, Jenkins, Azure DevOps)

```bash
pip install -r requirements.txt && bash scripts/install_tools.sh
python -m securescan.cli scan . --no-llm --fail-on critical --out securescan-reports
```
Publish `securescan-reports/` as a build artifact. A non-zero exit code fails the pipeline.

---

## 4. Security controls by layer

| Layer | Controls |
|---|---|
| Transport | Binds to `127.0.0.1` by default; TLS terminates at a reverse proxy; HSTS; the Ollama URL **must** be local (enforced in config) |
| Authentication | API keys stored only as SHA-256 hashes and compared in constant time; UI login gives a signed `HttpOnly`, `SameSite=Strict` cookie with a 1-hour lifetime; login rate-limited to 10/min per IP |
| Authorization | RBAC `viewer < scanner < approver`, enforced server-side on every route, deny by default |
| Web | Strict CSP (no inline script), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, COOP/CORP; CSRF via the custom-header requirement; UI renders only with `textContent`; no API docs exposed |
| Input validation | Pydantic schemas; path containment (no traversal or symlink escape); git URL must be `https` on an allow-listed host with no credentials, port or query (SSRF); UUID scan IDs; model names must be in Ollama's installed list |
| Execution | Argument lists with `shell=False`; per-tool timeouts; minimal child environment (app secrets aren't inherited); git clone with hooks, file protocol, symlinks and submodules disabled; size and file-count limits; pip-audit runs with `--no-deps --disable-pip`, so a malicious `setup.py` never runs; **scanned code is never executed** |
| AI / LLM | Local model (code never leaves the host); the LLM has **no tools**; code is fenced as untrusted data, and fence-breaking is neutralized; secrets are redacted before prompting; JSON-only output, validated, with a quality gate; humans approve Critical/High fixes |
| Data | Gitleaks `--redact`, plus a second redaction pass on every snippet, description, LLM output and audit record; report SHA-256 integrity hash; secrets never logged |
| Audit | `data/audit.log` (JSON lines) records logins, failed logins, authz denials, scans, approvals, downloads and webhooks |
| Availability | Per-IP rate limiting, 1 MB body cap, concurrent-scan cap and queue limit, tool timeouts |
| Supply chain | Pinned Python dependencies; CI actions pinned to commit SHAs; scanner binaries checksum-verified; **SecureScan scans itself in CI** |
| Container | Non-root user, read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, PID and memory limits, Ollama not exposed to the host |

---

## 5. Deploy with Docker

```bash
python scripts/setup_keys.py
docker compose up -d --build
docker compose exec ollama ollama pull llama3.2:3b
```
The UI is at http://127.0.0.1:8000. For a shared or production setup, put a TLS reverse proxy (nginx,
Caddy, or a cloud load balancer) in front, set `SECURESCAN_HTTPS_ONLY_COOKIES=true`, and keep the
port bound to localhost or a private network.

---

## 6. Configuration (`.env`, all prefixed `SECURESCAN_`)

| Variable | Default | Purpose |
|---|---|---|
| `VIEWER/SCANNER/APPROVER_KEY_HASHES` | none | Comma-separated SHA-256 hashes of API keys |
| `SESSION_SECRET` | random per start | Signs session cookies |
| `GITHUB_WEBHOOK_SECRET` | none | HMAC secret for `/api/webhook/github` |
| `ALLOWED_SCAN_ROOT` | `./samples` | Local repos must be inside this directory |
| `ALLOWED_GIT_HOSTS` | `github.com` | Hosts allowed for git URL scans |
| `EXCLUDE_DIRS` | none | Extra directories to skip |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Must be local |
| `OLLAMA_MODEL` | none | Default model (empty = choose at runtime) |
| `OLLAMA_EMBED_MODEL` | none | e.g. `nomic-embed-text` for vector RAG (default is BM25) |
| `LLM_MAX_FINDINGS` | `10` | Maximum LLM calls per scan |
| `MAX_CONCURRENT_SCANS` | `2` | Scan worker threads |

### Using your own secure-coding policy

Put your policy files (`.md`, `.txt` or `.pdf`) in `policies/`. Give each control an id like
`SCP-02.1` so that fixes can cite it. Then restart the server, or call
`POST /api/policies/reload` as an approver.

---

## 7. Project layout

```
securescan/
  config.py         settings (env), local-only Ollama guard
  security.py       key hashing, redaction, validation, sandboxed subprocess, audit log
  models.py         Finding / FixRecommendation / request schemas
  scanners/         semgrep, pip-audit, trivy, gitleaks adapters
  normalizer.py     tool output → Finding, cross-tool de-duplication
  prioritizer.py    risk scoring
  rag/              policy loading, chunking, BM25 / embedding retrieval
  llm.py            Ollama model discovery, hardened prompt, JSON parsing, fallback fixes
  agent/graph.py    LangGraph agent + human-in-the-loop
  reports/          JSON + PDF
  web/              FastAPI app, UI (templates/, static/)
  cli.py            CLI for local use and CI/CD (SARIF, exit codes, step summary)
policies/           company secure-coding policy (RAG source)
rules/semgrep/      bundled offline Semgrep rules
samples/            deliberately vulnerable demo app (fake secrets)
.github/workflows/  CI pipeline
docs/               architecture and CI/CD guide
tests/              pytest suite
```

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| Semgrep tool note says "used bundled offline rules" | The Semgrep registry was unreachable. Allow `semgrep.dev`, or rely on the offline rules |
| pip-audit "not pinned" errors | pip-audit only audits `==` pinned requirements (it never installs them). Pin them, or rely on Trivy |
| No AI models in the dropdown | Start Ollama (`ollama serve`) and `ollama pull llama3.2:3b` |
| Trivy's first run is slow | It downloads its vulnerability database once; CI caches it |
| Login says "Invalid API key" | Re-run `scripts/setup_keys.py` and restart the server (`.env` is read at start) |
