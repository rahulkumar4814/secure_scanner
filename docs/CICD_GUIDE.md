# CI/CD Integration Guide

SecureScan AI can scan every push in two ways:

| | A. GitHub Actions | B. Webhook to the SecureScan server |
|---|---|---|
| Where the scan runs | GitHub runner | Your SecureScan server |
| Breaks the build | Yes (`--fail-on`) | No (reports in the UI) |
| Human approval of Critical/High fixes | Recorded as *pending* in the report | In the UI by an *approver* |
| Results | SARIF → Security tab, artifacts, job summary | UI, JSON and PDF |
| Best for | Gating merges | Central security team review |

Many teams use both: **A** to gate pull requests, and **B** so the security team can triage and approve
fixes.

---

## A. GitHub Actions

### 1. Add the workflow
Copy `.github/workflows/securescan.yml` into the repository you want to scan, at the same path.

### 2. Tell the workflow where SecureScan lives
Go to **Settings → Secrets and variables → Actions → Variables → New repository variable**:

| Variable | Example | Required |
|---|---|---|
| `SECURESCAN_REPO` | `https://github.com/your-org/securescan-ai.git` | yes (unless you vendor the tool) |
| `SECURESCAN_MODEL` | `llama3.2:3b` | no. Empty means policy-based fixes (fast, no GPU needed) |
| `SECURESCAN_EXCLUDE_DIRS` | `tests,fixtures,docs` | no |

If `SECURESCAN_REPO` is private, clone it with a read-only deploy key instead of a public URL.

### 3. Pick the build-breaking threshold
In the workflow, `env.FAIL_ON` takes `critical` (default), `high`, `medium`, `low`, or `none`.

### 4. Push
Every push and pull request now:

1. checks out your code (`persist-credentials: false`),
2. installs SecureScan and the scanners (Trivy and Gitleaks binaries are **checksum-verified**),
3. optionally starts Ollama from a pinned container image and pulls the model,
4. runs `python -m securescan.cli scan … --fail-on $FAIL_ON`,
5. uploads `securescan-report.sarif` to **Security → Code scanning**,
6. uploads `securescan-reports/` (JSON, PDF, SARIF, Markdown summary) as an artifact, and
7. writes a findings table to the job summary page.

Workflow hardening: least-privilege `permissions`, every action pinned to a commit SHA, nothing piped
from the internet into a shell, and per-ref `concurrency`.

### 5. Make it required (optional)
Go to **Settings → Branches → Branch protection rule → Require status checks** and select
**SecureScan AI / securescan**. Merges are then blocked while Critical findings exist.

---

## B. GitHub webhook

### 1. Run the server reachably and securely
- Deploy with `docker compose up -d` behind a TLS reverse proxy.
- Set `SECURESCAN_HTTPS_ONLY_COOKIES=true`.
- Set `SECURESCAN_ALLOWED_GIT_HOSTS=github.com`, or your GitHub Enterprise host.
- Optionally set `SECURESCAN_OLLAMA_MODEL=llama3.2:3b` so webhook scans get AI fixes.

### 2. Configure the secret
`python scripts/setup_keys.py` writes `SECURESCAN_GITHUB_WEBHOOK_SECRET` to `.env`. Restart the
server after running it.

### 3. Add the webhook in GitHub
Go to **Repository → Settings → Webhooks → Add webhook**:
- **Payload URL**: `https://<your-host>/api/webhook/github`
- **Content type**: `application/json`
- **Secret**: the value of `SECURESCAN_GITHUB_WEBHOOK_SECRET`
- **Which events**: *Just the push event*

GitHub sends a `ping` first. SecureScan answers `202 {"pong": true}` when the signature is valid.

### 4. What happens on each push
1. SecureScan verifies `X-Hub-Signature-256` (HMAC-SHA256, constant-time). Invalid signatures get `401`
   and are written to the audit log.
2. It validates `repository.clone_url` against the host allow-list.
3. It shallow-clones the pushed branch (hooks and submodules disabled) into a temporary directory,
   scans it, then deletes the clone.
4. The scan appears under **Scans**. Approvers open **Results** and approve or reject the Critical/High
   fixes.

For a private repository, the server needs read access: give it a read-only deploy key or a git
credential helper. Never put tokens in the URL, because SecureScan rejects URLs that contain
credentials.

---

## C. Any other CI (GitLab, Jenkins, Azure DevOps, Bitbucket)

```bash
pip install -r requirements.txt
bash scripts/install_tools.sh
python -m securescan.cli scan "$CI_PROJECT_DIR" --no-llm --fail-on critical --out securescan-reports
```

GitLab CI example:
```yaml
securescan:
  image: python:3.12-slim
  before_script:
    - apt-get update && apt-get install -y git curl
    - git clone --depth 1 "$SECURESCAN_REPO" /opt/securescan
    - pip install -r /opt/securescan/requirements.txt
    - bash /opt/securescan/scripts/install_tools.sh
  script:
    - cd /opt/securescan && python -m securescan.cli scan "$CI_PROJECT_DIR" --no-llm --fail-on critical --out "$CI_PROJECT_DIR/securescan-reports"
  artifacts:
    when: always
    paths: [securescan-reports/]
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No findings at or above the threshold |
| 1 | Findings at or above `--fail-on`: fail the build |
| 2 | Scan error (bad path, tool crash): fail the build |
