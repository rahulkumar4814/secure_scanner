// SecureScan AI UI. All dynamic text is rendered with textContent (never innerHTML) to prevent XSS.
"use strict";

const STEPS = [
  ["prepare_source", "Prepare source", "Validate path / clone repo safely"],
  ["detect_languages", "Detect languages", "Python & Node.js manifests"],
  ["run_scanners", "Run scanners", "Semgrep · pip-audit · Trivy · Gitleaks"],
  ["normalize", "Normalize", "One schema, de-duplicated"],
  ["prioritize", "Prioritize", "Risk score 0-100"],
  ["retrieve_policy", "Retrieve policy (RAG)", "Company secure-coding policy"],
  ["recommend_fixes", "Recommend fixes", "Local LLM via Ollama"],
  ["build_report", "Build reports", "JSON + PDF"],
  ["human_approval", "Human approval", "Critical / High fixes"],
];
const CONTROLS = [
  ["Transport", "Local bind by default, TLS at reverse proxy, HSTS, Ollama restricted to localhost"],
  ["Authentication", "Hashed API keys (constant-time compare), HttpOnly SameSite=Strict signed session, HMAC-verified GitHub webhooks"],
  ["Authorization", "RBAC: viewer < scanner < approver; Critical/High approvals require approver role (server-side)"],
  ["Web", "Strict CSP (no inline script), X-Frame-Options DENY, nosniff, CSRF header check, textContent-only rendering"],
  ["Input", "Pydantic schemas, path containment under scan root, https + host allow-list for git (SSRF), UUID ids, model allow-list"],
  ["Execution", "No shell, argument lists, timeouts, minimal env, git hooks/submodules disabled, scanned code never executed"],
  ["AI / LLM", "Local model, no tools, code fenced as untrusted, secrets redacted, JSON-only output, human approval"],
  ["Data", "Secrets redacted (gitleaks + second pass), report SHA-256 integrity hash, audit log of every action"],
  ["Availability", "Rate limiting, body size cap, concurrent scan cap, per-tool timeouts"],
  ["Deployment", "Non-root container, read-only FS, all capabilities dropped, no-new-privileges"],
];
const YAML = `# .github/workflows/securescan.yml  (trimmed - full file in the repo)
on: { push: { branches: ["**"] }, pull_request: {} }
permissions: { contents: read, security-events: write }
jobs:
  securescan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - name: Install scanners (semgrep, pip-audit, trivy, gitleaks)
        run: ./scripts/install_tools.sh
      - name: Scan
        run: python -m securescan.cli scan "$GITHUB_WORKSPACE" --no-llm --fail-on critical --out securescan-reports
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: securescan-reports/securescan-report.sarif }
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: securescan-reports, path: securescan-reports/ }`;

const $ = (id) => document.getElementById(id);
const state = { me: null, scanId: null, report: null, meta: null, timer: null };

function el(tag, props = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const c of children) if (c != null) n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return n;
}

async function api(method, path, body) {
  const opts = { method, credentials: "same-origin", headers: { "X-Requested-With": "SecureScan" } };
  if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  const r = await fetch(path, opts);
  let data = null;
  try { data = await r.json(); } catch { /* empty body */ }
  if (!r.ok) {
    const msg = data && data.detail ? (typeof data.detail === "string" ? data.detail : data.detail.map((d) => d.msg).join("; ")) : r.statusText;
    const err = new Error(msg); err.status = r.status; throw err;
  }
  return data;
}

// ------------------------------------------------------------------ navigation
function show(view) {
  document.querySelectorAll(".view").forEach((v) => v.classList.add("hidden"));
  $(`view-${view}`).classList.remove("hidden");
  document.querySelectorAll("#nav button").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  if (view === "history") loadHistory();
}
document.querySelectorAll("#nav button").forEach((b) => b.addEventListener("click", () => show(b.dataset.view)));

// ------------------------------------------------------------------ auth
async function boot() {
  try { state.me = await api("GET", "/api/auth/me"); enterApp(); }
  catch { show("login"); }
}
$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("login-error").textContent = "";
  try {
    state.me = await api("POST", "/api/auth/login", { api_key: $("login-key").value, name: $("login-name").value });
    $("login-key").value = "";
    enterApp();
  } catch (err) { $("login-error").textContent = err.message; }
});
$("logout").addEventListener("click", async () => { await api("POST", "/api/auth/logout"); location.reload(); });

function enterApp() {
  $("nav").classList.remove("hidden"); $("who").classList.remove("hidden");
  $("who-name").textContent = `${state.me.name}`;
  if (state.me.role === "viewer") { $("scan-btn").disabled = true; $("scan-error").textContent = "Your role (viewer) can view reports but not start scans."; }
  renderPipeline($("pipeline"), null);
  renderPipeline($("arch-pipeline"), null, true);
  $("controls").replaceChildren(...CONTROLS.map(([a, b]) => el("tr", {}, el("td", { text: a }), el("td", { text: b }))));
  $("yaml-snippet").textContent = YAML;
  loadEnv();
  show("scan");
}

// ------------------------------------------------------------------ new scan
async function loadEnv() {
  try {
    const [st, tg] = await Promise.all([api("GET", "/api/status"), api("GET", "/api/targets")]);
    const items = Object.entries(st.tools).map(([t, ok]) => [t, ok]);
    items.push([`Ollama (${st.models.length} models)`, st.ollama]);
    items.push([`Policy RAG: ${st.rag_mode} · ${st.policy_chunks} chunks`, st.policy_chunks > 0]);
    $("env").replaceChildren(...items.map(([n, ok]) => el("li", {}, el("span", { class: `dot ${ok ? "ok" : "bad"}` }), n)));
    const sel = $("model");
    sel.replaceChildren(el("option", { value: "", text: "No LLM - policy-based fixes (fast)" }),
      ...st.models.map((m) => el("option", { value: m, text: m })));
    if (st.default_model && st.models.includes(st.default_model)) sel.value = st.default_model;
    else if (st.models.length) sel.value = st.models[0];
    $("local-target").replaceChildren(...tg.targets.map((t) => el("option", { value: t, text: `${tg.root}/${t}` })));
  } catch (err) { $("scan-error").textContent = err.message; }
}
document.querySelectorAll('input[name="src"]').forEach((r) => r.addEventListener("change", () => {
  const git = document.querySelector('input[name="src"]:checked').value === "git";
  $("git-wrap").classList.toggle("hidden", !git); $("ref-wrap").classList.toggle("hidden", !git);
  $("local-wrap").classList.toggle("hidden", git);
}));
$("scan-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("scan-error").textContent = "";
  const src = document.querySelector('input[name="src"]:checked').value;
  const model = $("model").value;
  const body = { source_type: src, target: src === "git" ? $("git-url").value.trim() : $("local-target").value, use_llm: !!model };
  if (model) body.model = model;
  if (src === "git" && $("git-ref").value.trim()) body.git_ref = $("git-ref").value.trim();
  $("scan-btn").disabled = true;
  try {
    const r = await api("POST", "/api/scans", body);
    state.scanId = r.id;
    $("progress-text").textContent = `Scan ${r.id.slice(0, 8)} started (model: ${r.model || "none"})`;
    poll();
  } catch (err) { $("scan-error").textContent = err.message; $("scan-btn").disabled = false; }
});

function renderPipeline(ol, meta, withDesc = false) {
  const step = meta ? (meta.step || "").split(" ")[0] : null;
  const idx = STEPS.findIndex((s) => s[0] === step);
  const finished = meta && meta.status === "completed";
  ol.replaceChildren(...STEPS.map(([key, label, desc], i) => {
    let cls = "";
    if (finished) cls = key === "human_approval" && !(meta.pending_approvals > 0) ? "done" : "done";
    else if (meta && meta.status === "awaiting_approval") cls = key === "human_approval" ? "wait" : "done";
    else if (idx >= 0) cls = i < idx ? "done" : i === idx ? "current" : "";
    return el("li", { class: cls }, label, (withDesc || cls === "current") ? el("small", { text: desc }) : null);
  }));
}

function poll() {
  clearTimeout(state.timer);
  const tick = async () => {
    try {
      const { meta, report } = await api("GET", `/api/scans/${state.scanId}`);
      renderPipeline($("pipeline"), meta);
      $("progress-text").textContent = `Status: ${meta.status} · ${meta.step || ""}`;
      if (["completed", "awaiting_approval", "failed"].includes(meta.status)) {
        $("scan-btn").disabled = state.me.role === "viewer";
        if (meta.status === "failed") { $("scan-error").textContent = `Scan failed: ${meta.error || "unknown error"}`; return; }
        openResults(meta, report);
        return;
      }
    } catch (err) { $("progress-text").textContent = err.message; }
    state.timer = setTimeout(tick, 2000);
  };
  tick();
}

// ------------------------------------------------------------------ history
async function loadHistory() {
  const { scans } = await api("GET", "/api/scans");
  $("history-body").replaceChildren(...scans.map((s) => {
    const bp = (s.summary && s.summary.by_priority) || {};
    const tr = el("tr", { class: "click", tabindex: "0" },
      el("td", { text: (s.created_at || "").replace("T", " ").replace("Z", "") }),
      el("td", { text: s.source_type === "git" ? (s.target || "").replace("https://", "") : (s.target || "").split(/[\\/]/).pop(), title: s.target || "" }),
      el("td", {}, el("span", { class: `status ${s.status}`, text: s.status })),
      el("td", { text: bp.CRITICAL ?? "-" }), el("td", { text: bp.HIGH ?? "-" }), el("td", { text: bp.MEDIUM ?? "-" }),
      el("td", { text: s.pending_approvals ?? "-" }), el("td", { text: s.actor || "" }));
    const open = async () => {
      state.scanId = s.id;
      const r = await api("GET", `/api/scans/${s.id}`);
      if (r.report) openResults(r.meta, r.report); else { show("scan"); poll(); }
    };
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
    return tr;
  }));
}
$("refresh-history").addEventListener("click", loadHistory);

// ------------------------------------------------------------------ results
function openResults(meta, report) {
  state.meta = meta; state.report = report;
  $("nav-results").disabled = false;
  renderResults();
  show("results");
}

function renderResults() {
  const r = state.report, m = state.meta;
  $("res-title").textContent = `Results · ${r.scan.target}`;
  $("res-meta").textContent = `Scan ${r.scan.id.slice(0, 8)} · ${r.scan.generated_at} · languages: ${r.scan.languages.join(", ") || "-"} · AI: ${r.scan.ai_model} · RAG: ${r.scan.rag_mode}`;
  $("dl-json").href = `/api/scans/${r.scan.id}/report.json`;
  $("dl-pdf").href = `/api/scans/${r.scan.id}/report.pdf`;
  const bp = r.summary.by_priority;
  $("stats").replaceChildren(...["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) =>
    el("div", { class: `stat ${s}` }, el("div", { class: "n", text: bp[s] }), el("div", { class: "l", text: s }))),
    el("div", { class: "stat" }, el("div", { class: "n", text: r.approvals.pending }), el("div", { class: "l", text: "Pending approval" })));
  const cats = r.summary.by_category, max = Math.max(1, ...Object.values(cats));
  $("chart-cat").replaceChildren(...["SAST", "SCA", "SECRET"].map((c) => {
    const v = cats[c] || 0;
    const fill = el("div", { class: "fill" }); fill.style.width = `${(v / max) * 100}%`;
    return el("div", { class: "bar" }, el("span", { text: c }), el("div", { class: "track" }, fill), el("span", { class: "v", text: v }));
  }));
  $("tools").replaceChildren(...r.tools.map((t) => el("div", { class: "tool" },
    el("span", {}, el("span", { class: `dot ${t.status === "ok" ? "ok" : t.status === "skipped" ? "" : "bad"}` }), ` ${t.tool}`),
    el("span", { class: "note", text: `${t.status} · ${t.duration}s${t.error ? " · " + t.error.slice(0, 60) : ""}` }))));

  const canApprove = state.me.role === "approver" && m.status === "awaiting_approval";
  const pending = r.approvals.pending;
  $("approval-banner").classList.toggle("hidden", !(pending > 0));
  $("approval-text").textContent = canApprove
    ? `${pending} Critical/High fix recommendation(s) need your decision (policy SCP-12.1). Choose Approve or Reject on each finding, then submit.`
    : m.status !== "awaiting_approval"
      ? `${pending} Critical/High fix recommendation(s) are recorded as pending: this was a non-interactive (CLI/CI) scan. Re-run it from this UI to approve fixes.`
      : `${pending} Critical/High fix recommendation(s) are waiting for a user with the approver role.`;
  $("approval-actions").classList.toggle("hidden", !canApprove);
  renderFindings(canApprove);
}

function renderFindings(canApprove) {
  const fp = $("f-prio").value, fc = $("f-cat").value, fa = $("f-appr").value, ft = $("f-text").value.toLowerCase();
  const tpl = $("finding-tpl");
  const list = state.report.findings.filter((f) =>
    (!fp || f.priority === fp) && (!fc || f.category === fc) && (!fa || (f.fix && f.fix.approval === fa)) &&
    (!ft || `${f.title} ${f.file} ${f.rule_id} ${f.package} ${f.cve.join(" ")}`.toLowerCase().includes(ft)));
  const nodes = list.map((f) => {
    const n = tpl.content.firstElementChild.cloneNode(true);
    n.dataset.id = f.id;
    const q = (s) => n.querySelector(s);
    q(".sev").textContent = f.priority; q(".sev").classList.add(f.priority);
    q(".risk").textContent = f.risk_score;
    q(".cat").textContent = f.category;
    q(".title").textContent = f.title;
    q(".loc").textContent = f.line ? `${f.file}:${f.line}` : f.file;
    if (f.fix && f.fix.approval !== "not_required") {
      q(".appr").append(el("span", { class: `pill ${f.fix.approval}`, text: f.fix.approval.replace("_", " ") }));
    }
    q(".desc").textContent = f.description || "";
    const facts = [`Tool(s): ${f.detected_by.join(", ")}`, `Rule: ${f.rule_id}`];
    if (f.cwe.length) facts.push(`CWE: ${f.cwe.join(", ")}`);
    if (f.cve.length) facts.push(`CVE: ${f.cve.join(", ")}`);
    if (f.package) facts.push(`Package: ${f.package} ${f.installed_version} → fixed: ${f.fixed_version || "n/a"}`);
    if (f.cvss) facts.push(`CVSS ${f.cvss}`);
    q(".facts").textContent = facts.join(" · ");
    if (f.snippet) q(".snippet").textContent = f.snippet; else q(".snippet").remove();
    if (!f.fix) { q(".fix").remove(); return n; }
    q(".fix-src").textContent = f.fix.source === "policy-fallback" ? "· policy-based"
      : `· AI (${f.fix.model}) + policy RAG${f.fix.source === "llm+policy" ? " · code from policy example" : ""}`;
    q(".fix-summary").textContent = f.fix.summary;
    if (f.fix.fixed_code) q(".fix-code").textContent = f.fix.fixed_code; else q(".fix-code").remove();
    q(".policy").textContent = f.fix.policy_references.length ? `Policy: ${f.fix.policy_references.join(", ")}` : "";
    if (f.fix.approval === "pending_approval" && canApprove) {
      q(".decide").classList.remove("hidden");
      n.querySelectorAll(".decide input[type=radio]").forEach((r) => { r.name = `d-${f.id}`; });
    }
    if (f.fix.approved_by) {
      q(".decided").textContent = `${f.fix.approval} by ${f.fix.approved_by}${f.fix.approval_comment ? ` - "${f.fix.approval_comment}"` : ""}`;
    }
    return n;
  });
  $("findings").replaceChildren(...(nodes.length ? nodes : [el("p", { class: "muted", text: "No findings match the filters." })]));
}
["f-prio", "f-cat", "f-appr"].forEach((id) => $(id).addEventListener("change", () => renderFindings(state.me.role === "approver" && state.meta.status === "awaiting_approval")));
$("f-text").addEventListener("input", () => renderFindings(state.me.role === "approver" && state.meta.status === "awaiting_approval"));

function selectAll(value) {
  document.querySelectorAll(`#findings .decide:not(.hidden) input[value="${value}"]`).forEach((r) => { r.checked = true; });
}
$("approve-all").addEventListener("click", () => selectAll("approve"));
$("reject-all").addEventListener("click", () => selectAll("reject"));

$("submit-approvals").addEventListener("click", async () => {
  const decisions = [];
  document.querySelectorAll("#findings .finding").forEach((n) => {
    const picked = n.querySelector(".decide input[type=radio]:checked");
    if (picked) decisions.push({ finding_id: n.dataset.id, approved: picked.value === "approve", comment: n.querySelector(".comment").value.slice(0, 500) });
  });
  if (!decisions.length) { alert("Select Approve or Reject on at least one finding."); return; }
  $("submit-approvals").disabled = true;
  try {
    await api("POST", `/api/scans/${state.scanId}/approvals`, { decisions });
    const r = await api("GET", `/api/scans/${state.scanId}`);
    openResults(r.meta, r.report);
  } catch (err) { alert(err.message); }
  finally { $("submit-approvals").disabled = false; }
});

boot();
