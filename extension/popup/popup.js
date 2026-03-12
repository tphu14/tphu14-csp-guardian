// CSP Guardian v3 – popup/popup.js
// New: CSP diff view, live preview, risk breakdown chips, TypeScript-backed

import { generateCSP } from "../utils/csp-generator.js";
import { calculateRiskScore } from "../utils/risk-scorer.js";
import { diffCSP, renderDiffHTML } from "../utils/csp-diff.js";

const BACKEND_URL = "http://localhost:8000";
const WS_URL      = "ws://localhost:8000/ws/violations";

// ── State ──────────────────────────────────────────────────────────────────
let state = {
  isRecording:   false,
  resources:     null,
  cspResult:     null,
  riskResult:    null,
  aiResult:      null,
  analysisId:    null,
  currentDomain: null,
  violations:    [],
};
let ws = null;
let livePreviewTimer = null;

// ── DOM refs ───────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const statusBadge      = $("status-badge");
const btnStart         = $("btn-start");
const btnStop          = $("btn-stop");
const resourceCountEl  = $("resource-count");
const riskSection      = $("risk-section");
const tabsSection      = $("tabs-section");
const footerActions    = $("footer-actions");
const riskBar          = $("risk-bar");
const riskValue        = $("risk-score-value");
const riskLevelBadge   = $("risk-level-badge");
const riskBreakdown    = $("risk-breakdown");
const generatedCSP     = $("generated-csp-text");
const hardenedCSP      = $("hardened-csp-text");
const explanationEl    = $("explanation-text");
const issuesList       = $("issues-list");
const issuesBadge      = $("issues-badge");
const aiLoading        = $("ai-loading");
const wsIndicator      = $("ws-indicator");
const violationsBadge  = $("violations-badge");
const violationsList   = $("violations-list");
const providerBadge    = $("provider-badge");
const reportUriSection = $("report-uri-section");
const reportUriCode    = $("report-uri-code");
const historyList      = $("history-list");
const historyStats     = $("history-stats");
const diffContainer    = $("diff-container");
const diffBadge        = $("diff-badge");
const previewBar       = $("preview-bar");
const previewCSP       = $("preview-csp");
const generatedMeta    = $("generated-meta");

// ── Tabs ───────────────────────────────────────────────────────────────────
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    $(`tab-${btn.dataset.tab}`)?.classList.add("active");
    if (btn.dataset.tab === "violations") violationsBadge.textContent = "0";
  });
});

// ── WebSocket ──────────────────────────────────────────────────────────────
function connectWS(domain) {
  if (ws) ws.close();
  const url = domain ? `${WS_URL}?domain=${encodeURIComponent(domain)}` : WS_URL;
  ws = new WebSocket(url);
  ws.onopen  = () => { wsIndicator.className = "ws-dot ws-dot--on"; };
  ws.onmessage = e => {
    try {
      const msg = JSON.parse(e.data);
      if (msg.type === "violation") handleViolation(msg.data);
    } catch {}
  };
  ws.onclose = () => {
    wsIndicator.className = "ws-dot ws-dot--off";
    setTimeout(() => connectWS(domain), 5000);
  };
  ws.onerror = () => ws.close();
}

function handleViolation(v) {
  state.violations.unshift(v);
  const n = parseInt(violationsBadge.textContent || "0") + 1;
  violationsBadge.textContent = n;
  renderViolations(state.violations.slice(0, 50), true);
}

// ── Start Recording ────────────────────────────────────────────────────────
btnStart.addEventListener("click", async () => {
  const resp = await sendMsg("START_RECORDING");
  if (!resp?.ok) return alert("Could not start. Refresh the tab first.");

  state.isRecording = true;
  btnStart.disabled = true;
  btnStop.disabled  = false;
  statusBadge.textContent = "Recording";
  statusBadge.className   = "badge badge--recording";
  riskSection.classList.add("hidden");
  tabsSection.classList.add("hidden");
  footerActions.classList.add("hidden");
  previewBar.classList.remove("hidden");

  // Live preview: poll resources and update preview every 2s
  livePreviewTimer = setInterval(async () => {
    const r = await sendMsg("GET_STATUS");
    if (r) resourceCountEl.textContent = `${r.count} resources captured`;

    const res = await sendMsg("GET_RESOURCES");
    if (res?.resources) {
      const csp = generateCSP(res.resources);
      previewCSP.textContent = csp.csp
        ? csp.csp.substring(0, 200) + (csp.csp.length > 200 ? "…" : "")
        : "Recording…";
    }
  }, 2000);
});

// ── Stop & Analyze ─────────────────────────────────────────────────────────
btnStop.addEventListener("click", async () => {
  clearInterval(livePreviewTimer);
  previewBar.classList.add("hidden");

  const resp = await sendMsg("STOP_RECORDING");
  if (!resp?.ok) return alert("Failed to stop.");

  state.isRecording = false;
  state.resources   = resp.resources;
  btnStart.disabled = false;
  btnStop.disabled  = true;
  statusBadge.textContent = "Done";
  statusBadge.className   = "badge badge--done";

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  try { state.currentDomain = new URL(tab?.url || "").hostname; } catch {}

  analyze(state.resources);
  connectWS(state.currentDomain);
});

// ── Analyze ────────────────────────────────────────────────────────────────
function analyze(resources) {
  const cspResult  = generateCSP(resources);
  const riskResult = calculateRiskScore(resources, cspResult);
  state.cspResult  = cspResult;
  state.riskResult = riskResult;

  // Risk UI
  riskSection.classList.remove("hidden");
  riskValue.textContent      = riskResult.risk_score;
  riskBar.style.width        = `${riskResult.risk_score}%`;
  riskBar.style.background   = riskResult.risk_color;
  riskLevelBadge.textContent = riskResult.risk_level;
  riskLevelBadge.className   = `risk-level-badge risk-level--${riskResult.risk_level.toLowerCase()}`;

  // Breakdown chips
  riskBreakdown.innerHTML = Object.entries(riskResult.breakdown || {})
    .map(([k, v]) => `<span class="breakdown-chip">+${v} ${k}</span>`)
    .join("");

  // Generated CSP
  generatedCSP.textContent = cspResult.csp || "No CSP generated.";
  generatedCSP.classList.remove("muted");

  // Meta info
  const stats = riskResult.stats || {};
  generatedMeta.textContent =
    `${stats.totalResources || 0} resources · ${stats.thirdPartyDomains || 0} domains`;

  const allIssues = [...(cspResult.warnings || []), ...(riskResult.issues || [])];
  issuesBadge.textContent = allIssues.length;
  renderIssues(allIssues);

  tabsSection.classList.remove("hidden");
  footerActions.classList.remove("hidden");
}

// ── AI Analysis ────────────────────────────────────────────────────────────
$("btn-analyze-ai").addEventListener("click", async () => {
  if (!state.cspResult) return alert("Record a page first.");
  aiLoading.classList.remove("hidden");
  hardenedCSP.classList.add("hidden");
  providerBadge.classList.add("hidden");

  const rs = state.resources;
  const payload = {
    domain: state.currentDomain || "unknown",
    resource_summary: {
      script_domains:  [...new Set(rs.scripts?.map(r => r.domain).filter(Boolean))],
      style_domains:   [...new Set(rs.styles?.map(r => r.domain).filter(Boolean))],
      connect_domains: [...new Set(rs.xhr?.map(r => r.domain).filter(Boolean))],
      inline_script:   (rs.inlineScripts?.length || 0) > 0,
      eval_detected:   rs.evalDetected || false,
      wildcard_used:   (rs.wildcardDomains?.length || 0) > 0,
      wildcard_domains: rs.wildcardDomains || [],
    },
    generated_csp:  state.cspResult.csp,
    risk_score:     state.riskResult.risk_score,
    risk_level:     state.riskResult.risk_level,
    issues:         state.riskResult.issues,
    resource_stats: state.riskResult.stats || {},
  };

  try {
    const resp = await fetch(`${BACKEND_URL}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!resp.ok) throw new Error(`Backend error: ${resp.status}`);
    const data = await resp.json();
    state.aiResult   = data;
    state.analysisId = data.analysis_id;

    hardenedCSP.textContent = data.hardened_csp || "No hardened CSP.";
    hardenedCSP.classList.remove("muted", "hidden");

    if (data.provider) {
      providerBadge.textContent = `via ${data.provider}`;
      providerBadge.classList.remove("hidden");
    }

    if (state.analysisId) {
      reportUriCode.textContent = `report-uri ${BACKEND_URL}/csp-report`;
      reportUriSection.classList.remove("hidden");
    }

    renderExplanation(data.explanation);
    renderDiff();

    if (data.recommendations?.length) {
      const all = [...(state.riskResult.issues || []),
                   ...data.recommendations.map(r => `ℹ️ ${r}`)];
      issuesBadge.textContent = all.length;
      renderIssues(all);
    }
  } catch (err) {
    hardenedCSP.textContent = `Error: ${err.message}\n\nMake sure backend is running at ${BACKEND_URL}`;
    hardenedCSP.classList.remove("hidden");
    hardenedCSP.classList.add("muted");
  } finally {
    aiLoading.classList.add("hidden");
  }
});

// ── Diff View ──────────────────────────────────────────────────────────────
$("btn-refresh-diff").addEventListener("click", renderDiff);

function renderDiff() {
  const oldCSP = state.cspResult?.csp;
  const newCSP = state.aiResult?.hardened_csp;

  if (!oldCSP || !newCSP) {
    diffContainer.innerHTML = `<div class="muted" style="padding:12px">Run AI analysis first to see diff.</div>`;
    return;
  }

  const diff = diffCSP(oldCSP, newCSP);
  diffContainer.innerHTML = renderDiffHTML(diff);

  // Update diff badge
  const totalChanges = diff.added + diff.removed + diff.changed;
  if (totalChanges > 0) {
    diffBadge.textContent = totalChanges;
    diffBadge.classList.remove("hidden");
  }
}

// ── History ────────────────────────────────────────────────────────────────
$("btn-load-history").addEventListener("click", loadHistory);

async function loadHistory() {
  historyList.innerHTML = `<div class="muted" style="padding:12px">Loading…</div>`;
  try {
    const [listResp, statsResp] = await Promise.all([
      fetch(`${BACKEND_URL}/history?limit=20`),
      fetch(`${BACKEND_URL}/history/stats/summary`),
    ]);
    const list  = await listResp.json();
    const stats = await statsResp.json();

    historyStats.textContent =
      `${stats.total_analyses || 0} total · avg ${stats.avg_risk_score || 0} score`;
    renderHistory(list.items || []);
  } catch (err) {
    historyList.innerHTML = `<div class="muted" style="padding:12px">Error: ${err.message}</div>`;
  }
}

function renderHistory(items) {
  if (!items.length) {
    historyList.innerHTML = `<div class="muted" style="padding:12px">No history yet.</div>`;
    return;
  }
  historyList.innerHTML = items.map(item => {
    const level = item.risk_level?.toLowerCase() || "low";
    const time  = item.created_at
      ? new Date(item.created_at).toLocaleString("vi-VN", { dateStyle:"short", timeStyle:"short" })
      : "–";
    return `<div class="history-item">
      <div class="history-domain">${escHtml(item.domain)}</div>
      <div class="history-meta">
        <span class="history-score score--${level}">${item.risk_score} ${item.risk_level}</span>
        <span class="history-time">${time}</span>
        ${item.violation_count ? `<span class="badge-count">${item.violation_count} violations</span>` : ""}
        <span style="font-size:10px;color:var(--text-muted);margin-left:auto">#${item.id}</span>
      </div>
    </div>`;
  }).join("");
}

// ── Violations ─────────────────────────────────────────────────────────────
$("btn-load-violations").addEventListener("click", async () => {
  try {
    const url = `${BACKEND_URL}/violations?limit=50${state.currentDomain ? `&domain=${state.currentDomain}` : ""}`;
    const data = await (await fetch(url)).json();
    state.violations = data.items || [];
    renderViolations(state.violations);
  } catch (err) {
    violationsList.innerHTML = `<div class="muted" style="padding:12px">Error: ${err.message}</div>`;
  }
});

function renderViolations(items, isNew = false) {
  if (!items.length) {
    violationsList.innerHTML = `<div class="muted" style="padding:12px">No violations yet.</div>`;
    return;
  }
  violationsList.innerHTML = items.map((v, i) => `
    <div class="violation-item ${isNew && i === 0 ? "new" : ""}">
      <div class="violation-directive">${escHtml(v.violated_directive || v.effective_directive || "unknown")}</div>
      <div class="violation-blocked">Blocked: ${escHtml(v.blocked_uri || "(inline)")}</div>
      <div class="violation-time">${v.received_at ? new Date(v.received_at).toLocaleString("vi-VN") : "–"}</div>
    </div>`).join("");
}

// ── Renderers ──────────────────────────────────────────────────────────────
function renderIssues(issues) {
  if (!issues.length) {
    issuesList.innerHTML = `<li class="issue-item muted">No issues detected.</li>`;
    return;
  }
  issuesList.innerHTML = issues.map(iss => {
    const icon = iss.startsWith("🚨") ? "🚨" : iss.startsWith("⚠️") ? "⚠️" : "ℹ️";
    return `<li class="issue-item">
      <span class="issue-icon">${icon}</span>
      <span class="issue-text">${escHtml(iss.replace(/^[🚨⚠️ℹ️]\s*/,""))}</span>
    </li>`;
  }).join("");
}

function renderExplanation(text) {
  explanationEl.classList.remove("muted");
  if (!text) { explanationEl.textContent = "No explanation returned."; return; }
  const obj = typeof text === "object" ? text : (() => { try { return JSON.parse(text); } catch { return null; } })();
  if (obj) {
    explanationEl.innerHTML = Object.entries(obj).map(([k, v]) =>
      `<div class="explanation-directive">
        <strong>${escHtml(k)}</strong>
        <p>${escHtml(String(v))}</p>
      </div>`).join("");
    return;
  }
  explanationEl.innerHTML = String(text).split("\n").filter(Boolean)
    .map(l => `<p>${escHtml(l)}</p>`).join("");
}

// ── Copy / Export / Reset ──────────────────────────────────────────────────
$("copy-generated").addEventListener("click", () => copyText(generatedCSP.textContent, $("copy-generated")));
$("copy-hardened").addEventListener("click",  () => copyText(hardenedCSP.textContent,  $("copy-hardened")));
$("copy-report-uri").addEventListener("click", () => copyText(reportUriCode.textContent, $("copy-report-uri")));

function copyText(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = "✓ Copied!";
    setTimeout(() => btn.textContent = orig, 1500);
  });
}

$("btn-export").addEventListener("click", () => {
  const data = {
    analysis_id:  state.analysisId,
    domain:       state.currentDomain,
    generated_csp: state.cspResult?.csp,
    hardened_csp:  state.aiResult?.hardened_csp,
    risk:          state.riskResult,
    issues:        state.riskResult?.issues,
    ai_recommendations: state.aiResult?.recommendations,
    report_uri:    `${BACKEND_URL}/csp-report`,
    resources_summary: {
      scripts:      state.resources?.scripts?.length,
      styles:       state.resources?.styles?.length,
      images:       state.resources?.images?.length,
      xhr:          state.resources?.xhr?.length,
      inlineScripts: state.resources?.inlineScripts?.length,
      evalDetected:  state.resources?.evalDetected,
    },
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type:"application/json" });
  const url  = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = `csp-guardian-${state.currentDomain || "report"}.json`;
  a.click(); URL.revokeObjectURL(url);
});

$("btn-reset").addEventListener("click", () => {
  clearInterval(livePreviewTimer);
  if (ws) { ws.close(); ws = null; }
  state = { isRecording:false, resources:null, cspResult:null, riskResult:null, aiResult:null, analysisId:null, currentDomain:null, violations:[] };
  riskSection.classList.add("hidden");
  tabsSection.classList.add("hidden");
  footerActions.classList.add("hidden");
  previewBar.classList.add("hidden");
  statusBadge.textContent = "Idle"; statusBadge.className = "badge badge--idle";
  resourceCountEl.textContent = "–";
  wsIndicator.className = "ws-dot ws-dot--off";
  diffBadge.classList.add("hidden");
  reportUriSection.classList.add("hidden");
});

// ── Helpers ────────────────────────────────────────────────────────────────
function sendMsg(type, data = {}) {
  return chrome.runtime.sendMessage({ type, data }).catch(() => null);
}

function escHtml(str) {
  return String(str).replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

// ── Init ───────────────────────────────────────────────────────────────────
(async () => {
  const s = await sendMsg("GET_STATUS");
  if (s?.isRecording) {
    state.isRecording = true;
    btnStart.disabled = true; btnStop.disabled = false;
    statusBadge.textContent = "Recording"; statusBadge.className = "badge badge--recording";
    resourceCountEl.textContent = `${s.count} resources captured`;
    previewBar.classList.remove("hidden");
  }
  connectWS();
})();