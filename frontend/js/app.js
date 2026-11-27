/**
 * SecureFL Cybersecurity SOC Dashboard Controller (14 Modules, XSS-Safe, Firebase + FastAPI Hybrid).
 */
import {
  apiFetch,
  downloadAuthenticatedBlob,
  escapeHtml,
  getToken,
  setToken,
  startBearerSSE,
} from "./api.js";
import {
  renderBenchmarkBars,
  renderDonutChart,
  renderFlConvergenceChart,
  renderPrivacyGauge,
} from "./charts.js";
import { DEFAULT_API_BASE, loadRuntimeFirebaseConfig } from "./firebase-config.js";
import {
  firebaseSendReset,
  firebaseSignInEmail,
  firebaseSignOut,
  initFirebaseWeb,
  subscribeTenantAlertsFirestore,
} from "./firebase-sdk.js";

let currentUser = null;
let currentPage = "overview";
let stopSSE = null;
let stopFirestoreListener = null;
let publicTenants = [];
let runtimeFirebase = { ready: false };

const PRESETS = {
  brute_force: { num_failed_logins: 26, request_frequency: 195, bytes_transferred_kb: 320, cross_tenant_access_attempts: 0, secret_detection_count: 0, privilege_level: 1, response_code_status: 1, is_new_device: 1 },
  exfil: { num_failed_logins: 1, request_frequency: 72, bytes_transferred_kb: 185000, cross_tenant_access_attempts: 0, secret_detection_count: 0, privilege_level: 2, unusual_access_time: 1, hour_of_day: 2, is_vpn: 1, session_duration_sec: 9500 },
  cross_tenant: { num_failed_logins: 4, request_frequency: 45, bytes_transferred_kb: 600, cross_tenant_access_attempts: 8, secret_detection_count: 0, privilege_level: 2, response_code_status: 1, suspicious_artifact_activity: 1, is_new_device: 1 },
  normal: { num_failed_logins: 0, request_frequency: 6, bytes_transferred_kb: 180, cross_tenant_access_attempts: 0, secret_detection_count: 0, privilege_level: 1, response_code_status: 0, is_new_device: 0 },
};

function showToast(type, title, body) {
  const c = document.getElementById("toast-container");
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.innerHTML = `
    <div>
      <div style="font-weight:700;color:var(--text-bright)">${escapeHtml(title)}</div>
      <div style="font-size:12px;color:var(--text)">${escapeHtml(body)}</div>
    </div>
    <button type="button" style="background:none;border:none;color:var(--muted)" onclick="this.parentElement.remove()">✕</button>
  `;
  c.appendChild(el);
  setTimeout(() => el.remove(), 5500);
}

function showAuthAlert(msg, color = "var(--danger)") {
  const box = document.getElementById("auth-alert");
  box.textContent = msg;
  box.style.display = "block";
  box.style.border = `1px solid ${color}`;
  box.style.color = color;
}

function clearAuthAlert() {
  document.getElementById("auth-alert").style.display = "none";
}

function switchAuthTab(tab) {
  clearAuthAlert();
  ["signin", "register", "reset"].forEach((t) => {
    document.getElementById(`tab-btn-${t}`).classList.toggle("active", t === tab);
    document.getElementById(`form-${t}`).style.display = t === tab ? "block" : "none";
  });
}

async function checkHealth() {
  const statusEl = document.getElementById("auth-api-status");
  try {
    const res = await fetch(`${DEFAULT_API_BASE}/health`);
    if (res.ok) {
      const h = await res.json();
      statusEl.textContent = `Connected (${h.services?.firebase_mode || "local"})`;
      statusEl.style.color = "var(--success)";
      return;
    }
  } catch {
    // ignore
  }
  statusEl.textContent = "Backend unreachable — start FastAPI (:8000)";
  statusEl.style.color = "var(--danger)";
}

async function loadPublicTenants() {
  try {
    const res = await fetch(`${DEFAULT_API_BASE}/api/v1/auth/public-tenants`);
    if (!res.ok) return;
    publicTenants = await res.json();
    const sel = document.getElementById("reg-tenant-select");
    if (sel) {
      sel.innerHTML = publicTenants
        .map((t) => `<option value="${escapeHtml(t.id)}">${escapeHtml(t.name)}</option>`)
        .join("");
    }
  } catch {
    // ignore
  }
}

async function enterDashboard() {
  const res = await apiFetch("/api/v1/auth/me");
  if (!res.ok) throw new Error("Session validation failed");
  currentUser = await res.json();

  document.getElementById("login-modal").style.display = "none";
  document.getElementById("app-shell").style.display = "flex";
  document.getElementById("topbar-user-info").textContent =
    `${currentUser.username} · ${currentUser.role.toUpperCase()} · ${currentUser.tenant_name || ""}`;

  const isAdmin = currentUser.role === "admin";
  const isAnalystUp = isAdmin || currentUser.role === "analyst";
  document.querySelectorAll(".admin-only").forEach((el) => {
    el.style.display = isAdmin ? "" : "none";
  });
  document.querySelectorAll(".analyst-up").forEach((el) => {
    el.style.display = isAnalystUp ? "" : "none";
  });

  if (stopSSE) stopSSE();
  stopSSE = startBearerSSE(
    (evt) => {
      addFeedItem(evt);
      showToast("danger", evt.threat_type, `${evt.tenant_name || "Tenant"} (${Math.round(evt.confidence * 100)}%)`);
      if (currentPage === "overview" || currentPage === "threats") loadPage(currentPage);
    },
    (online) => {
      const pill = document.getElementById("live-pill");
      const txt = document.getElementById("live-pill-text");
      pill.classList.toggle("offline", !online);
      txt.textContent = online ? "Live Bearer Stream Active" : "Stream Reconnecting";
    }
  );

  if (runtimeFirebase.ready && currentUser.tenant_id) {
    if (stopFirestoreListener) stopFirestoreListener();
    stopFirestoreListener = subscribeTenantAlertsFirestore(currentUser.tenant_id, (items) => {
      if (items.length && currentPage === "overview") loadOverview();
    });
  }

  switchPage("overview");
}

function addFeedItem(t) {
  const feed = document.getElementById("sse-feed");
  if (!feed) return;
  if (feed.textContent.includes("Listening")) feed.innerHTML = "";
  const div = document.createElement("div");
  div.className = "feed-item";
  const sev = escapeHtml(t.severity || (t.confidence >= 0.88 ? "critical" : "high"));
  div.innerHTML = `
    <div>
      <span class="badge ${sev}">${sev}</span>
      <strong style="color:var(--text-bright);margin-left:6px">${escapeHtml(t.threat_type)}</strong>
      <span style="color:var(--muted)"> · ${escapeHtml(t.tenant_name || "Tenant")}</span>
    </div>
    <span class="mono" style="font-size:11px;color:var(--muted)">${Math.round((t.confidence || 0) * 100)}%</span>
  `;
  feed.prepend(div);
  if (feed.children.length > 15) feed.removeChild(feed.lastChild);
}

function switchPage(page) {
  currentPage = page;
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.page === page));
  document.querySelectorAll(".page").forEach((p) => p.classList.toggle("active", p.id === `page-${page}`));
  document.getElementById("sidebar")?.classList.remove("open");
  loadPage(page);
}

async function loadPage(page) {
  switch (page) {
    case "overview": await loadOverview(); break;
    case "threats": await loadThreats(); break;
    case "history": await loadHistory(); break;
    case "benchmarks": await loadBenchmarks(); break;
    case "fl": await loadFL(); break;
    case "privacy": await loadPrivacy(); break;
    case "xai": await loadXaiSelector(); break;
    case "responses": await loadResponses(); break;
    case "isolation": await loadIsolation(); break;
    case "users": await loadUsers(); break;
    case "audit": await loadAudit(); break;
    case "cicd": await loadCicdStatus(); break;
    case "firebase": await loadFirebaseStatus(); break;
    case "settings": await loadSettings(); break;
  }
}

async function loadOverview() {
  const [stRes, thRes] = await Promise.all([apiFetch("/api/v1/stats"), apiFetch("/api/v1/threats/?page=1&page_size=8")]);
  if (stRes.ok) {
    const s = await stRes.json();
    document.getElementById("stat-threats").textContent = s.threats;
    document.getElementById("stat-tenants").textContent = s.tenants;
    document.getElementById("stat-pending").textContent = s.pendingVerifications;
    document.getElementById("stat-resp-pending").textContent = `Responses pending: ${s.pendingResponses || 0}`;
    document.getElementById("stat-fl").textContent = `${s.flRounds} rds`;
    document.getElementById("stat-fl-acc").textContent = `Accuracy: ${(Number(s.flAccuracy || 0) * 100).toFixed(1)}%`;
    document.getElementById("stat-eps").textContent = `${Number(s.epsilonUsed || 0).toFixed(2)} / ${s.epsilonTotal}`;
    document.getElementById("firebase-mode-chip").textContent = `Backend: ${s.firebaseMode}`;

    const pb = document.getElementById("nav-pending-badge");
    if (pb) {
      pb.textContent = s.pendingVerifications;
      pb.style.display = s.pendingVerifications > 0 ? "inline-block" : "none";
    }
    const rb = document.getElementById("nav-resp-badge");
    if (rb) {
      rb.textContent = s.pendingResponses || 0;
      rb.style.display = (s.pendingResponses || 0) > 0 ? "inline-block" : "none";
    }
  }
  if (thRes.ok) {
    const data = await thRes.json();
    const items = data.items || [];
    renderDonutChart(items);
    document.getElementById("ov-threats-tbody").innerHTML = items.length
      ? items
          .map((t) => {
            const sev = escapeHtml(t.severity || (t.confidence >= 0.88 ? "critical" : "high"));
            return `<tr>
              <td class="mono">${new Date(t.timestamp).toLocaleTimeString()}</td>
              <td>${escapeHtml(t.tenant_name || t.tenant_id)}</td>
              <td><strong>${escapeHtml(t.threat_type)}</strong></td>
              <td><span class="badge ${sev}">${sev}</span></td>
              <td>${Math.round(t.confidence * 100)}%</td>
              <td class="mono">${escapeHtml(t.ml_model || "LSTM")}</td>
              <td><span class="badge ${escapeHtml(t.status)}">${escapeHtml(t.status)}</span></td>
            </tr>`;
          })
          .join("")
      : `<tr><td colspan="7" style="text-align:center;color:var(--muted)">No alerts yet.</td></tr>`;
  }
}

async function loadThreats() {
  const res = await apiFetch("/api/v1/threats/?page=1&page_size=30");
  if (!res.ok) return;
  const data = await res.json();
  const tbody = document.getElementById("threats-tbody");
  tbody.innerHTML = (data.items || [])
    .map((t) => {
      const sev = escapeHtml(t.severity || (t.confidence >= 0.88 ? "critical" : "high"));
      return `<tr>
        <td class="mono">${new Date(t.timestamp).toLocaleTimeString()}</td>
        <td>${escapeHtml(t.tenant_name || t.tenant_id)}</td>
        <td><strong>${escapeHtml(t.threat_type)}</strong></td>
        <td><span class="badge ${sev}">${sev}</span></td>
        <td>${Math.round(t.confidence * 100)}%</td>
        <td class="mono">${escapeHtml(t.source_ip || "—")}</td>
        <td><span class="badge ${escapeHtml(t.status)}">${escapeHtml(t.status)}</span></td>
        <td style="display:flex;gap:4px">
          ${t.status === "open" ? `<button class="btn btn-outline btn-sm" data-ack="${escapeHtml(t.id)}">Ack</button>` : ""}
          ${t.status !== "resolved" ? `<button class="btn btn-success btn-sm" data-res="${escapeHtml(t.id)}">Resolve</button>` : ""}
          <button class="btn btn-secondary btn-sm" data-xai="${escapeHtml(t.id)}">XAI</button>
        </td>
      </tr>`;
    })
    .join("");

  tbody.querySelectorAll("[data-ack]").forEach((b) => (b.onclick = () => ackAlert(b.dataset.ack)));
  tbody.querySelectorAll("[data-res]").forEach((b) => (b.onclick = () => resolveAlert(b.dataset.res)));
  tbody.querySelectorAll("[data-xai]").forEach((b) => (b.onclick = () => { switchPage("xai"); inspectAlertXai(b.dataset.xai); }));
}

async function ackAlert(id) {
  const res = await apiFetch(`/api/v1/threats/${id}/acknowledge`, { method: "POST" });
  if (res.ok) { showToast("success", "Acknowledged", "Threat alert acknowledged."); loadThreats(); }
  else { showToast("danger", "Error", "Failed to acknowledge alert."); }
}

async function resolveAlert(id) {
  const res = await apiFetch(`/api/v1/threats/${id}/resolve`, { method: "POST" });
  if (res.ok) { showToast("success", "Resolved", "Threat alert resolved."); loadThreats(); }
  else { showToast("danger", "Error", "Failed to resolve alert."); }
}

async function loadHistory() {
  const st = document.getElementById("hist-status").value;
  const q = document.getElementById("hist-search").value.trim();
  let url = `/api/v1/threats/?page=1&page_size=50`;
  if (st) url += `&status=${encodeURIComponent(st)}`;
  if (q) url += `&threat_type=${encodeURIComponent(q)}`;
  const res = await apiFetch(url);
  if (!res.ok) return;
  const data = await res.json();
  document.getElementById("history-tbody").innerHTML = (data.items || [])
    .map((t) => `<tr>
      <td class="mono">${new Date(t.timestamp).toLocaleString()}</td>
      <td>${escapeHtml(t.tenant_name || t.tenant_id)}</td>
      <td>${escapeHtml(t.threat_type)}</td>
      <td>${(t.confidence * 100).toFixed(1)}%</td>
      <td>${t.anomaly_score != null ? t.anomaly_score.toFixed(3) : "—"}</td>
      <td class="mono">${escapeHtml(t.source_ip || "—")}</td>
      <td style="max-width:260px;font-size:12px;color:var(--muted)">${escapeHtml(t.description || "—")}</td>
      <td><span class="badge ${escapeHtml(t.status)}">${escapeHtml(t.status)}</span></td>
    </tr>`)
    .join("");
}

async function loadBenchmarks() {
  const res = await apiFetch("/api/v1/fl/benchmarks");
  if (!res.ok) return;
  const data = await res.json();
  const models = data.models || [];
  renderBenchmarkBars(models);
  document.getElementById("bench-tbody").innerHTML = models.length
    ? models
        .map((m) => `<tr>
          <td><strong>${escapeHtml(m.model_name)}</strong></td>
          <td>${escapeHtml(m.scope)}</td>
          <td>${(m.accuracy * 100).toFixed(2)}%</td>
          <td>${(m.precision * 100).toFixed(2)}%</td>
          <td>${(m.recall * 100).toFixed(2)}%</td>
          <td>${(m.f1_score * 100).toFixed(2)}%</td>
          <td>${(m.fpr * 100).toFixed(2)}%</td>
          <td class="mono">${Number(m.latency_ms).toFixed(4)}</td>
        </tr>`)
        .join("")
    : `<tr><td colspan="8" style="text-align:center;color:var(--muted)">No benchmark runs recorded yet.</td></tr>`;

  const cmEl = document.getElementById("cm-container");
  const firstWithCm = models.find((m) => Array.isArray(m.confusion_matrix));
  if (firstWithCm) {
    const labels = ["Normal", "BruteForce", "Exfil", "PrivEsc", "CrossTenant"];
    cmEl.innerHTML = `<table><thead><tr><th>True \\ Pred</th>${labels.map((l) => `<th>${l}</th>`).join("")}</tr></thead><tbody>${
      firstWithCm.confusion_matrix
        .map((row, rIdx) => `<tr><th>${labels[rIdx]}</th>${row.map((v) => `<td class="mono">${v}</td>`).join("")}</tr>`)
        .join("")
    }</tbody></table>`;
  } else {
    cmEl.textContent = "Run the benchmark suite to inspect the 5x5 confusion matrix.";
  }
}

async function loadFL() {
  const [rRes, cRes] = await Promise.all([apiFetch("/api/v1/fl/rounds"), apiFetch("/api/v1/fl/clients")]);
  if (rRes.ok) {
    const rounds = await rRes.json();
    renderFlConvergenceChart(rounds);
    document.getElementById("fl-rounds-tbody").innerHTML = rounds
      .slice()
      .reverse()
      .map((r) => `<tr>
        <td><strong>Round ${r.round_num}</strong></td>
        <td><span class="badge medium">${escapeHtml(r.strategy)}</span></td>
        <td>${(r.accuracy * 100).toFixed(2)}%</td>
        <td>${r.loss.toFixed(4)}</td>
        <td class="mono">${r.privacy_epsilon.toFixed(3)}</td>
        <td>${(r.participating_tenants || []).length} nodes</td>
        <td>${(r.rejected_tenants || []).length ? `<span class="badge critical">${escapeHtml(r.rejected_tenants.join(", "))}</span>` : "None"}</td>
        <td class="mono">${new Date(r.timestamp).toLocaleTimeString()}</td>
      </tr>`)
      .join("");
  }
  if (cRes.ok) {
    const clients = await cRes.json();
    document.getElementById("fl-clients-list").innerHTML = clients
      .map((c) => `<div class="feed-item">
        <div><strong>${escapeHtml(c.name)}</strong> <span class="mono" style="color:var(--muted)">(${escapeHtml(c.tenant_id)})</span></div>
        <span class="badge verified">${c.samples_count} samples · ${escapeHtml(c.isolation_status)}</span>
      </div>`)
      .join("");
  }
}

async function loadPrivacy() {
  const [bRes, hRes] = await Promise.all([apiFetch("/api/v1/fl/privacy/budget"), apiFetch("/api/v1/fl/privacy/history")]);
  if (bRes.ok) {
    const b = await bRes.json();
    renderPrivacyGauge(b.epsilon_spent, b.epsilon_total_budget);
    document.getElementById("dp-summary-text").textContent =
      `Spent: ${b.epsilon_spent.toFixed(3)} / ${b.epsilon_total_budget} ε (Remaining: ${b.epsilon_remaining.toFixed(3)})`;
    document.getElementById("dp-params-box").innerHTML = `
      <div>Accountant: <strong>${escapeHtml(b.accountant_type)}</strong></div>
      <div>Noise Multiplier (σ): <strong>${b.noise_multiplier}</strong></div>
      <div>L2 Clip Norm (C): <strong>${b.clip_norm}</strong></div>
      <div>Target δ: <strong>${b.delta}</strong></div>
      <div>Budget Status: <span class="badge ${b.is_budget_exceeded ? "critical" : "verified"}">${b.is_budget_exceeded ? "EXCEEDED" : "WITHIN CAP"}</span></div>
    `;
  }
  if (hRes.ok) {
    const rows = await hRes.json();
    document.getElementById("dp-history-tbody").innerHTML = rows
      .slice()
      .reverse()
      .map((r) => `<tr>
        <td>Round ${r.round_num}</td>
        <td>${escapeHtml(r.accountant_type)}</td>
        <td class="mono">${r.noise_multiplier}</td>
        <td class="mono">${r.clip_norm}</td>
        <td class="mono">+${Number(r.round_epsilon).toFixed(4)}</td>
        <td class="mono">${Number(r.cumulative_epsilon).toFixed(4)}</td>
        <td class="mono">${r.delta}</td>
        <td><span class="badge ${r.budget_exceeded ? "critical" : "verified"}">${r.budget_exceeded ? "Exceeded" : "OK"}</span></td>
      </tr>`)
      .join("");
  }
}

async function loadXaiSelector() {
  const res = await apiFetch("/api/v1/threats/?page=1&page_size=20");
  if (!res.ok) return;
  const data = await res.json();
  const sel = document.getElementById("xai-alert-select");
  sel.innerHTML = (data.items || [])
    .map((t) => `<option value="${escapeHtml(t.id)}">${escapeHtml(t.threat_type)} (${Math.round(t.confidence * 100)}%) — ${escapeHtml(t.tenant_name || "")}</option>`)
    .join("");
  if (data.items?.length) inspectAlertXai(data.items[0].id);
}

async function inspectAlertXai(alertId) {
  if (!alertId) return;
  const res = await apiFetch(`/api/v1/threats/${alertId}/explain`);
  if (!res.ok) return;
  const x = await res.json();
  renderXaiCard(document.getElementById("xai-detail-box"), x);
}

function renderXaiCard(container, x) {
  const sev = escapeHtml(x.severity || "high");
  const bars = (x.top_features || [])
    .map(
      (f) => `<div class="xai-bar-row">
        <div style="width:190px;font-weight:600">${escapeHtml(f.label)}</div>
        <div class="xai-bar-track"><div class="xai-bar-fill" style="width:${Math.min(100, Math.round(f.impact * 100))}%"></div></div>
        <div class="mono" style="width:110px;text-align:right">val=${f.value} (${(f.impact * 100).toFixed(1)}%)</div>
      </div>`
    )
    .join("");

  container.innerHTML = `
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:10px">
      <span class="badge ${sev}">${sev}</span>
      <strong style="color:var(--text-bright);font-size:15px">${escapeHtml(x.threat_type || x.threat_label)}</strong>
      <span class="badge medium">Confidence ${(x.confidence * 100).toFixed(1)}%</span>
      <span class="badge pending">Anomaly ${Number(x.anomaly_score || 0).toFixed(3)}</span>
      <span class="badge verified">Action: ${escapeHtml(x.recommended_action)}</span>
    </div>
    <p style="margin-bottom:12px;color:var(--text)">${escapeHtml(x.explanation)}</p>
    <div>${bars}</div>
  `;
}

async function loadResponses() {
  const res = await apiFetch("/api/v1/responses/");
  if (!res.ok) return;
  const items = await res.json();
  const isAdmin = currentUser?.role === "admin";
  document.getElementById("responses-tbody").innerHTML = items.length
    ? items
        .map((r) => `<tr>
          <td class="mono">${new Date(r.timestamp).toLocaleTimeString()}</td>
          <td><strong>${escapeHtml(r.action_type)}</strong></td>
          <td class="mono">${escapeHtml(r.target_subject || "—")}</td>
          <td>${r.requires_approval ? "Admin Gate" : "Auto-Low"}</td>
          <td><span class="badge ${escapeHtml(r.approval_status)}">${escapeHtml(r.approval_status)}</span></td>
          <td>${escapeHtml(r.approved_by || "—")}</td>
          <td>${
            isAdmin && r.approval_status === "pending"
              ? `<button class="btn btn-success btn-sm" data-resp-app="${escapeHtml(r.id)}">Approve</button>
                 <button class="btn btn-danger btn-sm" data-resp-rej="${escapeHtml(r.id)}">Reject</button>`
              : "—"
          }</td>
        </tr>`)
        .join("")
    : `<tr><td colspan="7" style="text-align:center;color:var(--muted)">No response events recorded.</td></tr>`;

  document.querySelectorAll("[data-resp-app]").forEach((b) => (b.onclick = () => decideResponse(b.dataset.respApp, "approve")));
  document.querySelectorAll("[data-resp-rej]").forEach((b) => (b.onclick = () => decideResponse(b.dataset.respRej, "reject")));
}

async function decideResponse(id, decision) {
  const res = await apiFetch(`/api/v1/responses/${id}/decide`, {
    method: "POST",
    body: JSON.stringify({ decision }),
  });
  if (res.ok) {
    showToast("success", `Response ${decision.toUpperCase()}`, "Updated security response record.");
    loadResponses();
  } else {
    showToast("danger", "Error", "Could not update response.");
  }
}

async function loadIsolation() {
  const [tRes, aRes] = await Promise.all([apiFetch("/api/v1/tenants/me/current"), apiFetch("/api/v1/tenants/me/archives")]);
  if (tRes.ok) {
    const t = await tRes.json();
    document.getElementById("iso-tenant-card").innerHTML = `
      <div>Tenant: <strong>${escapeHtml(t.name)}</strong></div>
      <div>Algorithm: <strong>${escapeHtml(t.encryption_algorithm)}</strong></div>
      <div>Key Version: <strong>v${t.key_version}</strong></div>
      <div class="crypto-box">Fingerprint: <span class="mono">${escapeHtml(t.key_fingerprint)}</span></div>
    `;
  }
  if (aRes.ok) {
    const arch = await aRes.json();
    document.getElementById("archives-list").innerHTML = arch.length
      ? arch.map((a) => `<div class="feed-item"><span class="mono">${escapeHtml(a.filename)}</span><span>${a.size_bytes} B · AES-256-GCM</span></div>`).join("")
      : `<div style="color:var(--muted)">No encrypted archives uploaded yet.</div>`;
  }
}

async function runRealIsolationProbe() {
  const box = document.getElementById("iso-probe-result");
  box.style.display = "block";
  box.textContent = "Executing live HTTP cross-tenant probe…";
  const foreign = publicTenants.find((t) => t.id !== currentUser.tenant_id);
  const targetId = foreign ? foreign.id : "00000000-0000-0000-0000-000000000001";
  const res = await apiFetch(`/api/v1/tenants/${targetId}`);
  const body = await res.json();
  if (currentUser.role === "admin") {
    box.textContent = `Admin global read HTTP ${res.status}: cross-tenant isolation restricts non-admin callers (switch to tenant user to verify HTTP 403 block).`;
  } else {
    box.textContent = `Live Server Response: HTTP ${res.status} — ${body.detail || JSON.stringify(body)}`;
  }
}

async function loadUsers() {
  const [pRes, aRes] = await Promise.all([apiFetch("/api/v1/admin/pending-users"), apiFetch("/api/v1/admin/users")]);
  if (pRes.ok) {
    const pending = await pRes.json();
    document.getElementById("pending-users-tbody").innerHTML = pending.length
      ? pending
          .map((u) => `<tr>
            <td class="mono">${escapeHtml(u.username)}</td>
            <td>${escapeHtml(u.email || "—")}</td>
            <td>${escapeHtml(u.tenant_name)}</td>
            <td><span class="badge pending">${escapeHtml(u.role)}</span></td>
            <td>
              <button class="btn btn-success btn-sm" data-v-app="${escapeHtml(u.id)}">Approve</button>
              <button class="btn btn-danger btn-sm" data-v-rej="${escapeHtml(u.id)}">Reject</button>
            </td>
          </tr>`)
          .join("")
      : `<tr><td colspan="5" style="text-align:center;color:var(--success)">Zero pending verifications.</td></tr>`;
    document.querySelectorAll("[data-v-app]").forEach((b) => (b.onclick = () => verifyUser(b.dataset.vApp, "approve")));
    document.querySelectorAll("[data-v-rej]").forEach((b) => (b.onclick = () => verifyUser(b.dataset.vRej, "reject")));
  }
  if (aRes.ok) {
    const all = await aRes.json();
    document.getElementById("all-users-tbody").innerHTML = all
      .map((u) => `<tr>
        <td class="mono">${escapeHtml(u.username)}</td>
        <td>${escapeHtml(u.tenant_name)}</td>
        <td><span class="badge medium">${escapeHtml(u.role)}</span></td>
        <td><span class="badge ${u.is_verified ? "verified" : "pending"}">${u.is_verified ? "Verified" : "Pending"}</span></td>
        <td><span class="badge ${u.is_active && !u.is_restricted ? "verified" : "critical"}">${u.is_restricted ? "Restricted" : u.is_active ? "Active" : "Disabled"}</span></td>
        <td style="display:flex;gap:4px">
          <button class="btn btn-outline btn-sm" data-rev="${escapeHtml(u.id)}">Revoke Sessions</button>
          ${u.is_restricted ? `<button class="btn btn-success btn-sm" data-unr="${escapeHtml(u.id)}">Unrestrict</button>` : ""}
        </td>
      </tr>`)
      .join("");
    document.querySelectorAll("[data-rev]").forEach((b) => (b.onclick = async () => {
      const r = await apiFetch(`/api/v1/admin/users/${b.dataset.rev}/revoke-sessions`, { method: "POST" });
      if (r.ok) showToast("warning", "Sessions Revoked", "Refresh tokens revoked.");
    }));
    document.querySelectorAll("[data-unr]").forEach((b) => (b.onclick = async () => {
      const r = await apiFetch(`/api/v1/admin/users/${b.dataset.unr}/unrestrict`, { method: "POST" });
      if (r.ok) { showToast("success", "Unrestricted", "User account restored."); loadUsers(); }
    }));
  }
}

async function verifyUser(id, action) {
  const res = await apiFetch(`/api/v1/admin/users/${id}/verify`, {
    method: "POST",
    body: JSON.stringify({ action }),
  });
  if (res.ok) { showToast("success", "Updated", `User ${action}d.`); loadUsers(); }
}

async function loadAudit() {
  const res = await apiFetch("/api/v1/audit/logs?page=1&page_size=40");
  if (!res.ok) return;
  const data = await res.json();
  document.getElementById("audit-tbody").innerHTML = (data.items || [])
    .map((l) => `<tr>
      <td class="mono">${new Date(l.timestamp).toLocaleString()}</td>
      <td><strong>${escapeHtml(l.event_type)}</strong></td>
      <td><span class="badge ${escapeHtml(l.severity)}">${escapeHtml(l.severity)}</span></td>
      <td class="mono">${escapeHtml(l.actor_uid || "system")}</td>
      <td class="mono">${escapeHtml((l.integrity_hash || "").slice(0, 14))}…</td>
      <td style="font-size:11.5px;color:var(--muted)">${escapeHtml(JSON.stringify(l.details || {}))}</td>
    </tr>`)
    .join("");
}

async function loadCicdStatus() {
  const res = await apiFetch("/api/v1/cicd/status");
  if (!res.ok) return;
  const s = await res.json();
  document.getElementById("cicd-status-box").innerHTML = `
    <div>Overall Gate Status: <span class="badge verified">${escapeHtml(s.status)}</span></div>
    <div style="margin-top:8px">Source Secret Scan: <strong>${escapeHtml(s.source_secret_scan?.status)}</strong> (${s.source_secret_scan?.scanned_files} files)</div>
    <div>Dependency CVE Scan: <strong>${escapeHtml(s.dependency_cve_scan?.status)}</strong></div>
    <div style="margin-top:8px;font-size:12px;color:var(--muted)">${Object.entries(s.gates || {}).map(([k, v]) => `<div>${escapeHtml(k)}: ${escapeHtml(v)}</div>`).join("")}</div>
  `;
}

async function loadFirebaseStatus() {
  const res = await apiFetch("/api/v1/firebase/status");
  if (!res.ok) return;
  const s = await res.json();
  document.getElementById("firebase-status-card").innerHTML = `
    <div style="display:grid;gap:8px">
      <div>Active Mode: <span class="badge medium">${escapeHtml(s.mode)}</span></div>
      <div>Project ID: <span class="mono">${escapeHtml(s.project_id)}</span></div>
      <div>Firebase Auth: <strong>${s.auth_ready ? "CONNECTED" : "LOCAL FALLBACK"}</strong></div>
      <div>Cloud Firestore (11 Collections): <strong>${s.firestore_ready ? "CONNECTED" : "LOCAL SQLITE MIRROR"}</strong></div>
      <div>Firebase Storage: <strong>${escapeHtml(s.storage_fallback)}</strong></div>
      <div>Cloud Functions: <strong>${escapeHtml(s.functions_mode)}</strong></div>
      <div>App Check Enforced: <strong>${s.app_check_enforced ? "YES" : "NO"}</strong></div>
    </div>
  `;
}

async function loadSettings() {
  const res = await apiFetch("/api/v1/settings");
  if (!res.ok) return;
  const s = await res.json();
  document.getElementById("set-eps").value = s.dp_epsilon_budget;
  document.getElementById("set-sigma").value = s.dp_noise_multiplier;
  document.getElementById("set-strat").value = s.fl_strategy;
  document.getElementById("set-rate").value = s.rate_limit_auth_per_min;
}

/* ==================== BOOTSTRAP & EVENT WIRING ==================== */
window.addEventListener("DOMContentLoaded", async () => {
  checkHealth();
  loadPublicTenants();
  const fbCfg = await loadRuntimeFirebaseConfig();
  runtimeFirebase = await initFirebaseWeb(fbCfg);

  document.getElementById("tab-btn-signin").onclick = () => switchAuthTab("signin");
  document.getElementById("tab-btn-register").onclick = () => switchAuthTab("register");
  document.getElementById("tab-btn-reset").onclick = () => switchAuthTab("reset");

  document.getElementById("form-signin").onsubmit = async (e) => {
    e.preventDefault();
    clearAuthAlert();
    const u = document.getElementById("login-username").value.trim();
    const p = document.getElementById("login-password").value;
    try {
      if (runtimeFirebase.ready && u.includes("@")) {
        const idTok = await firebaseSignInEmail(u, p);
        const syncRes = await fetch(`${DEFAULT_API_BASE}/api/v1/auth/firebase-sync`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id_token: idTok }),
        });
        const sd = await syncRes.json();
        if (!syncRes.ok) { showAuthAlert(sd.detail || "Firebase auth denied"); return; }
        setToken(idTok);
      } else {
        const res = await fetch(`${DEFAULT_API_BASE}/api/v1/auth/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: u, password: p }),
        });
        const data = await res.json();
        if (!res.ok) { showAuthAlert(data.detail || "Invalid credentials"); return; }
        setToken(data.access_token);
      }
      await enterDashboard();
    } catch (err) {
      showAuthAlert(err.message || "Sign in failed");
    }
  };

  document.getElementById("form-register").onsubmit = async (e) => {
    e.preventDefault();
    clearAuthAlert();
    const payload = {
      full_name: document.getElementById("reg-fullname").value.trim(),
      email: document.getElementById("reg-email").value.trim(),
      username: document.getElementById("reg-username").value.trim(),
      password: document.getElementById("reg-password").value,
      tenant_id: document.getElementById("reg-tenant-select").value,
      role: document.getElementById("reg-role").value,
    };
    const res = await fetch(`${DEFAULT_API_BASE}/api/v1/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) showAuthAlert(data.detail || "Registration error");
    else showAuthAlert(data.message, "var(--warning)");
  };

  document.getElementById("form-reset").onsubmit = async (e) => {
    e.preventDefault();
    const email = document.getElementById("reset-email").value.trim();
    if (runtimeFirebase.ready) {
      await firebaseSendReset(email).catch(() => {});
    }
    await fetch(`${DEFAULT_API_BASE}/api/v1/auth/password-reset`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    showAuthAlert("Password reset workflow initiated.", "var(--success)");
  };

  document.querySelectorAll(".nav-item").forEach((b) => (b.onclick = () => switchPage(b.dataset.page)));
  document.getElementById("btn-mobile-menu").onclick = () => document.getElementById("sidebar").classList.toggle("open");
  document.getElementById("btn-theme-toggle").onclick = () => {
    const html = document.documentElement;
    html.dataset.theme = html.dataset.theme === "light" ? "dark" : "light";
  };

  document.getElementById("btn-logout").onclick = async () => {
    await apiFetch("/api/v1/auth/logout", { method: "POST" }).catch(() => {});
    await firebaseSignOut().catch(() => {});
    if (stopSSE) stopSSE();
    if (stopFirestoreListener) stopFirestoreListener();
    setToken("");
    location.reload();
  };

  document.getElementById("btn-ov-refresh").onclick = () => loadOverview();
  document.getElementById("btn-ov-sim").onclick = async () => {
    const r = await apiFetch("/api/v1/threats/simulate", { method: "POST" });
    if (r.ok) { showToast("warning", "Synthetic Telemetry Injected", "Scored by LSTM + XAI."); loadOverview(); }
  };
  document.getElementById("btn-ov-fl").onclick = async () => {
    const r = await apiFetch("/api/v1/fl/trigger", { method: "POST", body: JSON.stringify({ rounds: 1, strategy: "krum" }) });
    if (r.ok) { const d = await r.json(); showToast("success", "Flower FL Round Complete", d.message); loadOverview(); }
  };

  document.getElementById("analyze-preset").onchange = (e) => {
    const p = PRESETS[e.target.value];
    if (!p) return;
    document.getElementById("f-failed").value = p.num_failed_logins || 0;
    document.getElementById("f-freq").value = p.request_frequency || 5;
    document.getElementById("f-bytes").value = p.bytes_transferred_kb || 200;
    document.getElementById("f-cross").value = p.cross_tenant_access_attempts || 0;
    document.getElementById("f-secrets").value = p.secret_detection_count || 0;
    document.getElementById("f-priv").value = p.privilege_level || 1;
  };

  document.getElementById("form-analyze").onsubmit = async (e) => {
    e.preventDefault();
    const preset = PRESETS[document.getElementById("analyze-preset").value] || {};
    const features = {
      ...preset,
      num_failed_logins: Number(document.getElementById("f-failed").value),
      request_frequency: Number(document.getElementById("f-freq").value),
      bytes_transferred_kb: Number(document.getElementById("f-bytes").value),
      cross_tenant_access_attempts: Number(document.getElementById("f-cross").value),
      secret_detection_count: Number(document.getElementById("f-secrets").value),
      privilege_level: Number(document.getElementById("f-priv").value),
    };
    const r = await apiFetch("/api/v1/threats/analyze", {
      method: "POST",
      body: JSON.stringify({ model_type: document.getElementById("analyze-model").value, features }),
    });
    if (r.ok) {
      const data = await r.json();
      renderXaiCard(document.getElementById("analyze-result-box"), data);
      loadThreats();
    }
  };

  document.getElementById("btn-hist-refresh").onclick = () => loadHistory();
  document.getElementById("btn-run-bench").onclick = async () => {
    showToast("info", "Benchmark Running", "Evaluating LSTM, Random Forest, and XGBoost…");
    const r = await apiFetch("/api/v1/fl/benchmarks/run", { method: "POST" });
    if (r.ok) { showToast("success", "Benchmarks Complete", "Updated metrics persisted."); loadBenchmarks(); }
  };

  document.getElementById("form-fl-trigger").onsubmit = async (e) => {
    e.preventDefault();
    const r = await apiFetch("/api/v1/fl/trigger", {
      method: "POST",
      body: JSON.stringify({
        strategy: document.getElementById("fl-strategy").value,
        rounds: Number(document.getElementById("fl-rounds-count").value),
        dp_noise_multiplier: Number(document.getElementById("fl-sigma").value),
        inject_byzantine: document.getElementById("fl-byzantine").checked,
      }),
    });
    if (r.ok) { const d = await r.json(); showToast("success", "Flower FL Finished", d.message); loadFL(); }
  };

  document.getElementById("btn-xai-load").onclick = () => inspectAlertXai(document.getElementById("xai-alert-select").value);
  document.getElementById("btn-iso-probe").onclick = () => runRealIsolationProbe();
  document.getElementById("btn-rotate-key").onclick = async () => {
    const r = await apiFetch("/api/v1/tenants/me/rotate-key", { method: "POST" });
    if (r.ok) { showToast("success", "HKDF Key Rotated", "New DEK version derived."); loadIsolation(); }
  };
  document.getElementById("form-archive").onsubmit = async (e) => {
    e.preventDefault();
    let payload;
    try { payload = JSON.parse(document.getElementById("arch-payload").value); } catch { payload = { raw: document.getElementById("arch-payload").value }; }
    const r = await apiFetch("/api/v1/tenants/me/encrypt-archive", {
      method: "POST",
      body: JSON.stringify({ archive_name: document.getElementById("arch-name").value, payload }),
    });
    if (r.ok) { showToast("success", "Encrypted Archive Stored", "AES-256-GCM AAD verified."); loadIsolation(); }
  };

  document.getElementById("btn-export-csv").onclick = () =>
    downloadAuthenticatedBlob("/api/v1/audit/logs/export", "audit_logs.csv").catch((e) => showToast("danger", "Export Error", e.message));
  document.getElementById("btn-export-pdf").onclick = () =>
    downloadAuthenticatedBlob("/api/v1/audit/reports/pdf", "security_report.pdf").catch((e) => showToast("danger", "Report Error", e.message));

  document.getElementById("form-cicd").onsubmit = async (e) => {
    e.preventDefault();
    const r = await apiFetch("/api/v1/cicd/scan", {
      method: "POST",
      body: JSON.stringify({
        repository_name: document.getElementById("cicd-repo").value,
        commit_sha: document.getElementById("cicd-sha").value,
        secrets_detected: Number(document.getElementById("cicd-secrets").value),
        vulnerabilities_detected: Number(document.getElementById("cicd-vulns").value),
      }),
    });
    if (r.ok) {
      const d = await r.json();
      document.getElementById("cicd-result").innerHTML = `<span class="badge ${d.decision === "BLOCK" ? "critical" : "verified"}">${escapeHtml(d.decision)}</span> <span>${escapeHtml(d.reasons.join("; "))}</span>`;
    }
  };

  document.getElementById("form-settings").onsubmit = async (e) => {
    e.preventDefault();
    const r = await apiFetch("/api/v1/settings", {
      method: "PUT",
      body: JSON.stringify({
        dp_epsilon_budget: Number(document.getElementById("set-eps").value),
        dp_noise_multiplier: Number(document.getElementById("set-sigma").value),
        fl_strategy: document.getElementById("set-strat").value,
        rate_limit_auth_per_min: Number(document.getElementById("set-rate").value),
      }),
    });
    if (r.ok) showToast("success", "Settings Saved", "Policy updated in DB & Firestore.");
  };

  document.getElementById("btn-open-add-tenant").onclick = () => (document.getElementById("modal-add-tenant").style.display = "flex");
  document.getElementById("btn-cancel-tenant").onclick = () => (document.getElementById("modal-add-tenant").style.display = "none");
  document.getElementById("form-add-tenant").onsubmit = async (e) => {
    e.preventDefault();
    const r = await apiFetch("/api/v1/tenants/", {
      method: "POST",
      body: JSON.stringify({ name: document.getElementById("new-tenant-name").value.trim() }),
    });
    if (r.ok) {
      document.getElementById("modal-add-tenant").style.display = "none";
      showToast("success", "Tenant Created", "Provisioned with HKDF AES-256-GCM.");
      loadPublicTenants();
      loadUsers();
    }
  };

  if (getToken()) {
    try { await enterDashboard(); } catch { setToken(""); }
  }
});
