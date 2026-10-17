/**
 * ZeroTrust Banking • Minimalist Client Application
 * Clean, humanized, robust interface logic
 */

const state = {
  personas: {},
  currentPersonaKey: "alice",
  token: null,
  userProfile: null,
  accounts: [],
  lastTelemetry: null
};

document.addEventListener("DOMContentLoaded", async () => {
  initTabs();
  setupEventListeners();
  await loadPersonas();
  await switchPersona("alice");
  pollSystemHealth();
  setInterval(pollSystemHealth, 8000);
});

// Setup Tab Navigation
function initTabs() {
  const tabs = document.querySelectorAll(".tab-btn");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");

      const targetId = tab.getAttribute("data-tab");
      document.querySelectorAll(".tab-panel").forEach(panel => {
        panel.classList.remove("active");
      });
      const activePanel = document.getElementById(targetId);
      if (activePanel) activePanel.classList.add("active");

      if (targetId === "tab-ledger") {
        fetchLedger();
      }
    });
  });
}

function setupEventListeners() {
  const form = document.getElementById("transferForm");
  if (form) form.addEventListener("submit", executeTransfer);

  const btnRefresh = document.getElementById("btnRefreshAccounts");
  if (btnRefresh) btnRefresh.addEventListener("click", fetchAccounts);

  const btnVerify = document.getElementById("btnVerifyLedger");
  if (btnVerify) btnVerify.addEventListener("click", verifyLedgerIntegrity);

  const btnTamper = document.getElementById("btnSimulateTamper");
  if (btnTamper) btnTamper.addEventListener("click", simulateLedgerTamper);

  const btnRefreshLedger = document.getElementById("btnRefreshLedger");
  if (btnRefreshLedger) btnRefreshLedger.addEventListener("click", fetchLedger);

  const btnReset = document.getElementById("btnSystemReset");
  if (btnReset) btnReset.addEventListener("click", resetSystemDemo);

  const btnBurst = document.getElementById("btnWiresharkBurst");
  if (btnBurst) btnBurst.addEventListener("click", triggerWiresharkBurst);
}

// System Node Health
async function pollSystemHealth() {
  try {
    const res = await fetch("/api/status");
    if (!res.ok) return;
    const data = await res.json();

    updateDot("dotGateway", data.gateway?.status);
    updateDot("dotAccount", data.account_service?.status);
    updateDot("dotLedger", data.ledger_service?.status);
    updateDot("dotOpa", data.opa?.status);
  } catch (e) {
    console.warn("Status check failed:", e);
  }
}

function updateDot(dotId, status) {
  const dot = document.getElementById(dotId);
  if (!dot) return;
  dot.className = status === "HEALTHY" ? "dot" : "dot offline";
}

// Persona Management
async function loadPersonas() {
  try {
    const res = await fetch("/api/personas");
    state.personas = await res.json();
    renderPersonaChips();
  } catch (e) {
    showToast("Failed to load personas", "error");
  }
}

function renderPersonaChips() {
  const container = document.getElementById("personaButtonGroup");
  if (!container) return;
  container.innerHTML = "";

  Object.entries(state.personas).forEach(([key, p]) => {
    const isAttacker = key === "rogue_hacker";
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = `user-chip ${key === state.currentPersonaKey ? "active" : ""} ${isAttacker ? "attacker" : ""}`;
    btn.id = `chip-${key}`;
    btn.innerHTML = `
      <span>${p.name}</span>
      <span class="tag">${p.badge}</span>
    `;
    btn.onclick = () => switchPersona(key);
    container.appendChild(btn);
  });
}

async function switchPersona(personaKey) {
  state.currentPersonaKey = personaKey;
  const persona = state.personas[personaKey];
  if (!persona) return;

  document.querySelectorAll(".user-chip").forEach(c => c.classList.remove("active"));
  const activeChip = document.getElementById(`chip-${personaKey}`);
  if (activeChip) activeChip.classList.add("active");

  // Update profile card
  document.getElementById("personaName").textContent = persona.name;
  document.getElementById("personaDescription").textContent = persona.description;

  const roleBadge = document.getElementById("personaRoleBadge");
  roleBadge.textContent = persona.badge.toUpperCase();

  document.getElementById("personaAccountMeta").textContent = persona.account_id ? `Account: ${persona.account_id}` : `Role: ${persona.department || persona.branch || "External Threat"}`;
  document.getElementById("personaLimitMeta").textContent = persona.role === "customer" 
    ? "Transfer Limit: $10,000" 
    : (persona.role === "teller" ? "Transfer Limit: $50,000" : (persona.role === "admin" ? "Transfer Limit: Unlimited" : "Access: Read-Only Audit"));

  if (personaKey === "rogue_hacker") {
    state.token = "rogue-unauthorized-bearer-token";
    const label = document.getElementById("activeWorkloadLabel");
    label.textContent = "mTLS: rogue-unauthorized-workload";
    label.style.color = "var(--red)";
    updateInspectorWithToken(null, persona);
    showToast("Switched to Attacker (rogue certificate)", "info");
    fetchAccounts();
    return;
  }

  const label = document.getElementById("activeWorkloadLabel");
  label.textContent = "mTLS: client-fintech-portal";
  label.style.color = "#a78bfa";

  try {
    const res = await fetch("/api/auth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: personaKey })
    });
    const data = await res.json();
    if (res.ok) {
      state.token = data.access_token;
      state.userProfile = data.user_profile;
      updateInspectorWithToken(data.access_token, persona);
      showToast(`Authenticated as ${persona.name}`, "success");
      logSiemEvent("AUTH_TOKEN", "gateway", persona.id, persona.role, "POST /auth/token", "ALLOW", `Issued JWT token`);
      await fetchAccounts();
    } else {
      showToast(`Authentication failed: ${data.detail || "Error"}`, "error");
    }
  } catch (e) {
    showToast(`Gateway connection error: ${e}`, "error");
  }
}

function updateInspectorWithToken(token, persona) {
  document.getElementById("inspectJwtSub").textContent = persona.id;
  document.getElementById("inspectJwtRole").textContent = persona.role;
  document.getElementById("inspectJwtRaw").textContent = token || "No valid Bearer token";
  document.getElementById("inspectJwtExp").textContent = token ? "7200s" : "N/A";
  document.getElementById("inspectOpaDecision").textContent = "ALLOW";
  document.getElementById("inspectOpaDecision").style.color = "var(--green)";
  document.getElementById("inspectOpaReason").textContent = `Verified user: ${persona.name} (${persona.role})`;
}

// Accounts
async function fetchAccounts() {
  const container = document.getElementById("accountsContainer");
  if (!container) return;

  container.innerHTML = `<div style="color: var(--text-dim); font-size: 12px; padding: 10px;">Loading accounts...</div>`;

  try {
    const res = await fetch("/api/accounts", {
      headers: { "Authorization": `Bearer ${state.token}` }
    });
    const data = await res.json();

    if (res.status === 200 && data.accounts) {
      state.accounts = data.accounts;
      container.innerHTML = "";

      data.accounts.forEach(acc => {
        const isOwn = acc.owner_id === state.currentPersonaKey;
        const box = document.createElement("div");
        box.className = `acc-box ${isOwn ? "owned" : ""}`;
        box.innerHTML = `
          <div class="acc-top">
            <span>${acc.account_type} • ${acc.account_id}</span>
            <span class="tag">${isOwn ? "Your Account" : "Owner: " + acc.owner_id}</span>
          </div>
          <div class="acc-balance">$${acc.balance.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })} <span style="font-size: 12px; color: var(--text-dim);">${acc.currency}</span></div>
          <div class="acc-bottom">
            <span>ID: ${acc.account_id}</span>
            <button class="btn btn-secondary btn-sm" onclick="testAccountInspection('${acc.account_id}')">
              Test Access (ABAC)
            </button>
          </div>
        `;
        container.appendChild(box);
      });

      logSiemEvent("LIST_ACCOUNTS", "account-service", state.currentPersonaKey, state.personas[state.currentPersonaKey]?.role, "GET /accounts", "ALLOW", `Retrieved ${data.accounts.length} accounts`);
    } else {
      container.innerHTML = `
        <div style="padding: 10px; background: var(--red-subtle); border: 1px solid var(--red); border-radius: var(--radius-sm); font-size: 12px; color: var(--red);">
          <strong>Access Denied:</strong> ${data.detail?.message || data.detail || "Unable to load accounts."}
        </div>
      `;
    }
  } catch (e) {
    container.innerHTML = `<div style="color: var(--red); font-size: 12px;">Error: ${e}</div>`;
  }
}

async function testAccountInspection(accountId) {
  try {
    const res = await fetch(`/api/accounts/${accountId}`, {
      headers: { "Authorization": `Bearer ${state.token}` }
    });
    const data = await res.json();

    if (res.ok) {
      showToast(`Access allowed: Viewed ${accountId} ($${data.account.balance.toLocaleString()})`, "success");
      document.getElementById("inspectOpaDecision").textContent = "ALLOW";
      document.getElementById("inspectOpaDecision").style.color = "var(--green)";
      document.getElementById("inspectOpaReason").textContent = data.authz_reason || "Access authorized by ABAC policy.";
      logSiemEvent("ACCOUNT_READ", "account-service", state.currentPersonaKey, state.personas[state.currentPersonaKey]?.role, `GET /accounts/${accountId}`, "ALLOW", data.authz_reason);
    } else {
      const reason = data.detail?.reason || data.detail?.message || "Policy denied";
      showToast(`Access blocked: ${reason}`, "error");
      document.getElementById("inspectOpaDecision").textContent = "DENY";
      document.getElementById("inspectOpaDecision").style.color = "var(--red)";
      document.getElementById("inspectOpaReason").textContent = reason;
      logSiemEvent("ACCOUNT_READ", "account-service", state.currentPersonaKey, state.personas[state.currentPersonaKey]?.role, `GET /accounts/${accountId}`, "DENY", reason);
    }
  } catch (e) {
    showToast(`Request error: ${e}`, "error");
  }
}

function setTransferAmount(amt) {
  const input = document.getElementById("transferAmount");
  if (input) input.value = amt.toFixed(2);
}

// Transfer Execution
async function executeTransfer(e) {
  e.preventDefault();
  const src = document.getElementById("transferSource").value;
  const dst = document.getElementById("transferDest").value;
  const amount = parseFloat(document.getElementById("transferAmount").value);
  const note = document.getElementById("transferNote").value || "Transfer";

  const resultBox = document.getElementById("transferResultBox");
  const submitBtn = document.getElementById("btnSubmitTransfer");
  submitBtn.disabled = true;
  submitBtn.textContent = "Checking policy in OPA...";

  try {
    const res = await fetch("/api/transfers", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${state.token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        source_account: src,
        destination_account: dst,
        amount: amount,
        note: note
      })
    });
    const data = await res.json();
    resultBox.style.display = "block";

    if (res.ok && data.status === "COMPLETED") {
      resultBox.innerHTML = `
        <div style="background: var(--green-subtle); border: 1px solid var(--green); border-radius: var(--radius-sm); padding: 12px;">
          <div style="font-weight: 600; color: var(--green); margin-bottom: 4px;">Transfer Completed</div>
          <div style="font-size: 12px; color: var(--text);">
            Transferred <strong>$${amount.toFixed(2)} USD</strong> from <code>${src}</code> to <code>${dst}</code>.
          </div>
          <div style="font-size: 11px; font-family: var(--font-mono); color: var(--text-dim); margin-top: 6px;">
            New balance: $${data.remaining_balance?.toFixed(2)} • Hash: ${data.ledger_receipt?.entry_hash?.substring(0, 24)}...
          </div>
        </div>
      `;
      showToast(`Transferred $${amount.toFixed(2)}`, "success");
      document.getElementById("inspectOpaDecision").textContent = "ALLOW";
      document.getElementById("inspectOpaDecision").style.color = "var(--green)";
      document.getElementById("inspectOpaReason").textContent = data.authz_reason;

      logSiemEvent("TRANSFER", "account-service", state.currentPersonaKey, state.personas[state.currentPersonaKey]?.role, `POST /accounts/${src}/transfers`, "ALLOW", data.authz_reason);
      fetchAccounts();
    } else {
      const reason = data.detail?.reason || data.detail?.message || "Transfer blocked by policy";
      resultBox.innerHTML = `
        <div style="background: var(--red-subtle); border: 1px solid var(--red); border-radius: var(--radius-sm); padding: 12px;">
          <div style="font-weight: 600; color: var(--red); margin-bottom: 4px;">Transfer Blocked</div>
          <div style="font-size: 12px; color: var(--text);">${reason}</div>
        </div>
      `;
      showToast(`Blocked: ${reason}`, "error");
      document.getElementById("inspectOpaDecision").textContent = "DENY";
      document.getElementById("inspectOpaDecision").style.color = "var(--red)";
      document.getElementById("inspectOpaReason").textContent = reason;

      logSiemEvent("TRANSFER", "account-service", state.currentPersonaKey, state.personas[state.currentPersonaKey]?.role, `POST /accounts/${src}/transfers`, "DENY", reason);
    }
  } catch (err) {
    showToast(`Transfer failed: ${err}`, "error");
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Send Transfer";
  }
}

// Ledger Table
async function fetchLedger() {
  const tbody = document.getElementById("ledgerTableBody");
  const banner = document.getElementById("ledgerIntegrityBanner");
  if (!tbody) return;

  tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--text-dim); padding: 16px;">Loading ledger entries...</td></tr>`;
  if (banner) banner.style.display = "none";

  try {
    const res = await fetch("/api/ledger", {
      headers: { "Authorization": `Bearer ${state.token}` }
    });
    const data = await res.json();

    if (res.status === 200 && data.audit_entries) {
      renderLedgerTable(data);
      logSiemEvent("LEDGER_READ", "ledger-service", state.currentPersonaKey, state.personas[state.currentPersonaKey]?.role, "GET /ledger/audit-trail", "ALLOW", `Read ${data.total_entries} entries`);
    } else {
      const reason = data.detail?.message || data.detail?.reason || "Access restricted by segregation of duties.";
      tbody.innerHTML = `
        <tr>
          <td colspan="10" style="padding: 24px; text-align: center;">
            <div style="font-weight: 500; color: var(--red); margin-bottom: 4px;">Access Denied</div>
            <div style="font-size: 12px; color: var(--text-dim); margin-bottom: 12px;">${reason}</div>
            <div style="display: inline-flex; gap: 8px;">
              <button class="btn btn-secondary btn-sm" onclick="switchPersona('auditor_carol')">Switch to Carol (Auditor)</button>
              <button class="btn btn-secondary btn-sm" onclick="switchPersona('admin_dave')">Switch to Dave (Admin)</button>
            </div>
          </td>
        </tr>
      `;
      logSiemEvent("LEDGER_READ", "ledger-service", state.currentPersonaKey, state.personas[state.currentPersonaKey]?.role, "GET /ledger/audit-trail", "DENY", reason);
    }
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="10" style="color: var(--red); text-align: center;">Error: ${e}</td></tr>`;
  }
}

function renderLedgerTable(data) {
  const tbody = document.getElementById("ledgerTableBody");
  const banner = document.getElementById("ledgerIntegrityBanner");
  if (!tbody) return;

  if (banner) {
    banner.style.display = "block";
    if (data.cryptographic_integrity_verified) {
      banner.innerHTML = `
        <div style="background: var(--green-subtle); border: 1px solid var(--green); border-radius: var(--radius-sm); padding: 10px 14px; display: flex; align-items: center; justify-content: space-between;">
          <div style="font-size: 12px; color: var(--green);">
            <strong>Hash Chain Verified:</strong> All ${data.total_entries} blocks match SHA-256 parent links. No tampering found.
          </div>
          <span class="status-badge ok">INTACT</span>
        </div>
      `;
    } else {
      banner.innerHTML = `
        <div style="background: var(--red-subtle); border: 1px solid var(--red); border-radius: var(--radius-sm); padding: 10px 14px; display: flex; align-items: center; justify-content: space-between;">
          <div style="font-size: 12px; color: var(--red);">
            <strong>Integrity Alert:</strong> Tampering detected in block(s) #${data.tampered_blocks?.join(", ") || "Unknown"}. Hash mismatch!
          </div>
          <button class="btn btn-secondary btn-sm" onclick="resetSystemDemo()">Reset Ledger</button>
        </div>
      `;
    }
  }

  if (data.audit_entries.length === 0) {
    tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--text-dim); padding: 16px;">Ledger is empty. Make a transfer in the Banking tab to create Block #1.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";

  data.audit_entries.forEach((entry, idx) => {
    const isValid = entry.is_cryptographically_valid !== false;
    const tr = document.createElement("tr");
    if (!isValid) tr.className = "tampered";

    tr.innerHTML = `
      <td>${entry.block_index || idx + 1}</td>
      <td style="font-family: var(--font-mono); color: var(--text-dim);">${entry.timestamp.substring(11, 19)}</td>
      <td><code>${entry.source_account}</code></td>
      <td><code>${entry.destination_account}</code></td>
      <td><strong>$${entry.amount.toFixed(2)}</strong></td>
      <td><code>${entry.workload_cn}</code></td>
      <td>${entry.executed_by_user}</td>
      <td><span class="hash" title="${entry.prev_hash}">${entry.prev_hash}</span></td>
      <td><span class="hash ${isValid ? '' : 'invalid'}" title="${entry.entry_hash}">${entry.entry_hash}</span></td>
      <td>
        <span class="status-badge ${isValid ? 'ok' : 'err'}">
          ${isValid ? 'OK' : 'TAMPERED'}
        </span>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

async function verifyLedgerIntegrity() {
  showToast("Verifying SHA-256 hash chain...", "info");
  await fetchLedger();
}

async function simulateLedgerTamper() {
  let tokenToUse = state.token;
  if (state.currentPersonaKey !== "admin_dave") {
    showToast("Switching to Admin to tamper with database row...", "info");
    const res = await fetch("/api/auth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "admin_dave" })
    });
    const d = await res.json();
    tokenToUse = d.access_token;
  }

  try {
    const res = await fetch("/api/ledger/tamper", {
      method: "POST",
      headers: { "Authorization": `Bearer ${tokenToUse}` }
    });
    const data = await res.json();
    if (res.ok) {
      showToast("Altered database row without updating hash. Re-verifying...", "error");
      await fetchLedger();
    } else {
      showToast(`Tamper failed: ${data.detail?.message || data.detail || "Error"}`, "error");
    }
  } catch (e) {
    showToast(`Tamper error: ${e}`, "error");
  }
}

async function resetSystemDemo() {
  let tokenToUse = state.token;
  if (state.currentPersonaKey !== "admin_dave") {
    const res = await fetch("/api/auth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "admin_dave" })
    });
    const d = await res.json();
    tokenToUse = d.access_token;
  }

  try {
    const res = await fetch("/api/system/reset", {
      method: "POST",
      headers: { "Authorization": `Bearer ${tokenToUse}` }
    });
    if (res.ok) {
      showToast("Balances and ledger reset to default", "success");
      await fetchAccounts();
      await fetchLedger();
    } else {
      showToast("Reset failed", "error");
    }
  } catch (e) {
    showToast(`Reset error: ${e}`, "error");
  }
}

// Scenarios 1-9
async function triggerScenario(id) {
  const terminal = document.getElementById("scenarioTerminalOutput");
  const verdictBadge = document.getElementById("scenarioVerdictBadge");
  verdictBadge.textContent = `Running #${id}...`;

  terminal.innerHTML = `<div style="color: var(--blue);">Running Scenario #${id}...</div>`;

  try {
    const res = await fetch(`/api/demo/scenario/${id}`, { method: "POST" });
    const data = await res.json();

    verdictBadge.textContent = data.verdict || "Done";

    let html = `
      <div style="margin-bottom: 8px;">
        <strong>Scenario ${data.scenario}: ${data.title}</strong>
        <div style="color: var(--text-dim); font-size: 11px;">Rule: ${data.zero_trust_principle}</div>
        <div style="color: ${data.verdict?.includes('DENIED') || data.verdict?.includes('DROPPED') ? 'var(--red)' : 'var(--green)'}; margin-top: 2px;">
          Verdict: ${data.verdict}
        </div>
      </div>
    `;

    if (data.steps) {
      data.steps.forEach(s => {
        const color = s.status === "BLOCKED" ? "var(--red)" : (s.status === "SUCCESS" ? "var(--green)" : "var(--amber)");
        html += `
          <div style="margin-top: 4px;">
            <span style="color: ${color};">[Step ${s.step}] [${s.status}]</span> ${s.action}
            ${s.status_code ? `<span style="color: var(--text-dim);"> (Status: ${s.status_code})</span>` : ""}
            ${s.detail ? `<div style="color: var(--text-muted); padding-left: 12px;">${s.detail}</div>` : ""}
            ${s.response ? `<pre style="color: #94a3b8; font-size: 11px; padding: 4px 6px; background: #0c0e14; border-radius: 3px; margin-top: 2px;">${JSON.stringify(s.response, null, 2)}</pre>` : ""}
          </div>
        `;
      });
    }

    terminal.innerHTML = html;
    showToast(`Scenario #${id}: ${data.verdict}`, "success");
    logSiemEvent("SCENARIO", "test-suite", "automated", "secops", `SCENARIO_${id}`, data.verdict, data.title);
  } catch (e) {
    terminal.innerHTML = `<div style="color: var(--red);">Error: ${e}</div>`;
  }
}

// Wireshark Burst
async function triggerWiresharkBurst() {
  const output = document.getElementById("wiresharkBurstOutput");
  output.innerHTML = `<span style="color: var(--blue);">Sending test traffic across mesh...</span>`;

  try {
    const res = await fetch("/api/wireshark/burst", { method: "POST" });
    const data = await res.json();

    let html = `
      <div style="background: rgba(59, 130, 246, 0.08); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 10px;">
        <div style="font-weight: 500; color: #fff; margin-bottom: 6px;">${data.message}</div>
        <div style="display: flex; flex-direction: column; gap: 3px; font-family: var(--font-mono); font-size: 11px;">
    `;

    data.operations.forEach((op, i) => {
      html += `<div>#${i + 1}: ${op.action} &rarr; <code>${op.target}</code> (${op.status})</div>`;
    });

    html += `
        </div>
        <div style="font-size: 11px; color: var(--text-dim); margin-top: 8px;">
          Filter in Wireshark: <code>tls.handshake.type == 13</code> (Cert Request) or <code>tls.handshake.type == 11</code> (Certificates).
        </div>
      </div>
    `;

    output.innerHTML = html;
    showToast("Traffic burst sent", "success");
  } catch (e) {
    output.innerHTML = `<span style="color: var(--red);">Failed: ${e}</span>`;
  }
}

function copyFilter(filterText) {
  navigator.clipboard.writeText(filterText).then(() => {
    showToast(`Copied: ${filterText}`, "info");
  }).catch(() => {
    showToast("Failed to copy", "error");
  });
}

// SIEM Logger
function logSiemEvent(eventType, service, userId, userRole, action, decision, reason) {
  const terminal = document.getElementById("siemTerminalOutput");
  if (!terminal) return;

  const ts = new Date().toISOString().substring(11, 19);
  const color = decision === "ALLOW" ? "var(--green)" : "var(--red)";

  const entry = document.createElement("div");
  entry.style.marginTop = "3px";
  entry.style.borderLeft = `2px solid ${color}`;
  entry.style.paddingLeft = "6px";
  entry.innerHTML = `
    <span style="color: var(--text-dim);">${ts}</span> 
    <span style="color: #38bdf8;">[${service}]</span> 
    <span>${action}</span> 
    <strong style="color: ${color};">[${decision}]</strong>
    <span style="color: var(--text-dim); font-size: 10.5px;">• ${userId} (${userRole}) • ${reason || "OK"}</span>
  `;

  terminal.prepend(entry);
}

function clearTelemetryLog() {
  const terminal = document.getElementById("siemTerminalOutput");
  if (terminal) {
    terminal.innerHTML = `<div style="color: var(--text-dim);">[Cleared] Event log reset.</div>`;
  }
}

// Toasts
function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${message}</span>`;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 200);
  }, 3000);
}
