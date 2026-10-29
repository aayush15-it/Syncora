/**
 * MerkleChain — Peer Network & Local Synchronization Dashboard
 * Vanilla ES6+ implementation with zero external framework dependencies.
 */

const state = {
  csrf: "",
  view: location.hash.slice(1) || "overview",
  peer: {
    role: "none",
    state: "IDLE",
    phase: "Idle",
    device_id: "",
    sync_root: "",
    peer_address: "",
    peer_port: 47832,
    session_id: "",
    remote_peer_id: "",
    current_file: "",
    bytes_transferred: 0,
    total_bytes: 0,
    files_transferred: 0,
    total_files: 0,
    last_error: "",
    tls_negotiated: false,
    tls_version: "",
    peer_pin_verified: false,
    expected_pin: "",
    received_pin: ""
  },
  peerPlan: null,
  peerActivity: [],
  peerEvents: [],
  // Preserved Local Mode state
  plan: null,
  files: [],
  activity: [],
  lastResult: null,
  selected: null,
  inspectorTab: "metadata",
  restoreTarget: null,
  // Selective sync and Algorithm Explorer state
  scopeMode: "all",
  sourceFiles: [],
  selectedPaths: new Set(),
  treeExpanded: new Set(),
  treeSearch: "",
  lastComparison: null,
  lastSyncResult: null
};

const $ = id => document.getElementById(id);
const put = (el, val) => { if (el) el.textContent = String(val ?? ""); };

const validViews = new Set([
  "home", "network-select",
  "host-overview", "host-clients", "host-submissions", "host-workspace", "host-review", "host-publish", "host-versions", "host-activity",
  "client-overview", "client-submit", "client-submissions", "client-review", "client-receive", "client-versions", "client-account",
  "local-overview", "synchronize", "versions", "algorithm", "merkle", "chunks", "scheduler", "activity",
  "overview", "pairing", "connection", "peer-sync", "approval", "progress", "peer-activity", "settings"
]);

function escBytes(val) {
  let n = Math.max(0, Number(val) || 0);
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
  return `${n.toFixed(n >= 10 ? 1 : 2)} ${units[i]}`;
}

async function api(path, body) {
  const opts = body
    ? {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ csrf: state.csrf, ...body })
      }
    : { credentials: "same-origin" };

  const response = await fetch(path, opts);
  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error(`HTTP ${response.status}: invalid server response`);
  }
  if (!response.ok || data.error) {
    throw new Error(data.error || `HTTP ${response.status}`);
  }
  return data;
}

function toast(message) {
  put($("toast"), message);
  $("toast")?.classList.add("show");
  setTimeout(() => $("toast")?.classList.remove("show"), 3200);
}

function empty(container, message) {
  if (!container) return;
  const p = document.createElement("p");
  p.className = "empty";
  p.textContent = message;
  container.replaceChildren(p);
}

function view(name, pushHash = true) {
  // Devices & Access has moved to Peer Network; redirect legacy route safely.
  if (name === "devices") {
    name = "synchronize";
    if (pushHash) { location.hash = "#synchronize"; }
  }
  // Benchmarks removed from dashboard; redirect legacy route safely to overview.
  if (name === "benchmarks") {
    name = "overview";
    if (pushHash) { location.hash = "#overview"; }
  }
  // Fresh launch with no hash opens the landing page. Unknown routes fall back safely.
  if (!name || name === "" || !validViews.has(name)) {
    name = "home";
  }
  state.view = name;

  // Toggle landing page full-screen mode vs workspace mode
  if (document.body) {
    document.body.classList.toggle("landing-active", name === "home");
  }

  // Determine active workspace and update sidebar and topbar context
  const isHost = ["host-overview", "host-clients", "host-submissions", "host-workspace", "host-review", "host-publish", "host-versions", "host-activity"].includes(name);
  const isClient = ["client-overview", "client-submit", "client-submissions", "client-review", "client-receive", "client-versions", "client-account"].includes(name);
  const isLocal = ["local-overview", "synchronize", "versions", "algorithm", "merkle", "chunks", "scheduler", "activity"].includes(name);
  const isPeer = ["overview", "pairing", "connection", "peer-sync", "approval", "progress", "peer-activity"].includes(name);

  if (document.body) {
    if (name === "home" || name === "network-select") {
      document.body.dataset.workspace = "home";
    } else if (isHost) {
      document.body.dataset.workspace = "host";
    } else if (isClient) {
      document.body.dataset.workspace = "client";
    } else if (isLocal) {
      document.body.dataset.workspace = "local";
    } else {
      document.body.dataset.workspace = "peer";
    }
  }

  // Update dynamic sidebar labels and toggle button
  if (name !== "home") {
    let wsLabel = "Local Workspace";
    let modeLabel = "Offline Mode";
    let modeClass = "state-pill active";

    if (isHost) {
      wsLabel = "Host Dashboard";
      modeLabel = "Host Mode (Admin)";
      modeClass = "state-pill active";
    } else if (isClient) {
      wsLabel = "Client Workspace";
      const u = localStorage.getItem("mc_client_username") || "Alice";
      modeLabel = `Client (${u})`;
      modeClass = "state-pill active";
    } else if (isLocal) {
      wsLabel = "Local Workspace";
      modeLabel = "Offline Mode";
    } else {
      wsLabel = "Peer Network";
      modeLabel = state.peer?.state === "CONNECTED" ? "Connected" : "Standby";
      modeClass = state.peer?.state === "CONNECTED" ? "state-pill active" : "state-pill";
    }

    put($("sidebar-workspace-label"), wsLabel);
    put($("breadcrumb-section"), wsLabel);
    const modeBadge = $("workspace-mode-badge");
    if (modeBadge) {
      modeBadge.textContent = modeLabel;
      modeBadge.className = modeClass;
    }
    const peerControls = $("topbar-peer-controls");
    if (peerControls) {
      peerControls.style.display = isPeer ? "flex" : "none";
    }
    const toggleBtn = $("btn-toggle-workspace");
    if (toggleBtn) {
      if (isHost || isClient) {
        toggleBtn.innerHTML = 'Switch Workspace / Role <span>&rlarr;</span>';
        toggleBtn.dataset.go = "network-select";
      } else if (isLocal) {
        toggleBtn.innerHTML = 'Switch to Network Model <span>&rlarr;</span>';
        toggleBtn.dataset.go = "network-select";
      } else {
        toggleBtn.innerHTML = 'Switch to Local Workspace <span>&rlarr;</span>';
        toggleBtn.dataset.go = "local-overview";
      }
    }
  }

  document.querySelectorAll(".view").forEach(v => {
    v.classList.toggle("active", v.id === `view-${name}`);
  });

  document.querySelectorAll("[data-view]").forEach(a => {
    a.classList.toggle("active", a.dataset.view === name);
  });

  const targetSec = document.querySelector(`#view-${name}`);
  const activeTitle = targetSec?.dataset.title || name;
  put($("breadcrumb-current"), activeTitle);

  const targetHash = `#${name}`;
  if (pushHash) {
    if (location.hash !== targetHash) {
      location.hash = targetHash;
    }
  } else {
    if (location.hash !== targetHash) {
      history.replaceState(null, "", targetHash);
    }
  }

  // Load view-specific data safely
  try {
    if (name === "peer-sync" || name === "approval") loadPeerPlan();
    if (name === "peer-activity") loadPeerActivity();
    if (name === "versions") loadVersions();
    if (["activity", "chunks"].includes(name)) loadActivity();
    if (name === "local-overview") renderLocalOverview();
    if (name === "merkle") renderMerkle();
    if (name === "scheduler") renderScheduler();
    if (name === "chunks") renderChunks();
    // Host view loaders
    if (name === "host-overview") loadHostOverview();
    if (name === "host-clients") loadHostClients();
    if (name === "host-submissions") loadHostSubmissions();
    if (name === "host-workspace") loadHostWorkspaceFiles();
    if (name === "host-review") loadHostReview();
    if (name === "host-versions") loadHostVersions();
    if (name === "host-activity") loadHostActivity();
    // Client view loaders
    if (name === "client-overview") loadClientOverview();
    if (name === "client-submissions") loadClientSubmissions();
    if (name === "client-review") loadClientUpdates();
    if (name === "client-receive") populateClientReceiveDropdown();
    if (name === "client-versions") loadClientVersions();
    if (name === "client-account") loadClientAccount();
  } catch (err) {
    console.error("View data load error:", err);
  }
}

/* ========================================================================= */
/* PEER NETWORK WORKFLOW                                                     */
/* ========================================================================= */

function updatePeerUI(p) {
  state.peer = { ...state.peer, ...p };

  // Overview updates
  put($("overview-device-id"), p.device_id || "Unconfigured");
  put($("overview-peer-state"), p.state || "IDLE");
  put($("overview-sync-root"), p.sync_root || "Not configured");
  put($("overview-peer-endpoint"), p.peer_address ? `${p.peer_address}:${p.peer_port}` : "—");
  put($("overview-local-pin"), p.local_certificate_pin || "Not loaded");
  put($("overview-expected-pin"), p.expected_peer_pin || "Not configured");

  const roleText = (p.role || "none").toUpperCase();
  put($("overview-role-badge"), roleText);
  put($("role-badge"), roleText);
  const roleBadge = $("role-badge");
  if (roleBadge) roleBadge.className = `mode-badge role-${p.role || "none"}`;

  const secDot = $("sec-cert-dot");
  if (secDot) {
    secDot.className = `sec-dot ${p.local_certificate_pin ? "verified" : ""}`;
  }
  const peerDot = $("sec-peer-dot");
  if (peerDot) {
    peerDot.className = `sec-dot ${p.peer_pin_verified ? "verified" : p.expected_peer_pin ? "unverified" : ""}`;
  }
  const hsDot = $("sec-handshake-dot");
  if (hsDot) {
    hsDot.className = `sec-dot ${p.tls_negotiated ? "verified" : ""}`;
  }
  put($("overview-handshake-text"), p.tls_negotiated ? `Established (${p.tls_version || "TLS 1.3"})` : "Awaiting connection");

  // Connection View updates
  put($("conn-state-badge"), p.state || "STOPPED");
  const connBadge = $("conn-state-badge");
  if (connBadge) connBadge.className = `badge ${p.state === "CONNECTED" || p.state === "COMPLETED" ? "active" : p.state === "ERROR" ? "danger" : ""}`;
  put($("conn-role-pill"), p.role ? `Role: ${p.role.toUpperCase()}` : "No Role");
  put($("conn-phase"), p.phase || "Idle");
  put($("conn-session-id"), p.session_id ? p.session_id.slice(0, 16) + "…" : "—");
  put($("conn-remote-id"), p.remote_peer_id || "—");

  const isRunning = ["LISTENING", "CONNECTING", "CONNECTED", "TRANSFERRING", "COMMITTING", "AWAITING_APPROVAL"].includes(p.state);
  const startBtn = $("btn-start-service");
  const stopBtn = $("btn-stop-service");
  if (startBtn) startBtn.disabled = isRunning || p.role === "none";
  if (stopBtn) stopBtn.disabled = !isRunning;

  if (p.role === "host") {
    put($("conn-instruction"), isRunning ? "Host listener active. Awaiting incoming peer connection on configured port." : "Host mode configured. Click 'Start Service' to begin listening.");
  } else if (p.role === "client") {
    put($("conn-instruction"), isRunning ? "Client session active. Communicating with remote host peer." : "Client mode configured. Click 'Start Service' to connect to host peer.");
  } else {
    put($("conn-instruction"), "Configure device role and credentials in Device Pairing before starting service.");
  }

  put($("auth-tls-status"), p.tls_negotiated ? `Verified (${p.tls_version || "TLS 1.3"})` : "Not connected");
  put($("auth-pin-status"), p.peer_pin_verified ? "Verified Match" : p.expected_peer_pin ? "Pending Handshake" : "No pin configured");
  put($("auth-identity-status"), p.remote_peer_id ? `Authenticated (${p.remote_peer_id})` : "Pending");
  put($("auth-error"), p.last_error || "None");
  if ($("auth-error")) $("auth-error").className = p.last_error ? "error-text" : "muted";

  // Progress View updates
  put($("progress-phase-badge"), p.phase || "IDLE");
  put($("prog-current-file"), p.current_file || "None");
  put($("prog-bytes"), `${escBytes(p.bytes_transferred)} / ${escBytes(p.total_bytes)}`);
  put($("prog-files"), `${p.files_transferred} / ${p.total_files}`);

  const pct = p.total_bytes > 0 ? Math.min(100, Math.round((p.bytes_transferred / p.total_bytes) * 100)) : 0;
  if ($("prog-bar-fill")) $("prog-bar-fill").style.width = `${pct}%`;
  put($("prog-percent-text"), `${pct}%`);
  put($("prog-phase-desc"), getPhaseDescription(p.phase, p.state));

  updateProgressSteps(p.phase);

  // If newly awaiting approval, automatically trigger plan fetch
  if (p.phase === "AwaitingApproval" && (!state.peerPlan || state.peerPlan.session_id !== p.session_id)) {
    loadPeerPlan();
  }
}

function getPhaseDescription(phase, pState) {
  switch (phase) {
    case "Listening": return "Waiting for incoming peer connection on mTLS port...";
    case "Connecting": return "Initiating TCP handshake and TLS transport with peer...";
    case "Handshake": return "Performing mutual TLS verification and leaf certificate pinning...";
    case "ManifestExchange": return "Exchanging SHA-256 Merkle manifests between endpoints...";
    case "Planning": return "Computing bilateral delta synchronization plan...";
    case "AwaitingApproval": return "Plan computed. Awaiting explicit interactive user authorization...";
    case "Transferring": return "Transferring file contents and verifying staged blocks...";
    case "Committing": return "Performing two-phase atomic commit and updating local ledger...";
    case "Completed": return "Synchronization completed and verified successfully.";
    default: return pState === "ERROR" ? "Session encountered an error." : "Engine is currently idle.";
  }
}

function updateProgressSteps(phase) {
  const steps = ["listen", "handshake", "manifest", "plan", "approve", "transfer", "commit"];
  const phaseOrder = {
    "Listening": 0, "Connecting": 0, "Connected": 0,
    "Handshake": 1,
    "ManifestExchange": 2,
    "Planning": 3,
    "AwaitingApproval": 4,
    "Transferring": 5,
    "Committing": 6,
    "Completed": 7
  };

  const currentIdx = phaseOrder[phase] ?? -1;
  steps.forEach((s, idx) => {
    const el = $(`pstep-${s}`);
    if (el) {
      el.classList.toggle("completed", idx < currentIdx);
      el.classList.toggle("active", idx === currentIdx);
    }
  });
}

async function pollPeerStatus() {
  try {
    const data = await api("/api/peer/status");
    updatePeerUI(data);
    put($("connection-status"), data.state === "IDLE" ? "Connected · 127.0.0.1" : `Peer: ${data.state}`);
    $("connection-dot")?.classList.add("online");
  } catch (e) {
    put($("connection-status"), "Offline / Unreachable");
    $("connection-dot")?.classList.remove("online");
  }
}

async function validatePairingConfig() {
  const reportBox = $("validation-report");
  const badge = $("val-badge");
  const details = $("val-details");
  const localPinEl = $("val-local-pin");

  reportBox?.classList.remove("hidden");
  put(badge, "Validating…");
  badge.className = "badge";
  empty(details, "Checking local paths and certificate validity…");

  try {
    const payload = {
      role: $("cfg-role").value,
      device_id: $("cfg-device-id").value.trim(),
      sync_root: $("cfg-sync-root").value.trim(),
      peer_address: $("cfg-peer-addr").value.trim(),
      peer_port: Number($("cfg-peer-port").value) || 47832,
      cert_path: $("cfg-cert-path").value.trim(),
      key_path: $("cfg-key-path").value.trim(),
      ca_path: $("cfg-ca-path").value.trim(),
      expected_peer_pin: $("cfg-expected-pin").value.trim()
    };

    const res = await api("/api/peer/validate-config", payload);
    put(badge, res.valid ? "Configuration Valid" : "Invalid");
    badge.className = `badge ${res.valid ? "active" : "danger"}`;

    details.textContent = res.message || (res.valid ? "All configuration parameters, certificate paths, and pins verified." : "Validation failed.");
    put(localPinEl, res.local_certificate_pin || "Not generated / unavailable");

    if (res.valid) {
      toast("Configuration verified successfully");
    }
  } catch (e) {
    put(badge, "Error");
    badge.className = "badge danger";
    put(details, e.message);
  }
}

async function savePairingConfig(e) {
  e.preventDefault();
  const statusEl = $("pairing-status");
  put(statusEl, "Saving and applying configuration…");
  statusEl.className = "status-msg";

  try {
    const payload = {
      role: $("cfg-role").value,
      device_id: $("cfg-device-id").value.trim(),
      sync_root: $("cfg-sync-root").value.trim(),
      peer_address: $("cfg-peer-addr").value.trim(),
      peer_port: Number($("cfg-peer-port").value) || 47832,
      cert_path: $("cfg-cert-path").value.trim(),
      key_path: $("cfg-key-path").value.trim(),
      ca_path: $("cfg-ca-path").value.trim(),
      expected_peer_pin: $("cfg-expected-pin").value.trim()
    };

    const res = await api("/api/peer/configure", payload);
    put(statusEl, "Configuration active and saved.");
    statusEl.className = "status-msg success";
    toast("Peer configuration activated");

    await pollPeerStatus();
    view("connection");
  } catch (e) {
    put(statusEl, e.message);
    statusEl.className = "status-msg error";
  }
}

async function startPeerService() {
  const startBtn = $("btn-start-service");
  startBtn.disabled = true;
  try {
    const res = await api("/api/peer/start", {});
    toast(res.message || "Peer service started");
    await pollPeerStatus();
  } catch (e) {
    toast(`Failed to start: ${e.message}`);
  } finally {
    startBtn.disabled = false;
  }
}

async function stopPeerService() {
  const stopBtn = $("btn-stop-service");
  stopBtn.disabled = true;
  try {
    const res = await api("/api/peer/stop", {});
    toast(res.message || "Peer service stopped");
    await pollPeerStatus();
  } catch (e) {
    toast(`Failed to stop: ${e.message}`);
  } finally {
    stopBtn.disabled = false;
  }
}

/* ========================================================================= */
/* SYNCHRONIZATION CENTER & APPROVAL                                         */
/* ========================================================================= */

async function loadPeerPlan() {
  try {
    const data = await api("/api/peer/plan");
    state.peerPlan = data;
    renderPeerPlan();
    renderApprovalView();
  } catch (e) {
    state.peerPlan = null;
    renderPeerPlan();
    renderApprovalView();
  }
}

function renderPeerPlan() {
  const plan = state.peerPlan;
  const metricsBox = $("peer-plan-metrics");
  const conflictBanner = $("peer-conflict-banner");
  const countEl = $("peer-plan-count");
  const summaryEl = $("peer-plan-summary");
  const rowsEl = $("peer-plan-rows");
  const emptyEl = $("empty-peer-plan");

  if (!plan || !plan.entries) {
    conflictBanner?.classList.add("hidden");
    put(countEl, "(0)");
    put(summaryEl, "No active plan currently negotiated.");
    if (rowsEl) rowsEl.replaceChildren();
    emptyEl?.classList.remove("hidden");
    return;
  }

  const counts = plan.counts || {};
  put($("cnt-add-local"), counts.add_local || 0);
  put($("cnt-update-local"), counts.update_local || 0);
  put($("cnt-del-local"), counts.delete_local || 0);
  put($("cnt-add-remote"), counts.add_remote || 0);
  put($("cnt-update-remote"), counts.update_remote || 0);
  put($("cnt-conflicts"), counts.conflicts || 0);

  // Unresolved conflicts banner
  conflictBanner?.classList.toggle("hidden", !plan.has_unresolved_conflicts);

  const entries = filterPeerPlanEntries(plan.entries);
  put(countEl, `(${entries.length})`);
  put(summaryEl, `${entries.length} items shown · Plan Hash: ${plan.plan_hash ? plan.plan_hash.slice(0, 16) + '…' : 'None'}`);

  if (rowsEl) rowsEl.replaceChildren();
  if (entries.length === 0) {
    emptyEl?.classList.remove("hidden");
  } else {
    emptyEl?.classList.add("hidden");
    if (rowsEl) {
      entries.forEach(e => {
        const tr = document.createElement("tr");

      const tdPath = document.createElement("td");
      tdPath.textContent = e.path;

      const tdAction = document.createElement("td");
      const badge = document.createElement("span");
      badge.className = `op-badge ${getOpClass(e.action)}`;
      badge.textContent = e.action;
      tdAction.append(badge);

      const tdLocalSize = document.createElement("td");
      tdLocalSize.textContent = escBytes(e.local_size);

      const tdRemoteSize = document.createElement("td");
      tdRemoteSize.textContent = escBytes(e.remote_size);

      const tdConflict = document.createElement("td");
      if (e.is_conflict) {
        const cSpan = document.createElement("span");
        cSpan.className = "op-badge op-conflict";
        cSpan.textContent = "CONFLICT";
        tdConflict.append(cSpan);
      } else {
        tdConflict.textContent = "No";
      }

      const tdDigest = document.createElement("td");
      const digest = e.remote_digest || e.local_digest || "—";
      tdDigest.textContent = digest.length > 16 ? digest.slice(0, 16) + "…" : digest;

      tr.append(tdPath, tdAction, tdLocalSize, tdRemoteSize, tdConflict, tdDigest);
      rowsEl.append(tr);
    });
    }
  }
}

function getOpClass(action) {
  if (!action) return "";
  if (action.includes("Add")) return "op-add";
  if (action.includes("Update")) return "op-update";
  if (action.includes("Delete")) return "op-delete";
  if (action.includes("Conflict")) return "op-conflict";
  return "op-preserve";
}

function filterPeerPlanEntries(entries) {
  const q = $("search-peer-files")?.value.trim().toLowerCase() || "";
  const filter = $("filter-peer-op")?.value || "ALL";

  return entries.filter(e => {
    const matchesFilter = filter === "ALL" || e.action === filter;
    const matchesQuery = !q || e.path.toLowerCase().includes(q);
    return matchesFilter && matchesQuery;
  });
}

function renderApprovalView() {
  const plan = state.peerPlan;
  const sessionBadge = $("approval-session-badge");
  const delPrompt = $("peer-deletion-prompt");
  const commitBtn = $("btn-peer-commit");
  const declineBtn = $("btn-peer-decline");

  if (!plan) {
    put($("appr-session-id"), "No active session");
    put($("appr-plan-hash"), "—");
    put($("appr-remote-root"), "—");
    put($("appr-local-root"), "—");
    put(sessionBadge, "NO ACTIVE PLAN");
    if (sessionBadge) sessionBadge.className = "badge";
    delPrompt?.classList.add("hidden");
    if (commitBtn) commitBtn.disabled = true;
    if (declineBtn) declineBtn.disabled = true;
    return;
  }

  put($("appr-session-id"), plan.session_id || "—");
  put($("appr-plan-hash"), plan.plan_hash || "—");
  put($("appr-remote-root"), plan.remote_merkle_root || "—");
  put($("appr-local-root"), plan.local_merkle_root || "—");

  const deleteCount = (plan.counts?.delete_local || 0) + (plan.counts?.delete_remote || 0);
  if (delPrompt) {
    delPrompt.classList.toggle("hidden", deleteCount === 0);
    put($("del-count-display"), deleteCount);
  }

  const isConflictBlocked = Boolean(plan.has_unresolved_conflicts);
  const appFb = $("approval-feedback");
  if (isConflictBlocked) {
    put(sessionBadge, "CONFLICT BLOCKED");
    if (sessionBadge) sessionBadge.className = "badge danger";
    put(appFb, "Commit is blocked because the plan contains unresolved conflicts.");
    if (appFb) appFb.className = "status-msg error";
  } else {
    put(sessionBadge, "AWAITING APPROVAL");
    if (sessionBadge) sessionBadge.className = "badge warning";
    put(appFb, "");
  }

  if (declineBtn) declineBtn.disabled = false;
  validateApprovalForm();
}

function validateApprovalForm() {
  const plan = state.peerPlan;
  const commitBtn = $("btn-peer-commit");
  if (!commitBtn) return;

  if (!plan) {
    commitBtn.disabled = true;
    return;
  }

  if (plan.has_unresolved_conflicts) {
    commitBtn.disabled = true;
    return;
  }

  const approved = $("chk-peer-approve")?.checked;
  const deleteCount = (plan.counts?.delete_local || 0) + (plan.counts?.delete_remote || 0);
  const delConfirmed = deleteCount === 0 || $("chk-peer-confirm-del")?.checked;

  commitBtn.disabled = !(approved && delConfirmed);
}

async function submitPeerApproval(approve) {
  const commitBtn = $("btn-peer-commit");
  const declineBtn = $("btn-peer-decline");
  const feedback = $("approval-feedback");
  const resultPanel = $("peer-approval-result");

  if (commitBtn) commitBtn.disabled = true;
  if (declineBtn) declineBtn.disabled = true;
  put(feedback, approve ? "Submitting approval to peer session…" : "Declining plan and aborting session…");

  try {
    const payload = {
      approve: approve,
      confirm_deletions: $("chk-peer-confirm-del")?.checked || false
    };

    const res = await api("/api/peer/approve", payload);
    put(feedback, res.message || "Submitted");
    if (feedback) feedback.className = "status-msg success";

    if (resultPanel) {
      resultPanel.classList.remove("hidden");
      resultPanel.replaceChildren();
      const h = document.createElement("h3");
      h.textContent = approve ? "Plan Authorized" : "Plan Declined";
      const p = document.createElement("p");
      p.textContent = res.message;
      resultPanel.append(h, p);
    }

    toast(approve ? "Synchronization approved" : "Synchronization declined");

    if (approve) {
      view("progress");
    } else {
      state.peerPlan = null;
      renderPeerPlan();
      renderApprovalView();
    }
  } catch (e) {
    put(feedback, e.message);
    feedback.className = "status-msg error";
    commitBtn.disabled = false;
    declineBtn.disabled = false;
  }
}

/* ========================================================================= */
/* ACTIVITY & RECOVERY VIEW                                                  */
/* ========================================================================= */

async function loadPeerActivity() {
  try {
    const res = await api("/api/peer/activity");
    state.peerActivity = res.sessions || [];
    renderPeerActivity();
  } catch (e) {
    state.peerActivity = [];
    renderPeerActivity();
  }
}

function renderPeerActivity() {
  const rowsEl = $("peer-act-rows");
  const emptyEl = $("empty-peer-act");
  const q = $("search-peer-act")?.value.trim().toLowerCase() || "";

  let sessions = state.peerActivity;
  put($("stat-total-sessions"), sessions.length);
  put($("stat-committed-sessions"), sessions.filter(s => s.status === "COMPLETED").length);
  put($("stat-cancelled-sessions"), sessions.filter(s => s.status === "CANCELLED").length);
  put($("stat-failed-sessions"), sessions.filter(s => s.status === "FAILED" || s.status === "ERROR").length);

  if (q) {
    sessions = sessions.filter(s =>
      (s.session_id && s.session_id.toLowerCase().includes(q)) ||
      (s.peer_identity && s.peer_identity.toLowerCase().includes(q))
    );
  }

  if (rowsEl) rowsEl.replaceChildren();
  if (sessions.length === 0) {
    emptyEl?.classList.remove("hidden");
  } else {
    emptyEl?.classList.add("hidden");
    if (rowsEl) {
      sessions.forEach(s => {
        const tr = document.createElement("tr");

      const tdId = document.createElement("td");
      tdId.textContent = s.session_id ? s.session_id.slice(0, 12) + "…" : "—";

      const tdRole = document.createElement("td");
      tdRole.textContent = (s.role || "—").toUpperCase();

      const tdPeer = document.createElement("td");
      tdPeer.textContent = s.peer_identity || "—";

      const tdStart = document.createElement("td");
      tdStart.textContent = s.started_at ? new Date(s.started_at).toLocaleTimeString() : "—";

      const tdEnd = document.createElement("td");
      tdEnd.textContent = s.completed_at ? new Date(s.completed_at).toLocaleTimeString() : "In progress";

      const tdFiles = document.createElement("td");
      tdFiles.textContent = s.files_transferred || 0;

      const tdBytes = document.createElement("td");
      tdBytes.textContent = escBytes(s.bytes_transferred);

      const tdStatus = document.createElement("td");
      const badge = document.createElement("span");
      badge.className = `badge ${s.status === "COMPLETED" ? "active" : s.status === "FAILED" ? "danger" : ""}`;
      badge.textContent = s.status;
      tdStatus.append(badge);

      tr.append(tdId, tdRole, tdPeer, tdStart, tdEnd, tdFiles, tdBytes, tdStatus);
      rowsEl.append(tr);
    });
    }
  }
}

async function runDiagnostics() {
  const diagBadge = $("diag-state-badge");
  const countEl = $("diag-unfinished-count");
  const adviceEl = $("diag-advice");

  put(diagBadge, "Checking…");
  try {
    const res = await api("/api/peer/diagnostics");
    put(countEl, res.unfinished_sessions_count || 0);
    put(adviceEl, res.recovery_advice || "Ledger clean.");
    if (res.unfinished_sessions_count > 0) {
      put(diagBadge, "RECOVERY NEEDED");
      diagBadge.className = "badge warning";
    } else {
      put(diagBadge, "CLEAN");
      diagBadge.className = "badge active";
    }
  } catch (e) {
    put(diagBadge, "DIAG FAILED");
    diagBadge.className = "badge danger";
    put(adviceEl, e.message);
  }
}

/* ========================================================================= */
/* PRESERVED LOCAL ENGINE (BACKWARD COMPATIBILITY & CLI SMOKE)               */
/* ========================================================================= */

function summaryCounts(counts) {
  const host = $("overview-counts");
  if (!host) return;
  host.replaceChildren();
  if (!counts) {
    empty(host, "No comparison loaded.");
    return;
  }
  for (const [k, label] of [["add", "ADD"], ["modify", "MODIFY"], ["delete", "DELETE"], ["unchanged", "UNCHANGED"], ["preserve", "PRESERVE"]]) {
    const item = document.createElement("div");
    item.className = "compact-count";
    const n = document.createElement("b");
    n.textContent = counts[k] ?? 0;
    const l = document.createElement("small");
    l.textContent = label;
    item.append(n, l);
    host.append(item);
  }
}

function setApproval() {
  const counts = state.plan?.comparison?.counts;
  const hasMutations = Boolean(counts && (counts.add + counts.modify + counts.delete) > 0);
  const hasDeletes = Boolean(counts?.delete > 0);
  $("deletion-row")?.classList.toggle("hidden", !hasDeletes);
  if ($("sync-button")) {
    $("sync-button").disabled = !state.plan ||
      (hasMutations && !$("approve-changes").checked) ||
      (hasDeletes && !$("confirm-deletions").checked);
  }
}

function renderMetrics(counts) {
  const host = $("metrics");
  if (!host) return;
  host.replaceChildren();
  for (const [label, key] of [["ADD", "add"], ["MODIFY", "modify"], ["DELETE", "delete"], ["UNCHANGED", "unchanged"], ["PRESERVE", "preserve"]]) {
    const card = document.createElement("div");
    card.className = "metric";
    const small = document.createElement("small");
    small.textContent = label;
    const value = document.createElement("b");
    value.textContent = counts?.[key] ?? 0;
    card.append(small, value);
    host.append(card);
  }
}

function renderFiles() {
  const body = $("file-rows");
  if (!body) return;
  body.replaceChildren();
  const q = $("search-files")?.value.trim().toLowerCase() || "";
  const op = $("filter-operation")?.value || "ALL";

  const rows = state.files.filter(f =>
    (op === "ALL" || f.operation === op) && String(f.path).toLowerCase().includes(q)
  );

  for (const f of rows) {
    const tr = document.createElement("tr");
    tr.tabIndex = 0;
    tr.classList.toggle("selected", state.selected?.path === f.path);

    const path = document.createElement("td");
    path.textContent = f.path;

    const operation = document.createElement("td");
    const chip = document.createElement("span");
    chip.className = `op-badge ${getOpClass(f.operation)}`;
    chip.textContent = f.operation;
    operation.append(chip);

    const size = document.createElement("td");
    size.textContent = escBytes(f.size);

    const modified = document.createElement("td");
    const stamp = Number(f.source_modified_ms || f.destination_modified_ms);
    modified.textContent = stamp ? new Date(stamp).toLocaleTimeString() : "—";

    const status = document.createElement("td");
    status.textContent = f.error || f.state || "—";

    tr.append(path, operation, size, modified, status);
    tr.addEventListener("click", () => selectFile(f));
    body.append(tr);
  }
  $("empty-files")?.classList.toggle("hidden", rows.length > 0);
  put($("file-count"), `(${state.files.filter(f => !["UNCHANGED", "PRESERVE"].includes(f.operation)).length})`);
  put($("file-summary"), `${rows.length} shown · ${state.files.length} total`);
}

function selectFile(f) {
  state.selected = f;
  renderFiles();
  renderInspector();
}

function renderInspector() {
  const f = state.selected;
  if (!f) {
    put($("inspector-name"), "Select a file");
    put($("inspector-path"), "Choose a row to inspect metadata and hashes.");
    empty($("inspector-content"), "No file selected.");
    return;
  }
  put($("inspector-name"), f.path.split(/[\\/]/).pop());
  put($("inspector-path"), f.path);
  const box = $("inspector-content");
  if (state.inspectorTab === "hashes") {
    box.textContent = `Source SHA-256:\n${f.source_hash || "Not present"}\n\nDestination SHA-256:\n${f.destination_hash || "Not present"}`;
  } else if (state.inspectorTab === "transfer") {
    box.textContent = `Source Hash: ${f.source_hash || "—"}\nDestination Hash: ${f.destination_hash || "—"}`;
  } else {
    box.textContent = `Operation: ${f.operation}\nSize: ${escBytes(f.size)} (${f.size} bytes)\nRelative Path: ${f.path}\nState: ${f.state || "—"}`;
  }
}

/* ========================================================================= */
/* SELECTIVE SYNCHRONIZATION TREE LOGIC                                      */
/* ========================================================================= */

function buildDirectoryTree(files) {
  const root = { name: "", path: "", isDir: true, children: new Map(), files: [] };
  for (const f of files) {
    const parts = f.path.replace(/\\/g, "/").split("/");
    let curr = root;
    let accumulated = "";
    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      accumulated = accumulated ? `${accumulated}/${part}` : part;
      if (!curr.children.has(part)) {
        curr.children.set(part, {
          name: part,
          path: accumulated,
          isDir: true,
          children: new Map(),
          files: []
        });
      }
      curr = curr.children.get(part);
    }
    const fileName = parts[parts.length - 1];
    curr.files.push({
      name: fileName,
      path: f.path,
      isDir: false,
      size: f.size,
      sha256: f.sha256,
      modified_ms: f.modified_ms
    });
  }
  return root;
}

function updateScopeSummary() {
  const total = state.sourceFiles.length;
  const selected = state.selectedPaths.size;
  const badge = $("scope-summary-badge");
  const stats = $("scope-stats-text");

  if (state.scopeMode === "all") {
    if (badge) {
      badge.textContent = "Full sync";
      badge.className = "state-pill";
    }
    if (stats) stats.textContent = `Full sync active · all ${total} files selected`;
  } else {
    if (badge) {
      badge.textContent = `${selected} of ${total} selected`;
      badge.className = selected > 0 ? "state-pill active" : "state-pill danger";
    }
    if (stats) {
      stats.textContent = selected > 0
        ? `${selected} of ${total} files selected`
        : "No files selected — select at least one file or folder";
    }
  }
}

async function loadSourceTree(sourcePath) {
  if (!sourcePath) {
    state.sourceFiles = [];
    state.selectedPaths.clear();
    renderScopeTree();
    updateScopeSummary();
    return;
  }
  try {
    const data = await api("/api/list-files", { path: sourcePath });
    state.sourceFiles = data.files || [];
    // If selective mode was already active and no selections yet, select all by default
    if (state.selectedPaths.size === 0) {
      state.sourceFiles.forEach(f => state.selectedPaths.add(f.path));
    }
    renderScopeTree();
    updateScopeSummary();
  } catch (err) {
    console.warn("Could not list source files:", err.message);
    const container = $("scope-tree-container");
    if (container) {
      container.innerHTML = `<p class="muted" style="padding:0.5rem;color:var(--danger,#f87171);">Could not scan source folder: ${err.message}</p>`;
    }
  }
}

function renderScopeTree() {
  const container = $("scope-tree-container");
  if (!container) return;

  if (!state.sourceFiles || state.sourceFiles.length === 0) {
    container.innerHTML = '<p id="scope-tree-empty" class="muted" style="padding:0.5rem;">No files found in source folder.</p>';
    return;
  }

  const filterQuery = (state.treeSearch || "").toLowerCase().trim();
  const treeRoot = buildDirectoryTree(state.sourceFiles);

  container.innerHTML = "";
  const treeList = document.createElement("div");
  treeList.className = "tree-list";

  function renderDir(dirNode, depth = 0) {
    // If search active, check if any descendants match
    const sortedSubDirs = Array.from(dirNode.children.values()).sort((a, b) => a.name.localeCompare(b.name));
    const sortedFiles = dirNode.files.slice().sort((a, b) => a.name.localeCompare(b.name));

    for (const subDir of sortedSubDirs) {
      const dirElem = document.createElement("div");
      dirElem.className = "tree-dir-wrapper";

      // Collect all descendant files in subDir
      const descFiles = [];
      function collectDescFiles(node) {
        for (const f of node.files) descFiles.push(f.path);
        for (const child of node.children.values()) collectDescFiles(child);
      }
      collectDescFiles(subDir);

      const matchesSearch = !filterQuery || subDir.path.toLowerCase().includes(filterQuery) ||
        descFiles.some(p => p.toLowerCase().includes(filterQuery));
      if (!matchesSearch) continue;

      const row = document.createElement("div");
      row.className = "tree-node";
      row.style.paddingLeft = `${depth * 1.2 + 0.4}rem`;

      const isExpanded = filterQuery.length > 0 || state.treeExpanded.has(subDir.path);

      const toggle = document.createElement("span");
      toggle.className = "tree-toggle";
      toggle.textContent = isExpanded ? "▼" : "▶";
      toggle.addEventListener("click", (e) => {
        e.stopPropagation();
        if (state.treeExpanded.has(subDir.path)) {
          state.treeExpanded.delete(subDir.path);
        } else {
          state.treeExpanded.add(subDir.path);
        }
        renderScopeTree();
      });

      const chk = document.createElement("input");
      chk.type = "checkbox";
      chk.className = "tree-checkbox";

      const selectedDescCount = descFiles.filter(p => state.selectedPaths.has(p)).length;
      if (selectedDescCount === descFiles.length && descFiles.length > 0) {
        chk.checked = true;
        chk.indeterminate = false;
      } else if (selectedDescCount > 0) {
        chk.checked = false;
        chk.indeterminate = true;
      } else {
        chk.checked = false;
        chk.indeterminate = false;
      }

      chk.addEventListener("change", () => {
        if (chk.checked) {
          descFiles.forEach(p => state.selectedPaths.add(p));
        } else {
          descFiles.forEach(p => state.selectedPaths.delete(p));
        }
        // Invalidate current plan
        state.plan = null;
        setApproval();
        renderScopeTree();
        updateScopeSummary();
      });

      const icon = document.createElement("span");
      icon.className = "tree-icon";
      icon.textContent = isExpanded ? "📂" : "📁";

      const label = document.createElement("span");
      label.className = "tree-label";
      label.textContent = subDir.name;
      label.addEventListener("click", () => {
        toggle.click();
      });

      const sizeSpan = document.createElement("span");
      sizeSpan.className = "tree-size";
      sizeSpan.textContent = `(${descFiles.length} files)`;

      row.append(toggle, chk, icon, label, sizeSpan);
      dirElem.append(row);

      if (isExpanded) {
        const childContainer = document.createElement("div");
        childContainer.className = "tree-dir-children";
        renderDir(subDir, depth + 1);
        dirElem.append(childContainer);
      }

      treeList.append(dirElem);
    }

    for (const f of sortedFiles) {
      if (filterQuery && !f.path.toLowerCase().includes(filterQuery)) continue;

      const row = document.createElement("div");
      row.className = "tree-node file-node";
      row.style.paddingLeft = `${depth * 1.2 + 1.6}rem`;

      const chk = document.createElement("input");
      chk.type = "checkbox";
      chk.className = "tree-checkbox";
      chk.checked = state.selectedPaths.has(f.path);

      chk.addEventListener("change", () => {
        if (chk.checked) {
          state.selectedPaths.add(f.path);
        } else {
          state.selectedPaths.delete(f.path);
        }
        // Invalidate current plan
        state.plan = null;
        setApproval();
        renderScopeTree();
        updateScopeSummary();
      });

      const icon = document.createElement("span");
      icon.className = "tree-icon";
      icon.textContent = "📄";

      const label = document.createElement("span");
      label.className = "tree-label";
      label.textContent = f.name;
      label.title = f.path;

      const sizeSpan = document.createElement("span");
      sizeSpan.className = "tree-size";
      sizeSpan.textContent = escBytes(f.size);

      row.append(chk, icon, label, sizeSpan);
      treeList.append(row);
    }
  }

  renderDir(treeRoot, 0);
  container.append(treeList);
}

/* ========================================================================= */
/* ALGORITHM EXPLORER RENDERERS                                              */
/* ========================================================================= */


/* ========================================================================= */
/* LOCAL WORKSPACE OVERVIEW RENDERER                                         */
/* ========================================================================= */

function renderLocalOverview() {
  const tableBody = $("recent-sync-rows");
  const emptyMsg = $("recent-sync-empty");
  if (!tableBody) return;

  // Use real synchronization records if any completed in this session or stored
  if (state.lastSyncResult && state.lastSyncResult.jobs && state.lastSyncResult.jobs.length > 0) {
    if (emptyMsg) emptyMsg.classList.add("hidden");
    tableBody.replaceChildren();

    const tr = document.createElement("tr");

    const tdTime = document.createElement("td");
    tdTime.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    const tdSrc = document.createElement("td");
    const srcPath = $("folder-a")?.value.trim() || "Source Folder";
    tdSrc.innerHTML = `<code style="font-size:0.82rem;">${srcPath}</code>`;

    const tdDst = document.createElement("td");
    const dstPath = $("folder-b")?.value.trim() || "Destination Folder";
    tdDst.innerHTML = `<code style="font-size:0.82rem;">${dstPath}</code>`;

    const tdStatus = document.createElement("td");
    const isSuccess = state.lastSyncResult.success !== false;
    tdStatus.innerHTML = `<span class="state-pill ${isSuccess ? 'active' : 'danger'}">${isSuccess ? 'Completed' : 'Failed'}</span>`;

    const tdChanges = document.createElement("td");
    tdChanges.textContent = `${state.lastSyncResult.jobs.length} files`;

    tr.append(tdTime, tdSrc, tdDst, tdStatus, tdChanges);
    tableBody.append(tr);
  } else {
    if (emptyMsg) emptyMsg.classList.remove("hidden");
    tableBody.replaceChildren();
  }
}

function renderMerkle() {
  const rootA = $("explorer-root-a");
  const rootB = $("explorer-root-b");
  const tableBody = $("merkle-rows");
  const emptyMsg = $("merkle-empty");
  const heading = $("merkle-status-heading");
  const desc = $("merkle-status-desc");
  const badge = $("merkle-match-badge");
  const levelsBox = $("merkle-levels-container");

  const comparison = state.lastComparison;
  if (!comparison) {
    if (rootA) rootA.textContent = "—";
    if (rootB) rootB.textContent = "—";
    if (emptyMsg) emptyMsg.classList.remove("hidden");
    if (heading) heading.textContent = "Awaiting comparison";
    if (desc) desc.textContent = "Run a folder comparison in Synchronize to inspect Merkle tree structures, roots, and leaf digests.";
    if (badge) {
      badge.textContent = "—";
      badge.className = "state-pill";
    }
    if (levelsBox) levelsBox.classList.add("hidden");
    if (tableBody) tableBody.replaceChildren();
    return;
  }

  if (rootA) rootA.textContent = comparison.source_merkle_root || "—";
  if (rootB) rootB.textContent = comparison.destination_merkle_root || "—";

  const me = comparison.merkle_explorer;
  if (me) {
    if (heading) heading.textContent = me.roots_match ? "Merkle Roots Match" : "Merkle Roots Differ";
    if (desc) desc.textContent = me.differ_reason;
    if (badge) {
      badge.textContent = me.roots_match ? "Roots Identical" : `${me.differ_count} Differing Leaves`;
      badge.className = `state-pill ${me.roots_match ? "active" : "warning"}`;
    }
    if (levelsBox) levelsBox.classList.remove("hidden");
    put($("merkle-source-depth"), `${me.source_tree?.depth ?? "—"} levels (${me.source_tree?.file_count ?? 0} files)`);
    put($("merkle-dest-depth"), `${me.destination_tree?.depth ?? "—"} levels (${me.destination_tree?.file_count ?? 0} files)`);
    put($("merkle-diff-count"), `${me.differ_count} leaves differ`);

    if (tableBody) {
      tableBody.replaceChildren();
      const filter = ($("merkle-search")?.value || "").toLowerCase().trim();
      const leaves = (me.leaves || []).filter(l =>
        !filter || l.path.toLowerCase().includes(filter) ||
        (l.source_sha256 && l.source_sha256.toLowerCase().includes(filter)) ||
        (l.destination_sha256 && l.destination_sha256.toLowerCase().includes(filter))
      );

      if (leaves.length === 0) {
        if (emptyMsg) {
          emptyMsg.textContent = "No leaves match the search filter.";
          emptyMsg.classList.remove("hidden");
        }
      } else {
        if (emptyMsg) emptyMsg.classList.add("hidden");
        for (const l of leaves) {
          const tr = document.createElement("tr");

          const tdPath = document.createElement("td");
          tdPath.innerHTML = `<code style="font-size:0.82rem;">${l.path}</code>`;

          const tdOp = document.createElement("td");
          const opBadge = document.createElement("span");
          opBadge.className = `op-badge ${getOpClass(l.operation)}`;
          opBadge.textContent = l.operation;
          tdOp.append(opBadge);

          const tdSourceHash = document.createElement("td");
          tdSourceHash.innerHTML = l.source_sha256
            ? `<code class="muted" style="font-size:0.75rem;" title="${l.source_sha256}">${l.source_sha256.slice(0, 12)}…${l.source_sha256.slice(-8)}</code>`
            : '<span class="muted">—</span>';

          const tdDestHash = document.createElement("td");
          tdDestHash.innerHTML = l.destination_sha256
            ? `<code class="muted" style="font-size:0.75rem;" title="${l.destination_sha256}">${l.destination_sha256.slice(0, 12)}…${l.destination_sha256.slice(-8)}</code>`
            : '<span class="muted">—</span>';

          const tdSourceLeaf = document.createElement("td");
          tdSourceLeaf.innerHTML = l.source_leaf_hash
            ? `<code class="muted" style="font-size:0.75rem;" title="${l.source_leaf_hash}">${l.source_leaf_hash.slice(0, 12)}…${l.source_leaf_hash.slice(-8)}</code>`
            : '<span class="muted">—</span>';

          const tdDestLeaf = document.createElement("td");
          tdDestLeaf.innerHTML = l.destination_leaf_hash
            ? `<code class="muted" style="font-size:0.75rem;" title="${l.destination_leaf_hash}">${l.destination_leaf_hash.slice(0, 12)}…${l.destination_leaf_hash.slice(-8)}</code>`
            : '<span class="muted">—</span>';

          const tdReason = document.createElement("td");
          tdReason.className = "muted";
          tdReason.style.fontSize = "0.8rem";
          tdReason.textContent = l.reason || "—";

          tr.append(tdPath, tdOp, tdSourceHash, tdDestHash, tdSourceLeaf, tdDestLeaf, tdReason);
          tableBody.append(tr);
        }
      }
    }
  }
}

function renderScheduler() {
  const tableBody = $("scheduler-rows");
  const emptyMsg = $("scheduler-empty");
  const countBadge = $("scheduler-count");

  // If a sync was executed, display the completed operations
  if (state.lastSyncResult && state.lastSyncResult.jobs && state.lastSyncResult.jobs.length > 0) {
    if (emptyMsg) emptyMsg.classList.add("hidden");
    if (countBadge) {
      countBadge.textContent = `${state.lastSyncResult.jobs.length} completed operations`;
      countBadge.className = "state-pill active";
    }
    if (tableBody) {
      tableBody.replaceChildren();
      state.lastSyncResult.jobs.forEach((j, idx) => {
        const tr = document.createElement("tr");

        const tdOrder = document.createElement("td");
        tdOrder.textContent = String(idx + 1);

        const tdPath = document.createElement("td");
        tdPath.innerHTML = `<code style="font-size:0.82rem;">${j.relative_path}</code>`;

        const tdOp = document.createElement("td");
        const opBadge = document.createElement("span");
        opBadge.className = `op-badge ${getOpClass(j.operation)}`;
        opBadge.textContent = j.operation;
        tdOp.append(opBadge);

        const tdPriority = document.createElement("td");
        tdPriority.textContent = j.priority !== undefined ? String(j.priority) : "Executed";

        const tdSize = document.createElement("td");
        tdSize.textContent = escBytes(j.size);

        const tdTicks = document.createElement("td");
        tdTicks.className = "muted";
        tdTicks.textContent = j.modified_ticks || "—";

        const tdState = document.createElement("td");
        tdState.innerHTML = '<span class="state-pill active" style="font-size:0.75rem;">COMPLETED</span>';

        tr.append(tdOrder, tdPath, tdOp, tdPriority, tdSize, tdTicks, tdState);
        tableBody.append(tr);
      });
    }
    return;
  }

  // Otherwise, display the scheduler preview from the latest comparison
  const rawSched = state.lastComparison?.scheduler;
  const preview = Array.isArray(rawSched) ? rawSched : (rawSched?.preview || []);
  if (preview.length === 0) {
    if (emptyMsg) {
      emptyMsg.textContent = "Scan a folder pair to preview scheduler queue order.";
      emptyMsg.classList.remove("hidden");
    }
    if (countBadge) {
      countBadge.textContent = "No queued jobs";
      countBadge.className = "state-pill";
    }
    if (tableBody) tableBody.replaceChildren();
    return;
  }

  if (emptyMsg) emptyMsg.classList.add("hidden");
  if (countBadge) {
    countBadge.textContent = `${preview.length} operations queued`;
    countBadge.className = "state-pill";
  }

  if (tableBody) {
    tableBody.replaceChildren();
    preview.forEach((item, idx) => {
      const tr = document.createElement("tr");

      const tdOrder = document.createElement("td");
      tdOrder.textContent = String(idx + 1);

      const tdPath = document.createElement("td");
      tdPath.innerHTML = `<code style="font-size:0.82rem;">${item.path}</code>`;

      const tdOp = document.createElement("td");
      const opBadge = document.createElement("span");
      opBadge.className = `op-badge ${getOpClass(item.operation)}`;
      opBadge.textContent = item.operation;
      tdOp.append(opBadge);

      const tdPriority = document.createElement("td");
      tdPriority.innerHTML = `<b>${item.priority ?? 0}</b> <small class="muted">(${item.reason || "base"})</small>`;

      const tdSize = document.createElement("td");
      tdSize.textContent = escBytes(item.size);

      const tdTicks = document.createElement("td");
      tdTicks.className = "muted";
      tdTicks.textContent = item.modified_ticks || "—";

      const tdState = document.createElement("td");
      tdState.innerHTML = '<span class="state-pill" style="font-size:0.75rem;">QUEUED</span>';

      tr.append(tdOrder, tdPath, tdOp, tdPriority, tdSize, tdTicks, tdState);
      tableBody.append(tr);
    });
  }
}

function renderChunks() {
  const cm = state.lastSyncResult?.chunk_metrics;
  const chunkRows = $("chunk-rows");

  if (!cm) {
    put($("chunk-payload"), "—");
    put($("chunk-processed"), "—");
    put($("chunk-reused"), "—");
    put($("chunk-written"), "—");
    put($("chunk-count"), "—");
    put($("chunk-integrity"), "Awaiting synchronization");
    if (chunkRows) {
      chunkRows.innerHTML = '<p class="empty">No completed synchronization metrics recorded. Run an approved synchronization to inspect real chunk reuse measurements.</p>';
    }
    return;
  }

  put($("chunk-payload"), escBytes(cm.payload_bytes));
  put($("chunk-processed"), escBytes(cm.source_bytes_processed));
  put($("chunk-reused"), escBytes(cm.bytes_reused));
  put($("chunk-written"), escBytes(cm.bytes_written));

  const totalChunks = cm.chunks_total || 0;
  const reusedChunks = cm.chunks_reused || 0;
  const reusePct = totalChunks > 0 ? Math.round((reusedChunks / totalChunks) * 100) : 0;
  put($("chunk-count"), `${reusedChunks} / ${totalChunks} (${reusePct}%)`);

  const integ = $("chunk-integrity");
  if (integ) {
    integ.textContent = cm.verified ? "Root Verified" : "Verification Mismatch";
    integ.style.color = cm.verified ? "var(--active, #10b981)" : "var(--danger, #f87171)";
  }

  if (chunkRows) {
    const jobs = state.lastSyncResult?.jobs || [];
    const mutatingJobs = jobs.filter(j => j.operation === "ADD" || j.operation === "MODIFY");

    if (mutatingJobs.length === 0) {
      chunkRows.innerHTML = '<p class="empty">Plan completed with no content transfers requiring chunk processing.</p>';
      return;
    }

    chunkRows.replaceChildren();
    for (const j of mutatingJobs) {
      const card = document.createElement("div");
      card.className = "record-item";
      card.style.padding = "0.75rem";
      card.style.marginBottom = "0.5rem";
      card.style.background = "var(--bg-surface, #1e1e24)";
      card.style.border = "1px solid var(--border)";
      card.style.borderRadius = "6px";

      const header = document.createElement("div");
      header.style.display = "flex";
      header.style.justifyContent = "space-between";
      header.style.alignItems = "center";
      header.style.marginBottom = "0.4rem";

      header.innerHTML = `<span style="font-weight:600; font-family:var(--font-mono, monospace); font-size:0.85rem;">${j.relative_path}</span>
        <span class="op-badge ${getOpClass(j.operation)}">${j.operation}</span>`;

      const stats = document.createElement("div");
      stats.style.display = "grid";
      stats.style.gridTemplateColumns = "repeat(auto-fit, minmax(130px, 1fr))";
      stats.style.gap = "0.5rem";
      stats.style.fontSize = "0.8rem";

      stats.innerHTML = `<div><small class="muted">Processed:</small> <b>${escBytes(j.source_bytes_processed)}</b></div>
        <div><small class="muted">Reused:</small> <b>${escBytes(j.bytes_reused)}</b></div>
        <div><small class="muted">Written:</small> <b>${escBytes(j.bytes_written)}</b></div>
        <div><small class="muted">Chunks Reused:</small> <b>${j.chunks_reused} / ${j.chunks_total}</b></div>`;

      card.append(header, stats);
      chunkRows.append(card);
    }
  }
}

async function compare() {
  put($("folder-error"), "");
  const source = $("folder-a").value.trim();
  const destination = $("folder-b").value.trim();
  if (!source || !destination) {
    put($("folder-error"), "Choose both folders before comparing.");
    return;
  }
  const button = $("scan-button");
  button.disabled = true;
  button.textContent = "Scanning folders…";
  state.plan = null;
  setApproval();

  try {
    if (state.scopeMode === "selective" && state.selectedPaths.size === 0) {
      put($("folder-error"), "Please select at least one file or folder in the tree before comparing.");
      return;
    }

    const payload = {
      source,
      destination,
      scope_mode: state.scopeMode,
      scope_paths: state.scopeMode === "selective" ? Array.from(state.selectedPaths) : [],
      scope: {
        mode: state.scopeMode,
        paths: state.scopeMode === "selective" ? Array.from(state.selectedPaths) : []
      }
    };

    const data = await api("/api/scan", payload);
    state.plan = data;
    state.lastComparison = data;
    state.files = data.comparison?.files || [];
    state.selected = null;

    if (data.source_files && data.source_files.length > 0) {
      state.sourceFiles = data.source_files;
      renderScopeTree();
      updateScopeSummary();
    }

    // Populate root display panels
    put($("root-a"), data.source || source);
    put($("root-b"), data.destination || destination);
    $("comparison-section").classList.remove("hidden");
    $("sync-result").classList.add("hidden");
    $("approve-changes").checked = false;
    $("confirm-deletions").checked = false;
    renderMetrics(data.comparison?.counts);
    renderFiles();
    renderInspector();
    setApproval();

    // Render Merkle explorer & Scheduler preview immediately
    renderMerkle();
    renderScheduler();

    // Advance step indicators
    ["step-config", "step-compare", "step-review"].forEach(id => $(id)?.classList.add("complete"));
    $("step-apply")?.classList.remove("complete");
    $("step-verify")?.classList.remove("complete");
    toast("Comparison complete · review the exact plan");
  } catch (e) {
    put($("folder-error"), e.message);
    $("comparison-section").classList.add("hidden");
    ["step-compare", "step-review", "step-apply", "step-verify"].forEach(id => $(id)?.classList.remove("complete"));
  } finally {
    button.disabled = false;
    button.innerHTML = "Compare folders <span>→</span>";
  }
}

async function applyLocal() {
  if (!state.plan) return;
  setApproval();
  if ($("sync-button").disabled) return;
  const button = $("sync-button");
  button.disabled = true;
  put($("sync-status"), "Executing approved plan and verifying destination…");

  try {
    const data = await api("/api/sync", {
      plan_id: state.plan.plan_id,
      source: $("folder-a").value.trim(),
      destination: $("folder-b").value.trim(),
      scope_mode: state.scopeMode,
      scope_paths: state.scopeMode === "selective" ? Array.from(state.selectedPaths) : [],
      scope: {
        mode: state.scopeMode,
        paths: state.scopeMode === "selective" ? Array.from(state.selectedPaths) : []
      },
      approve: $("approve-changes").checked,
      confirm_deletions: $("confirm-deletions").checked
    });
    state.lastSyncResult = data;
    renderScheduler();
    renderChunks();

    const panel = $("sync-result");
    panel.classList.remove("hidden", "failure");
    panel.replaceChildren();
    const h = document.createElement("h3");
    h.textContent = data.message || "Synchronization complete";
    const details = document.createElement("p");
    details.className = "muted";
    const counts = state.plan?.comparison?.counts;
    if (counts) {
      details.textContent = `Applied: ${counts.add ?? 0} added · ${counts.modify ?? 0} modified · ${counts.delete ?? 0} deleted`;
    }
    panel.append(h);
    if (counts) panel.append(details);

    state.plan = null;
    setApproval();
    // Mark all steps complete
    ["step-config", "step-compare", "step-review", "step-apply", "step-verify"].forEach(id => $(id)?.classList.add("complete"));
    toast("Local synchronization completed");
  } catch (e) {
    put($("sync-status"), e.message);
  } finally {
    setApproval();
  }
}

async function pickFolder(slot) {
  try {
    const data = await api("/api/pick-folder", { slot });
    if (!data.cancelled) {
      if (slot === "a") $("folder-a").value = data.path;
      else if (slot === "b") $("folder-b").value = data.path;
      else if (slot === "peer-root") $("cfg-sync-root").value = data.path;
      toast("Folder selected");
    }
  } catch (e) {
    toast(`Browse error: ${e.message}`);
  }
}

async function loadVersions() {
  const dest = $("folder-b")?.value.trim();
  if (!dest) return;
  const host = $("versions-list");
  empty(host, "Loading saved versions…");
  try {
    const data = await api("/api/versions", { destination: dest });
    host.replaceChildren();
    if (!data.versions?.length) {
      empty(host, "No version snapshots found.");
      return;
    }
    data.versions.forEach(v => {
      const row = document.createElement("div");
      row.className = "list-row";
      const main = document.createElement("div");
      main.className = "list-main";
      const title = document.createElement("b");
      title.textContent = v.label || v.id;
      const detail = document.createElement("small");
      detail.textContent = `${new Date(Number(v.timestamp_ms)).toLocaleString()} · ${v.file_count} files · root ${v.integrity_hash}`;
      main.append(title, detail);
      row.append(main);
      host.append(row);
    });
  } catch (e) {
    empty(host, e.message);
  }
}

async function loadActivity() {
  const dest = $("folder-b")?.value.trim();
  if (!dest) return;
  try {
    const data = await api("/api/activity", { destination: dest });
    state.activity = data.activity || [];
    renderLocalActivity();
  } catch (e) {
    state.activity = [];
    renderLocalActivity();
  }
}

function renderLocalActivity() {
  const host = $("activity-list");
  if (!host) return;
  host.replaceChildren();
  if (!state.activity.length) {
    empty(host, "No activity recorded for Folder B.");
    return;
  }
  state.activity.forEach(e => {
    const row = document.createElement("div");
    row.className = "list-row";
    const main = document.createElement("div");
    main.className = "list-main";
    const title = document.createElement("b");
    title.textContent = `${e.operation} · ${e.path}`;
    const detail = document.createElement("small");
    detail.textContent = `${e.state} · payload ${escBytes(e.bytes_transferred)} · ${e.verified ? "verified" : "unverified"}`;
    main.append(title, detail);
    row.append(main);
    host.append(row);
  });
}

/* ========================================================================= */
/* EVENT LISTENERS & INITIALIZATION                                          */
/* ========================================================================= */

function attachListeners() {
  // Navigation - Sidebar Links
  document.querySelectorAll("[data-view]").forEach(a => {
    a.addEventListener("click", e => {
      if (e.ctrlKey || e.metaKey || e.button !== 0) return;
      e.preventDefault();
      const target = a.dataset.view;
      if (location.hash !== `#${target}`) {
        location.hash = `#${target}`;
      } else {
        view(target, false);
      }
    });
  });

  // Navigation - Action Buttons with data-go
  document.querySelectorAll("[data-go]").forEach(b => {
    b.addEventListener("click", e => {
      e.preventDefault();
      const target = b.dataset.go;
      if (location.hash !== `#${target}`) {
        location.hash = `#${target}`;
      } else {
        view(target, false);
      }
    });
  });

  // Device Pairing
  $("btn-validate-config")?.addEventListener("click", validatePairingConfig);
  $("pairing-form")?.addEventListener("submit", savePairingConfig);
  document.querySelector(".browse-peer-root")?.addEventListener("click", () => pickFolder("peer-root"));
  $("btn-copy-pin")?.addEventListener("click", () => {
    const pin = $("val-local-pin")?.textContent;
    if (pin && pin !== "—") {
      navigator.clipboard?.writeText(pin);
      toast("Pin copied to clipboard");
    }
  });

  // Peer Connection Controls
  $("btn-start-service")?.addEventListener("click", startPeerService);
  $("btn-stop-service")?.addEventListener("click", stopPeerService);

  // Sync Center & Approval Controls
  $("btn-refresh-plan")?.addEventListener("click", loadPeerPlan);
  $("search-peer-files")?.addEventListener("input", renderPeerPlan);
  $("filter-peer-op")?.addEventListener("change", renderPeerPlan);
  $("chk-peer-approve")?.addEventListener("change", validateApprovalForm);
  $("chk-peer-confirm-del")?.addEventListener("change", validateApprovalForm);
  $("btn-peer-commit")?.addEventListener("click", () => submitPeerApproval(true));
  $("btn-peer-decline")?.addEventListener("click", () => submitPeerApproval(false));

  // Activity & Recovery
  $("btn-refresh-peer-act")?.addEventListener("click", loadPeerActivity);
  $("btn-run-diag")?.addEventListener("click", runDiagnostics);
  $("search-peer-act")?.addEventListener("input", renderPeerActivity);

  // Preserved Local Mode Controls
  $("scan-button")?.addEventListener("click", compare);
  $("sync-button")?.addEventListener("click", applyLocal);
  $("approve-changes")?.addEventListener("change", setApproval);
  $("confirm-deletions")?.addEventListener("change", setApproval);
  document.querySelectorAll(".browse").forEach(b => {
    b.addEventListener("click", () => pickFolder(b.dataset.slot));
  });
  $("refresh-versions")?.addEventListener("click", loadVersions);
  $("refresh-activity")?.addEventListener("click", loadActivity);

  // Local Workspace — Search & Filter (live re-render)
  $("search-files")?.addEventListener("input", renderFiles);
  $("filter-operation")?.addEventListener("change", renderFiles);

  // Local Workspace — Swap source/destination folders
  $("swap-folders")?.addEventListener("click", () => {
    const a = $("folder-a"), b = $("folder-b");
    if (!a || !b) return;
    [a.value, b.value] = [b.value, a.value];
    // Reset plan when folders change
    state.plan = null;
    state.files = [];
    state.selected = null;
    $("comparison-section")?.classList.add("hidden");
    $("sync-result")?.classList.add("hidden");
    ["step-compare", "step-review", "step-apply", "step-verify"].forEach(id => $(id)?.classList.remove("complete"));
    setApproval();
  });

  // Local Workspace — Invalidate plan when folder inputs change manually
  ["folder-a", "folder-b"].forEach(id => {
    $(id)?.addEventListener("change", () => {
      state.plan = null;
      state.lastComparison = null;
      state.files = [];
      state.selected = null;
      $("comparison-section")?.classList.add("hidden");
      $("sync-result")?.classList.add("hidden");
      ["step-compare", "step-review", "step-apply", "step-verify"].forEach(sid => $(sid)?.classList.remove("complete"));
      setApproval();
      if (id === "folder-a") {
        loadSourceTree($(id).value.trim());
      }
    });
  });

  // Scope mode selection
  $("scope-mode-all")?.addEventListener("change", () => {
    state.scopeMode = "all";
    $("scope-tree-panel")?.classList.add("hidden");
    state.plan = null;
    setApproval();
    updateScopeSummary();
  });

  $("scope-mode-selective")?.addEventListener("change", () => {
    state.scopeMode = "selective";
    $("scope-tree-panel")?.classList.remove("hidden");
    state.plan = null;
    setApproval();
    if (state.sourceFiles.length === 0) {
      loadSourceTree($("folder-a")?.value.trim());
    } else {
      renderScopeTree();
      updateScopeSummary();
    }
  });

  $("scope-tree-search")?.addEventListener("input", (e) => {
    state.treeSearch = e.target.value;
    renderScopeTree();
  });

  $("tree-select-all")?.addEventListener("click", () => {
    state.sourceFiles.forEach(f => state.selectedPaths.add(f.path));
    state.plan = null;
    setApproval();
    renderScopeTree();
    updateScopeSummary();
  });

  $("tree-deselect-all")?.addEventListener("click", () => {
    state.selectedPaths.clear();
    state.plan = null;
    setApproval();
    renderScopeTree();
    updateScopeSummary();
  });

  $("tree-expand-all")?.addEventListener("click", () => {
    function expandAll(files) {
      for (const f of files) {
        const parts = f.path.replace(/\\/g, "/").split("/");
        let acc = "";
        for (let i = 0; i < parts.length - 1; i++) {
          acc = acc ? `${acc}/${parts[i]}` : parts[i];
          state.treeExpanded.add(acc);
        }
      }
    }
    expandAll(state.sourceFiles);
    renderScopeTree();
  });

  $("tree-collapse-all")?.addEventListener("click", () => {
    state.treeExpanded.clear();
    renderScopeTree();
  });

  $("merkle-search")?.addEventListener("input", renderMerkle);

  // Local Workspace — Inspector tab switching
  document.querySelectorAll("[data-inspector-tab]").forEach(btn => {
    btn.addEventListener("click", () => {
      state.inspectorTab = btn.dataset.inspectorTab;
      document.querySelectorAll("[data-inspector-tab]").forEach(b => {
        b.classList.toggle("selected", b === btn);
      });
      renderInspector();
    });
  });

  // Browser Back / Forward and URL Hash changes
  window.addEventListener("hashchange", () => {
    const rawHash = location.hash.replace(/^#/, "");
    view(rawHash, false);
  });
}

async function init() {
  attachListeners();
  put($("server-port"), location.port || "47831");
  put($("clock"), new Date().toLocaleTimeString());
  setInterval(() => put($("clock"), new Date().toLocaleTimeString()), 1000);

  const initialView = location.hash.replace(/^#/, "");
  view(initialView || "home", false);

  try {
    const status = await api("/api/status");
    state.csrf = status.csrf;
    if (status.peer) {
      updatePeerUI(status.peer);
    }
    put($("connection-status"), "Connected · 127.0.0.1");
    $("connection-dot")?.classList.add("online");
  } catch (e) {
    put($("connection-status"), "Backend unavailable");
    $("connection-dot")?.classList.remove("online");
  }

  // Poll peer status periodically
  await pollPeerStatus();
  setInterval(pollPeerStatus, 2000);
}

init();


/* ==========================================================================
   COLLABORATION PLATFORM CONTROLLER IMPLEMENTATION
   ========================================================================== */

let hostSelectedFile = null;
let hostWorkspaceFilesCache = [];
let clientUpdatesCache = [];

async function collabFetch(path, method = "GET", body = null) {
  const token = localStorage.getItem("mc_session_token");
  const headers = {};
  if (token) headers["X-Session-Token"] = token;
  const opts = { method, credentials: "same-origin", headers };
  if (body) {
    headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify({ csrf: state.csrf, ...body });
  }
  const res = await fetch(path, opts);
  let data;
  try {
    data = await res.json();
  } catch {
    throw new Error(`HTTP ${res.status}: Invalid server JSON response`);
  }
  if (!res.ok || data.error) {
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return data;
}

// ----------------- HOST OVERVIEW -----------------
async function loadHostOverview() {
  try {
    // 1. Fetch clients count
    const cData = await collabFetch("/api/host/clients");
    put($("host-stat-clients"), cData.clients?.length ?? 0);

    // 2. Fetch submissions
    const sData = await collabFetch("/api/host/submissions");
    const pendingSubs = (sData.submissions || []).filter(s => s.status === "pending").length;
    put($("host-stat-pending-subs"), pendingSubs);

    // 3. Fetch published versions
    const vData = await collabFetch("/api/host/workspaces/versions");
    put($("host-stat-published-versions"), vData.versions?.length ?? 0);

    // 4. Fetch working copy files
    const fData = await collabFetch("/api/host/workspaces/files");
    const fileCount = fData.files?.length ?? 0;
    put($("host-stat-working-files"), `${fileCount} file${fileCount === 1 ? '' : 's'}`);

    // 5. Fetch diff to get pending updates count and current root
    const dData = await collabFetch("/api/host/workspaces/changes");
    put($("host-stat-pending-updates"), (dData.counts?.added ?? 0) + (dData.counts?.modified ?? 0) + (dData.counts?.deleted ?? 0));

    // 6. Fetch recent events
    const eData = await collabFetch("/api/host/activity");
    const evRows = $("host-overview-activity-rows");
    if (evRows) {
      const recent = (eData.events || []).slice(0, 5);
      if (recent.length === 0) {
        evRows.innerHTML = '<tr><td colspan="5" class="empty">No security events recorded.</td></tr>';
      } else {
        evRows.innerHTML = recent.map(e => `
          <tr>
            <td><small>${new Date(e.timestamp_ms).toLocaleTimeString()}</small></td>
            <td><b>${e.actor_username || 'system'}</b></td>
            <td><code>${e.action}</code></td>
            <td>${e.resource || '&mdash;'}</td>
            <td><span class="badge ${e.outcome === 'success' ? 'badge-active' : 'badge-inactive'}">${e.outcome}</span></td>
          </tr>
        `).join('');
      }
    }
  } catch (err) {
    console.error("Error loading host overview:", err);
  }
}

// ----------------- CLIENT MANAGEMENT -----------------
async function loadHostClients() {
  const tbody = $("host-clients-table-rows");
  if (!tbody) return;
  try {
    const data = await collabFetch("/api/host/clients");
    const clients = data.clients || [];
    if (clients.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty">No client accounts found. Click "+ Create New Client" above.</td></tr>';
      return;
    }
    tbody.innerHTML = clients.map(c => `
      <tr>
        <td><b>${c.username}</b><br><small class="muted">${c.id}</small></td>
        <td><code>${c.role}</code></td>
        <td><span class="state-pill ${c.status === 'active' ? 'active' : ''}">${c.status}</span></td>
        <td><small>${new Date(c.created_at_ms).toLocaleDateString()}</small></td>
        <td><small>${c.last_login_ms ? new Date(c.last_login_ms).toLocaleString() : 'Never'}</small></td>
        <td>
          <button class="btn neutral btn-xs btn-client-toggle-status" data-id="${c.id}" data-status="${c.status}">
            ${c.status === 'active' ? 'Suspend' : 'Activate'}
          </button>
          <button class="btn neutral btn-xs btn-client-reset-pwd" data-id="${c.id}" data-user="${c.username}">
            Reset Pwd
          </button>
        </td>
      </tr>
    `).join('');

    // Attach actions
    tbody.querySelectorAll(".btn-client-toggle-status").forEach(btn => {
      btn.onclick = async () => {
        const id = btn.dataset.id;
        const newStatus = btn.dataset.status === "active" ? "suspended" : "active";
        try {
          await collabFetch(`/api/host/clients/${id}/suspend`, "POST", { status: newStatus });
          toast(`Client status updated to ${newStatus}`);
          loadHostClients();
        } catch (err) {
          toast(`Failed: ${err.message}`);
        }
      };
    });

    tbody.querySelectorAll(".btn-client-reset-pwd").forEach(btn => {
      btn.onclick = async () => {
        const id = btn.dataset.id;
        const user = btn.dataset.user;
        const newPass = prompt(`Enter new password for ${user}:`, "NewClientPassword2026!");
        if (!newPass) return;
        try {
          await collabFetch(`/api/host/clients/${id}/reset-password`, "POST", { new_password: newPass });
          toast(`Password reset successfully for ${user}`);
        } catch (err) {
          toast(`Failed: ${err.message}`);
        }
      };
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="error">${err.message}</td></tr>`;
  }
}

// ----------------- HOST SUBMISSIONS -----------------
async function loadHostSubmissions() {
  const tbody = $("host-submissions-table-rows");
  if (!tbody) return;
  try {
    const data = await collabFetch("/api/host/submissions");
    const subs = data.submissions || [];
    if (subs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="empty">No client submissions in queue.</td></tr>';
      return;
    }
    tbody.innerHTML = subs.map(s => `
      <tr>
        <td><code>${s.id}</code></td>
        <td><b>${s.client_username || s.client_id}</b></td>
        <td>${s.file_count}</td>
        <td>${escBytes(s.total_size)}</td>
        <td><code class="hash-code-inline" title="${s.merkle_root}">${s.merkle_root.slice(0, 16)}&hellip;</code></td>
        <td><small>${new Date(s.submitted_at_ms).toLocaleString()}</small></td>
        <td><span class="state-pill ${s.status === 'accepted' ? 'active' : s.status === 'pending' ? 'badge-amber' : ''}">${s.status}</span></td>
        <td>
          ${s.status === 'pending' ? `
            <button class="btn forest-btn btn-xs btn-accept-sub" data-id="${s.id}">Accept</button>
            <button class="btn danger btn-xs btn-reject-sub" data-id="${s.id}">Reject</button>
          ` : `<small class="muted">${s.review_notes || 'Reviewed'}</small>`}
        </td>
      </tr>
    `).join('');

    tbody.querySelectorAll(".btn-accept-sub").forEach(btn => {
      btn.onclick = async () => {
        const id = btn.dataset.id;
        const notes = prompt("Reviewer Acceptance Notes (optional):", "Accepted into workspace baseline");
        try {
          const res = await collabFetch(`/api/host/submissions/${id}/accept`, "POST", { notes: notes || "" });
          toast(res.message || "Submission accepted! Baseline and working copy established.");
          loadHostSubmissions();
        } catch (err) {
          toast(`Error: ${err.message}`);
        }
      };
    });

    tbody.querySelectorAll(".btn-reject-sub").forEach(btn => {
      btn.onclick = async () => {
        const id = btn.dataset.id;
        const reason = prompt("Rejection Reason:", "Files need revisions");
        if (!reason) return;
        try {
          const res = await collabFetch(`/api/host/submissions/${id}/reject`, "POST", { reason });
          toast(res.message || "Submission rejected.");
          loadHostSubmissions();
        } catch (err) {
          toast(`Error: ${err.message}`);
        }
      };
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" class="error">${err.message}</td></tr>`;
  }
}

// ----------------- HOST WORKSPACE FILES & EDITOR -----------------
async function loadHostWorkspaceFiles() {
  const container = $("host-workspace-file-list");
  if (!container) return;
  try {
    const data = await collabFetch("/api/host/workspaces/files");
    hostWorkspaceFilesCache = data.files || [];
    renderHostFileList(hostWorkspaceFilesCache);
  } catch (err) {
    container.innerHTML = `<p class="error">${err.message}</p>`;
  }
}

function renderHostFileList(files) {
  const container = $("host-workspace-file-list");
  if (!container) return;
  if (files.length === 0) {
    container.innerHTML = '<p class="empty">No files in working copy. Accept a client submission or click "+ New File".</p>';
    return;
  }
  container.innerHTML = files.map(f => `
    <div class="file-list-item ${hostSelectedFile === f.path ? 'selected' : ''}" data-path="${f.path}">
      <div>
        <b>${f.path}</b>
        <div class="file-item-meta">${escBytes(f.size)} &middot; ${new Date(f.modified_ms).toLocaleTimeString()}</div>
      </div>
      <small class="muted">&rsaquo;</small>
    </div>
  `).join('');

  container.querySelectorAll(".file-list-item").forEach(item => {
    item.onclick = () => selectHostFile(item.dataset.path);
  });
}

async function selectHostFile(path) {
  hostSelectedFile = path;
  put($("host-editor-filepath"), path);
  const textarea = $("host-editor-textarea");
  const saveBtn = $("btn-host-editor-save");
  const delBtn = $("btn-host-editor-delete");
  const statusPill = $("host-editor-status");

  document.querySelectorAll(".file-list-item").forEach(el => {
    el.classList.toggle("selected", el.dataset.path === path);
  });

  try {
    statusPill.textContent = "Loading...";
    const data = await collabFetch(`/api/host/workspaces/files/content?path=${encodeURIComponent(path)}`);
    textarea.value = data.content || "";
    textarea.disabled = false;
    saveBtn.disabled = false;
    delBtn.disabled = false;
    statusPill.textContent = "Loaded";
    statusPill.className = "state-pill active";
  } catch (err) {
    textarea.value = `[Error loading file: ${err.message}]`;
    statusPill.textContent = "Error";
    statusPill.className = "state-pill";
  }
}

async function saveCurrentHostFile() {
  if (!hostSelectedFile) return;
  const content = $("host-editor-textarea").value;
  const statusPill = $("host-editor-status");
  try {
    statusPill.textContent = "Saving...";
    await collabFetch("/api/host/workspaces/files/content", "POST", { path: hostSelectedFile, content });
    statusPill.textContent = "Saved";
    statusPill.className = "state-pill active";
    toast(`File saved: ${hostSelectedFile}`);
    loadHostWorkspaceFiles();
  } catch (err) {
    toast(`Failed to save: ${err.message}`);
    statusPill.textContent = "Save failed";
  }
}

async function deleteCurrentHostFile() {
  if (!hostSelectedFile) return;
  if (!confirm(`Are you sure you want to delete ${hostSelectedFile} from working copy?`)) return;
  try {
    await collabFetch("/api/host/workspaces/files/delete", "POST", { path: hostSelectedFile });
    toast(`File deleted: ${hostSelectedFile}`);
    hostSelectedFile = null;
    put($("host-editor-filepath"), "—");
    $("host-editor-textarea").value = "";
    $("host-editor-textarea").disabled = true;
    $("btn-host-editor-save").disabled = true;
    $("btn-host-editor-delete").disabled = true;
    loadHostWorkspaceFiles();
  } catch (err) {
    toast(`Delete failed: ${err.message}`);
  }
}

// ----------------- HOST REVIEW & DIFF -----------------
async function loadHostReview() {
  const tbody = $("host-diff-files-rows");
  const diffBox = $("host-diff-viewer");
  if (!tbody) return;
  try {
    const data = await collabFetch("/api/host/workspaces/changes");
    put($("review-count-added"), data.counts?.added ?? 0);
    put($("review-count-modified"), data.counts?.modified ?? 0);
    put($("review-count-deleted"), data.counts?.deleted ?? 0);
    put($("review-count-unchanged"), data.counts?.unchanged ?? 0);

    const diffs = data.diffs || [];
    const changed = diffs.filter(d => d.change_type !== "UNCHANGED");

    if (changed.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" class="empty">No changes detected. Working copy matches baseline exactly.</td></tr>';
      if (diffBox) diffBox.innerHTML = '<p class="empty">All files are in sync with baseline.</p>';
      return;
    }

    tbody.innerHTML = changed.map(d => `
      <tr class="diff-file-row" data-path="${d.relative_path}" style="cursor:pointer;">
        <td><b>${d.relative_path}</b></td>
        <td><span class="badge ${d.change_type === 'ADDED' ? 'badge-active' : d.change_type === 'MODIFIED' ? 'badge-amber' : 'badge-inactive'}">${d.change_type}</span></td>
        <td><small class="muted font-mono">${d.baseline_hash ? d.baseline_hash.slice(0, 10) + '…' : '&mdash;'}</small></td>
        <td><small class="muted font-mono">${d.current_hash ? d.current_hash.slice(0, 10) + '…' : '&mdash;'}</small></td>
      </tr>
    `).join('');

    tbody.querySelectorAll(".diff-file-row").forEach(row => {
      row.onclick = () => renderFileDiff(row.dataset.path);
    });

    // Automatically inspect first changed file
    if (changed[0]) renderFileDiff(changed[0].relative_path);
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="4" class="error">${err.message}</td></tr>`;
  }
}

async function renderFileDiff(relPath) {
  const diffBox = $("host-diff-viewer");
  put($("host-diff-active-path"), relPath);
  if (!diffBox) return;
  try {
    diffBox.innerHTML = '<p class="muted">Loading diff lines...</p>';
    const d = await collabFetch(`/api/host/workspaces/diff?path=${encodeURIComponent(relPath)}`);
    if (d.diff_text) {
      const lines = d.diff_text.split('\n');
      diffBox.innerHTML = lines.map((line, i) => {
        let cls = "diff-line-context";
        if (line.startsWith("+")) cls = "diff-line-added";
        else if (line.startsWith("-")) cls = "diff-line-deleted";
        return `<div class="diff-line ${cls}"><span class="diff-ln">${i + 1}</span><span class="diff-content">${line || ' '}</span></div>`;
      }).join('');
    } else {
      diffBox.innerHTML = `<p class="empty">${d.change_type}: File is identical or binary.</p>`;
    }
  } catch (err) {
    diffBox.innerHTML = `<p class="error">${err.message}</p>`;
  }
}

// ----------------- PUBLISH VERSION -----------------
async function publishVersion() {
  const title = $("publish-title").value.trim();
  const notes = $("publish-notes").value.trim();
  if (!title) { toast("Version title required"); return; }
  try {
    const res = await collabFetch("/api/host/workspaces/publish", "POST", { title, release_notes: notes });
    const v = res.version;
    $("publish-result-card").style.display = "block";
    put($("pub-result-id"), v.id);
    put($("pub-result-title"), v.title);
    put($("pub-result-root"), v.merkle_root);
    put($("pub-result-meta"), `${v.file_count} files (${escBytes(v.total_size)})`);
    toast("Immutable version published successfully!");
  } catch (err) {
    toast(`Publish failed: ${err.message}`);
  }
}

// ----------------- HOST VERSIONS -----------------
async function loadHostVersions() {
  const tbody = $("host-versions-table-rows");
  if (!tbody) return;
  try {
    const data = await collabFetch("/api/host/workspaces/versions");
    const versions = data.versions || [];
    if (versions.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty">No published versions yet.</td></tr>';
      return;
    }
    tbody.innerHTML = versions.map(v => `
      <tr>
        <td><b>${v.title}</b><br><small class="muted font-mono">${v.id}</small></td>
        <td><small>${new Date(v.published_at_ms).toLocaleString()}</small></td>
        <td>${v.file_count}</td>
        <td>${escBytes(v.total_size)}</td>
        <td><code class="hash-code-inline" title="${v.merkle_root}">${v.merkle_root.slice(0, 16)}&hellip;</code></td>
        <td>${v.published_by_username || v.published_by_id}</td>
        <td><small>${v.release_notes || '&mdash;'}</small></td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="error">${err.message}</td></tr>`;
  }
}

// ----------------- HOST ACTIVITY LOG -----------------
async function loadHostActivity() {
  const tbody = $("host-activity-table-rows");
  if (!tbody) return;
  try {
    const data = await collabFetch("/api/host/activity");
    const events = data.events || [];
    if (events.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty">No security events recorded.</td></tr>';
      return;
    }
    tbody.innerHTML = events.map(e => `
      <tr>
        <td><small>${new Date(e.timestamp_ms).toLocaleString()}</small></td>
        <td><b>${e.actor_username || 'system'}</b></td>
        <td><code>${e.action}</code></td>
        <td>${e.resource || '&mdash;'}</td>
        <td><span class="badge ${e.outcome === 'success' ? 'badge-active' : 'badge-inactive'}">${e.outcome}</span></td>
        <td><small>${e.detail || '&mdash;'}</small></td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="error">${err.message}</td></tr>`;
  }
}

// ----------------- CLIENT CONTROLLERS -----------------
async function loginClient() {
  const u = $("login-client-username").value.trim();
  const p = $("login-client-password").value;
  const errBox = $("client-login-error");
  errBox.style.display = "none";
  try {
    const res = await collabFetch("/api/auth/login", "POST", { username: u, password: p });
    localStorage.setItem("mc_session_token", res.session_token);
    localStorage.setItem("mc_client_username", res.user.username);
    toast(`Welcome, ${res.user.username}!`);
    view("client-overview");
  } catch (err) {
    errBox.textContent = err.message;
    errBox.style.display = "block";
  }
}

async function loadClientOverview() {
  const username = localStorage.getItem("mc_client_username") || "client_alice";
  put($("client-user-display"), username);
  try {
    const subs = await collabFetch("/api/client/submissions");
    put($("client-stat-subs"), subs.submissions?.length ?? 0);

    const upds = await collabFetch("/api/client/updates");
    clientUpdatesCache = upds.updates || [];
    const pending = clientUpdatesCache.filter(u => u.status === "available" || u.status === "accepted").length;
    put($("client-stat-updates"), pending);

    const notice = $("client-update-notice-text");
    if (notice) {
      if (pending > 0) {
        notice.innerHTML = `<b class="text-amber">${pending} new version update${pending === 1 ? '' : 's'} published by Host.</b> Review and apply when ready.`;
      } else {
        notice.textContent = "Your local workspace is currently up to date with the latest published release.";
      }
    }
  } catch (err) {
    console.error("Error loading client overview:", err);
  }
}

async function submitClientFolder() {
  const folder = $("client-source-folder").value.trim();
  const notes = $("client-submission-notes").value.trim();
  if (!folder) { toast("Select a folder first"); return; }
  const btn = $("btn-client-send-submission");
  btn.disabled = true;
  btn.textContent = "Scanning & Submitting...";
  try {
    const res = await collabFetch("/api/client/submissions", "POST", { source_folder: folder, notes });
    const s = res.submission;
    $("client-submission-receipt").style.display = "block";
    put($("sub-receipt-id"), s.id);
    put($("sub-receipt-meta"), `${s.file_count} files (${escBytes(s.total_size)})`);
    put($("sub-receipt-root"), s.merkle_root);
    toast("Folder submitted to Host successfully!");
  } catch (err) {
    toast(`Submission error: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Scan & Submit to Host";
  }
}

async function loadClientSubmissions() {
  const tbody = $("client-submissions-table-rows");
  if (!tbody) return;
  try {
    const data = await collabFetch("/api/client/submissions");
    const subs = data.submissions || [];
    if (subs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty">You have not submitted any folders yet.</td></tr>';
      return;
    }
    tbody.innerHTML = subs.map(s => `
      <tr>
        <td><code>${s.id}</code></td>
        <td><small>${new Date(s.submitted_at_ms).toLocaleString()}</small></td>
        <td>${s.file_count}</td>
        <td>${escBytes(s.total_size)}</td>
        <td><code class="hash-code-inline" title="${s.merkle_root}">${s.merkle_root.slice(0, 16)}&hellip;</code></td>
        <td><span class="state-pill ${s.status === 'accepted' ? 'active' : s.status === 'pending' ? 'badge-amber' : ''}">${s.status}</span></td>
        <td><small>${s.review_notes || '&mdash;'}</small></td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="error">${err.message}</td></tr>`;
  }
}

async function loadClientUpdates() {
  const container = $("client-updates-container");
  if (!container) return;
  try {
    const data = await collabFetch("/api/client/updates");
    clientUpdatesCache = data.updates || [];
    if (clientUpdatesCache.length === 0) {
      container.innerHTML = '<p class="empty">No published updates available for this workspace.</p>';
      return;
    }
    container.innerHTML = clientUpdatesCache.map(u => `
      <div class="update-card-item">
        <div class="update-card-header">
          <div>
            <h3>${u.version_title}</h3>
            <small class="muted font-mono">Update ID: ${u.id} &middot; Published Merkle: ${u.merkle_root.slice(0, 16)}&hellip;</small>
          </div>
          <span class="state-pill ${u.status === 'applied' ? 'active' : u.status === 'accepted' ? 'badge-amber' : ''}">${u.status.toUpperCase()}</span>
        </div>
        <div class="update-card-body">
          <p>${u.release_notes || 'Published release update.'}</p>
          <div class="kv-grid" style="margin-bottom: 12px;">
            <div><span class="muted">Files:</span> <b>${u.file_count}</b></div>
            <div><span class="muted">Size:</span> <b>${escBytes(u.total_size)}</b></div>
          </div>
        </div>
        <div class="update-card-footer">
          <div>
            ${u.status === 'available' ? `
              <button class="btn forest-btn btn-sm btn-accept-update" data-id="${u.id}">Accept Update</button>
            ` : u.status === 'accepted' ? `
              <span class="badge badge-active">&#10003; Accepted</span>
            ` : `
              <span class="badge badge-active">&#10003; Applied on ${new Date(u.applied_at_ms).toLocaleDateString()}</span>
            `}
          </div>
          <div>
            <button class="btn neutral btn-sm" onclick="view('client-receive')">Proceed to Apply &rarr;</button>
          </div>
        </div>
      </div>
    `).join('');

    container.querySelectorAll(".btn-accept-update").forEach(btn => {
      btn.onclick = async () => {
        const id = btn.dataset.id;
        try {
          await collabFetch(`/api/client/updates/${id}/accept`, "POST");
          toast("Update accepted! You can now apply it to your local directory.");
          loadClientUpdates();
        } catch (err) {
          toast(`Accept failed: ${err.message}`);
        }
      };
    });
  } catch (err) {
    container.innerHTML = `<p class="error">${err.message}</p>`;
  }
}

async function populateClientReceiveDropdown() {
  const select = $("receive-update-id");
  if (!select) return;
  try {
    const data = await collabFetch("/api/client/updates");
    clientUpdatesCache = data.updates || [];
    select.innerHTML = '<option value="">-- Choose an accepted update --</option>' +
      clientUpdatesCache.filter(u => u.status === "accepted" || u.status === "available").map(u => `
        <option value="${u.id}">${u.version_title} (${u.status}) &ndash; ${u.merkle_root.slice(0, 10)}&hellip;</option>
      `).join('');
  } catch (err) {
    console.error("Error populating receive dropdown:", err);
  }
}

async function applyClientUpdate() {
  const updId = $("receive-update-id").value;
  const targetFolder = $("receive-target-folder").value.trim();
  if (!updId) { toast("Select an update first"); return; }
  if (!targetFolder) { toast("Select target directory"); return; }
  const btn = $("btn-apply-update-exec");
  btn.disabled = true;
  btn.textContent = "Verifying & Applying...";
  try {
    const res = await collabFetch(`/api/client/updates/${updId}/apply`, "POST", { target_folder: targetFolder });
    $("client-apply-result").style.display = "block";
    put($("apply-result-root"), res.merkle_root);
    toast("Update verified with SHA-256 and Merkle root applied!");
  } catch (err) {
    toast(`Apply failed: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Apply Verified Update";
  }
}

async function loadClientVersions() {
  const tbody = $("client-history-table-rows");
  if (!tbody) return;
  try {
    const data = await collabFetch("/api/client/updates");
    const applied = (data.updates || []).filter(u => u.status === "applied");
    if (applied.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty">No updates have been applied to this client directory yet.</td></tr>';
      return;
    }
    tbody.innerHTML = applied.map(u => `
      <tr>
        <td><code>${u.version_id}</code></td>
        <td><b>${u.version_title}</b></td>
        <td><span class="state-pill active">Applied</span></td>
        <td><code class="hash-code-inline">${u.merkle_root}</code></td>
        <td><small>${new Date(u.applied_at_ms).toLocaleString()}</small></td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" class="error">${err.message}</td></tr>`;
  }
}

async function loadClientAccount() {
  const username = localStorage.getItem("mc_client_username") || "client_alice";
  put($("account-client-username"), username);
  put($("account-client-id"), "usr-" + username);
}

// ----------------- EVENT LISTENERS BINDING -----------------
window.addEventListener("DOMContentLoaded", () => {
  // Client login submit
  $("client-quick-login-form")?.addEventListener("submit", loginClient);
  $("btn-submit-client-login")?.addEventListener("click", loginClient);

  // Host overview refresh
  $("btn-host-refresh-overview")?.addEventListener("click", loadHostOverview);

  // Client Management toggle form
  $("btn-toggle-new-client-form")?.addEventListener("click", () => {
    const formCard = $("card-new-client");
    if (formCard) formCard.style.display = formCard.style.display === "none" ? "block" : "none";
  });
  $("btn-close-new-client")?.addEventListener("click", () => {
    $("card-new-client").style.display = "none";
  });
  $("btn-cancel-new-client")?.addEventListener("click", () => {
    $("card-new-client").style.display = "none";
  });
  $("btn-save-new-client")?.addEventListener("click", async () => {
    const u = $("new-client-username").value.trim();
    const p = $("new-client-password").value;
    if (!u || !p) { toast("Username and password required"); return; }
    try {
      await collabFetch("/api/host/clients", "POST", { username: u, password: p });
      toast(`Client ${u} created!`);
      $("card-new-client").style.display = "none";
      $("new-client-username").value = "";
      $("new-client-password").value = "";
      loadHostClients();
    } catch (err) {
      toast(`Error: ${err.message}`);
    }
  });

  // Host submissions
  $("btn-refresh-submissions")?.addEventListener("click", loadHostSubmissions);

  // Host workspace files
  $("btn-host-refresh-files")?.addEventListener("click", loadHostWorkspaceFiles);
  $("btn-host-editor-save")?.addEventListener("click", saveCurrentHostFile);
  $("btn-host-editor-delete")?.addEventListener("click", deleteCurrentHostFile);
  $("btn-host-new-file-prompt")?.addEventListener("click", async () => {
    const name = prompt("Enter new filename (e.g. notes.txt or docs/readme.md):");
    if (!name) return;
    try {
      await collabFetch("/api/host/workspaces/files", "POST", { path: name, content: "" });
      toast(`File created: ${name}`);
      loadHostWorkspaceFiles();
      selectHostFile(name);
    } catch (err) {
      toast(`Failed to create file: ${err.message}`);
    }
  });

  // Host review & diff
  $("btn-refresh-diff")?.addEventListener("click", loadHostReview);

  // Host publish
  $("btn-submit-publish")?.addEventListener("click", publishVersion);
  $("btn-refresh-host-versions")?.addEventListener("click", loadHostVersions);
  $("btn-refresh-host-activity")?.addEventListener("click", loadHostActivity);

  // Client browse folders
  $("btn-client-browse-folder")?.addEventListener("click", async () => {
    try {
      const res = await api("/api/pick-folder", { slot: "submission" });
      if (!res.cancelled && res.path) {
        $("client-source-folder").value = res.path;
      }
    } catch (err) {
      toast(`Browse error: ${err.message}`);
    }
  });

  $("btn-client-browse-target")?.addEventListener("click", async () => {
    try {
      const res = await api("/api/pick-folder", { slot: "target" });
      if (!res.cancelled && res.path) {
        $("receive-target-folder").value = res.path;
      }
    } catch (err) {
      toast(`Browse error: ${err.message}`);
    }
  });

  // Client actions
  $("btn-client-send-submission")?.addEventListener("click", submitClientFolder);
  $("btn-refresh-client-subs")?.addEventListener("click", loadClientSubmissions);
  $("btn-refresh-client-updates")?.addEventListener("click", loadClientUpdates);
  $("btn-apply-update-exec")?.addEventListener("click", applyClientUpdate);

  // Logout actions
  const doLogout = async () => {
    try {
      await collabFetch("/api/auth/logout", "POST");
    } catch {}
    localStorage.removeItem("mc_session_token");
    localStorage.removeItem("mc_client_username");
    toast("Signed out");
    view("home");
  };
  $("btn-client-logout-top")?.addEventListener("click", doLogout);
  $("btn-client-logout-page")?.addEventListener("click", doLogout);
});
