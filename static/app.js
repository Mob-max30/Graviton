let currentOrgId = null;
let currentOverview = null;
let currentSessionId = null;

const $ = (id) => document.getElementById(id);

function showToast(msg, isErr = false) {
  const t = $("toast");
  t.textContent = msg;
  t.style.borderColor = isErr ? "#ef4444" : "#38bdf8";
  t.style.display = "block";
  setTimeout(() => { t.style.display = "none"; }, 3500);
}

async function api(path, method = "GET", body = null) {
  const opts = { method, headers: { "Content-Type": "application/json" } };
  if (body !== null) opts.body = JSON.stringify(body);
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
  return data;
}

document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    $(`tab-${btn.dataset.tab}`).classList.add("active");
  });
});

async function loadOrgs() {
  const orgs = await api("/api/orgs");
  const sel = $("orgSelect");
  sel.innerHTML = "";
  orgs.forEach((o) => {
    const opt = document.createElement("option");
    opt.value = o.org_id;
    opt.textContent = `${o.name} (${o.org_id})`;
    sel.appendChild(opt);
  });
  if (orgs.length && !currentOrgId) currentOrgId = orgs[0].org_id;
  if (currentOrgId) {
    sel.value = currentOrgId;
    await refreshOverview();
  }
}

$("orgSelect").addEventListener("change", async (e) => {
  currentOrgId = e.target.value;
  currentSessionId = null;
  await refreshOverview();
});

function activeDeviceForUser(userId) {
  if (!currentOverview) return null;
  return currentOverview.devices.find((d) => d.user_id === userId && d.status === "ACTIVE") || null;
}

async function refreshOverview() {
  if (!currentOrgId) return;
  currentOverview = await api(`/api/orgs/${currentOrgId}/overview`);
  const activeKey = currentOverview.key_versions.find((k) => k.state === "ACTIVE");
  $("keyBadge").textContent = activeKey ? `Key v${activeKey.version}` : "No Active Key";

  // Nodes table
  $("nodesTable").innerHTML = `<table><tr><th>Node</th><th>Service</th><th>Key Ver</th><th>Revoked Devices</th><th>Epoch</th></tr>${
    currentOverview.nodes.map((n) =>
      `<tr><td>${n.node_id}</td><td>${n.service_name}</td><td>v${n.active_key_version}</td><td>${n.revoked_devices.length}</td><td>${n.revocation_epoch}</td></tr>`
    ).join("")
  }</table>`;

  // Users & Devices table
  $("usersTable").innerHTML = `<table><tr><th>Username</th><th>Identifier</th><th>Role</th><th>Status</th><th>Devices</th><th>Actions</th></tr>${
    currentOverview.users.map((u) => {
      const devs = currentOverview.devices.filter((d) => d.user_id === u.user_id);
      const devHtml = devs.map((d) =>
        `<div>${d.device_id} [${d.status}, v${d.key_version}] ${
          d.status === "ACTIVE" ? `<button class="warn" onclick="revokeDevice('${d.device_id}')">Revoke</button>` : ""
        }</div>`
      ).join("");
      return `<tr>
        <td>${u.username} ${u.is_admin ? "(Admin)" : ""}</td>
        <td>${u.identifier}</td>
        <td>${u.role}</td>
        <td>${u.quarantined ? "QUARANTINED" : "ACTIVE"}</td>
        <td>${devHtml}</td>
        <td>
          <button class="secondary" onclick="reenrollUser('${u.user_id}')">Re-enroll</button>
          <button class="secondary" onclick="promotePrompt('${u.user_id}')">Set Identifier</button>
        </td>
      </tr>`;
    }).join("")
  }</table>`;

  // Populate user selectors
  const selectors = ["accessActorSelect", "chatSenderSelect", "chatRecipientSelect"];
  selectors.forEach((sid) => {
    const el = $(sid);
    const prev = el.value;
    el.innerHTML = currentOverview.users
      .map((u) => `<option value="${u.user_id}">${u.username} [${u.identifier}]</option>`)
      .join("");
    if (prev && [...el.options].some((o) => o.value === prev)) el.value = prev;
  });

  await Promise.all([loadResources(), loadMessages(), loadAudit(), loadAlerts()]);
}

$("registerOrgForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const res = await api("/api/orgs", "POST", {
      org_name: $("orgName").value,
      admin_username: $("adminUsername").value,
      admin_identifier: $("adminIdentifier").value,
    });
    currentOrgId = res.org_id;
    showToast(`Registered ${res.org_name}`);
    await loadOrgs();
  } catch (err) { showToast(err.message, true); }
});

$("addUserForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await api(`/api/orgs/${currentOrgId}/users`, "POST", {
      admin_user_id: currentOverview.org.admin_user_id,
      username: $("newUsername").value,
      identifier: $("newIdentifier").value,
      role: $("newRole").value,
      approved_ticket: $("addTicket").value || null,
    });
    showToast("Member added");
    $("addUserForm").reset();
    $("newRole").value = "member";
    await refreshOverview();
  } catch (err) { showToast(err.message, true); }
});

window.revokeDevice = async (deviceId) => {
  try {
    const res = await api(`/api/orgs/${currentOrgId}/devices/${deviceId}/revoke`, "POST", {
      actor_user_id: currentOverview.org.admin_user_id,
      reason: "operator_revoke",
    });
    showToast(`Revoked across ${res.node_timings.length} nodes in ${res.propagation_to_last_node_ms} ms`);
    await refreshOverview();
  } catch (err) { showToast(err.message, true); }
};

window.reenrollUser = async (userId) => {
  try {
    const res = await api(`/api/orgs/${currentOrgId}/users/${userId}/reenroll`, "POST", {
      actor_user_id: currentOverview.org.admin_user_id,
    });
    showToast(`Re-enrolled ${res.device_id}`);
    await refreshOverview();
  } catch (err) { showToast(err.message, true); }
};

window.promotePrompt = async (userId) => {
  const newId = prompt("New identifier:");
  if (!newId) return;
  const ticket = prompt("Approved change ticket (leave blank for unapproved):") || null;
  try {
    await api(`/api/orgs/${currentOrgId}/users/${userId}/identifier`, "POST", {
      actor_user_id: currentOverview.org.admin_user_id,
      new_identifier: newId,
      approved_ticket: ticket,
    });
    showToast(`Updated identifier to ${newId}`);
    await refreshOverview();
  } catch (err) { showToast(err.message, true); }
};

$("rotateKeyBtn").addEventListener("click", async () => {
  try {
    const res = await api(`/api/orgs/${currentOrgId}/keys/rotate`, "POST", {
      actor_user_id: currentOverview.org.admin_user_id,
      grace_seconds: Number($("graceSeconds").value || 0),
    });
    showToast(`Rotated to v${res.to_version}`);
    await refreshOverview();
  } catch (err) { showToast(err.message, true); }
});

$("crashRotateBtn").addEventListener("click", async () => {
  try {
    await api(`/api/orgs/${currentOrgId}/keys/rotate`, "POST", {
      actor_user_id: currentOverview.org.admin_user_id,
      simulate_crash_after_prepare: true,
    });
  } catch (err) {
    showToast(`Crash simulated: ${err.message}`, true);
    await refreshOverview();
  }
});

$("recoverBtn").addEventListener("click", async () => {
  try {
    const res = await api(`/api/orgs/${currentOrgId}/keys/recover`, "POST", {
      actor_user_id: currentOverview.org.admin_user_id,
    });
    showToast(`Recovered to v${res.active_key_version}`);
    await refreshOverview();
  } catch (err) { showToast(err.message, true); }
});

$("exportBackupBtn").addEventListener("click", async () => {
  try {
    const res = await api(`/api/orgs/${currentOrgId}/backup/export`, "POST", {
      actor_user_id: currentOverview.org.admin_user_id,
    });
    $("backupBox").value = res.backup_b64;
    showToast("Exported ML-DSA signed backup");
  } catch (err) { showToast(err.message, true); }
});

$("verifyBackupBtn").addEventListener("click", async () => {
  try {
    const res = await api(`/api/orgs/${currentOrgId}/backup/verify`, "POST", {
      actor_user_id: currentOverview.org.admin_user_id,
      backup_b64: $("backupBox").value,
    });
    showToast(`Backup verified (${res.key_versions_restored} versions)`);
  } catch (err) { showToast(err.message, true); }
});

async function loadResources() {
  const list = await api(`/api/orgs/${currentOrgId}/resources`);
  $("resourcesTable").innerHTML = `<table><tr><th>Name</th><th>Allowed Identifiers</th><th>Key Ver</th><th>Action</th></tr>${
    list.map((r) =>
      `<tr><td>${r.name}</td><td>${r.allowed_identifiers.join(", ")}</td><td>v${r.key_version}</td><td><button onclick="accessResource('${r.resource_id}')">Access</button></td></tr>`
    ).join("")
  }</table>`;
}

$("addResourceForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const adminId = currentOverview.org.admin_user_id;
    const dev = activeDeviceForUser(adminId);
    if (!dev) throw new Error("No active admin device");
    await api(`/api/orgs/${currentOrgId}/resources`, "POST", {
      actor_user_id: adminId,
      actor_device_id: dev.device_id,
      name: $("resName").value,
      content_text: $("resContent").value,
      allowed_identifiers: $("resIdentifiers").value.split(",").map((s) => s.trim()).filter(Boolean),
      allowed_users: $("resUsers").value.split(",").map((s) => s.trim()).filter(Boolean),
    });
    showToast("Resource encrypted & stored");
    $("addResourceForm").reset();
    await refreshOverview();
  } catch (err) { showToast(err.message, true); }
});

window.accessResource = async (resourceId) => {
  try {
    const actorId = $("accessActorSelect").value;
    const dev = activeDeviceForUser(actorId);
    if (!dev) throw new Error("Selected user has no active device");
    const res = await api(`/api/orgs/${currentOrgId}/resources/${resourceId}/access`, "POST", {
      actor_user_id: actorId,
      actor_device_id: dev.device_id,
    });
    $("resourceOutput").textContent = JSON.stringify(res, null, 2);
  } catch (err) {
    $("resourceOutput").textContent = `DENIED: ${err.message}`;
    showToast(err.message, true);
  } finally {
    await Promise.all([loadAudit(), loadAlerts()]);
  }
};

$("establishSessionBtn").addEventListener("click", async () => {
  try {
    const initId = $("chatSenderSelect").value;
    const peerId = $("chatRecipientSelect").value;
    const initDev = activeDeviceForUser(initId);
    const peerDev = activeDeviceForUser(peerId);
    if (!initDev || !peerDev) throw new Error("Both peers need active devices");
    const res = await api(`/api/orgs/${currentOrgId}/chat/sessions`, "POST", {
      initiator_user_id: initId,
      initiator_device_id: initDev.device_id,
      peer_user_id: peerId,
      peer_device_id: peerDev.device_id,
    });
    currentSessionId = res.session_id;
    $("activeSessionInfo").textContent = `Session ${res.session_id} | Peer FP: ${res.peer_pk_fp}`;
    showToast("PQC forward-secret session established");
  } catch (err) { showToast(err.message, true); }
});

$("sendChatForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    if (!currentSessionId) throw new Error("Establish a PQC session first");
    const senderId = $("chatSenderSelect").value;
    const recipientId = $("chatRecipientSelect").value;
    const sDev = activeDeviceForUser(senderId);
    const rDev = activeDeviceForUser(recipientId);
    await api(`/api/orgs/${currentOrgId}/chat/messages`, "POST", {
      session_id: currentSessionId,
      sender_user_id: senderId,
      sender_device_id: sDev.device_id,
      recipient_user_id: recipientId,
      recipient_device_id: rDev.device_id,
      plaintext: $("chatPlaintext").value,
    });
    $("chatPlaintext").value = "";
    await refreshOverview();
  } catch (err) { showToast(err.message, true); }
});

async function loadMessages() {
  const msgs = await api(`/api/orgs/${currentOrgId}/chat/messages`);
  $("messagesTable").innerHTML = `<table><tr><th>Seq</th><th>From</th><th>To</th><th>Session</th><th>Action</th></tr>${
    msgs.map((m) =>
      `<tr><td>#${m.seq_no}</td><td>${m.sender_name}</td><td>${m.recipient_name}</td><td>${m.session_id}</td><td><button onclick="decryptMsg('${m.message_id}','${m.recipient_user_id}','${m.recipient_device_id}')">Decrypt</button></td></tr>`
    ).join("")
  }</table>`;
}

window.decryptMsg = async (msgId, recvUserId, recvDevId) => {
  try {
    const res = await api(`/api/orgs/${currentOrgId}/chat/messages/${msgId}/receive`, "POST", {
      receiver_user_id: recvUserId,
      receiver_device_id: recvDevId,
    });
    $("chatOutput").textContent = JSON.stringify(res, null, 2);
  } catch (err) {
    $("chatOutput").textContent = `REJECTED: ${err.message}`;
    showToast(err.message, true);
  }
};

async function loadAudit() {
  const logs = await api(`/api/orgs/${currentOrgId}/audit`);
  $("auditTable").innerHTML = `<table><tr><th>Seq</th><th>Actor</th><th>Service</th><th>Action</th><th>Target</th><th>Hash</th></tr>${
    logs.map((l) =>
      `<tr><td>${l.seq}</td><td>${l.actor_id}</td><td>${l.service}</td><td>${l.action}</td><td>${l.target}</td><td>${l.entry_hash.slice(0, 14)}...</td></tr>`
    ).join("")
  }</table>`;
}

async function loadAlerts() {
  const alerts = await api(`/api/orgs/${currentOrgId}/detector/alerts`);
  $("alertsTable").innerHTML = `<table><tr><th>Severity</th><th>Rule</th><th>Identity</th><th>Services</th><th>Explanation</th><th>Response</th></tr>${
    alerts.map((a) =>
      `<tr><td>${a.severity}</td><td>${a.rule_name}</td><td>${a.identity}</td><td>${a.services.join(", ")}</td><td>${a.explanation}</td><td>${a.auto_response || "-"}</td></tr>`
    ).join("")
  }</table>`;
}

$("verifyChainBtn").addEventListener("click", async () => {
  const res = await api(`/api/orgs/${currentOrgId}/audit/verify`);
  $("securityOutput").textContent = JSON.stringify(res, null, 2);
});

$("scanAlertsBtn").addEventListener("click", async () => {
  const res = await api(`/api/orgs/${currentOrgId}/detector/scan`, "POST", { auto_respond: false });
  $("securityOutput").textContent = `Found ${res.length} alert(s)`;
  await loadAlerts();
});

$("scanAutoRespondBtn").addEventListener("click", async () => {
  const res = await api(`/api/orgs/${currentOrgId}/detector/scan`, "POST", { auto_respond: true });
  $("securityOutput").textContent = `Scanned: ${res.length} alert(s) with auto-quarantine`;
  await refreshOverview();
});

$("benchmarkBtn").addEventListener("click", async () => {
  const res = await api("/api/detector/benchmark");
  $("securityOutput").textContent = JSON.stringify(res, null, 2);
});

loadOrgs().catch((err) => showToast(err.message, true));
