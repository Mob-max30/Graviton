let currentOrgId = null;
let currentOverview = null;
let currentResources = [];
let currentSessionId = null;

const $ = (id) => document.getElementById(id);

function showToast(msg, isErr = false) {
  const t = $("toast");
  t.textContent = msg;
  t.style.borderColor = isErr ? "rgba(255, 255, 255, 0.55)" : "rgba(255, 255, 255, 0.22)";
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

function showWorkspaceView() {
  $("view-register").classList.remove("active");
  $("view-workspace").classList.add("active");
  backToHub();
}

window.backToHub = () => {
  $("mainContainer").classList.remove("workspace-mode");
  $("iconHub").style.display = "flex";
  document.querySelectorAll(".wpanel").forEach((p) => p.classList.remove("active"));
};

document.querySelectorAll(".hub-icon-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    $("iconHub").style.display = "none";
    $("mainContainer").classList.add("workspace-mode");
    document.querySelectorAll(".wpanel").forEach((p) => p.classList.remove("active"));
    $(`wtab-${btn.dataset.wtab}`).classList.add("active");
  });
});

async function loadOrgs() {
  const orgs = await api("/api/orgs");
  const box = $("existingOrgBox");
  const sel = $("existingOrgSelect");
  if (orgs.length > 0) {
    sel.innerHTML = orgs.map((o) => `<option value="${o.org_id}">${o.name} (${o.org_id})</option>`).join("");
    box.style.display = "block";
  } else {
    box.style.display = "none";
  }
}

$("openExistingOrgBtn").addEventListener("click", async () => {
  const sel = $("existingOrgSelect");
  if (!sel.value) return;
  currentOrgId = sel.value;
  currentSessionId = null;
  await refreshOverview();
  showWorkspaceView();
});

function activeDeviceForUser(userId) {
  if (!currentOverview) return null;
  return currentOverview.devices.find((d) => d.user_id === userId && d.status === "ACTIVE") || null;
}

async function refreshOverview() {
  if (!currentOrgId) return;
  currentOverview = await api(`/api/orgs/${currentOrgId}/overview`);
  currentResources = await api(`/api/orgs/${currentOrgId}/resources`);

  renderUsersTable();
  renderResourcesTable();

  const selectors = ["chatSenderSelect", "chatRecipientSelect"];
  selectors.forEach((sid) => {
    const el = $(sid);
    if (!el) return;
    const prev = el.value;
    el.innerHTML = currentOverview.users
      .map((u) => `<option value="${u.user_id}">${u.username} [${u.identifier}]</option>`)
      .join("");
    if (prev && [...el.options].some((o) => o.value === prev)) el.value = prev;
  });

  await loadMessages();
}

function renderUsersTable() {
  $("usersTable").innerHTML = `<table><tr><th>Username</th><th>Identifier</th><th>File Access</th><th>Actions</th></tr>${
    currentOverview.users.map((u) => {
      const fileChecks = currentResources.map((r) => {
        const hasDirect = (r.allowed_users || []).includes(u.user_id);
        const hasId = (r.allowed_identifiers || []).includes(u.identifier);
        const checked = u.is_admin || hasDirect || hasId ? "checked" : "";
        const disabled = u.is_admin ? "disabled" : "";
        return `<label style="display:inline-flex;flex-direction:row;align-items:center;gap:6px;margin-right:10px;">
          <input type="checkbox" ${checked} ${disabled} onchange="toggleFileAccess('${r.resource_id}','${u.user_id}',this.checked)" />
          <span>${r.name}</span>
        </label>`;
      }).join("") || "<span class='muted'>No files</span>";

      const actions = u.is_admin
        ? "<span class='muted'>Admin</span>"
        : `<button class="secondary" onclick="setIdentifierPrompt('${u.user_id}')">Set Identifier</button>
           <button class="warn" onclick="removePerson('${u.user_id}')">Remove</button>`;

      return `<tr>
        <td>${u.username}</td>
        <td>${u.identifier}</td>
        <td>${fileChecks}</td>
        <td>${actions}</td>
      </tr>`;
    }).join("")
  }</table>`;
}

let ctxTargetResourceId = null;

function renderResourcesTable() {
  const fileSvg = `<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`;
  const folderSvg = `<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>`;

  $("resourcesGrid").innerHTML = currentResources.map((r) => {
    const icon = r.kind === "folder" ? folderSvg : fileSvg;
    return `<div class="resource-item" onclick="accessResource('${r.resource_id}','${r.kind}')" oncontextmenu="openContextMenu(event,'${r.resource_id}')">
      ${icon}
      <div class="resource-name">${r.name}</div>
    </div>`;
  }).join("");
}

window.openContextMenu = (e, resourceId) => {
  e.preventDefault();
  ctxTargetResourceId = resourceId;
  const menu = $("contextMenu");
  menu.style.left = `${e.clientX}px`;
  menu.style.top = `${e.clientY}px`;
  menu.style.display = "flex";
};

document.addEventListener("click", () => {
  const menu = $("contextMenu");
  if (menu) menu.style.display = "none";
});

$("ctxRenameBtn").addEventListener("click", async () => {
  if (!ctxTargetResourceId) return;
  const current = currentResources.find((r) => r.resource_id === ctxTargetResourceId);
  const newName = prompt("New name:", current ? current.name : "");
  if (!newName || !newName.trim()) return;
  try {
    await api(`/api/orgs/${currentOrgId}/resources/${ctxTargetResourceId}/rename`, "PUT", {
      actor_user_id: currentOverview.org.admin_user_id,
      new_name: newName.trim(),
    });
    showToast("Renamed");
    await refreshOverview();
  } catch (err) { showToast(err.message, true); }
});

$("ctxDeleteBtn").addEventListener("click", async () => {
  if (!ctxTargetResourceId) return;
  await deleteFile(ctxTargetResourceId);
});

$("registerOrgForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const res = await api("/api/orgs", "POST", {
      org_name: $("orgName").value,
      admin_username: $("adminUsername").value,
      admin_identifier: "admin",
    });
    currentOrgId = res.org_id;
    currentSessionId = null;
    $("registerOrgForm").reset();
    showToast(`Registered ${res.org_name}`);
    await refreshOverview();
    showWorkspaceView();
  } catch (err) { showToast(err.message, true); }
});

$("addUserForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await api(`/api/orgs/${currentOrgId}/users`, "POST", {
      admin_user_id: currentOverview.org.admin_user_id,
      username: $("newUsername").value,
      identifier: $("newIdentifier").value,
      role: "member",
    });
    showToast("Person added");
    $("addUserForm").reset();
    await refreshOverview();
  } catch (err) { showToast(err.message, true); }
});

window.removePerson = async (userId) => {
  try {
    const adminId = encodeURIComponent(currentOverview.org.admin_user_id);
    await api(`/api/orgs/${currentOrgId}/users/${userId}?admin_user_id=${adminId}`, "DELETE");
    showToast("Person removed");
    await refreshOverview();
  } catch (err) { showToast(err.message, true); }
};

window.setIdentifierPrompt = async (userId) => {
  const newId = prompt("New identifier:");
  if (!newId) return;
  try {
    await api(`/api/orgs/${currentOrgId}/users/${userId}/identifier`, "POST", {
      actor_user_id: currentOverview.org.admin_user_id,
      new_identifier: newId,
    });
    showToast(`Updated identifier to ${newId}`);
    await refreshOverview();
  } catch (err) { showToast(err.message, true); }
};

window.toggleFileAccess = async (resourceId, userId, grant) => {
  try {
    const res = currentResources.find((r) => r.resource_id === resourceId);
    if (!res) return;
    const allowedUsers = new Set(res.allowed_users || []);
    if (grant) allowedUsers.add(userId);
    else allowedUsers.delete(userId);

    await api(`/api/orgs/${currentOrgId}/resources/${resourceId}/acl`, "PUT", {
      actor_user_id: currentOverview.org.admin_user_id,
      allowed_identifiers: res.allowed_identifiers || [],
      allowed_users: Array.from(allowedUsers),
    });
    showToast("File access updated");
    await refreshOverview();
  } catch (err) { showToast(err.message, true); }
};

$("addFileIconBtn").addEventListener("click", () => {
  $("resFileInput").click();
});

$("resFileInput").addEventListener("change", async () => {
  const file = $("resFileInput").files[0];
  if (!file) return;
  try {
    const adminId = currentOverview.org.admin_user_id;
    const dev = activeDeviceForUser(adminId);
    if (!dev) throw new Error("No active admin device");
    const form = new FormData();
    form.append("actor_user_id", adminId);
    form.append("actor_device_id", dev.device_id);
    form.append("allowed_identifiers", "admin");
    form.append("allowed_users", "");
    form.append("file", file);

    const res = await fetch(`/api/orgs/${currentOrgId}/resources/upload`, { method: "POST", body: form });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    showToast(`Added ${data.name}`);
    $("resFileInput").value = "";
    await refreshOverview();
  } catch (err) { showToast(err.message, true); }
});

$("addFolderIconBtn").addEventListener("click", async () => {
  const name = prompt("Folder name:");
  if (!name || !name.trim()) return;
  try {
    const adminId = currentOverview.org.admin_user_id;
    const dev = activeDeviceForUser(adminId);
    if (!dev) throw new Error("No active admin device");
    await api(`/api/orgs/${currentOrgId}/folders`, "POST", {
      actor_user_id: adminId,
      actor_device_id: dev.device_id,
      name: name.trim(),
      allowed_identifiers: ["admin"],
    });
    showToast(`Created folder ${name.trim()}`);
    await refreshOverview();
  } catch (err) { showToast(err.message, true); }
});

window.deleteFile = async (resourceId) => {
  try {
    const actorId = encodeURIComponent(currentOverview.org.admin_user_id);
    await api(`/api/orgs/${currentOrgId}/resources/${resourceId}?actor_user_id=${actorId}`, "DELETE");
    showToast("Deleted");
    await refreshOverview();
  } catch (err) { showToast(err.message, true); }
};

window.accessResource = async (resourceId, kind = "file") => {
  if (kind === "folder") return;
  try {
    const actorId = currentOverview.org.admin_user_id;
    const dev = activeDeviceForUser(actorId);
    if (!dev) throw new Error("No active admin device");
    const res = await api(`/api/orgs/${currentOrgId}/resources/${resourceId}/access`, "POST", {
      actor_user_id: actorId,
      actor_device_id: dev.device_id,
    });
    const out = $("resourceOutput");
    out.style.display = "block";
    out.textContent = JSON.stringify(res, null, 2);
  } catch (err) {
    const out = $("resourceOutput");
    out.style.display = "block";
    out.textContent = `DENIED: ${err.message}`;
    showToast(err.message, true);
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
    $("activeSessionInfo").textContent = `Session ${res.session_id}`;
    showToast("Session established");
  } catch (err) { showToast(err.message, true); }
});

$("sendChatForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    if (!currentSessionId) throw new Error("Establish a session first");
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
  $("messagesTable").innerHTML = `<table><tr><th>Seq</th><th>From</th><th>To</th><th>Action</th></tr>${
    msgs.map((m) =>
      `<tr><td>#${m.seq_no}</td><td>${m.sender_name}</td><td>${m.recipient_name}</td><td><button onclick="decryptMsg('${m.message_id}','${m.recipient_user_id}','${m.recipient_device_id}')">Decrypt</button></td></tr>`
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

loadOrgs().catch((err) => showToast(err.message, true));
