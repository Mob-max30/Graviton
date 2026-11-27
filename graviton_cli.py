"""Terminal CLI for Graviton (`gt`) backed by the Graviton PQC engine (`dev` backend)."""
from __future__ import annotations

import base64
import getpass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request
import uuid

from graviton.admin import AdminManager
from graviton.audit.log import AuditLog
from graviton.client import ClientManager
from graviton.crypto.aead import aead_available, seal
from graviton.daemon.node import NodeDaemon, init_node_daemon

GREEN = "\033[92m"
WHITE = "\033[97m"
RESET = "\033[0m"


def _data_dir() -> Path:
    d = Path(os.environ.get("GRAVITON_DATA_DIR", Path.cwd() / "data"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _orgs_index_path() -> Path:
    return _data_dir() / "orgs.json"


def _active_org_file() -> Path:
    return _data_dir() / ".active_org"


def _server_url_file() -> Path:
    return _data_dir() / ".server_url"


def _get_server_url() -> str | None:
    f = _server_url_file()
    if f.is_file():
        val = f.read_text(encoding="utf-8").strip()
        return val or None
    return None


def _primary_machine_ip() -> str:
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    return "127.0.0.1"


def _current_machine_ips() -> set[str]:
    ips = {"127.0.0.1", "::1"}
    try:
        ips.add(socket.gethostbyname(socket.gethostname()))
    except OSError:
        pass
    return ips


def _remote_call(method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
    base = _get_server_url()
    if not base:
        raise RuntimeError("Not connected to a remote server")
    url = f"{base.rstrip('/')}{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json", "X-Client-IP": _primary_machine_ip()}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        detail = err.read().decode("utf-8", errors="replace")
        raise RuntimeError(detail or f"HTTP {err.code}") from err


def _load_orgs() -> dict[str, dict[str, Any]]:
    p = _orgs_index_path()
    if not p.is_file():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def _save_orgs(orgs: dict[str, dict[str, Any]]) -> None:
    _orgs_index_path().write_text(json.dumps(orgs, indent=2), encoding="utf-8")


def _org_dir(org_name: str, org_id: str) -> Path:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", org_name.strip()).strip("_") or "org"
    d = _data_dir() / "orgs" / f"{slug}_{org_id}"
    (d / "resources").mkdir(parents=True, exist_ok=True)
    return d


def _set_active_org(org_id: str) -> None:
    _active_org_file().write_text(org_id.strip(), encoding="utf-8")


def _get_active_org() -> dict[str, Any]:
    orgs = _load_orgs()
    if not orgs:
        print("No organization registered. Run: gt -register <company-name>")
        raise SystemExit(1)
    f = _active_org_file()
    org_id = f.read_text(encoding="utf-8").strip() if f.is_file() else ""
    if org_id and org_id in orgs:
        return orgs[org_id]
    return max(orgs.values(), key=lambda o: float(o.get("created_at", 0.0)))


def _get_passphrase(org: dict[str, Any]) -> str:
    env_pw = os.environ.get("GRAVITON_PASSPHRASE")
    if env_pw:
        return env_pw
    pw_file = Path(org["dir"]) / ".dev_passphrase"
    if pw_file.is_file():
        return pw_file.read_text(encoding="utf-8").strip()
    return getpass.getpass("Passphrase: ")


def _vault_index_path(org: dict[str, Any]) -> Path:
    return Path(org["dir"]) / "vault_index.json"


def _load_vault_index(org: dict[str, Any]) -> list[dict[str, Any]]:
    p = _vault_index_path(org)
    if not p.is_file():
        return []
    return json.loads(p.read_text(encoding="utf-8"))


def _save_vault_index(org: dict[str, Any], items: list[dict[str, Any]]) -> None:
    _vault_index_path(org).write_text(json.dumps(items, indent=2), encoding="utf-8")


def _members_meta_path(org: dict[str, Any]) -> Path:
    return Path(org["dir"]) / "members.json"


def _load_members_meta(org: dict[str, Any]) -> list[dict[str, Any]]:
    p = _members_meta_path(org)
    if not p.is_file():
        return []
    return json.loads(p.read_text(encoding="utf-8"))


def _save_members_meta(org: dict[str, Any], members: list[dict[str, Any]]) -> None:
    _members_meta_path(org).write_text(json.dumps(members, indent=2), encoding="utf-8")


def check_device_reachable(ip_str: str) -> bool:
    """Verify IP syntax and check if the device is reachable."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False

    if ip_obj.is_loopback:
        return True

    try:
        local_ips = {socket.gethostbyname(socket.gethostname()), "0.0.0.0"}
        if str(ip_obj) in local_ips:
            return True
    except OSError:
        pass

    ping_bin = shutil.which("ping")
    if ping_bin:
        flag = "-n" if platform.system().lower() == "windows" else "-c"
        wait_flag = "-w" if platform.system().lower() == "windows" else "-W"
        wait_val = "1000" if platform.system().lower() == "windows" else "1"
        res = subprocess.run(
            [ping_bin, flag, "1", wait_flag, wait_val, str(ip_obj)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if res.returncode == 0:
            return True

    for port in (8765, 8000, 22, 80, 443, 65432):
        try:
            with socket.create_connection((str(ip_obj), port), timeout=1.0):
                return True
        except ConnectionRefusedError:
            return True
        except OSError:
            continue
    return False


def _start_org_node_daemon(org: dict[str, Any]) -> tuple[str, int, NodeDaemon]:
    node_dir = Path(org["dir"]) / "node"
    daemon = NodeDaemon(
        node_dir,
        host="127.0.0.1",
        port=0,
        operators={org["admin_handle"], "admin"},
    )
    daemon.start()
    host, port = daemon.address
    admin = AdminManager(Path(org["dir"]) / "admin")
    st = admin._load_state()
    st["nodes"] = [{"host": host, "port": port, "node_id": org["node_id"], "node_pk_b64": org["node_pk_b64"]}]
    admin._save_state(st)
    admin.push_all()
    return host, port, daemon


def _require_aead() -> None:
    if not aead_available():
        print(
            "Error: AEAD ('cryptography') is required. Install with: pip install cryptography==50.0.2",
            file=sys.stderr,
        )
        raise SystemExit(1)


def cmd_register(company_name: str, admin_username: str | None = None) -> None:
    _require_aead()
    uname = (admin_username or input("Admin username [admin]: ").strip() or "admin").lower()
    pw = os.environ.get("GRAVITON_PASSPHRASE")
    if not pw:
        pw = secrets.token_hex(24)

    org_id = f"org_{uuid.uuid4().hex[:12]}"
    odir = _org_dir(company_name, org_id)
    pw_file = odir / ".dev_passphrase"
    pw_file.write_text(pw, encoding="utf-8")
    try:
        os.chmod(pw_file, 0o600)
    except OSError:
        pass

    admin = AdminManager(odir / "admin")
    g = admin.init_group(company_name, pw, operator_handle=uname)
    admin_pk = base64.b64decode(admin._load_state()["admin_pk_b64"])

    node_dir = odir / "node"
    node_id, node_pk, _ = init_node_daemon(node_dir, f"node-{org_id}", g["feed_id"], admin_pk)

    raw_vk_path = odir / "vault.key"
    raw_vk_path.write_bytes(secrets.token_bytes(32))
    try:
        os.chmod(raw_vk_path, 0o600)
    except OSError:
        pass

    orgs = _load_orgs()
    org_rec = {
        "org_id": org_id,
        "name": company_name,
        "dir": str(odir),
        "feed_id": g["feed_id"],
        "fingerprint": g["fingerprint"],
        "admin_handle": uname,
        "admin_ip": _primary_machine_ip(),
        "node_id": node_id,
        "node_pk_b64": base64.b64encode(node_pk).decode("ascii"),
        "created_at": time.time(),
    }
    orgs[org_id] = org_rec
    _save_orgs(orgs)
    _set_active_org(org_id)

    _save_members_meta(
        org_rec,
        [
            {
                "handle": uname,
                "username": uname,
                "identifier": "admin",
                "is_admin": True,
                "device_id": "admin-dev",
                "device_ip": _primary_machine_ip(),
                "fingerprint": g["fingerprint"],
                "status": "ACTIVE",
            }
        ],
    )
    print(f"Registered organization: {company_name} ({org_id})")
    print(f"Admin: {uname} [admin]")
    print(f"Vault: {odir / 'resources'}")


def cmd_use(company_name: str) -> None:
    if _get_server_url():
        res = _remote_call("POST", "/api/use", {"company_name": company_name.strip()})
        _set_active_org(res["org_id"])
        print(res["label"])
        return
    orgs = _load_orgs()
    matches = [o for o in orgs.values() if o["name"].lower() == company_name.strip().lower()]
    if not matches:
        print(f"Organization not found: {company_name}")
        raise SystemExit(1)
    org = max(matches, key=lambda o: float(o.get("created_at", 0.0)))
    _set_active_org(org["org_id"])
    print(f"({org['name']})")


def cmd_orgs() -> None:
    active_id = _active_org_file().read_text(encoding="utf-8").strip() if _active_org_file().is_file() else ""
    if _get_server_url():
        matched = _remote_call("GET", "/api/orgs")
        if not matched:
            print("This device is not added to any organization.")
            return
        for r in matched:
            mark = "* " if r["org_id"] == active_id else "  "
            print(f"{mark}{r['name']} -> {r['username']} [{r['identifier']}] (IP: {r['device_ip']})")
        return

    orgs = _load_orgs()
    if not orgs:
        print("No organizations registered. Run: gt -register <company-name>")
        return
    for org in sorted(orgs.values(), key=lambda o: float(o.get("created_at", 0.0)), reverse=True):
        mark = "* " if org["org_id"] == active_id else "  "
        print(f"{mark}{org['name']} ({org['org_id']}) -> admin={org['admin_handle']} fp={org['fingerprint']}")


def _store_encrypted_resource(
    org: dict[str, Any],
    name: str,
    kind: str,
    content: bytes,
    allowed_identifiers: list[str],
) -> tuple[str, bool]:
    vault_dir = Path(org["dir"]) / "resources"
    vault_dir.mkdir(parents=True, exist_ok=True)
    vault_key = (Path(org["dir"]) / "vault.key").read_bytes()

    items = _load_vault_index(org)
    existing = next((i for i in items if i["name"] == name and i["kind"] == kind), None)
    res_id = existing["resource_id"] if existing else f"res_{uuid.uuid4().hex[:12]}"
    aad = f"{org['org_id']}|{res_id}|{name}".encode("utf-8")
    blob = seal(vault_key, content, aad)
    (vault_dir / f"{res_id}.enc").write_bytes(blob)

    if existing:
        existing["updated_at"] = time.time()
    else:
        items.append(
            {
                "resource_id": res_id,
                "name": name,
                "kind": kind,
                "allowed_identifiers": allowed_identifiers,
                "created_at": time.time(),
            }
        )
    _save_vault_index(org, items)
    return res_id, existing is not None


def cmd_add(target_path: str) -> None:
    _require_aead()
    org = _get_active_org()
    p = Path(target_path).expanduser().resolve()
    if not p.exists():
        print(f"Path not found: {target_path}")
        raise SystemExit(1)

    audit = AuditLog(Path(org["dir"]) / "node" / "audit.db", Path(org["dir"]) / "node" / "audit_head.json")
    if p.is_file():
        res_id, updated = _store_encrypted_resource(org, p.name, "file", p.read_bytes(), ["admin"])
        audit.append_event(org["admin_handle"], "vault", "RESOURCE_UPDATE" if updated else "RESOURCE_ADD", res_id, "allow")
        print(f"{'Updated' if updated else 'Added'} encrypted file: {p.name} ({res_id})")
    elif p.is_dir():
        folder_id, f_updated = _store_encrypted_resource(org, p.name, "folder", b"", ["admin"])
        added_cnt = 0
        updated_cnt = 0
        for child in sorted(p.rglob("*")):
            if child.is_file():
                rel = f"{p.name}/{child.relative_to(p).as_posix()}"
                _, was_upd = _store_encrypted_resource(org, rel, "file", child.read_bytes(), ["admin"])
                if was_upd:
                    updated_cnt += 1
                else:
                    added_cnt += 1
        audit.append_event(org["admin_handle"], "vault", "FOLDER_UPDATE" if f_updated else "FOLDER_ADD", folder_id, "allow")
        print(f"Synced folder '{p.name}' ({folder_id}): {added_cnt} added, {updated_cnt} updated in {org['name']} vault.")


def cmd_ls(folder_filter: str | None = None) -> None:
    if _get_server_url():
        org_id = _active_org_file().read_text(encoding="utf-8").strip() if _active_org_file().is_file() else ""
        res = _remote_call("GET", f"/api/ls?org_id={urllib.parse.quote(org_id)}")
        if res.get("header"):
            print(res["header"])
        items = res.get("items", [])
    else:
        org = _get_active_org()
        print(f"({org['name']})")
        items = _load_vault_index(org)

    if not items:
        print("No files or folders added yet.")
        return

    folders = [i for i in items if i["kind"] == "folder"]
    files = [i for i in items if i["kind"] != "folder"]
    folder_names = [f["name"] for f in folders]

    if folder_filter:
        prefix = folder_filter.rstrip("/") + "/"
        matched = [f for f in files if f["name"].startswith(prefix)]
        print(f"[folder] {folder_filter}")
        if not matched:
            print("  (empty)")
            return
        for idx, child in enumerate(matched):
            branch = "└──" if idx == len(matched) - 1 else "├──"
            rel = child["name"][len(prefix):]
            ids = ", ".join(child["allowed_identifiers"])
            print(f"  {branch} {rel}  (access: {ids})")
        return

    grouped_ids: set[str] = set()
    for f in folders:
        ids = ", ".join(f["allowed_identifiers"])
        print(f"[folder] {f['name']}  (access: {ids})")
        prefix = f["name"].rstrip("/") + "/"
        children = [c for c in files if c["name"].startswith(prefix)]
        for idx, child in enumerate(children):
            grouped_ids.add(child["resource_id"])
            branch = "└──" if idx == len(children) - 1 else "├──"
            rel = child["name"][len(prefix):]
            c_ids = ", ".join(child["allowed_identifiers"])
            print(f"  {branch} {rel}  (access: {c_ids})")

    for item in files:
        if item["resource_id"] in grouped_ids:
            continue
        if any(item["name"].startswith(fn.rstrip("/") + "/") for fn in folder_names):
            continue
        ids = ", ".join(item["allowed_identifiers"])
        print(f"[file] {item['name']}  (access: {ids})")


def _define_new_access(org: dict[str, Any]) -> str:
    ident = input("Enter new access identifier (position) name: ").strip()
    if not ident:
        raise ValueError("Identifier name cannot be empty")
    items = _load_vault_index(org)
    if items:
        print("\nAvailable files & folders:")
        for idx, r in enumerate(items, start=1):
            print(f"  {idx}. [{r['kind']}] {r['name']}")
        sel = input("Select numbers to grant access (e.g. 1,3 or 'all' or 'none'): ").strip().lower()
        chosen: list[dict[str, Any]] = []
        if sel == "all":
            chosen = items
        elif sel not in ("", "none"):
            for part in sel.split(","):
                part = part.strip()
                if part.isdigit():
                    i = int(part) - 1
                    if 0 <= i < len(items):
                        chosen.append(items[i])
        for r in chosen:
            if ident not in r["allowed_identifiers"]:
                r["allowed_identifiers"].append(ident)
        _save_vault_index(org, items)
        print(f"Granted '{ident}' access to {len(chosen)} item(s).")
    else:
        print(f"Defined identifier '{ident}' (no files/folders uploaded yet).")
    return ident


def cmd_add_people() -> None:
    _require_aead()
    org = _get_active_org()
    pw = _get_passphrase(org)
    members = _load_members_meta(org)
    items = _load_vault_index(org)

    existing_positions = sorted(
        {m["identifier"] for m in members if not m.get("is_admin")}
        | {ident for it in items for ident in it["allowed_identifiers"] if ident != "admin"}
    )

    print(f"\nOrganization: {org['name']}")
    print("Select access identifier (position):")
    for idx, pos in enumerate(existing_positions, start=1):
        print(f"  {idx}. {pos}")
    define_idx = len(existing_positions) + 1
    print(f"  {define_idx}. Define new access")

    choice = input("Choice (number or position name): ").strip()
    if choice.isdigit() and int(choice) == define_idx:
        position = _define_new_access(org)
    elif choice.isdigit() and 1 <= int(choice) <= len(existing_positions):
        position = existing_positions[int(choice) - 1]
    elif choice:
        position = choice
    else:
        print("Invalid selection.")
        raise SystemExit(1)

    device_ip = input("Enter device IP address [127.0.0.1]: ").strip() or "127.0.0.1"
    if not check_device_reachable(device_ip):
        print(f"Device at {device_ip} is not reachable or does not exist. User not added.")
        raise SystemExit(1)

    count = sum(1 for m in members if m["identifier"] == position)
    handle = re.sub(r"[^a-z0-9._-]+", "-", f"{position}-{count + 1}".lower()).strip("-")
    display_name = f"{position} - {count + 1}"

    _, _, daemon = _start_org_node_daemon(org)
    try:
        admin = AdminManager(Path(org["dir"]) / "admin")
        cli = ClientManager(Path(org["dir"]) / "members" / handle)
        st = cli.init_identity(handle, pw)
        inv_path = Path(org["dir"]) / f"{handle}.invite"
        admin.create_invite(handle, 300, inv_path, pw)
        cli.join_invite(inv_path, pw, confirm_fn=lambda fp: fp == org["fingerprint"])
        admin.approve_join(handle, pw, confirm_fn=lambda fp: fp == st["fingerprint"])
        admin.push_all()
        inv_path.unlink(missing_ok=True)
    finally:
        daemon.stop()

    members.append(
        {
            "handle": handle,
            "username": display_name,
            "identifier": position,
            "is_admin": False,
            "device_id": st["device_id"],
            "device_ip": device_ip,
            "fingerprint": st["fingerprint"],
            "status": "ACTIVE",
        }
    )
    _save_members_meta(org, members)
    print(f"Added {display_name} (position: {position}, device IP: {device_ip}, handle: {handle})")


def cmd_people() -> None:
    if _get_server_url():
        org_id = _active_org_file().read_text(encoding="utf-8").strip() if _active_org_file().is_file() else ""
        res = _remote_call("GET", f"/api/people?org_id={urllib.parse.quote(org_id)}")
        if res.get("header"):
            print(res["header"])
        members = res.get("members", [])
        org_name = res.get("org_name", "")
    else:
        org = _get_active_org()
        print(f"({org['name']})")
        org_name = org["name"]
        members = _load_members_meta(org)

    if not members:
        print("No members found.")
        return
    grouped: dict[str, list[dict[str, Any]]] = {}
    for m in members:
        grouped.setdefault(m["identifier"], []).append(m)
    for ident, group in grouped.items():
        print(f"[{ident}] ({org_name})")
        for m in group:
            ip_val = m.get("device_ip", "127.0.0.1")
            print(f"  - {m['username']} -> IP: {ip_val} ({m['status']})")


def _remote_chat() -> None:
    org_id = _active_org_file().read_text(encoding="utf-8").strip() if _active_org_file().is_file() else ""
    info = _remote_call("GET", f"/api/chat/peers?org_id={urllib.parse.quote(org_id)}")
    me = info["me"]
    others = info["others"]
    if not others:
        print("No other members available to chat with.")
        raise SystemExit(1)

    print(f"\n[{info['org_name']}] Logged in as: {me['username']} [{me['identifier']}]")
    print("Select member to chat with:")
    for idx, u in enumerate(others, start=1):
        print(f"  {idx}. {u['username']} [{u['identifier']}]")

    peer_idx = int(input("Chat with (number): ").strip()) - 1
    if not (0 <= peer_idx < len(others)):
        print("Invalid member selection.")
        raise SystemExit(1)
    peer = others[peer_idx]

    print(f"\nEncrypted PQC chat started with {peer['username']} (real-time listening; type /quit to exit)\n")
    stop_event = threading.Event()
    print_lock = threading.Lock()
    seen_ids: set[str] = set()

    def _poll() -> None:
        try:
            msgs = _remote_call(
                "GET",
                f"/api/chat/messages?org_id={urllib.parse.quote(info['org_id'])}&me={urllib.parse.quote(me['handle'])}&peer={urllib.parse.quote(peer['handle'])}",
            )
        except Exception:
            return
        with print_lock:
            for m in msgs:
                mid = m["envelope_id"]
                if mid in seen_ids:
                    continue
                seen_ids.add(mid)
                sys.stdout.write(f"\r{WHITE}[{peer['username']}]: {m['text']}{RESET}\n> ")
                sys.stdout.flush()

    def _listener() -> None:
        while not stop_event.is_set():
            _poll()
            stop_event.wait(0.5)

    _poll()
    t = threading.Thread(target=_listener, daemon=True)
    t.start()
    try:
        while True:
            text = input("> ").strip()
            if not text:
                continue
            if text in ("/quit", "/exit"):
                break
            _remote_call(
                "POST",
                "/api/chat/send",
                {"org_id": info["org_id"], "me": me["handle"], "peer": peer["handle"], "text": text},
            )
            with print_lock:
                print(f"{GREEN}[{me['username']}]: {text}{RESET}")
    finally:
        stop_event.set()
        t.join(timeout=1.5)


def cmd_chat() -> None:
    _require_aead()
    if _get_server_url():
        _remote_chat()
        return

    org = _get_active_org()
    pw = _get_passphrase(org)
    members = [m for m in _load_members_meta(org) if not m.get("is_admin") and m.get("status") == "ACTIVE"]
    if len(members) < 2:
        print("Need at least 2 members to chat. Add people first with: gt -add-people")
        raise SystemExit(1)

    print(f"\nMembers in {org['name']}:")
    for idx, m in enumerate(members, start=1):
        print(f"  {idx}. {m['username']} [{m['identifier']}] ({m['handle']})")
    me_idx = int(input("You are (number): ").strip()) - 1
    if not (0 <= me_idx < len(members)):
        print("Invalid member selection.")
        raise SystemExit(1)
    me = members[me_idx]

    others = [m for m in members if m["handle"] != me["handle"]]
    print(f"\n[{org['name']}] Logged in as: {me['username']} [{me['identifier']}]")
    print("Select member to chat with:")
    for idx, m in enumerate(others, start=1):
        print(f"  {idx}. {m['username']} [{m['identifier']}] ({m['handle']})")
    peer_idx = int(input("Chat with (number): ").strip()) - 1
    if not (0 <= peer_idx < len(others)):
        print("Invalid member selection.")
        raise SystemExit(1)
    peer = others[peer_idx]

    host, port, daemon = _start_org_node_daemon(org)
    try:
        hub = (host, port)
        me_cli = ClientManager(Path(org["dir"]) / "members" / me["handle"])
        peer_cli = ClientManager(Path(org["dir"]) / "members" / peer["handle"])

        print(f"\nEncrypted PQC chat started with {peer['username']} (real-time listening; type /quit to exit)\n")
        stop_event = threading.Event()
        print_lock = threading.Lock()

        def _poll_loop() -> None:
            while not stop_event.is_set():
                try:
                    me_cli.flush_outbox(pw, hub=hub)
                    for item in me_cli.inbox(pw, hub=hub):
                        if item["sender"] == peer["handle"]:
                            msg = me_cli.read_message(item["envelope_id"], pw, hub=hub)
                            if msg["kind"] == "msg":
                                with print_lock:
                                    sys.stdout.write(f"\r{WHITE}[{peer['username']}]: {msg['text']}{RESET}\n> ")
                                    sys.stdout.flush()
                except Exception:
                    pass
                stop_event.wait(0.5)

        t = threading.Thread(target=_poll_loop, daemon=True)
        t.start()
        try:
            while True:
                text = input("> ").strip()
                if not text:
                    continue
                if text in ("/quit", "/exit"):
                    break
                res = me_cli.send_message_to(peer["handle"], text, pw, hub=hub)
                if res.get("queued"):
                    peer_cli.inbox(pw, hub=hub)
                    me_cli.flush_outbox(pw, hub=hub)
                with print_lock:
                    print(f"{GREEN}[{me['username']}]: {text}{RESET}")
        finally:
            stop_event.set()
            t.join(timeout=1.5)
    finally:
        daemon.stop()


def cmd_connect(server_target: str) -> None:
    target = server_target.strip()
    if target.startswith("http"):
        url = target
    elif ":" in target:
        url = f"http://{target}"
    else:
        url = f"http://{target}:8765"
    _server_url_file().write_text(url, encoding="utf-8")
    try:
        res = _remote_call("GET", "/api/health")
        print(f"Connected to Graviton server at {url} ({res.get('status')})")
    except Exception as exc:
        _server_url_file().unlink(missing_ok=True)
        print(f"Could not connect to {url}: {exc}")
        raise SystemExit(1)


def _make_server_handler(node_endpoints: dict[str, tuple[str, int]]):
    rate_lock = threading.Lock()
    rate_buckets: dict[str, list[float]] = {}

    class GravitonHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def _send_json(self, code: int, obj: Any) -> None:
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _check_rate_limit(self, ip: str, limit: int = 120, window_sec: float = 10.0) -> bool:
            now = time.monotonic()
            with rate_lock:
                bucket = [t for t in rate_buckets.get(ip, []) if now - t <= window_sec]
                if len(bucket) >= limit:
                    rate_buckets[ip] = bucket
                    return False
                bucket.append(now)
                rate_buckets[ip] = bucket
                return True

        def _client_ip(self) -> str:
            if self.client_address[0] in ("127.0.0.1", "::1"):
                return self.headers.get("X-Client-IP") or self.client_address[0]
            return self.client_address[0]

        def _read_json(self) -> dict[str, Any]:
            n = int(self.headers.get("Content-Length", "0"))
            if n < 0 or n > 1024 * 1024:
                raise ValueError("Payload size out of bounds")
            if n == 0:
                return {}
            obj = json.loads(self.rfile.read(n).decode("utf-8"))
            if not isinstance(obj, dict):
                raise ValueError("JSON body must be an object")
            return obj

        def _resolve_org(self, org_id: str) -> dict[str, Any] | None:
            orgs = _load_orgs()
            if org_id and org_id in orgs:
                return orgs[org_id]
            if not orgs:
                return None
            return max(orgs.values(), key=lambda o: float(o.get("created_at", 0.0)))

        def _resolve_member_by_ip(self, org: dict[str, Any], ip: str) -> dict[str, Any] | None:
            for m in _load_members_meta(org):
                if m.get("status") == "ACTIVE" and m.get("device_ip") == ip:
                    return m
            return None

        def do_GET(self) -> None:
            try:
                parsed = urllib.parse.urlparse(self.path)
                qs = urllib.parse.parse_qs(parsed.query)
                ip = self._client_ip()
                if not self._check_rate_limit(ip):
                    self._send_json(429, {"error": "Rate limit exceeded"})
                    return
                if parsed.path == "/api/health":
                    self._send_json(200, {"status": "ok"})
                    return
                if parsed.path == "/api/orgs":
                    out = []
                    for org in sorted(_load_orgs().values(), key=lambda o: float(o.get("created_at", 0.0)), reverse=True):
                        for m in _load_members_meta(org):
                            if m.get("status") == "ACTIVE" and m.get("device_ip") == ip:
                                out.append({
                                    "org_id": org["org_id"],
                                    "name": org["name"],
                                    "username": m["username"],
                                    "identifier": m["identifier"],
                                    "device_ip": ip,
                                })
                    self._send_json(200, out)
                    return

                org = self._resolve_org((qs.get("org_id") or [""])[0])
                if not org:
                    self._send_json(404, {"error": "No organization"})
                    return
                me = self._resolve_member_by_ip(org, ip)
                if not me:
                    self._send_json(403, {"error": f"Device IP {ip} not registered in {org['name']}"})
                    return

                if parsed.path == "/api/ls":
                    self._send_json(200, {"header": f"({org['name']})", "items": _load_vault_index(org)})
                    return
                if parsed.path == "/api/people":
                    self._send_json(200, {"header": f"({org['name']})", "org_name": org["name"], "members": _load_members_meta(org)})
                    return
                if parsed.path == "/api/chat/peers":
                    others = [m for m in _load_members_meta(org) if m["handle"] != me["handle"] and not m.get("is_admin") and m.get("status") == "ACTIVE"]
                    self._send_json(200, {"org_id": org["org_id"], "org_name": org["name"], "me": me, "others": others})
                    return
                if parsed.path == "/api/chat/messages":
                    me_handle = (qs.get("me") or [me["handle"]])[0]
                    peer_handle = (qs.get("peer") or [""])[0]
                    pw = _get_passphrase(org)
                    hub = node_endpoints[org["org_id"]]
                    me_cli = ClientManager(Path(org["dir"]) / "members" / me_handle)
                    me_cli.flush_outbox(pw, hub=hub)
                    out = []
                    for item in me_cli.inbox(pw, hub=hub):
                        if item["sender"] == peer_handle:
                            msg = me_cli.read_message(item["envelope_id"], pw, hub=hub)
                            if msg["kind"] == "msg":
                                out.append({"envelope_id": item["envelope_id"], "text": msg["text"]})
                    self._send_json(200, out)
                    return
                self._send_json(404, {"error": "Not found"})
            except Exception:
                self._send_json(500, {"error": "Internal error"})

        def do_POST(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            ip = self._client_ip()
            if not self._check_rate_limit(ip):
                self._send_json(429, {"error": "Rate limit exceeded"})
                return
            try:
                body = self._read_json()
            except Exception:
                self._send_json(400, {"error": "Invalid or oversized JSON payload"})
                return
            try:
                if parsed.path == "/api/use":
                    cname = str(body.get("company_name", "")).strip()
                    matches = [o for o in _load_orgs().values() if o["name"].lower() == cname.lower()]
                    if not matches:
                        self._send_json(403, {"error": f"Organization unavailable: {cname}"})
                        return
                    org = max(matches, key=lambda o: float(o.get("created_at", 0.0)))
                    usr = self._resolve_member_by_ip(org, ip)
                    if not usr:
                        self._send_json(403, {"error": f"Device IP {ip} is not registered in {org['name']}"})
                        return
                    label = f"({org['name']})" if usr.get("is_admin") else f"({org['name']}:{usr['identifier']})"
                    self._send_json(200, {"org_id": org["org_id"], "label": label})
                    return

                if parsed.path == "/api/chat/send":
                    org = self._resolve_org(str(body.get("org_id", "")))
                    if not org:
                        self._send_json(404, {"error": "Org not found"})
                        return
                    me = self._resolve_member_by_ip(org, ip)
                    if not me:
                        self._send_json(403, {"error": "Unauthorized"})
                        return
                    me_handle = str(body.get("me") or me["handle"])
                    peer_handle = str(body["peer"])
                    text = str(body["text"])
                    pw = _get_passphrase(org)
                    hub = node_endpoints[org["org_id"]]
                    me_cli = ClientManager(Path(org["dir"]) / "members" / me_handle)
                    peer_cli = ClientManager(Path(org["dir"]) / "members" / peer_handle)
                    res = me_cli.send_message_to(peer_handle, text, pw, hub=hub)
                    if res.get("queued"):
                        peer_cli.inbox(pw, hub=hub)
                        me_cli.flush_outbox(pw, hub=hub)
                    self._send_json(200, {"sent": True})
                    return
                self._send_json(404, {"error": "Not found"})
            except Exception:
                self._send_json(500, {"error": "Internal error"})

    return GravitonHandler


def cmd_serve(port: int = 8765) -> None:
    """Start Graviton server (HTTP control plane + dev NodeDaemon PQC backend)."""
    orgs = _load_orgs()
    if not orgs:
        print("No organization registered. Run: gt -register <company-name>")
        raise SystemExit(1)
    daemons: list[NodeDaemon] = []
    endpoints: dict[str, tuple[str, int]] = {}
    for org_id, org in orgs.items():
        h, p, d = _start_org_node_daemon(org)
        daemons.append(d)
        endpoints[org_id] = (h, p)

    srv = ThreadingHTTPServer(("0.0.0.0", port), _make_server_handler(endpoints))
    print(f"Graviton server listening on {_primary_machine_ip()}:{port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Graviton server...")
    finally:
        srv.server_close()
        for d in daemons:
            d.stop()


def cmd_prompt() -> None:
    f = _active_org_file()
    if not f.is_file():
        return
    org_id = f.read_text(encoding="utf-8").strip()
    orgs = _load_orgs()
    org = orgs.get(org_id)
    if org and org.get("admin_ip") in _current_machine_ips():
        sys.stdout.write(f" ({org['name']})")


def cmd_shell_init() -> None:
    print('_graviton_ps1() { local g; g=$(gt prompt 2>/dev/null); PS1="\\u@\\h:\\w${g}\\$ "; }')
    print('PROMPT_COMMAND="_graviton_ps1"')


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print("Usage:")
        print("  gt -register <company-name>")
        print("  gt -serve [port]")
        print("  gt -connect <server-ip>")
        print("  gt use <company-name>")
        print("  gt orgs")
        print("  gt ls [folder-name]")
        print("  gt people")
        print("  gt -add <file-or-folder-path>")
        print("  gt -add-people")
        print("  gt -chat")
        return 1

    flag = args[0]
    if flag in ("-serve", "--serve", "serve"):
        cmd_serve(int(args[1]) if len(args) > 1 else 8765)
        return 0
    if flag in ("-connect", "--connect", "connect"):
        if len(args) < 2:
            print("Usage: gt -connect <server-ip>")
            return 1
        cmd_connect(args[1])
        return 0
    if flag in ("-register", "--register", "register"):
        if len(args) < 2:
            print("Usage: gt -register <company-name>")
            return 1
        cmd_register(args[1], args[2] if len(args) > 2 else None)
        return 0
    if flag in ("use", "-use", "--use"):
        if len(args) < 2:
            print("Usage: gt use <company-name>")
            return 1
        cmd_use(args[1])
        return 0
    if flag in ("orgs", "-orgs", "--orgs"):
        cmd_orgs()
        return 0
    if flag in ("ls", "-ls", "--ls"):
        cmd_ls(args[1] if len(args) > 1 else None)
        return 0
    if flag in ("people", "-list", "--list"):
        cmd_people()
        return 0
    if flag in ("prompt", "-prompt"):
        cmd_prompt()
        return 0
    if flag in ("shell-init", "-shell-init"):
        cmd_shell_init()
        return 0
    if flag in ("-add", "--add"):
        if len(args) < 2:
            print("Usage: gt -add <file-or-folder-path>")
            return 1
        cmd_add(args[1])
        return 0
    if flag in ("-add-people", "--add-people", "-people", "--people"):
        cmd_add_people()
        return 0
    if flag in ("-chat", "--chat"):
        cmd_chat()
        return 0

    print(f"Unknown command: {flag}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
