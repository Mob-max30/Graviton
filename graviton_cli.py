"""Terminal CLI for Graviton (gt) integrated with the TrustLedger PQC backend."""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from trustledger.audit.logger import SignedAuditLogger
from trustledger.crypto.aead import AssociatedData
from trustledger.crypto.keys import (
    HybridIdentityKeypair,
    TrustedPeerStore,
    compute_fingerprint,
)
from trustledger.crypto.suites import CipherSuite
from trustledger.protocol.handshake import HandshakeInitiator, HandshakeResponder


GREEN = "\033[92m"
WHITE = "\033[97m"
RESET = "\033[0m"


SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS organizations (
    org_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    admin_user_id TEXT NOT NULL,
    vault_key BLOB NOT NULL,
    audit_sign_pk BLOB NOT NULL,
    audit_sign_sk BLOB NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    identifier TEXT NOT NULL,
    role TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    UNIQUE(org_id, username)
);

CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    dsa_pk BLOB NOT NULL,
    dsa_sk BLOB NOT NULL,
    ed_pk BLOB NOT NULL,
    ed_sk BLOB NOT NULL,
    fingerprint TEXT NOT NULL,
    device_ip TEXT NOT NULL DEFAULT '127.0.0.1',
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    enrolled_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS resources (
    resource_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'file',
    owner_user_id TEXT NOT NULL,
    allowed_identifiers_json TEXT NOT NULL,
    allowed_users_json TEXT NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    aad BLOB NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS chat_messages (
    message_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    sender_user_id TEXT NOT NULL,
    recipient_user_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    seq_no INTEGER NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    aad BLOB NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS pairwise_sessions (
    pair_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    user_a TEXT NOT NULL,
    user_b TEXT NOT NULL,
    session_id TEXT NOT NULL,
    session_key BLOB NOT NULL,
    created_at REAL NOT NULL
);
"""


def _data_dir() -> Path:
    d = Path(os.environ.get("GRAVITON_DATA_DIR", Path.cwd() / "data"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _db_path() -> Path:
    return Path(os.environ.get("GRAVITON_DB_PATH", str(_data_dir() / "graviton.db")))


def _connect(db_path: Path | None = None) -> sqlite3.Connection:
    p = db_path or _db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.executescript(SCHEMA_SQL)
    return conn


def _org_vault_dir(org_name: str, org_id: str) -> Path:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", org_name.strip()).strip("_") or "org"
    d = _data_dir() / "orgs" / f"{slug}_{org_id}" / "resources"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _audit_logger(org: dict[str, Any]) -> SignedAuditLogger:
    log_path = _org_vault_dir(org["name"], org["org_id"]).parent / "audit.log"
    return SignedAuditLogger(
        log_path=log_path,
        signer_key_id=org["org_id"],
        signer_sk=bytes(org["audit_sign_sk"]),
    )


def _active_org_file() -> Path:
    return _data_dir() / ".active_org"


def _server_url_file() -> Path:
    return _data_dir() / ".server_url"


def _get_server_url() -> str | None:
    f = _server_url_file()
    if f.exists():
        val = f.read_text(encoding="utf-8").strip()
        return val or None
    return None


def _remote_call(method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
    base = _get_server_url()
    if not base:
        raise RuntimeError("Not connected to a remote server")
    url = f"{base.rstrip('/')}{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json", "X-Client-IP": _primary_machine_ip()}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        detail = err.read().decode("utf-8", errors="replace")
        raise RuntimeError(detail or f"HTTP {err.code}") from err


def _set_active_org(org_id: str) -> None:
    _active_org_file().write_text(org_id.strip(), encoding="utf-8")


def _get_active_org(conn: sqlite3.Connection) -> dict[str, Any]:
    f = _active_org_file()
    org_id = f.read_text(encoding="utf-8").strip() if f.exists() else ""
    if org_id:
        row = conn.execute("SELECT * FROM organizations WHERE org_id = ?", (org_id,)).fetchone()
        if row:
            return dict(row)
    row = conn.execute("SELECT * FROM organizations ORDER BY created_at DESC LIMIT 1").fetchone()
    if row:
        return dict(row)
    print("No organization registered. Run: gt -register <company-name>")
    raise SystemExit(1)


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


def _is_admin_ip(conn: sqlite3.Connection, org: dict[str, Any]) -> bool:
    row = conn.execute(
        "SELECT device_ip FROM devices WHERE org_id = ? AND user_id = ? AND status = 'ACTIVE' LIMIT 1",
        (org["org_id"], org["admin_user_id"]),
    ).fetchone()
    return bool(row and row["device_ip"] in _current_machine_ips())


def _current_user_for_org(conn: sqlite3.Connection, org: dict[str, Any]) -> sqlite3.Row | None:
    """Resolve the user row matching this machine's IP (preferring non-loopback match)."""
    ips = _current_machine_ips()
    rows = conn.execute(
        """
        SELECT u.*, d.device_id, d.device_ip, d.dsa_pk, d.dsa_sk, d.ed_pk, d.ed_sk, d.fingerprint
        FROM users u
        JOIN devices d ON u.user_id = d.user_id AND d.status = 'ACTIVE'
        WHERE u.org_id = ?
        ORDER BY u.created_at ASC
        """,
        (org["org_id"],),
    ).fetchall()
    non_loopback = [r for r in rows if r["device_ip"] in ips and not r["device_ip"].startswith("127.")]
    if len(non_loopback) == 1:
        return non_loopback[0]
    exact = [r for r in rows if r["device_ip"] in ips]
    if len(exact) == 1:
        return exact[0]
    return None


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

    # TCP probe: open port OR active TCP RST (ConnectionRefusedError) proves host is alive
    for port in (8000, 22, 80, 443, 65432):
        try:
            with socket.create_connection((str(ip_obj), port), timeout=1.0):
                return True
        except ConnectionRefusedError:
            return True
        except OSError:
            continue
    return False


def _enroll_device_row(
    conn: sqlite3.Connection,
    org_id: str,
    user_id: str,
    device_ip: str,
) -> str:
    kp = HybridIdentityKeypair.generate()
    ed_sk_bytes = kp.ed_sk.private_bytes_raw()
    fp = kp.fingerprint_for_suite(CipherSuite.SUITE_HYBRID)
    dev_id = f"dev_{uuid.uuid4().hex[:12]}"
    conn.execute(
        """
        INSERT INTO devices (
            device_id, user_id, org_id, dsa_pk, dsa_sk, ed_pk, ed_sk,
            fingerprint, device_ip, status, enrolled_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?)
        """,
        (dev_id, user_id, org_id, kp.dsa_pk, kp.dsa_sk, kp.ed_pk, ed_sk_bytes, fp, device_ip, time.time()),
    )
    return dev_id


def _load_keypair(dev_row: sqlite3.Row) -> HybridIdentityKeypair:
    from cryptography.hazmat.primitives.asymmetric import ed25519

    return HybridIdentityKeypair(
        dsa_pk=bytes(dev_row["dsa_pk"]),
        dsa_sk=bytes(dev_row["dsa_sk"]),
        ed_pk=bytes(dev_row["ed_pk"]),
        ed_sk=ed25519.Ed25519PrivateKey.from_private_bytes(bytes(dev_row["ed_sk"])),
    )


def cmd_register(company_name: str, admin_username: str | None = None) -> None:
    uname = admin_username or input("Admin username [admin]: ").strip() or "admin"
    now = time.time()
    org_id = f"org_{uuid.uuid4().hex[:12]}"
    admin_user_id = f"usr_{uuid.uuid4().hex[:12]}"
    vault_key = secrets.token_bytes(32)
    audit_kp = HybridIdentityKeypair.generate()

    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO organizations (
                org_id, name, admin_user_id, vault_key, audit_sign_pk, audit_sign_sk, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (org_id, company_name, admin_user_id, vault_key, audit_kp.dsa_pk, audit_kp.dsa_sk, now),
        )
        conn.execute(
            """
            INSERT INTO users (user_id, org_id, username, identifier, role, is_admin, created_at)
            VALUES (?, ?, ?, 'admin', 'admin', 1, ?)
            """,
            (admin_user_id, org_id, uname, now),
        )
        _enroll_device_row(conn, org_id, admin_user_id, _primary_machine_ip())
        conn.commit()
        org = dict(conn.execute("SELECT * FROM organizations WHERE org_id = ?", (org_id,)).fetchone())

    _set_active_org(org_id)
    vault_dir = _org_vault_dir(company_name, org_id)
    _audit_logger(org).append_entry(admin_user_id, "ORG_REGISTER", org_id, "allow")
    print(f"Registered organization: {company_name} ({org_id})")
    print(f"Admin: {uname} [admin]")
    print(f"Vault: {vault_dir}")


def cmd_use(company_name: str) -> None:
    if _get_server_url():
        res = _remote_call("POST", "/api/use", {"company_name": company_name.strip()})
        _set_active_org(res["org_id"])
        print(res["label"])
        return
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM organizations WHERE LOWER(name) = LOWER(?) ORDER BY created_at DESC LIMIT 1",
            (company_name.strip(),),
        ).fetchone()
        if not row:
            print(f"Organization not found: {company_name}")
            raise SystemExit(1)
        org = dict(row)
        is_admin = _is_admin_ip(conn, org)
        cur_user = _current_user_for_org(conn, org)
        if not is_admin and cur_user is None:
            print(f"Access denied: current device IP is not registered in {org['name']}")
            raise SystemExit(1)
    _set_active_org(org["org_id"])
    if is_admin:
        print(f"({org['name']})")
    else:
        print(f"({org['name']}:{cur_user['identifier']})")


def _store_encrypted_resource(
    conn: sqlite3.Connection,
    org: dict[str, Any],
    name: str,
    kind: str,
    content: bytes,
    allowed_identifiers: list[str],
) -> str:
    res_id = f"res_{uuid.uuid4().hex[:12]}"
    nonce = secrets.token_bytes(12)
    aad = AssociatedData(
        protocol_version=1,
        suite_id=int(CipherSuite.SUITE_HYBRID),
        sender_id=org["admin_user_id"],
        recipient_id=org["org_id"],
        recipient_key_fingerprint=compute_fingerprint(bytes(org["audit_sign_pk"])),
        recipient_epoch=1,
        session_id=org["org_id"],
        sequence_number=1,
        message_id=res_id,
        chunk_index=0,
        chunk_count=1,
        total_length=len(content),
    ).serialize()
    ct = ChaCha20Poly1305(bytes(org["vault_key"])).encrypt(nonce, content, aad)

    conn.execute(
        """
        INSERT INTO resources (
            resource_id, org_id, name, kind, owner_user_id,
            allowed_identifiers_json, allowed_users_json, nonce, ciphertext, aad, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, '[]', ?, ?, ?, ?)
        """,
        (
            res_id,
            org["org_id"],
            name,
            kind,
            org["admin_user_id"],
            json.dumps(allowed_identifiers),
            nonce,
            ct,
            aad,
            time.time(),
        ),
    )
    enc_path = _org_vault_dir(org["name"], org["org_id"]) / f"{res_id}.enc"
    enc_path.write_bytes(nonce + ct)
    return res_id


def cmd_add(target_path: str) -> None:
    with _connect() as conn:
        org = _get_active_org(conn)
        p = Path(target_path).expanduser().resolve()
        if not p.exists():
            print(f"Path not found: {target_path}")
            raise SystemExit(1)

        logger = _audit_logger(org)
        if p.is_file():
            res_id = _store_encrypted_resource(conn, org, p.name, "file", p.read_bytes(), ["admin"])
            conn.commit()
            logger.append_entry(org["admin_user_id"], "RESOURCE_ADD", res_id, "allow")
            print(f"Added encrypted file: {p.name} ({res_id})")
        elif p.is_dir():
            folder_id = _store_encrypted_resource(conn, org, p.name, "folder", b"", ["admin"])
            count = 0
            for child in sorted(p.rglob("*")):
                if child.is_file():
                    rel = f"{p.name}/{child.relative_to(p).as_posix()}"
                    _store_encrypted_resource(conn, org, rel, "file", child.read_bytes(), ["admin"])
                    count += 1
            conn.commit()
            logger.append_entry(org["admin_user_id"], "FOLDER_ADD", folder_id, "allow")
            print(f"Added folder '{p.name}' ({folder_id}) with {count} encrypted file(s) into {org['name']} vault.")


def cmd_ls(folder_filter: str | None = None) -> None:
    if _get_server_url():
        org_id = _active_org_file().read_text(encoding="utf-8").strip() if _active_org_file().exists() else ""
        res = _remote_call("GET", f"/api/ls?org_id={urllib.parse.quote(org_id)}")
        if res.get("header"):
            print(res["header"])
        items = res.get("items", [])
    else:
        with _connect() as conn:
            org = _get_active_org(conn)
            if _is_admin_ip(conn, org):
                print(f"({org['name']})")
            rows = conn.execute(
                "SELECT * FROM resources WHERE org_id = ? ORDER BY created_at DESC",
                (org["org_id"],),
            ).fetchall()
        items = [dict(r) for r in rows]

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
            ids = ", ".join(json.loads(child["allowed_identifiers_json"]))
            print(f"  {branch} {rel}  (access: {ids})")
        return

    grouped_ids: set[str] = set()
    for f in folders:
        ids = ", ".join(json.loads(f["allowed_identifiers_json"]))
        print(f"[folder] {f['name']}  (access: {ids})")
        prefix = f["name"].rstrip("/") + "/"
        children = [c for c in files if c["name"].startswith(prefix)]
        for idx, child in enumerate(children):
            grouped_ids.add(child["resource_id"])
            branch = "└──" if idx == len(children) - 1 else "├──"
            rel = child["name"][len(prefix):]
            c_ids = ", ".join(json.loads(child["allowed_identifiers_json"]))
            print(f"  {branch} {rel}  (access: {c_ids})")

    for item in files:
        if item["resource_id"] in grouped_ids:
            continue
        if any(item["name"].startswith(fn.rstrip("/") + "/") for fn in folder_names):
            continue
        ids = ", ".join(json.loads(item["allowed_identifiers_json"]))
        print(f"[file] {item['name']}  (access: {ids})")


def _define_new_access(conn: sqlite3.Connection, org: dict[str, Any]) -> str:
    ident = input("Enter new access identifier (position) name: ").strip()
    if not ident:
        raise ValueError("Identifier name cannot be empty")

    rows = conn.execute(
        "SELECT resource_id, name, kind, allowed_identifiers_json FROM resources WHERE org_id = ? ORDER BY created_at DESC",
        (org["org_id"],),
    ).fetchall()
    if rows:
        print("\nAvailable files & folders:")
        for idx, r in enumerate(rows, start=1):
            print(f"  {idx}. [{r['kind']}] {r['name']}")
        sel = input("Select numbers to grant access (e.g. 1,3 or 'all' or 'none'): ").strip().lower()
        chosen: list[sqlite3.Row] = []
        if sel == "all":
            chosen = list(rows)
        elif sel not in ("", "none"):
            for part in sel.split(","):
                part = part.strip()
                if part.isdigit():
                    i = int(part) - 1
                    if 0 <= i < len(rows):
                        chosen.append(rows[i])
        for r in chosen:
            cur_ids = json.loads(r["allowed_identifiers_json"])
            new_ids = list(dict.fromkeys([*cur_ids, ident]))
            conn.execute(
                "UPDATE resources SET allowed_identifiers_json = ? WHERE resource_id = ?",
                (json.dumps(new_ids), r["resource_id"]),
            )
        conn.commit()
        print(f"Granted '{ident}' access to {len(chosen)} item(s).")
    else:
        print(f"Defined identifier '{ident}' (no files/folders uploaded yet).")
    return ident


def cmd_add_people() -> None:
    with _connect() as conn:
        org = _get_active_org(conn)
        org_id = org["org_id"]
        user_rows = conn.execute(
            "SELECT identifier FROM users WHERE org_id = ? AND is_admin = 0",
            (org_id,),
        ).fetchall()
        res_rows = conn.execute(
            "SELECT allowed_identifiers_json FROM resources WHERE org_id = ?",
            (org_id,),
        ).fetchall()

        existing_positions = sorted(
            {r["identifier"] for r in user_rows}
            | {
                ident
                for res in res_rows
                for ident in json.loads(res["allowed_identifiers_json"])
                if ident != "admin"
            }
        )

        print(f"\nOrganization: {org['name']}")
        print("Select access identifier (position):")
        for idx, pos in enumerate(existing_positions, start=1):
            print(f"  {idx}. {pos}")
        define_idx = len(existing_positions) + 1
        print(f"  {define_idx}. Define new access")

        choice = input("Choice (number or position name): ").strip()
        if choice.isdigit() and int(choice) == define_idx:
            position = _define_new_access(conn, org)
        elif choice.isdigit() and 1 <= int(choice) <= len(existing_positions):
            position = existing_positions[int(choice) - 1]
        elif choice:
            position = choice
        else:
            print("Invalid selection.")
            raise SystemExit(1)

        device_ip = input("Enter device IP address: ").strip()
        if not check_device_reachable(device_ip):
            print(f"Device at {device_ip} is not reachable or does not exist. User not added.")
            raise SystemExit(1)

        count = conn.execute(
            "SELECT COUNT(*) AS c FROM users WHERE org_id = ? AND identifier = ?",
            (org_id, position),
        ).fetchone()["c"]
        numbered_name = f"{position} - {count + 1}"
        user_id = f"usr_{uuid.uuid4().hex[:12]}"
        conn.execute(
            """
            INSERT INTO users (user_id, org_id, username, identifier, role, is_admin, created_at)
            VALUES (?, ?, ?, ?, ?, 0, ?)
            """,
            (user_id, org_id, numbered_name, position, position, time.time()),
        )
        _enroll_device_row(conn, org_id, user_id, device_ip)
        conn.commit()

    _audit_logger(org).append_entry(org["admin_user_id"], "USER_ADD", user_id, "allow")
    print(f"Added {numbered_name} (position: {position}, device IP: {device_ip}, id: {user_id})")


def _get_or_create_pairwise_session(
    conn: sqlite3.Connection,
    org_id: str,
    user1_id: str,
    user2_id: str,
) -> tuple[str, bytes]:
    """Get or establish a dedicated ML-KEM-768 + X25519 pairwise E2EE session key for (user1, user2)."""
    ua, ub = sorted((user1_id, user2_id))
    pair_id = f"{org_id}:{ua}:{ub}"
    row = conn.execute(
        "SELECT session_id, session_key FROM pairwise_sessions WHERE pair_id = ?",
        (pair_id,),
    ).fetchone()
    if row:
        return row["session_id"], bytes(row["session_key"])

    dev_a = conn.execute(
        "SELECT u.identifier, d.* FROM users u JOIN devices d ON u.user_id = d.user_id AND d.status = 'ACTIVE' WHERE u.user_id = ? AND u.org_id = ? LIMIT 1",
        (ua, org_id),
    ).fetchone()
    dev_b = conn.execute(
        "SELECT u.identifier, d.* FROM users u JOIN devices d ON u.user_id = d.user_id AND d.status = 'ACTIVE' WHERE u.user_id = ? AND u.org_id = ? LIMIT 1",
        (ub, org_id),
    ).fetchone()
    if not dev_a or not dev_b:
        raise RuntimeError("Both peers must have active devices")

    kp_a = _load_keypair(dev_a)
    kp_b = _load_keypair(dev_b)
    pin_store = TrustedPeerStore()
    pin_store.register_peer(ua, kp_a, CipherSuite.SUITE_HYBRID)
    pin_store.register_peer(ub, kp_b, CipherSuite.SUITE_HYBRID)

    suite = CipherSuite.SUITE_HYBRID
    initiator = HandshakeInitiator(ua, dev_a["identifier"], kp_a, suite=suite, trusted_peers=pin_store)
    responder = HandshakeResponder(ub, dev_b["identifier"], kp_b, trusted_peers=pin_store)
    s_nonce, kem_ct, s_x_pk, s_sig, _ = responder.process_client_hello_and_reply(
        client_id=initiator.identity,
        client_role=initiator.role,
        suite=suite,
        client_nonce=initiator.client_nonce,
        client_kem_pk=initiator.ephemeral_key.kem_pk,
        client_x25519_pk=initiator.ephemeral_key.x25519_pk,
    )
    client_sig, keys_a = initiator.process_server_hello_and_authenticate(
        server_id=ub,
        server_role=dev_b["identifier"],
        server_identity_dsa_pk=kp_b.dsa_pk,
        server_identity_ed_pk=kp_b.ed_pk,
        server_nonce=s_nonce,
        kem_ciphertext=kem_ct,
        server_x25519_pk=s_x_pk,
        server_signature=s_sig,
    )
    responder.complete_handshake(
        client_identity_dsa_pk=kp_a.dsa_pk,
        client_identity_ed_pk=kp_a.ed_pk,
        client_signature=client_sig,
    )
    conn.execute(
        "INSERT INTO pairwise_sessions (pair_id, org_id, user_a, user_b, session_id, session_key, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (pair_id, org_id, ua, ub, keys_a.session_id, keys_a.send_key, time.time()),
    )
    conn.commit()
    return keys_a.session_id, keys_a.send_key


def _remote_chat() -> None:
    org_id = _active_org_file().read_text(encoding="utf-8").strip() if _active_org_file().exists() else ""
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

    ses = _remote_call("POST", "/api/chat/session", {"org_id": info["org_id"], "peer_id": peer["user_id"]})
    session_id = ses["session_id"]
    pair_key = base64.b64decode(ses["session_key_b64"].encode("ascii"))
    peer_fp = ses["peer_fingerprint"]

    print(f"\nEncrypted PQC chat started with {peer['username']} (real-time listening; type /quit to exit)\n")
    state = {"last_seen": 0.0, "seq": 0}
    print_lock = threading.Lock()
    stop_event = threading.Event()

    def _poll() -> None:
        try:
            msgs = _remote_call(
                "GET",
                f"/api/chat/messages?org_id={urllib.parse.quote(info['org_id'])}&peer_id={urllib.parse.quote(peer['user_id'])}&since={state['last_seen']}",
            )
            with print_lock:
                for m in msgs:
                    # Strictly verify sender/recipient belong ONLY to this (me <-> peer) pair
                    if {m["sender_user_id"], m["recipient_user_id"]} != {me["user_id"], peer["user_id"]}:
                        continue
                    pt = ChaCha20Poly1305(pair_key).decrypt(
                        base64.b64decode(m["nonce_b64"]),
                        base64.b64decode(m["ct_b64"]),
                        base64.b64decode(m["aad_b64"]),
                    ).decode("utf-8")
                    if m["sender_user_id"] == me["user_id"]:
                        print(f"\r{GREEN}[{me['username']}]: {pt}{RESET}")
                    else:
                        print(f"\r{WHITE}[{peer['username']}]: {pt}{RESET}")
                    state["last_seen"] = max(state["last_seen"], float(m["created_at"]))
        except Exception:
            pass

    def _listener() -> None:
        while not stop_event.is_set():
            _poll()
            stop_event.wait(0.4)

    _poll()
    listener_thread = threading.Thread(target=_listener, daemon=True)
    listener_thread.start()

    try:
        while True:
            text = input("> ").strip()
            if not text:
                continue
            if text == "/quit":
                break
            state["seq"] += 1
            msg_id = f"msg_{uuid.uuid4().hex[:12]}"
            nonce = secrets.token_bytes(12)
            aad = AssociatedData(
                protocol_version=1,
                suite_id=int(CipherSuite.SUITE_HYBRID),
                sender_id=me["user_id"],
                recipient_id=peer["user_id"],
                recipient_key_fingerprint=peer_fp,
                recipient_epoch=1,
                session_id=session_id,
                sequence_number=state["seq"],
                message_id=msg_id,
                chunk_index=0,
                chunk_count=1,
                total_length=len(text.encode("utf-8")),
            ).serialize()
            ct = ChaCha20Poly1305(pair_key).encrypt(nonce, text.encode("utf-8"), aad)
            _remote_call(
                "POST",
                "/api/chat/send",
                {
                    "org_id": info["org_id"],
                    "peer_id": peer["user_id"],
                    "message_id": msg_id,
                    "session_id": session_id,
                    "seq_no": state["seq"],
                    "nonce_b64": base64.b64encode(nonce).decode("ascii"),
                    "ct_b64": base64.b64encode(ct).decode("ascii"),
                    "aad_b64": base64.b64encode(aad).decode("ascii"),
                },
            )
            _poll()
    finally:
        stop_event.set()


def cmd_chat() -> None:
    if _get_server_url():
        _remote_chat()
        return
    with _connect() as conn:
        org = _get_active_org(conn)
        users = conn.execute(
            """
            SELECT u.user_id, u.username, u.identifier, u.is_admin, d.*
            FROM users u
            JOIN devices d ON u.user_id = d.user_id AND d.status = 'ACTIVE'
            WHERE u.org_id = ?
            ORDER BY u.created_at ASC
            """,
            (org["org_id"],),
        ).fetchall()
        cur_user = _current_user_for_org(conn, org)

    if len(users) < 2:
        print("Need at least 2 members to chat. Add people first with: gt -add-people")
        raise SystemExit(1)

    if cur_user is not None:
        me = cur_user
    else:
        print(f"\nMembers in {org['name']}:")
        for idx, u in enumerate(users, start=1):
            print(f"  {idx}. {u['username']} [{u['identifier']}]")
        me_idx = int(input("You are (number): ").strip()) - 1
        if not (0 <= me_idx < len(users)):
            print("Invalid member selection.")
            raise SystemExit(1)
        me = users[me_idx]

    others = [u for u in users if u["user_id"] != me["user_id"]]
    if not others:
        print("No other members available to chat with.")
        raise SystemExit(1)

    print(f"\n[{org['name']}] Logged in as: {me['username']} [{me['identifier']}]")
    print("Select member to chat with:")
    for idx, u in enumerate(others, start=1):
        print(f"  {idx}. {u['username']} [{u['identifier']}]")

    peer_idx = int(input("Chat with (number): ").strip()) - 1
    if not (0 <= peer_idx < len(others)):
        print("Invalid member selection.")
        raise SystemExit(1)

    peer = others[peer_idx]

    me_kp = _load_keypair(me)
    peer_kp = _load_keypair(peer)
    pin_store = TrustedPeerStore()
    pin_store.register_peer(me["user_id"], me_kp, CipherSuite.SUITE_HYBRID)
    pin_store.register_peer(peer["user_id"], peer_kp, CipherSuite.SUITE_HYBRID)

    suite = CipherSuite.SUITE_HYBRID
    initiator = HandshakeInitiator(me["user_id"], me["identifier"], me_kp, suite=suite, trusted_peers=pin_store)
    responder = HandshakeResponder(peer["user_id"], peer["identifier"], peer_kp, trusted_peers=pin_store)
    s_nonce, kem_ct, s_x_pk, s_sig, _ = responder.process_client_hello_and_reply(
        client_id=initiator.identity,
        client_role=initiator.role,
        suite=suite,
        client_nonce=initiator.client_nonce,
        client_kem_pk=initiator.ephemeral_key.kem_pk,
        client_x25519_pk=initiator.ephemeral_key.x25519_pk,
    )
    client_sig, me_keys = initiator.process_server_hello_and_authenticate(
        server_id=peer["user_id"],
        server_role=peer["identifier"],
        server_identity_dsa_pk=peer_kp.dsa_pk,
        server_identity_ed_pk=peer_kp.ed_pk,
        server_nonce=s_nonce,
        kem_ciphertext=kem_ct,
        server_x25519_pk=s_x_pk,
        server_signature=s_sig,
    )
    responder.complete_handshake(
        client_identity_dsa_pk=me_kp.dsa_pk,
        client_identity_ed_pk=me_kp.ed_pk,
        client_signature=client_sig,
    )

    session_id = me_keys.session_id
    logger = _audit_logger(org)
    chat_key = bytes(org["vault_key"])
    print(f"\nEncrypted PQC chat started with {peer['username']} (type /refresh to read, /quit to exit)\n")

    def _print_history(since_ts: float) -> float:
        with _connect() as conn:
            msgs = conn.execute(
                """
                SELECT * FROM chat_messages
                WHERE org_id = ?
                  AND ((sender_user_id = ? AND recipient_user_id = ?)
                    OR (sender_user_id = ? AND recipient_user_id = ?))
                  AND created_at > ?
                ORDER BY created_at ASC
                """,
                (org["org_id"], me["user_id"], peer["user_id"], peer["user_id"], me["user_id"], since_ts),
            ).fetchall()
        last_ts = since_ts
        for m in msgs:
            pt = ChaCha20Poly1305(chat_key).decrypt(bytes(m["nonce"]), bytes(m["ciphertext"]), bytes(m["aad"])).decode("utf-8")
            if m["sender_user_id"] == me["user_id"]:
                print(f"{GREEN}[{me['username']}]: {pt}{RESET}")
            else:
                print(f"{WHITE}[{peer['username']}]: {pt}{RESET}")
            last_ts = max(last_ts, float(m["created_at"]))
        return last_ts

    last_seen = _print_history(0.0)
    seq = 0
    while True:
        text = input("> ").strip()
        if not text:
            continue
        if text == "/quit":
            break
        if text == "/refresh":
            last_seen = _print_history(last_seen)
            continue
        seq += 1
        msg_id = f"msg_{uuid.uuid4().hex[:12]}"
        nonce = secrets.token_bytes(12)
        aad = AssociatedData(
            protocol_version=1,
            suite_id=int(CipherSuite.SUITE_HYBRID),
            sender_id=me["user_id"],
            recipient_id=peer["user_id"],
            recipient_key_fingerprint=peer["fingerprint"],
            recipient_epoch=1,
            session_id=session_id,
            sequence_number=seq,
            message_id=msg_id,
            chunk_index=0,
            chunk_count=1,
            total_length=len(text.encode("utf-8")),
        ).serialize()

        ct = ChaCha20Poly1305(chat_key).encrypt(nonce, text.encode("utf-8"), aad)
        now = time.time()
        with _connect() as conn:
            conn.execute(
                """
                INSERT INTO chat_messages (
                    message_id, org_id, sender_user_id, recipient_user_id,
                    session_id, seq_no, nonce, ciphertext, aad, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (msg_id, org["org_id"], me["user_id"], peer["user_id"], session_id, seq, nonce, ct, aad, now),
            )
            conn.commit()
        last_seen = _print_history(last_seen)
        logger.append_entry(me["user_id"], "CHAT_SEND", peer["user_id"], "allow")


def cmd_people() -> None:
    """List members grouped by their identifier/position section along with their org and IP."""
    if _get_server_url():
        org_id = _active_org_file().read_text(encoding="utf-8").strip() if _active_org_file().exists() else ""
        res = _remote_call("GET", f"/api/people?org_id={urllib.parse.quote(org_id)}")
        if res.get("header"):
            print(res["header"])
        rows = res.get("members", [])
        org_name = res.get("org_name", "")
    else:
        with _connect() as conn:
            org = _get_active_org(conn)
            if _is_admin_ip(conn, org):
                print(f"({org['name']})")
            org_name = org["name"]
            db_rows = conn.execute(
                """
                SELECT u.username, u.identifier, u.is_admin, d.device_ip, d.status
                FROM users u
                JOIN devices d ON u.user_id = d.user_id
                WHERE u.org_id = ?
                ORDER BY u.is_admin DESC, u.identifier ASC, u.created_at ASC
                """,
                (org["org_id"],),
            ).fetchall()
            rows = [dict(r) for r in db_rows]

    if not rows:
        print("No members found.")
        return
    grouped: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        grouped.setdefault(r["identifier"], []).append(r)

    for ident, members in grouped.items():
        print(f"[{ident}] ({org_name})")
        for m in members:
            print(f"  - {m['username']} -> IP: {m['device_ip']} ({m['status']})")


def cmd_orgs() -> None:
    """List all organizations this device IP belongs to."""
    active_id = _active_org_file().read_text(encoding="utf-8").strip() if _active_org_file().exists() else ""
    if _get_server_url():
        matched = _remote_call("GET", "/api/orgs")
    else:
        ips = _current_machine_ips()
        with _connect() as conn:
            rows = conn.execute(
                """
                SELECT o.org_id, o.name, u.username, u.identifier, u.is_admin, d.device_ip
                FROM organizations o
                JOIN users u ON o.org_id = u.org_id
                JOIN devices d ON u.user_id = d.user_id AND d.status = 'ACTIVE'
                ORDER BY o.created_at DESC
                """
            ).fetchall()
        matched = [dict(r) for r in rows if r["device_ip"] in ips]

    if not matched:
        print("This device is not added to any organization.")
        return
    for r in matched:
        mark = "* " if r["org_id"] == active_id else "  "
        print(f"{mark}{r['name']} -> {r['username']} [{r['identifier']}] (IP: {r['device_ip']})")


def cmd_connect(server_target: str) -> None:
    """Connect this user device to the admin Graviton server IP."""
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


def _make_server_handler(db_path: Path | None = None):
    srv_db = db_path or _db_path()

    class GravitonHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def _send_json(self, code: int, obj: Any) -> None:
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _client_ip(self) -> str:
            return self.headers.get("X-Client-IP") or self.client_address[0]

        def _read_json(self) -> dict[str, Any]:
            n = int(self.headers.get("Content-Length", "0"))
            return json.loads(self.rfile.read(n).decode("utf-8")) if n > 0 else {}

        def _resolve_org(self, conn: sqlite3.Connection, org_id: str) -> dict[str, Any] | None:
            if org_id:
                r = conn.execute("SELECT * FROM organizations WHERE org_id = ?", (org_id,)).fetchone()
                if r:
                    return dict(r)
            r = conn.execute("SELECT * FROM organizations ORDER BY created_at DESC LIMIT 1").fetchone()
            return dict(r) if r else None

        def _resolve_user_by_ip(self, conn: sqlite3.Connection, org_id: str, ip: str) -> sqlite3.Row | None:
            return conn.execute(
                """
                SELECT u.*, d.device_ip, d.fingerprint
                FROM users u
                JOIN devices d ON u.user_id = d.user_id AND d.status = 'ACTIVE'
                WHERE u.org_id = ? AND d.device_ip = ?
                ORDER BY u.created_at ASC LIMIT 1
                """,
                (org_id, ip),
            ).fetchone()

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            ip = self._client_ip()
            if parsed.path == "/api/health":
                self._send_json(200, {"status": "ok"})
                return
            with _connect(srv_db) as conn:
                if parsed.path == "/api/orgs":
                    rows = conn.execute(
                        """
                        SELECT o.org_id, o.name, u.username, u.identifier, u.is_admin, d.device_ip
                        FROM organizations o
                        JOIN users u ON o.org_id = u.org_id
                        JOIN devices d ON u.user_id = d.user_id AND d.status = 'ACTIVE'
                        WHERE d.device_ip = ?
                        ORDER BY o.created_at DESC
                        """,
                        (ip,),
                    ).fetchall()
                    self._send_json(200, [dict(r) for r in rows])
                    return
                org = self._resolve_org(conn, (qs.get("org_id") or [""])[0])
                if not org:
                    self._send_json(404, {"error": "No organization"})
                    return
                if parsed.path == "/api/ls":
                    rows = conn.execute(
                        "SELECT resource_id, name, kind, allowed_identifiers_json FROM resources WHERE org_id = ? ORDER BY created_at DESC",
                        (org["org_id"],),
                    ).fetchall()
                    self._send_json(200, {"header": f"({org['name']})", "items": [dict(r) for r in rows]})
                    return
                if parsed.path == "/api/people":
                    rows = conn.execute(
                        """
                        SELECT u.username, u.identifier, u.is_admin, d.device_ip, d.status
                        FROM users u JOIN devices d ON u.user_id = d.user_id
                        WHERE u.org_id = ?
                        ORDER BY u.is_admin DESC, u.identifier ASC, u.created_at ASC
                        """,
                        (org["org_id"],),
                    ).fetchall()
                    self._send_json(200, {"header": f"({org['name']})", "org_name": org["name"], "members": [dict(r) for r in rows]})
                    return
                if parsed.path == "/api/chat/peers":
                    me = self._resolve_user_by_ip(conn, org["org_id"], ip)
                    if not me:
                        self._send_json(403, {"error": f"Device IP {ip} not registered in {org['name']}"})
                        return
                    others = conn.execute(
                        "SELECT user_id, username, identifier FROM users WHERE org_id = ? AND user_id != ? ORDER BY created_at ASC",
                        (org["org_id"], me["user_id"]),
                    ).fetchall()
                    self._send_json(
                        200,
                        {
                            "org_id": org["org_id"],
                            "org_name": org["name"],
                            "me": {"user_id": me["user_id"], "username": me["username"], "identifier": me["identifier"]},
                            "others": [dict(o) for o in others],
                        },
                    )
                    return
                if parsed.path == "/api/chat/messages":
                    me = self._resolve_user_by_ip(conn, org["org_id"], ip)
                    if not me:
                        self._send_json(403, {"error": "Unauthorized"})
                        return
                    peer_id = (qs.get("peer_id") or [""])[0]
                    since = float((qs.get("since") or ["0"])[0])
                    # Strictly return ONLY messages between me and peer_id
                    msgs = conn.execute(
                        """
                        SELECT message_id, sender_user_id, recipient_user_id, nonce, ciphertext, aad, created_at
                        FROM chat_messages
                        WHERE org_id = ?
                          AND ((sender_user_id = ? AND recipient_user_id = ?)
                            OR (sender_user_id = ? AND recipient_user_id = ?))
                          AND created_at > ?
                        ORDER BY created_at ASC
                        """,
                        (org["org_id"], me["user_id"], peer_id, peer_id, me["user_id"], since),
                    ).fetchall()
                    out = [
                        {
                            "message_id": m["message_id"],
                            "sender_user_id": m["sender_user_id"],
                            "recipient_user_id": m["recipient_user_id"],
                            "nonce_b64": base64.b64encode(bytes(m["nonce"])).decode("ascii"),
                            "ct_b64": base64.b64encode(bytes(m["ciphertext"])).decode("ascii"),
                            "aad_b64": base64.b64encode(bytes(m["aad"])).decode("ascii"),
                            "created_at": m["created_at"],
                        }
                        for m in msgs
                    ]
                    self._send_json(200, out)
                    return
            self._send_json(404, {"error": "Not found"})

        def do_POST(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            body = self._read_json()
            ip = self._client_ip()
            with _connect(srv_db) as conn:
                if parsed.path == "/api/use":
                    cname = str(body.get("company_name", "")).strip()
                    row = conn.execute(
                        "SELECT * FROM organizations WHERE LOWER(name) = LOWER(?) ORDER BY created_at DESC LIMIT 1",
                        (cname,),
                    ).fetchone()
                    if not row:
                        self._send_json(404, {"error": f"Organization not found: {cname}"})
                        return
                    org = dict(row)
                    usr = self._resolve_user_by_ip(conn, org["org_id"], ip)
                    if not usr:
                        self._send_json(403, {"error": f"Device IP {ip} is not registered in {org['name']}"})
                        return
                    label = f"({org['name']})" if usr["is_admin"] else f"({org['name']}:{usr['identifier']})"
                    self._send_json(200, {"org_id": org["org_id"], "label": label})
                    return
                if parsed.path == "/api/chat/session":
                    org = self._resolve_org(conn, str(body.get("org_id", "")))
                    if not org:
                        self._send_json(404, {"error": "Org not found"})
                        return
                    me = self._resolve_user_by_ip(conn, org["org_id"], ip)
                    if not me:
                        self._send_json(403, {"error": "Unauthorized"})
                        return
                    peer_id = str(body.get("peer_id", ""))
                    peer_dev = conn.execute(
                        "SELECT fingerprint FROM devices WHERE org_id = ? AND user_id = ? AND status = 'ACTIVE' LIMIT 1",
                        (org["org_id"], peer_id),
                    ).fetchone()
                    if not peer_dev:
                        self._send_json(404, {"error": "Peer not found"})
                        return
                    ses_id, ses_key = _get_or_create_pairwise_session(conn, org["org_id"], me["user_id"], peer_id)
                    self._send_json(
                        200,
                        {
                            "session_id": ses_id,
                            "session_key_b64": base64.b64encode(ses_key).decode("ascii"),
                            "peer_fingerprint": peer_dev["fingerprint"],
                        },
                    )
                    return
                if parsed.path == "/api/chat/send":
                    org = self._resolve_org(conn, str(body.get("org_id", "")))
                    if not org:
                        self._send_json(404, {"error": "Org not found"})
                        return
                    me = self._resolve_user_by_ip(conn, org["org_id"], ip)
                    if not me:
                        self._send_json(403, {"error": "Unauthorized"})
                        return
                    peer_id = str(body.get("peer_id", ""))
                    msg_id = str(body.get("message_id") or f"msg_{uuid.uuid4().hex[:12]}")
                    ses_id = str(body.get("session_id") or "")
                    seq_no = int(body.get("seq_no") or 1)
                    nonce = base64.b64decode(str(body["nonce_b64"]))
                    ct = base64.b64decode(str(body["ct_b64"]))
                    aad = base64.b64decode(str(body["aad_b64"]))
                    conn.execute(
                        """
                        INSERT INTO chat_messages (
                            message_id, org_id, sender_user_id, recipient_user_id,
                            session_id, seq_no, nonce, ciphertext, aad, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (msg_id, org["org_id"], me["user_id"], peer_id, ses_id, seq_no, nonce, ct, aad, time.time()),
                    )
                    conn.commit()
                    _audit_logger(org).append_entry(me["user_id"], "CHAT_SEND", peer_id, "allow")
                    self._send_json(200, {"sent": True, "message_id": msg_id})
                    return
            self._send_json(404, {"error": "Not found"})

    return GravitonHandler


def cmd_serve(port: int = 8765) -> None:
    """Start Graviton network server for multi-container/device clients."""
    srv = ThreadingHTTPServer(("0.0.0.0", port), _make_server_handler())
    print(f"Graviton server listening on {_primary_machine_ip()}:{port}")
    srv.serve_forever()


def cmd_prompt() -> None:
    f = _active_org_file()
    if not f.exists():
        return
    org_id = f.read_text(encoding="utf-8").strip()
    if not org_id:
        return
    p = _db_path()
    if not p.exists():
        return
    conn = sqlite3.connect(str(p))
    try:
        org = conn.execute("SELECT name, admin_user_id FROM organizations WHERE org_id = ?", (org_id,)).fetchone()
        if not org:
            return
        dev = conn.execute(
            "SELECT device_ip FROM devices WHERE org_id = ? AND user_id = ? AND status = 'ACTIVE' LIMIT 1",
            (org_id, org[1]),
        ).fetchone()
        if dev and dev[0] in _current_machine_ips():
            sys.stdout.write(f" ({org[0]})")
    finally:
        conn.close()


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
