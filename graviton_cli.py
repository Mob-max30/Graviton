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
import time
import uuid
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
"""


def _data_dir() -> Path:
    d = Path(os.environ.get("GRAVITON_DATA_DIR", Path.cwd() / "data"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _db_path() -> Path:
    return Path(os.environ.get("GRAVITON_DB_PATH", str(_data_dir() / "graviton.db")))


def _connect() -> sqlite3.Connection:
    p = _db_path()
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
        _enroll_device_row(conn, org_id, admin_user_id, "127.0.0.1")
        conn.commit()
        org = dict(conn.execute("SELECT * FROM organizations WHERE org_id = ?", (org_id,)).fetchone())

    _set_active_org(org_id)
    vault_dir = _org_vault_dir(company_name, org_id)
    _audit_logger(org).append_entry(admin_user_id, "ORG_REGISTER", org_id, "allow")
    print(f"Registered organization: {company_name} ({org_id})")
    print(f"Admin: {uname} [admin]")
    print(f"Vault: {vault_dir}")


def cmd_use(company_name: str) -> None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM organizations WHERE LOWER(name) = LOWER(?) ORDER BY created_at DESC LIMIT 1",
            (company_name.strip(),),
        ).fetchone()
        if not row:
            print(f"Organization not found: {company_name}")
            raise SystemExit(1)
        org = dict(row)
        if not _is_admin_ip(conn, org):
            print(f"Access denied: current device IP is not the admin IP for {org['name']}")
            raise SystemExit(1)
    _set_active_org(org["org_id"])
    print(f"({org['name']})")


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
    with _connect() as conn:
        org = _get_active_org(conn)
        if _is_admin_ip(conn, org):
            print(f"({org['name']})")
        rows = conn.execute(
            "SELECT * FROM resources WHERE org_id = ? ORDER BY created_at DESC",
            (org["org_id"],),
        ).fetchall()

    if not rows:
        print("No files or folders added yet.")
        return

    items = [dict(r) for r in rows]
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


def cmd_chat() -> None:
    with _connect() as conn:
        org = _get_active_org(conn)
        users = conn.execute(
            """
            SELECT u.user_id, u.username, u.identifier, d.*
            FROM users u
            JOIN devices d ON u.user_id = d.user_id AND d.status = 'ACTIVE'
            WHERE u.org_id = ?
            ORDER BY u.created_at ASC
            """,
            (org["org_id"],),
        ).fetchall()

    if len(users) < 2:
        print("Need at least 2 members to chat. Add people first with: gt -add-people")
        raise SystemExit(1)

    print(f"\nMembers in {org['name']}:")
    for idx, u in enumerate(users, start=1):
        print(f"  {idx}. {u['username']} [{u['identifier']}]")

    me_idx = int(input("You are (number): ").strip()) - 1
    peer_idx = int(input("Chat with (number): ").strip()) - 1
    if not (0 <= me_idx < len(users)) or not (0 <= peer_idx < len(users)) or me_idx == peer_idx:
        print("Invalid member selection.")
        raise SystemExit(1)

    me = users[me_idx]
    peer = users[peer_idx]

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
    peer_keys = responder.complete_handshake(
        client_identity_dsa_pk=me_kp.dsa_pk,
        client_identity_ed_pk=me_kp.ed_pk,
        client_signature=client_sig,
    )

    session_id = me_keys.session_id
    logger = _audit_logger(org)
    print(f"\nEncrypted PQC chat started with {peer['username']} (type /quit to exit)\n")

    seq = 0
    while True:
        text = input("> ").strip()
        if not text:
            continue
        if text == "/quit":
            break
        seq += 1
        nonce = seq.to_bytes(12, "big")
        aad = AssociatedData(
            protocol_version=1,
            suite_id=int(CipherSuite.SUITE_HYBRID),
            sender_id=me["user_id"],
            recipient_id=peer["user_id"],
            recipient_key_fingerprint=peer["fingerprint"],
            recipient_epoch=1,
            session_id=session_id,
            sequence_number=seq,
            message_id=f"msg_{seq}",
            chunk_index=0,
            chunk_count=1,
            total_length=len(text.encode("utf-8")),
        ).serialize()

        ct = ChaCha20Poly1305(me_keys.send_key).encrypt(nonce, text.encode("utf-8"), aad)
        print(f"{GREEN}[{me['username']}]: {text}{RESET}")
        pt = ChaCha20Poly1305(peer_keys.recv_key).decrypt(nonce, ct, aad).decode("utf-8")
        print(f"{WHITE}[{peer['username']} received]: {pt}{RESET}")
        logger.append_entry(me["user_id"], "CHAT_SEND", peer["user_id"], "allow")


def cmd_people() -> None:
    """List all members, their positions, and their connected device IPs."""
    with _connect() as conn:
        org = _get_active_org(conn)
        if _is_admin_ip(conn, org):
            print(f"({org['name']})")
        rows = conn.execute(
            """
            SELECT u.username, u.identifier, u.is_admin, d.device_ip, d.status
            FROM users u
            JOIN devices d ON u.user_id = d.user_id
            WHERE u.org_id = ?
            ORDER BY u.created_at ASC
            """,
            (org["org_id"],),
        ).fetchall()

    if not rows:
        print("No members found.")
        return
    for r in rows:
        role_tag = " [admin]" if r["is_admin"] else f" [{r['identifier']}]"
        print(f"{r['username']}{role_tag} -> IP: {r['device_ip']} ({r['status']})")


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
        print("  gt use <company-name>")
        print("  gt ls [folder-name]")
        print("  gt people")
        print("  gt -add <file-or-folder-path>")
        print("  gt -add-people")
        print("  gt -chat")
        return 1

    flag = args[0]
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
