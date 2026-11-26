"""SQLite WAL-backed persistence layer for Graviton."""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from typing import Iterator


SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS organizations (
    org_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    admin_user_id TEXT NOT NULL,
    authority_sign_pk BLOB NOT NULL,
    authority_sign_sk BLOB NOT NULL,
    backup_wrap_key BLOB NOT NULL,
    ticket_key BLOB NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    identifier TEXT NOT NULL,
    role TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    quarantined INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    UNIQUE(org_id, username)
);

CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    sign_pk BLOB NOT NULL,
    sign_sk BLOB NOT NULL,
    kem_pk BLOB NOT NULL,
    kem_sk BLOB NOT NULL,
    x25519_pk BLOB NOT NULL,
    x25519_sk BLOB NOT NULL,
    key_version INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'REVOKED')),
    enrolled_at REAL NOT NULL,
    revoked_at REAL
);

CREATE TABLE IF NOT EXISTS key_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    symmetric_key BLOB NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('PREPARED', 'ACTIVE', 'GRACE', 'RETIRED', 'ROLLED_BACK')),
    cutoff_at REAL,
    grace_until REAL,
    created_at REAL NOT NULL,
    UNIQUE(org_id, version)
);

CREATE TABLE IF NOT EXISTS rotation_wal (
    tx_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    from_version INTEGER NOT NULL,
    to_version INTEGER NOT NULL,
    phase TEXT NOT NULL CHECK(phase IN ('PREPARE', 'COMMITTED', 'ROLLED_BACK')),
    grace_seconds REAL NOT NULL,
    payload_json TEXT NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS node_states (
    node_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    service_name TEXT NOT NULL,
    active_key_version INTEGER NOT NULL,
    revoked_devices_json TEXT NOT NULL,
    revocation_epoch INTEGER NOT NULL DEFAULT 0,
    last_synced_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS resources (
    resource_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    owner_user_id TEXT NOT NULL,
    allowed_identifiers_json TEXT NOT NULL,
    allowed_users_json TEXT NOT NULL,
    key_version INTEGER NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    aad_json TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS chat_messages (
    message_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    sender_user_id TEXT NOT NULL,
    sender_device_id TEXT NOT NULL,
    recipient_user_id TEXT NOT NULL,
    recipient_device_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    seq_no INTEGER NOT NULL,
    key_version INTEGER NOT NULL,
    kem_ct BLOB NOT NULL,
    init_x25519_pk BLOB NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    aad_json TEXT NOT NULL,
    signature BLOB NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    initiator_user_id TEXT NOT NULL,
    initiator_device_id TEXT NOT NULL,
    initiator_pk_fp TEXT NOT NULL,
    peer_user_id TEXT NOT NULL,
    peer_device_id TEXT NOT NULL,
    peer_pk_fp TEXT NOT NULL,
    session_key BLOB NOT NULL,
    next_seq INTEGER NOT NULL DEFAULT 1,
    seen_seqs_json TEXT NOT NULL DEFAULT '[]',
    resumption_ticket BLOB,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE NOT NULL,
    org_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    received_at REAL NOT NULL,
    actor_id TEXT NOT NULL,
    service TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    context_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    signature BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    created_at REAL NOT NULL,
    severity TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    identity TEXT NOT NULL,
    services_json TEXT NOT NULL,
    events_json TEXT NOT NULL,
    explanation TEXT NOT NULL,
    uncertain_order INTEGER NOT NULL DEFAULT 0,
    auto_response TEXT
);
"""


class Database:
    """Thread-safe SQLite WAL database wrapper."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        parent = os.path.dirname(os.path.abspath(db_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_schema(self) -> None:
        with self.tx() as conn:
            conn.executescript(SCHEMA_SQL)
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(resources)").fetchall()}
            if "kind" not in cols:
                conn.execute("ALTER TABLE resources ADD COLUMN kind TEXT NOT NULL DEFAULT 'file'")

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()
