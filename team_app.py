"""Track 4 adapter dispatch implementation using Python stdlib + pqcrypto.

Persists state across process invocations in TRACK4_STATE_DIR (or OS temp dir)
so it runs cleanly in read-only offline judging containers.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from pqcrypto.kem import ml_kem_768


def _state_db_path() -> Path:
    base = os.environ.get("TRACK4_STATE_DIR") or tempfile.gettempdir()
    p = Path(base) / "graviton_track4_adapter.db"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_state_db_path()), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=FULL;")
    return conn


def _init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS adapter_meta (
            k TEXT PRIMARY KEY,
            v TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS adapter_assets (
            asset_id TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL,
            body_enc_b64 TEXT NOT NULL,
            body_mac_hex TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS adapter_disabled (
            actor_id TEXT PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS adapter_audit (
            request_id TEXT PRIMARY KEY,
            actor_id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            decision TEXT NOT NULL
        );
        """
    )


def _derive_keys(key_material: str) -> tuple[bytes, bytes]:
    enc_key = hashlib.sha256(b"enc|" + key_material.encode("utf-8")).digest()
    mac_key = hashlib.sha256(b"mac|" + key_material.encode("utf-8")).digest()
    return enc_key, mac_key


def _xor_stream(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """Deterministic keystream using SHA-256 counter blocks (stdlib-only for offline judging container)."""
    out = bytearray(len(data))
    counter = 0
    pos = 0
    while pos < len(data):
        block = hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
        take = min(len(block), len(data) - pos)
        for i in range(take):
            out[pos + i] = data[pos + i] ^ block[i]
        pos += take
        counter += 1
    return bytes(out)


def _seal_body(key_material: str, asset_id: str, body: str) -> tuple[str, str]:
    enc_key, mac_key = _derive_keys(key_material)
    nonce = os.urandom(16)
    pt = body.encode("utf-8")
    ct = _xor_stream(enc_key, nonce, pt)
    blob = nonce + ct
    mac = hmac.new(mac_key, asset_id.encode("utf-8") + b"|" + blob, hashlib.sha256).hexdigest()
    return base64.b64encode(blob).decode("ascii"), mac


def _open_body(key_material: str, asset_id: str, blob_b64: str, mac_hex: str) -> str:
    enc_key, mac_key = _derive_keys(key_material)
    blob = base64.b64decode(blob_b64.encode("ascii"))
    expected_mac = hmac.new(mac_key, asset_id.encode("utf-8") + b"|" + blob, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_mac, mac_hex):
        raise ValueError("Stored asset integrity check failed")
    nonce, ct = blob[:16], blob[16:]
    return _xor_stream(enc_key, nonce, ct).decode("utf-8")


def _handle_setup(request: dict[str, Any]) -> dict[str, Any]:
    owners = request.get("owners") or {}
    contents = request.get("contents") or {}
    disabled = request.get("disabled") or []
    key_material = str(request.get("key_material") or "default-key-material")

    db_path = _state_db_path()
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(db_path) + suffix)
        if p.exists():
            p.unlink()

    with _connect() as conn:
        _init_db(conn)
        conn.execute("INSERT INTO adapter_meta (k, v) VALUES ('key_material', ?)", (key_material,))
        for asset_id, owner_id in owners.items():
            body = str(contents.get(asset_id, ""))
            blob_b64, mac_hex = _seal_body(key_material, str(asset_id), body)
            conn.execute(
                "INSERT INTO adapter_assets (asset_id, owner_id, body_enc_b64, body_mac_hex) VALUES (?, ?, ?, ?)",
                (str(asset_id), str(owner_id), blob_b64, mac_hex),
            )
        for actor_id in disabled:
            conn.execute("INSERT OR IGNORE INTO adapter_disabled (actor_id) VALUES (?)", (str(actor_id),))
        conn.commit()
    return {"ready": True}


def _authorize_and_fetch(conn: sqlite3.Connection, actor: str, asset: str) -> tuple[bool, str | None]:
    is_disabled = conn.execute(
        "SELECT 1 FROM adapter_disabled WHERE actor_id = ?",
        (actor,),
    ).fetchone()
    if is_disabled:
        return False, None

    row = conn.execute(
        "SELECT owner_id, body_enc_b64, body_mac_hex FROM adapter_assets WHERE asset_id = ?",
        (asset,),
    ).fetchone()
    if not row or row["owner_id"] != actor:
        return False, None

    km_row = conn.execute("SELECT v FROM adapter_meta WHERE k = 'key_material'").fetchone()
    if not km_row:
        return False, None
    body = _open_body(km_row["v"], asset, row["body_enc_b64"], row["body_mac_hex"])
    return True, body


def _handle_read(request: dict[str, Any]) -> dict[str, Any]:
    actor = str(request["actor"])
    asset = str(request["asset"])
    request_id = str(request["request_id"])

    with _connect() as conn:
        _init_db(conn)
        allowed, body = _authorize_and_fetch(conn, actor, asset)
        decision = "allow" if allowed else "deny"
        conn.execute(
            "INSERT OR REPLACE INTO adapter_audit (request_id, actor_id, asset_id, decision) VALUES (?, ?, ?, ?)",
            (request_id, actor, asset, decision),
        )
        conn.commit()

    if allowed and body is not None:
        return {"decision": "allow", "body": body}
    return {"decision": "deny"}


def _handle_revoke(request: dict[str, Any]) -> dict[str, Any]:
    actor = str(request["actor"])
    with _connect() as conn:
        _init_db(conn)
        conn.execute("INSERT OR IGNORE INTO adapter_disabled (actor_id) VALUES (?)", (actor,))
        conn.commit()
    return {"revoked": True, "actor": actor}


def _handle_audit(request: dict[str, Any]) -> dict[str, Any]:
    request_id = str(request["request_id"])
    with _connect() as conn:
        _init_db(conn)
        row = conn.execute(
            "SELECT request_id, decision FROM adapter_audit WHERE request_id = ?",
            (request_id,),
        ).fetchone()
    if not row:
        return {"request_id": request_id, "decision": "deny"}
    return {"request_id": row["request_id"], "decision": row["decision"]}


def _handle_protected_read(request: dict[str, Any]) -> dict[str, Any]:
    actor = str(request["actor"])
    asset = str(request["asset"])
    challenge = str(request["challenge"])
    public_key_b64 = str(request["public_key"])
    request_id = request.get("request_id")

    with _connect() as conn:
        _init_db(conn)
        allowed, body = _authorize_and_fetch(conn, actor, asset)
        if request_id is not None:
            conn.execute(
                "INSERT OR REPLACE INTO adapter_audit (request_id, actor_id, asset_id, decision) VALUES (?, ?, ?, ?)",
                (str(request_id), actor, asset, "allow" if allowed else "deny"),
            )
            conn.commit()

    if not allowed or body is None:
        return {"decision": "deny"}

    pk_bytes = base64.b64decode(public_key_b64.encode("ascii"), validate=True)
    ct, shared_secret = ml_kem_768.encaps(pk_bytes)
    proof = hmac.new(
        bytes(shared_secret),
        (challenge + body).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {
        "ciphertext": base64.b64encode(bytes(ct)).decode("ascii"),
        "proof": proof,
    }


def dispatch(request: dict[str, Any]) -> dict[str, Any]:
    """Dispatch Track 4 adapter operations."""
    op = request.get("op")
    if op == "setup":
        return _handle_setup(request)
    if op == "read":
        return _handle_read(request)
    if op == "revoke":
        return _handle_revoke(request)
    if op == "audit":
        return _handle_audit(request)
    if op == "protected_read":
        return _handle_protected_read(request)
    raise ValueError(f"Unsupported op: {op}")
