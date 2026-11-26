"""Graviton security engine for the Track 4 adapter contract (Phase 4 wired)."""
from __future__ import annotations

import base64
import binascii
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import tempfile

from pqcrypto.kem import ml_kem_768

from graviton.crypto.signatures import generate_signing_keypair
from graviton.feed.author import FeedAuthor
from graviton.feed.entries import compute_entry_hash
from graviton.nodes.node import Node, ReasonCode
from graviton.storage import (
    atomic_write_text as _atomic_write_text,
    ensure_state_dir as _ensure_state_dir,
    fsync_dir as _fsync_dir,
    state_lock as _state_lock,
)

STATE_VERSION = 2
POINTER_FILENAME = "current_generation.json"
ADAPTER_STATE_FILENAME = "adapter_state.json"
ADMIN_KEY_FILENAME = "admin_key.json"
AUDIT_LOG_FILENAME = "audit_log.jsonl"
NODE_SUBDIR = "node"


def get_state_dir() -> Path:
    """Return the writable state directory from TRACK4_STATE_DIR or OS temp."""
    env_dir = os.environ.get("TRACK4_STATE_DIR")
    if env_dir:
        return Path(env_dir)
    return Path(tempfile.gettempdir()) / "graviton_state"


def _append_audit_record(gen_dir: Path, record: dict) -> None:
    """Append a single canonical JSON-lines audit record durably."""
    log_path = gen_dir / AUDIT_LOG_FILENAME
    line = json.dumps(record, allow_nan=False, separators=(",", ":")) + "\n"
    fd = os.open(log_path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
    try:
        try:
            os.chmod(log_path, 0o600)
        except OSError:
            pass
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_dir(gen_dir)


def _resolve_generation_dir(state_dir: Path) -> Path | None:
    pointer_path = state_dir / POINTER_FILENAME
    if not pointer_path.is_file():
        return None
    try:
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
        if not isinstance(pointer, dict) or pointer.get("version") != STATE_VERSION:
            return None
        gen_name = pointer.get("generation")
        if not isinstance(gen_name, str) or not gen_name.startswith("gen_"):
            return None
        if Path(gen_name).name != gen_name:
            return None
        gen_dir = state_dir / gen_name
        if not gen_dir.is_dir():
            return None
        return gen_dir
    except Exception:
        return None


def _load_adapter_state(gen_dir: Path) -> dict | None:
    state_path = gen_dir / ADAPTER_STATE_FILENAME
    if not state_path.is_file():
        return None
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("version") != STATE_VERSION:
            return None
        if not isinstance(data.get("owners"), dict) or not isinstance(data.get("contents"), dict):
            return None
        return data
    except Exception:
        return None


def _find_audit_record(gen_dir: Path, request_id: str) -> dict | None:
    log_path = gen_dir / AUDIT_LOG_FILENAME
    if not log_path.is_file():
        return None
    found = None
    with log_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            record = json.loads(stripped)
            if record.get("request_id") == request_id:
                found = record
    return found


def _cleanup_old_generations(state_dir: Path, active_name: str) -> None:
    try:
        for entry in state_dir.iterdir():
            if entry.is_dir() and entry.name.startswith("gen_") and entry.name != active_name:
                shutil.rmtree(entry, ignore_errors=True)
    except OSError:
        pass


def _authorize_request(gen_dir: Path, state: dict, actor: str, asset: str) -> tuple[bool, str]:
    """Evaluate ownership and node feed revocation; returns (allowed, internal_reason)."""
    try:
        node = Node(gen_dir / NODE_SUBDIR, freshness_window=None)
        node_decision = node.check_actor(actor)
        if node_decision.decision != "allow":
            return False, node_decision.reason.value
        owners = state["owners"]
        contents = state["contents"]
        if asset not in owners or asset not in contents:
            return False, "UNKNOWN_ASSET"
        if owners[asset] != actor:
            return False, "NOT_OWNER"
        return True, ReasonCode.OK.value
    except Exception:
        return False, ReasonCode.STATE_CORRUPT.value


def _handle_setup(state_dir: Path, request: dict) -> dict:
    owners = request.get("owners")
    contents = request.get("contents")
    disabled = request.get("disabled", [])
    key_material = request.get("key_material")

    if not isinstance(owners, dict) or not isinstance(contents, dict):
        return {"error": "invalid_setup_fields"}
    if not isinstance(disabled, list) or not all(isinstance(x, str) for x in disabled):
        return {"error": "invalid_disabled_list"}
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in owners.items()):
        return {"error": "invalid_owners_map"}
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in contents.items()):
        return {"error": "invalid_contents_map"}
    if key_material is not None and not isinstance(key_material, str):
        return {"error": "invalid_key_material"}

    gen_name = f"gen_{secrets.token_hex(12)}"
    gen_dir = state_dir / gen_name
    _ensure_state_dir(gen_dir)

    admin_pk, admin_sk = generate_signing_keypair()
    feed_id = secrets.token_hex(16)
    node = Node.initialise(gen_dir / NODE_SUBDIR, feed_id, admin_pk, freshness_window=None)
    author = FeedAuthor(feed_id, admin_sk)

    genesis_bytes = author.genesis()
    gen_res = node.apply_entry(genesis_bytes)
    if not gen_res.applied:
        return {"error": "setup_feed_failed"}

    for actor in dict.fromkeys(disabled):
        rev_bytes = author.revoke_actor(actor)
        rev_res = node.apply_entry(rev_bytes)
        if not rev_res.applied:
            return {"error": "setup_revoke_failed"}

    adapter_state = {
        "version": STATE_VERSION,
        "owners": dict(owners),
        "contents": dict(contents),
        "key_material": key_material if key_material is not None else "",
    }
    _atomic_write_text(
        gen_dir / ADAPTER_STATE_FILENAME,
        json.dumps(adapter_state, allow_nan=False, separators=(",", ":")),
    )

    admin_key_state = {
        "version": STATE_VERSION,
        "feed_id": feed_id,
        "admin_secret_key_b64": base64.b64encode(admin_sk).decode("ascii"),
        "epoch": author.epoch,
        "last_hash_hex": author.last_hash.hex(),
    }
    _atomic_write_text(
        gen_dir / ADMIN_KEY_FILENAME,
        json.dumps(admin_key_state, allow_nan=False, separators=(",", ":")),
    )
    _atomic_write_text(gen_dir / AUDIT_LOG_FILENAME, "")

    _atomic_write_text(
        state_dir / POINTER_FILENAME,
        json.dumps({"version": STATE_VERSION, "generation": gen_name}, allow_nan=False, separators=(",", ":")),
    )
    _cleanup_old_generations(state_dir, gen_name)
    return {"ready": True}


def _handle_read(state_dir: Path, request: dict) -> dict:
    actor = request.get("actor")
    asset = request.get("asset")
    request_id = request.get("request_id")
    if not all(isinstance(x, str) for x in (actor, asset, request_id)):
        return {"error": "missing_or_invalid_fields"}

    gen_dir = _resolve_generation_dir(state_dir)
    if gen_dir is None:
        return {"decision": "deny"}

    state = _load_adapter_state(gen_dir)
    if state is None:
        return {"decision": "deny"}

    allowed, internal_reason = _authorize_request(gen_dir, state, actor, asset)
    decision = "allow" if allowed else "deny"
    _append_audit_record(
        gen_dir,
        {
            "version": STATE_VERSION,
            "request_id": request_id,
            "op": "read",
            "actor": actor,
            "asset": asset,
            "decision": decision,
            "reason": internal_reason,
        },
    )
    if allowed:
        return {"decision": "allow", "body": state["contents"][asset]}
    return {"decision": "deny"}


def _handle_revoke(state_dir: Path, request: dict) -> dict:
    actor = request.get("actor")
    if not isinstance(actor, str) or not actor:
        return {"error": "missing_or_invalid_actor"}

    gen_dir = _resolve_generation_dir(state_dir)
    if gen_dir is None:
        return {"error": "not_initialized"}

    if _load_adapter_state(gen_dir) is None:
        return {"error": "state_corrupt"}

    node = Node(gen_dir / NODE_SUBDIR, freshness_window=None)
    current = node.check_actor(actor)
    if current.reason == ReasonCode.STATE_CORRUPT:
        return {"error": "state_corrupt"}
    if current.reason == ReasonCode.REVOKED_ACTOR:
        return {}

    admin_path = gen_dir / ADMIN_KEY_FILENAME
    if not admin_path.is_file():
        return {"error": "state_corrupt"}
    try:
        admin_data = json.loads(admin_path.read_text(encoding="utf-8"))
        admin_sk = base64.b64decode(admin_data["admin_secret_key_b64"], validate=True)
        author = FeedAuthor(admin_data["feed_id"], admin_sk)
        author.epoch = int(admin_data["epoch"])
        author.last_hash = bytes.fromhex(admin_data["last_hash_hex"])
        rev_bytes = author.revoke_actor(actor)
    except Exception:
        return {"error": "revoke_author_failed"}

    apply_res = node.apply_entry(rev_bytes)
    if not apply_res.applied and apply_res.status != "already_applied":
        return {"error": "revoke_apply_failed"}

    admin_data["epoch"] = author.epoch
    admin_data["last_hash_hex"] = compute_entry_hash(rev_bytes).hex()
    _atomic_write_text(
        admin_path,
        json.dumps(admin_data, allow_nan=False, separators=(",", ":")),
    )
    return {}


def _handle_audit(state_dir: Path, request: dict) -> dict:
    request_id = request.get("request_id")
    if not isinstance(request_id, str):
        return {"error": "missing_or_invalid_request_id"}

    gen_dir = _resolve_generation_dir(state_dir)
    if gen_dir is None:
        return {"error": "not_initialized"}

    if _load_adapter_state(gen_dir) is None:
        return {"error": "state_corrupt"}

    try:
        record = _find_audit_record(gen_dir, request_id)
    except Exception:
        return {"error": "state_corrupt"}
    if record is None:
        return {"error": "unknown_request"}
    return {"request_id": record["request_id"], "decision": record["decision"]}


def _handle_protected_read(state_dir: Path, request: dict) -> dict:
    actor = request.get("actor")
    asset = request.get("asset")
    challenge = request.get("challenge")
    public_key_b64 = request.get("public_key")
    if not all(isinstance(x, str) for x in (actor, asset, challenge, public_key_b64)):
        return {"error": "missing_or_invalid_fields"}

    gen_dir = _resolve_generation_dir(state_dir)
    if gen_dir is None:
        return {"decision": "deny"}

    state = _load_adapter_state(gen_dir)
    if state is None:
        return {"decision": "deny"}

    allowed, _ = _authorize_request(gen_dir, state, actor, asset)
    if not allowed:
        return {"decision": "deny"}

    try:
        public_key = base64.b64decode(public_key_b64.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError, binascii.Error):
        return {"error": "invalid_public_key"}

    if len(public_key) != ml_kem_768.PUBLIC_KEY_SIZE:
        return {"error": "invalid_public_key_length"}

    try:
        ciphertext, shared_secret = ml_kem_768.encrypt(public_key)
    except Exception:
        return {"error": "kem_encapsulation_failed"}

    body = state["contents"][asset]
    message = (challenge + body).encode("utf-8")
    proof = hmac.new(shared_secret, message, hashlib.sha256).hexdigest()
    ciphertext_b64 = base64.b64encode(ciphertext).decode("ascii")
    return {
        "decision": "allow",
        "ciphertext": ciphertext_b64,
        "proof": proof,
    }


def dispatch(request: dict) -> dict:
    """Dispatch one adapter request against persisted state."""
    op = request.get("op")
    if not isinstance(op, str):
        return {"error": "missing_op"}

    state_dir = get_state_dir()
    with _state_lock(state_dir):
        if op == "setup":
            return _handle_setup(state_dir, request)
        if op == "read":
            return _handle_read(state_dir, request)
        if op == "revoke":
            return _handle_revoke(state_dir, request)
        if op == "audit":
            return _handle_audit(state_dir, request)
        if op == "protected_read":
            return _handle_protected_read(state_dir, request)
        return {"error": "unsupported_operation"}
