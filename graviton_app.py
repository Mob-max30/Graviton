"""Graviton security engine for the Track 4 adapter contract (hardened Phase 1)."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import tempfile

from graviton.adapter_store import (
    STORE_VERSION,
    ZERO_HASH_HEX,
    LockTimeoutError,
    append_audit_record,
    atomic_write_json,
    bounded_lock,
    check_consistency_and_anti_rollback,
    derive_and_save_keys,
    ensure_private_dir,
    get_key_dir,
    load_head,
    load_keys,
    save_head,
    sign_state,
    verify_and_read_audit_log,
    verify_state,
)

STATE_VERSION = STORE_VERSION
POINTER_FILENAME = "current_generation.json"
ADAPTER_STATE_FILENAME = "adapter_state.json"
ADMIN_KEY_FILENAME = "admin_key.json"
AUDIT_LOG_FILENAME = "audit_log.jsonl"
NODE_SUBDIR = "node"
MAX_REQUEST_ID_LEN = 128


def get_state_dir() -> Path:
    """Return the writable state directory from TRACK4_STATE_DIR or OS temp."""
    env_dir = os.environ.get("TRACK4_STATE_DIR")
    if env_dir:
        return Path(env_dir)
    return Path(tempfile.gettempdir()) / "graviton_state"


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


def _cleanup_old_generations(state_dir: Path, active_name: str) -> None:
    try:
        for entry in state_dir.iterdir():
            if entry.is_dir() and entry.name.startswith("gen_") and entry.name != active_name:
                shutil.rmtree(entry, ignore_errors=True)
    except OSError:
        pass


def _load_verified_context(state_dir: Path) -> tuple[Path, Path, dict[str, bytes], dict, dict, list[dict]] | None:
    """Load and cryptographically verify keys, state, head, and full audit chain."""
    gen_dir = _resolve_generation_dir(state_dir)
    if gen_dir is None:
        return None
    key_dir = get_key_dir(state_dir)
    keys = load_keys(key_dir)
    if keys is None:
        return None
    head = load_head(key_dir, keys["k_head"])
    if head is None:
        return None
    state_path = gen_dir / ADAPTER_STATE_FILENAME
    if not state_path.is_file():
        return None
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not verify_state(state, keys["k_state"]):
        return None
    if not isinstance(state.get("owners"), dict) or not isinstance(state.get("contents"), dict):
        return None

    log_ok, records = verify_and_read_audit_log(gen_dir / AUDIT_LOG_FILENAME, keys["k_audit"])
    if not log_ok:
        return None

    consistent, needs_heal = check_consistency_and_anti_rollback(state, head, records)
    if not consistent:
        return None
    if needs_heal:
        head_body = {
            "version": STATE_VERSION,
            "generation": state["generation"],
            "last_seq": state["last_seq"],
            "last_hash": state["last_hash"],
            "revoked_count": len(state.get("revoked", [])),
        }
        save_head(key_dir, head_body, keys["k_head"])
        head = load_head(key_dir, keys["k_head"]) or head_body
    return gen_dir, key_dir, keys, state, head, records


def _authorize(gen_dir: Path, state: dict, actor: str, asset: str) -> tuple[bool, str]:
    """Constant-time, exact-match authorization without normalization."""
    node_dir = gen_dir / NODE_SUBDIR
    if not (node_dir / "node_state.json").is_file():
        return False, "STATE_CORRUPT"
    try:
        from graviton.nodes.node import Node

        node_dec = Node(node_dir, freshness_window=None).check_actor(actor)
        if node_dec.decision != "allow":
            return False, node_dec.reason.value
    except Exception:
        return False, "STATE_CORRUPT"

    actor_bytes = actor.encode("utf-8")
    for dis in state.get("disabled", []):
        if hmac.compare_digest(str(dis).encode("utf-8"), actor_bytes):
            return False, "DISABLED_ACTOR"
    for rev in state.get("revoked", []):
        if hmac.compare_digest(str(rev).encode("utf-8"), actor_bytes):
            return False, "REVOKED_ACTOR"

    owners = state["owners"]
    contents = state["contents"]
    matched_owner = None
    for k, v in owners.items():
        if hmac.compare_digest(str(k).encode("utf-8"), asset.encode("utf-8")):
            matched_owner = str(v)
            break
    if matched_owner is None:
        return False, "UNKNOWN_ASSET"

    has_content = any(
        hmac.compare_digest(str(k).encode("utf-8"), asset.encode("utf-8"))
        for k in contents
    )
    if not has_content:
        return False, "UNKNOWN_ASSET"

    if not hmac.compare_digest(matched_owner.encode("utf-8"), actor_bytes):
        return False, "NOT_OWNER"
    return True, "OK"


def _persist_mutation(
    gen_dir: Path,
    key_dir: Path,
    keys: dict[str, bytes],
    state: dict,
    *,
    request_id: str,
    actor: str,
    asset: str,
    op: str,
    decision: str,
    reason: str,
) -> dict:
    """Append audit record, persist authenticated state, then advance anti-rollback head."""
    next_seq = int(state["last_seq"]) + 1
    prev_hash = str(state["last_hash"])
    rec = append_audit_record(
        gen_dir / AUDIT_LOG_FILENAME,
        keys["k_audit"],
        seq=next_seq,
        prev_hash=prev_hash,
        request_id=request_id,
        actor=actor,
        asset=asset,
        op=op,
        decision=decision,
        reason=reason,
    )
    new_state_body = {k: v for k, v in state.items() if k != "state_mac"}
    new_state_body["last_seq"] = next_seq
    new_state_body["last_hash"] = rec["record_hash"]
    atomic_write_json(gen_dir / ADAPTER_STATE_FILENAME, sign_state(new_state_body, keys["k_state"]))
    save_head(
        key_dir,
        {
            "version": STATE_VERSION,
            "generation": new_state_body["generation"],
            "last_seq": next_seq,
            "last_hash": rec["record_hash"],
            "revoked_count": len(new_state_body.get("revoked", [])),
        },
        keys["k_head"],
    )
    return rec


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

    key_dir = get_key_dir(state_dir)
    keys = derive_and_save_keys(key_dir, key_material if key_material is not None else "")

    gen_name = f"gen_{secrets.token_hex(12)}"
    gen_dir = state_dir / gen_name
    ensure_private_dir(gen_dir)

    disabled_unique = list(dict.fromkeys(disabled))
    state_body = {
        "version": STATE_VERSION,
        "generation": gen_name,
        "owners": dict(owners),
        "contents": dict(contents),
        "disabled": disabled_unique,
        "revoked": list(disabled_unique),
        "last_seq": 0,
        "last_hash": ZERO_HASH_HEX,
    }
    atomic_write_json(gen_dir / ADAPTER_STATE_FILENAME, sign_state(state_body, keys["k_state"]))
    (gen_dir / AUDIT_LOG_FILENAME).write_bytes(b"")
    save_head(
        key_dir,
        {
            "version": STATE_VERSION,
            "generation": gen_name,
            "last_seq": 0,
            "last_hash": ZERO_HASH_HEX,
            "revoked_count": len(disabled_unique),
        },
        keys["k_head"],
    )

    # Also initialise Node policy feed lazily if graviton.nodes is available
    try:
        from graviton.crypto.signatures import generate_signing_keypair
        from graviton.feed.author import FeedAuthor
        from graviton.nodes.node import Node

        admin_pk, admin_sk = generate_signing_keypair()
        feed_id = secrets.token_hex(16)
        node = Node.initialise(gen_dir / NODE_SUBDIR, feed_id, admin_pk, freshness_window=None)
        author = FeedAuthor(feed_id, admin_sk)
        node.apply_entry(author.genesis())
        for actor_name in disabled_unique:
            node.apply_entry(author.revoke_actor(actor_name))
        atomic_write_json(
            gen_dir / ADMIN_KEY_FILENAME,
            {
                "version": STATE_VERSION,
                "feed_id": feed_id,
                "admin_secret_key_b64": base64.b64encode(admin_sk).decode("ascii"),
                "epoch": author.epoch,
                "last_hash_hex": author.last_hash.hex(),
            },
        )
    except Exception:
        pass

    atomic_write_json(state_dir / POINTER_FILENAME, {"version": STATE_VERSION, "generation": gen_name})
    _cleanup_old_generations(state_dir, gen_name)
    return {"ready": True}


def _handle_read(state_dir: Path, request: dict) -> dict:
    actor = request.get("actor")
    asset = request.get("asset")
    request_id = request.get("request_id")
    if not all(isinstance(x, str) for x in (actor, asset, request_id)):
        return {"error": "missing_or_invalid_fields"}
    if not request_id or len(request_id) > MAX_REQUEST_ID_LEN:
        return {"error": "invalid_request_id"}

    if _resolve_generation_dir(state_dir) is None:
        return {"decision": "deny"}

    ctx = _load_verified_context(state_dir)
    if ctx is None:
        return {"error": "integrity_violation"}
    gen_dir, key_dir, keys, state, _head, records = ctx

    if any(r.get("request_id") == request_id for r in records):
        _persist_mutation(
            gen_dir, key_dir, keys, state,
            request_id=request_id, actor=actor, asset=asset, op="read",
            decision="deny", reason="REQUEST_ID_REUSED",
        )
        return {"decision": "deny"}

    allowed, reason = _authorize(gen_dir, state, actor, asset)
    decision = "allow" if allowed else "deny"
    _persist_mutation(
        gen_dir, key_dir, keys, state,
        request_id=request_id, actor=actor, asset=asset, op="read",
        decision=decision, reason=reason,
    )
    if allowed:
        return {"decision": "allow", "body": state["contents"][asset]}
    return {"decision": "deny"}


def _handle_revoke(state_dir: Path, request: dict) -> dict:
    actor = request.get("actor")
    if not isinstance(actor, str) or not actor:
        return {"error": "missing_or_invalid_actor"}

    if _resolve_generation_dir(state_dir) is None:
        return {"error": "not_initialized"}

    ctx = _load_verified_context(state_dir)
    if ctx is None:
        return {"error": "integrity_violation"}
    gen_dir, key_dir, keys, state, _head, _records = ctx

    node_dir = gen_dir / NODE_SUBDIR
    if not (node_dir / "node_state.json").is_file():
        return {"error": "state_corrupt"}
    try:
        from graviton.nodes.node import Node, ReasonCode

        node_chk = Node(node_dir, freshness_window=None).check_actor(actor)
        if node_chk.reason == ReasonCode.STATE_CORRUPT:
            return {"error": "state_corrupt"}
    except Exception:
        return {"error": "state_corrupt"}

    revoked_list = list(state.get("revoked", []))
    if actor in revoked_list:
        return {}
    revoked_list.append(actor)
    state["revoked"] = revoked_list

    _persist_mutation(
        gen_dir, key_dir, keys, state,
        request_id=f"revoke:{secrets.token_hex(8)}",
        actor=actor, asset="", op="revoke", decision="allow", reason="REVOKED",
    )

    # Mirror revocation into Node feed if present
    admin_path = gen_dir / ADMIN_KEY_FILENAME
    if admin_path.is_file():
        try:
            from graviton.feed.author import FeedAuthor
            from graviton.feed.entries import compute_entry_hash
            from graviton.nodes.node import Node

            node = Node(gen_dir / NODE_SUBDIR, freshness_window=None)
            admin_data = json.loads(admin_path.read_text(encoding="utf-8"))
            admin_sk = base64.b64decode(admin_data["admin_secret_key_b64"], validate=True)
            author = FeedAuthor(admin_data["feed_id"], admin_sk)
            author.epoch = int(admin_data["epoch"])
            author.last_hash = bytes.fromhex(admin_data["last_hash_hex"])
            rev_bytes = author.revoke_actor(actor)
            node.apply_entry(rev_bytes)
            admin_data["epoch"] = author.epoch
            admin_data["last_hash_hex"] = compute_entry_hash(rev_bytes).hex()
            atomic_write_json(admin_path, admin_data)
        except Exception:
            pass
    return {}


def _handle_audit(state_dir: Path, request: dict) -> dict:
    request_id = request.get("request_id")
    if not isinstance(request_id, str) or not request_id or len(request_id) > MAX_REQUEST_ID_LEN:
        return {"error": "missing_or_invalid_request_id"}

    if _resolve_generation_dir(state_dir) is None:
        return {"error": "not_initialized"}

    ctx = _load_verified_context(state_dir)
    if ctx is None:
        return {"error": "integrity_violation"}
    _gen_dir, _key_dir, _keys, _state, _head, records = ctx

    # First-write-wins: return the original record for request_id
    for rec in records:
        if rec.get("request_id") == request_id:
            return {"request_id": rec["request_id"], "decision": rec["decision"]}
    return {"error": "unknown_request"}


def _handle_protected_read(state_dir: Path, request: dict) -> dict:
    actor = request.get("actor")
    asset = request.get("asset")
    challenge = request.get("challenge")
    public_key_b64 = request.get("public_key")
    request_id = request.get("request_id")
    if not all(isinstance(x, str) for x in (actor, asset, challenge, public_key_b64)):
        return {"error": "missing_or_invalid_fields"}
    if request_id is not None and (not isinstance(request_id, str) or not request_id or len(request_id) > MAX_REQUEST_ID_LEN):
        return {"error": "invalid_request_id"}

    if _resolve_generation_dir(state_dir) is None:
        return {"decision": "deny"}

    ctx = _load_verified_context(state_dir)
    if ctx is None:
        return {"error": "integrity_violation"}
    gen_dir, key_dir, keys, state, _head, records = ctx

    req_id = request_id or f"pread:{secrets.token_hex(8)}"
    if any(r.get("request_id") == req_id for r in records):
        _persist_mutation(
            gen_dir, key_dir, keys, state,
            request_id=req_id, actor=actor, asset=asset, op="protected_read",
            decision="deny", reason="REQUEST_ID_REUSED",
        )
        return {"decision": "deny"}

    allowed, reason = _authorize(gen_dir, state, actor, asset)
    if not allowed:
        _persist_mutation(
            gen_dir, key_dir, keys, state,
            request_id=req_id, actor=actor, asset=asset, op="protected_read",
            decision="deny", reason=reason,
        )
        return {"decision": "deny"}

    try:
        public_key = base64.b64decode(public_key_b64.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError, binascii.Error):
        return {"error": "invalid_public_key"}

    from pqcrypto.kem import ml_kem_768  # Lazy import per Hard Rule 5

    if len(public_key) != ml_kem_768.PUBLIC_KEY_SIZE:
        return {"error": "invalid_public_key_length"}

    try:
        ciphertext, shared_secret = ml_kem_768.encrypt(public_key)
    except Exception:
        return {"error": "kem_encapsulation_failed"}

    _persist_mutation(
        gen_dir, key_dir, keys, state,
        request_id=req_id, actor=actor, asset=asset, op="protected_read",
        decision="allow", reason="OK",
    )

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
    """Dispatch one adapter request against locked, integrity-verified state."""
    op = request.get("op")
    if not isinstance(op, str):
        return {"error": "missing_op"}

    state_dir = get_state_dir()
    try:
        with bounded_lock(state_dir):
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
    except LockTimeoutError:
        return {"error": "busy"}
