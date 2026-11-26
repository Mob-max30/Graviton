"""Judged Core Dispatcher: Implements setup, read, revoke, audit, and protected_read."""
import base64
import hashlib
import hmac
from typing import Any, Dict

from trustledger.core.audit import AuditLog
from trustledger.core.lock import FileLock
from trustledger.core.store import IntegrityError, StateStore, ct_equal

MAX_PAYLOAD_SIZE = 1024 * 1024  # 1 MiB
MAX_IDENTIFIER_SIZE = 64 * 1024  # 64 KiB


class DispatchError(ValueError):
    """Raised on invalid request format or parameters."""


def _validate_identifier(val: Any, name: str) -> str:
    if not isinstance(val, str):
        raise DispatchError(f"{name} must be a string")
    if len(val) > MAX_IDENTIFIER_SIZE:
        raise DispatchError(f"{name} exceeds max allowed length")
    return val


def _authorize(
    state: Dict[str, Any],
    actor: str,
    asset: str,
) -> tuple[str, str]:
    """Evaluate ownership and revocation using constant-time UTF-8 comparison."""
    disabled_actors = state.get("disabled", [])
    revoked_tombstones = state.get("revoked_tombstones", [])
    owners = state.get("owners", {})
    contents = state.get("contents", {})

    if any(ct_equal(d, actor) for d in disabled_actors) or any(ct_equal(r, actor) for r in revoked_tombstones):
        return "deny", "ACTOR_REVOKED_OR_DISABLED"
    if asset not in owners or asset not in contents:
        return "deny", "ASSET_NOT_FOUND"
    if not ct_equal(str(owners[asset]), actor):
        return "deny", "ACTOR_NOT_OWNER"
    return "allow", "OWNER_AUTHORIZED"


def dispatch(request: Dict[str, Any]) -> Dict[str, Any]:
    """Process incoming JSON request strictly adhering to the adapter contract."""
    if not isinstance(request, dict):
        raise DispatchError("Request must be a dictionary")

    op = request.get("op")
    if not isinstance(op, str):
        raise DispatchError("Missing or invalid operation")

    store = StateStore()
    audit_log = AuditLog(store.audit_file)

    with FileLock(store.lock_file, timeout_seconds=4.0):
        if op == "setup":
            owners = request.get("owners")
            contents = request.get("contents")
            disabled = request.get("disabled", [])
            key_material = request.get("key_material")

            if not isinstance(owners, dict) or not isinstance(contents, dict):
                raise DispatchError("owners and contents must be dictionaries")
            if not isinstance(disabled, list):
                raise DispatchError("disabled must be a list")
            if not isinstance(key_material, str) or not key_material:
                raise DispatchError("key_material must be a non-empty string")

            store.initialize(
                owners={str(k): str(v) for k, v in owners.items()},
                contents={str(k): str(v) for k, v in contents.items()},
                disabled=[str(d) for d in disabled],
                key_material=key_material,
            )
            return {"ready": True}

        if op == "revoke":
            actor = _validate_identifier(request.get("actor"), "actor")
            state = store.load_state()
            _, k_audit = store.load_keys()

            disabled_set = set(state.get("disabled", []))
            disabled_set.add(actor)
            state["disabled"] = sorted(disabled_set)

            revoked_set = set(state.get("revoked_tombstones", []))
            revoked_set.add(actor)
            state["revoked_tombstones"] = sorted(revoked_set)

            seq = state.get("last_seq", 0) + 1
            prev_hash = state.get("last_hash", "")
            new_hash, _ = audit_log.append_event(
                seq=seq,
                prev_hash=prev_hash,
                op="revoke",
                actor=actor,
                asset="",
                request_id="",
                decision="allow",
                reason_code="ACTOR_REVOKED",
                k_audit=k_audit,
            )
            state["last_seq"] = seq
            state["last_hash"] = new_hash
            store.save_state(state)
            return {}

        if op == "audit":
            request_id = _validate_identifier(request.get("request_id"), "request_id")
            state = store.load_state()
            _, k_audit = store.load_keys()
            rec = audit_log.find_request(
                request_id,
                k_audit=k_audit,
                expected_last_seq=state.get("last_seq"),
                expected_last_hash=state.get("last_hash"),
            )
            if rec is None:
                return {"error": "unknown_request"}
            return {
                "request_id": rec["request_id"],
                "decision": rec["decision"],
            }

        if op == "read":
            actor = _validate_identifier(request.get("actor"), "actor")
            asset = _validate_identifier(request.get("asset"), "asset")
            request_id = _validate_identifier(request.get("request_id"), "request_id")

            state = store.load_state()
            _, k_audit = store.load_keys()

            # Check request_id reuse against full verified audit log (first record is authoritative)
            existing = audit_log.find_request(
                request_id,
                k_audit=k_audit,
                expected_last_seq=state.get("last_seq"),
                expected_last_hash=state.get("last_hash"),
            )
            if existing is not None:
                decision = "deny"
                reason_code = "REQUEST_ID_REUSED"
            else:
                try:
                    decision, reason_code = _authorize(state, actor, asset)
                except IntegrityError:
                    raise
                except Exception:
                    decision = "deny"
                    reason_code = "INTERNAL_AUTH_ERROR"

            seq = state.get("last_seq", 0) + 1
            prev_hash = state.get("last_hash", "")
            new_hash, _ = audit_log.append_event(
                seq=seq,
                prev_hash=prev_hash,
                op="read",
                actor=actor,
                asset=asset,
                request_id=request_id,
                decision=decision,
                reason_code=reason_code,
                k_audit=k_audit,
            )
            state["last_seq"] = seq
            state["last_hash"] = new_hash
            store.save_state(state)

            if decision == "allow":
                return {
                    "decision": "allow",
                    "body": state["contents"][asset],
                }
            return {"decision": "deny"}

        if op == "protected_read":
            actor = _validate_identifier(request.get("actor"), "actor")
            asset = _validate_identifier(request.get("asset"), "asset")
            challenge = _validate_identifier(request.get("challenge"), "challenge")
            pk_b64 = _validate_identifier(request.get("public_key"), "public_key")

            state = store.load_state()
            _, k_audit = store.load_keys()

            try:
                decision, reason_code = _authorize(state, actor, asset)
            except IntegrityError:
                raise
            except Exception:
                decision = "deny"
                reason_code = "INTERNAL_AUTH_ERROR"

            seq = state.get("last_seq", 0) + 1
            prev_hash = state.get("last_hash", "")

            if decision != "allow":
                new_hash, _ = audit_log.append_event(
                    seq=seq,
                    prev_hash=prev_hash,
                    op="protected_read",
                    actor=actor,
                    asset=asset,
                    request_id=f"prot-{seq}",
                    decision="deny",
                    reason_code=reason_code,
                    k_audit=k_audit,
                )
                state["last_seq"] = seq
                state["last_hash"] = new_hash
                store.save_state(state)
                return {"decision": "deny"}

            # Validate public_key, base64, and pqcrypto BEFORE logging an allow disclosure
            try:
                pk_bytes = base64.b64decode(pk_b64, validate=True)
            except Exception as err:
                new_hash, _ = audit_log.append_event(
                    seq=seq,
                    prev_hash=prev_hash,
                    op="protected_read",
                    actor=actor,
                    asset=asset,
                    request_id=f"prot-{seq}",
                    decision="deny",
                    reason_code="ALLOWED_BUT_KEM_FAILED",
                    k_audit=k_audit,
                )
                state["last_seq"] = seq
                state["last_hash"] = new_hash
                store.save_state(state)
                raise DispatchError("Invalid base64 encoding for public_key") from err

            if len(pk_bytes) != 1184:
                new_hash, _ = audit_log.append_event(
                    seq=seq,
                    prev_hash=prev_hash,
                    op="protected_read",
                    actor=actor,
                    asset=asset,
                    request_id=f"prot-{seq}",
                    decision="deny",
                    reason_code="ALLOWED_BUT_KEM_FAILED",
                    k_audit=k_audit,
                )
                state["last_seq"] = seq
                state["last_hash"] = new_hash
                store.save_state(state)
                raise DispatchError(f"Invalid ML-KEM-768 public key size: {len(pk_bytes)} != 1184")

            try:
                import pqcrypto.kem.ml_kem_768 as ml_kem
            except ImportError as err:
                new_hash, _ = audit_log.append_event(
                    seq=seq,
                    prev_hash=prev_hash,
                    op="protected_read",
                    actor=actor,
                    asset=asset,
                    request_id=f"prot-{seq}",
                    decision="deny",
                    reason_code="ALLOWED_BUT_KEM_FAILED",
                    k_audit=k_audit,
                )
                state["last_seq"] = seq
                state["last_hash"] = new_hash
                store.save_state(state)
                raise RuntimeError("pqcrypto module is required for protected_read") from err

            ciphertext, shared_secret = ml_kem.encrypt(pk_bytes)
            stored_body = state["contents"][asset]
            proof_data = (challenge + stored_body).encode("utf-8", errors="surrogatepass")
            proof_hex = hmac.new(shared_secret, proof_data, hashlib.sha256).hexdigest().lower()

            new_hash, _ = audit_log.append_event(
                seq=seq,
                prev_hash=prev_hash,
                op="protected_read",
                actor=actor,
                asset=asset,
                request_id=f"prot-{seq}",
                decision="allow",
                reason_code="OWNER_AUTHORIZED",
                k_audit=k_audit,
            )
            state["last_seq"] = seq
            state["last_hash"] = new_hash
            store.save_state(state)

            ct_b64 = base64.b64encode(ciphertext).decode("ascii")
            return {
                "ciphertext": ct_b64,
                "proof": proof_hex,
            }

        return {"error": "unsupported_operation"}
