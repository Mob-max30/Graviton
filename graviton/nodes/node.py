"""Independent enforcement node state, feed application, and authorization."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from enum import Enum
import json
from pathlib import Path
import time
from typing import Callable

from graviton.crypto.signatures import DSA_PUBLIC_KEY_SIZE, verify_signature
from graviton.feed.encoding import MAX_ENTRY_LEN, FeedFormatError, enc_bytes, enc_id, enc_str, enc_u8, enc_u32
from graviton.feed.entries import (
    ZERO_HASH,
    EntryType,
    FeedEntry,
    compute_entry_hash,
    decode_entry_body,
    unpack_signed_entry,
)
from graviton.feed.verify import FeedContinuityError, FeedVerificationError, verify_entry
from graviton.storage import (
    atomic_write_text as _atomic_write_text,
    ensure_state_dir as _ensure_state_dir,
    state_lock as _state_lock,
)

NODE_STATE_VERSION = 1
NODE_STATE_FILENAME = "node_state.json"
REQUEST_SIGN_DOMAIN = b"request"


class ReasonCode(str, Enum):
    OK = "OK"
    UNKNOWN_KEY = "UNKNOWN_KEY"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    REVOKED_DEVICE = "REVOKED_DEVICE"
    REVOKED_ACTOR = "REVOKED_ACTOR"
    KEY_RETIRED = "KEY_RETIRED"
    STALE_STATE = "STALE_STATE"
    STATE_CORRUPT = "STATE_CORRUPT"


@dataclass(frozen=True)
class Decision:
    decision: str
    reason: ReasonCode


@dataclass(frozen=True)
class ApplyResult:
    applied: bool
    status: str
    epoch: int | None = None
    detail: str = ""


@dataclass(frozen=True)
class BatchApplyResult:
    applied_count: int
    stopped_reason: str | None
    results: list[ApplyResult]


class NodeInitError(ValueError):
    """Raised when node initialisation conflicts with existing pinned trust root."""


class _SemanticError(ValueError):
    """Raised when an entry violates semantic state rules."""


def build_request_signing_bytes(
    feed_id: str,
    actor: str,
    device_id: str,
    key_version: int,
    payload: bytes,
) -> bytes:
    """Build canonical request bytes signed by a device ML-DSA-65 key."""
    return (
        enc_u8(1)
        + enc_id(feed_id)
        + enc_str(actor)
        + enc_str(device_id)
        + enc_u32(key_version)
        + enc_bytes(payload)
    )


def _apply_semantic_transition(
    registry: dict,
    revoked_actors: list[str],
    entry: FeedEntry,
) -> None:
    """Apply a verified FeedEntry to in-memory registry/revoked_actors dicts."""
    if entry.entry_type in (EntryType.GENESIS, EntryType.HEAD):
        return

    if entry.entry_type == EntryType.REGISTER_KEY:
        actor = entry.actor
        device_id = entry.device_id
        assert actor is not None and device_id is not None and entry.public_key is not None
        if entry.key_version != 1:
            raise _SemanticError("REGISTER_KEY requires key_version == 1")
        if actor in revoked_actors:
            raise _SemanticError("Cannot register key for revoked actor")
        actor_devices = registry.setdefault(actor, {})
        if device_id in actor_devices:
            raise _SemanticError("Device already exists (or was revoked)")
        actor_devices[device_id] = {
            "versions": {
                "1": {
                    "public_key_b64": base64.b64encode(entry.public_key).decode("ascii"),
                    "cutoff_epoch": None,
                }
            },
            "current_version": 1,
            "revoked": False,
        }
        return

    if entry.entry_type == EntryType.ROTATE_KEY:
        actor = entry.actor
        device_id = entry.device_id
        assert (
            actor is not None
            and device_id is not None
            and entry.key_version is not None
            and entry.public_key is not None
            and entry.cutoff_epoch is not None
        )
        if actor in revoked_actors:
            raise _SemanticError("Cannot rotate key for revoked actor")
        actor_devices = registry.get(actor, {})
        device = actor_devices.get(device_id)
        if device is None:
            raise _SemanticError("Device does not exist")
        if device.get("revoked"):
            raise _SemanticError("Cannot rotate key for revoked device")
        current_ver = int(device["current_version"])
        if entry.key_version != current_ver + 1:
            raise _SemanticError("new_version must equal current_version + 1")
        if entry.cutoff_epoch <= entry.epoch:
            raise _SemanticError("cutoff_epoch must be greater than entry epoch")
        device["versions"][str(current_ver)]["cutoff_epoch"] = entry.cutoff_epoch
        device["versions"][str(entry.key_version)] = {
            "public_key_b64": base64.b64encode(entry.public_key).decode("ascii"),
            "cutoff_epoch": None,
        }
        device["current_version"] = entry.key_version
        return

    if entry.entry_type == EntryType.REVOKE_DEVICE:
        actor = entry.actor
        device_id = entry.device_id
        assert actor is not None and device_id is not None
        actor_devices = registry.get(actor, {})
        device = actor_devices.get(device_id)
        if device is None:
            raise _SemanticError("Device does not exist")
        device["revoked"] = True
        return

    if entry.entry_type == EntryType.REVOKE_ACTOR:
        actor = entry.actor
        assert actor is not None
        if actor not in revoked_actors:
            revoked_actors.append(actor)
        return

    raise _SemanticError(f"Unsupported entry type: {entry.entry_type}")


class Node:
    """Independent enforcement node backed by a local persisted state directory."""

    def __init__(
        self,
        state_dir: str | Path,
        *,
        freshness_window: int | None = None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self.state_dir = Path(state_dir)
        self.freshness_window = freshness_window
        self._clock = clock or (lambda: int(time.time()))

    @classmethod
    def initialise(
        cls,
        state_dir: str | Path,
        feed_id: str,
        admin_public_key: bytes,
        *,
        freshness_window: int | None = None,
        clock: Callable[[], int] | None = None,
    ) -> "Node":
        """Initialise a node directory with an immutable (feed_id, admin_public_key)."""
        if not isinstance(feed_id, str) or not feed_id:
            raise NodeInitError("feed_id must be a non-empty string")
        if not isinstance(admin_public_key, (bytes, bytearray)) or len(admin_public_key) != DSA_PUBLIC_KEY_SIZE:
            raise NodeInitError("Invalid ML-DSA-65 admin public key")

        path = Path(state_dir)
        admin_pk_b64 = base64.b64encode(bytes(admin_public_key)).decode("ascii")
        with _state_lock(path):
            _ensure_state_dir(path)
            state_file = path / NODE_STATE_FILENAME
            if state_file.exists():
                try:
                    existing = json.loads(state_file.read_text(encoding="utf-8"))
                except Exception as exc:
                    raise NodeInitError("Existing node state is corrupt") from exc
                if (
                    existing.get("version") != NODE_STATE_VERSION
                    or existing.get("feed_id") != feed_id
                    or existing.get("admin_public_key_b64") != admin_pk_b64
                ):
                    raise NodeInitError("Node already initialised with different trust root")
            else:
                initial = {
                    "version": NODE_STATE_VERSION,
                    "feed_id": feed_id,
                    "admin_public_key_b64": admin_pk_b64,
                    "applied_epoch": 0,
                    "last_entry_hash_hex": ZERO_HASH.hex(),
                    "applied_entries": [],
                    "last_issued_at": 0,
                    "registry": {},
                    "revoked_actors": [],
                }
                _atomic_write_text(state_file, json.dumps(initial, allow_nan=False, separators=(",", ":")))
        return cls(path, freshness_window=freshness_window, clock=clock)

    def _load_raw_state(self) -> dict:
        state_file = self.state_dir / NODE_STATE_FILENAME
        if not state_file.is_file():
            raise ValueError("Missing node state file")
        data = json.loads(state_file.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("version") != NODE_STATE_VERSION:
            raise ValueError("Invalid node state schema")
        required = (
            "feed_id",
            "admin_public_key_b64",
            "applied_epoch",
            "last_entry_hash_hex",
            "applied_entries",
            "last_issued_at",
            "registry",
            "revoked_actors",
        )
        if not all(k in data for k in required):
            raise ValueError("Incomplete node state")
        return data

    def _verify_state_integrity(self, state: dict) -> bool:
        try:
            feed_id = state["feed_id"]
            admin_pk = base64.b64decode(state["admin_public_key_b64"], validate=True)
            if len(admin_pk) != DSA_PUBLIC_KEY_SIZE:
                return False
            entries_b64 = state["applied_entries"]
            if not isinstance(entries_b64, list):
                return False

            expected_epoch = 0
            prev_hash = ZERO_HASH
            last_issued_at = 0
            registry: dict = {}
            revoked_actors: list[str] = []

            for raw_b64 in entries_b64:
                raw = base64.b64decode(raw_b64, validate=True)
                expected_epoch += 1
                entry = verify_entry(raw, admin_pk, feed_id, expected_epoch, prev_hash)
                _apply_semantic_transition(registry, revoked_actors, entry)
                prev_hash = compute_entry_hash(raw)
                last_issued_at = entry.issued_at

            return (
                state["applied_epoch"] == expected_epoch
                and state["last_entry_hash_hex"] == prev_hash.hex()
                and state["last_issued_at"] == last_issued_at
                and state["registry"] == registry
                and state["revoked_actors"] == revoked_actors
            )
        except Exception:
            return False

    def verify_integrity(self) -> bool:
        """Replay applied_entries from genesis and verify stored state matches."""
        with _state_lock(self.state_dir):
            try:
                state = self._load_raw_state()
            except Exception:
                return False
            return self._verify_state_integrity(state)

    def applied_epoch(self) -> int:
        with _state_lock(self.state_dir):
            state = self._load_raw_state()
            return int(state["applied_epoch"])

    def get_trust_root(self) -> tuple[str, bytes]:
        """Return (feed_id, admin_public_key) from persisted node state."""
        with _state_lock(self.state_dir):
            state = self._load_raw_state()
            return state["feed_id"], base64.b64decode(state["admin_public_key_b64"], validate=True)

    def entries_after(self, since_epoch: int) -> list[bytes]:
        """Return raw serialized feed entries with epoch > since_epoch."""
        if since_epoch < 0:
            raise ValueError("since_epoch must be non-negative")
        with _state_lock(self.state_dir):
            state = self._load_raw_state()
            return [base64.b64decode(b, validate=True) for b in state["applied_entries"][since_epoch:]]

    def get_device_public_key(self, actor: str, device_id: str, key_version: int) -> bytes | None:
        """Return registered ML-DSA-65 public key for exact (actor, device_id, key_version)."""
        with _state_lock(self.state_dir):
            try:
                state = self._load_raw_state()
            except Exception:
                return None
            ver_info = (
                state.get("registry", {})
                .get(actor, {})
                .get(device_id, {})
                .get("versions", {})
                .get(str(key_version))
            )
            if not isinstance(ver_info, dict) or "public_key_b64" not in ver_info:
                return None
            return base64.b64decode(ver_info["public_key_b64"], validate=True)

    def apply_entry(self, raw_bytes: bytes) -> ApplyResult:
        """Verify and atomically apply one serialized feed entry."""
        if not isinstance(raw_bytes, (bytes, bytearray)) or len(raw_bytes) > MAX_ENTRY_LEN:
            return ApplyResult(applied=False, status="invalid", detail="Invalid or oversized entry")
        raw = bytes(raw_bytes)

        with _state_lock(self.state_dir):
            try:
                state = self._load_raw_state()
            except Exception:
                return ApplyResult(applied=False, status="state_corrupt", detail="Corrupt node state")

            try:
                body, _ = unpack_signed_entry(raw)
                decoded = decode_entry_body(body)
            except FeedFormatError as exc:
                return ApplyResult(applied=False, status="invalid", detail=str(exc))

            current_epoch = int(state["applied_epoch"])
            if decoded.epoch <= current_epoch:
                if decoded.epoch < 1:
                    return ApplyResult(applied=False, status="rollback_rejected", epoch=decoded.epoch)
                stored_b64 = state["applied_entries"][decoded.epoch - 1]
                stored_raw = base64.b64decode(stored_b64)
                if raw == stored_raw:
                    return ApplyResult(applied=False, status="already_applied", epoch=decoded.epoch)
                if decoded.epoch == current_epoch:
                    return ApplyResult(applied=False, status="fork_rejected", epoch=decoded.epoch)
                return ApplyResult(applied=False, status="rollback_rejected", epoch=decoded.epoch)

            if decoded.epoch > current_epoch + 1:
                return ApplyResult(applied=False, status="gap", epoch=decoded.epoch)

            admin_pk = base64.b64decode(state["admin_public_key_b64"])
            prev_hash = bytes.fromhex(state["last_entry_hash_hex"])
            try:
                verified = verify_entry(
                    raw,
                    admin_pk,
                    state["feed_id"],
                    current_epoch + 1,
                    prev_hash,
                )
            except FeedContinuityError as exc:
                return ApplyResult(applied=False, status=exc.code, epoch=decoded.epoch, detail=str(exc))
            except FeedVerificationError as exc:
                return ApplyResult(applied=False, status="invalid", epoch=decoded.epoch, detail=str(exc))

            registry = json.loads(json.dumps(state["registry"]))
            revoked_actors = list(state["revoked_actors"])
            try:
                _apply_semantic_transition(registry, revoked_actors, verified)
            except _SemanticError as exc:
                return ApplyResult(applied=False, status="invalid", epoch=verified.epoch, detail=str(exc))

            state["applied_epoch"] = verified.epoch
            state["last_entry_hash_hex"] = compute_entry_hash(raw).hex()
            state["last_issued_at"] = verified.issued_at
            state["applied_entries"].append(base64.b64encode(raw).decode("ascii"))
            state["registry"] = registry
            state["revoked_actors"] = revoked_actors

            _atomic_write_text(
                self.state_dir / NODE_STATE_FILENAME,
                json.dumps(state, allow_nan=False, separators=(",", ":")),
            )
            return ApplyResult(applied=True, status="applied", epoch=verified.epoch)

    def apply_entries(self, entries: list[bytes]) -> BatchApplyResult:
        """Apply entries in order, stopping at the first rejection."""
        results: list[ApplyResult] = []
        applied_count = 0
        for raw in entries:
            res = self.apply_entry(raw)
            results.append(res)
            if res.applied:
                applied_count += 1
            elif res.status != "already_applied":
                return BatchApplyResult(
                    applied_count=applied_count,
                    stopped_reason=res.status,
                    results=results,
                )
        return BatchApplyResult(applied_count=applied_count, stopped_reason=None, results=results)

    def _authorize_from_state(
        self,
        state: dict,
        actor: str,
        device_id: str,
        key_version: int,
    ) -> Decision:
        if actor in state["revoked_actors"]:
            return Decision("deny", ReasonCode.REVOKED_ACTOR)

        device = state["registry"].get(actor, {}).get(device_id)
        if device is None:
            return Decision("deny", ReasonCode.UNKNOWN_KEY)
        if device.get("revoked"):
            return Decision("deny", ReasonCode.REVOKED_DEVICE)

        ver_info = device["versions"].get(str(key_version))
        if ver_info is None:
            return Decision("deny", ReasonCode.UNKNOWN_KEY)

        applied_epoch = int(state["applied_epoch"])
        if key_version != int(device["current_version"]):
            cutoff = ver_info.get("cutoff_epoch")
            if cutoff is not None and applied_epoch >= int(cutoff):
                return Decision("deny", ReasonCode.KEY_RETIRED)

        if self.freshness_window is not None:
            age = int(self._clock()) - int(state["last_issued_at"])
            if age > self.freshness_window:
                return Decision("deny", ReasonCode.STALE_STATE)

        return Decision("allow", ReasonCode.OK)

    def check_actor(self, actor: str) -> Decision:
        """Check whether an opaque actor is revoked without requiring device keys."""
        if not isinstance(actor, str) or not actor:
            return Decision("deny", ReasonCode.REVOKED_ACTOR)
        with _state_lock(self.state_dir):
            try:
                state = self._load_raw_state()
            except Exception:
                return Decision("deny", ReasonCode.STATE_CORRUPT)
            if not self._verify_state_integrity(state):
                return Decision("deny", ReasonCode.STATE_CORRUPT)
            if actor in state["revoked_actors"]:
                return Decision("deny", ReasonCode.REVOKED_ACTOR)
            if self.freshness_window is not None:
                age = int(self._clock()) - int(state["last_issued_at"])
                if age > self.freshness_window:
                    return Decision("deny", ReasonCode.STALE_STATE)
            return Decision("allow", ReasonCode.OK)

    def authorize(self, actor: str, device_id: str, key_version: int) -> Decision:
        """Make a fail-closed allow/deny decision from freshly loaded node state."""
        with _state_lock(self.state_dir):
            try:
                state = self._load_raw_state()
            except Exception:
                return Decision("deny", ReasonCode.STATE_CORRUPT)
            if not self._verify_state_integrity(state):
                return Decision("deny", ReasonCode.STATE_CORRUPT)
            return self._authorize_from_state(state, actor, device_id, key_version)

    def authenticate_request(
        self,
        actor: str,
        device_id: str,
        key_version: int,
        payload: bytes,
        signature: bytes,
    ) -> Decision:
        """Verify ML-DSA-65 device signature (domain 'request') then authorize."""
        if not isinstance(payload, (bytes, bytearray)) or not isinstance(signature, (bytes, bytearray)):
            return Decision("deny", ReasonCode.INVALID_SIGNATURE)

        with _state_lock(self.state_dir):
            try:
                state = self._load_raw_state()
            except Exception:
                return Decision("deny", ReasonCode.STATE_CORRUPT)
            if not self._verify_state_integrity(state):
                return Decision("deny", ReasonCode.STATE_CORRUPT)

            decision = self._authorize_from_state(state, actor, device_id, key_version)
            if decision.decision != "allow":
                return decision

            ver_info = state["registry"][actor][device_id]["versions"][str(key_version)]
            pub_key = base64.b64decode(ver_info["public_key_b64"])
            try:
                signed_bytes = build_request_signing_bytes(
                    state["feed_id"], actor, device_id, key_version, bytes(payload)
                )
            except FeedFormatError:
                return Decision("deny", ReasonCode.INVALID_SIGNATURE)

            if not verify_signature(pub_key, signed_bytes, bytes(signature), domain=REQUEST_SIGN_DOMAIN):
                return Decision("deny", ReasonCode.INVALID_SIGNATURE)

            return Decision("allow", ReasonCode.OK)
