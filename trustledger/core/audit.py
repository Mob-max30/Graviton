"""Append-only audit log with cryptographic hash-chaining, HMAC verification, and first-write request_id authority."""
import datetime
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from trustledger.core.store import GENESIS_HASH, IntegrityError, canonical_json_bytes, ct_equal


class AuditLog:
    """Manages append-only canonical audit logging with full chain verification."""

    def __init__(self, audit_path: Path):
        self.audit_path = audit_path

    def append_event(
        self,
        seq: int,
        prev_hash: str,
        op: str,
        actor: str,
        asset: str,
        request_id: str,
        decision: str,
        reason_code: str,
        k_audit: bytes,
    ) -> Tuple[str, Dict[str, Any]]:
        """Append an event to the audit log and return (new_hash, record)."""
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        record_core: Dict[str, Any] = {
            "actor": actor,
            "asset": asset,
            "decision": decision,
            "op": op,
            "prev_hash": prev_hash,
            "reason_code": reason_code,
            "request_id": request_id,
            "seq": seq,
            "timestamp": now_utc,
        }
        core_bytes = canonical_json_bytes(record_core)
        hasher = hashlib.sha256()
        hasher.update(prev_hash.encode("ascii"))
        hasher.update(core_bytes)
        record_hash = hasher.hexdigest()

        record_mac = hmac.new(k_audit, record_hash.encode("ascii"), hashlib.sha256).hexdigest()

        full_record = dict(record_core)
        full_record["record_hash"] = record_hash
        full_record["mac"] = record_mac

        line_bytes = canonical_json_bytes(full_record) + b"\n"

        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if sys.platform != "win32":
            fd = os.open(str(self.audit_path), flags, 0o600)
        else:
            fd = os.open(str(self.audit_path), flags)
        try:
            os.write(fd, line_bytes)
            os.fsync(fd)
        finally:
            os.close(fd)

        return record_hash, full_record

    def _verify_record(self, rec: Dict[str, Any], k_audit: bytes, expected_seq: int, expected_prev_hash: str) -> str:
        """Verify record sequence, prev_hash, hash, and HMAC using k_audit; fail closed on mismatch."""
        if rec.get("seq") != expected_seq:
            raise IntegrityError(f"Audit sequence gap: expected {expected_seq}, got {rec.get('seq')}")
        prev_hash = str(rec.get("prev_hash", ""))
        if not ct_equal(prev_hash, expected_prev_hash):
            raise IntegrityError(f"Audit chain break at seq {expected_seq}")

        core_keys = ("actor", "asset", "decision", "op", "prev_hash", "reason_code", "request_id", "seq", "timestamp")
        record_core = {k: rec[k] for k in core_keys if k in rec}

        hasher = hashlib.sha256()
        hasher.update(prev_hash.encode("ascii"))
        hasher.update(canonical_json_bytes(record_core))
        expected_hash = hasher.hexdigest()
        recorded_hash = str(rec.get("record_hash", ""))
        if not ct_equal(recorded_hash, expected_hash):
            raise IntegrityError("Audit record hash mismatch.")

        expected_mac = hmac.new(k_audit, recorded_hash.encode("ascii"), hashlib.sha256).hexdigest()
        recorded_mac = str(rec.get("mac", ""))
        if not ct_equal(recorded_mac, expected_mac):
            raise IntegrityError("Audit record MAC verification failed.")

        return recorded_hash

    def verify_chain(
        self,
        k_audit: bytes,
        expected_last_seq: Optional[int] = None,
        expected_last_hash: Optional[str] = None,
    ) -> None:
        """Verify full hash-chain continuity and HMACs without searching for a specific request."""
        self.find_request(
            request_id="",
            k_audit=k_audit,
            expected_last_seq=expected_last_seq,
            expected_last_hash=expected_last_hash,
        )

    def find_request(
        self,
        request_id: str,
        k_audit: Optional[bytes] = None,
        expected_last_seq: Optional[int] = None,
        expected_last_hash: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Verify full hash-chain continuity and return the FIRST authoritative record matching request_id."""
        if not self.audit_path.exists():
            if expected_last_seq and expected_last_seq > 0:
                raise IntegrityError("Audit log missing while state expects recorded events.")
            return None
        with open(self.audit_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        expected_seq = 1
        expected_prev = GENESIS_HASH
        first_match: Optional[Dict[str, Any]] = None

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                rec: Dict[str, Any] = json.loads(stripped)
            except json.JSONDecodeError as err:
                raise IntegrityError("Corrupted JSON in audit log.") from err
            if k_audit is not None:
                expected_prev = self._verify_record(rec, k_audit, expected_seq, expected_prev)
                expected_seq += 1
            if request_id and first_match is None:
                rec_req_id = rec.get("request_id")
                if isinstance(rec_req_id, str) and ct_equal(rec_req_id, request_id):
                    first_match = rec

        if k_audit is not None:
            if expected_last_seq is not None and (expected_seq - 1) != expected_last_seq:
                raise IntegrityError("Audit log truncated or out of sync with state last_seq.")
            if expected_last_hash is not None and not ct_equal(expected_prev, expected_last_hash):
                raise IntegrityError("Audit log tail hash does not match state last_hash.")

        return first_match
