"""Hash-chained, append-only SQLite audit log with external head hash and ML-DSA-65 checkpoints."""
from __future__ import annotations

import base64
from contextlib import closing
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
import time
from typing import Callable

from graviton.crypto.signatures import sign_message, verify_signature
from graviton.feed.encoding import enc_bytes, enc_id, enc_str, enc_u8, enc_u64
from graviton.storage import atomic_write_text, ensure_state_dir, state_lock

AUDIT_LOG_VERSION = 1
AUDIT_CHECKPOINT_DOMAIN = b"audit-checkpoint"
ZERO_HASH = b"\x00" * 32


class AuditLogError(RuntimeError):
    """Raised on audit log initialization or persistence failures."""


@dataclass(frozen=True)
class AuthenticatedSession:
    """Verified caller identity; actor is bound strictly from this session."""

    actor: str
    session_id: str = ""


@dataclass(frozen=True)
class VerifyResult:
    valid: bool
    event_count: int
    checkpoint_count: int
    head_seq: int
    head_hash_hex: str
    first_bad_seq: int | None = None
    reason: str = "OK"


def _canonical_event_bytes(
    seq: int,
    timestamp: int,
    prev_hash: bytes,
    actor: str,
    action: str,
    target: str,
    decision: str,
    detail: str,
) -> bytes:
    """Length-prefixed binary encoding so user text cannot forge record boundaries."""
    return (
        enc_u8(AUDIT_LOG_VERSION)
        + enc_u64(seq)
        + enc_u64(timestamp)
        + enc_bytes(prev_hash)
        + enc_id(actor)
        + enc_str(action)
        + enc_str(target)
        + enc_str(decision)
        + enc_str(detail)
    )


def _checkpoint_signing_bytes(seq: int, head_hash: bytes) -> bytes:
    return enc_u8(AUDIT_LOG_VERSION) + enc_u64(seq) + enc_bytes(head_hash)


class AuditLog:
    """Tamper-evident audit log backed by append-only SQLite + external head hash."""

    def __init__(
        self,
        db_path: str | Path,
        external_head_path: str | Path,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.external_head_path = Path(external_head_path)
        self._lock_dir = self.db_path.parent
        self._clock = clock or (lambda: int(time.time()))
        self._init_storage()

    def _connect(self):
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        return closing(conn)

    def _init_storage(self) -> None:
        with state_lock(self._lock_dir):
            ensure_state_dir(self.db_path.parent)
            ensure_state_dir(self.external_head_path.parent)
            with self._connect() as conn:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS audit_events (
                        seq INTEGER PRIMARY KEY,
                        timestamp INTEGER NOT NULL,
                        prev_hash BLOB NOT NULL,
                        record_hash BLOB NOT NULL,
                        actor TEXT NOT NULL,
                        action TEXT NOT NULL,
                        target TEXT NOT NULL,
                        decision TEXT NOT NULL,
                        detail TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS audit_checkpoints (
                        seq INTEGER PRIMARY KEY,
                        head_hash BLOB NOT NULL,
                        signer_id TEXT NOT NULL,
                        signature BLOB NOT NULL,
                        created_at INTEGER NOT NULL
                    );
                    CREATE TRIGGER IF NOT EXISTS prevent_event_update
                    BEFORE UPDATE ON audit_events
                    BEGIN
                        SELECT RAISE(ABORT, 'audit_events is append-only');
                    END;
                    CREATE TRIGGER IF NOT EXISTS prevent_event_delete
                    BEFORE DELETE ON audit_events
                    BEGIN
                        SELECT RAISE(ABORT, 'audit_events is append-only');
                    END;
                    CREATE TRIGGER IF NOT EXISTS prevent_checkpoint_update
                    BEFORE UPDATE ON audit_checkpoints
                    BEGIN
                        SELECT RAISE(ABORT, 'audit_checkpoints is append-only');
                    END;
                    CREATE TRIGGER IF NOT EXISTS prevent_checkpoint_delete
                    BEFORE DELETE ON audit_checkpoints
                    BEGIN
                        SELECT RAISE(ABORT, 'audit_checkpoints is append-only');
                    END;
                    """
                )
            if not self.external_head_path.exists():
                self._write_external_head(0, ZERO_HASH)

    def _write_external_head(self, seq: int, head_hash: bytes) -> None:
        payload = {
            "version": AUDIT_LOG_VERSION,
            "seq": seq,
            "head_hash_hex": head_hash.hex(),
        }
        atomic_write_text(
            self.external_head_path,
            json.dumps(payload, allow_nan=False, separators=(",", ":")),
        )

    def append_event(
        self,
        session: AuthenticatedSession,
        action: str,
        target: str,
        decision: str,
        detail: str = "",
        *,
        claimed_actor: str | None = None,
    ) -> int:
        """Append an event; actor is bound strictly from `session.actor`.

        Any `claimed_actor` argument is ignored for the `actor` column (and
        optionally noted in detail only if needed; never trusted).
        """
        if not isinstance(session, AuthenticatedSession) or not session.actor:
            raise AuditLogError("Valid AuthenticatedSession with non-empty actor required")
        actor = session.actor
        ts = int(self._clock())

        with state_lock(self._lock_dir):
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT seq, record_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                if row is None:
                    seq = 1
                    prev_hash = ZERO_HASH
                else:
                    seq = int(row["seq"]) + 1
                    prev_hash = bytes(row["record_hash"])

                canonical = _canonical_event_bytes(
                    seq, ts, prev_hash, actor, action, target, decision, detail
                )
                record_hash = hashlib.sha256(canonical).digest()
                conn.execute(
                    """
                    INSERT INTO audit_events
                        (seq, timestamp, prev_hash, record_hash, actor, action, target, decision, detail)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (seq, ts, prev_hash, record_hash, actor, action, target, decision, detail),
                )
                conn.commit()
            self._write_external_head(seq, record_hash)
            return seq

    def create_checkpoint(self, signer_secret_key: bytes, signer_id: str = "admin") -> int:
        """Sign the current chain head with ML-DSA-65 and store a checkpoint."""
        ts = int(self._clock())
        with state_lock(self._lock_dir):
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT seq, record_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                if row is None:
                    seq = 0
                    head_hash = ZERO_HASH
                else:
                    seq = int(row["seq"])
                    head_hash = bytes(row["record_hash"])

                msg = _checkpoint_signing_bytes(seq, head_hash)
                sig = sign_message(signer_secret_key, msg, domain=AUDIT_CHECKPOINT_DOMAIN)
                conn.execute(
                    """
                    INSERT INTO audit_checkpoints (seq, head_hash, signer_id, signature, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (seq, head_hash, signer_id, sig, ts),
                )
                conn.commit()
            return seq

    def fetch_events(self) -> list[dict]:
        with state_lock(self._lock_dir):
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT seq, timestamp, prev_hash, record_hash, actor, action, target, decision, detail "
                    "FROM audit_events ORDER BY seq ASC"
                ).fetchall()
                return [
                    {
                        "seq": int(r["seq"]),
                        "timestamp": int(r["timestamp"]),
                        "prev_hash_hex": bytes(r["prev_hash"]).hex(),
                        "record_hash_hex": bytes(r["record_hash"]).hex(),
                        "actor": r["actor"],
                        "action": r["action"],
                        "target": r["target"],
                        "decision": r["decision"],
                        "detail": r["detail"],
                    }
                    for r in rows
                ]

    def verify(self, verifier_public_key: bytes | None = None) -> VerifyResult:
        """Walk the full hash chain, verify checkpoints, and check external head hash."""
        with state_lock(self._lock_dir):
            try:
                ext = json.loads(self.external_head_path.read_text(encoding="utf-8"))
                ext_seq = int(ext["seq"])
                ext_hash = bytes.fromhex(ext["head_hash_hex"])
            except Exception:
                return VerifyResult(
                    valid=False,
                    event_count=0,
                    checkpoint_count=0,
                    head_seq=0,
                    head_hash_hex=ZERO_HASH.hex(),
                    first_bad_seq=0,
                    reason="External head hash missing or unreadable",
                )

            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT seq, timestamp, prev_hash, record_hash, actor, action, target, decision, detail "
                    "FROM audit_events ORDER BY seq ASC"
                ).fetchall()

                expected_seq = 0
                prev_hash = ZERO_HASH
                seq_to_hash: dict[int, bytes] = {0: ZERO_HASH}

                for r in rows:
                    expected_seq += 1
                    seq = int(r["seq"])
                    if seq != expected_seq:
                        return VerifyResult(
                            valid=False,
                            event_count=len(rows),
                            checkpoint_count=0,
                            head_seq=expected_seq - 1,
                            head_hash_hex=prev_hash.hex(),
                            first_bad_seq=expected_seq,
                            reason=f"Sequence gap or out-of-order row: expected {expected_seq}, got {seq}",
                        )
                    if bytes(r["prev_hash"]) != prev_hash:
                        return VerifyResult(
                            valid=False,
                            event_count=len(rows),
                            checkpoint_count=0,
                            head_seq=seq - 1,
                            head_hash_hex=prev_hash.hex(),
                            first_bad_seq=seq,
                            reason=f"prev_hash mismatch at seq {seq}",
                        )
                    canonical = _canonical_event_bytes(
                        seq,
                        int(r["timestamp"]),
                        prev_hash,
                        r["actor"],
                        r["action"],
                        r["target"],
                        r["decision"],
                        r["detail"],
                    )
                    recomputed = hashlib.sha256(canonical).digest()
                    if bytes(r["record_hash"]) != recomputed:
                        return VerifyResult(
                            valid=False,
                            event_count=len(rows),
                            checkpoint_count=0,
                            head_seq=seq - 1,
                            head_hash_hex=prev_hash.hex(),
                            first_bad_seq=seq,
                            reason=f"record_hash mismatch at seq {seq}",
                        )
                    prev_hash = recomputed
                    seq_to_hash[seq] = recomputed

                checkpoints = conn.execute(
                    "SELECT seq, head_hash, signer_id, signature FROM audit_checkpoints ORDER BY seq ASC"
                ).fetchall()
                for cp in checkpoints:
                    cp_seq = int(cp["seq"])
                    cp_hash = bytes(cp["head_hash"])
                    if cp_seq not in seq_to_hash or seq_to_hash[cp_seq] != cp_hash:
                        return VerifyResult(
                            valid=False,
                            event_count=len(rows),
                            checkpoint_count=len(checkpoints),
                            head_seq=expected_seq,
                            head_hash_hex=prev_hash.hex(),
                            first_bad_seq=cp_seq,
                            reason=f"Checkpoint head_hash mismatch at seq {cp_seq}",
                        )
                    if verifier_public_key is not None:
                        msg = _checkpoint_signing_bytes(cp_seq, cp_hash)
                        if not verify_signature(
                            verifier_public_key,
                            msg,
                            bytes(cp["signature"]),
                            domain=AUDIT_CHECKPOINT_DOMAIN,
                        ):
                            return VerifyResult(
                                valid=False,
                                event_count=len(rows),
                                checkpoint_count=len(checkpoints),
                                head_seq=expected_seq,
                                head_hash_hex=prev_hash.hex(),
                                first_bad_seq=cp_seq,
                                reason=f"Invalid checkpoint signature at seq {cp_seq}",
                            )

                if expected_seq != ext_seq or prev_hash != ext_hash:
                    return VerifyResult(
                        valid=False,
                        event_count=len(rows),
                        checkpoint_count=len(checkpoints),
                        head_seq=expected_seq,
                        head_hash_hex=prev_hash.hex(),
                        first_bad_seq=min(expected_seq, ext_seq),
                        reason="Database head does not match external head hash (possible rewrite or truncation)",
                    )

                return VerifyResult(
                    valid=True,
                    event_count=len(rows),
                    checkpoint_count=len(checkpoints),
                    head_seq=expected_seq,
                    head_hash_hex=prev_hash.hex(),
                )
