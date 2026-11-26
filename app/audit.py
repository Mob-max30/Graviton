"""Tamper-evident, hash-chained, ML-DSA-signed audit logger and verifier."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from app.crypto_engine import canonical_json, sha256_hex, sign_data, verify_signature
from app.db import Database


class AuditLogger:
    """Append-only canonical JSON audit logger with hash-chaining and ML-DSA-65 signatures."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def log_event(
        self,
        org_id: str,
        actor_id: str,
        service: str,
        action: str,
        target: str,
        context: dict[str, Any] | None = None,
        timestamp: float | None = None,
    ) -> dict[str, Any]:
        """Append a signed, hash-chained event. Immune to newline/actor injection."""
        now = time.time()
        ts = float(timestamp) if timestamp is not None else now
        event_id = f"evt_{uuid.uuid4().hex[:16]}"
        ctx = context or {}
        # Ensure actor_id, service, action, target are strictly bound as separate JSON fields
        ctx_json = json.dumps(ctx, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

        with self.db.tx() as conn:
            org_row = conn.execute(
                "SELECT authority_sign_sk FROM organizations WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            if not org_row:
                raise ValueError(f"Unknown organization: {org_id}")

            last_row = conn.execute(
                "SELECT entry_hash FROM audit_logs WHERE org_id = ? ORDER BY seq DESC LIMIT 1",
                (org_id,),
            ).fetchone()
            prev_hash = last_row["entry_hash"] if last_row else "GENESIS"

            payload = {
                "event_id": event_id,
                "org_id": org_id,
                "timestamp": round(ts, 6),
                "actor_id": str(actor_id),
                "service": str(service),
                "action": str(action),
                "target": str(target),
                "context": json.loads(ctx_json),
                "prev_hash": prev_hash,
            }
            entry_hash = sha256_hex(canonical_json(payload))
            sig = sign_data(bytes(org_row["authority_sign_sk"]), entry_hash.encode("ascii"))

            conn.execute(
                """
                INSERT INTO audit_logs (
                    event_id, org_id, timestamp, received_at,
                    actor_id, service, action, target, context_json,
                    prev_hash, entry_hash, signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    org_id,
                    round(ts, 6),
                    now,
                    str(actor_id),
                    str(service),
                    str(action),
                    str(target),
                    ctx_json,
                    prev_hash,
                    entry_hash,
                    sig,
                ),
            )

        return {
            "event_id": event_id,
            "org_id": org_id,
            "timestamp": round(ts, 6),
            "received_at": now,
            "actor_id": str(actor_id),
            "service": str(service),
            "action": str(action),
            "target": str(target),
            "context": json.loads(ctx_json),
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
        }

    def verify_chain(self, org_id: str) -> dict[str, Any]:
        """Verify hash chain and ML-DSA-65 signature for every log entry of an org."""
        with self.db.read() as conn:
            org_row = conn.execute(
                "SELECT authority_sign_pk FROM organizations WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            if not org_row:
                return {"valid": False, "checked_count": 0, "first_broken_seq": None, "reason": "Organization not found"}

            pk = bytes(org_row["authority_sign_pk"])
            rows = conn.execute(
                "SELECT * FROM audit_logs WHERE org_id = ? ORDER BY seq ASC",
                (org_id,),
            ).fetchall()

        expected_prev = "GENESIS"
        for idx, row in enumerate(rows, start=1):
            if row["prev_hash"] != expected_prev:
                return {
                    "valid": False,
                    "checked_count": idx - 1,
                    "first_broken_seq": row["seq"],
                    "reason": f"prev_hash mismatch at seq {row['seq']}",
                }
            try:
                ctx_obj = json.loads(row["context_json"])
            except json.JSONDecodeError:
                return {
                    "valid": False,
                    "checked_count": idx - 1,
                    "first_broken_seq": row["seq"],
                    "reason": f"Malformed context_json at seq {row['seq']}",
                }

            payload = {
                "event_id": row["event_id"],
                "org_id": row["org_id"],
                "timestamp": row["timestamp"],
                "actor_id": row["actor_id"],
                "service": row["service"],
                "action": row["action"],
                "target": row["target"],
                "context": ctx_obj,
                "prev_hash": row["prev_hash"],
            }
            recomputed = sha256_hex(canonical_json(payload))
            if recomputed != row["entry_hash"]:
                return {
                    "valid": False,
                    "checked_count": idx - 1,
                    "first_broken_seq": row["seq"],
                    "reason": f"entry_hash mismatch at seq {row['seq']}",
                }
            if not verify_signature(pk, recomputed.encode("ascii"), bytes(row["signature"])):
                return {
                    "valid": False,
                    "checked_count": idx - 1,
                    "first_broken_seq": row["seq"],
                    "reason": f"ML-DSA signature invalid at seq {row['seq']}",
                }
            expected_prev = row["entry_hash"]

        return {
            "valid": True,
            "checked_count": len(rows),
            "first_broken_seq": None,
            "reason": None,
        }

    def list_events(self, org_id: str, limit: int = 100) -> list[dict[str, Any]]:
        """Return recent audit events."""
        with self.db.read() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_logs WHERE org_id = ? ORDER BY seq DESC LIMIT ?",
                (org_id, limit),
            ).fetchall()
        return [
            {
                "seq": r["seq"],
                "event_id": r["event_id"],
                "timestamp": r["timestamp"],
                "received_at": r["received_at"],
                "actor_id": r["actor_id"],
                "service": r["service"],
                "action": r["action"],
                "target": r["target"],
                "context": json.loads(r["context_json"]),
                "prev_hash": r["prev_hash"],
                "entry_hash": r["entry_hash"],
            }
            for r in rows
        ]
