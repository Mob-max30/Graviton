"""Cryptographically signed, tamper-evident audit logger with periodic and terminal Merkle checkpoints."""
import datetime
import hashlib
import os
from pathlib import Path
from types import TracebackType
from typing import Any, Optional, Type

import pqcrypto.sign.ml_dsa_65 as ml_dsa

from trustledger.core.store import canonical_json_bytes
from trustledger.keys.backup import compute_merkle_root

GENESIS_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
DEFAULT_CHECKPOINT_INTERVAL = int(os.environ.get("TRUSTLEDGER_CHECKPOINT_INTERVAL", "10"))


class SignedAuditLogger:
    """Manages signed append-only logs with periodic and terminal Merkle checkpoints."""

    def __init__(
        self,
        log_path: Path,
        signer_key_id: str,
        signer_sk: bytes,
        checkpoint_interval: int = DEFAULT_CHECKPOINT_INTERVAL,
    ):
        self.log_path = Path(log_path)
        self.signer_key_id = signer_key_id
        self.signer_sk = signer_sk
        self.checkpoint_interval = max(1, checkpoint_interval)
        self.last_seq = 0
        self.last_hash = GENESIS_HASH
        self._current_leaf_hashes: list[str] = []
        self._finalized = False

        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_path.exists():
            self.log_path.touch(mode=0o600, exist_ok=True)

    def append_entry(
        self,
        actor: str,
        action: str,
        target: str,
        decision: str,
        epoch: int = 1,
        payload_data: bytes = b"",
    ) -> dict[str, Any]:
        """Append signed audit entry and generate checkpoint if interval reached."""
        if self._finalized:
            raise RuntimeError("Cannot append to a finalized audit log")

        self.last_seq += 1
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        payload_hash = hashlib.sha256(payload_data).hexdigest()

        entry_core: dict[str, Any] = {
            "action": action,
            "actor": actor,
            "decision": decision,
            "epoch": epoch,
            "payload_hash": payload_hash,
            "prev_hash": self.last_hash,
            "seq": self.last_seq,
            "signer_key_id": self.signer_key_id,
            "target": target,
            "timestamp": now_utc,
        }

        core_bytes = canonical_json_bytes(entry_core)
        entry_hash = hashlib.sha256(core_bytes).hexdigest()
        sig = ml_dsa.sign(self.signer_sk, core_bytes)

        full_entry = dict(entry_core)
        full_entry["entry_hash"] = entry_hash
        full_entry["signature"] = sig.hex()

        self._write_line(full_entry)
        self.last_hash = entry_hash
        self._current_leaf_hashes.append(entry_hash)

        if len(self._current_leaf_hashes) >= self.checkpoint_interval:
            self._write_checkpoint()

        return full_entry

    def _write_checkpoint(self, terminal: bool = False) -> dict[str, Any]:
        """Emit a signed periodic or terminal checkpoint containing the Merkle root."""
        merkle_root = compute_merkle_root(self._current_leaf_hashes)
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        cp_core: dict[str, Any] = {
            "checkpoint_seq": self.last_seq,
            "entry_count": len(self._current_leaf_hashes),
            "last_seq": self.last_seq,
            "merkle_root": merkle_root,
            "op": "terminal_checkpoint" if terminal else "checkpoint",
            "prev_hash": self.last_hash,
            "signer_key_id": self.signer_key_id,
            "timestamp": now_utc,
        }
        cp_bytes = canonical_json_bytes(cp_core)
        sig = ml_dsa.sign(self.signer_sk, cp_bytes)

        full_cp = dict(cp_core)
        full_cp["signature"] = sig.hex()

        self._write_line(full_cp)
        self._current_leaf_hashes = []
        return full_cp

    def finalize(self) -> dict[str, Any]:
        """Emit a signed terminal checkpoint anchoring the final sequence number."""
        if self._finalized:
            raise RuntimeError("Audit log already finalized")
        cp = self._write_checkpoint(terminal=True)
        self._finalized = True
        return cp

    def close(self) -> None:
        if not self._finalized:
            self.finalize()

    def __enter__(self) -> "SignedAuditLogger":
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.close()

    def _write_line(self, data: dict[str, Any]) -> None:
        line_bytes = canonical_json_bytes(data) + b"\n"
        with open(self.log_path, "ab") as f:
            f.write(line_bytes)
            f.flush()
            os.fsync(f.fileno())
