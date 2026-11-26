"""Tamper-evident, injection-safe, ML-DSA-65 signed append-only audit log."""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from graviton.crypto import SignKeyPair, generate_sign_keypair, sign_message, verify_signature

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _sanitize_text(val: str) -> str:
    """Neutralize control characters, ANSI escapes, and newlines so user text
    cannot forge log boundaries or alter recorded actors.
    """
    cleaned = _ANSI_RE.sub("", val)
    return (
        cleaned.replace("\\", "\\\\")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("\t", "\\t")
        .replace("\x00", "")
    )


@dataclass
class LogEntry:
    seq: int
    timestamp: float
    actor: str
    action: str
    service: str
    detail: str
    prev_hash: str
    entry_hash: str
    sig: str


class AuditLog:
    def __init__(self, log_path: str | Path, sign_kp: Optional[SignKeyPair] = None) -> None:
        self.log_path = Path(log_path).resolve()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.pub_path = self.log_path.with_suffix(".pub.json")

        if sign_kp is not None:
            self.sign_kp = sign_kp
            self._persist_pubkey()
        elif self.pub_path.exists():
            # Load existing public key for verification; generate new signing kp only if empty
            self.sign_kp = generate_sign_keypair()
        else:
            self.sign_kp = generate_sign_keypair()
            self._persist_pubkey()

        self.entries: List[LogEntry] = []
        if self.log_path.exists():
            self._load()

    def _persist_pubkey(self) -> None:
        self.pub_path.write_text(
            json.dumps({"algorithm": self.sign_kp.algorithm, "public_key": self.sign_kp.public_key.hex()}),
            encoding="utf-8",
        )

    def _load(self) -> None:
        self.entries.clear()
        for line in self.log_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                self.entries.append(LogEntry(**json.loads(line)))

    def append(
        self,
        actor: str,
        action: str,
        service: str,
        detail: str = "",
        timestamp: Optional[float] = None,
    ) -> LogEntry:
        seq = len(self.entries)
        prev_hash = self.entries[-1].entry_hash if self.entries else "0" * 64
        ts = timestamp if timestamp is not None else time.time()
        clean_actor = _sanitize_text(actor)
        clean_action = _sanitize_text(action)
        clean_service = _sanitize_text(service)
        clean_detail = _sanitize_text(detail)

        body = {
            "seq": seq,
            "timestamp": ts,
            "actor": clean_actor,
            "action": clean_action,
            "service": clean_service,
            "detail": clean_detail,
            "prev_hash": prev_hash,
        }
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        entry_hash = hashlib.sha256(canonical).hexdigest()
        sig = sign_message(self.sign_kp.secret_key, entry_hash.encode()).hex()

        entry = LogEntry(
            seq=seq,
            timestamp=ts,
            actor=clean_actor,
            action=clean_action,
            service=clean_service,
            detail=clean_detail,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
            sig=sig,
        )
        self.entries.append(entry)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry.__dict__, sort_keys=True) + "\n")
        return entry

    def verify_log(self, from_disk: bool = False, public_key: Optional[bytes] = None) -> Tuple[bool, Optional[str]]:
        """Verify sequence, hash chain, and ML-DSA-65 signatures."""
        pk = public_key
        if pk is None:
            if self.pub_path.exists():
                pk = bytes.fromhex(json.loads(self.pub_path.read_text(encoding="utf-8"))["public_key"])
            else:
                pk = self.sign_kp.public_key

        entries = self.entries
        if from_disk:
            entries = []
            try:
                for line in self.log_path.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        entries.append(LogEntry(**json.loads(line)))
            except Exception as exc:
                return False, f"Corrupted log format on disk: {exc}"

        expected_prev = "0" * 64
        for idx, e in enumerate(entries):
            if e.seq != idx:
                return False, f"Sequence mismatch at index {idx}"
            if e.prev_hash != expected_prev:
                return False, f"Hash chain broken at seq {idx}"
            body = {
                "seq": e.seq,
                "timestamp": e.timestamp,
                "actor": e.actor,
                "action": e.action,
                "service": e.service,
                "detail": e.detail,
                "prev_hash": e.prev_hash,
            }
            canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            if hashlib.sha256(canonical).hexdigest() != e.entry_hash:
                return False, f"Entry hash mismatch at seq {idx}"
            if not verify_signature(pk, e.entry_hash.encode(), bytes.fromhex(e.sig)):
                return False, f"Signature invalid at seq {idx}"
            expected_prev = e.entry_hash
        return True, None
