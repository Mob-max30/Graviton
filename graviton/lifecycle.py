"""Key lifecycle management: rotation with grace-period cutoff, multi-node revocation,
device re-enrollment, WAL crash recovery with anti-rollback, and encrypted/signed backups.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from graviton.crypto import (
    SignKeyPair,
    aead_decrypt,
    aead_encrypt,
    generate_sign_keypair,
    sign_message,
    verify_signature,
)

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _validate_identifier(val: str, kind: str = "identifier") -> str:
    if not _SAFE_ID_RE.match(val) or ".." in val:
        raise ValueError(f"Invalid {kind}: {val!r}")
    return val


@dataclass
class KeyRecord:
    key_id: str
    owner: str
    version: int
    material_hash: str
    created_at: float
    expires_at: Optional[float] = None
    revoked: bool = False


class NodeVerifier:
    """Cluster node enforcing key rotation cutoffs and revocations."""

    def __init__(self, node_id: str, propagation_delay_ms: float = 0.0) -> None:
        self.node_id = _validate_identifier(node_id, "node_id")
        self.propagation_delay_ms = propagation_delay_ms
        self.active_keys: Dict[str, KeyRecord] = {}
        self.revoked_keys: Set[str] = set()
        self.grace_cutoffs: Dict[str, float] = {}
        self.last_revocation_at: Dict[str, float] = {}

    def apply_key(self, record: KeyRecord) -> None:
        if record.key_id in self.revoked_keys:
            return
        self.active_keys[record.key_id] = record

    def set_cutoff(self, old_key_id: str, cutoff_ts: float) -> None:
        self.grace_cutoffs[old_key_id] = cutoff_ts

    def revoke_key(self, key_id: str) -> None:
        if self.propagation_delay_ms > 0:
            time.sleep(self.propagation_delay_ms / 1000.0)
        self.revoked_keys.add(key_id)
        self.last_revocation_at[key_id] = time.perf_counter()
        if key_id in self.active_keys:
            self.active_keys[key_id].revoked = True

    def is_key_authorized(self, key_id: str, now: Optional[float] = None) -> Tuple[bool, str]:
        ts = now if now is not None else time.time()
        if key_id in self.revoked_keys:
            return False, "key_revoked"
        rec = self.active_keys.get(key_id)
        if not rec or rec.revoked:
            return False, "key_unknown_or_revoked"
        cutoff = self.grace_cutoffs.get(key_id)
        if cutoff is not None and ts > cutoff:
            return False, "key_past_rotation_cutoff"
        return True, "ok"


class KeyLifecycleManager:
    """Manages key rotation, multi-node revocation, crash recovery, and verified backups."""

    def __init__(self, state_dir: str | Path, grace_seconds: float = 5.0) -> None:
        self.state_dir = Path(state_dir).resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.wal_path = self.state_dir / "wal.jsonl"
        self.state_path = self.state_dir / "state.json"
        self.authority_path = self.state_dir / "backup_authority.json"
        self.grace_seconds = grace_seconds

        self.backup_sign_kp, self.backup_enc_key = self._load_or_create_authority()
        self.epoch: int = 0
        self.keys: Dict[str, KeyRecord] = {}
        self.revoked_keys: Set[str] = set()
        self.cutoffs: Dict[str, float] = {}
        self.nodes: Dict[str, NodeVerifier] = {}
        self._load_or_recover()

    def _load_or_create_authority(self) -> Tuple[SignKeyPair, bytes]:
        if self.authority_path.exists():
            data = json.loads(self.authority_path.read_text(encoding="utf-8"))
            kp = SignKeyPair(
                public_key=bytes.fromhex(data["sign_pk"]),
                secret_key=bytes.fromhex(data["sign_sk"]),
            )
            enc_key = bytes.fromhex(data["enc_key"])
            return kp, enc_key
        kp = generate_sign_keypair()
        enc_key = os.urandom(32)
        tmp = self.authority_path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(
                {
                    "sign_pk": kp.public_key.hex(),
                    "sign_sk": kp.secret_key.hex(),
                    "enc_key": enc_key.hex(),
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        os.replace(tmp, self.authority_path)
        return kp, enc_key

    def register_node(self, node: NodeVerifier) -> None:
        self.nodes[node.node_id] = node
        for rec in self.keys.values():
            node.apply_key(rec)
        for kid, cutoff in self.cutoffs.items():
            node.set_cutoff(kid, cutoff)
        for rk in self.revoked_keys:
            node.revoke_key(rk)

    def enroll_user(self, owner: str, key_id: Optional[str] = None, version: int = 1) -> KeyRecord:
        _validate_identifier(owner, "owner")
        kid = _validate_identifier(key_id, "key_id") if key_id else f"{owner}-v{version}-{os.urandom(4).hex()}"
        mat_hash = hashlib.sha256(os.urandom(32)).hexdigest()
        rec = KeyRecord(
            key_id=kid,
            owner=owner,
            version=version,
            material_hash=mat_hash,
            created_at=time.time(),
        )
        self.epoch += 1
        self._append_wal({"op": "commit_key", "epoch": self.epoch, "record": rec.__dict__})
        self.keys[kid] = rec
        for node in self.nodes.values():
            node.apply_key(rec)
        self._persist_state()
        return rec

    def rotate_key(
        self,
        old_key_id: str,
        now: Optional[float] = None,
        simulate_crash_before_commit: bool = False,
    ) -> Optional[KeyRecord]:
        """Rotate a key with atomic WAL. If interrupted before commit, recovery
        preserves the previous consistent key version.
        """
        ts = now if now is not None else time.time()
        old_rec = self.keys.get(old_key_id)
        if not old_rec or old_key_id in self.revoked_keys:
            raise ValueError("Cannot rotate unknown or revoked key")

        new_kid = f"{old_rec.owner}-v{old_rec.version + 1}-{os.urandom(4).hex()}"
        new_rec = KeyRecord(
            key_id=new_kid,
            owner=old_rec.owner,
            version=old_rec.version + 1,
            material_hash=hashlib.sha256(os.urandom(32)).hexdigest(),
            created_at=ts,
        )
        self._append_wal({"op": "prepare_rotation", "old_key_id": old_key_id, "new_record": new_rec.__dict__})
        if simulate_crash_before_commit:
            return None

        cutoff = ts + self.grace_seconds
        self.epoch += 1
        self._append_wal(
            {
                "op": "commit_rotation",
                "epoch": self.epoch,
                "old_key_id": old_key_id,
                "new_record": new_rec.__dict__,
                "cutoff": cutoff,
            }
        )
        self.keys[new_kid] = new_rec
        self.cutoffs[old_key_id] = cutoff
        for node in self.nodes.values():
            node.apply_key(new_rec)
            node.set_cutoff(old_key_id, cutoff)
        self._persist_state()
        return new_rec

    def revoke_and_propagate(self, key_id: str) -> float:
        """Revoke key across all nodes and return total time until last node enforces it (ms)."""
        t0 = time.perf_counter()
        self.epoch += 1
        self._append_wal({"op": "revoke_key", "epoch": self.epoch, "key_id": key_id})
        self.revoked_keys.add(key_id)
        if key_id in self.keys:
            self.keys[key_id].revoked = True
        for node in self.nodes.values():
            node.revoke_key(key_id)
        self._persist_state()
        return (time.perf_counter() - t0) * 1000.0

    def reenroll_after_device_loss(self, owner: str, lost_key_id: str) -> Tuple[KeyRecord, float]:
        """Revoke lost device key across nodes and issue a fresh key for the owner."""
        prop_ms = self.revoke_and_propagate(lost_key_id)
        old_ver = self.keys[lost_key_id].version if lost_key_id in self.keys else 0
        new_rec = self.enroll_user(owner, version=old_ver + 1)
        return new_rec, prop_ms

    def create_backup(self) -> bytes:
        """Create an AES-256-GCM encrypted, SHA-256 hashed, ML-DSA-65 signed backup."""
        plaintext = json.dumps(
            {
                "epoch": self.epoch,
                "keys": {k: v.__dict__ for k, v in self.keys.items()},
                "revoked_keys": sorted(self.revoked_keys),
                "cutoffs": self.cutoffs,
            },
            sort_keys=True,
        ).encode()
        aad = f"graviton-backup-epoch-{self.epoch}".encode()
        nonce, ct = aead_encrypt(self.backup_enc_key, plaintext, aad)
        bundle = json.dumps(
            {
                "epoch": self.epoch,
                "nonce": nonce.hex(),
                "ciphertext": ct.hex(),
            },
            sort_keys=True,
        ).encode()
        digest = hashlib.sha256(bundle).hexdigest()
        sig = sign_message(self.backup_sign_kp.secret_key, bundle)
        envelope = {
            "bundle": bundle.decode(),
            "sha256": digest,
            "sig": sig.hex(),
        }
        return json.dumps(envelope, sort_keys=True).encode()

    def restore_backup(self, backup_blob: bytes, allow_rollback: bool = False) -> None:
        """Verify backup SHA-256, ML-DSA-65 signature, AES-GCM tag, and epoch before restoring."""
        try:
            env = json.loads(backup_blob.decode())
            bundle_bytes = env["bundle"].encode()
            expected_hash = env["sha256"]
            sig = bytes.fromhex(env["sig"])
        except Exception as exc:
            raise ValueError(f"Damaged backup format: {exc}") from exc

        if hashlib.sha256(bundle_bytes).hexdigest() != expected_hash:
            raise ValueError("Backup integrity check failed: SHA-256 mismatch")
        if not verify_signature(self.backup_sign_kp.public_key, bundle_bytes, sig):
            raise ValueError("Backup integrity check failed: ML-DSA-65 signature invalid")

        try:
            bundle = json.loads(bundle_bytes.decode())
            b_epoch = int(bundle["epoch"])
            if not allow_rollback and b_epoch < self.epoch:
                raise ValueError(
                    f"Rollback rejected: backup epoch {b_epoch} < current epoch {self.epoch}"
                )
            aad = f"graviton-backup-epoch-{b_epoch}".encode()
            plaintext = aead_decrypt(
                self.backup_enc_key,
                bytes.fromhex(bundle["nonce"]),
                bytes.fromhex(bundle["ciphertext"]),
                aad,
            )
            data = json.loads(plaintext.decode())
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError(f"Damaged or tampered backup payload: {exc}") from exc

        self.epoch = b_epoch
        self.keys = {k: KeyRecord(**v) for k, v in data["keys"].items()}
        self.revoked_keys = set(data["revoked_keys"])
        self.cutoffs = {k: float(v) for k, v in data.get("cutoffs", {}).items()}
        for rk in self.revoked_keys:
            if rk in self.keys:
                self.keys[rk].revoked = True
        for node in self.nodes.values():
            for rec in self.keys.values():
                node.apply_key(rec)
            for kid, cutoff in self.cutoffs.items():
                node.set_cutoff(kid, cutoff)
            for rk in self.revoked_keys:
                node.revoke_key(rk)
        self._persist_state()

    def _append_wal(self, entry: dict) -> None:
        raw = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
        checksum = hashlib.sha256(raw).hexdigest()
        line = json.dumps({"checksum": checksum, "entry": entry}, sort_keys=True)
        with open(self.wal_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())

    def _persist_state(self) -> None:
        tmp = self.state_path.with_suffix(".tmp")
        data = {
            "epoch": self.epoch,
            "keys": {k: v.__dict__ for k, v in self.keys.items()},
            "revoked_keys": sorted(self.revoked_keys),
            "cutoffs": self.cutoffs,
        }
        tmp.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.state_path)

    def _load_or_recover(self) -> None:
        """Replay committed WAL entries; uncommitted prepare_rotation or truncated
        crash lines are safely rolled back/ignored.
        """
        if self.state_path.exists():
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            self.epoch = int(data.get("epoch", 0))
            self.keys = {k: KeyRecord(**v) for k, v in data.get("keys", {}).items()}
            self.revoked_keys = set(data.get("revoked_keys", []))
            self.cutoffs = {k: float(v) for k, v in data.get("cutoffs", {}).items()}

        if self.wal_path.exists():
            for line in self.wal_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    wrapper = json.loads(line)
                    entry = wrapper["entry"]
                    raw = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
                    if hashlib.sha256(raw).hexdigest() != wrapper["checksum"]:
                        continue
                except Exception:
                    # Truncated/corrupted trailing WAL line from simulated crash
                    continue

                op = entry.get("op")
                if op == "commit_key":
                    rec = KeyRecord(**entry["record"])
                    self.keys[rec.key_id] = rec
                    self.epoch = max(self.epoch, int(entry.get("epoch", self.epoch)))
                elif op == "commit_rotation":
                    rec = KeyRecord(**entry["new_record"])
                    self.keys[rec.key_id] = rec
                    self.cutoffs[entry["old_key_id"]] = float(entry["cutoff"])
                    self.epoch = max(self.epoch, int(entry.get("epoch", self.epoch)))
                elif op == "revoke_key":
                    kid = entry["key_id"]
                    self.revoked_keys.add(kid)
                    if kid in self.keys:
                        self.keys[kid].revoked = True
                    self.epoch = max(self.epoch, int(entry.get("epoch", self.epoch)))
        for rk in self.revoked_keys:
            if rk in self.keys:
                self.keys[rk].revoked = True
