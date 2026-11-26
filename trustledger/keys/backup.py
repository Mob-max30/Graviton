"""Encrypted backup and restore with recomputed Merkle verification and persistent rollback rejection."""
import datetime
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional

import pqcrypto.sign.ml_dsa_65 as ml_dsa
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class BackupError(ValueError):
    """Raised when backup verification or restore fails."""


def compute_merkle_root(leaf_hashes: List[str]) -> str:
    """Compute Merkle tree root hex string from list of leaf hex hashes."""
    if not leaf_hashes:
        return hashlib.sha256(b"EMPTY_MERKLE_TREE").hexdigest()

    current_level = [bytes.fromhex(h) for h in leaf_hashes]
    while len(current_level) > 1:
        if len(current_level) % 2 != 0:
            current_level.append(current_level[-1])
        next_level = []
        for i in range(0, len(current_level), 2):
            combined = hashlib.sha256(current_level[i] + current_level[i + 1]).digest()
            next_level.append(combined)
        current_level = next_level

    return current_level[0].hex()


class BackupManifest(NamedTuple):
    backup_counter: int
    suite_id: int
    created_at_utc: str
    key_ids: List[str]
    entry_hashes: List[str]
    merkle_root: str
    signature_hex: str


class BackupManager:
    """Creates encrypted backups and performs strict pre-restore Merkle and signature validation."""

    def __init__(
        self,
        admin_dsa_sk: bytes,
        admin_dsa_pk: bytes,
        backup_aead_key: Optional[bytes] = None,
        counter_path: Optional[Path] = None,
    ):
        self.admin_dsa_sk = admin_dsa_sk
        self.admin_dsa_pk = admin_dsa_pk
        self.backup_key = backup_aead_key or secrets.token_bytes(32)
        self._aead = ChaCha20Poly1305(self.backup_key)
        self.counter_path = Path(counter_path) if counter_path is not None else None
        self.last_restored_counter = self._load_counter()

    def restore_to_store(self, bundle: Dict[str, Any], key_store: Any) -> List[Dict[str, Any]]:
        """Verify backup integrity first; only load into key_store if all checks pass."""
        records = self.verify_and_restore(bundle)
        for rec in records:
            key_store.load_verified_record(rec)
        return records

    def _load_counter(self) -> int:
        if self.counter_path is not None and self.counter_path.exists():
            data = json.loads(self.counter_path.read_text(encoding="utf-8"))
            return int(data.get("last_restored_counter", 0))
        return 0

    def _save_counter(self, counter: int) -> None:
        if self.counter_path is None:
            return
        self.counter_path.parent.mkdir(parents=True, exist_ok=True)
        raw = json.dumps({"last_restored_counter": counter}).encode("utf-8")
        tmp = self.counter_path.with_name(f"{self.counter_path.name}.tmp.{secrets.token_hex(4)}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(str(tmp), flags, 0o600) if sys.platform != "win32" else os.open(str(tmp), flags)
        try:
            os.write(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self.counter_path)

    def create_backup(self, backup_counter: int, key_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create an encrypted backup bundle with signed Merkle manifest."""
        encrypted_entries: List[Dict[str, Any]] = []
        entry_hashes: List[str] = []
        key_ids: List[str] = []

        for rec in key_records:
            k_id = rec["key_id"]
            key_ids.append(k_id)
            payload = json.dumps(rec, sort_keys=True).encode("utf-8")
            nonce = secrets.token_bytes(12)
            ct = self._aead.encrypt(nonce, payload, f"backup-counter:{backup_counter}".encode("utf-8"))
            blob = nonce + ct
            e_hash = hashlib.sha256(blob).hexdigest()
            entry_hashes.append(e_hash)
            encrypted_entries.append({"key_id": k_id, "blob_hex": blob.hex(), "hash": e_hash})

        merkle_root = compute_merkle_root(entry_hashes)
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        manifest_data = {
            "backup_counter": backup_counter,
            "created_at_utc": now_utc,
            "entry_hashes": entry_hashes,
            "key_ids": key_ids,
            "merkle_root": merkle_root,
            "suite_id": 1,
        }
        manifest_bytes = json.dumps(manifest_data, sort_keys=True).encode("utf-8")
        sig = ml_dsa.sign(self.admin_dsa_sk, manifest_bytes)

        return {
            "manifest": manifest_data,
            "signature_hex": sig.hex(),
            "entries": encrypted_entries,
        }

    def verify_and_restore(self, backup_bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Verify signature, recomputed entry hashes, Merkle root, counter, and decrypt entries."""
        manifest = backup_bundle.get("manifest", {})
        sig_hex = backup_bundle.get("signature_hex", "")
        entries = backup_bundle.get("entries", [])

        manifest_bytes = json.dumps(manifest, sort_keys=True).encode("utf-8")
        try:
            sig = bytes.fromhex(sig_hex)
            if not ml_dsa.verify(self.admin_dsa_pk, manifest_bytes, sig):
                raise BackupError("REPLACED_OR_INVALID_SIGNATURE: Manifest signature verification failed")
        except BackupError:
            raise
        except Exception as err:
            raise BackupError("REPLACED_OR_INVALID_SIGNATURE: Manifest signature invalid") from err

        counter = int(manifest.get("backup_counter", 0))
        if counter <= self.last_restored_counter:
            raise BackupError(
                f"ROLLBACK_REJECTED: Backup counter {counter} <= last restored {self.last_restored_counter}"
            )

        # Recompute SHA-256 directly from each blob_hex rather than trusting e["hash"]
        recomputed_hashes: List[str] = []
        raw_blobs: List[bytes] = []
        for e in entries:
            try:
                raw_blob = bytes.fromhex(e["blob_hex"])
            except (KeyError, ValueError) as err:
                raise BackupError("CORRUPT_ENTRY: Invalid entry blob hex") from err
            recomputed = hashlib.sha256(raw_blob).hexdigest()
            if e.get("hash") != recomputed:
                raise BackupError("ENTRY_HASH_MISMATCH: Entry blob does not match declared entry hash")
            recomputed_hashes.append(recomputed)
            raw_blobs.append(raw_blob)

        if recomputed_hashes != manifest.get("entry_hashes", []):
            raise BackupError("ENTRY_HASH_MISMATCH: Entry order or contents do not match manifest")

        actual_merkle = compute_merkle_root(recomputed_hashes)
        if actual_merkle != manifest.get("merkle_root"):
            raise BackupError(
                f"MERKLE_ROOT_MISMATCH: Computed {actual_merkle} != manifest {manifest.get('merkle_root')}"
            )

        restored: List[Dict[str, Any]] = []
        for e, raw_blob in zip(entries, raw_blobs):
            if len(raw_blob) < 12:
                raise BackupError("CORRUPT_ENTRY: Entry blob too short")
            nonce, ct = raw_blob[:12], raw_blob[12:]
            try:
                pt = self._aead.decrypt(nonce, ct, f"backup-counter:{counter}".encode("utf-8"))
                restored.append(json.loads(pt.decode("utf-8")))
            except Exception as err:
                raise BackupError(f"ENTRY_DECRYPTION_FAILED: Failed to decrypt key {e.get('key_id')}") from err

        self.last_restored_counter = counter
        self._save_counter(counter)
        return restored
