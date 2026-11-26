"""Encrypted backup integrity, Merkle root verification, and anti-rollback tests."""
import pytest
import pqcrypto.sign.ml_dsa_65 as ml_dsa

from trustledger.keys.backup import BackupError, BackupManager


def test_encrypted_backup_roundtrip():
    pk, sk = ml_dsa.generate_keypair()
    mgr = BackupManager(admin_dsa_sk=sk, admin_dsa_pk=pk)

    entries = [
        {"key_id": "key-01", "epoch": 1, "state": "ACTIVE"},
        {"key_id": "key-02", "epoch": 2, "state": "PENDING"},
    ]

    bundle = mgr.create_backup(backup_counter=101, key_records=entries)
    restored = mgr.verify_and_restore(bundle)
    assert len(restored) == 2
    assert restored[0]["key_id"] == "key-01"


def test_backup_tampering_and_rollback_rejection():
    pk, sk = ml_dsa.generate_keypair()
    mgr = BackupManager(admin_dsa_sk=sk, admin_dsa_pk=pk)

    entries = [{"key_id": "key-01", "epoch": 1, "state": "ACTIVE"}]
    bundle = mgr.create_backup(backup_counter=200, key_records=entries)

    # 1. Successful restore
    mgr.verify_and_restore(bundle)

    # 2. Rollback attempt (same or lower counter)
    with pytest.raises(BackupError, match="ROLLBACK_REJECTED"):
        mgr.verify_and_restore(bundle)

    # 3. Signature tampering on fresh bundle
    bundle2 = mgr.create_backup(backup_counter=201, key_records=entries)
    bundle2["signature_hex"] = "00" * 3309
    with pytest.raises(BackupError, match="REPLACED_OR_INVALID_SIGNATURE"):
        mgr.verify_and_restore(bundle2)

    # 4. Entry corruption / bit flip with unchanged declared hash (must fail ENTRY_HASH_MISMATCH before AEAD)
    bundle3 = mgr.create_backup(backup_counter=202, key_records=entries)
    bad_blob = bytearray.fromhex(bundle3["entries"][0]["blob_hex"])
    bad_blob[15] ^= 0xFF
    bundle3["entries"][0]["blob_hex"] = bad_blob.hex()
    with pytest.raises(BackupError, match="ENTRY_HASH_MISMATCH|MERKLE_ROOT_MISMATCH"):
        mgr.verify_and_restore(bundle3)


def test_unverified_backup_never_reaches_key_store():
    """Part 3.5: Spy key store receives zero calls when backup signature, Merkle root, or AEAD tag fails."""
    class SpyKeyStore:
        def __init__(self) -> None:
            self.loaded: list[dict] = []

        def load_verified_record(self, rec: dict) -> None:
            self.loaded.append(rec)

    pk, sk = ml_dsa.generate_keypair()
    mgr = BackupManager(admin_dsa_sk=sk, admin_dsa_pk=pk)
    entries = [{"key_id": "key-spy-1", "epoch": 1, "state": "ACTIVE"}]

    # 1. Tampered signature -> BackupError, spy store untouched
    bad_sig_bundle = mgr.create_backup(backup_counter=10, key_records=entries)
    bad_sig_bundle["signature_hex"] = "ff" * 3309
    spy = SpyKeyStore()
    with pytest.raises(BackupError):
        mgr.restore_to_store(bad_sig_bundle, spy)
    assert spy.loaded == []

    # 2. Tampered ciphertext -> BackupError, spy store untouched
    bad_ct_bundle = mgr.create_backup(backup_counter=11, key_records=entries)
    bad_blob = bytearray.fromhex(bad_ct_bundle["entries"][0]["blob_hex"])
    bad_blob[-1] ^= 0x01
    bad_ct_bundle["entries"][0]["blob_hex"] = bad_blob.hex()
    with pytest.raises(BackupError):
        mgr.restore_to_store(bad_ct_bundle, spy)
    assert spy.loaded == []

    # 3. Valid backup -> spy store receives verified record
    good_bundle = mgr.create_backup(backup_counter=12, key_records=entries)
    mgr.restore_to_store(good_bundle, spy)
    assert len(spy.loaded) == 1
    assert spy.loaded[0]["key_id"] == "key-spy-1"
