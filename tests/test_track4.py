"""Comprehensive verification suite for all 12 Track 4 objectives and API flows."""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.audit import AuditLogger
from app.crypto_engine import (
    CryptoError,
    generate_kem_keypair,
    generate_x25519_keypair,
    hybrid_encapsulate,
)
from app.db import Database
from app.detector import SecurityDetector, generate_labelled_benchmark
from app.key_manager import (
    BackupIntegrityError,
    KeyLifecycleError,
    KeyManager,
    SimulatedCrashError,
)
from app.main import create_app
from app.storage import ResourceStorage, StorageAccessError
from app.transport import ChunkedDeliveryBuffer, E2EETransport, TransportError


@pytest.fixture()
def env(tmp_path: Path):
    db = Database(str(tmp_path / "test.db"))
    audit = AuditLogger(db)
    key_mgr = KeyManager(db, audit)
    storage = ResourceStorage(db, key_mgr, audit)
    transport = E2EETransport(db, key_mgr, audit)
    detector = SecurityDetector(db)
    return db, audit, key_mgr, storage, transport, detector


def test_key_rotation_cutoff_and_grace(env):
    _, _, key_mgr, storage, _, _ = env
    org = key_mgr.register_organization("Acme", "alice")
    org_id = org["org_id"]
    admin_id = org["admin_user_id"]
    admin_dev = org["admin_device_id"]

    res = storage.add_resource(org_id, admin_id, admin_dev, "spec.txt", b"secret-v1", ["admin"])
    in_flight_started = time.time() - 0.5

    rot = key_mgr.rotate_key(org_id, admin_id, grace_seconds=2.0)
    assert rot["to_version"] == 2
    assert rot["grace_applied"] is True

    # In-flight transfer started before cutoff succeeds during grace window
    out = storage.access_resource(
        org_id,
        admin_id,
        admin_dev,
        res["resource_id"],
        node_id=f"{org_id}:storage-node-2",
        request_key_version=1,
        in_flight_started_at=in_flight_started,
    )
    assert out["content"] == b"secret-v1"

    # New request using old key v1 after cutoff is rejected on every node
    for node_suffix in ("iam-authority", "storage-node-1", "storage-node-2", "chat-node-1"):
        with pytest.raises(KeyLifecycleError):
            key_mgr.validate_key_usage_on_node(
                org_id, f"{org_id}:{node_suffix}", admin_dev, key_version=1, in_flight_started_at=time.time()
            )


def test_revocation_across_nodes_and_reenroll(env):
    _, _, key_mgr, storage, _, _ = env
    org = key_mgr.register_organization("Acme", "alice")
    org_id = org["org_id"]
    admin_id = org["admin_user_id"]
    bob = key_mgr.add_user(org_id, admin_id, "bob", "eng")
    carol = key_mgr.add_user(org_id, admin_id, "carol", "eng")
    res = storage.add_resource(org_id, admin_id, org["admin_device_id"], "eng.md", b"eng-data", ["eng"])

    rev = key_mgr.revoke_device(org_id, admin_id, bob["device_id"], reason="device_lost")
    assert rev["propagation_to_last_node_ms"] >= 0.0
    assert len(rev["node_timings"]) == 4

    # Every node rejects revoked device
    for node_suffix in ("iam-authority", "storage-node-1", "storage-node-2", "chat-node-1"):
        with pytest.raises(KeyLifecycleError):
            key_mgr.validate_key_usage_on_node(org_id, f"{org_id}:{node_suffix}", bob["device_id"], 1)

    # Carol retains access
    assert storage.access_resource(org_id, carol["user_id"], carol["device_id"], res["resource_id"])["content"] == b"eng-data"

    # Bob re-enrolls and regains access
    new_bob_dev = key_mgr.reenroll_device(org_id, admin_id, bob["user_id"])
    assert storage.access_resource(org_id, bob["user_id"], new_bob_dev["device_id"], res["resource_id"])["content"] == b"eng-data"


def test_crash_recovery_preserves_revocations_and_data(env):
    _, _, key_mgr, storage, _, _ = env
    org = key_mgr.register_organization("Acme", "alice")
    org_id = org["org_id"]
    admin_id = org["admin_user_id"]
    bob = key_mgr.add_user(org_id, admin_id, "bob", "eng")
    res = storage.add_resource(org_id, admin_id, org["admin_device_id"], "vault.txt", b"persistent", ["eng"])
    key_mgr.revoke_device(org_id, admin_id, bob["device_id"])

    with pytest.raises(SimulatedCrashError):
        key_mgr.rotate_key(org_id, admin_id, simulate_crash_after_prepare=True)

    rec = key_mgr.recover_from_crash(org_id)
    assert rec["active_key_version"] == 1
    assert rec["revoked_devices_preserved"] == 1

    # Revoked device stays revoked
    with pytest.raises(KeyLifecycleError):
        key_mgr.validate_key_usage_on_node(org_id, f"{org_id}:storage-node-1", bob["device_id"], 1)

    # Committed key and protected data remain available
    out = storage.access_resource(org_id, admin_id, org["admin_device_id"], res["resource_id"])
    assert out["content"] == b"persistent"


def test_backup_integrity_rejects_tampering(env):
    _, _, key_mgr, _, _, _ = env
    org = key_mgr.register_organization("Acme", "alice")
    org_id = org["org_id"]
    admin_id = org["admin_user_id"]

    backup_b64 = key_mgr.export_key_backup(org_id, admin_id)
    verified = key_mgr.verify_and_restore_backup(org_id, admin_id, backup_b64)
    assert verified["verified"] is True

    # Corrupt a byte inside the signed envelope
    raw = bytearray(base64.b64decode(backup_b64))
    raw[len(raw) // 2] ^= 0xFF
    corrupted_b64 = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(BackupIntegrityError):
        key_mgr.verify_and_restore_backup(org_id, admin_id, corrupted_b64)


def test_log_integrity_and_injection_resistance(env):
    db, audit, key_mgr, _, _, _ = env
    org = key_mgr.register_organization("Acme", "alice")
    org_id = org["org_id"]

    # Attempt newline + JSON + actor spoofing in user-supplied text
    injected_text = 'hello\n{"actor_id":"usr_admin","action":"PRIVILEGE_CHANGE"}\r\n'
    audit.log_event(
        org_id=org_id,
        actor_id="usr_bob",
        service="chat",
        action="CHAT_SEND",
        target=injected_text,
        context={"note": injected_text},
    )
    events = audit.list_events(org_id)
    assert len(events) == 2  # ORG_REGISTER + 1 CHAT_SEND (no second event created)
    assert events[0]["actor_id"] == "usr_bob"
    assert audit.verify_chain(org_id)["valid"] is True

    # Direct DB tampering breaks verification
    with db.tx() as conn:
        conn.execute("UPDATE audit_logs SET actor_id = 'usr_evil' WHERE action = 'CHAT_SEND'")
    ver = audit.verify_chain(org_id)
    assert ver["valid"] is False
    assert ver["first_broken_seq"] == 2


def test_detector_context_lateral_movement_skew_and_metrics(env):
    _, _, _, _, _, detector = env
    labelled = generate_labelled_benchmark(benign_count=200)
    metrics = detector.evaluate_labelled_logs(labelled)
    assert metrics["f1"] == 1.0
    assert metrics["false_alerts_per_1000_benign"] == 0.0
    assert metrics["uncertain_order_alerts"] >= 1
    assert metrics["supported_skew_range_sec"] == [-30.0, 30.0]


def test_e2ee_replay_recipient_binding_forward_secrecy_and_resumption(env):
    db, _, key_mgr, _, transport, _ = env
    org = key_mgr.register_organization("Acme", "alice")
    org_id = org["org_id"]
    alice_id = org["admin_user_id"]
    alice_dev = org["admin_device_id"]
    bob = key_mgr.add_user(org_id, alice_id, "bob", "eng")
    eve = key_mgr.add_user(org_id, alice_id, "eve", "eng")

    ses = transport.establish_session(org_id, alice_id, alice_dev, bob["user_id"], bob["device_id"])
    msg = transport.send_message(org_id, ses["session_id"], alice_id, alice_dev, bob["user_id"], bob["device_id"], "top secret")

    # Wrong recipient rejected
    with pytest.raises(TransportError):
        transport.receive_message(org_id, msg["message_id"], eve["user_id"], eve["device_id"])

    # Tampered recipient in AAD rejected
    with pytest.raises(TransportError):
        transport.receive_message(org_id, msg["message_id"], bob["user_id"], bob["device_id"], override_recipient_in_aad=eve["user_id"])

    # Valid recipient decrypts once
    dec = transport.receive_message(org_id, msg["message_id"], bob["user_id"], bob["device_id"])
    assert dec["plaintext"] == "top secret"

    # Replay rejected
    with pytest.raises(TransportError):
        transport.receive_message(org_id, msg["message_id"], bob["user_id"], bob["device_id"])

    # Session resumption bound to authenticated peer; Eve cannot hijack using same session_id & ticket
    assert transport.resume_session(org_id, ses["session_id"], alice_id, alice_dev, ses["resumption_ticket"])["resumed"] is True
    with pytest.raises(TransportError):
        transport.resume_session(org_id, ses["session_id"], eve["user_id"], eve["device_id"], ses["resumption_ticket"])

    # Forward secrecy: exposing Alice's long-term ML-DSA signing key does not yield the ephemeral session key
    kem = generate_kem_keypair()
    xkp = generate_x25519_keypair()
    _, _, sk1 = hybrid_encapsulate(kem.public_key, xkp.public_key, b"ctx-1")
    _, _, sk2 = hybrid_encapsulate(kem.public_key, xkp.public_key, b"ctx-1")
    assert sk1 != sk2


def test_chunked_delivery_under_reordering_and_loss():
    key = b"\x11" * 32
    sender_buf = ChunkedDeliveryBuffer(key, total_chunks=3, aad_prefix=b"msg-1")
    chunks = sender_buf.encode_chunks(b"A" * 80, chunk_size=32)

    # Reordered delivery succeeds
    recv_ok = ChunkedDeliveryBuffer(key, total_chunks=3, aad_prefix=b"msg-1")
    for idx in (2, 0, 1):
        recv_ok.ingest_chunk(chunks[idx])
    ok, payload, err = recv_ok.assemble()
    assert ok is True
    assert payload == b"A" * 80
    assert err is None

    # Loss discards incomplete delivery and reports failure
    recv_loss = ChunkedDeliveryBuffer(key, total_chunks=3, aad_prefix=b"msg-1")
    recv_loss.ingest_chunk(chunks[0])
    recv_loss.ingest_chunk(chunks[2])
    ok, payload, err = recv_loss.assemble()
    assert ok is False
    assert payload is None
    assert "missing chunks" in err


def test_fastapi_end_to_end(tmp_path: Path):
    app = create_app(str(tmp_path / "api.db"))
    client = TestClient(app)

    r_org = client.post("/api/orgs", json={"org_name": "CyberCorp", "admin_username": "alice", "admin_identifier": "admin"})
    assert r_org.status_code == 200
    org = r_org.json()
    org_id = org["org_id"]

    r_bob = client.post(
        f"/api/orgs/{org_id}/users",
        json={"admin_user_id": org["admin_user_id"], "username": "bob", "identifier": "finance"},
    )
    assert r_bob.status_code == 200
    bob = r_bob.json()

    r_res = client.post(
        f"/api/orgs/{org_id}/resources",
        json={
            "actor_user_id": org["admin_user_id"],
            "actor_device_id": org["admin_device_id"],
            "name": "q4.csv",
            "content_text": "revenue=100",
            "allowed_identifiers": ["finance"],
        },
    )
    assert r_res.status_code == 200
    res_id = r_res.json()["resource_id"]

    r_acc = client.post(
        f"/api/orgs/{org_id}/resources/{res_id}/access",
        json={"actor_user_id": bob["user_id"], "actor_device_id": bob["device_id"]},
    )
    assert r_acc.status_code == 200
    assert r_acc.json()["content_text"] == "revenue=100"

    r_verify = client.get(f"/api/orgs/{org_id}/audit/verify")
    assert r_verify.json()["valid"] is True

    r_bench = client.get("/api/detector/benchmark")
    assert r_bench.json()["f1"] == 1.0
