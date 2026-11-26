"""Comprehensive Track 4 functional verification suite for Graviton."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from graviton.audit_log import AuditLog
from graviton.crypto import generate_hybrid_kem_keypair, generate_sign_keypair
from graviton.detector import AccessEvent, TrustDetector
from graviton.lifecycle import KeyLifecycleManager, NodeVerifier
from graviton.messaging import Identity, MessagingEndpoint


def _make_identity(uid: str) -> Identity:
    return Identity(uid, generate_sign_keypair(), generate_hybrid_kem_keypair())


def _establish_session(alice: MessagingEndpoint, bob: MessagingEndpoint) -> str:
    sid, init_p, init_s = alice.initiate_session(bob.identity.user_id)
    _, resp_p, resp_s = bob.accept_session(alice.identity.user_id, init_p, init_s)
    alice.finalize_session(bob.identity.user_id, resp_p, resp_s)
    return sid


def test_messaging_pqc_reordering_replay_recipient_resumption_and_close():
    alice = MessagingEndpoint(_make_identity("alice"))
    bob = MessagingEndpoint(_make_identity("bob"))
    alice.register_peer(bob.identity)
    bob.register_peer(alice.identity)

    sid = _establish_session(alice, bob)

    # Send 3 messages, deliver out of order (2, 0, 1)
    m0 = alice.send(sid, b"msg-0")
    m1 = alice.send(sid, b"msg-1")
    m2 = alice.send(sid, b"msg-2")

    d2, e2 = bob.receive(m2)
    assert d2 == [] and e2 == []  # buffered
    d0, e0 = bob.receive(m0)
    assert d0 == [b"msg-0"] and e0 == []
    d1, e1 = bob.receive(m1)
    assert d1 == [b"msg-1", b"msg-2"] and e1 == []

    # Replay rejected
    dr, er = bob.receive(m1)
    assert dr == [] and "Replay" in er[0]

    # Recipient binding: tampered recipient rejected
    m3 = alice.send(sid, b"msg-3")
    m3.recipient = "eve"
    dt, et = bob.receive(m3)
    assert dt == [] and "mismatch" in et[0]

    # Session resumption bound to authenticated peer
    challenge = b"nonce-123"
    mac, sig = alice.make_resumption_proof(sid, challenge)
    assert bob.resume_session(sid, "alice", mac, sig, challenge) is True
    assert bob.resume_session(sid, "eve", mac, sig, challenge) is False

    # Closing session destroys ephemeral root key
    bob.sessions[sid].close()
    m4 = alice.send(sid, b"msg-4")
    df, ef = bob.receive(m4)
    assert df == [] and "closed" in ef[0]


def test_key_rotation_revocation_crash_recovery_and_backup(tmp_path: Path):
    mgr = KeyLifecycleManager(tmp_path / "state", grace_seconds=2.0)
    n1, n2 = NodeVerifier("node-1"), NodeVerifier("node-2")
    mgr.register_node(n1)
    mgr.register_node(n2)

    alice_k1 = mgr.enroll_user("alice")
    bob_k1 = mgr.enroll_user("bob")

    # Rotation with grace period
    t0 = 1000.0
    alice_k2 = mgr.rotate_key(alice_k1.key_id, now=t0)
    assert alice_k2 is not None
    assert n1.is_key_authorized(alice_k1.key_id, now=t0 + 1.0)[0] is True
    assert n1.is_key_authorized(alice_k1.key_id, now=t0 + 3.0)[0] is False
    assert n2.is_key_authorized(alice_k2.key_id, now=t0 + 3.0)[0] is True

    # Crash recovery: interrupted rotation rolls back cleanly
    assert mgr.rotate_key(alice_k2.key_id, now=t0 + 4.0, simulate_crash_before_commit=True) is None
    recovered = KeyLifecycleManager(tmp_path / "state", grace_seconds=2.0)
    assert alice_k2.key_id in recovered.keys
    assert len(recovered.keys) == 3  # alice_k1, bob_k1, alice_k2

    # Revocation across nodes + re-enrollment; bob retains access
    alice_k3, prop_ms = recovered.reenroll_after_device_loss("alice", alice_k2.key_id)
    assert prop_ms >= 0.0
    assert recovered.nodes == {}  # register nodes on recovered manager to verify persistence
    recovered.register_node(n1)
    recovered.register_node(n2)
    assert n1.is_key_authorized(alice_k2.key_id)[0] is False
    assert n2.is_key_authorized(alice_k2.key_id)[0] is False
    assert n1.is_key_authorized(alice_k3.key_id)[0] is True
    assert n2.is_key_authorized(bob_k1.key_id)[0] is True

    # Backup integrity: valid backup restores after restart, tampered backup rejected
    backup = recovered.create_backup()
    tampered = json.loads(backup.decode())
    tampered["bundle"] = tampered["bundle"].replace("1", "2", 1)
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        recovered.restore_backup(json.dumps(tampered).encode())

    restarted = KeyLifecycleManager(tmp_path / "state", grace_seconds=2.0)
    restarted.restore_backup(backup)
    assert alice_k3.key_id in restarted.keys
    assert alice_k2.key_id in restarted.revoked_keys


def test_audit_log_integrity_and_injection_resistance(tmp_path: Path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("alice", "login", "auth", "ok")
    log.append("bob", "upload", "files", 'hello\n{"actor":"admin","action":"grant_admin"}')
    assert len(log.entries) == 2
    ok, err = log.verify_log(from_disk=True)
    assert ok is True and err is None

    # Tamper with entry on disk
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace('"actor": "bob"', '"actor": "admin"')
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok2, err2 = log.verify_log(from_disk=True)
    assert ok2 is False and err2 is not None


def test_detector_routine_lateral_movement_and_clock_skew():
    det = TrustDetector(approved_tickets={"CHG-101"})
    events = [
        AccessEvent("e1", 100.0, "alice", "login", "auth", label="benign"),
        AccessEvent("e2", 105.0, "alice", "grant_admin", "auth", approved_ticket="CHG-101", label="benign"),
        AccessEvent("e3", 110.0, "alice", "read", "vault", label="benign"),
        AccessEvent("e4", 120.0, "eve", "read", "files", clock_offset_s=10.0, label="benign"),
        AccessEvent("e5", 135.0, "eve", "grant_admin", "billing", clock_offset_s=10.0, label="malicious"),
    ]
    alerts = det.analyze(events)
    rules = {a.rule for a in alerts}
    assert "unapproved_privilege_change" in rules
    assert "lateral_movement_unusual_path" in rules

    metrics = det.evaluate(events, alerts)
    assert metrics["f1"] == 1.0
    assert metrics["false_alerts_per_1000_benign"] == 0.0
