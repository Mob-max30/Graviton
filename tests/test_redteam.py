"""Adversarial & Red-Team test suite for Graviton Track 4 security guarantees."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from graviton.audit_log import AuditLog
from graviton.crypto import generate_hybrid_kem_keypair, generate_sign_keypair
from graviton.detector import AccessEvent, TrustDetector
from graviton.lifecycle import KeyLifecycleManager, NodeVerifier
from graviton.messaging import Identity, MessagingEndpoint


def _make_identity(uid: str) -> Identity:
    return Identity(uid, generate_sign_keypair(), generate_hybrid_kem_keypair())


def test_redteam_true_forward_secrecy_after_longterm_key_compromise():
    """Compromising BOTH Alice and Bob's long-term identity keys AFTER a session
    completes must NOT allow an attacker who recorded the handshake to decrypt
    the session's messages.
    """
    alice_id = _make_identity("alice")
    bob_id = _make_identity("bob")
    alice = MessagingEndpoint(alice_id)
    bob = MessagingEndpoint(bob_id)
    alice.register_peer(bob_id)
    bob.register_peer(alice_id)

    sid, init_p, init_s = alice.initiate_session("bob")
    _, resp_p, resp_s = bob.accept_session("alice", init_p, init_s)
    alice.finalize_session("bob", resp_p, resp_s)

    env = alice.send(sid, b"top-secret-earlier-session")
    delivered, errs = bob.receive(env)
    assert delivered == [b"top-secret-earlier-session"] and errs == []

    # Close session & verify ephemeral secret keys are gone
    alice.sessions[sid].close()
    bob.sessions[sid].close()
    assert sid not in alice._pending_ephemeral

    # Attacker steals long-term identity keys of Alice and Bob and tries to
    # re-derive root_key from recorded handshake (resp_p) using long-term kem_kp:
    from graviton.crypto import aead_decrypt, hkdf_sha256, hybrid_kem_decapsulate

    meta = json.loads(resp_p.decode())
    # ML-KEM uses implicit rejection (returns pseudorandom key on wrong sk), so
    # deriving root_key + msg_key and attempting AEAD decryption must fail!
    wrong_ss = hybrid_kem_decapsulate(
        alice_id.kem_kp.mlkem_sk,
        alice_id.kem_kp.x25519_sk,
        bytes.fromhex(meta["mlkem_ct"]),
        bytes.fromhex(meta["resp_x25519_pk"]),
    )
    wrong_root = hkdf_sha256(
        wrong_ss,
        bytes.fromhex(meta["init_hash"]),
        f"session:{sid}:alice:bob".encode(),
        32,
    )
    wrong_msg_key = hkdf_sha256(wrong_root, env.seq.to_bytes(8, "big"), b"msg-key", 32)
    aad = f"{sid}|alice|bob|{env.seq}".encode()
    with pytest.raises(Exception):
        aead_decrypt(wrong_msg_key, env.nonce, env.ciphertext, aad)


def test_redteam_session_resumption_hijack_blocked():
    """Another identity presenting the same session_id and even a stolen MAC cannot
    hijack a resumed session without the original peer's ML-DSA-65 signature.
    """
    alice = MessagingEndpoint(_make_identity("alice"))
    bob = MessagingEndpoint(_make_identity("bob"))
    eve = MessagingEndpoint(_make_identity("eve"))
    alice.register_peer(bob.identity)
    bob.register_peer(alice.identity)
    bob.register_peer(eve.identity)

    sid, init_p, init_s = alice.initiate_session("bob")
    _, resp_p, resp_s = bob.accept_session("alice", init_p, init_s)
    alice.finalize_session("bob", resp_p, resp_s)

    challenge = b"resume-chal-1"
    mac, sig = alice.make_resumption_proof(sid, challenge)
    assert bob.resume_session(sid, "alice", mac, sig, challenge) is True
    assert bob.resume_session(sid, "eve", mac, sig, challenge) is False
    # Wrong challenge also rejected
    assert bob.resume_session(sid, "alice", mac, sig, b"wrong-chal") is False


def test_redteam_delivery_under_loss_and_corruption_discarded():
    alice = MessagingEndpoint(_make_identity("alice"))
    bob = MessagingEndpoint(_make_identity("bob"))
    alice.register_peer(bob.identity)
    bob.register_peer(alice.identity)

    sid, init_p, init_s = alice.initiate_session("bob")
    _, resp_p, resp_s = bob.accept_session("alice", init_p, init_s)
    alice.finalize_session("bob", resp_p, resp_s)

    m0 = alice.send(sid, b"pkt-0")
    _m1_lost = alice.send(sid, b"pkt-1-lost")
    m2 = alice.send(sid, b"pkt-2")
    m3 = alice.send(sid, b"pkt-3-corrupted")
    m3.ciphertext = bytes([m3.ciphertext[0] ^ 0xFF]) + m3.ciphertext[1:]

    assert bob.receive(m0)[0] == [b"pkt-0"]
    assert bob.receive(m2)[0] == []  # buffered waiting for lost m1
    d3, e3 = bob.receive(m3)
    assert d3 == [] and "Decryption/authentication failed" in e3[0]

    report = bob.report_incomplete_deliveries(sid)
    assert report["missing_seqs"] == [1]
    assert report["buffered_out_of_order"] == [2]
    assert len(report["failed_deliveries"]) == 1
    assert bob.discard_incomplete(sid) == 1


def test_redteam_path_traversal_and_rollback_blocked(tmp_path: Path):
    with pytest.raises(ValueError, match="Invalid node_id"):
        NodeVerifier("../../etc/passwd")

    mgr = KeyLifecycleManager(tmp_path / "state", grace_seconds=2.0)
    with pytest.raises(ValueError, match="Invalid owner"):
        mgr.enroll_user("../evil")

    k1 = mgr.enroll_user("alice")
    old_backup = mgr.create_backup()
    mgr.rotate_key(k1.key_id, now=1000.0)
    # Attempting to restore older-epoch backup must be rejected
    with pytest.raises(ValueError, match="Rollback rejected"):
        mgr.restore_backup(old_backup)


def test_redteam_truncated_wal_crash_recovery(tmp_path: Path):
    state_dir = tmp_path / "state"
    mgr = KeyLifecycleManager(state_dir, grace_seconds=2.0)
    k1 = mgr.enroll_user("alice")
    # Simulate power-loss mid-write by appending a truncated JSON line to wal.jsonl
    with open(state_dir / "wal.jsonl", "a", encoding="utf-8") as f:
        f.write('{"checksum":"deadbeef","entry":{"op":"commit_key"\n')

    recovered = KeyLifecycleManager(state_dir, grace_seconds=2.0)
    assert k1.key_id in recovered.keys


def test_redteam_log_injection_and_clock_skew_uncertainty(tmp_path: Path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("mallory\n{\"actor\":\"root\"}", "login\r\n", "auth\x00", "ok\x1b[31m")
    assert len(log.entries) == 1
    assert "\n" not in log.entries[0].actor
    assert "\x00" not in log.entries[0].service
    assert log.verify_log(from_disk=True)[0] is True

    # Clock skew > 300s and overlapping uncertainty window
    det = TrustDetector(max_clock_skew_s=300.0, uncertainty_window_s=2.0)
    alerts = det.analyze([
        AccessEvent("e1", 100.0, "eve", "read", "files", clock_offset_s=0.0, label="benign"),
        AccessEvent("e2", 500.5, "eve", "grant_admin", "billing", clock_offset_s=400.0, label="malicious"),
    ])
    assert len(alerts) >= 1
    assert all(a.order_uncertain is True for a in alerts)


def test_redteam_scale_10k_events_under_1s():
    events = [
        AccessEvent(f"ev-{i}", float(i), f"user-{i % 100}", "read", "vault" if i % 2 else "auth", label="benign")
        for i in range(10_000)
    ]
    det = TrustDetector()
    t0 = time.perf_counter()
    alerts = det.analyze(events)
    elapsed = time.perf_counter() - t0
    assert elapsed < 1.0
    assert len(alerts) == 0
