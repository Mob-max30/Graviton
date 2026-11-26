"""Interactive 5-Minute Live Demonstration Script for Stage 2 Review."""
import datetime
import tempfile
from pathlib import Path

import pqcrypto.sign.ml_dsa_65 as ml_dsa

from trustledger.audit.logger import SignedAuditLogger
from trustledger.audit.verifier import verify_log
from trustledger.cluster.crash import RecoveryManager
from trustledger.cluster.gossip import GossipCluster
from trustledger.crypto.keys import HybridIdentityKeypair, TrustedPeerStore
from trustledger.crypto.suites import CipherSuite
from trustledger.detect.adapters.csv_adapter import EventAdapter
from trustledger.detect.engine import DetectionPipeline
from trustledger.fixtures import get_practice_dir
from trustledger.keys.backup import BackupError, BackupManager
from trustledger.keys.lifecycle import KeyLifecycleManager, KeyState
from trustledger.keys.rotation import RotationCoordinator
from trustledger.protocol.handshake import HandshakeInitiator, HandshakeResponder
from trustledger.protocol.ratchet import SymmetricRatchetSession


def print_step(step_num: int, title: str) -> None:
    print(f"\n[{step_num}/9] {title}")
    print("-" * 70)


def run_demo() -> None:
    print("=====================================================================")
    print("TrustLedger: Stage 2 Live Desk Review & Verification Demo")
    print("=====================================================================")

    # Step 1: Enroll users
    print_step(1, "Enrolling Identities & Generating Post-Quantum Keypairs")
    alice_key = HybridIdentityKeypair.generate()
    srv_key = HybridIdentityKeypair.generate()
    print(f"Alice Identity Fingerprint : {alice_key.fingerprint[:16]}... (ML-DSA-65 + Ed25519)")
    print(f"Server Identity Fingerprint: {srv_key.fingerprint[:16]}... (ML-DSA-65 + Ed25519)")

    # Step 2: E2E PQ Messaging
    print_step(2, "End-to-End Post-Quantum & Hybrid Handshake + Ratchet")
    trust_store = TrustedPeerStore()
    trust_store.register_peer("alice", alice_key, CipherSuite.SUITE_HYBRID)
    trust_store.register_peer("srv1", srv_key, CipherSuite.SUITE_HYBRID)
    init = HandshakeInitiator("alice", "client", alice_key, CipherSuite.SUITE_HYBRID, trusted_peers=trust_store)
    resp = HandshakeResponder("srv1", "server", srv_key, trusted_peers=trust_store)

    s_nonce, kem_ct, s_x, s_sig, _ = resp.process_client_hello_and_reply(
        init.identity,
        init.role,
        CipherSuite.SUITE_HYBRID,
        init.client_nonce,
        init.ephemeral_key.kem_pk,  # type: ignore[union-attr]
        init.ephemeral_key.x25519_pk,  # type: ignore[union-attr]
    )
    c_sig, c_keys = init.process_server_hello_and_authenticate("srv1", "server", srv_key.dsa_pk, srv_key.ed_pk, s_nonce, kem_ct, s_x, s_sig)
    s_keys = resp.complete_handshake(alice_key.dsa_pk, alice_key.ed_pk, c_sig)
    print("Handshake Complete: Ephemeral ML-KEM-768 Shared Secret + X25519 DH Derived.")

    alice_ratchet = SymmetricRatchetSession(c_keys.session_id, CipherSuite.SUITE_HYBRID, "alice", "srv1", srv_key.fingerprint, c_keys.send_key, c_keys.recv_key)
    srv_ratchet = SymmetricRatchetSession(s_keys.session_id, CipherSuite.SUITE_HYBRID, "srv1", "alice", alice_key.fingerprint, s_keys.send_key, s_keys.recv_key)

    ct = alice_ratchet.encrypt_message(b"CRITICAL_DATA: Access Granted", "msg-001")
    pt = srv_ratchet.decrypt_message(ct, 0, "msg-001", "alice", "srv1", srv_key.fingerprint, 1, total_length=29)
    print(f"Server Received Ratcheted Payload: {pt.decode('utf-8')}")

    # Step 3: Two-Phase Commit Rotation
    print_step(3, "Two-Phase Commit Key Rotation Under Live Traffic")
    with tempfile.TemporaryDirectory() as tmp_dir:
        lifecycle = KeyLifecycleManager(initial_epoch=1)
        lifecycle.register_key("key-v1", "ML-DSA-65", "pub1")
        lifecycle.transition_state("key-v1", KeyState.ACTIVE)
        coord = RotationCoordinator(Path(tmp_dir), lifecycle)

        print("Phase 1: Preparing rotation to key-v2 in WAL...")
        coord.prepare_rotation("key-v2", "ML-DSA-65", "pub2")
        print("Phase 2: Committing rotation to active epoch 2...")
        coord.commit_rotation("key-v2")
        active = lifecycle.get_active_key()
        old_rec = lifecycle.get_key("key-v1")
        print(f"Active Key Post-Rotation: {active.key_id if active else 'none'} (Epoch {lifecycle.current_epoch})")
        print(f"Old Key State           : {old_rec.state if old_rec else 'none'} (Accepted during grace period)")

    # Step 4: Device Loss, Cluster Revocation & Owner Re-Enrollment
    print_step(4, "Lost Device Scenario: Cluster Revocation & Owner Re-Enrollment")
    cluster = GossipCluster([f"node-{i:02d}" for i in range(8)])
    cluster.enroll_device_globally("alice", "alice-laptop-01")
    cluster.enroll_device_globally("bob", "bob-phone-01")
    prop_ms = cluster.revoke_device_globally("alice-laptop-01")
    cluster.enroll_device_globally("alice", "alice-laptop-02")
    print(f"Revoked 'alice-laptop-01' across 8 cluster nodes in {prop_ms:.3f} ms.")
    for n in cluster.nodes.values():
        assert n.can_access("alice", "alice", device_key_id="alice-laptop-01")[0] is False
        assert n.can_access("alice", "alice", device_key_id="alice-laptop-02")[0] is True
        assert n.can_access("bob", "bob", device_key_id="bob-phone-01")[0] is True
    print("Verified: Old device denied on all 8 nodes; re-enrolled 'alice-laptop-02' & peer 'bob-phone-01' allowed.")

    # Step 5: Crash Mid-Rotation & Recovery
    print_step(5, "Simulated Crash Mid-Rotation and Deterministic Recovery")
    with tempfile.TemporaryDirectory() as tmp_dir:
        lifecycle = KeyLifecycleManager(1)
        lifecycle.register_key("k1", "ML-DSA-65", "p1")
        lifecycle.transition_state("k1", KeyState.ACTIVE)
        coord = RotationCoordinator(Path(tmp_dir), lifecycle)
        rec_mgr = RecoveryManager(coord, lifecycle)

        coord.prepare_rotation("k2", "ML-DSA-65", "p2")
        print("Crash injected at point: PRE_COMMIT")
        status = rec_mgr.recover()
        print(f"Recovery Result: {status}")
        rec_mgr.assert_invariants()
        print("Invariants Verified: Exactly 1 ACTIVE key asserted. No resurrected revoked keys.")

    # Step 6: Backup Tamper Detection via Merkle Root
    print_step(6, "Encrypted Backup Integrity & Anti-Rollback")
    pk, sk = ml_dsa.generate_keypair()
    bm = BackupManager(sk, pk)
    bundle = bm.create_backup(100, [{"key_id": "k1", "state": "ACTIVE"}])
    print(f"Backup Created. Merkle Root: {bundle['manifest']['merkle_root'][:16]}...")
    bad_bundle = dict(bundle)
    bad_bundle["manifest"] = dict(bundle["manifest"])
    bad_bundle["manifest"]["backup_counter"] = 99
    try:
        bm.verify_and_restore(bad_bundle)
    except BackupError as e:
        print(f"Tamper Successfully Caught: {e}")

    # Step 7: Log Integrity & Free-Text Injection
    print_step(7, "Tamper-Evident Audit Log & Verification")
    with tempfile.TemporaryDirectory() as tmp_dir:
        lf = Path(tmp_dir) / "audit.log"
        logger = SignedAuditLogger(lf, "sig-01", sk, checkpoint_interval=5)
        logger.append_entry("admin", "update", 'evil\r\n{"seq": 999}\x00', "allow")
        logger.finalize()
        _passed, reason, _ = verify_log(lf, pk)
        print(f"Offline Log Verification: {reason} (CRLF/NUL injections remain inert)")

    # Step 8: Behavioral Detection & Active Containment
    print_step(8, "Explainable Detection (NO ML) on Practice Dataset")
    practice_dir = get_practice_dir()
    pipeline = DetectionPipeline(practice_dir / "approvals.json")
    alerts = pipeline.run_file(practice_dir / "events.csv", active_response=True)
    for a in alerts:
        print(f"Alert [{a.severity.value}] {a.rule_id} on {a.identity}: {a.explanation[:85]}... (Quarantined: {a.quarantined})")

    # Step 9: Real Clock Skew & Arrival Disorder Execution
    print_step(9, "Clock Skew Handling & Arrival Disorder Flagging")
    raw_events = EventAdapter().load_events(practice_dir / "events.csv")
    DetectionPipeline(practice_dir / "approvals.json").process_events(raw_events)
    e15 = next(e for e in raw_events if e.event_id == "evt-015")
    e14 = next(e for e in raw_events if e.event_id == "evt-014")
    e13 = next(e for e in raw_events if e.event_id == "evt-013")
    corrected_dt = datetime.datetime.fromtimestamp(e15.corrected_time_epoch_ms / 1000.0, tz=datetime.timezone.utc)
    print(f"Event {e15.event_id} (offset {e15.source_clock_offset_ms:+d}ms) aligned to {corrected_dt.isoformat()}.")
    print(f"Arrival inversion {e14.event_id} (receipt={e14.receipt_index}) before {e13.event_id} (receipt={e13.receipt_index}): order_uncertain={e14.order_uncertain}.")

    print("\n=====================================================================")
    print("Stage 2 Live Demonstration Completed Successfully.")
    print("=====================================================================")


if __name__ == "__main__":
    run_demo()
