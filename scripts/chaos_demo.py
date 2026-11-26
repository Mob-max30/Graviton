"""End-to-end Chaos & Track 4 Checklist Demonstration for Graviton."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graviton.audit_log import AuditLog
from graviton.crypto import generate_hybrid_kem_keypair, generate_sign_keypair
from graviton.detector import AccessEvent, TrustDetector
from graviton.lifecycle import KeyLifecycleManager, NodeVerifier
from graviton.messaging import Identity, MessagingEndpoint


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        print("=== 1. Key Lifecycle, Rotation, Revocation & Crash Recovery ===")
        mgr = KeyLifecycleManager(tmp_path / "state", grace_seconds=2.0)
        n1, n2 = NodeVerifier("node-1"), NodeVerifier("node-2")
        mgr.register_node(n1)
        mgr.register_node(n2)

        alice_k1 = mgr.enroll_user("alice")
        bob_k1 = mgr.enroll_user("bob")
        t0 = 1000.0
        alice_k2 = mgr.rotate_key(alice_k1.key_id, now=t0)
        assert alice_k2 is not None
        print(f"Rotation grace check (t0+1s): old={n1.is_key_authorized(alice_k1.key_id, t0+1)[0]}, new={n1.is_key_authorized(alice_k2.key_id, t0+1)[0]}")
        print(f"Rotation cutoff check (t0+3s): old={n1.is_key_authorized(alice_k1.key_id, t0+3)[0]}, new={n1.is_key_authorized(alice_k2.key_id, t0+3)[0]}")

        mgr.rotate_key(alice_k2.key_id, now=t0 + 4.0, simulate_crash_before_commit=True)
        recovered = KeyLifecycleManager(tmp_path / "state", grace_seconds=2.0)
        print(f"Crash recovery: keys={len(recovered.keys)} (uncommitted rotation rolled back)")

        alice_k3, prop_ms = recovered.reenroll_after_device_loss("alice", alice_k2.key_id)
        print(f"Device-loss revocation propagated in {prop_ms:.3f} ms; bob_k1 still active={bob_k1.key_id in recovered.keys}")

        backup = recovered.create_backup()
        tampered = json.loads(backup.decode())
        tampered["bundle"] = tampered["bundle"].replace("1", "2", 1)
        try:
            recovered.restore_backup(json.dumps(tampered).encode())
        except ValueError as exc:
            print(f"Tampered backup rejected: {exc}")

        print("\n=== 2. Forward-Secret PQC E2EE Messaging ===")
        alice_id = Identity("alice", generate_sign_keypair(), generate_hybrid_kem_keypair())
        bob_id = Identity("bob", generate_sign_keypair(), generate_hybrid_kem_keypair())
        alice, bob = MessagingEndpoint(alice_id), MessagingEndpoint(bob_id)
        alice.register_peer(bob_id)
        bob.register_peer(alice_id)

        sid, init_p, init_s = alice.initiate_session("bob")
        _, resp_p, resp_s = bob.accept_session("alice", init_p, init_s)
        alice.finalize_session("bob", resp_p, resp_s)

        m0 = alice.send(sid, b"quantum-safe-0")
        m1 = alice.send(sid, b"quantum-safe-1")
        print(f"Out-of-order m1 arrives first -> delivered={bob.receive(m1)[0]}")
        print(f"Then m0 arrives -> delivered={bob.receive(m0)[0]}")
        print(f"Replay m1 -> error={bob.receive(m1)[1]}")

        print("\n=== 3. Audit Log Integrity & Lateral Movement Detection ===")
        log = AuditLog(tmp_path / "audit.jsonl")
        log.append("alice", "login", "auth", "ok")
        log.append("eve", "upload", "files", 'payload\n{"actor":"admin","action":"grant_admin"}')
        ok, _ = log.verify_log(from_disk=True)
        print(f"AuditLog verified={ok}, entries={len(log.entries)}")

        det = TrustDetector(approved_tickets={"CHG-101"})
        alerts = det.analyze([
            AccessEvent("e1", 100.0, "eve", "read", "files", label="benign"),
            AccessEvent("e2", 105.0, "eve", "grant_admin", "billing", label="malicious"),
        ])
        for a in alerts:
            print(f"Alert [{a.rule}]: {a.explanation}")


if __name__ == "__main__":
    main()
