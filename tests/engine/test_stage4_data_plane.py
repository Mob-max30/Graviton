"""Stage 4: Real-network E2EE data plane, relay/vault SQLite & database-protection tests."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import time
import unittest

from graviton.admin import AdminManager
from graviton.client import ClientManager
from graviton.comms.resumption import ResumptionError, ResumptionManager
from graviton.comms.session import MessageError
from graviton.crypto.keystore import load_keystore
from graviton.daemon.node import init_node_daemon
from graviton.net.client import NodeClient, NodeClientError
from graviton.net.protocol import format_fingerprint
from tests.engine.helpers import DaemonProcess


class Stage4DataPlaneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="graviton_stage4_"))
        self.kavya_home = self.tmp / "kavya_home"
        self.arjun_home = self.tmp / "arjun_home"
        self.neel_home = self.tmp / "neel_home"
        self.mallory_home = self.tmp / "mallory_home"
        self.hub_dir = self.tmp / "hub"
        self.rep_dir = self.tmp / "rep"
        self.procs = []

        self.admin_pw = "kavya-pw-123"
        self.arjun_pw = "arjun-pw-123"
        self.neel_pw = "neel-pw-123"
        self.mallory_pw = "mallory-pw-123"

        self.admin = AdminManager(self.kavya_home)
        g = self.admin.init_group("acme-sec", self.admin_pw, operator_handle="kavya")
        admin_pk = base64.b64decode(self.admin._load_state()["admin_pk_b64"])

        init_node_daemon(self.hub_dir, "hub-1", g["feed_id"], admin_pk)
        init_node_daemon(self.rep_dir, "rep-1", g["feed_id"], admin_pk)

        hub_ready = self.tmp / "hub.ready"
        self.hub_proc = DaemonProcess(
            ["node", "run", "--dir", str(self.hub_dir), "--operator", "kavya", "--ready-file", str(hub_ready)],
            hub_ready,
        )
        self.procs.append(self.hub_proc)
        rep_ready = self.tmp / "rep.ready"
        self.rep_proc = DaemonProcess(
            [
                "node",
                "run",
                "--dir",
                str(self.rep_dir),
                "--operator",
                "kavya",
                "--upstream",
                f"{self.hub_proc.host}:{self.hub_proc.port}",
                "--sync-interval",
                "0.1",
                "--ready-file",
                str(rep_ready),
            ],
            rep_ready,
        )
        self.procs.append(self.rep_proc)

        self.admin.add_node(self.hub_proc.host, self.hub_proc.port)
        self.admin.add_node(self.rep_proc.host, self.rep_proc.port)
        self.admin.push_all()

        # Enrol Arjun, Neel, and Mallory (valid member used to test cross-user isolation)
        self.arjun = ClientManager(self.arjun_home)
        self.neel = ClientManager(self.neel_home)
        self.mallory = ClientManager(self.mallory_home)

        for handle, cli_mgr, pw in [
            ("arjun", self.arjun, self.arjun_pw),
            ("neel", self.neel, self.neel_pw),
            ("mallory", self.mallory, self.mallory_pw),
        ]:
            st = cli_mgr.init_identity(handle, pw)
            inv_path = self.tmp / f"{handle}.invite"
            self.admin.create_invite(handle, 300, inv_path, self.admin_pw)
            cli_mgr.join_invite(inv_path, pw, confirm_fn=lambda fp, gfp=g["fingerprint"]: fp == gfp)
            self.admin.approve_join(
                handle,
                self.admin_pw,
                confirm_fn=lambda fp, dfp=st["fingerprint"]: fp == dfp,
            )
        self.admin.push_all()
        # Wait briefly for replica to sync
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            with NodeClient(self.rep_proc.host, self.rep_proc.port, expected_node_pk=self.rep_proc.node_pk) as c:
                if c.hello.node_epoch >= 4:
                    break
            time.sleep(0.05)

    def tearDown(self) -> None:
        for p in reversed(self.procs):
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_01_e2ee_messaging_file_burn_ttl_resumption_and_db_protection(self) -> None:
        secret_text = "ULTRA_SECRET_LAUNCH_CODE_948172"
        secret_file = b"GRAVITON_FILE_SECRET_BYTES_" * 14  # > 64-byte chunks

        # 1. Arjun sends to Neel -> initiates ML-KEM-768 handshake & queues message
        r1 = self.arjun.send_message_to("neel", secret_text, self.arjun_pw)
        self.assertEqual(r1["status"], "handshake_initiated")
        self.assertTrue(r1["queued"])

        # 2. Neel checks inbox -> processes session_init, sends session_resp
        self.assertEqual(self.neel.inbox(self.neel_pw), [])

        # 3. Arjun flushes outbox -> processes session_resp, deletes eph_sk, sends encrypted msg
        flushed = self.arjun.flush_outbox(self.arjun_pw)
        self.assertEqual(len(flushed), 1)
        self.assertEqual(flushed[0]["status"], "sent")

        # Verify no pending eph_sk remains in Arjun's encrypted store
        _, _, arjun_sk = load_keystore(self.arjun.keystore_path, self.arjun_pw)
        arjun_sess = self.arjun._load_sessions(arjun_sk)
        self.assertEqual(arjun_sess["pending_handshakes"], {})
        self.assertIn("neel", arjun_sess["sessions"])

        # 4. Neel lists inbox and reads the message
        inbox_items = self.neel.inbox(self.neel_pw)
        self.assertEqual(len(inbox_items), 1)
        env_id = inbox_items[0]["envelope_id"]

        # 5. Mallory (valid registered member!) cannot fetch Neel's envelope
        mallory_st = self.mallory.get_identity()
        _, _, mallory_sk = load_keystore(self.mallory.keystore_path, self.mallory_pw)
        with NodeClient(self.hub_proc.host, self.hub_proc.port, expected_node_pk=self.hub_proc.node_pk) as mc:
            with self.assertRaises(NodeClientError):
                mc.fetch_envelope("mallory", mallory_st["device_id"], 1, mallory_sk, env_id)

        # 6. Neel reads & decrypts
        msg = self.neel.read_message(env_id, self.neel_pw)
        self.assertEqual(msg["kind"], "msg")
        self.assertEqual(msg["text"], secret_text)
        self.assertEqual(msg["sender"], "arjun")

        # 7. Replay protection: trying to decrypt the same envelope again fails
        with self.assertRaises(MessageError):
            self.neel.replay_cache.check_and_record(
                arjun_sess["sessions"]["neel"]["session_id"], 0
            )

        # 8. Chunked file transfer + Burn-after-reading
        f_res = self.arjun.send_message_to(
            "neel", secret_file, self.arjun_pw, is_file=True, filename="plan.bin", burn=True, chunk_size=64
        )
        self.assertEqual(f_res["kind"], "file")
        self.assertGreater(f_res["chunks"], 3)
        file_env_id = f_res["envelope_id"]

        # Read once -> succeeds and atomically deletes envelope via DELETE ... RETURNING
        f_msg = self.neel.read_message(file_env_id, self.neel_pw)
        self.assertEqual(f_msg["kind"], "file")
        self.assertEqual(f_msg["data"], secret_file)

        # Second fetch of burn-after-reading envelope MUST fail
        with self.assertRaises(NodeClientError):
            self.neel.read_message(file_env_id, self.neel_pw)

        # 9. Database-protection claim: copy SQLite DB and search raw bytes
        db_copy = self.tmp / "copied_relay_vault.db"
        shutil.copy2(self.hub_dir / "relay_vault.db", db_copy)
        raw_db = db_copy.read_bytes()
        self.assertNotIn(secret_text.encode("utf-8"), raw_db)
        self.assertNotIn(b"GRAVITON_FILE_SECRET_BYTES_", raw_db)
        self.assertNotIn(arjun_sk, raw_db)
        sess_key_bytes = base64.b64decode(arjun_sess["sessions"]["neel"]["session_key_b64"])
        self.assertNotIn(sess_key_bytes, raw_db)

        # 10. Resumption over the real network (using ResumptionManager + ML-DSA-65 proof)
        rm = ResumptionManager()
        neel_st = self.neel.get_identity()
        neel_pk = base64.b64decode(neel_st["public_key_b64"])
        _, _, neel_sk = load_keystore(self.neel.keystore_path, self.neel_pw)
        ticket = rm.issue_ticket(arjun_sess["sessions"]["neel"]["session_id"], "neel", neel_pk)
        nonce = b"resume-nonce-1234"
        sig = rm.sign_resume_challenge(neel_sk, ticket.session_id, "neel", nonce)
        self.assertTrue(rm.verify_resumption(ticket, "neel", nonce, sig))
        rm.revoke_peer_tickets("neel")
        with self.assertRaises(ResumptionError):
            rm.verify_resumption(ticket, "neel", nonce, sig)

        # 11. TTL purge test
        ttl_res = self.arjun.send_message_to("neel", "ephemeral-msg", self.arjun_pw, ttl_s=1)
        time.sleep(1.3)
        self.assertEqual(self.neel.inbox(self.neel_pw), [])
        with self.assertRaises(NodeClientError):
            self.neel.read_message(ttl_res["envelope_id"], self.neel_pw)

        # 12. SQL injection inertness
        sqli = "'; DROP TABLE relay_envelopes; --"
        sqli_res = self.arjun.send_message_to("neel", sqli, self.arjun_pw)
        sqli_read = self.neel.read_message(sqli_res["envelope_id"], self.neel_pw)
        self.assertEqual(sqli_read["text"], sqli)

        # 13. Tamper / truncate / reorder detection in SQLite rows
        t1 = self.arjun.send_message_to("neel", "tamper-test-msg", self.arjun_pw)
        f2 = self.arjun.send_message_to("neel", b"A" * 200, self.arjun_pw, is_file=True, filename="t.bin", chunk_size=64)
        conn = sqlite3.connect(str(self.hub_dir / "relay_vault.db"))
        # Tamper message ciphertext
        row = conn.execute("SELECT payload_json FROM relay_envelopes WHERE envelope_id = ?", (t1["envelope_id"],)).fetchone()
        pobj = json.loads(row[0])
        ct_bytes = bytearray(base64.b64decode(pobj["envelope"]["ciphertext_b64"]))
        ct_bytes[0] ^= 0xFF
        pobj["envelope"]["ciphertext_b64"] = base64.b64encode(bytes(ct_bytes)).decode("ascii")
        conn.execute("UPDATE relay_envelopes SET payload_json = ? WHERE envelope_id = ?", (json.dumps(pobj), t1["envelope_id"]))
        # Swap chunk 0 and chunk 1 payloads (reorder attack in DB)
        c0_key = f"{f2['envelope_id'][5:]}:0"
        c1_key = f"{f2['envelope_id'][5:]}:1"
        c0 = conn.execute("SELECT payload_json FROM vault_chunks WHERE chunk_key = ?", (c0_key,)).fetchone()[0]
        c1 = conn.execute("SELECT payload_json FROM vault_chunks WHERE chunk_key = ?", (c1_key,)).fetchone()[0]
        conn.execute("UPDATE vault_chunks SET payload_json = ? WHERE chunk_key = ?", (c1, c0_key))
        conn.execute("UPDATE vault_chunks SET payload_json = ? WHERE chunk_key = ?", (c0, c1_key))
        conn.commit()
        conn.close()

        with self.assertRaises(MessageError):
            self.neel.read_message(t1["envelope_id"], self.neel_pw)
        with self.assertRaises(MessageError):
            self.neel.read_message(f2["envelope_id"], self.neel_pw)

        # 14. Revoked member can neither send nor fetch on ANY node (hub and replica)
        self.admin.revoke("arjun", self.admin_pw)
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            with NodeClient(self.rep_proc.host, self.rep_proc.port, expected_node_pk=self.rep_proc.node_pk) as c:
                if c.hello.node_epoch >= 5:
                    break
            time.sleep(0.05)

        arjun_st = self.arjun.get_identity()
        for proc in (self.hub_proc, self.rep_proc):
            with NodeClient(proc.host, proc.port, expected_node_pk=proc.node_pk) as ac:
                with self.assertRaises(NodeClientError):
                    ac.put_envelope("arjun", arjun_st["device_id"], 1, arjun_sk, "rev-test", "neel", {"k": 1})
                with self.assertRaises(NodeClientError):
                    ac.list_inbox("arjun", arjun_st["device_id"], 1, arjun_sk)

    def test_02_quota_enforcement(self) -> None:
        import threading
        from graviton.daemon.node import NodeDaemon

        q_dir = self.tmp / "quota_node"
        g = self.admin._load_state()
        admin_pk = base64.b64decode(g["admin_pk_b64"])
        init_node_daemon(q_dir, "q-1", g["feed_id"], admin_pk)
        daemon = NodeDaemon(q_dir, max_envelopes_per_user=2, max_storage_bytes_per_user=500)
        q_host, q_port = daemon.start()
        t = threading.Thread(target=daemon.serve_forever, daemon=True)
        t.start()
        try:
            with NodeClient(q_host, q_port, expected_node_pk=daemon.node_pk) as c:
                c.feed_push([bytes.fromhex(h) for h in g["entries_hex"]])
            arjun_st = self.arjun.get_identity()
            _, _, arjun_sk = load_keystore(self.arjun.keystore_path, self.arjun_pw)
            with NodeClient(q_host, q_port, expected_node_pk=daemon.node_pk) as ac:
                ac.put_envelope("arjun", arjun_st["device_id"], 1, arjun_sk, "q1", "neel", {"d": "x" * 10})
                ac.put_envelope("arjun", arjun_st["device_id"], 1, arjun_sk, "q2", "neel", {"d": "x" * 10})
                with self.assertRaises(NodeClientError):
                    ac.put_envelope("arjun", arjun_st["device_id"], 1, arjun_sk, "q3", "neel", {"d": "x" * 10})
        finally:
            daemon.stop()


if __name__ == "__main__":
    unittest.main()
