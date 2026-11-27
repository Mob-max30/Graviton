"""Stage 5: Sentinel live detection, audit verify, clock skew, and red-team tests."""
from __future__ import annotations

import base64
from pathlib import Path
import shutil
import tempfile
import unittest

from graviton.admin import AdminManager
from graviton.client import ClientManager
from graviton.crypto.aead import aead_available
from graviton.crypto.keystore import load_keystore
from graviton.daemon.node import init_node_daemon
from graviton.redteam import run_redteam_scenario
from graviton.sentinel import SentinelRunner, load_alerts, verify_node_audits
from tests.engine.helpers import DaemonProcess


@unittest.skipUnless(aead_available(), "Stage 5 requires the 'app' extra (cryptography)")
class Stage5SentinelRedteamTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="graviton_stage5_"))
        self.kavya_home = self.tmp / "kavya"
        self.arjun_home = self.tmp / "arjun"
        self.mallory_home = self.tmp / "mallory"
        self.hub_dir = self.tmp / "hub"
        self.procs = []

        self.admin_pw = "kavya-pw-123"
        self.arjun_pw = "arjun-pw-123"
        self.mallory_pw = "mallory-pw-123"

        self.admin = AdminManager(self.kavya_home)
        g = self.admin.init_group("acme-sec", self.admin_pw, operator_handle="kavya")
        self.feed_id = g["feed_id"]
        admin_pk = base64.b64decode(self.admin._load_state()["admin_pk_b64"])
        init_node_daemon(self.hub_dir, "hub-1", self.feed_id, admin_pk)

        ready = self.tmp / "hub.ready"
        self.hub_proc = DaemonProcess(
            ["node", "run", "--dir", str(self.hub_dir), "--operator", "kavya", "--ready-file", str(ready)],
            ready,
        )
        self.procs.append(self.hub_proc)
        self.admin.add_node(self.hub_proc.host, self.hub_proc.port)
        self.admin.push_all()

        self.arjun = ClientManager(self.arjun_home)
        self.mallory = ClientManager(self.mallory_home)
        for handle, cli, pw in [("arjun", self.arjun, self.arjun_pw), ("mallory", self.mallory, self.mallory_pw)]:
            st = cli.init_identity(handle, pw)
            inv = self.tmp / f"{handle}.invite"
            self.admin.create_invite(handle, 300, inv, self.admin_pw)
            cli.join_invite(inv, pw, confirm_fn=lambda fp, gfp=g["fingerprint"]: fp == gfp)
            self.admin.approve_join(handle, self.admin_pw, confirm_fn=lambda fp, dfp=st["fingerprint"]: fp == dfp)
        self.admin.push_all()

    def tearDown(self) -> None:
        for p in reversed(self.procs):
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_01_benign_admin_no_alerts_and_redteam_triggers_denial_and_alerts(self) -> None:
        st = self.admin._load_state()
        _, _, admin_sk = load_keystore(self.admin.keystore_path, self.admin_pw)
        sentinel = SentinelRunner(home_dir=self.kavya_home, operators={"kavya", "admin"})

        # 1. Benign admin workflow already happened in setUp -> should produce 0 alerts
        benign_alerts = sentinel.pull_and_analyze(
            st["nodes"], "kavya", "admin-dev", 1, admin_sk, print_alerts=False
        )
        self.assertEqual(benign_alerts, [])

        # 2. Revoke mallory so redteam 'revoked' scenario tests a real revoked key
        self.admin.revoke("mallory", self.admin_pw)
        arjun_st = self.arjun.get_identity()
        _, _, arjun_sk = load_keystore(self.arjun.keystore_path, self.arjun_pw)
        mallory_st = self.mallory.get_identity()
        _, _, mallory_sk = load_keystore(self.mallory.keystore_path, self.mallory_pw)

        # 3. Run all 9 redteam scenarios against live NodeDaemon
        rt_results = run_redteam_scenario(
            "all",
            self.hub_proc.host,
            self.hub_proc.port,
            expected_node_pk=self.hub_proc.node_pk,
            actor="arjun",
            device_id=arjun_st["device_id"],
            signing_sk=arjun_sk,
            revoked_sk=mallory_sk,
            revoked_actor="mallory",
            revoked_device_id=mallory_st["device_id"],
            feed_id=self.feed_id,
            node_db_path=self.hub_dir / "relay_vault.db",
        )
        self.assertEqual(len(rt_results), 9)
        for item in rt_results:
            self.assertTrue(item["denied"], f"Scenario not denied: {item}")
            self.assertTrue(item["node_alive"], f"Node died during: {item}")

        # 4. Loopback guard rejects non-loopback without explicit confirmation
        with self.assertRaises(ValueError):
            run_redteam_scenario("oversized", "192.0.2.10", 9000)

        # 5. Sentinel pulls live audit logs and emits alerts (privilege change + lateral movement + abuse)
        live_alerts = sentinel.pull_and_analyze(
            st["nodes"], "kavya", "admin-dev", 1, admin_sk, print_alerts=False
        )
        cats = {a["category"] for a in live_alerts}
        self.assertIn("unexpected_privilege_change", cats)
        self.assertIn("lateral_movement", cats)
        saved = load_alerts(sentinel.alerts_path)
        self.assertGreaterEqual(len(saved), 2)

        # 6. Audit verify checks hash chain & external head
        ver = verify_node_audits([self.hub_dir])
        self.assertTrue(ver[0]["valid"])
        self.assertGreater(ver[0]["event_count"], 5)

    def test_02_out_of_order_and_skewed_clock_flagged_order_uncertain(self) -> None:
        sentinel = SentinelRunner(home_dir=self.kavya_home, operators={"kavya"})
        events_by_node = {
            "node-a": [
                {
                    "seq": 2,
                    "timestamp": 1700000020,
                    "event_time_ms": 1700000020000,
                    "received_time_ms": 1700000020100,
                    "clock_offset_ms": 0,
                    "actor": "arjun",
                    "action": "PUT_CHUNK",
                    "target": "vault",
                    "decision": "allow",
                    "detail": '{"service":"vault"}',
                }
            ],
            "node-b": [
                {
                    "seq": 1,
                    "timestamp": 1700000010,
                    "event_time_ms": 1700000010000,
                    "received_time_ms": 1700000010100,
                    "clock_offset_ms": 25000,  # > MAX_SKEW_MS (5000) -> order_uncertain
                    "actor": "arjun",
                    "action": "LIST_INBOX",
                    "target": "relay",
                    "decision": "allow",
                    "detail": '{"service":"relay"}',
                }
            ],
        }
        alerts = sentinel.analyze_events(events_by_node, print_alerts=False)
        self.assertTrue(any(a["category"] == "order_uncertain" and a["order_uncertain"] for a in alerts))


if __name__ == "__main__":
    unittest.main()
