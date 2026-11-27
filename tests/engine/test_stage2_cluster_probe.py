"""Stage 2 real multi-process cluster, rotation, crash-catchup, and 30-run probe tests."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import unittest

from graviton.admin import AdminManager
from graviton.cluster import cluster_down, cluster_status, cluster_up
from graviton.crypto.aead import aead_available
from graviton.crypto.signatures import generate_signing_keypair
from graviton.net.client import NodeClient
from graviton.net.protocol import OP_STATUS, STATUS_DENIED, STATUS_OK
from tests.engine.helpers import DaemonProcess

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@unittest.skipUnless(aead_available(), "Stage 2 requires the 'app' extra (cryptography)")
class TestStage2ClusterAndProbe(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="graviton-stage2-")
        self.base = Path(self._tmp.name)
        self.home = self.base / "home"
        self.cluster_dir = self.base / "cluster"
        self.passphrase = secrets.token_hex(16)
        self.mgr = AdminManager(self.home)
        self.mgr.init_group("kavya-grp", self.passphrase)
        st = self.mgr._load_state()
        self.feed_id = st["feed_id"]
        self.admin_pk = base64.b64decode(st["admin_pk_b64"])
        self.entries = [bytes.fromhex(h) for h in st["entries_hex"]]

    def tearDown(self) -> None:
        cluster_down(self.cluster_dir)
        self._tmp.cleanup()

    def test_01_cluster_rotation_offline_catchup_and_30_run_probe(self) -> None:
        cinfo = cluster_up(
            self.cluster_dir,
            3,
            self.feed_id,
            self.admin_pk,
            sync_interval_s=0.1,
            initial_entries=self.entries,
        )
        nodes = cinfo["nodes"]
        for n in nodes:
            self.mgr.add_node(n["host"], int(n["port"]))
        for n in nodes[1:]:
            self.mgr.register_key(
                n["node_id"], n["node_id"], base64.b64decode(n["node_pk_b64"]), self.passphrase
            )

        # Verify cluster_status sees all 3 live nodes
        statuses = cluster_status(self.cluster_dir)
        self.assertEqual(len(statuses), 3)
        self.assertTrue(all(s["alive"] for s in statuses))

        # Register Arjun v1, then rotate to v2 with cutoff 2 epochs ahead
        arjun_pk1, arjun_sk1 = generate_signing_keypair()
        arjun_pk2, arjun_sk2 = generate_signing_keypair()
        self.mgr.register_key("arjun", "dev-1", arjun_pk1, self.passphrase)
        self.mgr.rotate("arjun", "dev-1", 2, arjun_pk2, cutoff_offset=2, passphrase=self.passphrase)

        # Before cutoff: both v1 and v2 accepted on every node
        for n in nodes:
            pk = base64.b64decode(n["node_pk_b64"])
            with NodeClient(n["host"], int(n["port"]), expected_node_pk=pk) as cli:
                self.assertEqual(cli.send_request("arjun", "dev-1", 1, arjun_sk1, OP_STATUS).status, STATUS_OK)
                self.assertEqual(cli.send_request("arjun", "dev-1", 2, arjun_sk2, OP_STATUS).status, STATUS_OK)

        # Emit 2 HEADs to reach cutoff_epoch -> v1 refused on every node, v2 allowed
        self.mgr.emit_head(self.passphrase)
        self.mgr.emit_head(self.passphrase)
        for n in nodes:
            pk = base64.b64decode(n["node_pk_b64"])
            with NodeClient(n["host"], int(n["port"]), expected_node_pk=pk) as cli:
                self.assertEqual(cli.send_request("arjun", "dev-1", 1, arjun_sk1, OP_STATUS).status, STATUS_DENIED)
                self.assertEqual(cli.send_request("arjun", "dev-1", 2, arjun_sk2, OP_STATUS).status, STATUS_OK)

        # Run external 30-run revocation probe CLI as a separate process
        probe_out = self.base / "probe_30.json"
        env = os.environ.copy()
        env["GRAVITON_HOME"] = str(self.home)
        env["GRAVITON_PASSPHRASE"] = self.passphrase
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "graviton",
                "probe",
                "revocation",
                "--cluster-dir",
                str(self.cluster_dir),
                "--runs",
                "30",
                "--poll-interval",
                "0.05",
                "--out",
                str(probe_out),
            ],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        print("\n" + proc.stdout.strip(), flush=True)
        pdata = json.loads(probe_out.read_text(encoding="utf-8"))
        self.assertEqual(pdata["runs"], 30)
        self.assertEqual(pdata["node_count"], 3)
        self.assertGreater(pdata["last_node_median_ms"], 0.0)

        # Offline node catch-up: kill node_2, revoke Neel on hub only, restart node_2 with --upstream
        neel_pk, neel_sk = generate_signing_keypair()
        self.mgr.register_key("neel", "neel-dev", neel_pk, self.passphrase)

        n2 = nodes[2]
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(n2["pid"]), "/T", "/F"], capture_output=True, check=False)
        else:
            os.kill(int(n2["pid"]), 9)

        # Revoke Neel and push ONLY to hub (node_0)
        author, st, _ = self.mgr._load_author(self.passphrase)
        rev_neel = author.revoke_actor("neel")
        self.mgr._commit_entry(author, st, rev_neel)
        hub = nodes[0]
        hub_pk = base64.b64decode(hub["node_pk_b64"])
        with NodeClient(hub["host"], int(hub["port"]), expected_node_pk=hub_pk) as cli:
            cli.feed_push([rev_neel])

        # Restart node_2 pointing to hub --upstream; poll until it refuses Neel
        rfile = self.base / "node2_restarted.ready.json"
        restarted = DaemonProcess(
            [
                "node",
                "run",
                "--dir",
                n2["dir"],
                "--listen",
                "127.0.0.1:0",
                "--upstream",
                f"{hub['host']}:{hub['port']}",
                "--sync-interval",
                "0.1",
                "--ready-file",
                str(rfile),
            ],
            rfile,
        )
        try:
            n2_pk = base64.b64decode(n2["node_pk_b64"])
            deadline = time.monotonic() + 10.0
            refused = False
            while time.monotonic() < deadline:
                with NodeClient(restarted.host, restarted.port, expected_node_pk=n2_pk) as cli:
                    if cli.send_request("neel", "neel-dev", 1, neel_sk, OP_STATUS).status == STATUS_DENIED:
                        refused = True
                        break
                time.sleep(0.05)
            self.assertTrue(refused, "Restarted offline node did not catch up and refuse revoked Neel")
        finally:
            restarted.stop()


if __name__ == "__main__":
    unittest.main()
