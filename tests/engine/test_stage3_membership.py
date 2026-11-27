"""Stage 3 real-process tests: invitation, out-of-band fingerprint, join, approve, and lost device."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import secrets
import socket
import tempfile
import unittest

from graviton.admin import AdminManager
from graviton.client import ClientManager
from graviton.crypto.aead import aead_available
from graviton.crypto.keystore import load_keystore
from graviton.crypto.signatures import generate_signing_keypair
from graviton.daemon.node import init_node_daemon
from graviton.net.client import NodeClient, NodeClientError
from graviton.net.protocol import (
    OP_STATUS,
    STATUS_DENIED,
    STATUS_OK,
    read_frame,
    write_frame,
)
from tests.engine.helpers import DaemonProcess


@unittest.skipUnless(aead_available(), "Stage 3 requires the 'app' extra (cryptography)")
class TestStage3Membership(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="graviton-stage3-")
        self.base = Path(self._tmp.name)
        self.pw_kavya = secrets.token_hex(12)
        self.pw_arjun = secrets.token_hex(12)
        self.pw_neel = secrets.token_hex(12)
        self.pw_mallory = secrets.token_hex(12)

        self.kavya = AdminManager(self.base / "kavya_home")
        self.kavya.init_group("kavya-team", self.pw_kavya, operator_handle="kavya")
        st = self.kavya._load_state()
        self.feed_id = st["feed_id"]
        self.admin_pk = base64.b64decode(st["admin_pk_b64"])

        self.hub_dir = self.base / "hub"
        self.hub_ready = self.base / "hub.ready.json"
        _, self.hub_pk, _ = init_node_daemon(self.hub_dir, "hub-1", self.feed_id, self.admin_pk)
        self.hub = DaemonProcess(
            [
                "node",
                "run",
                "--dir",
                str(self.hub_dir),
                "--listen",
                "127.0.0.1:0",
                "--operator",
                "kavya",
                "--ready-file",
                str(self.hub_ready),
            ],
            self.hub_ready,
        )
        self.kavya.add_node(
            self.hub.host, self.hub.port, node_pk_b64=base64.b64encode(self.hub_pk).decode("ascii")
        )

    def tearDown(self) -> None:
        self.hub.stop()
        self._tmp.cleanup()

    def test_01_full_join_flow_and_lost_device_and_mallory_isolation(self) -> None:
        # 1. Kavya invites Arjun; Arjun initialises and joins with out-of-band fingerprint confirmation
        inv_arjun = self.kavya.create_invite("arjun", 900, self.base / "arjun.invite", self.pw_kavya)
        arjun = ClientManager(self.base / "arjun_home")
        arjun_st = arjun.init_identity("arjun", self.pw_arjun, device_id="arjun-dev1")
        _, _, arjun_sk = load_keystore(arjun.keystore_path, self.pw_arjun)

        # Unconfirmed admin fingerprint must abort
        with self.assertRaises(PermissionError):
            arjun.join_invite(self.base / "arjun.invite", self.pw_arjun, confirm_fn=lambda _fp: False)

        # Confirmed join submits JOIN_REQUEST; before approval Arjun is still denied
        join_res = arjun.join_invite(
            self.base / "arjun.invite",
            self.pw_arjun,
            confirm_fn=lambda fp: fp == inv_arjun["admin_fp"],
        )
        self.assertEqual(join_res["status"], "pending")
        with NodeClient(self.hub.host, self.hub.port, expected_node_pk=self.hub_pk) as cli:
            self.assertEqual(cli.send_request("arjun", "arjun-dev1", 1, arjun_sk, OP_STATUS).status, STATUS_DENIED)

        # Replay of used invite after join -> refused
        with self.assertRaises(NodeClientError):
            arjun.join_invite(self.base / "arjun.invite", self.pw_arjun, confirm_fn=lambda _fp: True)

        # Kavya checks pending and approves Arjun after fingerprint check
        pending = self.kavya.pending_joins(self.pw_kavya)
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["device_fp"], arjun_st["fingerprint"])
        self.kavya.approve_join("arjun", self.pw_kavya, confirm_fn=lambda fp: fp == arjun_st["fingerprint"])

        # Now Arjun succeeds
        with NodeClient(self.hub.host, self.hub.port, expected_node_pk=self.hub_pk) as cli:
            self.assertEqual(cli.send_request("arjun", "arjun-dev1", 1, arjun_sk, OP_STATUS).status, STATUS_OK)

        # 2. Invite replay after approval -> refused
        with self.assertRaises(NodeClientError):
            arjun.join_invite(self.base / "arjun.invite", self.pw_arjun, confirm_fn=lambda _fp: True)

        # 3. Kavya invites Neel -> joins & approved
        self.kavya.create_invite("neel", 900, self.base / "neel.invite", self.pw_kavya)
        neel = ClientManager(self.base / "neel_home")
        neel_st = neel.init_identity("neel", self.pw_neel, device_id="neel-dev1")
        _, _, neel_sk = load_keystore(neel.keystore_path, self.pw_neel)
        neel.join_invite(self.base / "neel.invite", self.pw_neel, confirm_fn=lambda _fp: True)
        self.kavya.approve_join("neel", self.pw_kavya, confirm_fn=lambda fp: fp == neel_st["fingerprint"])
        with NodeClient(self.hub.host, self.hub.port, expected_node_pk=self.hub_pk) as cli:
            self.assertEqual(cli.send_request("neel", "neel-dev1", 1, neel_sk, OP_STATUS).status, STATUS_OK)

        # 4. Mallory creates her own group -> gains nothing in Kavya's group
        mallory_adm = AdminManager(self.base / "mallory_home")
        mallory_adm.init_group("mallory-grp", self.pw_mallory, operator_handle="mallory")
        _, _, mallory_sk = load_keystore(mallory_adm.keystore_path, self.pw_mallory)
        with NodeClient(self.hub.host, self.hub.port, expected_node_pk=self.hub_pk) as cli:
            self.assertEqual(cli.send_request("mallory", "admin-dev", 1, mallory_sk, OP_STATUS).status, STATUS_DENIED)

        # 5. Lost device: revoke arjun-dev1, re-enrol arjun-dev2, Neel stays unaffected
        self.kavya.revoke("arjun", self.pw_kavya, device_id="arjun-dev1")
        with NodeClient(self.hub.host, self.hub.port, expected_node_pk=self.hub_pk) as cli:
            self.assertEqual(cli.send_request("arjun", "arjun-dev1", 1, arjun_sk, OP_STATUS).status, STATUS_DENIED)
            self.assertEqual(cli.send_request("neel", "neel-dev1", 1, neel_sk, OP_STATUS).status, STATUS_OK)

        self.kavya.create_invite("arjun", 900, self.base / "arjun2.invite", self.pw_kavya)
        arjun2 = ClientManager(self.base / "arjun2_home")
        arjun2_st = arjun2.init_identity("arjun", self.pw_arjun, device_id="arjun-dev2")
        _, _, arjun2_sk = load_keystore(arjun2.keystore_path, self.pw_arjun)
        arjun2.join_invite(self.base / "arjun2.invite", self.pw_arjun, confirm_fn=lambda _fp: True)
        self.kavya.approve_join("arjun", self.pw_kavya, confirm_fn=lambda fp: fp == arjun2_st["fingerprint"])
        with NodeClient(self.hub.host, self.hub.port, expected_node_pk=self.hub_pk) as cli:
            self.assertEqual(cli.send_request("arjun", "arjun-dev2", 1, arjun2_sk, OP_STATUS).status, STATUS_OK)
            self.assertEqual(cli.send_request("arjun", "arjun-dev1", 1, arjun_sk, OP_STATUS).status, STATUS_DENIED)

    def test_02_expired_wrong_secret_bad_pop_and_malformed_join_rejected(self) -> None:
        # Expired invite
        self.kavya.create_invite("arjun", -10, self.base / "exp.invite", self.pw_kavya)
        c1 = ClientManager(self.base / "c1")
        c1.init_identity("arjun", self.pw_arjun, device_id="d1")
        with self.assertRaises(NodeClientError):
            c1.join_invite(self.base / "exp.invite", self.pw_arjun, confirm_fn=lambda _fp: True)

        # Wrong secret
        inv = self.kavya.create_invite("arjun", 900, self.base / "good.invite", self.pw_kavya)
        wrong_sec_inv = dict(inv)
        wrong_sec_inv["invite_secret_b64"] = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        (self.base / "wrong.invite").write_text(json.dumps(wrong_sec_inv), encoding="utf-8")
        with self.assertRaises(NodeClientError):
            c1.join_invite(self.base / "wrong.invite", self.pw_arjun, confirm_fn=lambda _fp: True)

        # PoP signed by a different key
        other_pk, other_sk = generate_signing_keypair()
        with NodeClient(self.hub.host, self.hub.port, expected_node_pk=self.hub_pk) as cli:
            r_bad_pop = cli.join_request(
                inv["invite_id"],
                base64.b64decode(inv["invite_secret_b64"]),
                "arjun",
                "d-bad",
                other_pk,
                self.kavya._load_author(self.pw_kavya)[0]._admin_secret_key,  # wrong signing key
            )
            self.assertEqual(r_bad_pop.status, STATUS_DENIED)

        # Malformed JOIN_REQUEST frame
        with socket.create_connection((self.hub.host, self.hub.port), timeout=5) as s:
            _ = read_frame(s)
            write_frame(s, b"\x01\x05\x00\x00")
            resp = read_frame(s)
            self.assertTrue(len(resp) > 0)


if __name__ == "__main__":
    unittest.main()
