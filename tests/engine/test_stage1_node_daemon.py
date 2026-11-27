"""Stage 1 real-process TCP tests for NodeDaemon and wire protocol."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import secrets
import socket
import tempfile
import unittest

from graviton.audit import AuditLog
from graviton.crypto.signatures import generate_signing_keypair, sign_message
from graviton.daemon.node import init_node_daemon
from graviton.feed.author import FeedAuthor
from graviton.feed.encoding import enc_u32
from graviton.net.client import NodeClient, NodeClientError
from graviton.net.protocol import (
    OP_STATUS,
    REQUEST_SIGN_DOMAIN,
    STATUS_DENIED,
    STATUS_OK,
    RequestMessage,
    decode_hello,
    decode_response,
    encode_request,
    read_frame,
    request_signing_bytes,
    write_frame,
)
from graviton.nodes import Node
from tests.engine.helpers import DaemonProcess


class TestStage1NodeDaemon(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="graviton-stage1-")
        self.base = Path(self._tmp.name)
        self.node_dir = self.base / "node1"
        self.ready_file = self.base / "node1.ready.json"
        self.feed_id = "grp-" + secrets.token_hex(8)
        self.kavya_pk, self.kavya_sk = generate_signing_keypair()
        self.arjun_pk1, self.arjun_sk1 = generate_signing_keypair()
        self.arjun_pk2, self.arjun_sk2 = generate_signing_keypair()
        self.mallory_pk, self.mallory_sk = generate_signing_keypair()

        self.author = FeedAuthor(self.feed_id, self.kavya_sk)
        self.e_genesis = self.author.genesis()
        self.e_reg_arjun = self.author.register_key("arjun", "arjun-dev1", self.arjun_pk1)

        _, self.node_pk, _ = init_node_daemon(self.node_dir, "hub-1", self.feed_id, self.kavya_pk)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _start_node(self, *, max_connections: int = 64, read_timeout: float = 5.0) -> DaemonProcess:
        return DaemonProcess(
            [
                "node",
                "run",
                "--dir",
                str(self.node_dir),
                "--listen",
                "127.0.0.1:0",
                "--max-connections",
                str(max_connections),
                "--read-timeout",
                str(read_timeout),
                "--ready-file",
                str(self.ready_file),
            ],
            self.ready_file,
        )

    def test_01_feed_push_status_pull_and_auth_failures(self) -> None:
        daemon = self._start_node()
        try:
            with NodeClient(daemon.host, daemon.port, expected_node_pk=self.node_pk) as cli:
                push_res = cli.feed_push([self.e_genesis, self.e_reg_arjun])
                self.assertEqual(push_res["applied"], 2)

                st = cli.status("arjun", "arjun-dev1", 1, self.arjun_sk1)
                self.assertEqual(st["applied_epoch"], 2)
                self.assertTrue(st["integrity_ok"])

                pulled = cli.feed_pull("arjun", "arjun-dev1", 1, self.arjun_sk1, since_epoch=0)
                self.assertEqual(pulled, [self.e_genesis, self.e_reg_arjun])

                # Wrong key -> STATUS_DENIED, no reason in payload
                r_bad_key = cli.send_request("arjun", "arjun-dev1", 1, self.mallory_sk, OP_STATUS)
                self.assertEqual(r_bad_key.status, STATUS_DENIED)
                self.assertEqual(r_bad_key.payload, b"")

                # Wrong version -> STATUS_DENIED
                r_bad_ver = cli.send_request("arjun", "arjun-dev1", 99, self.arjun_sk1, OP_STATUS)
                self.assertEqual(r_bad_ver.status, STATUS_DENIED)
                self.assertEqual(r_bad_ver.payload, b"")

            # Forked/gapped/rolled-back entries rejected
            fork_author = FeedAuthor(self.feed_id, self.kavya_sk)
            fork_e1 = fork_author.genesis()
            with NodeClient(daemon.host, daemon.port, expected_node_pk=self.node_pk) as cli:
                with self.assertRaises(NodeClientError):
                    # feed_push returns STATUS_DENIED (valid signature from node, status != 0)
                    res = cli.feed_push([fork_e1])
                    if res.get("applied", 0) == 0:
                        raise NodeClientError("rejected")

            # Replay captured REQUEST on a new connection (different server_nonce) -> denied
            with socket.create_connection((daemon.host, daemon.port), timeout=5) as s1:
                hello1 = decode_hello(read_frame(s1))
                sig1 = sign_message(
                    self.arjun_sk1,
                    request_signing_bytes(self.feed_id, hello1.server_nonce, 1, OP_STATUS, b""),
                    domain=REQUEST_SIGN_DOMAIN,
                )
                captured_req = encode_request(RequestMessage("arjun", "arjun-dev1", 1, 1, OP_STATUS, b"", sig1))
                write_frame(s1, captured_req)
                self.assertEqual(decode_response(read_frame(s1)).status, STATUS_OK)

                # Repeated seq=1 on same connection -> denied and closed
                write_frame(s1, captured_req)
                self.assertEqual(decode_response(read_frame(s1)).status, STATUS_DENIED)

            with socket.create_connection((daemon.host, daemon.port), timeout=5) as s2:
                _ = decode_hello(read_frame(s2))
                write_frame(s2, captured_req)
                self.assertEqual(decode_response(read_frame(s2)).status, STATUS_DENIED)

            # Revoke Arjun -> refused on next connection
            e_rev = self.author.revoke_actor("arjun")
            with NodeClient(daemon.host, daemon.port, expected_node_pk=self.node_pk) as cli:
                self.assertEqual(cli.feed_push([e_rev])["applied"], 1)
                r_rev = cli.send_request("arjun", "arjun-dev1", 1, self.arjun_sk1, OP_STATUS)
                self.assertEqual(r_rev.status, STATUS_DENIED)
                self.assertEqual(r_rev.payload, b"")
        finally:
            out, err = daemon.stop()
            # No secret key material in stdout/stderr
            self.assertNotIn(base64.b64encode(self.kavya_sk).decode(), out + err)
            self.assertNotIn(base64.b64encode(self.arjun_sk1).decode(), out + err)

        audit = AuditLog(self.node_dir / "audit.db", self.node_dir / "audit_head.json")
        self.assertTrue(audit.verify().valid)
        self.assertGreaterEqual(len(audit.fetch_events()), 5)

    def test_02_hostile_inputs_and_kill_restart_consistency(self) -> None:
        daemon = self._start_node(max_connections=4, read_timeout=0.5)
        try:
            with NodeClient(daemon.host, daemon.port, expected_node_pk=self.node_pk) as cli:
                cli.feed_push([self.e_genesis, self.e_reg_arjun, self.author.revoke_actor("arjun")])

            # 1. Oversized length prefix (> 1 MiB) -> node drops connection and stays up
            with socket.create_connection((daemon.host, daemon.port), timeout=2) as s:
                _ = read_frame(s)
                s.sendall(enc_u32(10 * 1024 * 1024))

            # 2. Random bytes / truncated frame
            with socket.create_connection((daemon.host, daemon.port), timeout=2) as s:
                _ = read_frame(s)
                s.sendall(b"\x00\x00\x00\x05\xff\xfe")

            # 3. Unknown message type
            with socket.create_connection((daemon.host, daemon.port), timeout=2) as s:
                _ = read_frame(s)
                write_frame(s, b"\x01\x7f\x00")

            # 4. Slow client timeout
            with socket.create_connection((daemon.host, daemon.port), timeout=2) as s:
                _ = read_frame(s)
                s.sendall(b"\x00\x00")

            # 5. Hard kill (kill -9 equivalent) and restart on same directory
            daemon.kill()
            self.ready_file.unlink(missing_ok=True)
            restarted = self._start_node()
            try:
                with NodeClient(restarted.host, restarted.port, expected_node_pk=self.node_pk) as cli:
                    # Arjun remains revoked after hard crash & restart
                    r_rev = cli.send_request("arjun", "arjun-dev1", 1, self.arjun_sk1, OP_STATUS)
                    self.assertEqual(r_rev.status, STATUS_DENIED)
                self.assertTrue(Node(self.node_dir).verify_integrity())
            finally:
                restarted.stop()
        finally:
            daemon.stop()


if __name__ == "__main__":
    unittest.main()
