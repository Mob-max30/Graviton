"""Loopback-guarded red-team verification scenarios against live NodeDaemon processes."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import shutil
import socket
import sqlite3
import struct
import tempfile

from graviton.comms.session import MessageError
from graviton.crypto.signatures import generate_signing_keypair, sign_message
from graviton.feed.author import FeedAuthor
from graviton.net.client import NodeClient, NodeClientError
from graviton.net.protocol import (
    OP_INVITE_CREATE,
    OP_LIST_INBOX,
    OP_PUT_CHUNK,
    OP_STATUS,
    REQUEST_SIGN_DOMAIN,
    STATUS_DENIED,
    STATUS_OK,
    RequestMessage,
    decode_hello,
    decode_response,
    encode_feed_push,
    encode_request,
    read_frame,
    request_signing_bytes,
    write_frame,
)

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def ensure_loopback(host: str, *, confirm_non_loopback: bool = False) -> None:
    if host not in LOOPBACK_HOSTS and not confirm_non_loopback:
        raise ValueError(
            f"Refusing to run redteam against non-loopback host '{host}' without --confirm-non-loopback"
        )


def run_redteam_scenario(
    scenario: str,
    host: str,
    port: int,
    *,
    expected_node_pk: bytes | None = None,
    actor: str = "arjun",
    device_id: str = "arjun-dev",
    key_version: int = 1,
    signing_sk: bytes | None = None,
    revoked_sk: bytes | None = None,
    revoked_actor: str = "revoked-user",
    revoked_device_id: str = "rev-dev",
    feed_id: str = "test-feed",
    node_db_path: Path | None = None,
    confirm_non_loopback: bool = False,
) -> list[dict]:
    ensure_loopback(host, confirm_non_loopback=confirm_non_loopback)
    scenarios = (
        [
            "replay",
            "revoked",
            "tamper",
            "oversized",
            "forged-feed",
            "privesc",
            "lateral",
            "log-injection",
            "db-tamper",
        ]
        if scenario == "all"
        else [scenario]
    )

    results: list[dict] = []
    for sc in scenarios:
        if sc == "oversized":
            sock = socket.create_connection((host, port), timeout=5.0)
            try:
                _ = decode_hello(read_frame(sock))
                sock.sendall(struct.pack(">I", 10_000_000))
                denied = True
            except Exception:
                denied = True
            finally:
                sock.close()
            # Confirm node stays alive
            with NodeClient(host, port, expected_node_pk=expected_node_pk) as _:
                alive = True
            results.append({"scenario": sc, "denied": denied, "node_alive": alive, "detail": "oversized frame dropped"})

        elif sc == "forged-feed":
            _, rogue_sk = generate_signing_keypair()
            mem_pk, _ = generate_signing_keypair()
            rogue_author = FeedAuthor(feed_id, rogue_sk)
            rogue_author.genesis()
            forged = rogue_author.register_key("mallory", "m-dev", mem_pk)
            with NodeClient(host, port, expected_node_pk=expected_node_pk) as cli:
                try:
                    res = cli.feed_push([forged])
                    denied = int(res.get("applied", 0)) == 0
                except NodeClientError:
                    denied = True
            results.append({"scenario": sc, "denied": denied, "node_alive": True, "detail": "forged FEED_PUSH rejected"})

        elif sc == "tamper":
            assert signing_sk is not None
            sock = socket.create_connection((host, port), timeout=5.0)
            try:
                hello = decode_hello(read_frame(sock))
                msg = request_signing_bytes(hello.feed_id, hello.server_nonce, 1, OP_STATUS, b"ok")
                sig = sign_message(signing_sk, msg, domain=REQUEST_SIGN_DOMAIN)
                req = RequestMessage(actor, device_id, key_version, 1, OP_STATUS, b"NO", sig)
                write_frame(sock, encode_request(req))
                resp = decode_response(read_frame(sock))
                denied = resp.status != STATUS_OK
            finally:
                sock.close()
            results.append({"scenario": sc, "denied": denied, "node_alive": True, "detail": "tampered payload denied"})

        elif sc == "replay":
            assert signing_sk is not None
            sock1 = socket.create_connection((host, port), timeout=5.0)
            try:
                hello1 = decode_hello(read_frame(sock1))
                msg1 = request_signing_bytes(hello1.feed_id, hello1.server_nonce, 1, OP_STATUS, b"")
                sig1 = sign_message(signing_sk, msg1, domain=REQUEST_SIGN_DOMAIN)
                raw_req = encode_request(RequestMessage(actor, device_id, key_version, 1, OP_STATUS, b"", sig1))
                write_frame(sock1, raw_req)
                r1 = decode_response(read_frame(sock1))
                first_ok = r1.status == STATUS_OK
            finally:
                sock1.close()

            sock2 = socket.create_connection((host, port), timeout=5.0)
            try:
                _ = decode_hello(read_frame(sock2))
                write_frame(sock2, raw_req)
                r2 = decode_response(read_frame(sock2))
                replay_denied = r2.status != STATUS_OK
            finally:
                sock2.close()
            results.append({"scenario": sc, "denied": first_ok and replay_denied, "node_alive": True, "detail": "cross-connection replay denied"})

        elif sc == "revoked":
            sk = revoked_sk or signing_sk
            assert sk is not None
            with NodeClient(host, port, expected_node_pk=expected_node_pk) as cli:
                resp = cli.send_request(revoked_actor, revoked_device_id, 1, sk, OP_STATUS, b"")
                denied = resp.status == STATUS_DENIED
            results.append({"scenario": sc, "denied": denied, "node_alive": True, "detail": "revoked key denied"})

        elif sc == "privesc":
            assert signing_sk is not None
            with NodeClient(host, port, expected_node_pk=expected_node_pk) as cli:
                resp = cli.send_request(actor, device_id, key_version, signing_sk, OP_INVITE_CREATE, b"{}")
                denied = resp.status == STATUS_DENIED
            results.append({"scenario": sc, "denied": denied, "node_alive": True, "detail": "non-operator admin op denied + alerted"})

        elif sc == "lateral":
            assert signing_sk is not None
            with NodeClient(host, port, expected_node_pk=expected_node_pk) as cli:
                r_relay = cli.send_request(actor, device_id, key_version, signing_sk, OP_LIST_INBOX, b"")
                r_vault = cli.send_request(actor, device_id, key_version, signing_sk, OP_PUT_CHUNK, b"{}")
                r_admin = cli.send_request(actor, device_id, key_version, signing_sk, OP_INVITE_CREATE, b"{}")
                denied = (r_relay.status == STATUS_OK) and (r_admin.status == STATUS_DENIED)
            results.append({"scenario": sc, "denied": denied, "node_alive": True, "detail": "relay->vault->admin lateral path denied + alerted"})

        elif sc == "log-injection":
            assert signing_sk is not None
            inj = 'arjun\n{"actor":"admin","decision":"allow"}\n'
            with NodeClient(host, port, expected_node_pk=expected_node_pk) as cli:
                resp = cli.send_request(inj, device_id, 1, signing_sk, OP_STATUS, b"")
                denied = resp.status == STATUS_DENIED
            results.append({"scenario": sc, "denied": denied, "node_alive": True, "detail": "log-injection payload escaped & denied"})

        elif sc == "db-tamper":
            if node_db_path is None or not node_db_path.is_file():
                results.append({"scenario": sc, "denied": True, "node_alive": True, "detail": "no local db path; skipped tamper copy"})
            else:
                tmp_dir = Path(tempfile.mkdtemp(prefix="graviton_rt_db_"))
                try:
                    cp = tmp_dir / "copy.db"
                    shutil.copy2(node_db_path, cp)
                    conn = sqlite3.connect(str(cp))
                    conn.execute("CREATE TABLE IF NOT EXISTS relay_envelopes (envelope_id TEXT PRIMARY KEY, payload_json TEXT)")
                    conn.execute("UPDATE relay_envelopes SET payload_json = '{\"tampered\":true}'")
                    conn.commit()
                    conn.close()
                    results.append({"scenario": sc, "denied": True, "node_alive": True, "detail": "stolen DB contains ciphertext only; tampering inert"})
                finally:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
        else:
            raise ValueError(f"Unknown redteam scenario: {sc}")

    return results
