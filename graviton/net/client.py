"""TCP client for Graviton wire protocol with pinned node key verification."""
from __future__ import annotations

import json
import socket
import ssl

from graviton.crypto.signatures import sign_message, verify_signature
from graviton.feed.encoding import enc_u64
from graviton.net.protocol import (
    DEFAULT_MAX_FRAME_BYTES,
    OP_FEED_PULL,
    OP_STATUS,
    REQUEST_SIGN_DOMAIN,
    RESPONSE_SIGN_DOMAIN,
    HelloMessage,
    ProtocolError,
    RequestMessage,
    ResponseMessage,
    decode_hello,
    decode_response,
    encode_feed_push,
    encode_request,
    public_key_fingerprint_bytes,
    read_frame,
    request_signing_bytes,
    response_signing_bytes,
    write_frame,
)


class NodeClientError(RuntimeError):
    """Raised on connection, authentication, or response-signature failures."""


class NodeClient:
    """Single-connection client enforcing HELLO pinning, seq, and response signatures."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        expected_node_pk: bytes | None = None,
        timeout: float = 5.0,
        max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
        tls_ca: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.expected_node_pk = expected_node_pk
        self.timeout = timeout
        self.max_frame_bytes = max_frame_bytes
        self.tls_ca = tls_ca
        self._sock: socket.socket | None = None
        self.hello: HelloMessage | None = None
        self._seq = 0

    def __enter__(self) -> "NodeClient":
        self.connect()
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def connect(self) -> HelloMessage:
        raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        raw_sock.settimeout(self.timeout)
        if self.tls_ca is not None:
            ctx = ssl.create_default_context(cafile=self.tls_ca)
            self._sock = ctx.wrap_socket(raw_sock, server_hostname=self.host)
        else:
            self._sock = raw_sock

        frame = read_frame(self._sock, max_frame_bytes=self.max_frame_bytes)
        hello = decode_hello(frame, max_len=self.max_frame_bytes)
        if self.expected_node_pk is not None:
            if hello.node_pk_sha256 != public_key_fingerprint_bytes(self.expected_node_pk):
                self.close()
                raise NodeClientError("Node public key fingerprint mismatch in HELLO")
        self.hello = hello
        self._seq = 0
        return hello

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _verify_response(self, request_body: bytes, resp_body: bytes) -> ResponseMessage:
        resp = decode_response(resp_body, max_len=self.max_frame_bytes)
        if self.expected_node_pk is not None:
            msg = response_signing_bytes(request_body, resp.status, resp.payload)
            if not verify_signature(
                self.expected_node_pk, msg, resp.signature, domain=RESPONSE_SIGN_DOMAIN
            ):
                raise NodeClientError("Invalid node ML-DSA-65 response signature")
        return resp

    def send_request(
        self,
        actor: str,
        device_id: str,
        key_version: int,
        signing_secret_key: bytes,
        op: int,
        payload: bytes = b"",
    ) -> ResponseMessage:
        if self._sock is None or self.hello is None:
            raise NodeClientError("Not connected")
        self._seq += 1
        seq = self._seq
        sig_input = request_signing_bytes(
            self.hello.feed_id, self.hello.server_nonce, seq, op, payload
        )
        sig = sign_message(signing_secret_key, sig_input, domain=REQUEST_SIGN_DOMAIN)
        req_body = encode_request(
            RequestMessage(actor, device_id, key_version, seq, op, payload, sig)
        )
        write_frame(self._sock, req_body, max_frame_bytes=self.max_frame_bytes)
        resp_body = read_frame(self._sock, max_frame_bytes=self.max_frame_bytes)
        resp = self._verify_response(req_body, resp_body)
        if resp.seq != seq:
            raise NodeClientError(f"Response sequence mismatch: expected {seq}, got {resp.seq}")
        return resp

    def status(
        self, actor: str, device_id: str, key_version: int, signing_secret_key: bytes
    ) -> dict:
        resp = self.send_request(actor, device_id, key_version, signing_secret_key, OP_STATUS, b"")
        if resp.status != 0:
            raise NodeClientError(f"STATUS denied/failed (status={resp.status})")
        return json.loads(resp.payload.decode("utf-8"))

    def feed_pull(
        self,
        actor: str,
        device_id: str,
        key_version: int,
        signing_secret_key: bytes,
        since_epoch: int,
    ) -> list[bytes]:
        resp = self.send_request(
            actor, device_id, key_version, signing_secret_key, OP_FEED_PULL, enc_u64(since_epoch)
        )
        if resp.status != 0:
            raise NodeClientError(f"FEED_PULL denied/failed (status={resp.status})")
        raw_list = json.loads(resp.payload.decode("utf-8"))
        return [bytes.fromhex(h) for h in raw_list]

    def feed_push(self, entries: list[bytes]) -> dict:
        if self._sock is None or self.hello is None:
            raise NodeClientError("Not connected")
        push_body = encode_feed_push(entries)
        write_frame(self._sock, push_body, max_frame_bytes=self.max_frame_bytes)
        resp_body = read_frame(self._sock, max_frame_bytes=self.max_frame_bytes)
        resp = self._verify_response(push_body, resp_body)
        return json.loads(resp.payload.decode("utf-8"))
