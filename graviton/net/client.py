"""TCP client for Graviton wire protocol with pinned node key verification."""
from __future__ import annotations

import json
import socket
import ssl

from graviton.crypto.signatures import sign_message, verify_signature
from graviton.feed.encoding import enc_u64
from graviton.net.protocol import (
    DEFAULT_MAX_FRAME_BYTES,
    JOIN_SIGN_DOMAIN,
    OP_ACK,
    OP_AUDIT_PULL,
    OP_FEED_PULL,
    OP_FETCH_ENVELOPE,
    OP_GET_CHUNK,
    OP_INVITE_CREATE,
    OP_JOIN_LIST,
    OP_JOIN_RESOLVE,
    OP_LIST_INBOX,
    OP_PUT_CHUNK,
    OP_PUT_ENVELOPE,
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
    encode_join_request,
    encode_request,
    join_signing_bytes,
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
        timeout: float = 15.0,
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
        if not resp.payload:
            raise NodeClientError(f"FEED_PUSH rejected (status={resp.status})")
        return json.loads(resp.payload.decode("utf-8"))

    def join_request(
        self,
        invite_id: str,
        invite_secret: bytes,
        handle: str,
        device_id: str,
        device_pk: bytes,
        device_sk: bytes,
    ) -> ResponseMessage:
        if self._sock is None or self.hello is None:
            raise NodeClientError("Not connected")
        msg = join_signing_bytes(invite_id, invite_secret, handle, device_id, device_pk)
        pop_sig = sign_message(device_sk, msg, domain=JOIN_SIGN_DOMAIN)
        body = encode_join_request(invite_id, invite_secret, handle, device_id, device_pk, pop_sig)
        write_frame(self._sock, body, max_frame_bytes=self.max_frame_bytes)
        resp_body = read_frame(self._sock, max_frame_bytes=self.max_frame_bytes)
        return self._verify_response(body, resp_body)

    def create_invite(
        self,
        actor: str,
        device_id: str,
        key_version: int,
        signing_sk: bytes,
        invite_id: str,
        secret_sha256: str,
        handle_hint: str,
        expires_at: int,
    ) -> dict:
        payload = json.dumps(
            {
                "invite_id": invite_id,
                "secret_sha256": secret_sha256,
                "handle_hint": handle_hint,
                "expires_at": expires_at,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        resp = self.send_request(actor, device_id, key_version, signing_sk, OP_INVITE_CREATE, payload)
        if resp.status != 0:
            raise NodeClientError(f"INVITE_CREATE denied (status={resp.status})")
        return json.loads(resp.payload.decode("utf-8"))

    def join_list(self, actor: str, device_id: str, key_version: int, signing_sk: bytes) -> list[dict]:
        resp = self.send_request(actor, device_id, key_version, signing_sk, OP_JOIN_LIST, b"")
        if resp.status != 0:
            raise NodeClientError(f"JOIN_LIST denied (status={resp.status})")
        return json.loads(resp.payload.decode("utf-8"))

    def join_resolve(
        self,
        actor: str,
        device_id: str,
        key_version: int,
        signing_sk: bytes,
        invite_id: str,
        status: str,
    ) -> dict:
        payload = json.dumps({"invite_id": invite_id, "status": status}, separators=(",", ":")).encode("utf-8")
        resp = self.send_request(actor, device_id, key_version, signing_sk, OP_JOIN_RESOLVE, payload)
        if resp.status != 0:
            raise NodeClientError(f"JOIN_RESOLVE denied (status={resp.status})")
        return json.loads(resp.payload.decode("utf-8"))

    def put_envelope(
        self,
        actor: str,
        device_id: str,
        key_version: int,
        signing_sk: bytes,
        envelope_id: str,
        recipient: str,
        payload: dict | str,
        *,
        ttl_s: int = 3600,
        burn_after_read: bool = False,
    ) -> dict:
        body = json.dumps(
            {
                "envelope_id": envelope_id,
                "recipient": recipient,
                "payload": payload,
                "ttl_s": ttl_s,
                "burn_after_read": burn_after_read,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        resp = self.send_request(actor, device_id, key_version, signing_sk, OP_PUT_ENVELOPE, body)
        if resp.status != 0:
            raise NodeClientError(f"PUT_ENVELOPE denied (status={resp.status})")
        return json.loads(resp.payload.decode("utf-8"))

    def list_inbox(
        self,
        actor: str,
        device_id: str,
        key_version: int,
        signing_sk: bytes,
    ) -> list[dict]:
        resp = self.send_request(actor, device_id, key_version, signing_sk, OP_LIST_INBOX, b"")
        if resp.status != 0:
            raise NodeClientError(f"LIST_INBOX denied (status={resp.status})")
        return json.loads(resp.payload.decode("utf-8"))

    def fetch_envelope(
        self,
        actor: str,
        device_id: str,
        key_version: int,
        signing_sk: bytes,
        envelope_id: str,
    ) -> dict:
        body = json.dumps({"envelope_id": envelope_id}, separators=(",", ":")).encode("utf-8")
        resp = self.send_request(actor, device_id, key_version, signing_sk, OP_FETCH_ENVELOPE, body)
        if resp.status != 0:
            raise NodeClientError(f"FETCH_ENVELOPE denied (status={resp.status})")
        return json.loads(resp.payload.decode("utf-8"))

    def ack_envelope(
        self,
        actor: str,
        device_id: str,
        key_version: int,
        signing_sk: bytes,
        envelope_id: str,
    ) -> dict:
        body = json.dumps({"envelope_id": envelope_id}, separators=(",", ":")).encode("utf-8")
        resp = self.send_request(actor, device_id, key_version, signing_sk, OP_ACK, body)
        if resp.status != 0:
            raise NodeClientError(f"ACK denied (status={resp.status})")
        return json.loads(resp.payload.decode("utf-8"))

    def put_chunk(
        self,
        actor: str,
        device_id: str,
        key_version: int,
        signing_sk: bytes,
        chunk_key: str,
        recipient: str,
        payload: dict,
        *,
        ttl_s: int = 3600,
    ) -> dict:
        body = json.dumps(
            {
                "chunk_key": chunk_key,
                "recipient": recipient,
                "payload": payload,
                "ttl_s": ttl_s,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        resp = self.send_request(actor, device_id, key_version, signing_sk, OP_PUT_CHUNK, body)
        if resp.status != 0:
            raise NodeClientError(f"PUT_CHUNK denied (status={resp.status})")
        return json.loads(resp.payload.decode("utf-8"))

    def get_chunk(
        self,
        actor: str,
        device_id: str,
        key_version: int,
        signing_sk: bytes,
        chunk_key: str,
    ) -> dict:
        body = json.dumps({"chunk_key": chunk_key}, separators=(",", ":")).encode("utf-8")
        resp = self.send_request(actor, device_id, key_version, signing_sk, OP_GET_CHUNK, body)
        if resp.status != 0:
            raise NodeClientError(f"GET_CHUNK denied (status={resp.status})")
        return json.loads(resp.payload.decode("utf-8"))

    def audit_pull(
        self,
        actor: str,
        device_id: str,
        key_version: int,
        signing_sk: bytes,
        *,
        since_seq: int = 0,
    ) -> list[dict]:
        body = json.dumps({"since_seq": since_seq}, separators=(",", ":")).encode("utf-8")
        resp = self.send_request(actor, device_id, key_version, signing_sk, OP_AUDIT_PULL, body)
        if resp.status != 0:
            raise NodeClientError(f"AUDIT_PULL denied (status={resp.status})")
        return json.loads(resp.payload.decode("utf-8"))
