"""Binary length-prefixed wire protocol reusing graviton.feed.encoding."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import socket
import struct

from graviton.crypto.signatures import DSA_PUBLIC_KEY_SIZE, DSA_SIGNATURE_SIZE
from graviton.feed.encoding import (
    FeedFormatError,
    Reader,
    enc_bytes,
    enc_id,
    enc_u8,
    enc_u32,
    enc_u64,
)

PROTO_VERSION = 1
DEFAULT_MAX_FRAME_BYTES = 1_048_576  # 1 MiB

MSG_HELLO = 1
MSG_REQUEST = 2
MSG_RESPONSE = 3
MSG_FEED_PUSH = 4
MSG_JOIN_REQUEST = 5

OP_STATUS = 1
OP_FEED_PULL = 2
OP_PUT_ENVELOPE = 10
OP_LIST_INBOX = 11
OP_FETCH_ENVELOPE = 12
OP_ACK = 13
OP_PUT_CHUNK = 20
OP_GET_CHUNK = 21
OP_AUDIT_PULL = 30
OP_JOIN_LIST = 31
OP_JOIN_RESOLVE = 32

SERVICE_BY_OP: dict[int, str] = {
    OP_STATUS: "directory",
    OP_FEED_PULL: "directory",
    OP_PUT_ENVELOPE: "relay",
    OP_LIST_INBOX: "relay",
    OP_FETCH_ENVELOPE: "relay",
    OP_ACK: "relay",
    OP_PUT_CHUNK: "vault",
    OP_GET_CHUNK: "vault",
    OP_AUDIT_PULL: "admin",
    OP_JOIN_LIST: "admin",
    OP_JOIN_RESOLVE: "admin",
}

STATUS_OK = 0
STATUS_DENIED = 1
STATUS_BAD_REQUEST = 2
STATUS_RATE_LIMITED = 3

REQUEST_SIGN_DOMAIN = b"request"
RESPONSE_SIGN_DOMAIN = b"response"
JOIN_SIGN_DOMAIN = b"join"


class ProtocolError(ValueError):
    """Raised on malformed, oversized, or truncated wire frames."""


def public_key_fingerprint_bytes(public_key: bytes) -> bytes:
    return hashlib.sha256(public_key).digest()


def format_fingerprint(public_key: bytes) -> str:
    """Short grouped hex fingerprint (4 groups of 4 hex chars) from SHA-256."""
    h = hashlib.sha256(public_key).hexdigest()[:16].upper()
    return f"{h[0:4]}-{h[4:8]}-{h[8:12]}-{h[12:16]}"


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (socket.timeout, TimeoutError) as exc:
            raise ProtocolError("Socket read timed out") from exc
        except OSError as exc:
            raise ProtocolError(f"Socket read error: {exc}") from exc
        if not chunk:
            raise ProtocolError("Unexpected EOF on socket")
        buf.extend(chunk)
    return bytes(buf)


def read_frame(sock: socket.socket, *, max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES) -> bytes:
    """Read a length-prefixed frame, checking length BEFORE allocating body."""
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    if length == 0 or length > max_frame_bytes:
        raise ProtocolError(f"Frame length {length} outside (0, {max_frame_bytes}]")
    return _recv_exact(sock, length)


def write_frame(sock: socket.socket, body: bytes, *, max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES) -> None:
    if not body or len(body) > max_frame_bytes:
        raise ProtocolError(f"Frame body length {len(body)} outside (0, {max_frame_bytes}]")
    sock.sendall(enc_u32(len(body)) + body)


def request_signing_bytes(
    feed_id: str,
    server_nonce: bytes,
    seq: int,
    op: int,
    payload: bytes,
) -> bytes:
    return (
        enc_u8(PROTO_VERSION)
        + enc_id(feed_id)
        + enc_bytes(server_nonce)
        + enc_u32(seq)
        + enc_u8(op)
        + enc_bytes(hashlib.sha256(payload).digest())
    )


def response_signing_bytes(request_body: bytes, status: int, payload: bytes) -> bytes:
    return (
        enc_u8(PROTO_VERSION)
        + enc_bytes(hashlib.sha256(request_body).digest())
        + enc_u8(status)
        + enc_bytes(hashlib.sha256(payload).digest())
    )


def join_signing_bytes(
    invite_id: str,
    invite_secret: bytes,
    handle: str,
    device_id: str,
    device_pk: bytes,
) -> bytes:
    return (
        enc_u8(PROTO_VERSION)
        + enc_id(invite_id)
        + enc_bytes(invite_secret)
        + enc_id(handle)
        + enc_id(device_id)
        + enc_bytes(device_pk)
    )


@dataclass(frozen=True)
class HelloMessage:
    feed_id: str
    node_id: str
    node_epoch: int
    server_nonce: bytes
    node_pk_sha256: bytes


@dataclass(frozen=True)
class RequestMessage:
    actor: str
    device_id: str
    key_version: int
    seq: int
    op: int
    payload: bytes
    signature: bytes


@dataclass(frozen=True)
class ResponseMessage:
    seq: int
    status: int
    payload: bytes
    signature: bytes


def encode_hello(msg: HelloMessage) -> bytes:
    return (
        enc_u8(PROTO_VERSION)
        + enc_u8(MSG_HELLO)
        + enc_id(msg.feed_id)
        + enc_id(msg.node_id)
        + enc_u64(msg.node_epoch)
        + enc_bytes(msg.server_nonce)
        + enc_bytes(msg.node_pk_sha256)
    )


def decode_hello(body: bytes, *, max_len: int = DEFAULT_MAX_FRAME_BYTES) -> HelloMessage:
    try:
        r = Reader(body, max_len=max_len)
        if r.read_u8() != PROTO_VERSION or r.read_u8() != MSG_HELLO:
            raise ProtocolError("Invalid HELLO header")
        feed_id = r.read_id()
        node_id = r.read_id()
        node_epoch = r.read_u64()
        nonce = r.read_bytes(max_len=32)
        pk_sha = r.read_bytes(max_len=32)
        r.assert_finished()
        if len(nonce) != 32 or len(pk_sha) != 32:
            raise ProtocolError("HELLO nonce and pk_sha256 must be 32 bytes")
        return HelloMessage(feed_id, node_id, node_epoch, nonce, pk_sha)
    except FeedFormatError as exc:
        raise ProtocolError(str(exc)) from exc


def encode_request(msg: RequestMessage) -> bytes:
    return (
        enc_u8(PROTO_VERSION)
        + enc_u8(MSG_REQUEST)
        + enc_id(msg.actor)
        + enc_id(msg.device_id)
        + enc_u32(msg.key_version)
        + enc_u32(msg.seq)
        + enc_u8(msg.op)
        + enc_bytes(msg.payload)
        + enc_bytes(msg.signature)
    )


def decode_request(body: bytes, *, max_len: int = DEFAULT_MAX_FRAME_BYTES) -> RequestMessage:
    try:
        r = Reader(body, max_len=max_len)
        if r.read_u8() != PROTO_VERSION or r.read_u8() != MSG_REQUEST:
            raise ProtocolError("Invalid REQUEST header")
        actor = r.read_id()
        device_id = r.read_id()
        key_version = r.read_u32()
        seq = r.read_u32()
        op = r.read_u8()
        payload = r.read_bytes(max_len=max_len)
        sig = r.read_bytes(max_len=DSA_SIGNATURE_SIZE)
        r.assert_finished()
        if len(sig) != DSA_SIGNATURE_SIZE:
            raise ProtocolError("Invalid REQUEST signature length")
        return RequestMessage(actor, device_id, key_version, seq, op, payload, sig)
    except FeedFormatError as exc:
        raise ProtocolError(str(exc)) from exc


def encode_response(msg: ResponseMessage) -> bytes:
    return (
        enc_u8(PROTO_VERSION)
        + enc_u8(MSG_RESPONSE)
        + enc_u32(msg.seq)
        + enc_u8(msg.status)
        + enc_bytes(msg.payload)
        + enc_bytes(msg.signature)
    )


def decode_response(body: bytes, *, max_len: int = DEFAULT_MAX_FRAME_BYTES) -> ResponseMessage:
    try:
        r = Reader(body, max_len=max_len)
        if r.read_u8() != PROTO_VERSION or r.read_u8() != MSG_RESPONSE:
            raise ProtocolError("Invalid RESPONSE header")
        seq = r.read_u32()
        status = r.read_u8()
        payload = r.read_bytes(max_len=max_len)
        sig = r.read_bytes(max_len=DSA_SIGNATURE_SIZE)
        r.assert_finished()
        if len(sig) != DSA_SIGNATURE_SIZE:
            raise ProtocolError("Invalid RESPONSE signature length")
        return ResponseMessage(seq, status, payload, sig)
    except FeedFormatError as exc:
        raise ProtocolError(str(exc)) from exc


def encode_feed_push(entries: list[bytes]) -> bytes:
    buf = bytearray()
    buf.extend(enc_u8(PROTO_VERSION))
    buf.extend(enc_u8(MSG_FEED_PUSH))
    buf.extend(enc_u32(len(entries)))
    for entry in entries:
        buf.extend(enc_bytes(entry))
    return bytes(buf)


def decode_feed_push(body: bytes, *, max_len: int = DEFAULT_MAX_FRAME_BYTES) -> list[bytes]:
    try:
        r = Reader(body, max_len=max_len)
        if r.read_u8() != PROTO_VERSION or r.read_u8() != MSG_FEED_PUSH:
            raise ProtocolError("Invalid FEED_PUSH header")
        count = r.read_u32()
        if count > 512:
            raise ProtocolError("Too many entries in FEED_PUSH")
        entries = [r.read_bytes(max_len=16384) for _ in range(count)]
        r.assert_finished()
        return entries
    except FeedFormatError as exc:
        raise ProtocolError(str(exc)) from exc


def encode_join_request(
    invite_id: str,
    invite_secret: bytes,
    handle: str,
    device_id: str,
    device_pk: bytes,
    pop_sig: bytes,
) -> bytes:
    return (
        enc_u8(PROTO_VERSION)
        + enc_u8(MSG_JOIN_REQUEST)
        + enc_id(invite_id)
        + enc_bytes(invite_secret)
        + enc_id(handle)
        + enc_id(device_id)
        + enc_bytes(device_pk)
        + enc_bytes(pop_sig)
    )


def decode_join_request(body: bytes, *, max_len: int = DEFAULT_MAX_FRAME_BYTES) -> dict:
    try:
        r = Reader(body, max_len=max_len)
        if r.read_u8() != PROTO_VERSION or r.read_u8() != MSG_JOIN_REQUEST:
            raise ProtocolError("Invalid JOIN_REQUEST header")
        invite_id = r.read_id()
        invite_secret = r.read_bytes(max_len=64)
        handle = r.read_id()
        device_id = r.read_id()
        device_pk = r.read_bytes(max_len=DSA_PUBLIC_KEY_SIZE)
        pop_sig = r.read_bytes(max_len=DSA_SIGNATURE_SIZE)
        r.assert_finished()
        if len(device_pk) != DSA_PUBLIC_KEY_SIZE or len(pop_sig) != DSA_SIGNATURE_SIZE:
            raise ProtocolError("Invalid JOIN_REQUEST key or signature length")
        return {
            "invite_id": invite_id,
            "invite_secret": invite_secret,
            "handle": handle,
            "device_id": device_id,
            "device_pk": device_pk,
            "pop_sig": pop_sig,
        }
    except FeedFormatError as exc:
        raise ProtocolError(str(exc)) from exc
