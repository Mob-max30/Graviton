"""Real TCP enforcement node daemon wrapping graviton.nodes.Node and AuditLog."""
from __future__ import annotations

import base64
from collections import defaultdict, deque
from contextlib import closing
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import signal
import socket
import sqlite3
import ssl
import sys
import threading
import time

from graviton.audit import AuditLog, AuthenticatedSession
from graviton.crypto.signatures import generate_signing_keypair, sign_message, verify_signature
from graviton.feed.encoding import Reader
from graviton.net.protocol import (
    DEFAULT_MAX_FRAME_BYTES,
    JOIN_SIGN_DOMAIN,
    MSG_FEED_PUSH,
    MSG_JOIN_REQUEST,
    MSG_REQUEST,
    OP_FEED_PULL,
    OP_INVITE_CREATE,
    OP_JOIN_LIST,
    OP_JOIN_RESOLVE,
    OP_STATUS,
    PROTO_VERSION,
    REQUEST_SIGN_DOMAIN,
    RESPONSE_SIGN_DOMAIN,
    SERVICE_BY_OP,
    STATUS_BAD_REQUEST,
    STATUS_DENIED,
    STATUS_OK,
    STATUS_RATE_LIMITED,
    HelloMessage,
    ProtocolError,
    ResponseMessage,
    decode_feed_push,
    decode_join_request,
    decode_request,
    encode_hello,
    encode_response,
    format_fingerprint,
    join_signing_bytes,
    public_key_fingerprint_bytes,
    read_frame,
    request_signing_bytes,
    response_signing_bytes,
    write_frame,
)
from graviton.nodes import Node, ReasonCode
from graviton.storage import atomic_write_text, ensure_state_dir

NODE_IDENTITY_FILENAME = "node_identity.json"
DEFAULT_MAX_CONNECTIONS = 64
DEFAULT_READ_TIMEOUT_S = 5.0
DEFAULT_IDLE_TIMEOUT_S = 30.0
DEFAULT_SOURCE_RATE = (600, 10.0)    # 600 requests per 10s per source IP
DEFAULT_IDENTITY_RATE = (600, 10.0)  # 600 requests per 10s per identity


class _RateLimiter:
    """Thread-safe sliding-window rate limiter."""

    def __init__(self, max_events: int, window_s: float) -> None:
        self.max_events = max_events
        self.window_s = window_s
        self._lock = threading.Lock()
        self._buckets: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_s
        with self._lock:
            dq = self._buckets[key]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self.max_events:
                return False
            dq.append(now)
            return True


def init_node_daemon(
    node_dir: str | Path,
    node_id: str,
    feed_id: str,
    admin_public_key: bytes,
) -> tuple[str, bytes, str]:
    """Initialise node state directory and generate its ML-DSA-65 identity keypair."""
    path = Path(node_dir)
    ensure_state_dir(path)
    Node.initialise(path, feed_id, admin_public_key, freshness_window=None)

    id_path = path / NODE_IDENTITY_FILENAME
    if id_path.is_file():
        data = json.loads(id_path.read_text(encoding="utf-8"))
        pk = base64.b64decode(data["node_pk_b64"], validate=True)
        return data["node_id"], pk, format_fingerprint(pk)

    pk, sk = generate_signing_keypair()
    identity = {
        "version": 1,
        "node_id": node_id,
        "node_pk_b64": base64.b64encode(pk).decode("ascii"),
        "node_sk_b64": base64.b64encode(sk).decode("ascii"),
    }
    atomic_write_text(id_path, json.dumps(identity, allow_nan=False, separators=(",", ":")))
    return node_id, pk, format_fingerprint(pk)


class NodeDaemon:
    """Long-running TCP enforcement node daemon."""

    def __init__(
        self,
        node_dir: str | Path,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
        read_timeout_s: float = DEFAULT_READ_TIMEOUT_S,
        idle_timeout_s: float = DEFAULT_IDLE_TIMEOUT_S,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        source_rate: tuple[int, float] = DEFAULT_SOURCE_RATE,
        identity_rate: tuple[int, float] = DEFAULT_IDENTITY_RATE,
        operators: set[str] | None = None,
        tls_cert: str | None = None,
        tls_key: str | None = None,
        ready_file: str | Path | None = None,
        upstream: tuple[str, int] | None = None,
        sync_interval_s: float = 1.0,
    ) -> None:
        self.node_dir = Path(node_dir)
        self.host = host
        self.port = port
        self.max_frame_bytes = max_frame_bytes
        self.read_timeout_s = read_timeout_s
        self.idle_timeout_s = idle_timeout_s
        self.max_connections = max_connections
        self.operators = set(operators or set())
        self.ready_file = Path(ready_file) if ready_file else None
        self.upstream = upstream
        self.sync_interval_s = sync_interval_s

        if host not in ("127.0.0.1", "::1", "localhost"):
            print(
                f"WARNING: Binding node to non-loopback address {host}:{port}; "
                "default transport has no encryption unless --tls-cert/--tls-key is set.",
                file=sys.stderr,
            )

        id_data = json.loads((self.node_dir / NODE_IDENTITY_FILENAME).read_text(encoding="utf-8"))
        self.node_id: str = id_data["node_id"]
        self.node_pk = base64.b64decode(id_data["node_pk_b64"], validate=True)
        self._node_sk = base64.b64decode(id_data["node_sk_b64"], validate=True)

        self.node = Node(self.node_dir, freshness_window=None)
        self.audit = AuditLog(self.node_dir / "audit.db", self.node_dir / "audit_head.json")
        self.db_path = self.node_dir / "relay_vault.db"
        self._init_db()

        self._source_limiter = _RateLimiter(*source_rate)
        self._identity_limiter = _RateLimiter(*identity_rate)
        self._conn_sem = threading.BoundedSemaphore(max_connections)
        self._stop_event = threading.Event()
        self._srv_sock: socket.socket | None = None
        self._ssl_ctx: ssl.SSLContext | None = None
        if tls_cert and tls_key:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=tls_cert, keyfile=tls_key)
            self._ssl_ctx = ctx

    def _connect_db(self):
        conn = sqlite3.connect(str(self.db_path), timeout=10.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return closing(conn)

    def _init_db(self) -> None:
        with self._connect_db() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS invites (
                    invite_id TEXT PRIMARY KEY,
                    secret_sha256 TEXT NOT NULL,
                    handle_hint TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS pending_joins (
                    invite_id TEXT PRIMARY KEY,
                    handle TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    device_pk_b64 TEXT NOT NULL,
                    device_fp TEXT NOT NULL,
                    received_at INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PENDING'
                );
                """
            )

    def _audit_event(
        self,
        actor: str,
        service: str,
        op_name: str,
        decision: str,
        reason: str,
        *,
        device_id: str = "",
        req_hash: str = "",
    ) -> None:
        detail = json.dumps(
            {
                "node_id": self.node_id,
                "service": service,
                "device_id": device_id,
                "reason": reason,
                "request_hash": req_hash,
            },
            separators=(",", ":"),
        )
        self.audit.append_event(
            AuthenticatedSession(actor=actor or "anonymous"),
            op_name,
            service,
            decision,
            detail,
        )

    def _sign_response(self, request_body: bytes, seq: int, status: int, payload: bytes) -> bytes:
        msg = response_signing_bytes(request_body, status, payload)
        sig = sign_message(self._node_sk, msg, domain=RESPONSE_SIGN_DOMAIN)
        return encode_response(ResponseMessage(seq, status, payload, sig))

    def _handle_feed_push(self, body: bytes, peer_ip: str) -> bytes:
        req_hash = hashlib.sha256(body).hexdigest()[:16]
        try:
            entries = decode_feed_push(body, max_len=self.max_frame_bytes)
        except ProtocolError as exc:
            self._audit_event("feed-push", "directory", "FEED_PUSH", "deny", str(exc), req_hash=req_hash)
            return self._sign_response(body, 0, STATUS_BAD_REQUEST, b"")

        applied = 0
        statuses: list[str] = []
        for raw in entries:
            res = self.node.apply_entry(raw)
            statuses.append(res.status)
            if res.applied:
                applied += 1
            elif res.status != "already_applied":
                self._audit_event(
                    "feed-push",
                    "directory",
                    "FEED_PUSH",
                    "deny",
                    f"entry_rejected:{res.status}",
                    req_hash=req_hash,
                )
                payload = json.dumps({"applied": applied, "statuses": statuses}, separators=(",", ":")).encode("utf-8")
                return self._sign_response(body, 0, STATUS_DENIED, payload)

        self._audit_event(
            "feed-push",
            "directory",
            "FEED_PUSH",
            "allow",
            f"applied={applied}",
            req_hash=req_hash,
        )
        payload = json.dumps({"applied": applied, "statuses": statuses}, separators=(",", ":")).encode("utf-8")
        return self._sign_response(body, 0, STATUS_OK, payload)

    def _handle_join_request(self, body: bytes) -> bytes:
        req_hash = hashlib.sha256(body).hexdigest()[:16]
        try:
            jr = decode_join_request(body, max_len=self.max_frame_bytes)
        except ProtocolError as exc:
            self._audit_event("join-anon", "directory", "JOIN_REQUEST", "deny", str(exc), req_hash=req_hash)
            return self._sign_response(body, 0, STATUS_BAD_REQUEST, b"")

        pop_msg = join_signing_bytes(
            jr["invite_id"], jr["invite_secret"], jr["handle"], jr["device_id"], jr["device_pk"]
        )
        if not verify_signature(jr["device_pk"], pop_msg, jr["pop_sig"], domain=JOIN_SIGN_DOMAIN):
            self._audit_event(
                jr["handle"], "directory", "JOIN_REQUEST", "deny", "INVALID_POP_SIGNATURE",
                device_id=jr["device_id"], req_hash=req_hash,
            )
            return self._sign_response(body, 0, STATUS_DENIED, b"")

        now = int(time.time())
        secret_hash = hashlib.sha256(jr["invite_secret"]).hexdigest()
        fp = format_fingerprint(jr["device_pk"])
        pk_b64 = base64.b64encode(jr["device_pk"]).decode("ascii")

        with self._connect_db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT secret_sha256, expires_at, used FROM invites WHERE invite_id = ?",
                    (jr["invite_id"],),
                ).fetchone()
                if row is None:
                    conn.execute("ROLLBACK")
                    self._audit_event(jr["handle"], "directory", "JOIN_REQUEST", "deny", "UNKNOWN_INVITE", req_hash=req_hash)
                    return self._sign_response(body, 0, STATUS_DENIED, b"")
                if int(row["used"]) != 0:
                    conn.execute("ROLLBACK")
                    self._audit_event(jr["handle"], "directory", "JOIN_REQUEST", "deny", "INVITE_REUSED", req_hash=req_hash)
                    return self._sign_response(body, 0, STATUS_DENIED, b"")
                if now >= int(row["expires_at"]):
                    conn.execute("ROLLBACK")
                    self._audit_event(jr["handle"], "directory", "JOIN_REQUEST", "deny", "INVITE_EXPIRED", req_hash=req_hash)
                    return self._sign_response(body, 0, STATUS_DENIED, b"")
                if not hmac.compare_digest(row["secret_sha256"], secret_hash):
                    conn.execute("ROLLBACK")
                    self._audit_event(jr["handle"], "directory", "JOIN_REQUEST", "deny", "INVITE_BAD_SECRET", req_hash=req_hash)
                    return self._sign_response(body, 0, STATUS_DENIED, b"")

                conn.execute("UPDATE invites SET used = 1 WHERE invite_id = ?", (jr["invite_id"],))
                conn.execute(
                    """
                    INSERT INTO pending_joins (invite_id, handle, device_id, device_pk_b64, device_fp, received_at, status)
                    VALUES (?, ?, ?, ?, ?, ?, 'PENDING')
                    """,
                    (jr["invite_id"], jr["handle"], jr["device_id"], pk_b64, fp, now),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

        self._audit_event(
            jr["handle"], "directory", "JOIN_REQUEST", "allow", f"pending_fp={fp}",
            device_id=jr["device_id"], req_hash=req_hash,
        )
        payload = json.dumps({"status": "pending", "device_fp": fp}, separators=(",", ":")).encode("utf-8")
        return self._sign_response(body, 0, STATUS_OK, payload)

    def _handle_request(self, body: bytes, feed_id: str, server_nonce: bytes, expected_seq: int) -> tuple[bytes, bool]:
        req_hash = hashlib.sha256(body).hexdigest()[:16]
        try:
            req = decode_request(body, max_len=self.max_frame_bytes)
        except ProtocolError as exc:
            self._audit_event("malformed", "directory", "REQUEST", "deny", str(exc), req_hash=req_hash)
            return self._sign_response(body, 0, STATUS_BAD_REQUEST, b""), True

        if req.seq != expected_seq:
            self._audit_event(
                req.actor,
                SERVICE_BY_OP.get(req.op, "unknown"),
                f"OP_{req.op}",
                "deny",
                f"OUT_OF_ORDER_SEQ:expected={expected_seq},got={req.seq}",
                device_id=req.device_id,
                req_hash=req_hash,
            )
            return self._sign_response(body, req.seq, STATUS_DENIED, b""), True

        service = SERVICE_BY_OP.get(req.op, "unknown")
        if not self._identity_limiter.allow(req.actor):
            self._audit_event(
                req.actor, service, f"OP_{req.op}", "deny", "IDENTITY_RATE_LIMITED",
                device_id=req.device_id, req_hash=req_hash,
            )
            return self._sign_response(body, req.seq, STATUS_RATE_LIMITED, b""), False

        # Authenticate BEFORE parsing payload: check node policy + ML-DSA-65 signature
        auth = self.node.authorize(req.actor, req.device_id, req.key_version)
        if auth.decision != "allow":
            self._audit_event(
                req.actor, service, f"OP_{req.op}", "deny", auth.reason.value,
                device_id=req.device_id, req_hash=req_hash,
            )
            return self._sign_response(body, req.seq, STATUS_DENIED, b""), False

        pub_key = self.node.get_device_public_key(req.actor, req.device_id, req.key_version)
        if pub_key is None:
            self._audit_event(
                req.actor, service, f"OP_{req.op}", "deny", ReasonCode.UNKNOWN_KEY.value,
                device_id=req.device_id, req_hash=req_hash,
            )
            return self._sign_response(body, req.seq, STATUS_DENIED, b""), False

        sig_msg = request_signing_bytes(feed_id, server_nonce, req.seq, req.op, req.payload)
        if not verify_signature(pub_key, sig_msg, req.signature, domain=REQUEST_SIGN_DOMAIN):
            self._audit_event(
                req.actor, service, f"OP_{req.op}", "deny", ReasonCode.INVALID_SIGNATURE.value,
                device_id=req.device_id, req_hash=req_hash,
            )
            return self._sign_response(body, req.seq, STATUS_DENIED, b""), False

        # Dispatch authenticated operation
        if req.op == OP_STATUS:
            payload = json.dumps(
                {
                    "node_id": self.node_id,
                    "feed_id": feed_id,
                    "applied_epoch": self.node.applied_epoch(),
                    "integrity_ok": self.node.verify_integrity(),
                },
                separators=(",", ":"),
            ).encode("utf-8")
            self._audit_event(
                req.actor, service, "STATUS", "allow", ReasonCode.OK.value,
                device_id=req.device_id, req_hash=req_hash,
            )
            return self._sign_response(body, req.seq, STATUS_OK, payload), False

        if req.op == OP_FEED_PULL:
            try:
                r = Reader(req.payload, max_len=8)
                since_epoch = r.read_u64()
                r.assert_finished()
                entries = self.node.entries_after(since_epoch)
                payload = json.dumps([e.hex() for e in entries], separators=(",", ":")).encode("utf-8")
                self._audit_event(
                    req.actor, service, "FEED_PULL", "allow", f"count={len(entries)}",
                    device_id=req.device_id, req_hash=req_hash,
                )
                return self._sign_response(body, req.seq, STATUS_OK, payload), False
            except Exception:
                self._audit_event(
                    req.actor, service, "FEED_PULL", "deny", "BAD_PAYLOAD",
                    device_id=req.device_id, req_hash=req_hash,
                )
                return self._sign_response(body, req.seq, STATUS_BAD_REQUEST, b""), False

        if req.op in (OP_INVITE_CREATE, OP_JOIN_LIST, OP_JOIN_RESOLVE):
            if req.actor not in self.operators:
                self._audit_event(
                    req.actor, service, f"OP_{req.op}", "deny", "OPERATOR_REQUIRED",
                    device_id=req.device_id, req_hash=req_hash,
                )
                return self._sign_response(body, req.seq, STATUS_DENIED, b""), False

            if req.op == OP_INVITE_CREATE:
                try:
                    data = json.loads(req.payload.decode("utf-8"))
                    inv_id = str(data["invite_id"])
                    sec_sha = str(data["secret_sha256"])
                    hint = str(data["handle_hint"])
                    exp = int(data["expires_at"])
                except Exception:
                    return self._sign_response(body, req.seq, STATUS_BAD_REQUEST, b""), False
                with self._connect_db() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    conn.execute(
                        "INSERT INTO invites (invite_id, secret_sha256, handle_hint, expires_at, used) VALUES (?, ?, ?, ?, 0)",
                        (inv_id, sec_sha, hint, exp),
                    )
                    conn.execute("COMMIT")
                self._audit_event(req.actor, service, "INVITE_CREATE", "allow", f"for={hint}", device_id=req.device_id, req_hash=req_hash)
                return self._sign_response(body, req.seq, STATUS_OK, b'{"created":true}'), False

            if req.op == OP_JOIN_LIST:
                with self._connect_db() as conn:
                    rows = conn.execute(
                        "SELECT invite_id, handle, device_id, device_pk_b64, device_fp, received_at, status "
                        "FROM pending_joins WHERE status = 'PENDING' ORDER BY received_at ASC"
                    ).fetchall()
                items = [dict(r) for r in rows]
                self._audit_event(req.actor, service, "JOIN_LIST", "allow", f"count={len(items)}", device_id=req.device_id, req_hash=req_hash)
                return self._sign_response(body, req.seq, STATUS_OK, json.dumps(items, separators=(",", ":")).encode("utf-8")), False

            if req.op == OP_JOIN_RESOLVE:
                try:
                    data = json.loads(req.payload.decode("utf-8"))
                    inv_id = str(data["invite_id"])
                    new_status = str(data["status"])
                    if new_status not in ("APPROVED", "REJECTED"):
                        raise ValueError("Invalid status")
                except Exception:
                    return self._sign_response(body, req.seq, STATUS_BAD_REQUEST, b""), False
                with self._connect_db() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    conn.execute("UPDATE pending_joins SET status = ? WHERE invite_id = ?", (new_status, inv_id))
                    conn.execute("COMMIT")
                self._audit_event(req.actor, service, "JOIN_RESOLVE", "allow", f"{inv_id}:{new_status}", device_id=req.device_id, req_hash=req_hash)
                return self._sign_response(body, req.seq, STATUS_OK, b'{"resolved":true}'), False

        self._audit_event(
            req.actor, service, f"OP_{req.op}", "deny", "UNSUPPORTED_OP",
            device_id=req.device_id, req_hash=req_hash,
        )
        return self._sign_response(body, req.seq, STATUS_DENIED, b""), False

    def _handle_client(self, conn: socket.socket, addr: tuple[str, int]) -> None:
        peer_ip = addr[0]
        try:
            if self._ssl_ctx is not None:
                conn = self._ssl_ctx.wrap_socket(conn, server_side=True)
            conn.settimeout(self.read_timeout_s)

            feed_id, _ = self.node.get_trust_root()
            server_nonce = secrets.token_bytes(32)
            hello = HelloMessage(
                feed_id=feed_id,
                node_id=self.node_id,
                node_epoch=self.node.applied_epoch(),
                server_nonce=server_nonce,
                node_pk_sha256=public_key_fingerprint_bytes(self.node_pk),
            )
            write_frame(conn, encode_hello(hello), max_frame_bytes=self.max_frame_bytes)

            expected_seq = 1
            while not self._stop_event.is_set():
                conn.settimeout(self.idle_timeout_s)
                body = read_frame(conn, max_frame_bytes=self.max_frame_bytes)
                conn.settimeout(self.read_timeout_s)

                if not self._source_limiter.allow(peer_ip):
                    self._audit_event("rate-limit", "directory", "RATE_LIMIT", "deny", "SOURCE_RATE_LIMITED")
                    write_frame(conn, self._sign_response(body, 0, STATUS_RATE_LIMITED, b""), max_frame_bytes=self.max_frame_bytes)
                    break

                if len(body) < 2 or body[0] != PROTO_VERSION:
                    self._audit_event("malformed", "directory", "FRAME", "deny", "INVALID_VERSION")
                    break

                msg_type = body[1]
                if msg_type == MSG_FEED_PUSH:
                    resp = self._handle_feed_push(body, peer_ip)
                    write_frame(conn, resp, max_frame_bytes=self.max_frame_bytes)
                elif msg_type == MSG_JOIN_REQUEST:
                    resp = self._handle_join_request(body)
                    write_frame(conn, resp, max_frame_bytes=self.max_frame_bytes)
                elif msg_type == MSG_REQUEST:
                    resp, close_after = self._handle_request(body, feed_id, server_nonce, expected_seq)
                    write_frame(conn, resp, max_frame_bytes=self.max_frame_bytes)
                    if close_after:
                        break
                    expected_seq += 1
                else:
                    self._audit_event("malformed", "directory", "FRAME", "deny", f"UNKNOWN_MSG_TYPE:{msg_type}")
                    break
        except (ProtocolError, OSError, ssl.SSLError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
            self._conn_sem.release()

    def start(self) -> tuple[str, int]:
        """Bind socket and write ready_file if configured; returns (host, port)."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(self.max_connections)
        srv.settimeout(0.25)
        self._srv_sock = srv
        bound_host, bound_port = srv.getsockname()[:2]

        if self.ready_file is not None:
            atomic_write_text(
                self.ready_file,
                json.dumps(
                    {
                        "host": bound_host,
                        "port": bound_port,
                        "node_id": self.node_id,
                        "node_pk_b64": base64.b64encode(self.node_pk).decode("ascii"),
                    },
                    separators=(",", ":"),
                ),
            )
        return bound_host, bound_port

    def _upstream_sync_loop(self) -> None:
        from graviton.net.client import NodeClient

        assert self.upstream is not None
        u_host, u_port = self.upstream
        while not self._stop_event.is_set():
            try:
                since = self.node.applied_epoch()
                with NodeClient(u_host, u_port, timeout=self.read_timeout_s) as cli:
                    entries = cli.feed_pull(
                        self.node_id, self.node_id, 1, self._node_sk, since_epoch=since
                    )
                for raw in entries:
                    self.node.apply_entry(raw)
            except Exception:
                pass
            self._stop_event.wait(self.sync_interval_s)

    def serve_forever(self) -> None:
        if self._srv_sock is None:
            self.start()
        if self.upstream is not None:
            sync_t = threading.Thread(target=self._upstream_sync_loop, daemon=True)
            sync_t.start()
        assert self._srv_sock is not None
        while not self._stop_event.is_set():
            try:
                conn, addr = self._srv_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self._conn_sem.acquire(blocking=False):
                try:
                    conn.close()
                except OSError:
                    pass
                continue
            t = threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True)
            t.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._srv_sock is not None:
            try:
                self._srv_sock.close()
            except OSError:
                pass


def run_node_cli(args) -> int:
    upstream = None
    if getattr(args, "upstream", None):
        uh, up = args.upstream.rsplit(":", 1)
        upstream = (uh, int(up))
    daemon = NodeDaemon(
        args.dir,
        host=args.host,
        port=args.port,
        max_frame_bytes=args.max_frame_bytes,
        read_timeout_s=args.read_timeout,
        idle_timeout_s=args.idle_timeout,
        max_connections=args.max_connections,
        operators=set(args.operator or []),
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
        ready_file=args.ready_file,
        upstream=upstream,
        sync_interval_s=getattr(args, "sync_interval", 1.0),
    )

    def _shutdown(_signum, _frame) -> None:
        daemon.stop()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    daemon.start()
    try:
        daemon.serve_forever()
    finally:
        daemon.stop()
    return 0
