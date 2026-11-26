"""End-to-end encrypted messaging with hybrid PQC forward secrecy, replay, and resumption binding."""

from __future__ import annotations

import base64
import json
import time
import uuid
from typing import Any

from app.audit import AuditLogger
from app.crypto_engine import (
    CryptoError,
    aead_decrypt,
    aead_encrypt,
    canonical_json,
    derive_subkey,
    hybrid_decapsulate,
    hybrid_encapsulate,
    key_fingerprint,
    sign_data,
    verify_signature,
)
from app.db import Database
from app.key_manager import KeyLifecycleError, KeyManager


class TransportError(Exception):
    """Raised on replay, recipient mismatch, session hijack, or delivery failure."""


class E2EETransport:
    """Handles forward-secret sessions, replay-protected E2EE messages, and chunked delivery."""

    def __init__(self, db: Database, key_mgr: KeyManager, audit: AuditLogger) -> None:
        self.db = db
        self.key_mgr = key_mgr
        self.audit = audit

    def establish_session(
        self,
        org_id: str,
        initiator_user_id: str,
        initiator_device_id: str,
        peer_user_id: str,
        peer_device_id: str,
    ) -> dict[str, Any]:
        """Establish a forward-secret hybrid ML-KEM-768 + X25519 session and identity-bound resumption ticket."""
        chat_node = f"{org_id}:chat-node-1"
        session_id = f"ses_{uuid.uuid4().hex[:12]}"
        now = time.time()

        with self.db.read() as conn:
            org = conn.execute(
                "SELECT ticket_key FROM organizations WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            init_dev = conn.execute(
                "SELECT * FROM devices WHERE device_id = ? AND user_id = ? AND org_id = ?",
                (initiator_device_id, initiator_user_id, org_id),
            ).fetchone()
            peer_dev = conn.execute(
                "SELECT * FROM devices WHERE device_id = ? AND user_id = ? AND org_id = ?",
                (peer_device_id, peer_user_id, org_id),
            ).fetchone()
            if not org or not init_dev or not peer_dev:
                raise TransportError("Invalid org or device for session establishment")

        self.key_mgr.validate_key_usage_on_node(org_id, chat_node, initiator_device_id, init_dev["key_version"])
        self.key_mgr.validate_key_usage_on_node(org_id, chat_node, peer_device_id, peer_dev["key_version"])

        context = f"{org_id}|{session_id}|{initiator_user_id}|{peer_user_id}".encode("utf-8")
        kem_ct, init_eph_x25519_pk, session_key = hybrid_encapsulate(
            bytes(peer_dev["kem_pk"]),
            bytes(peer_dev["x25519_pk"]),
            context,
        )
        # Verify peer can decapsulate identically (both derive same forward-secret session_key)
        peer_derived = hybrid_decapsulate(
            bytes(peer_dev["kem_sk"]),
            bytes(peer_dev["x25519_sk"]),
            kem_ct,
            init_eph_x25519_pk,
            context,
        )
        if peer_derived != session_key:
            raise TransportError("Session key agreement mismatch")

        init_fp = key_fingerprint(bytes(init_dev["sign_pk"]))
        peer_fp = key_fingerprint(bytes(peer_dev["sign_pk"]))

        ticket_payload = canonical_json(
            {
                "session_id": session_id,
                "org_id": org_id,
                "initiator_pk_fp": init_fp,
                "peer_pk_fp": peer_fp,
                "issued_at": now,
            }
        )
        t_nonce, t_ct = aead_encrypt(
            bytes(org["ticket_key"]),
            ticket_payload,
            f"{org_id}|{session_id}".encode("utf-8"),
        )
        resumption_ticket = base64.b64encode(
            canonical_json({"n": base64.b64encode(t_nonce).decode("ascii"), "c": base64.b64encode(t_ct).decode("ascii")})
        )

        with self.db.tx() as conn:
            conn.execute(
                """
                INSERT INTO sessions (
                    session_id, org_id,
                    initiator_user_id, initiator_device_id, initiator_pk_fp,
                    peer_user_id, peer_device_id, peer_pk_fp,
                    session_key, next_seq, seen_seqs_json, resumption_ticket, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, '[]', ?, ?)
                """,
                (
                    session_id,
                    org_id,
                    initiator_user_id,
                    initiator_device_id,
                    init_fp,
                    peer_user_id,
                    peer_device_id,
                    peer_fp,
                    session_key,
                    resumption_ticket,
                    now,
                ),
            )

        self.audit.log_event(
            org_id=org_id,
            actor_id=initiator_user_id,
            service="chat",
            action="SESSION_ESTABLISH",
            target=session_id,
            context={"peer_user_id": peer_user_id, "kem": "ML-KEM-768+X25519"},
        )
        return {
            "session_id": session_id,
            "initiator_pk_fp": init_fp,
            "peer_pk_fp": peer_fp,
            "resumption_ticket": resumption_ticket.decode("ascii"),
            "kem_ct_b64": base64.b64encode(kem_ct).decode("ascii"),
            "init_x25519_pk_b64": base64.b64encode(init_eph_x25519_pk).decode("ascii"),
        }

    def resume_session(
        self,
        org_id: str,
        session_id: str,
        presenter_user_id: str,
        presenter_device_id: str,
        resumption_ticket_b64: str,
    ) -> dict[str, Any]:
        """Resume a session only if the presenter's authenticated identity matches the ticket binding."""
        with self.db.read() as conn:
            org = conn.execute(
                "SELECT ticket_key FROM organizations WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            dev = conn.execute(
                "SELECT sign_pk, status FROM devices WHERE device_id = ? AND user_id = ? AND org_id = ?",
                (presenter_device_id, presenter_user_id, org_id),
            ).fetchone()
            ses = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ? AND org_id = ?",
                (session_id, org_id),
            ).fetchone()
            if not org or not dev or not ses:
                raise TransportError("Invalid session resumption parameters")
            if dev["status"] != "ACTIVE":
                raise TransportError("Presenter device is revoked")

        try:
            env = json.loads(base64.b64decode(resumption_ticket_b64.encode("ascii")).decode("utf-8"))
            t_nonce = base64.b64decode(env["n"].encode("ascii"))
            t_ct = base64.b64decode(env["c"].encode("ascii"))
            ticket = json.loads(
                aead_decrypt(
                    bytes(org["ticket_key"]),
                    t_nonce,
                    t_ct,
                    f"{org_id}|{session_id}".encode("utf-8"),
                ).decode("utf-8")
            )
        except Exception as exc:
            raise TransportError(f"Invalid resumption ticket: {exc}") from exc

        presenter_fp = key_fingerprint(bytes(dev["sign_pk"]))
        if presenter_fp not in (ticket["initiator_pk_fp"], ticket["peer_pk_fp"]):
            self.audit.log_event(
                org_id=org_id,
                actor_id=presenter_user_id,
                service="chat",
                action="SESSION_HIJACK_ATTEMPT",
                target=session_id,
                context={"presenter_fp": presenter_fp, "expected": [ticket["initiator_pk_fp"], ticket["peer_pk_fp"]]},
            )
            raise TransportError("Session resumption rejected: identity does not match authenticated peer")

        return {"session_id": session_id, "resumed": True, "bound_identity_fp": presenter_fp}

    def send_message(
        self,
        org_id: str,
        session_id: str,
        sender_user_id: str,
        sender_device_id: str,
        recipient_user_id: str,
        recipient_device_id: str,
        plaintext: str,
    ) -> dict[str, Any]:
        """Encrypt and sign an E2EE chat message bound to sender, recipient, session, and sequence."""
        chat_node = f"{org_id}:chat-node-1"
        message_id = f"msg_{uuid.uuid4().hex[:12]}"
        now = time.time()

        with self.db.tx() as conn:
            ses = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ? AND org_id = ?",
                (session_id, org_id),
            ).fetchone()
            sender_dev = conn.execute(
                "SELECT * FROM devices WHERE device_id = ? AND user_id = ? AND org_id = ?",
                (sender_device_id, sender_user_id, org_id),
            ).fetchone()
            if not ses or not sender_dev:
                raise TransportError("Session or sender device not found")

            self.key_mgr.validate_key_usage_on_node(org_id, chat_node, sender_device_id, sender_dev["key_version"])
            seq_no = ses["next_seq"]
            conn.execute("UPDATE sessions SET next_seq = ? WHERE session_id = ?", (seq_no + 1, session_id))

            msg_key = derive_subkey(bytes(ses["session_key"]), f"msg|{seq_no}".encode("utf-8"))
            aad_obj = {
                "org_id": org_id,
                "session_id": session_id,
                "seq_no": seq_no,
                "sender_user_id": sender_user_id,
                "recipient_user_id": recipient_user_id,
                "key_version": sender_dev["key_version"],
            }
            aad_bytes = canonical_json(aad_obj)
            nonce, ct = aead_encrypt(msg_key, plaintext.encode("utf-8"), aad_bytes)
            sig = sign_data(bytes(sender_dev["sign_sk"]), aad_bytes + nonce + ct)

            conn.execute(
                """
                INSERT INTO chat_messages (
                    message_id, org_id, sender_user_id, sender_device_id,
                    recipient_user_id, recipient_device_id, session_id, seq_no,
                    key_version, kem_ct, init_x25519_pk, nonce, ciphertext, aad_json, signature, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message_id,
                    org_id,
                    sender_user_id,
                    sender_device_id,
                    recipient_user_id,
                    recipient_device_id,
                    session_id,
                    seq_no,
                    sender_dev["key_version"],
                    b"",
                    b"",
                    nonce,
                    ct,
                    aad_bytes.decode("utf-8"),
                    sig,
                    now,
                ),
            )

        self.audit.log_event(
            org_id=org_id,
            actor_id=sender_user_id,
            service="chat",
            action="CHAT_SEND",
            target=recipient_user_id,
            context={"session_id": session_id, "message_id": message_id, "seq_no": seq_no},
        )
        return {
            "message_id": message_id,
            "session_id": session_id,
            "seq_no": seq_no,
            "sender_user_id": sender_user_id,
            "recipient_user_id": recipient_user_id,
            "created_at": now,
        }

    def receive_message(
        self,
        org_id: str,
        message_id: str,
        receiver_user_id: str,
        receiver_device_id: str,
        override_recipient_in_aad: str | None = None,
    ) -> dict[str, Any]:
        """Verify signature, recipient binding, replay window, and decrypt message."""
        chat_node = f"{org_id}:chat-node-1"
        replay_info: tuple[str, int] | None = None
        with self.db.tx() as conn:
            msg = conn.execute(
                "SELECT * FROM chat_messages WHERE message_id = ? AND org_id = ?",
                (message_id, org_id),
            ).fetchone()
            if not msg:
                raise TransportError("Message not found")

            ses = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ? AND org_id = ?",
                (msg["session_id"], org_id),
            ).fetchone()
            sender_dev = conn.execute(
                "SELECT sign_pk FROM devices WHERE device_id = ?",
                (msg["sender_device_id"],),
            ).fetchone()
            recv_dev = conn.execute(
                "SELECT key_version FROM devices WHERE device_id = ? AND user_id = ? AND org_id = ?",
                (receiver_device_id, receiver_user_id, org_id),
            ).fetchone()
            if not ses or not sender_dev or not recv_dev:
                raise TransportError("Invalid session or device")

            try:
                self.key_mgr.validate_key_usage_on_node(org_id, chat_node, receiver_device_id, recv_dev["key_version"])
            except KeyLifecycleError as exc:
                raise TransportError(str(exc)) from exc

            if msg["recipient_user_id"] != receiver_user_id:
                raise TransportError("Recipient binding failed: not the intended recipient")

            seen_seqs = set(json.loads(ses["seen_seqs_json"]))
            if msg["seq_no"] in seen_seqs:
                replay_info = (msg["session_id"], msg["seq_no"])
            else:
                aad_bytes = msg["aad_json"].encode("utf-8")
                if override_recipient_in_aad is not None:
                    tampered = json.loads(msg["aad_json"])
                    tampered["recipient_user_id"] = override_recipient_in_aad
                    aad_bytes = canonical_json(tampered)

                if not verify_signature(
                    bytes(sender_dev["sign_pk"]),
                    aad_bytes + bytes(msg["nonce"]) + bytes(msg["ciphertext"]),
                    bytes(msg["signature"]),
                ):
                    raise TransportError("Sender ML-DSA signature invalid or header tampered")

                msg_key = derive_subkey(bytes(ses["session_key"]), f"msg|{msg['seq_no']}".encode("utf-8"))
                try:
                    plaintext = aead_decrypt(
                        msg_key,
                        bytes(msg["nonce"]),
                        bytes(msg["ciphertext"]),
                        aad_bytes,
                    ).decode("utf-8")
                except CryptoError as exc:
                    raise TransportError(f"Recipient/AAD binding or decryption failed: {exc}") from exc

                seen_seqs.add(msg["seq_no"])
                conn.execute(
                    "UPDATE sessions SET seen_seqs_json = ? WHERE session_id = ?",
                    (json.dumps(sorted(seen_seqs)), msg["session_id"]),
                )

        if replay_info is not None:
            self.audit.log_event(
                org_id=org_id,
                actor_id=receiver_user_id,
                service="chat",
                action="REPLAY_REJECTED",
                target=message_id,
                context={"session_id": replay_info[0], "seq_no": replay_info[1]},
            )
            raise TransportError(f"Replay detected for seq_no={replay_info[1]}")

        return {
            "message_id": message_id,
            "session_id": msg["session_id"],
            "seq_no": msg["seq_no"],
            "sender_user_id": msg["sender_user_id"],
            "recipient_user_id": msg["recipient_user_id"],
            "plaintext": plaintext,
        }

    def list_messages_for_org(self, org_id: str) -> list[dict[str, Any]]:
        """List encrypted message metadata (ciphertext only, no plaintext)."""
        with self.db.read() as conn:
            rows = conn.execute(
                """
                SELECT m.message_id, m.session_id, m.seq_no, m.sender_user_id, m.recipient_user_id,
                       m.recipient_device_id, m.created_at, u1.username AS sender_name, u2.username AS recipient_name
                FROM chat_messages m
                JOIN users u1 ON m.sender_user_id = u1.user_id
                JOIN users u2 ON m.recipient_user_id = u2.user_id
                WHERE m.org_id = ?
                ORDER BY m.created_at DESC LIMIT 100
                """,
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]


class ChunkedDeliveryBuffer:
    """Reassembles out-of-order authenticated chunks and discards incomplete/invalid deliveries."""

    def __init__(self, session_key: bytes, total_chunks: int, aad_prefix: bytes) -> None:
        self.session_key = session_key
        self.total_chunks = total_chunks
        self.aad_prefix = aad_prefix
        self.chunks: dict[int, bytes] = {}
        self.invalid_chunks: list[int] = []

    def encode_chunks(self, payload: bytes, chunk_size: int = 32) -> list[dict[str, Any]]:
        """Split payload into authenticated chunks."""
        parts = [payload[i : i + chunk_size] for i in range(0, len(payload), chunk_size)] or [b""]
        total = len(parts)
        out = []
        for idx, part in enumerate(parts):
            aad = self.aad_prefix + f"|{idx}|{total}".encode("utf-8")
            nonce, ct = aead_encrypt(self.session_key, part, aad)
            out.append({"index": idx, "total": total, "nonce": nonce, "ct": ct})
        return out

    def ingest_chunk(self, chunk: dict[str, Any]) -> None:
        """Verify and store an arriving chunk (even if out of order)."""
        idx = chunk["index"]
        total = chunk["total"]
        if total != self.total_chunks or idx < 0 or idx >= total:
            self.invalid_chunks.append(idx)
            return
        aad = self.aad_prefix + f"|{idx}|{total}".encode("utf-8")
        try:
            pt = aead_decrypt(self.session_key, chunk["nonce"], chunk["ct"], aad)
            self.chunks[idx] = pt
        except CryptoError:
            self.invalid_chunks.append(idx)

    def assemble(self) -> tuple[bool, bytes | None, str | None]:
        """Return (success, payload, failure_reason)."""
        if self.invalid_chunks:
            self.chunks.clear()
            return False, None, f"Discarded delivery: invalid/corrupted chunks {self.invalid_chunks}"
        missing = [i for i in range(self.total_chunks) if i not in self.chunks]
        if missing:
            self.chunks.clear()
            return False, None, f"Discarded incomplete delivery: missing chunks {missing}"
        return True, b"".join(self.chunks[i] for i in range(self.total_chunks)), None
