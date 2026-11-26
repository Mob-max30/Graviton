"""End-to-end encrypted messaging with true ephemeral forward secrecy,
replay & recipient binding, delivery under loss/reordering, and identity-bound
session resumption.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from graviton.crypto import (
    HybridKEMKeyPair,
    SignKeyPair,
    aead_decrypt,
    aead_encrypt,
    generate_hybrid_kem_keypair,
    hkdf_sha256,
    hybrid_kem_decapsulate,
    hybrid_kem_encapsulate,
    sign_message,
    verify_signature,
)


@dataclass
class Identity:
    user_id: str
    sign_kp: SignKeyPair
    kem_kp: HybridKEMKeyPair


@dataclass
class EncryptedEnvelope:
    session_id: str
    sender: str
    recipient: str
    seq: int
    nonce: bytes
    ciphertext: bytes


@dataclass
class SessionState:
    session_id: str
    peer_id: str
    peer_sign_pk_hash: str
    root_key: Optional[bytes]
    next_send_seq: int = 0
    next_recv_seq: int = 0
    seen_seqs: Set[int] = field(default_factory=set)
    reorder_buffer: Dict[int, bytes] = field(default_factory=dict)
    failed_seqs: List[Tuple[int, str]] = field(default_factory=list)
    closed: bool = False
    resumption_ticket: Optional[bytes] = None

    def close(self) -> None:
        """Destroy session key material for forward secrecy."""
        self.root_key = None
        self.resumption_ticket = None
        self.reorder_buffer.clear()
        self.closed = True


class MessagingEndpoint:
    def __init__(self, identity: Identity) -> None:
        self.identity = identity
        self.sessions: Dict[str, SessionState] = {}
        self.peer_directory: Dict[str, Identity] = {}
        self._pending_ephemeral: Dict[str, HybridKEMKeyPair] = {}

    def register_peer(self, peer: Identity) -> None:
        self.peer_directory[peer.user_id] = peer

    def initiate_session(self, peer_id: str, session_id: Optional[str] = None) -> Tuple[str, bytes, bytes]:
        """Step 1 (Initiator): Generate an ephemeral Hybrid KEM keypair (ML-KEM-768 + X25519)
        and sign it with the initiator's long-term ML-DSA-65 identity key.
        """
        if peer_id not in self.peer_directory:
            raise ValueError(f"Unknown peer: {peer_id}")
        sid = session_id or os.urandom(16).hex()
        eph_kem = generate_hybrid_kem_keypair()
        self._pending_ephemeral[sid] = eph_kem

        payload = json.dumps(
            {
                "session_id": sid,
                "sender": self.identity.user_id,
                "recipient": peer_id,
                "eph_mlkem_pk": eph_kem.mlkem_pk.hex(),
                "eph_x25519_pk": eph_kem.x25519_pk.hex(),
                "nonce": os.urandom(16).hex(),
            },
            sort_keys=True,
        ).encode()
        sig = sign_message(self.identity.sign_kp.secret_key, payload)
        return sid, payload, sig

    def accept_session(self, sender_id: str, init_payload: bytes, init_sig: bytes) -> Tuple[str, bytes, bytes]:
        """Step 2 (Responder): Verify initiator's ML-DSA-65 signature, encapsulate to
        initiator's ephemeral Hybrid KEM public key, and return signed response.
        Responder's ephemeral X25519 secret is never stored.
        """
        if sender_id not in self.peer_directory:
            raise ValueError(f"Unknown peer: {sender_id}")
        sender = self.peer_directory[sender_id]
        if not verify_signature(sender.sign_kp.public_key, init_payload, init_sig):
            raise ValueError("Invalid initiator handshake signature")

        meta = json.loads(init_payload.decode())
        if meta["recipient"] != self.identity.user_id or meta["sender"] != sender_id:
            raise ValueError("Recipient/sender binding mismatch in handshake")

        sid = meta["session_id"]
        eph_mlkem_pk = bytes.fromhex(meta["eph_mlkem_pk"])
        eph_x25519_pk = bytes.fromhex(meta["eph_x25519_pk"])
        salt = hashlib.sha256(init_payload).digest()

        ml_ct, resp_x_pk, shared_secret = hybrid_kem_encapsulate(eph_mlkem_pk, eph_x25519_pk)
        root_key = hkdf_sha256(
            shared_secret,
            salt,
            f"session:{sid}:{sender_id}:{self.identity.user_id}".encode(),
            32,
        )
        resumption_ticket = hkdf_sha256(
            root_key,
            salt,
            f"resume:{sid}:{sender_id}:{self.identity.user_id}".encode(),
            32,
        )
        peer_pk_hash = hashlib.sha256(sender.sign_kp.public_key).hexdigest()
        self.sessions[sid] = SessionState(
            session_id=sid,
            peer_id=sender_id,
            peer_sign_pk_hash=peer_pk_hash,
            root_key=root_key,
            resumption_ticket=resumption_ticket,
        )

        resp_payload = json.dumps(
            {
                "session_id": sid,
                "sender": self.identity.user_id,
                "recipient": sender_id,
                "init_hash": salt.hex(),
                "mlkem_ct": ml_ct.hex(),
                "resp_x25519_pk": resp_x_pk.hex(),
            },
            sort_keys=True,
        ).encode()
        resp_sig = sign_message(self.identity.sign_kp.secret_key, resp_payload)
        return sid, resp_payload, resp_sig

    def finalize_session(self, peer_id: str, resp_payload: bytes, resp_sig: bytes) -> str:
        """Step 3 (Initiator): Verify responder's signature, decapsulate using ephemeral
        secret keys, derive root_key, and immediately erase ephemeral secret keys.
        """
        if peer_id not in self.peer_directory:
            raise ValueError(f"Unknown peer: {peer_id}")
        peer = self.peer_directory[peer_id]
        if not verify_signature(peer.sign_kp.public_key, resp_payload, resp_sig):
            raise ValueError("Invalid responder handshake signature")

        meta = json.loads(resp_payload.decode())
        if meta["recipient"] != self.identity.user_id or meta["sender"] != peer_id:
            raise ValueError("Recipient/sender binding mismatch in handshake response")

        sid = meta["session_id"]
        eph_kem = self._pending_ephemeral.pop(sid, None)
        if eph_kem is None:
            raise ValueError(f"No pending ephemeral handshake for session {sid}")

        try:
            salt = bytes.fromhex(meta["init_hash"])
            ml_ct = bytes.fromhex(meta["mlkem_ct"])
            resp_x_pk = bytes.fromhex(meta["resp_x25519_pk"])
            shared_secret = hybrid_kem_decapsulate(
                eph_kem.mlkem_sk, eph_kem.x25519_sk, ml_ct, resp_x_pk
            )
        finally:
            # Erase ephemeral secret keys immediately for forward secrecy
            eph_kem.erase_secret_keys()

        root_key = hkdf_sha256(
            shared_secret,
            salt,
            f"session:{sid}:{self.identity.user_id}:{peer_id}".encode(),
            32,
        )
        resumption_ticket = hkdf_sha256(
            root_key,
            salt,
            f"resume:{sid}:{self.identity.user_id}:{peer_id}".encode(),
            32,
        )
        peer_pk_hash = hashlib.sha256(peer.sign_kp.public_key).hexdigest()
        self.sessions[sid] = SessionState(
            session_id=sid,
            peer_id=peer_id,
            peer_sign_pk_hash=peer_pk_hash,
            root_key=root_key,
            resumption_ticket=resumption_ticket,
        )
        return sid

    def make_resumption_proof(self, session_id: str, challenge: bytes = b"default-challenge") -> Tuple[bytes, bytes]:
        """Create an identity-bound resumption proof (HMAC + ML-DSA-65 signature)."""
        sess = self.sessions.get(session_id)
        if not sess or sess.closed or sess.resumption_ticket is None:
            raise ValueError("Cannot resume closed or unknown session")
        mac = hmac.new(
            sess.resumption_ticket,
            f"resume:{session_id}:{self.identity.user_id}:".encode() + challenge,
            hashlib.sha256,
        ).digest()
        sig = sign_message(
            self.identity.sign_kp.secret_key,
            f"resume:{session_id}:{self.identity.user_id}:".encode() + challenge + mac,
        )
        return mac, sig

    def resume_session(
        self,
        session_id: str,
        claimed_peer_id: str,
        proof_mac: bytes,
        proof_sig: bytes,
        challenge: bytes = b"default-challenge",
    ) -> bool:
        """Verify that a resumed session remains bound to its authenticated peer."""
        sess = self.sessions.get(session_id)
        if not sess or sess.closed or sess.resumption_ticket is None:
            return False
        if sess.peer_id != claimed_peer_id:
            return False
        peer = self.peer_directory.get(claimed_peer_id)
        if peer is None:
            return False
        if hashlib.sha256(peer.sign_kp.public_key).hexdigest() != sess.peer_sign_pk_hash:
            return False

        expected_mac = hmac.new(
            sess.resumption_ticket,
            f"resume:{session_id}:{claimed_peer_id}:".encode() + challenge,
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(proof_mac, expected_mac):
            return False

        signed_msg = f"resume:{session_id}:{claimed_peer_id}:".encode() + challenge + proof_mac
        return verify_signature(peer.sign_kp.public_key, signed_msg, proof_sig)

    def send(self, session_id: str, plaintext: bytes) -> EncryptedEnvelope:
        sess = self.sessions.get(session_id)
        if not sess or sess.closed or sess.root_key is None:
            raise ValueError("Session unavailable or closed")
        seq = sess.next_send_seq
        sess.next_send_seq += 1
        aad = f"{session_id}|{self.identity.user_id}|{sess.peer_id}|{seq}".encode()
        msg_key = hkdf_sha256(sess.root_key, seq.to_bytes(8, "big"), b"msg-key", 32)
        nonce, ct = aead_encrypt(msg_key, plaintext, aad)
        return EncryptedEnvelope(
            session_id=session_id,
            sender=self.identity.user_id,
            recipient=sess.peer_id,
            seq=seq,
            nonce=nonce,
            ciphertext=ct,
        )

    def receive(self, env: EncryptedEnvelope) -> Tuple[List[bytes], List[str]]:
        """Authenticate, decrypt, and deliver in-order messages; buffer out-of-order;
        reject replays, recipient mismatches, and corrupted envelopes.
        """
        sess = self.sessions.get(env.session_id)
        if not sess or sess.closed or sess.root_key is None:
            return [], ["Session unavailable or closed"]
        if env.recipient != self.identity.user_id or env.sender != sess.peer_id:
            return [], ["Recipient or sender binding mismatch"]
        if env.seq < 0:
            return [], [f"Invalid negative sequence number seq={env.seq}"]
        if env.seq in sess.seen_seqs or env.seq < sess.next_recv_seq:
            return [], [f"Replay detected for seq={env.seq}"]

        aad = f"{env.session_id}|{env.sender}|{env.recipient}|{env.seq}".encode()
        msg_key = hkdf_sha256(sess.root_key, env.seq.to_bytes(8, "big"), b"msg-key", 32)
        try:
            pt = aead_decrypt(msg_key, env.nonce, env.ciphertext, aad)
        except Exception as exc:
            err = f"Decryption/authentication failed for seq={env.seq}: {exc}"
            sess.failed_seqs.append((env.seq, err))
            return [], [err]

        sess.seen_seqs.add(env.seq)
        sess.reorder_buffer[env.seq] = pt

        delivered: List[bytes] = []
        while sess.next_recv_seq in sess.reorder_buffer:
            delivered.append(sess.reorder_buffer.pop(sess.next_recv_seq))
            sess.next_recv_seq += 1

        return delivered, []

    def report_incomplete_deliveries(self, session_id: str) -> Dict[str, object]:
        """Report missing (lost) sequence numbers, buffered out-of-order messages,
        and invalid/corrupted messages, discarding incomplete buffered state on demand.
        """
        sess = self.sessions.get(session_id)
        if not sess:
            raise ValueError(f"Unknown session: {session_id}")
        highest_buffered = max(sess.reorder_buffer.keys(), default=sess.next_recv_seq - 1)
        missing_seqs = [
            s
            for s in range(sess.next_recv_seq, highest_buffered + 1)
            if s not in sess.reorder_buffer and s not in sess.seen_seqs
        ]
        return {
            "next_expected_seq": sess.next_recv_seq,
            "missing_seqs": missing_seqs,
            "buffered_out_of_order": sorted(sess.reorder_buffer.keys()),
            "failed_deliveries": list(sess.failed_seqs),
        }

    def discard_incomplete(self, session_id: str) -> int:
        """Discard unrecoverable out-of-order buffered messages and return count discarded."""
        sess = self.sessions.get(session_id)
        if not sess:
            return 0
        count = len(sess.reorder_buffer)
        sess.reorder_buffer.clear()
        return count
