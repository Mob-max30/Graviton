"""Forward-secret ML-KEM-768 session establishment, recipient binding, and replay cache."""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
import secrets

from graviton.crypto.aead import aead_available, build_associated_data, open_sealed, seal
from graviton.crypto.kdf import hkdf
from graviton.crypto.kem import decapsulate, encapsulate, generate_kem_keypair
from graviton.crypto.signatures import sign_message, verify_signature
from graviton.feed.encoding import enc_bytes, enc_id, enc_u8
from graviton.storage import atomic_write_text, state_lock

SESSION_INIT_DOMAIN = b"session-init"
SESSION_RESP_DOMAIN = b"session-resp"
DEFAULT_REPLAY_CACHE_SIZE = 10_000


class MessageError(RuntimeError):
    """Raised on session handshake, authentication, recipient-binding, or replay errors."""


@dataclass(frozen=True)
class SessionTranscript:
    """Public handshake transcript (recorded by an eavesdropper)."""

    session_id: str
    initiator_id: str
    responder_id: str
    ephemeral_kem_pk: bytes
    initiator_sig: bytes
    kem_ciphertext: bytes
    responder_sig: bytes


@dataclass
class SessionContext:
    """Established session holding only the derived symmetric session key (no ephemeral sk)."""

    session_id: str
    initiator_id: str
    responder_id: str
    session_key: bytes

    def erase(self) -> None:
        self.session_key = b"\x00" * len(self.session_key)


def establish_session(
    initiator_id: str,
    initiator_sign_sk: bytes,
    initiator_sign_pk: bytes,
    responder_id: str,
    responder_sign_sk: bytes,
    responder_sign_pk: bytes,
    *,
    session_id: str | None = None,
) -> tuple[SessionContext, SessionContext, SessionTranscript]:
    """Perform an ephemeral ML-KEM-768 + ML-DSA-65 authenticated key exchange.

    Long-term ML-DSA-65 keys only sign; ephemeral ML-KEM-768 keys are discarded
    immediately after deriving the session key, providing forward secrecy.
    """
    sid = session_id or secrets.token_hex(16)
    eph_pk, eph_sk = generate_kem_keypair()

    init_msg = enc_u8(1) + enc_id(sid) + enc_id(initiator_id) + enc_id(responder_id) + enc_bytes(eph_pk)
    init_sig = sign_message(initiator_sign_sk, init_msg, domain=SESSION_INIT_DOMAIN)

    # Responder verifies initiator's identity signature before encapsulating
    if not verify_signature(initiator_sign_pk, init_msg, init_sig, domain=SESSION_INIT_DOMAIN):
        raise MessageError("Initiator handshake signature verification failed")

    kem_ct, ss_resp = encapsulate(eph_pk)
    resp_msg = enc_u8(1) + enc_id(sid) + enc_id(responder_id) + enc_id(initiator_id) + enc_bytes(kem_ct)
    resp_sig = sign_message(responder_sign_sk, resp_msg, domain=SESSION_RESP_DOMAIN)

    # Initiator verifies responder's identity signature before decapsulating
    if not verify_signature(responder_sign_pk, resp_msg, resp_sig, domain=SESSION_RESP_DOMAIN):
        raise MessageError("Responder handshake signature verification failed")

    ss_init = decapsulate(eph_sk, kem_ct)
    # Ephemeral secret material goes out of scope and is never stored or returned
    del eph_sk

    if not hmac.compare_digest(ss_init, ss_resp):
        raise MessageError("ML-KEM shared secret mismatch")

    info = b"graviton-session-v1"
    salt = sid.encode("utf-8")
    key_init = hkdf(salt, ss_init, info, 32)
    key_resp = hkdf(salt, ss_resp, info, 32)
    del ss_init, ss_resp

    transcript = SessionTranscript(
        session_id=sid,
        initiator_id=initiator_id,
        responder_id=responder_id,
        ephemeral_kem_pk=eph_pk,
        initiator_sig=init_sig,
        kem_ciphertext=kem_ct,
        responder_sig=resp_sig,
    )
    return (
        SessionContext(sid, initiator_id, responder_id, key_init),
        SessionContext(sid, initiator_id, responder_id, key_resp),
        transcript,
    )


class ReplayCache:
    """Persisted per-session replay cache rejecting duplicate or evicted counters."""

    def __init__(self, cache_path: str | Path, max_per_session: int = DEFAULT_REPLAY_CACHE_SIZE) -> None:
        self.cache_path = Path(cache_path)
        self.max_per_session = max_per_session
        self._lock_dir = self.cache_path.parent

    def _load(self) -> dict:
        if not self.cache_path.is_file():
            return {"version": 1, "sessions": {}}
        return json.loads(self.cache_path.read_text(encoding="utf-8"))

    def _save(self, data: dict) -> None:
        atomic_write_text(
            self.cache_path,
            json.dumps(data, allow_nan=False, separators=(",", ":")),
        )

    def check_and_record(self, session_id: str, counter: int) -> None:
        """Reject duplicate or too-old counters; persist accepted counter atomically."""
        if counter < 0:
            raise MessageError("Counter must be non-negative")
        with state_lock(self._lock_dir):
            data = self._load()
            sess = data["sessions"].setdefault(session_id, {"seen": [], "floor": -1})
            floor = int(sess["floor"])
            seen = sess["seen"]

            if counter <= floor or counter in seen:
                raise MessageError(f"Replay detected for session {session_id} counter {counter}")

            seen.append(counter)
            if len(seen) > self.max_per_session:
                seen.sort()
                evict_count = len(seen) - self.max_per_session
                new_floor = max(floor, seen[evict_count - 1])
                sess["floor"] = new_floor
                sess["seen"] = seen[evict_count:]
            self._save(data)


def encrypt_message(
    session: SessionContext,
    sender_id: str,
    recipient_id: str,
    counter: int,
    plaintext: bytes,
) -> dict:
    """Encrypt/authenticate a message bound to (recipient_id, sender_id, session_id, counter)."""
    aad = build_associated_data(recipient_id, sender_id, session.session_id, counter)
    if aead_available():
        nonce, ct = seal(session.session_key, plaintext, aad)
        return {
            "mode": "aes-256-gcm",
            "session_id": session.session_id,
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "counter": counter,
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "ciphertext_b64": base64.b64encode(ct).decode("ascii"),
        }

    # Documented fallback when `cryptography` is absent (pqcrypto-only runtime):
    # authenticates AAD + payload with HMAC-SHA-256 without inventing a custom cipher.
    mac_key = hkdf(session.session_id.encode("utf-8"), session.session_key, b"graviton-mac-fallback", 32)
    tag = hmac.new(mac_key, aad + enc_bytes(plaintext), hashlib.sha256).hexdigest()
    return {
        "mode": "hmac-sha256-fallback",
        "session_id": session.session_id,
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "counter": counter,
        "payload_b64": base64.b64encode(plaintext).decode("ascii"),
        "tag_hex": tag,
    }


def decrypt_message(
    session: SessionContext,
    envelope: dict,
    expected_recipient_id: str,
    *,
    replay_cache: ReplayCache | None = None,
) -> bytes:
    """Verify recipient binding, authentication, and replay protection before returning plaintext."""
    if envelope.get("session_id") != session.session_id:
        raise MessageError("Session ID mismatch")
    recipient_id = envelope.get("recipient_id")
    sender_id = envelope.get("sender_id")
    counter = envelope.get("counter")
    if not isinstance(recipient_id, str) or not isinstance(sender_id, str) or not isinstance(counter, int):
        raise MessageError("Malformed message envelope")
    if recipient_id != expected_recipient_id:
        raise MessageError("Recipient mismatch")

    aad = build_associated_data(recipient_id, sender_id, session.session_id, counter)
    mode = envelope.get("mode")

    if mode == "aes-256-gcm":
        try:
            nonce = base64.b64decode(envelope["nonce_b64"], validate=True)
            ct = base64.b64decode(envelope["ciphertext_b64"], validate=True)
            plaintext = open_sealed(session.session_key, nonce, ct, aad)
        except Exception as exc:
            raise MessageError("AEAD authentication failed") from exc
    elif mode == "hmac-sha256-fallback":
        try:
            plaintext = base64.b64decode(envelope["payload_b64"], validate=True)
            tag_hex = envelope["tag_hex"]
        except Exception as exc:
            raise MessageError("Malformed fallback envelope") from exc
        mac_key = hkdf(session.session_id.encode("utf-8"), session.session_key, b"graviton-mac-fallback", 32)
        expected_tag = hmac.new(mac_key, aad + enc_bytes(plaintext), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(tag_hex, expected_tag):
            raise MessageError("Envelope MAC verification failed")
    else:
        raise MessageError(f"Unsupported envelope mode: {mode}")

    if replay_cache is not None:
        replay_cache.check_and_record(session.session_id, counter)
    return plaintext
