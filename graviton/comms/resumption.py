"""Identity-bound session resumption tickets (Section 18)."""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import hmac
import secrets
import time
from typing import Callable

from graviton.audit.log import AuditLog, AuthenticatedSession
from graviton.crypto.signatures import sign_message, verify_signature
from graviton.feed.encoding import enc_bytes, enc_id, enc_u8, enc_u64

RESUME_CHALLENGE_DOMAIN = b"session-resume"
DEFAULT_TICKET_LIFETIME_S = 3600


class ResumptionError(RuntimeError):
    """Raised when session resumption fails identity, expiry, or revocation checks."""


@dataclass(frozen=True)
class ResumptionTicket:
    session_id: str
    peer_id: str
    peer_public_key_b64: str
    expires_at: int
    ticket_mac_hex: str


class ResumptionManager:
    """Issues and verifies identity-bound session resumption tickets."""

    def __init__(
        self,
        *,
        ticket_secret: bytes | None = None,
        ticket_lifetime_s: int = DEFAULT_TICKET_LIFETIME_S,
        clock: Callable[[], int] | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        self._ticket_secret = ticket_secret or secrets.token_bytes(32)
        self.ticket_lifetime_s = ticket_lifetime_s
        self._clock = clock or (lambda: int(time.time()))
        self.audit_log = audit_log
        self._revoked_peers: set[str] = set()
        self._revoked_sessions: set[str] = set()

    def _compute_ticket_mac(
        self, session_id: str, peer_id: str, peer_pk_b64: str, expires_at: int
    ) -> str:
        msg = (
            enc_u8(1)
            + enc_id(session_id)
            + enc_id(peer_id)
            + enc_bytes(peer_pk_b64.encode("ascii"))
            + enc_u64(expires_at)
        )
        return hmac.new(self._ticket_secret, msg, hashlib.sha256).hexdigest()

    def issue_ticket(self, session_id: str, peer_id: str, peer_public_key: bytes) -> ResumptionTicket:
        if peer_id in self._revoked_peers:
            raise ResumptionError("Cannot issue ticket for revoked peer")
        pk_b64 = base64.b64encode(peer_public_key).decode("ascii")
        expires_at = int(self._clock()) + self.ticket_lifetime_s
        mac = self._compute_ticket_mac(session_id, peer_id, pk_b64, expires_at)
        return ResumptionTicket(
            session_id=session_id,
            peer_id=peer_id,
            peer_public_key_b64=pk_b64,
            expires_at=expires_at,
            ticket_mac_hex=mac,
        )

    def revoke_peer_tickets(self, peer_id: str) -> None:
        self._revoked_peers.add(peer_id)

    def revoke_session_ticket(self, session_id: str) -> None:
        self._revoked_sessions.add(session_id)

    @staticmethod
    def sign_resume_challenge(
        peer_secret_key: bytes, session_id: str, peer_id: str, nonce: bytes
    ) -> bytes:
        msg = enc_u8(1) + enc_id(session_id) + enc_id(peer_id) + enc_bytes(nonce)
        return sign_message(peer_secret_key, msg, domain=RESUME_CHALLENGE_DOMAIN)

    def verify_resumption(
        self,
        ticket: ResumptionTicket,
        claiming_peer_id: str,
        nonce: bytes,
        peer_signature: bytes,
    ) -> bool:
        """Verify ticket MAC, expiry, revocation, peer binding, and ML-DSA-65 proof of key."""

        def _reject(reason: str) -> ResumptionError:
            if self.audit_log is not None:
                self.audit_log.append_event(
                    AuthenticatedSession(actor=claiming_peer_id or "unknown"),
                    "session_resume",
                    ticket.session_id,
                    "deny",
                    reason,
                )
            return ResumptionError(reason)

        expected_mac = self._compute_ticket_mac(
            ticket.session_id, ticket.peer_id, ticket.peer_public_key_b64, ticket.expires_at
        )
        if not hmac.compare_digest(ticket.ticket_mac_hex, expected_mac):
            raise _reject("Invalid resumption ticket MAC")

        if ticket.session_id in self._revoked_sessions or ticket.peer_id in self._revoked_peers:
            raise _reject("Resumption ticket revoked")

        if int(self._clock()) > ticket.expires_at:
            raise _reject("Resumption ticket expired")

        if claiming_peer_id != ticket.peer_id:
            raise _reject("Peer identity mismatch on session resumption")

        peer_pk = base64.b64decode(ticket.peer_public_key_b64, validate=True)
        msg = enc_u8(1) + enc_id(ticket.session_id) + enc_id(claiming_peer_id) + enc_bytes(nonce)
        if not verify_signature(peer_pk, msg, peer_signature, domain=RESUME_CHALLENGE_DOMAIN):
            raise _reject("Invalid ML-DSA-65 proof of identity key on resumption")

        return True
