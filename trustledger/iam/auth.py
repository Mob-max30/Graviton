"""Authentication challenge-response with rate limiting and per-source lockout."""
import secrets
import struct
import time
from typing import Dict, NamedTuple, Optional, Tuple

import pqcrypto.sign.ml_dsa_65 as ml_dsa

from trustledger.crypto.keys import TrustedPeerStore
from trustledger.crypto.suites import CipherSuite

CHALLENGE_VALIDITY_SECONDS = 60.0
MAX_ATTEMPTS_BEFORE_LOCKOUT = 5
LOCKOUT_DURATION_SECONDS = 30.0


def _lp(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


class AuthChallenge(NamedTuple):
    challenge_id: str
    nonce: bytes
    created_at: float
    audience: str


class RateLimiter:
    """Per-identity + per-source bounded lockout tracker to prevent denial-of-service against others."""

    def __init__(self, max_attempts: int = MAX_ATTEMPTS_BEFORE_LOCKOUT, lockout_sec: float = LOCKOUT_DURATION_SECONDS):
        self.max_attempts = max_attempts
        self.lockout_sec = lockout_sec
        self._failures: Dict[str, Tuple[int, float]] = {}

    def _make_key(self, identity: str, source_ip: str) -> str:
        return f"{identity}:{source_ip}"

    def record_failure(self, identity: str, source_ip: str) -> Tuple[bool, float]:
        """Record an auth failure. Resets counter once a previous lockout window expires."""
        key = self._make_key(identity, source_ip)
        now = time.monotonic()
        count, lockout_until = self._failures.get(key, (0, 0.0))

        if lockout_until > 0.0:
            if now < lockout_until:
                return True, lockout_until - now
            # Previous lockout expired; reset counter for the new window
            count = 0
            lockout_until = 0.0

        count += 1
        if count >= self.max_attempts:
            lockout_until = now + self.lockout_sec
            self._failures[key] = (count, lockout_until)
            return True, self.lockout_sec

        self._failures[key] = (count, 0.0)
        return False, 0.0

    def is_locked(self, identity: str, source_ip: str) -> Tuple[bool, float]:
        key = self._make_key(identity, source_ip)
        now = time.monotonic()
        _count, lockout_until = self._failures.get(key, (0, 0.0))
        if now < lockout_until:
            return True, lockout_until - now
        return False, 0.0

    def record_success(self, identity: str, source_ip: str) -> None:
        key = self._make_key(identity, source_ip)
        self._failures.pop(key, None)


class Authenticator:
    """Issues and validates signed challenge-response proofs with optional TrustedPeerStore pinning."""

    def __init__(self, audience: str = "trustledger-cluster", trusted_peers: Optional[TrustedPeerStore] = None):
        self.audience = audience
        self.trusted_peers = trusted_peers
        self.rate_limiter = RateLimiter()
        self._pending_challenges: Dict[str, AuthChallenge] = {}

    def issue_challenge(self) -> AuthChallenge:
        c_id = secrets.token_hex(16)
        nonce = secrets.token_bytes(32)
        chal = AuthChallenge(
            challenge_id=c_id,
            nonce=nonce,
            created_at=time.monotonic(),
            audience=self.audience,
        )
        self._pending_challenges[c_id] = chal
        return chal

    def verify_response(
        self,
        challenge_id: str,
        identity: str,
        source_ip: str,
        identity_dsa_pk: bytes,
        signature: bytes,
    ) -> Tuple[bool, str]:
        """Verify client response signature over length-prefixed challenge nonce, audience, and identity."""
        locked, remaining = self.rate_limiter.is_locked(identity, source_ip)
        if locked:
            return False, f"LOCKOUT: Rate limit exceeded, retry in {remaining:.1f}s"

        chal = self._pending_challenges.pop(challenge_id, None)
        if not chal:
            self.rate_limiter.record_failure(identity, source_ip)
            return False, "INVALID_CHALLENGE: Unknown or expired challenge"

        if time.monotonic() - chal.created_at > CHALLENGE_VALIDITY_SECONDS:
            self.rate_limiter.record_failure(identity, source_ip)
            return False, "EXPIRED_CHALLENGE: Challenge timeout exceeded"

        if self.trusted_peers is not None:
            try:
                self.trusted_peers.verify_peer_key(identity, CipherSuite.SUITE_PQ, identity_dsa_pk, None)
            except ValueError:
                self.rate_limiter.record_failure(identity, source_ip)
                return False, "UNTRUSTED_KEY: Identity public key not pinned"

        msg = _lp(chal.nonce) + _lp(chal.audience.encode("utf-8")) + _lp(identity.encode("utf-8"))
        if not ml_dsa.verify(identity_dsa_pk, msg, signature):
            self.rate_limiter.record_failure(identity, source_ip)
            return False, "BAD_SIGNATURE: Authentication signature failed"

        self.rate_limiter.record_success(identity, source_ip)
        return True, "AUTHENTICATED"
