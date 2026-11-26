"""Session resumption tickets with durable single-use guards and proof-of-possession."""
import datetime
import hashlib
import hmac
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path
from typing import Dict, Optional, Set, Tuple

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from trustledger.crypto.suites import CipherSuite

TICKET_LIFETIME_SECONDS = int(os.environ.get("TRUSTLEDGER_TICKET_LIFETIME", "3600"))


class TicketError(ValueError):
    """Raised when session ticket validation fails."""


class TicketManager:
    """Issues and validates AEAD-sealed session resumption tickets with durable single-use persistence."""

    def __init__(
        self,
        server_ticket_key: Optional[bytes] = None,
        store_path: Optional[Path] = None,
    ):
        self.ticket_key = server_ticket_key or secrets.token_bytes(32)
        self._aead = ChaCha20Poly1305(self.ticket_key)
        if store_path is not None:
            self.store_path = Path(store_path)
        else:
            env_store = os.environ.get("TRUSTLEDGER_TICKET_STORE")
            if env_store:
                self.store_path = Path(env_store)
            else:
                self.store_path = (
                    Path(tempfile.gettempdir())
                    / f"trustledger-tickets-{os.getpid()}"
                    / f"tickets-{secrets.token_hex(6)}.json"
                )
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self._used_tickets: Dict[str, str] = {}
        self._revoked_identities: Set[str] = set()
        self._load_store()

    def _load_store(self) -> None:
        if not self.store_path.exists():
            return
        data = json.loads(self.store_path.read_text(encoding="utf-8"))
        now = datetime.datetime.now(datetime.timezone.utc)
        raw_used = data.get("used_tickets", {})
        self._used_tickets = {}
        for tid, exp_iso in raw_used.items():
            try:
                if datetime.datetime.fromisoformat(exp_iso) > now:
                    self._used_tickets[tid] = exp_iso
            except ValueError:
                continue
        self._revoked_identities = set(data.get("revoked_identities", []))

    def _persist_store(self) -> None:
        now = datetime.datetime.now(datetime.timezone.utc)
        pruned = {
            tid: exp
            for tid, exp in self._used_tickets.items()
            if datetime.datetime.fromisoformat(exp) > now
        }
        self._used_tickets = pruned
        payload = json.dumps(
            {
                "used_tickets": self._used_tickets,
                "revoked_identities": sorted(self._revoked_identities),
            },
            sort_keys=True,
        ).encode("utf-8")

        tmp_path = self.store_path.with_name(f"{self.store_path.name}.tmp.{secrets.token_hex(6)}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(str(tmp_path), flags, 0o600) if sys.platform != "win32" else os.open(str(tmp_path), flags)
        try:
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp_path, self.store_path)

    def revoke_identity(self, identity: str) -> None:
        """Revoke all tickets for a given identity and persist."""
        self._load_store()
        self._revoked_identities.add(identity)
        self._persist_store()

    def issue_ticket(
        self,
        peer_id: str,
        peer_fingerprint: str,
        suite: CipherSuite,
        epoch: int,
    ) -> Tuple[bytes, bytes]:
        """Issue an AEAD-sealed ticket and return (ticket_bytes, ticket_secret)."""
        ticket_id = secrets.token_hex(16)
        ticket_secret = secrets.token_bytes(32)
        now = datetime.datetime.now(datetime.timezone.utc)
        expiry = now + datetime.timedelta(seconds=TICKET_LIFETIME_SECONDS)

        payload = json.dumps({
            "ticket_id": ticket_id,
            "peer_id": peer_id,
            "peer_fingerprint": peer_fingerprint,
            "suite": int(suite),
            "epoch": epoch,
            "expires_at": expiry.isoformat(),
            "ticket_secret_hex": ticket_secret.hex(),
        }).encode("utf-8")

        nonce = secrets.token_bytes(12)
        ciphertext = self._aead.encrypt(nonce, payload, b"trustledger:resumption:v1")
        ticket_blob = nonce + ciphertext
        return ticket_blob, ticket_secret

    def validate_and_resume(
        self,
        ticket_blob: bytes,
        claimed_peer_id: str,
        client_nonce: bytes,
        proof_of_possession: str,
    ) -> Tuple[bytes, CipherSuite, int]:
        """Validate ticket, check durable revocation/replay & expiry, verify proof, return (resumed_key, suite, epoch)."""
        self._load_store()

        if len(ticket_blob) < 12:
            raise TicketError("Ticket blob too short")
        nonce = ticket_blob[:12]
        ciphertext = ticket_blob[12:]

        try:
            raw_payload = self._aead.decrypt(nonce, ciphertext, b"trustledger:resumption:v1")
            info = json.loads(raw_payload.decode("utf-8"))
        except Exception as err:
            raise TicketError("Tampered or invalid session ticket") from err

        ticket_id = info["ticket_id"]
        peer_id = info["peer_id"]
        suite = CipherSuite(info["suite"])
        epoch = info["epoch"]
        ticket_secret = bytes.fromhex(info["ticket_secret_hex"])
        expires_at = datetime.datetime.fromisoformat(info["expires_at"])

        if ticket_id in self._used_tickets:
            raise TicketError("Ticket already used (replay rejected)")

        if peer_id in self._revoked_identities or claimed_peer_id in self._revoked_identities:
            raise TicketError(f"Identity {peer_id} has been revoked")

        if peer_id != claimed_peer_id:
            raise TicketError(f"Ticket peer {peer_id} does not match claimed {claimed_peer_id}")

        now = datetime.datetime.now(datetime.timezone.utc)
        if now > expires_at:
            raise TicketError("Ticket has expired")

        expected_proof = hmac.new(ticket_secret, client_nonce, hashlib.sha256).hexdigest().lower()
        if not hmac.compare_digest(proof_of_possession.lower().encode("utf-8"), expected_proof.encode("utf-8")):
            raise TicketError("Proof of possession verification failed")

        self._used_tickets[ticket_id] = info["expires_at"]
        self._persist_store()

        resumed_key = hmac.new(ticket_secret, client_nonce + b":resumed", hashlib.sha256).digest()
        return resumed_key, suite, epoch
