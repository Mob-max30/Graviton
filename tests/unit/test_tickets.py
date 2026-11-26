"""Unit tests for Session Resumption Tickets."""
import secrets
import pytest

from trustledger.crypto.suites import CipherSuite
from trustledger.protocol.tickets import TicketError, TicketManager


def test_session_ticket_roundtrip():
    manager = TicketManager()
    ticket_blob, ticket_secret = manager.issue_ticket(
        peer_id="alice",
        peer_fingerprint="fp-alice-1234",
        suite=CipherSuite.SUITE_HYBRID,
        epoch=2,
    )

    client_nonce = secrets.token_bytes(32)
    import hashlib
    import hmac
    proof = hmac.new(ticket_secret, client_nonce, hashlib.sha256).hexdigest()

    resumed_key, suite, epoch = manager.validate_and_resume(
        ticket_blob=ticket_blob,
        claimed_peer_id="alice",
        client_nonce=client_nonce,
        proof_of_possession=proof,
    )
    assert len(resumed_key) == 32
    assert suite == CipherSuite.SUITE_HYBRID
    assert epoch == 2


def test_session_ticket_single_use_replay_prevention():
    manager = TicketManager()
    ticket_blob, ticket_secret = manager.issue_ticket(
        peer_id="alice",
        peer_fingerprint="fp-alice",
        suite=CipherSuite.SUITE_PQ,
        epoch=1,
    )
    client_nonce = secrets.token_bytes(32)
    import hashlib
    import hmac
    proof = hmac.new(ticket_secret, client_nonce, hashlib.sha256).hexdigest()

    # First use succeeds
    manager.validate_and_resume(ticket_blob, "alice", client_nonce, proof)

    # Second use fails
    with pytest.raises(TicketError, match="Ticket already used"):
        manager.validate_and_resume(ticket_blob, "alice", client_nonce, proof)


def test_revoked_identity_ticket_rejection():
    manager = TicketManager()
    ticket_blob, ticket_secret = manager.issue_ticket("bob", "fp-bob", CipherSuite.SUITE_PQ, 1)
    client_nonce = secrets.token_bytes(32)
    import hashlib
    import hmac
    proof = hmac.new(ticket_secret, client_nonce, hashlib.sha256).hexdigest()

    # Revoke Bob
    manager.revoke_identity("bob")

    with pytest.raises(TicketError, match="has been revoked"):
        manager.validate_and_resume(ticket_blob, "bob", client_nonce, proof)


def test_session_ticket_durable_across_restarts():
    """M-01: Used ticket IDs persist across manager restarts and reject replay."""
    import hashlib
    import hmac
    import tempfile
    from pathlib import Path

    ticket_key = secrets.token_bytes(32)
    with tempfile.TemporaryDirectory() as td:
        store_file = Path(td) / "tickets.json"
        mgr_a = TicketManager(server_ticket_key=ticket_key, store_path=store_file)
        ticket_blob, ticket_secret = mgr_a.issue_ticket("alice", "fp-alice", CipherSuite.SUITE_PQ, 1)

        nonce1 = secrets.token_bytes(32)
        proof1 = hmac.new(ticket_secret, nonce1, hashlib.sha256).hexdigest()
        resumed_key, _, _ = mgr_a.validate_and_resume(ticket_blob, "alice", nonce1, proof1)
        assert len(resumed_key) == 32
        del mgr_a

        # Simulate restart with new manager instance using same key and store
        mgr_b = TicketManager(server_ticket_key=ticket_key, store_path=store_file)
        nonce2 = secrets.token_bytes(32)
        proof2 = hmac.new(ticket_secret, nonce2, hashlib.sha256).hexdigest()
        with pytest.raises(TicketError, match="Ticket already used"):
            mgr_b.validate_and_resume(ticket_blob, "alice", nonce2, proof2)
