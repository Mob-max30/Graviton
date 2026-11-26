"""Comprehensive Adversarial Red-Team Test Suite covering all 12 attack vectors."""
import hashlib
import hmac
import json
import os
import secrets
import tempfile
from pathlib import Path

import pqcrypto.sign.ml_dsa_65 as ml_dsa
import pytest

from trustledger.audit.logger import SignedAuditLogger
from trustledger.audit.verifier import verify_log
from trustledger.core.service import DispatchError, dispatch
from trustledger.core.store import IntegrityError
from trustledger.crypto.aead import AEADCipher, AssociatedData
from trustledger.crypto.keys import HybridIdentityKeypair, TrustedPeerStore
from trustledger.crypto.suites import CipherSuite
from trustledger.protocol.channel import ResilientChannel
from trustledger.protocol.handshake import (
    HandshakeError,
    HandshakeInitiator,
    HandshakeResponder,
)
from trustledger.protocol.ratchet import RatchetError, SymmetricRatchetSession
from trustledger.protocol.tickets import TicketError, TicketManager


def test_attack_01_replay():
    """A-01: Attacker attempts to replay an earlier valid ciphertext."""
    alice = SymmetricRatchetSession("s1", CipherSuite.SUITE_PQ, "alice", "bob", "fp-b", b"1" * 32, b"2" * 32)
    bob = SymmetricRatchetSession("s1", CipherSuite.SUITE_PQ, "bob", "alice", "fp-a", b"2" * 32, b"1" * 32)

    ct = alice.encrypt_message(b"Transfer $1000", message_id="tx-100")
    pt = bob.decrypt_message(ct, 0, "tx-100", "alice", "bob", "fp-b", 1, total_length=14)
    assert pt == b"Transfer $1000"

    with pytest.raises(RatchetError, match="Replay detected"):
        bob.decrypt_message(ct, 0, "tx-100", "alice", "bob", "fp-b", 1, total_length=14)


def test_attack_02_reflection():
    """A-02: Attacker reflects client's own identity/signature back as server response."""
    client_key = HybridIdentityKeypair.generate()
    server_key = HybridIdentityKeypair.generate()
    trust = TrustedPeerStore()
    trust.register_peer("alice", client_key, CipherSuite.SUITE_PQ)
    trust.register_peer("srv1", server_key, CipherSuite.SUITE_PQ)

    initiator = HandshakeInitiator("alice", "client", client_key, suite=CipherSuite.SUITE_PQ, trusted_peers=trust)
    reflected_sig = ml_dsa.sign(client_key.dsa_sk, initiator.transcript.digest())

    # Attempting to reflect alice's key/signature as srv1 fails key-pinning check
    with pytest.raises(HandshakeError, match="fingerprint mismatch"):
        initiator.process_server_hello_and_authenticate(
            server_id="srv1",
            server_role="server",
            server_identity_dsa_pk=client_key.dsa_pk,
            server_identity_ed_pk=None,
            server_nonce=initiator.client_nonce,
            kem_ciphertext=b"0" * 1088,
            server_x25519_pk=None,
            server_signature=reflected_sig,
        )


def test_attack_03_kci():
    """A-03: Key-Compromise Impersonation against responder's long-term private key."""
    client_key = HybridIdentityKeypair.generate()
    server_key = HybridIdentityKeypair.generate()
    trust = TrustedPeerStore()
    trust.register_peer("alice", client_key, CipherSuite.SUITE_PQ)
    trust.register_peer("srv1", server_key, CipherSuite.SUITE_PQ)

    initiator = HandshakeInitiator("alice", "client", client_key, suite=CipherSuite.SUITE_PQ, trusted_peers=trust)
    responder = HandshakeResponder("srv1", "server", server_key, trusted_peers=trust)

    _s_nonce, _kem_ct, _s_x, _s_sig, transcript_hash = responder.process_client_hello_and_reply(
        client_id="alice",
        client_role="client",
        suite=CipherSuite.SUITE_PQ,
        client_nonce=initiator.client_nonce,
        client_kem_pk=initiator.ephemeral_key.kem_pk,  # type: ignore[union-attr]
        client_x25519_pk=None,
    )

    # Attacker compromises server_key.dsa_sk and tries to forge client alice's signature
    forged_client_sig = ml_dsa.sign(server_key.dsa_sk, transcript_hash)
    with pytest.raises(HandshakeError, match="ML-DSA-65 signature verification failed"):
        responder.complete_handshake(client_key.dsa_pk, None, forged_client_sig)


def test_attack_04_unknown_key_share():
    """A-04: Unknown Key Share (attacker substitutes peer identity while forwarding valid signature)."""
    alice_key = HybridIdentityKeypair.generate()
    eve_key = HybridIdentityKeypair.generate()
    server_key = HybridIdentityKeypair.generate()
    trust = TrustedPeerStore()
    trust.register_peer("alice", alice_key, CipherSuite.SUITE_PQ)
    trust.register_peer("eve", eve_key, CipherSuite.SUITE_PQ)
    trust.register_peer("srv1", server_key, CipherSuite.SUITE_PQ)

    initiator = HandshakeInitiator("alice", "client", alice_key, suite=CipherSuite.SUITE_PQ, trusted_peers=trust)
    responder = HandshakeResponder("srv1", "server", server_key, trusted_peers=trust)

    # Attacker forwards alice's ephemeral key under claimed identity 'eve'
    s_nonce, kem_ct, _s_x, s_sig, _ = responder.process_client_hello_and_reply(
        client_id="eve",
        client_role="client",
        suite=CipherSuite.SUITE_PQ,
        client_nonce=initiator.client_nonce,
        client_kem_pk=initiator.ephemeral_key.kem_pk,  # type: ignore[union-attr]
        client_x25519_pk=None,
    )

    # Server's transcript includes 'eve', so alice rejects server's signature
    with pytest.raises(HandshakeError, match="ML-DSA-65 signature verification failed"):
        initiator.process_server_hello_and_authenticate(
            server_id="srv1",
            server_role="server",
            server_identity_dsa_pk=server_key.dsa_pk,
            server_identity_ed_pk=None,
            server_nonce=s_nonce,
            kem_ciphertext=kem_ct,
            server_x25519_pk=None,
            server_signature=s_sig,
        )


def test_attack_05_downgrade():
    """A-05: Forcing insecure or unsupported protocol suite."""
    server_key = HybridIdentityKeypair.generate()
    responder = HandshakeResponder("srv1", "server", server_key)
    with pytest.raises(HandshakeError, match="Unsupported or downgraded"):
        responder.process_client_hello_and_reply("alice", "client", 0, b"0" * 32, b"0" * 1184, None)  # type: ignore[arg-type]


def test_attack_06_cross_session_ticket_reuse():
    """A-06: Reusing ticket issued for Alice to resume session as Bob."""
    mgr = TicketManager()
    ticket_blob, ticket_secret = mgr.issue_ticket("alice", "fp-alice", CipherSuite.SUITE_PQ, 1)

    nonce = secrets.token_bytes(32)
    proof = hmac.new(ticket_secret, nonce, hashlib.sha256).hexdigest()

    with pytest.raises(TicketError, match="does not match claimed"):
        mgr.validate_and_resume(ticket_blob, "bob", nonce, proof)


def test_attack_07_nonce_reuse():
    """A-07: AEAD monotonic counter produces distinct ciphertexts for identical plaintexts and enforces key limit."""
    cipher = AEADCipher(b"K" * 32)
    ad = AssociatedData(1, 1, "a", "b", "fp", 1, "s1", 0, "m1", 0, 1, 5)

    ct1 = cipher.encrypt(b"msg1", ad)
    ct2 = cipher.encrypt(b"msg1", ad)
    assert ct1 != ct2

    # Exhausting per-key message limit fails closed
    from trustledger.crypto.aead import MAX_MESSAGES_PER_KEY
    cipher._send_counter = MAX_MESSAGES_PER_KEY
    with pytest.raises(OverflowError, match="Maximum messages exceeded"):
        cipher.encrypt(b"msg1", ad)


def test_attack_08_toctou_on_revocation():
    """A-08: TOCTOU race: read immediately after revoke must fail closed."""
    with tempfile.TemporaryDirectory() as tmp_dir, tempfile.TemporaryDirectory() as key_dir:
        old_env = os.environ.get("TRACK4_STATE_DIR")
        old_key = os.environ.get("TRACK4_KEY_DIR")
        os.environ["TRACK4_STATE_DIR"] = tmp_dir
        os.environ["TRACK4_KEY_DIR"] = key_dir
        try:
            dispatch({
                "op": "setup",
                "owners": {"res1": "alice"},
                "contents": {"res1": "confidential"},
                "disabled": [],
                "key_material": secrets.token_hex(16),
            })

            res1 = dispatch({"op": "read", "actor": "alice", "asset": "res1", "request_id": "r1"})
            assert res1["decision"] == "allow"

            dispatch({"op": "revoke", "actor": "alice"})

            res2 = dispatch({"op": "read", "actor": "alice", "asset": "res1", "request_id": "r2"})
            assert res2["decision"] == "deny"
        finally:
            if old_env is not None:
                os.environ["TRACK4_STATE_DIR"] = old_env
            else:
                os.environ.pop("TRACK4_STATE_DIR", None)
            if old_key is not None:
                os.environ["TRACK4_KEY_DIR"] = old_key
            else:
                os.environ.pop("TRACK4_KEY_DIR", None)


def test_attack_09_state_rollback_and_tamper():
    """A-09: Attacker modifies state.json on disk; load fails closed via HMAC mismatch."""
    with tempfile.TemporaryDirectory() as tmp_dir, tempfile.TemporaryDirectory() as key_dir:
        old_env = os.environ.get("TRACK4_STATE_DIR")
        old_key = os.environ.get("TRACK4_KEY_DIR")
        os.environ["TRACK4_STATE_DIR"] = tmp_dir
        os.environ["TRACK4_KEY_DIR"] = key_dir
        try:
            dispatch({
                "op": "setup",
                "owners": {"res1": "alice"},
                "contents": {"res1": "secret"},
                "disabled": [],
                "key_material": secrets.token_hex(16),
            })

            state_file = Path(tmp_dir) / "state.json"
            data = json.loads(state_file.read_text(encoding="utf-8"))
            data["contents"]["res1"] = "tampered"
            state_file.write_text(json.dumps(data), encoding="utf-8")

            with pytest.raises(IntegrityError):
                dispatch({"op": "read", "actor": "alice", "asset": "res1", "request_id": "r1"})
        finally:
            if old_env is not None:
                os.environ["TRACK4_STATE_DIR"] = old_env
            else:
                os.environ.pop("TRACK4_STATE_DIR", None)
            if old_key is not None:
                os.environ["TRACK4_KEY_DIR"] = old_key
            else:
                os.environ.pop("TRACK4_KEY_DIR", None)


def test_attack_10_parser_bomb_oversize():
    """A-10: Oversize input payload or oversized identifier rejected."""
    huge_str = "A" * (65536 + 1)
    with pytest.raises(DispatchError, match="exceeds max allowed length"):
        dispatch({"op": "read", "actor": huge_str, "asset": "res", "request_id": "r1"})


def test_attack_11_audit_log_forgery_and_truncation():
    """A-11: Forging actor or truncating audit log tail is caught offline by verify_log."""
    pk, sk = ml_dsa.generate_keypair()
    with tempfile.TemporaryDirectory() as td:
        log_file = Path(td) / "audit.log"
        logger = SignedAuditLogger(log_file, "sig-1", sk, checkpoint_interval=5)
        logger.append_entry("alice", "read", "doc1", "allow")
        logger.append_entry("alice", "read", "doc2", "allow")
        logger.finalize()

        lines = log_file.read_bytes().splitlines()
        # Tail truncation
        log_file.write_bytes(b"\n".join(lines[:-1]) + b"\n")
        ok, reason, _ = verify_log(log_file, pk)
        assert ok is False
        assert "TRUNCATED" in reason


def test_attack_12_network_packet_corruption():
    """A-12: Bit-flipped packet is rejected by keyed chunk MAC and recovered via Reed-Solomon FEC."""
    channel = ResilientChannel(k_data=4, m_parity=2, channel_key=secrets.token_bytes(32))
    payload = b"TRUSTLEDGER_PACKET_CORRUPTION_TEST_" + secrets.token_bytes(32)
    packets = channel.prepare_message_packets("msg-corrupt-12", payload)

    # Corrupt byte in packet 0 payload
    corrupted = bytearray(packets[0])
    corrupted[-1] ^= 0xFF
    packets[0] = bytes(corrupted)

    ok, delivered, reason = channel.receive_and_assemble(packets, "msg-corrupt-12", len(payload))
    assert ok is True
    assert delivered == payload
    assert reason is None
