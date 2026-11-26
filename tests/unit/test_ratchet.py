"""Unit tests for Symmetric Ratchet, AD sensitivity, Recipient Binding, and Replay Protection."""
import pytest

from trustledger.crypto.suites import CipherSuite
from trustledger.protocol.ratchet import RatchetError, SymmetricRatchetSession


def test_ratchet_message_exchange():
    """Normal message encryption and decryption under symmetric ratchet."""
    alice_to_bob = b"A" * 32
    bob_to_alice = b"B" * 32

    alice_session = SymmetricRatchetSession(
        session_id="sess-001",
        suite=CipherSuite.SUITE_HYBRID,
        local_id="alice",
        peer_id="bob",
        peer_fingerprint="fp-bob",
        send_chain_key=alice_to_bob,
        recv_chain_key=bob_to_alice,
        peer_epoch=1,
    )

    bob_session = SymmetricRatchetSession(
        session_id="sess-001",
        suite=CipherSuite.SUITE_HYBRID,
        local_id="bob",
        peer_id="alice",
        peer_fingerprint="fp-alice",
        send_chain_key=bob_to_alice,
        recv_chain_key=alice_to_bob,
        peer_epoch=1,
    )

    payload = b"Top secret operational intelligence"
    ct = alice_session.encrypt_message(payload, message_id="msg-1")

    pt = bob_session.decrypt_message(
        ciphertext=ct,
        sequence_number=0,
        message_id="msg-1",
        sender_id="alice",
        recipient_id="bob",
        recipient_fp="fp-bob",
        recipient_epoch=1,
        total_length=len(payload),
    )
    assert pt == payload


def test_associated_data_tamper_sensitivity():
    """Flipping any single AD field causes decryption authentication failure."""
    alice_to_bob = b"A" * 32
    bob_to_alice = b"B" * 32

    alice = SymmetricRatchetSession("s1", CipherSuite.SUITE_PQ, "alice", "bob", "fp-bob", alice_to_bob, bob_to_alice)
    bob = SymmetricRatchetSession("s1", CipherSuite.SUITE_PQ, "bob", "alice", "fp-alice", bob_to_alice, alice_to_bob)

    payload = b"Sensitive payload"
    ct = alice.encrypt_message(payload, message_id="m1")

    # 1. Flip recipient_id
    with pytest.raises(RatchetError, match="Recipient mismatch"):
        bob.decrypt_message(ct, 0, "m1", "alice", "charlie", "fp-bob", 1, total_length=len(payload))

    # 2. Flip sender_id
    with pytest.raises(RatchetError, match="Sender mismatch"):
        bob.decrypt_message(ct, 0, "m1", "eve", "bob", "fp-bob", 1, total_length=len(payload))

    # 3. Flip sequence number (AD tag mismatch)
    with pytest.raises(Exception):
        bob.decrypt_message(ct, 1, "m1", "alice", "bob", "fp-bob", 1, total_length=len(payload))


def test_replay_protection():
    """Replay of duplicate message or message outside replay window is rejected."""
    alice_to_bob = b"A" * 32
    bob_to_alice = b"B" * 32

    alice = SymmetricRatchetSession("s1", CipherSuite.SUITE_PQ, "alice", "bob", "fp-bob", alice_to_bob, bob_to_alice)
    bob = SymmetricRatchetSession("s1", CipherSuite.SUITE_PQ, "bob", "alice", "fp-alice", bob_to_alice, alice_to_bob)

    ct = alice.encrypt_message(b"Hello", message_id="m-dup")
    pt = bob.decrypt_message(ct, 0, "m-dup", "alice", "bob", "fp-bob", 1, total_length=5)
    assert pt == b"Hello"

    # Replay same message_id
    with pytest.raises(RatchetError, match="Replay detected"):
        bob.decrypt_message(ct, 0, "m-dup", "alice", "bob", "fp-bob", 1, total_length=5)


def test_out_of_order_delivery_within_window():
    """M-02: Messages delivered in order 0, 2, 1 all authenticate without corrupting chain."""
    alice_to_bob = b"A" * 32
    bob_to_alice = b"B" * 32

    alice = SymmetricRatchetSession("s1", CipherSuite.SUITE_PQ, "alice", "bob", "fp-bob", alice_to_bob, bob_to_alice)
    bob = SymmetricRatchetSession("s1", CipherSuite.SUITE_PQ, "bob", "alice", "fp-alice", bob_to_alice, alice_to_bob)

    ct0 = alice.encrypt_message(b"msg-0", message_id="id-0")
    ct1 = alice.encrypt_message(b"msg-1", message_id="id-1")
    ct2 = alice.encrypt_message(b"msg-2", message_id="id-2")

    # Deliver 0, then 2, then 1
    assert bob.decrypt_message(ct0, 0, "id-0", "alice", "bob", "fp-bob", 1, total_length=5) == b"msg-0"
    assert bob.decrypt_message(ct2, 2, "id-2", "alice", "bob", "fp-bob", 1, total_length=5) == b"msg-2"
    assert bob.decrypt_message(ct1, 1, "id-1", "alice", "bob", "fp-bob", 1, total_length=5) == b"msg-1"

    # Replaying seq 1 or seq 2 afterwards must still fail
    with pytest.raises(RatchetError, match="Replay detected"):
        bob.decrypt_message(ct1, 1, "id-1-dup", "alice", "bob", "fp-bob", 1, total_length=5)


def test_forged_packets_do_not_corrupt_ratchet_state():
    """Pre-auth safety: forged packets with valid/future sequence numbers do not advance or break ratchet."""
    alice_to_bob = b"A" * 32
    bob_to_alice = b"B" * 32

    alice = SymmetricRatchetSession("s1", CipherSuite.SUITE_PQ, "alice", "bob", "fp-bob", alice_to_bob, bob_to_alice)
    bob = SymmetricRatchetSession("s1", CipherSuite.SUITE_PQ, "bob", "alice", "fp-alice", bob_to_alice, alice_to_bob)

    ct0 = alice.encrypt_message(b"legit-0", message_id="legit-0")
    ct1 = alice.encrypt_message(b"legit-1", message_id="legit-1")

    # Attacker injects forged packet claiming future sequence 5 and current sequence 0
    for forged_seq, forged_id in [(5, "forged-5"), (0, "forged-0")]:
        with pytest.raises(ValueError, match="AEAD authentication failed"):
            bob.decrypt_message(b"forged-bytes" * 3, forged_seq, forged_id, "alice", "bob", "fp-bob", 1, total_length=7)

    # Legitimate messages 0 and 1 must still authenticate cleanly
    assert bob.decrypt_message(ct0, 0, "legit-0", "alice", "bob", "fp-bob", 1, total_length=7) == b"legit-0"
    assert bob.decrypt_message(ct1, 1, "legit-1", "alice", "bob", "fp-bob", 1, total_length=7) == b"legit-1"

