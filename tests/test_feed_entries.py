"""Tests for graviton.feed entries, FeedAuthor, and verify_entry (Step 2)."""
from __future__ import annotations

import unittest

from graviton.crypto.signatures import generate_signing_keypair, sign_message
from graviton.feed.author import FeedAuthor
from graviton.feed.encoding import MAX_ENTRY_LEN
from graviton.feed.entries import (
    ZERO_HASH,
    EntryType,
    compute_entry_hash,
    decode_entry_body,
    encode_entry_body,
    pack_signed_entry,
    unpack_signed_entry,
)
from graviton.feed.verify import FeedContinuityError, FeedVerificationError, verify_entry


class TestFeedEntries(unittest.TestCase):
    def setUp(self) -> None:
        self.admin_pk, self.admin_sk = generate_signing_keypair()
        self.other_pk, self.other_sk = generate_signing_keypair()
        self.now = 1_700_000_000
        self.author = FeedAuthor("org-feed-1", self.admin_sk, clock=lambda: self.now)

    def test_round_trip_all_entry_types_and_canonical_form(self) -> None:
        dev_pk1, _ = generate_signing_keypair()
        dev_pk2, _ = generate_signing_keypair()

        raw_entries = [
            (self.author.genesis(), EntryType.GENESIS),
            (self.author.register_key("alice", "dev-1", dev_pk1), EntryType.REGISTER_KEY),
            (self.author.rotate_key("alice", "dev-1", 2, dev_pk2, cutoff_epoch=5), EntryType.ROTATE_KEY),
            (self.author.revoke_device("alice", "dev-1"), EntryType.REVOKE_DEVICE),
            (self.author.revoke_actor("alice"), EntryType.REVOKE_ACTOR),
            (self.author.head(), EntryType.HEAD),
        ]

        prev_hash = ZERO_HASH
        for epoch, (raw, expected_type) in enumerate(raw_entries, start=1):
            entry = verify_entry(raw, self.admin_pk, "org-feed-1", epoch, prev_hash)
            self.assertEqual(entry.entry_type, expected_type)
            body, _ = unpack_signed_entry(raw)
            self.assertEqual(encode_entry_body(decode_entry_body(body)), body)
            prev_hash = compute_entry_hash(raw)

    def test_signature_and_domain_and_feed_id_failures(self) -> None:
        g = self.author.genesis()
        body, sig = unpack_signed_entry(g)

        # Wrong admin key
        with self.assertRaises(FeedVerificationError):
            verify_entry(g, self.other_pk, "org-feed-1", 1, ZERO_HASH)

        # Wrong feed_id
        with self.assertRaises(FeedVerificationError):
            verify_entry(g, self.admin_pk, "wrong-feed", 1, ZERO_HASH)

        # Flipped bit in body
        bad_body = bytes([body[0] ^ 0x01]) + body[1:]
        with self.assertRaises(FeedVerificationError):
            verify_entry(pack_signed_entry(bad_body, sig), self.admin_pk, "org-feed-1", 1, ZERO_HASH)

        # Flipped bit in signature
        bad_sig = bytes([sig[0] ^ 0x01]) + sig[1:]
        with self.assertRaises(FeedVerificationError):
            verify_entry(pack_signed_entry(body, bad_sig), self.admin_pk, "org-feed-1", 1, ZERO_HASH)

        # Signature with "request" domain label presented as feed entry
        req_sig = sign_message(self.admin_sk, body, domain=b"request")
        with self.assertRaises(FeedVerificationError):
            verify_entry(pack_signed_entry(body, req_sig), self.admin_pk, "org-feed-1", 1, ZERO_HASH)

    def test_continuity_and_fork_and_oversized(self) -> None:
        e1 = self.author.genesis()
        h1 = compute_entry_hash(e1)
        e2 = self.author.head()
        h2 = compute_entry_hash(e2)
        e3 = self.author.head()

        # Epoch gap
        with self.assertRaises(FeedContinuityError):
            verify_entry(e3, self.admin_pk, "org-feed-1", 2, h1)

        # Repeated epoch
        with self.assertRaises(FeedContinuityError):
            verify_entry(e2, self.admin_pk, "org-feed-1", 3, h2)

        # Wrong prev_hash
        with self.assertRaises(FeedContinuityError):
            verify_entry(e2, self.admin_pk, "org-feed-1", 2, ZERO_HASH)

        # Non-genesis first entry
        with self.assertRaises(FeedVerificationError):
            verify_entry(e2, self.admin_pk, "org-feed-1", 1, ZERO_HASH)

        # Second genesis
        other_author = FeedAuthor("org-feed-1", self.admin_sk, clock=lambda: self.now)
        second_g = other_author.genesis()
        with self.assertRaises(FeedVerificationError):
            verify_entry(second_g, self.admin_pk, "org-feed-1", 2, h1)

        # Fork at epoch 2 (different entry signed at epoch 2)
        fork_author = FeedAuthor("org-feed-1", self.admin_sk, clock=lambda: self.now + 99)
        fork_e1 = fork_author.genesis()
        self.assertNotEqual(fork_e1, e1)

        # Oversized entry rejected
        with self.assertRaises(FeedVerificationError):
            verify_entry(b"\x00" * (MAX_ENTRY_LEN + 1), self.admin_pk, "org-feed-1", 1, ZERO_HASH)


if __name__ == "__main__":
    unittest.main()
