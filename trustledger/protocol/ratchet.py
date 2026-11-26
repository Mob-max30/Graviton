"""Symmetric per-message ratcheting session with pre-auth safety, out-of-order support, and replay binding."""
from collections import OrderedDict
import hashlib
import hmac
import os
from typing import Dict, Optional, Set, Tuple

from trustledger.crypto.aead import AEADCipher, AssociatedData
from trustledger.crypto.suites import CipherSuite

DEFAULT_REPLAY_WINDOW_SIZE = int(os.environ.get("TRUSTLEDGER_REPLAY_WINDOW", "128"))


class RatchetError(ValueError):
    """Raised on ratcheting, replay, or decryption authentication errors."""


class SymmetricRatchetSession:
    """Manages forward-secure per-message symmetric key evolution, reordering, and replay prevention."""

    def __init__(
        self,
        session_id: str,
        suite: CipherSuite,
        local_id: str,
        peer_id: str,
        peer_fingerprint: str,
        send_chain_key: bytes,
        recv_chain_key: bytes,
        peer_epoch: int = 1,
        max_skipped_keys: int = DEFAULT_REPLAY_WINDOW_SIZE,
    ):
        self.session_id = session_id
        self.suite = suite
        self.local_id = local_id
        self.peer_id = peer_id
        self.peer_fingerprint = peer_fingerprint
        self.peer_epoch = peer_epoch
        self.max_skipped_keys = max(1, max_skipped_keys)

        self._send_chain = bytearray(send_chain_key)
        self._recv_chain = bytearray(recv_chain_key)

        self.send_seq = 0
        self._recv_next_seq = 0
        self._skipped_keys: Dict[int, bytes] = {}
        self._seen_sequences: Set[int] = set()
        self._seen_message_ids: OrderedDict[str, None] = OrderedDict()
        self._max_seen_ids = 5000

    def _step_chain_pure(self, chain: bytes, label: bytes) -> Tuple[bytes, bytes]:
        """Pure non-mutating chain step returning (msg_key, next_chain)."""
        msg_key = hmac.new(chain, label + b":msg", hashlib.sha256).digest()
        next_chain = hmac.new(chain, label + b":step", hashlib.sha256).digest()
        return msg_key, next_chain

    def _peek_recv_key_for_seq(
        self, sequence_number: int
    ) -> Tuple[bytes, bytes, int, Dict[int, bytes], bool]:
        """Compute key for sequence_number WITHOUT mutating instance state.

        Returns (msg_key, new_chain_bytes, new_next_seq, new_skipped_additions, popped_from_skipped).
        """
        if sequence_number < 0:
            raise RatchetError(f"Invalid negative sequence number: {sequence_number}")

        if sequence_number in self._seen_sequences:
            raise RatchetError(f"Replay detected: sequence {sequence_number} already received")

        if sequence_number < self._recv_next_seq:
            msg_key = self._skipped_keys.get(sequence_number)
            if msg_key is None:
                raise RatchetError(f"Replay detected: sequence {sequence_number} outside reorder window")
            return msg_key, bytes(self._recv_chain), self._recv_next_seq, {}, True

        skip_count = sequence_number - self._recv_next_seq
        if skip_count > self.max_skipped_keys:
            raise RatchetError(f"Sequence jump {skip_count} exceeds max reorder window {self.max_skipped_keys}")

        temp_chain = bytes(self._recv_chain)
        temp_next = self._recv_next_seq
        additions: Dict[int, bytes] = {}

        while temp_next < sequence_number:
            skipped_key, temp_chain = self._step_chain_pure(temp_chain, b"send")
            additions[temp_next] = skipped_key
            temp_next += 1

        msg_key, temp_chain = self._step_chain_pure(temp_chain, b"send")
        temp_next += 1
        return msg_key, temp_chain, temp_next, additions, False

    def encrypt_message(
        self,
        plaintext: bytes,
        message_id: str,
        chunk_index: int = 0,
        chunk_count: int = 1,
        total_length: Optional[int] = None,
    ) -> bytes:
        """Derive per-message key, encrypt payload, and delete message key."""
        msg_key, next_chain = self._step_chain_pure(bytes(self._send_chain), b"send")
        self._send_chain[:] = next_chain
        cipher = AEADCipher(msg_key)

        ad = AssociatedData(
            protocol_version=1,
            suite_id=self.suite,
            sender_id=self.local_id,
            recipient_id=self.peer_id,
            recipient_key_fingerprint=self.peer_fingerprint,
            recipient_epoch=self.peer_epoch,
            session_id=self.session_id,
            sequence_number=self.send_seq,
            message_id=message_id,
            chunk_index=chunk_index,
            chunk_count=chunk_count,
            total_length=total_length if total_length is not None else len(plaintext),
        )

        ciphertext = cipher.encrypt(plaintext, ad)
        self.send_seq += 1

        del cipher
        del msg_key
        return ciphertext

    def decrypt_message(
        self,
        ciphertext: bytes,
        sequence_number: int,
        message_id: str,
        sender_id: str,
        recipient_id: str,
        recipient_fp: str,
        recipient_epoch: int,
        chunk_index: int = 0,
        chunk_count: int = 1,
        total_length: int = 0,
    ) -> bytes:
        """Verify recipient, guard against replay, decrypt, and ONLY commit ratchet state on success."""
        if recipient_id != self.local_id:
            raise RatchetError(f"Recipient mismatch: message meant for {recipient_id}, not {self.local_id}")
        if sender_id != self.peer_id:
            raise RatchetError(f"Sender mismatch: received from {sender_id}, expected {self.peer_id}")

        if message_id in self._seen_message_ids:
            raise RatchetError(f"Replay detected: duplicate message_id {message_id}")

        msg_key, new_chain, new_next_seq, additions, from_skipped = self._peek_recv_key_for_seq(sequence_number)
        cipher = AEADCipher(msg_key)

        ad = AssociatedData(
            protocol_version=1,
            suite_id=self.suite,
            sender_id=sender_id,
            recipient_id=recipient_id,
            recipient_key_fingerprint=recipient_fp,
            recipient_epoch=recipient_epoch,
            session_id=self.session_id,
            sequence_number=sequence_number,
            message_id=message_id,
            chunk_index=chunk_index,
            chunk_count=chunk_count,
            total_length=total_length,
        )

        try:
            plaintext = cipher.decrypt(ciphertext, 0, ad)
        finally:
            del cipher
            del msg_key

        # Commit ratchet state ONLY AFTER AEAD authentication succeeds
        if from_skipped:
            self._skipped_keys.pop(sequence_number, None)
        else:
            self._recv_chain[:] = new_chain
            self._recv_next_seq = new_next_seq
            for sk_seq, sk_key in additions.items():
                if len(self._skipped_keys) >= self.max_skipped_keys:
                    oldest_seq = min(self._skipped_keys)
                    self._skipped_keys.pop(oldest_seq, None)
                self._skipped_keys[sk_seq] = sk_key

        self._seen_sequences.add(sequence_number)
        if len(self._seen_sequences) > self.max_skipped_keys * 4:
            min_keep = self._recv_next_seq - self.max_skipped_keys
            self._seen_sequences = {s for s in self._seen_sequences if s >= min_keep}

        if len(self._seen_message_ids) >= self._max_seen_ids:
            self._seen_message_ids.popitem(last=False)
        self._seen_message_ids[message_id] = None

        return plaintext
