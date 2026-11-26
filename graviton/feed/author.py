"""In-memory admin feed authoring for signed, hash-chained policy entries."""
from __future__ import annotations

import time
from typing import Callable

from graviton.crypto.signatures import sign_message
from graviton.feed.entries import (
    FEED_FORMAT_VERSION,
    FEED_SIGN_DOMAIN,
    ZERO_HASH,
    EntryType,
    FeedEntry,
    compute_entry_hash,
    encode_entry_body,
    pack_signed_entry,
)


class FeedAuthor:
    """Signs policy feed entries with an in-memory admin ML-DSA-65 secret key."""

    def __init__(
        self,
        feed_id: str,
        admin_secret_key: bytes,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self.feed_id = feed_id
        self._admin_secret_key = bytes(admin_secret_key)
        self._clock = clock or (lambda: int(time.time()))
        self.epoch = 0
        self.last_hash = ZERO_HASH

    def _emit(self, entry_type: EntryType, **kwargs) -> bytes:
        next_epoch = self.epoch + 1
        prev_hash = ZERO_HASH if next_epoch == 1 else self.last_hash
        entry = FeedEntry(
            version=FEED_FORMAT_VERSION,
            entry_type=entry_type,
            feed_id=self.feed_id,
            epoch=next_epoch,
            prev_hash=prev_hash,
            issued_at=int(self._clock()),
            **kwargs,
        )
        body = encode_entry_body(entry)
        signature = sign_message(self._admin_secret_key, body, domain=FEED_SIGN_DOMAIN)
        serialized = pack_signed_entry(body, signature)
        self.epoch = next_epoch
        self.last_hash = compute_entry_hash(serialized)
        return serialized

    def genesis(self) -> bytes:
        if self.epoch != 0:
            raise ValueError("Genesis can only be emitted at epoch 0")
        return self._emit(EntryType.GENESIS)

    def register_key(
        self,
        actor: str,
        device_id: str,
        public_key: bytes,
        *,
        key_version: int = 1,
    ) -> bytes:
        if self.epoch < 1:
            raise ValueError("Must emit genesis before registering keys")
        return self._emit(
            EntryType.REGISTER_KEY,
            actor=actor,
            device_id=device_id,
            key_version=key_version,
            public_key=bytes(public_key),
        )

    def rotate_key(
        self,
        actor: str,
        device_id: str,
        new_version: int,
        new_public_key: bytes,
        cutoff_epoch: int,
    ) -> bytes:
        if self.epoch < 1:
            raise ValueError("Must emit genesis before rotating keys")
        return self._emit(
            EntryType.ROTATE_KEY,
            actor=actor,
            device_id=device_id,
            key_version=new_version,
            public_key=bytes(new_public_key),
            cutoff_epoch=cutoff_epoch,
        )

    def revoke_device(self, actor: str, device_id: str) -> bytes:
        if self.epoch < 1:
            raise ValueError("Must emit genesis before revoking")
        return self._emit(EntryType.REVOKE_DEVICE, actor=actor, device_id=device_id)

    def revoke_actor(self, actor: str) -> bytes:
        if self.epoch < 1:
            raise ValueError("Must emit genesis before revoking")
        return self._emit(EntryType.REVOKE_ACTOR, actor=actor)

    def head(self) -> bytes:
        if self.epoch < 1:
            raise ValueError("Must emit genesis before head")
        return self._emit(EntryType.HEAD)
