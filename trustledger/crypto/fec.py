"""Payload chunking and Reed-Solomon Forward Error Correction (FEC)."""

import reedsolo

CHUNK_SIZE = 16384  # 16 KiB chunk payload


class FECError(ValueError):
    """Raised on FEC encoding or decoding failure."""


class ChunkFEC:
    """Splits payload into chunks and computes/recovers Reed-Solomon parity."""

    def __init__(self, data_chunk_count: int = 4, parity_chunk_count: int = 2):
        self.k = data_chunk_count
        self.m = parity_chunk_count
        self.total = self.k + self.m
        self.rs = reedsolo.RSCodec(parity_chunk_count)

    def chunk_payload(self, payload: bytes) -> list[bytes]:
        """Split arbitrary payload into CHUNK_SIZE pieces."""
        if not payload:
            return [b""]
        return [payload[i : i + CHUNK_SIZE] for i in range(0, len(payload), CHUNK_SIZE)]

    def encode_group(self, data_chunks: list[bytes]) -> list[bytes]:
        """Add m parity chunks to k data chunks via byte-slice Reed-Solomon coding."""
        if len(data_chunks) != self.k:
            raise FECError(f"Expected {self.k} data chunks, got {len(data_chunks)}")

        max_len = max(len(c) for c in data_chunks)
        padded = [c.ljust(max_len, b"\x00") for c in data_chunks]
        parity_buffers = [bytearray(max_len) for _ in range(self.m)]

        for offset in range(max_len):
            symbols = bytes(padded[i][offset] for i in range(self.k))
            encoded = self.rs.encode(symbols)
            for p_idx in range(self.m):
                parity_buffers[p_idx][offset] = encoded[self.k + p_idx]

        return [bytes(p) for p in parity_buffers]

    def decode_group(
        self,
        received_chunks: dict[int, bytes],
        lengths: list[int],
    ) -> list[bytes]:
        """Reconstruct original k data chunks given available chunks and their original lengths."""
        if all(i in received_chunks for i in range(self.k)):
            return [received_chunks[i][: lengths[i]] for i in range(self.k)]

        if len(received_chunks) < self.k:
            raise FECError(f"Insufficient chunks to decode: have {len(received_chunks)}, need {self.k}")

        max_len = max(max(len(c) for c in received_chunks.values()), max(lengths))
        padded_map = {idx: chunk.ljust(max_len, b"\x00") for idx, chunk in received_chunks.items()}
        missing_indices = [idx for idx in range(self.total) if idx not in received_chunks]

        if len(missing_indices) > self.m:
            raise FECError(f"Too many missing chunks ({len(missing_indices)} > {self.m})")

        recovered_data = [bytearray(max_len) for _ in range(self.k)]

        for offset in range(max_len):
            block = bytearray(self.total)
            for idx, chunk in padded_map.items():
                block[idx] = chunk[offset]

            try:
                dec, _, _ = self.rs.decode(block, erase_pos=missing_indices)
                for i in range(self.k):
                    recovered_data[i][offset] = dec[i]
            except reedsolo.ReedSolomonError as err:
                raise FECError("Reed-Solomon erasure decoding failed") from err

        return [bytes(recovered_data[i][: lengths[i]]) for i in range(self.k)]
