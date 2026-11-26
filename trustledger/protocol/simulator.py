"""Deterministic seeded network simulator for packet loss, reordering, and corruption."""
import random
from typing import NamedTuple


class SimulatedPacket(NamedTuple):
    packet_id: int
    data: bytes


class NetworkSimulator:
    """Deterministic network impairment simulator."""

    def __init__(
        self,
        seed: int = 42,
        loss_rate: float = 0.05,
        reorder_prob: float = 0.10,
        duplicate_prob: float = 0.05,
        corrupt_prob: float = 0.02,
    ):
        self.rng = random.Random(seed)  # nosec B311 - deterministic seeded PRNG for simulation only
        self.loss_rate = loss_rate
        self.reorder_prob = reorder_prob
        self.duplicate_prob = duplicate_prob
        self.corrupt_prob = corrupt_prob

    def transmit(self, packets: list[bytes]) -> list[bytes]:
        """Apply deterministic loss, duplication, corruption, and reordering."""
        output: list[bytes] = []

        for p in packets:
            # 1. Packet loss
            if self.rng.random() < self.loss_rate:
                continue

            # 2. Corruption (bit flip)
            data = bytearray(p)
            if self.rng.random() < self.corrupt_prob and len(data) > 0:
                pos = self.rng.randint(0, len(data) - 1)
                data[pos] ^= 1 << self.rng.randint(0, 7)

            processed = bytes(data)
            output.append(processed)

            # 3. Duplication
            if self.rng.random() < self.duplicate_prob:
                output.append(processed)

        # 4. Reordering
        if len(output) > 1 and self.rng.random() < self.reorder_prob:
            i = self.rng.randint(0, len(output) - 2)
            output[i], output[i + 1] = output[i + 1], output[i]

        return output
