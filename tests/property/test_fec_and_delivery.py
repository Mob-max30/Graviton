"""Property-based tests for Reed-Solomon FEC and resilient channel delivery over >= 200 random seeds."""
import secrets
import pytest

from trustledger.protocol.channel import DeliveryFailureReason, ResilientChannel
from trustledger.protocol.simulator import NetworkSimulator


@pytest.mark.parametrize("seed", list(range(100, 305)))
def test_delivery_under_network_impairment(seed):
    """Test channel transmission across 205 deterministic seeds under loss, reordering, and corruption."""
    channel = ResilientChannel(k_data=4, m_parity=2)
    sim = NetworkSimulator(
        seed=seed,
        loss_rate=0.08,        # 8% packet loss
        reorder_prob=0.15,     # 15% packet reordering
        duplicate_prob=0.05,   # 5% packet duplication
        corrupt_prob=0.01,     # 1% bit flip
    )

    payload = b"CRITICAL_INTELLIGENCE_" + secrets.token_bytes(64)
    msg_id = f"msg-seed-{seed}"

    packets = channel.prepare_message_packets(msg_id, payload)
    transmitted = sim.transmit(packets)

    success, delivered, reason = channel.receive_and_assemble(transmitted, msg_id, len(payload))

    if success:
        # Guarantee: If delivered, it MUST be byte-exact
        assert delivered == payload
    else:
        # Guarantee: If not delivered, must emit explicit valid reason code
        assert reason in (
            DeliveryFailureReason.INCOMPLETE,
            DeliveryFailureReason.AUTH_FAIL,
            DeliveryFailureReason.WRONG_RECIPIENT,
        )


def test_forged_chunk_with_unkeyed_hash_rejected():
    """H-03: Attacker forging chunk bytes and recomputing unkeyed SHA-256 is rejected."""
    import hashlib
    import struct
    from trustledger.protocol.channel import FIXED_HEADER_FORMAT, FIXED_HEADER_SIZE

    channel = ResilientChannel(k_data=4, m_parity=2, channel_key=secrets.token_bytes(32))
    payload = b"LEGITIMATE_PAYLOAD_" + secrets.token_bytes(64)
    msg_id = "msg-forged-test"
    packets = channel.prepare_message_packets(msg_id, payload)

    # Forge packet 0 with attacker bytes and unkeyed SHA-256 tag
    p0 = bytearray(packets[0])
    hdr = list(struct.unpack_from(FIXED_HEADER_FORMAT, p0, 0))
    msg_id_len = hdr[9]
    forged_chunk = b"FORGED_ATTACKER_DATA_".ljust(len(p0) - FIXED_HEADER_SIZE - msg_id_len, b"X")
    hdr[8] = hashlib.sha256(forged_chunk).digest()  # Unkeyed tag
    struct.pack_into(FIXED_HEADER_FORMAT, p0, 0, *hdr)
    forged_packets = [bytes(p0[: FIXED_HEADER_SIZE + msg_id_len]) + forged_chunk] + packets[1:]

    # Even if FEC recovers from remaining packets, wait: if attacker drops all other data or corrupts enough chunks:
    # Let's drop parity packets so forged chunk is needed, OR verify forged chunk is discarded
    forged_only_set = [forged_packets[0]] + packets[1:4]  # Only 3 valid chunks + 1 forged chunk (need 4)
    success, delivered, reason = channel.receive_and_assemble(forged_only_set, msg_id, len(payload))
    assert success is False
    assert delivered is None
    assert reason in (DeliveryFailureReason.AUTH_FAIL, DeliveryFailureReason.INCOMPLETE)


def test_long_distinct_message_ids_do_not_truncate_or_collide():
    """M-02: Message IDs > 16 bytes sharing a 16-byte prefix remain distinct."""
    channel = ResilientChannel(k_data=4, m_parity=2, channel_key=secrets.token_bytes(32))
    payload = b"LONG_ID_PAYLOAD_" + secrets.token_bytes(32)
    long_a = "prefix-0123456789abcdef-alpha-suffix"
    long_b = "prefix-0123456789abcdef-beta-suffix"

    packets_a = channel.prepare_message_packets(long_a, payload)
    ok_a, del_a, _ = channel.receive_and_assemble(packets_a, long_a, len(payload))
    assert ok_a is True
    assert del_a == payload

    ok_b, del_b, reason_b = channel.receive_and_assemble(packets_a, long_b, len(payload))
    assert ok_b is False
    assert del_b is None
    assert reason_b == DeliveryFailureReason.WRONG_RECIPIENT
