"""Hypothesis fuzzing for frame codecs, parsers, and deserializers."""
from hypothesis import given, settings, strategies as st

from trustledger.codec.frame import CodecError, decode_bytes, decode_string, encode_bytes, encode_string, pack_frame, unpack_frame


@settings(max_examples=100)
@given(st.binary(max_size=50000))
def test_fuzz_encode_decode_bytes_roundtrip(data):
    encoded = encode_bytes(data)
    decoded, offset = decode_bytes(encoded, 0)
    assert decoded == data
    assert offset == len(encoded)


@settings(max_examples=100)
@given(st.text(max_size=10000))
def test_fuzz_encode_decode_string_roundtrip(s):
    encoded = encode_string(s)
    decoded, offset = decode_string(encoded, 0)
    assert decoded == s
    assert offset == len(encoded)


@settings(max_examples=100)
@given(st.integers(min_value=0, max_value=255), st.binary(max_size=20000))
def test_fuzz_pack_unpack_frame(frame_type, payload):
    packed = pack_frame(frame_type, payload)
    f_type, p_load = unpack_frame(packed)
    assert f_type == frame_type
    assert p_load == payload


@settings(max_examples=100)
@given(st.binary(max_size=1000))
def test_fuzz_arbitrary_bytes_unpack_safe(corrupted):
    """Arbitrary bytes never crash with unhandled exceptions (must raise CodecError or unpack safely)."""
    try:
        unpack_frame(corrupted)
    except CodecError:
        pass  # Expected safe rejection
