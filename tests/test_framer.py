"""Framer: a whole payload <-> a stream of field symbols across carrier units."""

import pytest

from celatim.channel.codec import FixedWidthCodec, VariableLengthCodec
from celatim.channel.framer import Framer


@pytest.mark.parametrize("width", [1, 3, 4, 8, 13, 16])
@pytest.mark.parametrize("payload", [b"", b"\x00", b"hi", b"covert!", bytes(range(20))])
def test_fixed_width_payload_roundtrip(width, payload):
    framer = Framer(FixedWidthCodec(width))
    symbols = framer.encode(payload)
    assert framer.decode(symbols) == payload


@pytest.mark.parametrize("length", [1, 2, 7])
@pytest.mark.parametrize("payload", [b"", b"x", b"a longer covert message"])
def test_variable_length_payload_roundtrip(length, payload):
    framer = Framer(VariableLengthCodec(length))
    assert framer.decode(framer.encode(payload)) == payload


def test_symbol_count_matches_capacity():
    # 'hi' (2 bytes) + 2-byte length prefix = 32 bits; 4-bit field -> 8 symbols.
    framer = Framer(FixedWidthCodec(4))
    assert len(framer.encode(b"hi")) == (2 + 2) * 8 // 4
    assert framer.encoded_symbol_count(len(b"hi")) == 8


def test_symbols_are_in_field_range():
    framer = Framer(FixedWidthCodec(4))
    assert all(0 <= s < 16 for s in framer.encode(b"payload"))


def test_rejects_oversized_payload():
    framer = Framer(FixedWidthCodec(8))
    with pytest.raises(ValueError):
        framer.encode(b"x" * 70000)  # exceeds the 16-bit length prefix


def test_decode_one_reads_concatenated_frames_incrementally():
    framer = Framer(FixedWidthCodec(5))
    first = framer.encode(b"first")
    second = framer.encode(b"second")
    stream = first + second

    payload, consumed = framer.decode_one(stream)
    payload2, consumed2 = framer.decode_one(stream, consumed)

    assert payload == b"first"
    assert consumed == len(first)
    assert payload2 == b"second"
    assert consumed + consumed2 == len(stream)


def test_decode_one_rejects_truncated_frame():
    framer = Framer(FixedWidthCodec(8))
    symbols = framer.encode(b"payload")

    with pytest.raises(ValueError, match="truncated"):
        framer.decode_one(symbols[:-1])
