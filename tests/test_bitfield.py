"""MSB-first bit-field placement/extraction at a wire offset.

This is the protocol-agnostic core every located packet-class mechanism shares:
place covert bits at a ``FieldLocator`` (bit_offset/bit_width, MSB-first from a
header base) inside an otherwise-real PDU, and read them back. Pure stdlib, so it
is fully deterministic and independent of Scapy.
"""

from __future__ import annotations

import pytest

from celatim.pdu.bitfield import extract_bits, place_bits


def test_place_low_nibble_msb_first():
    # bit_offset 12, width 4 -> low nibble of byte 1 (the TCP reserved-bits layout).
    buf = place_bits(bytes(4), bit_offset=12, bit_width=4, value=0xA)
    assert buf == bytes([0x00, 0x0A, 0x00, 0x00])
    assert extract_bits(buf, bit_offset=12, bit_width=4) == 0xA


def test_place_high_nibble_msb_first():
    buf = place_bits(bytes(1), bit_offset=0, bit_width=4, value=0xF)
    assert buf == bytes([0xF0])
    assert extract_bits(buf, bit_offset=0, bit_width=4) == 0xF


def test_place_spans_two_bytes():
    buf = place_bits(bytes(2), bit_offset=4, bit_width=8, value=0xAB)
    assert buf == bytes([0x0A, 0xB0])
    assert extract_bits(buf, bit_offset=4, bit_width=8) == 0xAB


def test_place_single_bit():
    buf = place_bits(bytes(1), bit_offset=3, bit_width=1, value=1)
    assert buf == bytes([0b0001_0000])
    assert extract_bits(buf, bit_offset=3, bit_width=1) == 1


def test_neighboring_bytes_preserved():
    base = bytes([0xFF, 0xFF, 0xFF, 0xFF])
    buf = place_bits(base, bit_offset=12, bit_width=4, value=0x5)
    # only the targeted nibble changes; every other bit stays set.
    assert buf == bytes([0xFF, 0xF5, 0xFF, 0xFF])
    assert extract_bits(buf, bit_offset=12, bit_width=4) == 0x5


def test_wide_byte_aligned_field_roundtrip():
    base = bytes(16)
    value = int.from_bytes(b"covert!!", "big")
    buf = place_bits(base, bit_offset=32, bit_width=64, value=value)
    assert buf[4:12] == b"covert!!"
    assert extract_bits(buf, bit_offset=32, bit_width=64) == value


def test_value_too_large_raises():
    with pytest.raises(ValueError, match="does not fit"):
        place_bits(bytes(2), bit_offset=0, bit_width=4, value=0x10)


def test_field_exceeds_buffer_raises():
    with pytest.raises(ValueError, match="exceeds buffer"):
        place_bits(bytes(2), bit_offset=12, bit_width=8, value=0x1)
    with pytest.raises(ValueError, match="exceeds buffer"):
        extract_bits(bytes(2), bit_offset=12, bit_width=8)


def test_roundtrip_many_offsets():
    for bit_offset in range(0, 24):
        for bit_width in (1, 2, 3, 7, 8, 11, 16):
            buf_len = (bit_offset + bit_width + 7) // 8 + 1
            value = (1 << bit_width) - 1
            buf = place_bits(
                bytes(buf_len), bit_offset=bit_offset, bit_width=bit_width, value=value
            )
            assert extract_bits(buf, bit_offset=bit_offset, bit_width=bit_width) == value
