"""Bit-level pack/unpack primitives — the foundation under every storage codec."""

import pytest

from celatim.channel.bits import BitReader, BitWriter


def test_write_then_byte_align():
    w = BitWriter()
    w.write(0b101, 3)
    w.write(0b11, 2)
    assert w.nbits == 5
    # 10111 -> zero-padded MSB-first to 10111000 = 0xB8
    assert w.getvalue() == bytes([0xB8])


def test_empty_writer():
    w = BitWriter()
    assert w.nbits == 0
    assert w.getvalue() == b""


def test_write_rejects_overwide_value():
    w = BitWriter()
    with pytest.raises(ValueError):
        w.write(0b100, 2)  # 4 does not fit in 2 bits


def test_read_msb_first():
    r = BitReader(bytes([0xB8]))  # 10111000
    assert r.read(3) == 0b101
    assert r.read(2) == 0b11
    assert r.remaining == 3


def test_read_past_end_raises():
    r = BitReader(bytes([0xFF]))
    r.read(8)
    with pytest.raises(EOFError):
        r.read(1)


@pytest.mark.parametrize(
    "symbols",
    [
        [(1, 1), (0, 1), (5, 3), (255, 8)],
        [(0xABCD, 16), (0x7, 3), (0x1, 1)],
        [(0, 4)],
    ],
)
def test_round_trip(symbols):
    w = BitWriter()
    for value, width in symbols:
        w.write(value, width)
    r = BitReader(w.getvalue())
    for value, width in symbols:
        assert r.read(width) == value


def test_zero_width_is_noop():
    w = BitWriter()
    w.write(0, 0)
    assert w.nbits == 0
    r = BitReader(b"")
    assert r.read(0) == 0
