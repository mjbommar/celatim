"""Remaining application/format carriers built as real minimal protocol structures."""

from __future__ import annotations

from pathlib import Path

from celatim.catalog import load_mechanisms
from celatim.channel.codec import VariableLengthCodec
from celatim.channel.registry import codec_for
from celatim.pdu import struct_fields as s

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def test_supports_only_registered_rows():
    assert s.supports("http-tunnel")
    assert s.supports("http3-reserved-frame-types")
    assert not s.supports("tcp-reserved-bits")


def test_each_structure_roundtrips_in_real_protocol_layout():
    mechs = {m.id: m for m in load_mechanisms(DATA)}
    for mid in s._CARRIERS:
        mech = mechs[mid]
        assert mech.locator is not None
        width = mech.locator.bit_width
        assert s.is_bytes_symbol(mid) == isinstance(codec_for(mech), VariableLengthCodec)
        if s.is_bytes_symbol(mid):
            n = min(width // 8, 64)
            value: int | bytes = bytes((i * 5 + 1) % 256 for i in range(n))
        else:
            value = ((1 << width) - 1) ^ (2 if width >= 2 else 0)
        carrier = s.build_structure(mid, value)
        assert carrier
        assert s.parse_structure(mid, carrier) == value
