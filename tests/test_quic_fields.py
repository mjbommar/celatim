"""QUIC reserved-field carriers built as real QUIC wire structures."""

from __future__ import annotations

from pathlib import Path

from celatim.catalog import load_mechanisms
from celatim.channel.codec import VariableLengthCodec
from celatim.channel.registry import codec_for
from celatim.pdu import quic_fields as q

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"

ROWS = (
    "quic-reserved-version",
    "quic-spin-bit",
    "quic-grease-bit",
    "quic-path-challenge",
    "quic-new-token",
    "quic-stateless-reset",
    "quic-reserved-transport-params",
)


def test_supports_registered_rows():
    for mid in ROWS:
        assert q.supports(mid)
    assert not q.supports("tcp-reserved-bits")


def test_each_quic_field_roundtrips_in_real_wire_structure():
    mechs = {m.id: m for m in load_mechanisms(DATA)}
    for mid in ROWS:
        mech = mechs[mid]
        assert mech.locator is not None
        width = mech.locator.bit_width
        assert q.is_bytes_symbol(mid) == isinstance(codec_for(mech), VariableLengthCodec)
        if q.is_bytes_symbol(mid):
            value: int | bytes = bytes((i * 5 + 1) % 256 for i in range(width // 8))
        else:
            value = ((1 << width) - 1) ^ (2 if width >= 2 else 0)
        carrier = q.build_packet(mid, value)
        assert carrier  # a real QUIC wire structure
        assert q.parse_packet(mid, carrier) == value
