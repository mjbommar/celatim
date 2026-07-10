"""TLS/DTLS reserved-field carriers built as real TLS wire structures."""

from __future__ import annotations

from pathlib import Path

from celatim.catalog import load_mechanisms
from celatim.channel.codec import VariableLengthCodec
from celatim.channel.registry import codec_for
from celatim.pdu import tls_fields as t

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"

ROWS = (
    "tls-legacy-record-version",
    "dtls-legacy-version",
    "tls-gmt-unix-time",
    "tls-legacy-session-id",
    "tls-record-padding",
    "tls-clienthello-padding",
    "tls-grease",
    "tls-heartbeat-padding",
)


def test_supports_registered_rows():
    for mid in ROWS:
        assert t.supports(mid)
    assert not t.supports("tcp-reserved-bits")


def test_each_tls_field_roundtrips_in_real_wire_structure():
    mechs = {m.id: m for m in load_mechanisms(DATA)}
    for mid in ROWS:
        locator = mechs[mid].locator
        assert locator is not None
        width = locator.bit_width
        assert t.is_bytes_symbol(mid) == isinstance(codec_for(mechs[mid]), VariableLengthCodec)
        if t.is_bytes_symbol(mid):
            value: int | bytes = bytes((i * 5 + 1) % 256 for i in range(width // 8))
        else:
            value = ((1 << width) - 1) ^ (2 if width >= 2 else 0)
        carrier = t.build_record(mid, value)
        assert carrier
        assert t.parse_record(mid, carrier) == value
