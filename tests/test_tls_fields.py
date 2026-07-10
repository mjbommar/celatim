"""TLS/DTLS reserved-field carriers built as real TLS wire structures."""

from __future__ import annotations

from pathlib import Path

import pytest

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


def test_each_tls_field_roundtrips_in_serialized_structure():
    mechs = {m.id: m for m in load_mechanisms(DATA)}
    for mid in ROWS:
        codec = codec_for(mechs[mid])
        width = codec.capacity_bits
        assert t.is_bytes_symbol(mid) == isinstance(codec, VariableLengthCodec)
        if t.is_bytes_symbol(mid):
            value: int | bytes = bytes((i * 5 + 1) % 256 for i in range(width // 8))
        else:
            value = ((1 << width) - 1) ^ (2 if width >= 2 else 0)
        carrier = t.build_record(mid, value)
        assert carrier
        assert t.parse_record(mid, carrier) == value


def test_tls13_record_padding_uses_only_an_all_zero_run_length():
    mechs = {m.id: m for m in load_mechanisms(DATA)}
    mechanism = mechs["tls-record-padding"]
    assert mechanism.raw_capacity_bits == 14
    assert mechanism.locator is None
    assert not t.is_bytes_symbol(mechanism.id)

    carrier = t.build_record(mechanism.id, 37)
    assert carrier[5] == 23
    assert carrier[6:] == b"\x00" * 37
    assert t.parse_record(mechanism.id, carrier) == 37

    invalid = carrier[:-1] + b"\x01"
    with pytest.raises(ValueError, match="contain only zeros"):
        t.parse_record(mechanism.id, invalid)
    with pytest.raises(ValueError, match="fit in 14 bits"):
        t.build_record(mechanism.id, 1 << 14)
