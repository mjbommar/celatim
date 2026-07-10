"""Format-carrier substantiation (JWT, UUIDv8, OpenPGP, TZif, Opus, Binary HTTP)."""

from __future__ import annotations

import pytest

from celatim.pdu import format_carriers as fc

INT_ROWS = {"uuidv8-custom": 122, "tzif-unused": 120}
BYTES_ROWS = {
    "jwt-private-claims": 64,
    "openpgp-padding-packet": 200,
    "ogg-opus-comment": 32,
    "binary-http-padding": 128,
}


def test_supports_registered_rows():
    for mid in {*INT_ROWS, *BYTES_ROWS}:
        assert fc.supports(mid)
    assert not fc.supports("tcp-reserved-bits")


@pytest.mark.parametrize("mid,width", INT_ROWS.items())
def test_int_format_roundtrips(mid, width):
    assert not fc.is_bytes_symbol(mid)
    value = ((1 << width) - 1) ^ 0b10
    carrier = fc.build_format(mid, value)
    assert any(b != 0 for b in carrier)
    assert fc.parse_format(mid, carrier) == value


@pytest.mark.parametrize("mid,nbytes", BYTES_ROWS.items())
def test_bytes_format_roundtrips(mid, nbytes):
    assert fc.is_bytes_symbol(mid)
    value = bytes((i * 5 + 1) % 256 for i in range(nbytes))
    carrier = fc.build_format(mid, value)
    assert carrier  # real format bytes
    assert fc.parse_format(mid, carrier) == value


def test_uuidv8_is_a_valid_uuid_version_8():
    import uuid

    carrier = fc.build_format("uuidv8-custom", 0x1234567)
    assert uuid.UUID(bytes=carrier[:16]).version == 8


def test_empty_bytes_control():
    assert fc.parse_format("jwt-private-claims", fc.build_format("jwt-private-claims", b"")) == b""
