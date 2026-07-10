"""HTTP/2 reserved-field carriers via the real hyperframe frame codec."""

from __future__ import annotations

import pytest

pytest.importorskip("hyperframe")

from celatim.pdu import http2_fields as h2


def test_supports_registered_rows():
    for mid in (
        "http2-padding",
        "http2-priority-deprecated",
        "http2-unused-flags",
        "http2-reserved-r-bit",
    ):
        assert h2.supports(mid)
    assert not h2.supports("tcp-reserved-bits")


def test_padding_carries_bytes_in_real_data_frame():
    value = b"covert-in-real-http2-padding"
    carrier = h2.build_frame("http2-padding", value)
    assert carrier[3] == 0x00  # DATA frame type
    assert h2.parse_frame("http2-padding", carrier) == value


def test_deprecated_priority_roundtrips():
    value = 0x9ABCDEF12 & ((1 << 40) - 1)
    assert (
        h2.parse_frame(
            "http2-priority-deprecated", h2.build_frame("http2-priority-deprecated", value)
        )
        == value
    )


def test_unused_flags_roundtrip():
    value = 0b00110110 & 0x3F
    assert (
        h2.parse_frame("http2-unused-flags", h2.build_frame("http2-unused-flags", value)) == value
    )


def test_reserved_r_bit_roundtrip():
    for value in (0, 1):
        assert (
            h2.parse_frame("http2-reserved-r-bit", h2.build_frame("http2-reserved-r-bit", value))
            == value
        )
