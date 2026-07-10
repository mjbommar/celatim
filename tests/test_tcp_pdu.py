"""Minimal TCP header fixtures."""

import pytest

from celatim.pdu import (
    TCP_HEADER_BYTES,
    build_tcp_reserved_bits_segment,
    parse_tcp_header,
    parse_tcp_reserved_bits,
    tcp_reserved_bits_offset,
)


def test_tcp_reserved_bits_segment_parses_nonzero_surrounding_header_fields():
    segment = build_tcp_reserved_bits_segment(0xA)
    header = parse_tcp_header(segment)

    assert len(segment) == TCP_HEADER_BYTES
    assert tcp_reserved_bits_offset() == 12
    assert parse_tcp_reserved_bits(segment) == 0xA
    assert header.src_port == 40000
    assert header.dst_port == 443
    assert header.seq == 0x11223344
    assert header.ack == 0x55667788
    assert header.data_offset_words == 5
    assert header.flags == 0x18
    assert header.window == 8192
    assert header.checksum == 0x1357


def test_tcp_reserved_bits_segment_rejects_invalid_symbol():
    with pytest.raises(ValueError, match="4 bits"):
        build_tcp_reserved_bits_segment(0x10)


def test_tcp_header_parser_rejects_truncated_segment():
    with pytest.raises(ValueError, match="truncated"):
        parse_tcp_header(b"\x00" * (TCP_HEADER_BYTES - 1))
