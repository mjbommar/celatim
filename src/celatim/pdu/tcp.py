"""Minimal TCP header fixture helpers."""

from __future__ import annotations

import struct
from dataclasses import dataclass

TCP_HEADER_BYTES = 20
TCP_RESERVED_BITS_WIDTH = 3
TCP_RESERVED_BITS_OFFSET = 12
_TCP_HEADER = struct.Struct("!HHIIBBHHH")


@dataclass(frozen=True)
class TCPHeader:
    src_port: int
    dst_port: int
    seq: int
    ack: int
    data_offset_words: int
    reserved_bits: int
    flags: int
    window: int
    checksum: int
    urgent_pointer: int


def build_tcp_reserved_bits_segment(
    reserved_bits: int,
    *,
    src_port: int = 40000,
    dst_port: int = 443,
    seq: int = 0x11223344,
    ack: int = 0x55667788,
    flags: int = 0x18,
    window: int = 8192,
    checksum: int = 0x1357,
    urgent_pointer: int = 0,
) -> bytes:
    """Build a parser-visible TCP header carrying the reserved-bit symbol."""

    if not 0 <= reserved_bits < (1 << TCP_RESERVED_BITS_WIDTH):
        raise ValueError("reserved_bits must fit in 3 bits")
    offset_reserved = (5 << 4) | (reserved_bits << 1)
    return _TCP_HEADER.pack(
        src_port,
        dst_port,
        seq,
        ack,
        offset_reserved,
        flags,
        window,
        checksum,
        urgent_pointer,
    )


def parse_tcp_header(segment: bytes) -> TCPHeader:
    if len(segment) < TCP_HEADER_BYTES:
        raise ValueError("truncated TCP header")
    src_port, dst_port, seq, ack, offset_reserved, flags, window, checksum, urgent = (
        _TCP_HEADER.unpack(segment[:TCP_HEADER_BYTES])
    )
    data_offset_words = offset_reserved >> 4
    if data_offset_words < 5:
        raise ValueError("invalid TCP data offset")
    data_offset_bytes = data_offset_words * 4
    if len(segment) < data_offset_bytes:
        raise ValueError("truncated TCP options")
    return TCPHeader(
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        ack=ack,
        data_offset_words=data_offset_words,
        reserved_bits=(offset_reserved & 0x0E) >> 1,
        flags=flags,
        window=window,
        checksum=checksum,
        urgent_pointer=urgent,
    )


def parse_tcp_reserved_bits(segment: bytes) -> int:
    return parse_tcp_header(segment).reserved_bits


def tcp_reserved_bits_offset() -> int:
    return TCP_RESERVED_BITS_OFFSET


__all__ = [
    "TCP_HEADER_BYTES",
    "TCP_RESERVED_BITS_OFFSET",
    "TCP_RESERVED_BITS_WIDTH",
    "TCPHeader",
    "build_tcp_reserved_bits_segment",
    "parse_tcp_header",
    "parse_tcp_reserved_bits",
    "tcp_reserved_bits_offset",
]
