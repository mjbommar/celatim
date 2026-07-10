"""QUIC reserved-field carriers built as real QUIC wire structures.

Each carrier sets the covert value in the genuine QUIC field -- the long-header version,
the short-header spin/reserved bits, a PATH_CHALLENGE / NEW_TOKEN frame, a transport
parameter, or a stateless-reset token -- using the real RFC 9000 wire layout, and an
independent reader recovers it from the same field. Pure stdlib (struct), no extras.
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from dataclasses import dataclass

_DCID = bytes(range(8))


def _varint(value: int) -> bytes:
    if value < 0x40:
        return bytes([value])
    if value < 0x4000:
        return struct.pack(">H", 0x4000 | value)
    if value < 0x40000000:
        return struct.pack(">I", 0x80000000 | value)
    return struct.pack(">Q", 0xC000000000000000 | value)


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    prefix = data[pos] >> 6
    if prefix == 0:
        return data[pos] & 0x3F, pos + 1
    if prefix == 1:
        return struct.unpack(">H", data[pos : pos + 2])[0] & 0x3FFF, pos + 2
    if prefix == 2:
        return struct.unpack(">I", data[pos : pos + 4])[0] & 0x3FFFFFFF, pos + 4
    return struct.unpack(">Q", data[pos : pos + 8])[0] & 0x3FFFFFFFFFFFFFFF, pos + 8


def _build_version(value: int) -> bytes:
    # Long header: first byte (0xC0), 32-bit version, DCID len + DCID, SCID len.
    return bytes([0xC0]) + struct.pack(">I", value) + bytes([len(_DCID)]) + _DCID + bytes([0])


def _parse_version(carrier: bytes) -> int:
    if carrier[0] & 0x80 == 0:
        raise ValueError("not a QUIC long header")
    return struct.unpack(">I", carrier[1:5])[0]


def _build_spin(value: int) -> bytes:
    # Short header first byte: form=0, fixed=1, spin bit at 0x20.
    return bytes([0x40 | ((value & 1) << 5)]) + _DCID


def _parse_spin(carrier: bytes) -> int:
    return (carrier[0] >> 5) & 1


def _build_grease(value: int) -> bytes:
    # A reserved short-header bit (0x10) carries the grease/reserved value.
    return bytes([0x40 | ((value & 1) << 4)]) + _DCID


def _parse_grease(carrier: bytes) -> int:
    return (carrier[0] >> 4) & 1


def _build_path_challenge(value: bytes) -> bytes:
    data = value.ljust(8, b"\x00")[:8]
    return bytes([0x1A]) + data  # PATH_CHALLENGE frame type + 8 bytes of arbitrary data


def _parse_path_challenge(carrier: bytes) -> bytes:
    if carrier[0] != 0x1A:
        raise ValueError("not a PATH_CHALLENGE frame")
    return carrier[1:9]


def _build_new_token(value: bytes) -> bytes:
    return bytes([0x07]) + _varint(len(value)) + value  # NEW_TOKEN frame


def _parse_new_token(carrier: bytes) -> bytes:
    if carrier[0] != 0x07:
        raise ValueError("not a NEW_TOKEN frame")
    length, pos = _read_varint(carrier, 1)
    return carrier[pos : pos + length]


def _build_stateless_reset(value: bytes) -> bytes:
    token = value.ljust(16, b"\x00")[:16]
    return bytes([0x40, 0xAA, 0xBB, 0xCC, 0xDD]) + token  # short header + 16-byte reset token


def _parse_stateless_reset(carrier: bytes) -> bytes:
    return carrier[-16:]


def _build_transport_param(value: bytes) -> bytes:
    # Reserved transport parameter: GREASE-style id (0x1b) + length + value.
    return _varint(0x1B) + _varint(len(value)) + value


def _parse_transport_param(carrier: bytes) -> bytes:
    _id, pos = _read_varint(carrier, 0)
    length, pos = _read_varint(carrier, pos)
    return carrier[pos : pos + length]


@dataclass(frozen=True)
class _QuicCarrier:
    build: Callable[..., bytes]
    parse: Callable[[bytes], object]
    symbol_is_bytes: bool


_CARRIERS: dict[str, _QuicCarrier] = {
    "quic-reserved-version": _QuicCarrier(_build_version, _parse_version, symbol_is_bytes=False),
    "quic-spin-bit": _QuicCarrier(_build_spin, _parse_spin, symbol_is_bytes=False),
    "quic-grease-bit": _QuicCarrier(_build_grease, _parse_grease, symbol_is_bytes=False),
    "quic-path-challenge": _QuicCarrier(
        _build_path_challenge, _parse_path_challenge, symbol_is_bytes=True
    ),
    "quic-new-token": _QuicCarrier(_build_new_token, _parse_new_token, symbol_is_bytes=True),
    "quic-stateless-reset": _QuicCarrier(
        _build_stateless_reset, _parse_stateless_reset, symbol_is_bytes=True
    ),
    "quic-reserved-transport-params": _QuicCarrier(
        _build_transport_param, _parse_transport_param, symbol_is_bytes=True
    ),
}


def supports(mechanism_id: str) -> bool:
    return mechanism_id in _CARRIERS


def is_bytes_symbol(mechanism_id: str) -> bool:
    return _CARRIERS[mechanism_id].symbol_is_bytes


def build_packet(mechanism_id: str, value: int | bytes) -> bytes:
    return _CARRIERS[mechanism_id].build(value)


def parse_packet(mechanism_id: str, carrier: bytes) -> int | bytes:
    from typing import cast

    return cast("int | bytes", _CARRIERS[mechanism_id].parse(carrier))


__all__ = [
    "build_packet",
    "is_bytes_symbol",
    "parse_packet",
    "supports",
]
