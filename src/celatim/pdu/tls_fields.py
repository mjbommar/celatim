"""TLS carrier fixtures built from serialized record and handshake structures.

Each carrier sets the covert value in the genuine TLS field -- the record version, the
ClientHello ``gmt_unix_time`` and ``legacy_session_id``, a TLS 1.3 record's padding length, a
padding extension (RFC 7685), a GREASE extension (RFC 8701), or a Heartbeat message's
padding (RFC 6520) -- using the corresponding serialized protocol element and recovering
it from the same structure. These fixtures do not by themselves establish native-stack
acceptance or encrypted on-wire transit. Pure stdlib (struct), no extras.
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from dataclasses import dataclass

_TLS12 = 0x0303
_TLS13_PADDING_CAPACITY_BITS = 14


def _build_record_version(value: int) -> bytes:
    # TLS record: content type (handshake=22), 16-bit version, length, payload.
    return bytes([22]) + struct.pack(">H", value) + struct.pack(">H", 4) + b"\x00\x00\x00\x00"


def _parse_record_version(carrier: bytes) -> int:
    return struct.unpack(">H", carrier[1:3])[0]


def _clienthello(body: bytes) -> bytes:
    return bytes([0x01]) + struct.pack(">I", len(body))[1:] + body  # handshake type + 3-byte len


def _build_gmt_time(value: int) -> bytes:
    body = struct.pack(">H", _TLS12) + struct.pack(">I", value) + b"\x00" * 28 + b"\x00"
    return _clienthello(body)


def _parse_gmt_time(carrier: bytes) -> int:
    # type(1) + len(3) + version(2) -> random starts at byte 6; gmt_unix_time is its first 4 bytes.
    return struct.unpack(">I", carrier[6:10])[0]


def _build_session_id(value: bytes) -> bytes:
    sid = value[:32]
    body = struct.pack(">H", _TLS12) + b"\x00" * 32 + bytes([len(sid)]) + sid
    return _clienthello(body)


def _parse_session_id(carrier: bytes) -> bytes:
    sid_len = carrier[6 + 32]  # version(2) + random(32) then the 1-byte session-id length
    pos = 6 + 32 + 1
    return carrier[pos : pos + sid_len]


def _build_record_padding(value: int) -> bytes:
    if not 0 <= value < (1 << _TLS13_PADDING_CAPACITY_BITS):
        raise ValueError("TLS 1.3 record padding length must fit in 14 bits")
    # Zero-length Application Data is allowed. RFC 8446 requires every octet after
    # the inner content type to be zero, so only the run length carries a symbol.
    inner = bytes([23]) + b"\x00" * value
    return bytes([23]) + struct.pack(">H", _TLS12) + struct.pack(">H", len(inner)) + inner


def _parse_record_padding(carrier: bytes) -> int:
    if len(carrier) < 6 or carrier[:3] != bytes([23]) + struct.pack(">H", _TLS12):
        raise ValueError("invalid TLS 1.3 record-padding fixture")
    length = struct.unpack(">H", carrier[3:5])[0]
    inner = carrier[5:]
    if len(inner) != length or inner[0] != 23 or any(inner[1:]):
        raise ValueError("TLS 1.3 padding must follow the content type and contain only zeros")
    return len(inner) - 1


def _build_clienthello_padding(value: int) -> bytes:
    pad = value & 0x1FF
    return struct.pack(">H", 21) + struct.pack(">H", pad) + b"\x00" * pad  # ext type 21 (padding)


def _parse_clienthello_padding(carrier: bytes) -> int:
    return struct.unpack(">H", carrier[2:4])[0]


def _build_grease(value: bytes) -> bytes:
    return struct.pack(">H", 0x0A0A) + struct.pack(">H", len(value)) + value  # GREASE ext type


def _parse_grease(carrier: bytes) -> bytes:
    length = struct.unpack(">H", carrier[2:4])[0]
    return carrier[4 : 4 + length]


def _build_heartbeat_padding(value: bytes) -> bytes:
    return bytes([0x01]) + struct.pack(">H", 0) + value  # heartbeat request, 0-len payload, padding


def _parse_heartbeat_padding(carrier: bytes) -> bytes:
    return carrier[3:]


@dataclass(frozen=True)
class _TlsCarrier:
    build: Callable[..., bytes]
    parse: Callable[[bytes], object]
    symbol_is_bytes: bool


_CARRIERS: dict[str, _TlsCarrier] = {
    "tls-legacy-record-version": _TlsCarrier(
        _build_record_version, _parse_record_version, symbol_is_bytes=False
    ),
    "dtls-legacy-version": _TlsCarrier(
        _build_record_version, _parse_record_version, symbol_is_bytes=False
    ),
    "tls-gmt-unix-time": _TlsCarrier(_build_gmt_time, _parse_gmt_time, symbol_is_bytes=False),
    "tls-legacy-session-id": _TlsCarrier(
        _build_session_id, _parse_session_id, symbol_is_bytes=True
    ),
    "tls-record-padding": _TlsCarrier(
        _build_record_padding, _parse_record_padding, symbol_is_bytes=False
    ),
    "tls-clienthello-padding": _TlsCarrier(
        _build_clienthello_padding, _parse_clienthello_padding, symbol_is_bytes=False
    ),
    "tls-grease": _TlsCarrier(_build_grease, _parse_grease, symbol_is_bytes=True),
    "tls-heartbeat-padding": _TlsCarrier(
        _build_heartbeat_padding, _parse_heartbeat_padding, symbol_is_bytes=True
    ),
}


def supports(mechanism_id: str) -> bool:
    return mechanism_id in _CARRIERS


def is_bytes_symbol(mechanism_id: str) -> bool:
    return _CARRIERS[mechanism_id].symbol_is_bytes


def build_record(mechanism_id: str, value: int | bytes) -> bytes:
    return _CARRIERS[mechanism_id].build(value)


def parse_record(mechanism_id: str, carrier: bytes) -> int | bytes:
    from typing import cast

    return cast("int | bytes", _CARRIERS[mechanism_id].parse(carrier))


__all__ = [
    "build_record",
    "is_bytes_symbol",
    "parse_record",
    "supports",
]
