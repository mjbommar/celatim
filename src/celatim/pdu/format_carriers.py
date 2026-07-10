"""Format-carrier substantiation for file/token-format covert channels.

These mechanisms are not network PDUs but structured data formats (a JWT, a UUIDv8, an
OpenPGP padding packet, a TZif file, an Ogg/Opus comment, a Binary HTTP message). The
covert value is placed in the format's designated field, the real format is serialized,
and an independent reader recovers the value -- the format itself is the validator.
Pure stdlib, no optional extras.
"""

from __future__ import annotations

import base64
import json
import struct
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

# UUIDv8 bit layout (RFC 9562): 122 custom bits around a 4-bit version (8) and 2-bit
# variant (0b10).
_UUID_VERSION = 8
_UUID_VARIANT = 0b10


def _build_uuidv8(value: int) -> bytes:
    seg_c = value & ((1 << 62) - 1)
    seg_b = (value >> 62) & ((1 << 12) - 1)
    seg_a = (value >> 74) & ((1 << 48) - 1)
    n = (seg_a << 80) | (_UUID_VERSION << 76) | (seg_b << 64) | (_UUID_VARIANT << 62) | seg_c
    return n.to_bytes(16, "big")


def _parse_uuidv8(carrier: bytes) -> int:
    import uuid

    parsed = uuid.UUID(bytes=carrier[:16])
    if parsed.version != _UUID_VERSION:
        raise ValueError("not a UUIDv8")
    n = int.from_bytes(carrier[:16], "big")
    seg_c = n & ((1 << 62) - 1)
    seg_b = (n >> 64) & ((1 << 12) - 1)
    seg_a = (n >> 80) & ((1 << 48) - 1)
    return (seg_a << 74) | (seg_b << 62) | seg_c


# TZif (RFC 8536): 4-byte magic, 1-byte version, 15-byte reserved/unused field.
def _build_tzif(value: int) -> bytes:
    reserved = value.to_bytes(15, "big")
    return b"TZif" + b"2" + reserved + struct.pack(">6I", 0, 0, 0, 0, 0, 0)


def _parse_tzif(carrier: bytes) -> int:
    if carrier[:4] != b"TZif":
        raise ValueError("not a TZif file")
    return int.from_bytes(carrier[5:20], "big")


def _build_jwt(value: bytes) -> bytes:
    def b64(raw: bytes) -> bytes:
        return base64.urlsafe_b64encode(raw).rstrip(b"=")

    header = b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = b64(json.dumps({"iss": "covert", "x": base64.b64encode(value).decode()}).encode())
    return header + b"." + payload + b"."


def _parse_jwt(carrier: bytes) -> bytes:
    payload_b64 = carrier.split(b".")[1]
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + b"=" * (-len(payload_b64) % 4)))
    return base64.b64decode(payload["x"])


# OpenPGP padding packet (RFC 9580 tag 21): new-format header byte 0xD5, then length.
def _build_openpgp(value: bytes) -> bytes:
    body = value
    length = bytes([len(body)]) if len(body) < 192 else bytes([255]) + struct.pack(">I", len(body))
    return bytes([0xD5]) + length + body


def _parse_openpgp(carrier: bytes) -> bytes:
    if carrier[0] != 0xD5:
        raise ValueError("not an OpenPGP padding packet")
    if carrier[1] < 192:
        return carrier[2 : 2 + carrier[1]]
    length = struct.unpack(">I", carrier[2:6])[0]
    return carrier[6 : 6 + length]


# Ogg/Opus comment header (RFC 7845): "OpusTags" magic, vendor string, user comments.
def _build_opus(value: bytes) -> bytes:
    vendor = b"celatim"
    out = b"OpusTags" + struct.pack("<I", len(vendor)) + vendor
    out += struct.pack("<I", 1)  # one user comment carrying the covert value
    comment = b"COVERT=" + base64.b64encode(value)
    return out + struct.pack("<I", len(comment)) + comment


def _parse_opus(carrier: bytes) -> bytes:
    if carrier[:8] != b"OpusTags":
        raise ValueError("not an OpusTags header")
    pos = 8
    (vlen,) = struct.unpack("<I", carrier[pos : pos + 4])
    pos += 4 + vlen
    pos += 4  # comment count
    (clen,) = struct.unpack("<I", carrier[pos : pos + 4])
    pos += 4
    comment = carrier[pos : pos + clen]
    return base64.b64decode(comment[len(b"COVERT=") :])


# Binary HTTP message (RFC 9292): a known-length request framing, padding carries covert.
def _build_binary_http(value: bytes) -> bytes:
    framing = bytes([0x00])  # framing indicator: request, known-length
    return framing + struct.pack(">I", len(value)) + value


def _parse_binary_http(carrier: bytes) -> bytes:
    if carrier[0] != 0x00:
        raise ValueError("not a known-length Binary HTTP request")
    (length,) = struct.unpack(">I", carrier[1:5])
    return carrier[5 : 5 + length]


@dataclass(frozen=True)
class _FormatCarrier:
    build: Callable[..., bytes]
    parse: Callable[[bytes], object]
    symbol_is_bytes: bool


_CARRIERS: dict[str, _FormatCarrier] = {
    "uuidv8-custom": _FormatCarrier(_build_uuidv8, _parse_uuidv8, symbol_is_bytes=False),
    "tzif-unused": _FormatCarrier(_build_tzif, _parse_tzif, symbol_is_bytes=False),
    "jwt-private-claims": _FormatCarrier(_build_jwt, _parse_jwt, symbol_is_bytes=True),
    "openpgp-padding-packet": _FormatCarrier(_build_openpgp, _parse_openpgp, symbol_is_bytes=True),
    "ogg-opus-comment": _FormatCarrier(_build_opus, _parse_opus, symbol_is_bytes=True),
    "binary-http-padding": _FormatCarrier(
        _build_binary_http, _parse_binary_http, symbol_is_bytes=True
    ),
}


def supports(mechanism_id: str) -> bool:
    """True if a real-format carrier is registered for this mechanism."""

    return mechanism_id in _CARRIERS


def is_bytes_symbol(mechanism_id: str) -> bool:
    return _CARRIERS[mechanism_id].symbol_is_bytes


def build_format(mechanism_id: str, value: int | bytes) -> bytes:
    """Build the real format carrying ``value`` in its designated field."""

    return _CARRIERS[mechanism_id].build(value)


def parse_format(mechanism_id: str, carrier: bytes) -> int | bytes:
    """Independently parse the real format and recover the covert value."""

    return cast("int | bytes", _CARRIERS[mechanism_id].parse(carrier))


__all__ = [
    "build_format",
    "is_bytes_symbol",
    "parse_format",
    "supports",
]
