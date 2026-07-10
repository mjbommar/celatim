"""Minimal QUIC long-header fixtures for connection-ID evidence.

This fixture targets the visible Destination Connection ID in a QUIC v1 Initial-like
long header. It is intentionally small, but it has the real surrounding structure:
long-header byte, version, DCID length, DCID, SCID length, SCID, token length, length,
packet number, and payload. The parser is separate from the generic bit-offset path so
the old "write at UDP payload byte zero" model fails validation.
"""

from __future__ import annotations

from dataclasses import dataclass

QUIC_V1 = 0x00000001
LONG_INITIAL_1BYTE_PN = 0xC0
DCID_LEN = 20
DEFAULT_SCID = b"server01"


@dataclass(frozen=True)
class QUICLongHeader:
    first_byte: int
    version: int
    dcid: bytes
    scid: bytes
    token: bytes
    packet_number: int
    payload: bytes

    @property
    def is_v1_initial(self) -> bool:
        return (
            self.first_byte & 0x80 == 0x80
            and self.first_byte & 0x40 == 0x40
            and self.first_byte & 0x30 == 0
            and self.version == QUIC_V1
        )


def build_initial_packet(
    dcid: bytes,
    *,
    scid: bytes = DEFAULT_SCID,
    packet_number: int = 1,
    payload: bytes = b"\x00",
) -> bytes:
    if len(dcid) != DCID_LEN:
        raise ValueError(f"QUIC DCID fixture must be {DCID_LEN} bytes")
    if len(scid) > 20:
        raise ValueError("QUIC SCID fixture must fit in one-byte length field")
    if not 0 <= packet_number <= 0xFF:
        raise ValueError("fixture uses a one-byte packet number")
    if len(payload) > 62:
        raise ValueError("fixture uses a one-byte QUIC varint length")
    packet_len = 1 + len(payload)  # one-byte packet number + protected payload bytes
    return (
        bytes([LONG_INITIAL_1BYTE_PN])
        + QUIC_V1.to_bytes(4, "big")
        + bytes([len(dcid)])
        + dcid
        + bytes([len(scid)])
        + scid
        + b"\x00"  # token length
        + bytes([packet_len])
        + bytes([packet_number])
        + payload
    )


def dcid_offset() -> int:
    """Byte offset of DCID within ``build_initial_packet``."""
    return 1 + 4 + 1


def parse_long_header(packet: bytes) -> QUICLongHeader:
    if len(packet) < dcid_offset():
        raise ValueError("truncated QUIC long header")
    first = packet[0]
    if first & 0x80 == 0:
        raise ValueError("not a QUIC long header")
    version = int.from_bytes(packet[1:5], "big")
    off = 5
    dcid_len = packet[off]
    off += 1
    if len(packet) < off + dcid_len + 1:
        raise ValueError("truncated QUIC DCID")
    dcid = packet[off : off + dcid_len]
    off += dcid_len
    scid_len = packet[off]
    off += 1
    if len(packet) < off + scid_len + 1:
        raise ValueError("truncated QUIC SCID")
    scid = packet[off : off + scid_len]
    off += scid_len
    token_len = packet[off]
    off += 1
    if len(packet) < off + token_len + 1:
        raise ValueError("truncated QUIC token")
    token = packet[off : off + token_len]
    off += token_len
    packet_len = packet[off]
    off += 1
    if packet_len < 1 or len(packet) < off + packet_len:
        raise ValueError("truncated QUIC packet payload")
    packet_number = packet[off]
    payload = packet[off + 1 : off + packet_len]
    return QUICLongHeader(first, version, dcid, scid, token, packet_number, payload)
