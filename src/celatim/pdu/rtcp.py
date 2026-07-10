"""Minimal RTCP APP packet fixture for application-data evidence.

The RTCP APP packet gives this marquee RTP/RTCP mechanism real surrounding PDU
structure: version/subtype, packet type 204, RTCP length, SSRC, four-byte name, and
application-dependent data. The parser is independent from the generic bit-offset
injector so the old "write at UDP payload byte zero" model fails validation.
"""

from __future__ import annotations

from dataclasses import dataclass

RTCP_VERSION = 2
RTCP_APP_PACKET_TYPE = 204
RTCP_APP_HEADER_LEN = 12
RTCP_APP_DATA_LEN = 100
DEFAULT_SSRC = 0x1122_3344
DEFAULT_APP_NAME = b"RFCX"


@dataclass(frozen=True)
class RTCPAppPacket:
    version: int
    padding: bool
    subtype: int
    packet_type: int
    ssrc: int
    name: bytes
    app_data: bytes

    @property
    def is_app(self) -> bool:
        return self.version == RTCP_VERSION and self.packet_type == RTCP_APP_PACKET_TYPE


def build_app_packet(
    app_data: bytes,
    *,
    subtype: int = 0,
    ssrc: int = DEFAULT_SSRC,
    name: bytes = DEFAULT_APP_NAME,
) -> bytes:
    if len(app_data) != RTCP_APP_DATA_LEN:
        raise ValueError(f"RTCP APP fixture data must be {RTCP_APP_DATA_LEN} bytes")
    if not 0 <= subtype <= 0x1F:
        raise ValueError("RTCP APP subtype must fit in five bits")
    if not 0 <= ssrc <= 0xFFFF_FFFF:
        raise ValueError("RTCP APP SSRC must fit in 32 bits")
    if len(name) != 4:
        raise ValueError("RTCP APP name must be exactly four bytes")
    total_len = RTCP_APP_HEADER_LEN + len(app_data)
    if total_len % 4:
        raise ValueError("RTCP APP packet length must be a multiple of 32 bits")
    length_words_minus_one = (total_len // 4) - 1
    first_byte = (RTCP_VERSION << 6) | subtype
    return (
        bytes([first_byte, RTCP_APP_PACKET_TYPE])
        + length_words_minus_one.to_bytes(2, "big")
        + ssrc.to_bytes(4, "big")
        + name
        + app_data
    )


def app_data_offset() -> int:
    """Byte offset of application-dependent data within ``build_app_packet``."""
    return RTCP_APP_HEADER_LEN


def parse_app_packet(packet: bytes) -> RTCPAppPacket:
    if len(packet) < RTCP_APP_HEADER_LEN:
        raise ValueError("truncated RTCP APP packet")
    first = packet[0]
    version = first >> 6
    padding = bool(first & 0x20)
    subtype = first & 0x1F
    packet_type = packet[1]
    if version != RTCP_VERSION:
        raise ValueError("unsupported RTCP version")
    if padding:
        raise ValueError("RTCP APP fixture does not use padding")
    if packet_type != RTCP_APP_PACKET_TYPE:
        raise ValueError("not an RTCP APP packet")
    length_words_minus_one = int.from_bytes(packet[2:4], "big")
    expected_len = (length_words_minus_one + 1) * 4
    if expected_len != len(packet):
        raise ValueError("RTCP APP length does not match packet size")
    ssrc = int.from_bytes(packet[4:8], "big")
    name = packet[8:12]
    app_data = packet[app_data_offset() :]
    return RTCPAppPacket(version, padding, subtype, packet_type, ssrc, name, app_data)
