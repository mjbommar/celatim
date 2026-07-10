"""Minimal HTTP/2 frame fixtures for PING opaque-data evidence.

The point of this module is not to implement HTTP/2. It gives the measurement harness
real surrounding PDU bytes for one marquee mechanism instead of a nominal offset into
``b"\x00" * 1500``:

* the HTTP/2 connection preface;
* a real empty SETTINGS frame;
* a real PING frame with its 8-byte opaque-data field.

The parser below is deliberately independent from the generic bit-offset injector. A
wrong offset can still round-trip through inject/capture, but it will not put the chosen
bytes in the parsed PING opaque field.
"""

from __future__ import annotations

from dataclasses import dataclass

HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FRAME_HEADER_LEN = 9
FRAME_TYPE_SETTINGS = 0x04
FRAME_TYPE_PING = 0x06
PING_OPAQUE_LEN = 8
EMPTY_SETTINGS_FRAME = b"\x00\x00\x00" + bytes([FRAME_TYPE_SETTINGS, 0]) + b"\x00\x00\x00\x00"


@dataclass(frozen=True)
class HTTP2Frame:
    length: int
    frame_type: int
    flags: int
    stream_id: int
    payload: bytes

    @property
    def is_ping(self) -> bool:
        return (
            self.frame_type == FRAME_TYPE_PING
            and self.stream_id == 0
            and self.length == PING_OPAQUE_LEN
        )


def build_ping_frame(opaque: bytes, *, ack: bool = False) -> bytes:
    if len(opaque) != PING_OPAQUE_LEN:
        raise ValueError(f"HTTP/2 PING opaque data must be {PING_OPAQUE_LEN} bytes")
    flags = 0x01 if ack else 0x00
    header = (
        PING_OPAQUE_LEN.to_bytes(3, "big")
        + bytes([FRAME_TYPE_PING, flags])
        + (0).to_bytes(4, "big")
    )
    return header + opaque


def build_connection_preface_ping(opaque: bytes) -> bytes:
    """Return client preface + empty SETTINGS + PING frame."""
    return HTTP2_PREFACE + EMPTY_SETTINGS_FRAME + build_ping_frame(opaque)


def ping_opaque_offset() -> int:
    """Byte offset of the PING opaque field within ``build_connection_preface_ping``."""
    return len(HTTP2_PREFACE) + len(EMPTY_SETTINGS_FRAME) + FRAME_HEADER_LEN


def parse_frames(data: bytes) -> list[HTTP2Frame]:
    """Parse frames after an optional client connection preface."""
    off = len(HTTP2_PREFACE) if data.startswith(HTTP2_PREFACE) else 0
    frames: list[HTTP2Frame] = []
    while off < len(data):
        if len(data) - off < FRAME_HEADER_LEN:
            raise ValueError("truncated HTTP/2 frame header")
        length = int.from_bytes(data[off : off + 3], "big")
        frame_type = data[off + 3]
        flags = data[off + 4]
        stream_id = int.from_bytes(data[off + 5 : off + 9], "big") & 0x7FFF_FFFF
        start = off + FRAME_HEADER_LEN
        end = start + length
        if end > len(data):
            raise ValueError("truncated HTTP/2 frame payload")
        frames.append(HTTP2Frame(length, frame_type, flags, stream_id, data[start:end]))
        off = end
    return frames
