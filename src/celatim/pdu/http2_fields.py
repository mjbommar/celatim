"""HTTP/2 reserved-field carriers via the real ``hyperframe`` frame codec.

These set the covert value in the *real* HTTP/2 frame field (padding bytes, the
deprecated PRIORITY fields, the reserved R bit, unused frame flags) using hyperframe --
h2's own wire codec -- and recover it by re-parsing the serialized frame. The catalog's
byte offset is irrelevant: the value goes in the named field, and the frame stays a valid
HTTP/2 frame. ``hyperframe`` ships with the ``daemon`` extra (it is an ``h2`` dependency),
imported lazily.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


def _frames() -> Any:
    from hyperframe.frame import DataFrame, Frame, PriorityFrame

    return Frame, DataFrame, PriorityFrame


def _build_padding(value: bytes) -> bytes:
    _frame, data_frame, _priority = _frames()
    frame = data_frame(stream_id=1, data=b"")
    frame.flags.add("PADDED")
    frame.pad_length = len(value)
    raw = bytearray(frame.serialize())
    raw[10 : 10 + len(value)] = value  # padding follows the 9-byte header + pad_length byte
    return bytes(raw)


def _parse_padding(carrier: bytes) -> bytes:
    frame_cls, _data, _priority = _frames()
    frame_cls.parse_frame_header(memoryview(carrier[:9]))  # validates the frame header
    pad_length = carrier[9]
    return carrier[10 : 10 + pad_length]


def _build_priority(value: int) -> bytes:
    _frame, _data, priority_frame = _frames()
    frame = priority_frame(stream_id=1)
    frame.exclusive = bool((value >> 39) & 1)
    frame.depends_on = (value >> 8) & 0x7FFFFFFF
    frame.stream_weight = value & 0xFF
    return frame.serialize()


def _parse_priority(carrier: bytes) -> int:
    frame_cls, _data, _priority = _frames()
    frame, length = frame_cls.parse_frame_header(memoryview(carrier[:9]))
    frame.parse_body(memoryview(carrier[9 : 9 + length]))
    return (int(frame.exclusive) << 39) | (frame.depends_on << 8) | frame.stream_weight


def _build_flags(value: int) -> bytes:
    _frame, data_frame, _priority = _frames()
    raw = bytearray(data_frame(stream_id=1, data=b"covert").serialize())
    raw[4] = value & 0xFF  # the frame flags byte
    return bytes(raw)


def _parse_flags(carrier: bytes) -> int:
    return carrier[4]


def _build_r_bit(value: int) -> bytes:
    _frame, data_frame, _priority = _frames()
    raw = bytearray(data_frame(stream_id=1, data=b"covert").serialize())
    # the reserved R bit is the top bit of the 31-bit stream-id field (header byte 5).
    raw[5] = (raw[5] & 0x7F) | ((value & 1) << 7)
    return bytes(raw)


def _parse_r_bit(carrier: bytes) -> int:
    return (carrier[5] >> 7) & 1


@dataclass(frozen=True)
class _H2Carrier:
    build: Callable[..., bytes]
    parse: Callable[[bytes], object]
    symbol_is_bytes: bool


_CARRIERS: dict[str, _H2Carrier] = {
    "http2-padding": _H2Carrier(_build_padding, _parse_padding, symbol_is_bytes=True),
    "http2-priority-deprecated": _H2Carrier(
        _build_priority, _parse_priority, symbol_is_bytes=False
    ),
    "http2-unused-flags": _H2Carrier(_build_flags, _parse_flags, symbol_is_bytes=False),
    "http2-reserved-r-bit": _H2Carrier(_build_r_bit, _parse_r_bit, symbol_is_bytes=False),
}


def supports(mechanism_id: str) -> bool:
    return mechanism_id in _CARRIERS


def is_bytes_symbol(mechanism_id: str) -> bool:
    return _CARRIERS[mechanism_id].symbol_is_bytes


def build_frame(mechanism_id: str, value: int | bytes) -> bytes:
    return _CARRIERS[mechanism_id].build(value)


def parse_frame(mechanism_id: str, carrier: bytes) -> int | bytes:
    from typing import cast

    return cast("int | bytes", _CARRIERS[mechanism_id].parse(carrier))


__all__ = [
    "build_frame",
    "is_bytes_symbol",
    "parse_frame",
    "supports",
]
