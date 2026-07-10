"""WebSocket frame-tunnel carrier primitives (build/parse a real WS binary frame).

A WebSocket binary frame's payload (RFC 6455) is arbitrary application data, so covert
bytes are conforming. These build/parse the frame with the ``websockets`` library's
sans-io codec; the paired client/server harness lives in
:mod:`celatim.testbed.ws_message`. ``websockets`` is the optional ``realtime`` extra,
imported lazily, so this module is safe to import without it.
"""

from __future__ import annotations

import io
from typing import Any

WS_CLAIM_STATUS = "local_websockets_client_server_frame_path"


def _frame_cls() -> Any:
    from websockets.frames import Frame, Opcode

    return Frame, Opcode


def build_ws_frame(payload: bytes) -> bytes:
    """Client role: serialize a real client-masked WS binary frame carrying ``payload``."""

    frame_cls, opcode = _frame_cls()
    return bytes(frame_cls(opcode.BINARY, payload).serialize(mask=True))


def parse_ws_frame(wire: bytes) -> bytes:
    """Server role / independent validator: recover the covert payload from a WS frame.

    Drives the ``websockets`` sans-io parse generator over a fully buffered reader.
    """

    frame_cls, _ = _frame_cls()
    buffer = io.BytesIO(wire)

    def read_exactly(count: int) -> Any:
        chunk = buffer.read(count)
        if len(chunk) != count:
            raise ValueError("truncated WebSocket frame")
        return chunk
        yield  # marks this a generator for the sans-io `yield from read_exactly(n)`

    parser = frame_cls.parse(read_exactly, mask=True)
    try:
        while True:
            next(parser)
    except StopIteration as stop:
        return bytes(stop.value.data)


__all__ = [
    "WS_CLAIM_STATUS",
    "build_ws_frame",
    "parse_ws_frame",
]
