"""Paired websockets client/server frame carrier.

A WebSocket binary frame's payload is arbitrary application data (RFC 6455), so covert
bytes are conforming. A client serializes a real (client-masked) frame with the
``websockets`` sans-io codec; a server parses it back with the same codec as the
independent validator.
"""

from __future__ import annotations

import pytest

pytest.importorskip("websockets")

from celatim.testbed.ws_message import (
    build_ws_frame,
    parse_ws_frame,
    run_websockets_roundtrip,
)


def test_ws_frame_roundtrips_arbitrary_bytes():
    covert = bytes(range(256)) * 2  # 512 bytes of full-range data
    wire = build_ws_frame(covert)
    assert len(wire) > len(covert)  # framing header + client mask precede the payload
    assert parse_ws_frame(wire) == covert


def test_empty_control_recovers_empty():
    assert parse_ws_frame(build_ws_frame(b"")) == b""


def test_paired_roundtrip_recovers_each_symbol_with_provenance():
    symbols = [b"ws-covert", b"\x00\x01\x02binary", b"p" * 800]
    result = run_websockets_roundtrip(symbols)

    assert result.recovered == symbols
    doc = result.to_json()
    assert doc["transport"] == "websocket_websockets"
    assert doc["client_role"] == "websockets.Frame.serialize(mask=True)"
    assert doc["server_role"] == "websockets.Frame.parse"
    assert doc["independent_validator"] == "websockets_frame_codec"
    assert all(ex["recovered"] for ex in doc["exchanges"])
