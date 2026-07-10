"""Paired websockets client/server frame carrier.

A client serializes a real client-masked WebSocket binary frame with the ``websockets``
sans-io codec (covert bytes in the conforming payload); a server parses it back with the
same codec as the independent validator. ``websockets`` is the optional ``realtime``
extra, imported lazily in the carrier primitives.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from ..pdu.ws_frame import WS_CLAIM_STATUS, build_ws_frame, parse_ws_frame


@dataclass(frozen=True)
class WebsocketRoundtripResult:
    """Result of a paired websockets frame exchange."""

    recovered: list[bytes]
    exchanges: list[dict[str, Any]]

    def to_json(self) -> dict[str, Any]:
        return {
            "transport": "websocket_websockets",
            "claim_status": WS_CLAIM_STATUS,
            "symbol_count": len(self.recovered),
            "client_role": "websockets.Frame.serialize(mask=True)",
            "server_role": "websockets.Frame.parse",
            "independent_validator": "websockets_frame_codec",
            "exchanges": self.exchanges,
        }


def run_websockets_roundtrip(symbols: list[bytes]) -> WebsocketRoundtripResult:
    """Run one paired WS frame serialize/parse exchange per covert symbol."""

    recovered: list[bytes] = []
    exchanges: list[dict[str, Any]] = []
    for index, symbol in enumerate(symbols):
        wire = build_ws_frame(symbol)
        recovered_symbol = parse_ws_frame(wire)
        recovered.append(recovered_symbol)
        exchanges.append(
            {
                "index": index,
                "wire_len": len(wire),
                "wire_sha256": hashlib.sha256(wire).hexdigest(),
                "recovered": recovered_symbol == symbol,
            }
        )
    return WebsocketRoundtripResult(recovered=recovered, exchanges=exchanges)


__all__ = [
    "WS_CLAIM_STATUS",
    "WebsocketRoundtripResult",
    "build_ws_frame",
    "parse_ws_frame",
    "run_websockets_roundtrip",
]
