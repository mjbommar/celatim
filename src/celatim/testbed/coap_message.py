"""Paired aiocoap client/server CoAP elective-option carrier.

A client builds a real CoAP message with aiocoap's wire codec, placing covert bytes in an
unknown elective option; a server re-parses the wire with aiocoap as the independent
validator. aiocoap is imported lazily in the carrier primitives.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from ..pdu.coap_msg import COAP_CLAIM_STATUS, build_coap_message, parse_coap_message


@dataclass(frozen=True)
class CoapRoundtripResult:
    """Result of a paired aiocoap payload exchange."""

    recovered: list[bytes]
    exchanges: list[dict[str, Any]]

    def to_json(self) -> dict[str, Any]:
        return {
            "transport": "coap_aiocoap",
            "claim_status": COAP_CLAIM_STATUS,
            "symbol_count": len(self.recovered),
            "client_role": "aiocoap.Message.encode",
            "server_role": "aiocoap.Message.decode",
            "independent_validator": "aiocoap_message_codec",
            "exchanges": self.exchanges,
        }


def run_aiocoap_roundtrip(symbols: list[bytes]) -> CoapRoundtripResult:
    """Run one paired CoAP encode/decode exchange per covert symbol."""

    recovered: list[bytes] = []
    exchanges: list[dict[str, Any]] = []
    for index, symbol in enumerate(symbols):
        wire = build_coap_message(symbol)
        recovered_symbol = parse_coap_message(wire)
        recovered.append(recovered_symbol)
        exchanges.append(
            {
                "index": index,
                "wire_len": len(wire),
                "wire_sha256": hashlib.sha256(wire).hexdigest(),
                "recovered": recovered_symbol == symbol,
            }
        )
    return CoapRoundtripResult(recovered=recovered, exchanges=exchanges)


__all__ = [
    "COAP_CLAIM_STATUS",
    "CoapRoundtripResult",
    "build_coap_message",
    "parse_coap_message",
    "run_aiocoap_roundtrip",
]
