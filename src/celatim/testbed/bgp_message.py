"""Paired scapy BGP speaker/peer optional-transitive attribute carrier.

A speaker builds a real BGP UPDATE with scapy's BGP codec, carrying covert bytes in an
unknown optional-transitive path attribute; a peer re-parses it with the same codec as
the independent validator. scapy is the optional ``packet`` extra, imported lazily in the
carrier primitives.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from ..pdu.bgp_attr import BGP_CLAIM_STATUS, build_bgp_update, parse_bgp_update


@dataclass(frozen=True)
class BgpRoundtripResult:
    """Result of a paired scapy BGP UPDATE exchange."""

    recovered: list[bytes]
    exchanges: list[dict[str, Any]]

    def to_json(self) -> dict[str, Any]:
        return {
            "transport": "bgp_scapy",
            "claim_status": BGP_CLAIM_STATUS,
            "symbol_count": len(self.recovered),
            "client_role": "scapy.BGPUpdate(optional-transitive)",
            "server_role": "scapy.BGPHeader.parse",
            "independent_validator": "scapy_bgp_codec",
            "exchanges": self.exchanges,
        }


def run_scapy_bgp_roundtrip(symbols: list[bytes]) -> BgpRoundtripResult:
    """Run one paired BGP UPDATE build/parse exchange per covert symbol."""

    recovered: list[bytes] = []
    exchanges: list[dict[str, Any]] = []
    for index, symbol in enumerate(symbols):
        wire = build_bgp_update(symbol)
        recovered_symbol = parse_bgp_update(wire)
        recovered.append(recovered_symbol)
        exchanges.append(
            {
                "index": index,
                "wire_len": len(wire),
                "wire_sha256": hashlib.sha256(wire).hexdigest(),
                "recovered": recovered_symbol == symbol,
            }
        )
    return BgpRoundtripResult(recovered=recovered, exchanges=exchanges)


__all__ = [
    "BGP_CLAIM_STATUS",
    "BgpRoundtripResult",
    "build_bgp_update",
    "parse_bgp_update",
    "run_scapy_bgp_roundtrip",
]
