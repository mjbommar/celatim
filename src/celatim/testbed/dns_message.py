"""Paired dnspython client/server DNS record-tunnel carrier.

TXT character-strings (RFC 1035 §3.3.14) and NULL RDATA (§3.3.10) both carry arbitrary
bytes by spec, so a resolver answering with covert bytes is standards-conforming. This
builds a real DNS response with dnspython (the server role), serializes it to wire, and
re-parses it with dnspython (the client role and independent validator). dnspython is the
optional ``dns`` extra, imported lazily, so this module is safe to import without it.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..pdu.dns_txt import (
    DNS_TXT_CLAIM_STATUS,
    build_null_response,
    build_txt_response,
    parse_null_response,
    parse_txt_response,
)

_RECORDS: dict[str, tuple[str, Callable[[str, bytes], bytes], Callable[[bytes], bytes]]] = {
    "TXT": ("dns_txt_dnspython", build_txt_response, parse_txt_response),
    "NULL": ("dns_null_dnspython", build_null_response, parse_null_response),
}


@dataclass(frozen=True)
class DnsRecordRoundtripResult:
    """Result of a paired dnspython record-tunnel exchange."""

    transport: str
    recovered: list[bytes]
    exchanges: list[dict[str, Any]]

    def to_json(self) -> dict[str, Any]:
        return {
            "transport": self.transport,
            "claim_status": DNS_TXT_CLAIM_STATUS,
            "symbol_count": len(self.recovered),
            "client_role": "dns.message.make_query",
            "server_role": "dns.message.make_response",
            "independent_validator": "dnspython_from_wire",
            "exchanges": self.exchanges,
        }


def run_dnspython_record_roundtrip(
    symbols: list[bytes],
    *,
    record: str = "TXT",
    qname: str = "covert.example.",
) -> DnsRecordRoundtripResult:
    """Run one paired query/response DNS exchange per covert symbol for ``record``."""

    transport, build, parse = _RECORDS[record]
    recovered: list[bytes] = []
    exchanges: list[dict[str, Any]] = []
    for index, symbol in enumerate(symbols):
        wire = build(qname, symbol)
        recovered_symbol = parse(wire)
        recovered.append(recovered_symbol)
        exchanges.append(
            {
                "index": index,
                "qname": qname,
                "record": record,
                "wire_len": len(wire),
                "wire_sha256": hashlib.sha256(wire).hexdigest(),
                "recovered": recovered_symbol == symbol,
            }
        )
    return DnsRecordRoundtripResult(transport=transport, recovered=recovered, exchanges=exchanges)


def run_dnspython_txt_roundtrip(
    symbols: list[bytes],
    *,
    qname: str = "covert.example.",
) -> DnsRecordRoundtripResult:
    """Paired TXT-record exchange (thin wrapper over the generic record roundtrip)."""

    return run_dnspython_record_roundtrip(symbols, record="TXT", qname=qname)


def run_dnspython_null_roundtrip(
    symbols: list[bytes],
    *,
    qname: str = "covert.example.",
) -> DnsRecordRoundtripResult:
    """Paired NULL-record exchange (thin wrapper over the generic record roundtrip)."""

    return run_dnspython_record_roundtrip(symbols, record="NULL", qname=qname)


__all__ = [
    "DNS_TXT_CLAIM_STATUS",
    "DnsRecordRoundtripResult",
    "build_null_response",
    "build_txt_response",
    "parse_null_response",
    "parse_txt_response",
    "run_dnspython_null_roundtrip",
    "run_dnspython_record_roundtrip",
    "run_dnspython_txt_roundtrip",
]
