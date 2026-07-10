"""Paired paramiko client/server SSH KEXINIT carrier.

A client builds a real SSH_MSG_KEXINIT with paramiko's ``Message`` wire codec, carrying
covert bytes across the 16-byte cookie and the trailing reserved ``uint32`` (RFC 4253
§7.1); a server re-parses the wire with paramiko as the independent validator. paramiko
is the optional ``ssh`` extra, imported lazily inside the carrier primitives.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from ..pdu.ssh_kex import (
    KEXINIT_CARRIER_LEN,
    SSH_KEXINIT_CLAIM_STATUS,
    build_kexinit,
    parse_kexinit,
)


@dataclass(frozen=True)
class SshKexinitRoundtripResult:
    """Result of a paired paramiko KEXINIT exchange."""

    recovered: list[bytes]
    exchanges: list[dict[str, Any]]

    def to_json(self) -> dict[str, Any]:
        return {
            "transport": "ssh_kexinit_paramiko",
            "claim_status": SSH_KEXINIT_CLAIM_STATUS,
            "symbol_count": len(self.recovered),
            "carrier_len": KEXINIT_CARRIER_LEN,
            "client_role": "paramiko.Message(KEXINIT)",
            "server_role": "paramiko.Message.parse",
            "independent_validator": "paramiko_message_codec",
            "exchanges": self.exchanges,
        }


def run_paramiko_kexinit_roundtrip(symbols: list[bytes]) -> SshKexinitRoundtripResult:
    """Run one paired KEXINIT build/parse exchange per covert symbol."""

    recovered: list[bytes] = []
    exchanges: list[dict[str, Any]] = []
    for index, symbol in enumerate(symbols):
        wire = build_kexinit(symbol)
        recovered_symbol = parse_kexinit(wire)
        recovered.append(recovered_symbol)
        exchanges.append(
            {
                "index": index,
                "wire_len": len(wire),
                "wire_sha256": hashlib.sha256(wire).hexdigest(),
                "recovered": recovered_symbol == symbol,
            }
        )
    return SshKexinitRoundtripResult(recovered=recovered, exchanges=exchanges)


__all__ = [
    "SSH_KEXINIT_CLAIM_STATUS",
    "SshKexinitRoundtripResult",
    "build_kexinit",
    "parse_kexinit",
    "run_paramiko_kexinit_roundtrip",
]
