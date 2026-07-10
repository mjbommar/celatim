"""Carrier-aware JSON envelopes for send/receive handoff.

The CLI is only one caller of this format. Daemon, pcap, and artifact transports can
use the same envelope model to carry both codec-level symbols and parser-visible
carrier bytes. When carrier bytes are present, the receiver parses them through the
mechanism adapter and rejects envelopes whose carrier bytes no longer match the
declared symbols.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Any

from .adapter import CarrierUnit
from .errors import EnvelopeValidationError
from .session import MechanismProfile, SendReceipt, Symbol


@dataclass(frozen=True)
class EnvelopeSymbols:
    symbols: list[Symbol]
    carrier_input_used: bool = False
    parser_validated: bool | None = None
    carrier_units_with_bytes: int = 0
    carrier_unit_sha256: tuple[str, ...] = ()


def build_send_envelope(
    receipt: SendReceipt,
    payload: bytes,
    symbols: list[Symbol],
    profile: MechanismProfile,
) -> dict[str, Any]:
    symbol_encoding, encoded_symbols = symbols_to_json(symbols)
    carriers = carrier_bytes_for_symbols(profile, symbols)
    return {
        "command": "send",
        "session_id": receipt.session_id,
        "mechanism_id": receipt.mechanism_id,
        "payload_len": receipt.payload_len,
        "payload_sha256": sha256_hex(payload),
        "carrier_units": receipt.carrier_units,
        "evidence_bucket": receipt.evidence_bucket.value,
        "adapter_status": receipt.adapter_status.value,
        "adapter_capabilities": sorted(
            capability.value for capability in receipt.adapter_capabilities
        ),
        "pacing": None if receipt.pacing is None else asdict(receipt.pacing),
        "scheduled_duration_s": receipt.scheduled_duration_s,
        "session_framing": receipt.session_framing,
        "chunk_count": receipt.chunk_count,
        "integrity_sha256": receipt.integrity_sha256,
        "symbol_encoding": symbol_encoding,
        "symbols": encoded_symbols,
        "carrier_encoding": "hex" if carriers else None,
        "carriers": [carrier.hex() for carrier in carriers],
        "carrier_units_with_bytes": len(carriers),
        "carrier_unit_sha256": [sha256_hex(carrier) for carrier in carriers],
    }


def parse_envelope_symbols(envelope: dict[str, Any], profile: MechanismProfile) -> EnvelopeSymbols:
    declares_carriers = envelope.get("carrier_encoding") is not None
    carriers = carrier_bytes_from_envelope(envelope)
    symbols = symbol_fields_from_envelope(envelope)
    if not carriers:
        if declares_carriers and symbols:
            raise EnvelopeValidationError("carrier count does not match envelope symbol count")
        return EnvelopeSymbols(symbols=symbols)
    if len(carriers) != len(symbols):
        raise EnvelopeValidationError("carrier count does not match envelope symbol count")
    declared_hashes = envelope.get("carrier_unit_sha256")
    if declared_hashes is not None:
        if not isinstance(declared_hashes, list):
            raise EnvelopeValidationError("carrier_unit_sha256 must be an array")
        actual_hashes = [sha256_hex(carrier) for carrier in carriers]
        if [str(value) for value in declared_hashes] != actual_hashes:
            raise EnvelopeValidationError("carrier hashes do not match carrier bytes")
    try:
        parsed_symbols = [profile.adapter.parse_carrier(carrier) for carrier in carriers]
    except EnvelopeValidationError:
        raise
    except Exception as exc:
        raise EnvelopeValidationError(f"carrier bytes could not be parsed: {exc}") from exc
    if parsed_symbols != symbols:
        raise EnvelopeValidationError("carrier bytes do not match envelope symbols")
    return EnvelopeSymbols(
        symbols=parsed_symbols,
        carrier_input_used=True,
        parser_validated=True,
        carrier_units_with_bytes=len(carriers),
        carrier_unit_sha256=tuple(sha256_hex(carrier) for carrier in carriers),
    )


def symbols_to_json(symbols: list[Symbol]) -> tuple[str, list[int] | list[str]]:
    if all(isinstance(symbol, int) for symbol in symbols):
        return "int", [int(symbol) for symbol in symbols]
    if all(isinstance(symbol, bytes) for symbol in symbols):
        return "hex", [bytes(symbol).hex() for symbol in symbols]
    raise EnvelopeValidationError("mixed symbol types are not supported by the JSON envelope")


def symbol_fields_from_envelope(envelope: dict[str, Any]) -> list[Symbol]:
    encoding = envelope["symbol_encoding"]
    raw_symbols = envelope["symbols"]
    if encoding == "int":
        return [int(symbol) for symbol in raw_symbols]
    if encoding == "hex":
        return [bytes.fromhex(str(symbol)) for symbol in raw_symbols]
    raise EnvelopeValidationError(f"unsupported symbol encoding: {encoding}")


def carrier_bytes_for_symbols(profile: MechanismProfile, symbols: list[Symbol]) -> list[bytes]:
    units = [
        CarrierUnit(index, symbol, profile.adapter.build_carrier(symbol))
        for index, symbol in enumerate(symbols)
    ]
    carriers = [unit.carrier for unit in units if unit.carrier is not None]
    if carriers and len(carriers) != len(units):
        raise EnvelopeValidationError(
            f"{profile.id}: adapter produced carriers for only part of the envelope"
        )
    return carriers


def carrier_bytes_from_envelope(envelope: dict[str, Any]) -> list[bytes]:
    encoding = envelope.get("carrier_encoding")
    raw_carriers = envelope.get("carriers", [])
    if encoding is None:
        return []
    if encoding != "hex":
        raise EnvelopeValidationError(f"unsupported carrier encoding: {encoding}")
    if not isinstance(raw_carriers, list):
        raise EnvelopeValidationError("carriers must be an array")
    return [bytes.fromhex(str(carrier)) for carrier in raw_carriers]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


__all__ = [
    "EnvelopeSymbols",
    "EnvelopeValidationError",
    "build_send_envelope",
    "carrier_bytes_for_symbols",
    "carrier_bytes_from_envelope",
    "parse_envelope_symbols",
    "sha256_hex",
    "symbol_fields_from_envelope",
    "symbols_to_json",
]
