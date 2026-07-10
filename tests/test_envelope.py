"""Carrier-aware send envelope model."""

from __future__ import annotations

from pathlib import Path

import pytest

from celatim.envelope import build_send_envelope, parse_envelope_symbols, sha256_hex
from celatim.errors import EnvelopeValidationError
from celatim.session import ChannelSession, InMemoryTransport, MechanismProfile, PacingConfig

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def _send_payload(mechanism_id: str, payload: bytes, pacing: PacingConfig | None = None):
    profile = MechanismProfile.from_catalog(mechanism_id, DATA)
    transport = InMemoryTransport()
    receipt = ChannelSession(profile, transport).send_message(
        payload,
        session_id=f"{mechanism_id}-envelope",
        pacing=pacing,
    )
    symbols = transport.receive_symbols(receipt.session_id)
    return profile, receipt, symbols


def test_send_envelope_includes_parser_visible_carriers_for_real_pdu_adapter():
    profile, receipt, symbols = _send_payload(
        "http2-ping-opaque",
        b"\x00\xff\x80A",
        PacingConfig(unit_rate_hz=25.0),
    )

    envelope = build_send_envelope(receipt, b"\x00\xff\x80A", symbols, profile)
    parsed = parse_envelope_symbols(envelope, profile)

    assert envelope["symbol_encoding"] == "hex"
    assert envelope["carrier_encoding"] == "hex"
    assert len(envelope["carriers"]) == len(symbols)
    assert envelope["carrier_units_with_bytes"] == len(symbols)
    assert len(envelope["carrier_unit_sha256"]) == len(symbols)
    assert envelope["pacing"]["unit_rate_hz"] == 25.0
    assert parsed.symbols == symbols
    assert parsed.carrier_input_used is True
    assert parsed.parser_validated is True
    assert list(parsed.carrier_unit_sha256) == envelope["carrier_unit_sha256"]


def test_send_envelope_stays_symbol_only_for_offset_represented_adapter():
    profile, receipt, symbols = _send_payload("bgp-path-attr-flags", b"offset represented")

    envelope = build_send_envelope(receipt, b"offset represented", symbols, profile)
    parsed = parse_envelope_symbols(envelope, profile)

    assert envelope["carrier_encoding"] is None
    assert envelope["carriers"] == []
    assert envelope["carrier_units_with_bytes"] == 0
    assert parsed.symbols == symbols
    assert parsed.carrier_input_used is False
    assert parsed.parser_validated is None


def test_parse_envelope_rejects_tampered_carrier_bytes():
    profile, receipt, symbols = _send_payload("quic-connection-id", b"\x00\xff\x80A")
    envelope = build_send_envelope(receipt, b"\x00\xff\x80A", symbols, profile)
    carrier = bytearray.fromhex(envelope["carriers"][0])
    symbol = bytes.fromhex(envelope["symbols"][0])
    symbol_offset = carrier.find(symbol)
    assert symbol_offset >= 0
    carrier[symbol_offset] ^= 0x01
    envelope["carriers"][0] = carrier.hex()
    envelope["carrier_unit_sha256"][0] = sha256_hex(bytes(carrier))

    with pytest.raises(
        EnvelopeValidationError, match="carrier bytes do not match envelope symbols"
    ):
        parse_envelope_symbols(envelope, profile)


def test_parse_envelope_wraps_unparseable_carrier_bytes():
    profile, receipt, symbols = _send_payload("http2-ping-opaque", b"\x00\xff\x80A")
    envelope = build_send_envelope(receipt, b"\x00\xff\x80A", symbols, profile)
    envelope["carriers"][0] = "00"
    envelope["carrier_unit_sha256"][0] = sha256_hex(b"\x00")

    with pytest.raises(EnvelopeValidationError, match="carrier bytes could not be parsed"):
        parse_envelope_symbols(envelope, profile)


def test_parse_envelope_rejects_partial_carrier_list():
    profile, receipt, symbols = _send_payload("rtp-rtcp-ext-app", b"longer payload")
    envelope = build_send_envelope(receipt, b"longer payload", symbols, profile)
    envelope["carriers"] = envelope["carriers"][:-1]

    with pytest.raises(
        EnvelopeValidationError, match="carrier count does not match envelope symbol count"
    ):
        parse_envelope_symbols(envelope, profile)
