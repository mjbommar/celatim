"""Paired aiocoap client/server CoAP payload carrier.

A CoAP message payload is arbitrary application data, so carrying covert bytes is
conforming. A client builds a real CoAP message with aiocoap's wire codec; a server
re-parses it with aiocoap as the independent validator.
"""

from __future__ import annotations

import pytest

pytest.importorskip("aiocoap")

from celatim.testbed.coap_message import (
    build_coap_message,
    parse_coap_message,
    run_aiocoap_roundtrip,
)


def test_coap_payload_roundtrips_arbitrary_bytes():
    covert = bytes(range(32))
    wire = build_coap_message(covert)
    assert len(wire) > len(covert)  # a real CoAP header precedes the payload
    assert parse_coap_message(wire) == covert


def test_empty_control_recovers_empty():
    assert parse_coap_message(build_coap_message(b"")) == b""


def test_paired_roundtrip_recovers_each_symbol_with_provenance():
    symbols = [b"coap-covert-bytes", b"\x00\x01\x02\x03payload", b"k" * 64]
    result = run_aiocoap_roundtrip(symbols)

    assert result.recovered == symbols
    doc = result.to_json()
    assert doc["transport"] == "coap_aiocoap"
    assert doc["client_role"] == "aiocoap.Message.encode"
    assert doc["server_role"] == "aiocoap.Message.decode"
    assert doc["independent_validator"] == "aiocoap_message_codec"
    assert all(ex["recovered"] for ex in doc["exchanges"])
