"""Paired dnspython client/server TXT-tunnel carrier.

A DNS TXT record's character-strings are arbitrary bytes by spec, so a resolver
returning covert bytes in a TXT answer is conforming. This exercises a real DNS
message exchange with two roles in one process: a client builds the query, an
independent server builds the response carrying covert bytes, and the client
re-parses the wire with dnspython as the independent validator.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("dns")

from celatim.testbed.dns_message import (
    build_null_response,
    build_txt_response,
    parse_null_response,
    parse_txt_response,
    run_dnspython_null_roundtrip,
    run_dnspython_txt_roundtrip,
)

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def test_txt_response_roundtrips_arbitrary_bytes():
    covert = bytes(range(256))[:255]  # full byte range, one max-length TXT string
    wire = build_txt_response("covert.example.", covert)
    assert isinstance(wire, bytes) and len(wire) > len(covert)  # real DNS message
    assert parse_txt_response(wire) == covert


def test_zero_length_control_recovers_empty():
    wire = build_txt_response("covert.example.", b"")
    assert parse_txt_response(wire) == b""


def test_paired_roundtrip_recovers_each_symbol_with_provenance():
    symbols = [b"alpha-covert-bytes", b"\x00\x01\x02\x03payload", b"z" * 200]
    result = run_dnspython_txt_roundtrip(symbols, qname="covert.example.")

    assert result.recovered == symbols
    doc = result.to_json()
    assert doc["transport"] == "dns_txt_dnspython"
    assert doc["symbol_count"] == len(symbols)
    # both roles are real, independent dnspython message objects.
    assert doc["client_role"] == "dns.message.make_query"
    assert doc["server_role"] == "dns.message.make_response"
    assert doc["independent_validator"] == "dnspython_from_wire"
    assert all(ex["recovered"] for ex in doc["exchanges"])


def test_null_record_roundtrips_arbitrary_bytes():
    covert = bytes(range(256))  # full byte range, NULL RDATA is "anything at all"
    wire = build_null_response("covert.example.", covert)
    assert parse_null_response(wire) == covert


def test_paired_null_roundtrip_recovers_each_symbol():
    symbols = [b"\x00\x01\x02null-covert", b"q" * 300, b""]
    result = run_dnspython_null_roundtrip(symbols)

    assert result.recovered == symbols
    doc = result.to_json()
    assert doc["transport"] == "dns_null_dnspython"
    assert all(ex["record"] == "NULL" for ex in doc["exchanges"])
