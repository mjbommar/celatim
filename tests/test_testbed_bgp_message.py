"""Paired scapy BGP speaker/peer optional-transitive attribute carrier.

An optional-transitive BGP path attribute of an unknown type is, by RFC 4271, passed
on unchanged by routers that do not recognize it -- a multi-hop covert carrier. A
speaker builds a real BGP UPDATE with scapy's BGP codec; a peer re-parses it with the
same codec as the independent validator.
"""

from __future__ import annotations

import pytest

pytest.importorskip("scapy")

from celatim.testbed.bgp_message import (
    build_bgp_update,
    parse_bgp_update,
    run_scapy_bgp_roundtrip,
)


def test_optional_transitive_attribute_roundtrips_arbitrary_bytes():
    covert = bytes((i * 7) % 256 for i in range(1000))  # exceeds the 1-byte length field
    wire = build_bgp_update(covert)
    assert wire[18] == 2  # BGP UPDATE message type after the 16-byte marker + length
    assert parse_bgp_update(wire) == covert


def test_short_value_and_empty_control():
    assert parse_bgp_update(build_bgp_update(b"hello-bgp")) == b"hello-bgp"
    assert parse_bgp_update(build_bgp_update(b"")) == b""


def test_paired_roundtrip_recovers_each_symbol_with_provenance():
    symbols = [b"bgp-covert", b"\x00\x01\x02attr", b"z" * 600]
    result = run_scapy_bgp_roundtrip(symbols)

    assert result.recovered == symbols
    doc = result.to_json()
    assert doc["transport"] == "bgp_scapy"
    assert doc["client_role"] == "scapy.BGPUpdate(optional-transitive)"
    assert doc["server_role"] == "scapy.BGPHeader.parse"
    assert doc["independent_validator"] == "scapy_bgp_codec"
    assert all(ex["recovered"] for ex in doc["exchanges"])
