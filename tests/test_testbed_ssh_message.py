"""Paired paramiko client/server SSH KEXINIT carrier.

RFC 4253 §7.1 gives SSH_MSG_KEXINIT a 16-byte random cookie and a trailing
``uint32 0`` reserved field. This carries bytes only in the cookie, builds a real
KEXINIT with paramiko's ``Message`` codec, and verifies that the reserved word remains
zero when the server role parses it.
"""

from __future__ import annotations

import pytest

pytest.importorskip("paramiko")

from celatim.pdu.ssh_kex import KEXINIT_CARRIER_LEN
from celatim.testbed.ssh_message import (
    build_kexinit,
    parse_kexinit,
    run_paramiko_kexinit_roundtrip,
)


def test_kexinit_carries_cookie_and_preserves_reserved_zero():
    symbol = bytes(range(KEXINIT_CARRIER_LEN))
    wire = build_kexinit(symbol)
    assert wire[0] == 20  # SSH_MSG_KEXINIT
    assert len(wire) > KEXINIT_CARRIER_LEN  # a real KEXINIT with name-lists, not a blob
    assert wire[-4:] == bytes(4)
    assert parse_kexinit(wire) == symbol


def test_kexinit_parser_rejects_nonzero_reserved_word():
    wire = build_kexinit(bytes(KEXINIT_CARRIER_LEN))
    with pytest.raises(ValueError, match="reserved uint32 must be zero"):
        parse_kexinit(wire[:-4] + b"\x00\x00\x00\x01")


def test_zero_control_recovers_zero_carrier():
    symbol = bytes(KEXINIT_CARRIER_LEN)
    assert parse_kexinit(build_kexinit(symbol)) == symbol


def test_paired_roundtrip_recovers_each_symbol_with_provenance():
    symbols = [bytes(range(16)), b"\xff" * 16, b"ssh-kexinit-test"]
    result = run_paramiko_kexinit_roundtrip(symbols)

    assert result.recovered == symbols
    doc = result.to_json()
    assert doc["transport"] == "ssh_kexinit_paramiko"
    assert doc["client_role"] == "paramiko.Message(KEXINIT)"
    assert doc["server_role"] == "paramiko.Message.parse"
    assert doc["independent_validator"] == "paramiko_message_codec"
    assert all(ex["recovered"] for ex in doc["exchanges"])
