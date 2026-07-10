"""Generic Scapy carrier wiring in the mechanism adapter.

Located L3/L4 rows were already *classified* as real-PDU evidence, but only four
fixtures plus the TCP template had executable carrier-building code. The Scapy
scaffold substantiates the classification: these rows now build a real PDU, place
covert bits at the locator, and recover them through an independent Scapy dissect.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("scapy")

from celatim.adapter import AdapterCapability, AdapterPathKind, adapter_for
from celatim.catalog import load_mechanisms

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"

SCAPY_ROWS = (
    "ipv4-id-atomic",
    "tcp-urgent-ptr",
    "tcp-isn",
    "ipv4-tos-dscp",
    "ipv4-reserved-flag",
    "ipv6-flow-label",
    "icmpv4-unused",
    "icmpv6-unused",
    "igmpv2-maxresp",
    "ah-reserved",
    "rtp-appbits",
    "vxlan-reserved",
    "bfd-auth-reserved",
    "isakmp-reserved",
    "gre-reserved",
    "stun-transmit-counter",
    "pim-sm-reserved",
    "diameter-flags-padding",
    "ospfv2-auth-null",
    "sctp-ppid",
    "ldp-reserved",
    "mldv1-reserved",
    "dhcp-option-tunnel",
    "ikev2-reserved",
    "nvgre-flowid",
    "mpls-exp-tc",
)


def mechs_by_id():
    return {m.id: m for m in load_mechanisms(DATA)}


@pytest.mark.parametrize("mid", SCAPY_ROWS)
def test_scapy_row_has_executable_real_pdu_carrier(mid):
    adapter = adapter_for(mechs_by_id()[mid])
    assert adapter.supports_carrier_bytes
    assert AdapterCapability.PACKET_PATH_TEMPLATE in adapter.capabilities
    assert AdapterCapability.PARSER_VALIDATED in adapter.capabilities
    assert AdapterPathKind.SCAPY_PACKET.value in adapter.path_kinds


@pytest.mark.parametrize("mid", SCAPY_ROWS)
def test_scapy_row_roundtrips_a_payload_through_real_pdus(mid):
    adapter = adapter_for(mechs_by_id()[mid])
    payload = b"\x00\xff\x80\x10owl"

    units = adapter.encode_payload(payload)
    assert units
    assert all(unit.has_carrier_bytes for unit in units)
    # each carrier byte string parses back to the symbol that built it,
    assert all(adapter.parse_carrier(unit.carrier) == unit.symbol for unit in units)
    # and the whole payload decodes from the carrier bytes alone.
    assert adapter.decode_units(units) == payload


def test_scapy_path_requires_packet_extra():
    adapter = adapter_for(mechs_by_id()["ipv4-tos-dscp"])
    path = adapter.path_for_transport("scapy_packet")
    assert path is not None
    assert path.evidence_tier == "real_pdu_packet_path"
    assert "packet" in path.required_extras
