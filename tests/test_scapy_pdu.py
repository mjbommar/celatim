"""Generic Scapy-backed real-PDU scaffold for located packet-class mechanisms.

Scapy builds a realistic surrounding PDU (correct neighboring fields, recomputed
checksums); the covert field is written MSB-first at the mechanism's locator. The
point is to promote a row from a zero-blob offset to a real PDU with an independent
dissector, so these tests assert: the field round-trips, the surrounding bytes are
non-zero (a real header, not a zero blob), Scapy independently dissects the carrier,
a benign (zero) control reads back zero, and a wrong-offset read does not recover
the value.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("scapy")

from celatim.catalog import load_mechanisms
from celatim.pdu import scapy_pdu

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"

# Representative located header-bit/flag rows the scaffold supports, spanning
# IPv4/IPv6/TCP/UDP/ICMP base layers.
SUPPORTED_SAMPLE = (
    "tcp-reserved-bits",
    "ipv4-reserved-flag",
    "ipv4-tos-dscp",
    "tcp-urgent-ptr",
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
)


def mechs_by_id():
    return {m.id: m for m in load_mechanisms(DATA)}


def test_supports_known_packet_rows_and_rejects_non_packet():
    mechs = mechs_by_id()
    for mid in SUPPORTED_SAMPLE:
        assert scapy_pdu.supports(mechs[mid]), mid
    # an application/crypto row with no kernel packet path is not supported here.
    assert not scapy_pdu.supports(mechs["rsa-pss-salt"])


@pytest.mark.parametrize("mid", SUPPORTED_SAMPLE)
def test_field_roundtrips_in_real_pdu(mid):
    mech = mechs_by_id()[mid]
    width = mech.locator.bit_width
    full = (1 << width) - 1
    value = full ^ (0b10 if width >= 2 else 0)  # a non-trivial in-range value

    carrier = scapy_pdu.build_real_pdu(mech, value)
    assert scapy_pdu.extract_field(mech, carrier) == value


@pytest.mark.parametrize("mid", SUPPORTED_SAMPLE)
def test_carrier_is_a_real_pdu_not_a_zero_blob(mid):
    mech = mechs_by_id()[mid]
    carrier = scapy_pdu.build_real_pdu(mech, 0)
    # a real header has non-zero neighboring bytes (ports, addresses, checksum...).
    assert any(b != 0 for b in carrier)
    # and Scapy independently dissects it into a well-formed PDU.
    scapy_pdu.dissect(mech, carrier)  # raises on malformed


@pytest.mark.parametrize("mid", SUPPORTED_SAMPLE)
def test_benign_zero_control_reads_zero(mid):
    mech = mechs_by_id()[mid]
    carrier = scapy_pdu.build_real_pdu(mech, 0)
    assert scapy_pdu.extract_field(mech, carrier) == 0


def test_wrong_offset_does_not_recover_value():
    mech = mechs_by_id()["ipv4-tos-dscp"]  # 8-bit field, distinctive value
    value = 0xA5
    carrier = scapy_pdu.build_real_pdu(mech, value)
    shifted = scapy_pdu.extract_field_at(
        carrier, mech.locator.bit_offset + 8, mech.locator.bit_width
    )
    assert shifted != value


def test_checksum_is_recomputed_for_tcp():
    # placing covert bits then rebuilding must leave a self-consistent checksum:
    # re-dissecting and re-serializing the carrier is stable.
    mech = mechs_by_id()["tcp-reserved-bits"]
    carrier = scapy_pdu.build_real_pdu(mech, 0xD)
    assert scapy_pdu.checksum_valid(mech, carrier)


def test_mldv1_reserved_roundtrips_across_checksum_gap():
    mech = mechs_by_id()["mldv1-reserved"]
    value = 0xA1B2C3D4E5

    carrier = scapy_pdu.build_real_pdu(mech, value)

    assert scapy_pdu.extract_field(mech, carrier) == value
    assert (
        scapy_pdu.extract_field_at(carrier, mech.locator.bit_offset, mech.locator.bit_width)
        != value
    )
