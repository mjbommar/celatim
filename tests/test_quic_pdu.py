"""QUIC long-header DCID real-PDU fixture for the marquee support-matrix upgrade."""

from pathlib import Path

import pytest

from celatim.catalog import load_mechanisms
from celatim.pdu import DCID_LEN, build_initial_packet, dcid_offset, parse_long_header

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def test_quic_initial_fixture_has_real_surrounding_pdu_bytes():
    dcid = bytes(range(DCID_LEN))
    packet = build_initial_packet(dcid)
    parsed = parse_long_header(packet)

    assert packet[dcid_offset() : dcid_offset() + DCID_LEN] == dcid
    assert parsed.is_v1_initial
    assert parsed.dcid == dcid
    assert parsed.scid == b"server01"
    assert parsed.packet_number == 1
    assert any(b != 0 for b in packet[: dcid_offset()])
    assert any(b != 0 for b in packet[dcid_offset() + DCID_LEN :])


def test_quic_connection_id_catalog_locator_targets_parsed_dcid():
    m = next(x for x in load_mechanisms(DATA) if x.id == "quic-connection-id")
    assert m.locator is not None
    # NH-base locator includes a 20-byte IPv4 header and 8-byte UDP header before
    # the QUIC payload. The carrier is the 20-byte DCID in a real long header.
    assert m.locator.bit_offset == (20 + 8 + dcid_offset()) * 8
    assert m.locator.bit_width == DCID_LEN * 8


def test_wrong_nominal_payload_offset_does_not_modify_parsed_dcid():
    packet = bytearray(build_initial_packet(b"\x00" * DCID_LEN))
    packet[:DCID_LEN] = bytes(range(DCID_LEN))  # the old zero-blob model wrote at payload start

    with pytest.raises(ValueError):
        parse_long_header(bytes(packet))
