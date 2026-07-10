"""RTCP APP real-PDU fixture for the marquee support-matrix upgrade."""

from pathlib import Path

import pytest

from celatim.catalog import load_mechanisms
from celatim.pdu import (
    RTCP_APP_DATA_LEN,
    RTCP_APP_HEADER_LEN,
    RTCP_APP_PACKET_TYPE,
    app_data_offset,
    build_app_packet,
    parse_app_packet,
)

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def test_rtcp_app_fixture_has_real_surrounding_pdu_bytes():
    app_data = bytes(range(RTCP_APP_DATA_LEN))
    packet = build_app_packet(app_data)
    parsed = parse_app_packet(packet)

    assert packet[app_data_offset() : app_data_offset() + RTCP_APP_DATA_LEN] == app_data
    assert parsed.is_app
    assert parsed.packet_type == RTCP_APP_PACKET_TYPE
    assert parsed.ssrc == 0x1122_3344
    assert parsed.name == b"RFCX"
    assert parsed.app_data == app_data
    assert any(b != 0 for b in packet[:RTCP_APP_HEADER_LEN])


def test_rtcp_app_catalog_locator_targets_parsed_application_data():
    m = next(x for x in load_mechanisms(DATA) if x.id == "rtp-rtcp-ext-app")
    assert m.locator is not None
    # NH-base locator includes a 20-byte IPv4 header and 8-byte UDP header before
    # the RTCP payload. The carrier is the APP application-dependent data field.
    assert m.locator.bit_offset == (20 + 8 + app_data_offset()) * 8
    assert m.locator.bit_width == RTCP_APP_DATA_LEN * 8


def test_wrong_nominal_payload_offset_does_not_modify_parsed_app_data():
    packet = bytearray(build_app_packet(b"\x00" * RTCP_APP_DATA_LEN))
    packet[:RTCP_APP_DATA_LEN] = bytes(range(RTCP_APP_DATA_LEN))

    with pytest.raises(ValueError):
        parse_app_packet(bytes(packet))
