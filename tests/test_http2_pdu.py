"""HTTP/2 PING real-PDU fixture for the marquee support-matrix upgrade."""

from pathlib import Path

import pytest

from celatim.catalog import load_mechanisms
from celatim.pdu import (
    HTTP2_PREFACE,
    build_connection_preface_ping,
    parse_frames,
    ping_opaque_offset,
)

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def test_http2_ping_fixture_has_real_surrounding_pdu_bytes():
    opaque = b"ABCDEFGH"
    pdu = build_connection_preface_ping(opaque)

    assert pdu.startswith(HTTP2_PREFACE)
    assert pdu[ping_opaque_offset() : ping_opaque_offset() + 8] == opaque
    assert any(b != 0 for b in pdu[: ping_opaque_offset()])

    frames = parse_frames(pdu)
    assert [(f.frame_type, f.length, f.stream_id) for f in frames] == [(4, 0, 0), (6, 8, 0)]
    assert frames[-1].is_ping
    assert frames[-1].payload == opaque


def test_http2_ping_catalog_locator_targets_parsed_opaque_field():
    m = next(x for x in load_mechanisms(DATA) if x.id == "http2-ping-opaque")
    assert m.locator is not None
    # NH-base locator includes a 20-byte IPv4 header and a 20-byte TCP header before
    # the HTTP/2 payload. The PING opaque field is inside a real HTTP/2 byte sequence.
    assert m.locator.bit_offset == (20 + 20 + ping_opaque_offset()) * 8
    assert m.locator.bit_width == 64


def test_wrong_nominal_payload_offset_does_not_modify_parsed_ping_opaque():
    original = build_connection_preface_ping(b"\x00" * 8)
    wrong = bytearray(original)
    wrong[:8] = b"ABCDEFGH"  # the old zero-blob model wrote at the payload start

    with pytest.raises(ValueError):
        parse_frames(bytes(wrong))
