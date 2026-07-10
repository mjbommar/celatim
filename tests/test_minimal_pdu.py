"""Minimal real-PDU carriers for protocols without a dedicated Scapy layer."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("scapy")

from celatim.catalog import load_mechanisms
from celatim.pdu import minimal_pdu

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"

ROWS = (
    "ipcomp-flags",
    "amt-reserved",
    "pcp-reserved",
    "nhrp-reserved",
    "capwap-reserved",
    "tcpcrypt-reserved",
    "hip-locator-reserved",
    "pcep-reserved",
    "bmp-reserved",
    "lisp-gpe-bits",
)


def mechs():
    return {m.id: m for m in load_mechanisms(DATA)}


def test_supports_registered_rows_and_rejects_others():
    m = mechs()
    for mid in ROWS:
        assert minimal_pdu.supports(m[mid]), mid
    assert not minimal_pdu.supports(m["tcp-reserved-bits"])  # has a real Scapy layer


@pytest.mark.parametrize("mid", ROWS)
def test_minimal_pdu_roundtrips_in_real_ip_framing(mid):
    mech = mechs()[mid]
    width = mech.locator.bit_width
    value = ((1 << width) - 1) ^ (2 if width >= 2 else 0)

    carrier = minimal_pdu.build_minimal_pdu(mech, value)
    assert any(b != 0 for b in carrier)  # real IP framing + header, not a zero blob
    minimal_pdu.dissect(mech, carrier)  # Scapy validates the IP framing
    assert minimal_pdu.extract_field(mech, carrier) == value


@pytest.mark.parametrize("mid", ROWS)
def test_zero_control_reads_zero(mid):
    mech = mechs()[mid]
    assert minimal_pdu.extract_field(mech, minimal_pdu.build_minimal_pdu(mech, 0)) == 0
