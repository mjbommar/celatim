"""Class A-E storage-channel capacity metrics."""

import math
from pathlib import Path

import pytest

from celatim.catalog import load_mechanisms
from celatim.metrics import density_header, density_wire, raw_bits, throughput_bps

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def mechs():
    return {m.id: m for m in load_mechanisms(DATA)}


def test_ipv4_id_metrics():
    m = mechs()["ipv4-id-atomic"]
    assert raw_bits(m) == 16
    assert math.isclose(density_header(m), 16 / 160)
    assert math.isclose(density_wire(m), 16 / 12000)
    # 16 bits/packet at 1000 packets/s = 16 kbit/s
    assert math.isclose(throughput_bps(m, 1000), 16000)


def test_tcp_reserved_density():
    m = mechs()["tcp-reserved-bits"]
    assert math.isclose(density_header(m), 3 / 160)


def test_quic_spin_density():
    m = mechs()["quic-spin-bit"]
    assert raw_bits(m) == 1
    assert math.isclose(density_header(m), 1 / 16)


def test_density_rejected_for_timing_channel():
    m = mechs()["quic-padding-frame-count"]  # Class F
    with pytest.raises(ValueError):
        density_header(m)
    with pytest.raises(ValueError):
        density_wire(m)


def test_density_rejected_for_subliminal_channel():
    m = mechs()["rsa-pss-salt"]  # Class G
    with pytest.raises(ValueError):
        density_header(m)


def test_raw_bits_still_available_for_nonstorage():
    # raw_bits is a plain representative count, valid for every class.
    assert raw_bits(mechs()["rsa-pss-salt"]) == 256
