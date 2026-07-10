"""C ground-truth cross-check: field/header widths from system <netinet/*> headers
measured via the cmeasure tool must match the catalog's bit accounting."""

import shutil
from pathlib import Path

import pytest

from celatim.catalog import load_mechanisms
from celatim.layout import header_facts

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"

_no_toolchain = shutil.which("make") is None or (
    shutil.which("cc") is None and shutil.which("gcc") is None
)
pytestmark = pytest.mark.skipif(_no_toolchain, reason="C toolchain (cc/gcc + make) unavailable")


def test_c_facts_have_expected_sizes():
    facts = header_facts()
    assert facts["ipv4_header_bits"] == 160
    assert facts["ipv4_id_bits"] == 16
    assert facts["tcp_header_bits"] == 160


def test_catalog_capacity_matches_c_ground_truth():
    facts = header_facts()
    mechs = {m.id: m for m in load_mechanisms(DATA)}

    # IPv4 ID: covert-field width measured directly from the C struct field.
    ip = mechs["ipv4-id-atomic"]
    assert ip.c_capacity_key is not None
    assert ip.c_header_key is not None
    assert facts[ip.c_capacity_key] == ip.raw_capacity_bits
    assert facts[ip.c_header_key] == ip.header_bits

    # TCP reserved bits: sub-byte bitfield (capacity is spec-sourced), but the
    # header-size denominator is cross-checked against the C struct.
    tcp = mechs["tcp-reserved-bits"]
    assert tcp.c_header_key is not None
    assert facts[tcp.c_header_key] == tcp.header_bits
