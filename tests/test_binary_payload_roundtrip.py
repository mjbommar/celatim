"""Exact binary-payload round trips across every usable mechanism."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

pytest.importorskip("scapy")

from celatim.adapter import adapter_for
from celatim.catalog import load_mechanisms

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"
PAYLOAD = hashlib.shake_256(b"celatim-1kb-proof").digest(1024)
USABLE_MECHANISMS = tuple(m for m in load_mechanisms(DATA) if m.is_usable_channel)


@pytest.mark.parametrize("mechanism", USABLE_MECHANISMS, ids=lambda mechanism: mechanism.id)
def test_every_usable_mechanism_roundtrips_1kb_binary_payload(mechanism):
    adapter = adapter_for(mechanism)

    units = adapter.encode_payload(PAYLOAD)

    assert adapter.decode_units(units) == PAYLOAD
