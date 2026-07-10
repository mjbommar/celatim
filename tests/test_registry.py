"""Registry: every catalog mechanism maps to a codec that round-trips a payload."""

from pathlib import Path

import pytest

from celatim.catalog import load_mechanisms
from celatim.channel.framer import Framer
from celatim.channel.registry import build_registry, codec_for

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def mechs():
    return load_mechanisms(DATA)


def test_every_mechanism_gets_a_codec():
    reg = build_registry(mechs())
    assert set(reg) == {m.id for m in mechs()}


def test_codec_capacity_matches_catalog():
    # the channel layer and the structural metric agree on bits per carrier unit.
    for m in mechs():
        assert codec_for(m).capacity_bits == m.raw_capacity_bits


def test_class_dispatch_spans_the_three_shapes():
    by_id = {m.id: codec_for(m) for m in mechs()}
    from celatim.channel.codec import (
        FixedWidthCodec,
        SymbolChoiceCodec,
        VariableLengthCodec,
    )

    assert isinstance(by_id["tcp-reserved-bits"], FixedWidthCodec)  # A
    assert isinstance(by_id["ipv4-id-atomic"], FixedWidthCodec)  # small C
    assert isinstance(by_id["http3-reserved-frame-types"], VariableLengthCodec)  # unbounded D
    assert isinstance(by_id["quic-padding-frame-count"], SymbolChoiceCodec)  # F count
    assert isinstance(by_id["rsa-pss-salt"], VariableLengthCodec)  # G salt bytes


@pytest.mark.parametrize("payload", [b"", b"\x01", b"covert payload!"])
def test_roundtrip_through_each_mechanism(payload):
    for m in mechs():
        framer = Framer(codec_for(m))
        assert framer.decode(framer.encode(payload)) == payload


def test_full_catalog_coverage():
    from celatim.model import CarrierClass

    ms = mechs()
    # the migration covers the whole corpus sweep: a substantial catalog spanning
    # every carrier class, each mechanism driving a multi-carrier-unit payload.
    assert len(ms) >= 100
    assert {m.carrier_class for m in ms} == set(CarrierClass)
    big = b"the quick brown fox" * 4  # forces many carrier units even at 1 bit/field
    for m in ms:
        framer = Framer(codec_for(m))
        assert framer.decode(framer.encode(big)) == big
