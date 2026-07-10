"""Channel end-to-end: clean path round-trips; a scrubbing middlebox kills it."""

from pathlib import Path

from celatim.catalog import load_mechanisms
from celatim.channel.codec import FixedWidthCodec
from celatim.channel.driver import Channel, IdealWire, MiddleboxWire
from celatim.channel.registry import codec_for

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def test_ideal_wire_roundtrips():
    channel = Channel(FixedWidthCodec(4), IdealWire())
    assert channel.transmit(b"covert!") == b"covert!"


def test_scrubbing_middlebox_destroys_the_channel():
    # A normalizer that zeros the field wipes the length prefix -> payload lost.
    channel = Channel(FixedWidthCodec(4), MiddleboxWire(lambda _s: 0))
    assert channel.transmit(b"covert!") == b""


def test_every_storage_mechanism_drives_over_ideal_wire():
    # The int-symbol mechanisms drive end to end through the registry's codec.
    for m in load_mechanisms(DATA):
        codec = codec_for(m)
        if not isinstance(codec, FixedWidthCodec):
            continue
        channel = Channel(codec, IdealWire())
        assert channel.transmit(b"hi") == b"hi"
