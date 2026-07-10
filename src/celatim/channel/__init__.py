"""Channel layer: encode/decode covert payload bits into protocol field values.

Pure and dependency-free (stdlib only); no network, no privilege. This is where
capacity and round-trip fidelity are established and property-tested. The transport
layer (putting the encoded field on a real wire in a controlled testbed) sits above
it and is kept separate so the science here runs anywhere."""

from __future__ import annotations

from .bits import BitReader, BitWriter
from .codec import Codec, FixedWidthCodec, SymbolChoiceCodec, VariableLengthCodec
from .driver import Channel, IdealWire, MiddleboxWire, Wire
from .framer import Framer
from .registry import AnyCodec, build_registry, codec_for

__all__ = [
    "AnyCodec",
    "BitReader",
    "BitWriter",
    "Channel",
    "Codec",
    "FixedWidthCodec",
    "Framer",
    "IdealWire",
    "MiddleboxWire",
    "SymbolChoiceCodec",
    "VariableLengthCodec",
    "Wire",
    "build_registry",
    "codec_for",
]
