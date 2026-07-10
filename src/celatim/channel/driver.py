"""Drive a mechanism end to end: payload -> symbols -> wire -> symbols -> payload.

The wire is abstract. An :class:`IdealWire` passes symbols through unchanged (a clean
path); a :class:`MiddleboxWire` applies a per-symbol transform, which is how a
normalizer or scrubber is modelled in memory — zeroing a reserved field, for
instance, corrupts the length prefix and the payload does not survive. The real
testbed (raw sockets, real TLS/QUIC stacks) implements the same :class:`Wire`
protocol, so the codec/framer above it are exercised identically whether the wire is
in memory or on a NIC."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from .codec import Codec
from .framer import Framer


class Wire[T](Protocol):
    """A path that carries field symbols, possibly altering them."""

    def transmit(self, symbols: list[T]) -> list[T]: ...


class IdealWire[T]:
    """A clean path: every symbol arrives unchanged."""

    def transmit(self, symbols: list[T]) -> list[T]:
        return list(symbols)


class MiddleboxWire[T]:
    """A path with an in-line device that rewrites each symbol (NAT, normalizer)."""

    def __init__(self, transform: Callable[[T], T]) -> None:
        self._transform = transform

    def transmit(self, symbols: list[T]) -> list[T]:
        return [self._transform(s) for s in symbols]


class Channel[T]:
    """A codec + framer over a wire: send a payload, recover what survives."""

    def __init__(self, codec: Codec[T], wire: Wire[T]) -> None:
        self._framer = Framer(codec)
        self._wire = wire

    def transmit(self, payload: bytes) -> bytes:
        """Encode, carry across the wire, and decode what arrives."""
        received = self._wire.transmit(self._framer.encode(payload))
        return self._framer.decode(received)
