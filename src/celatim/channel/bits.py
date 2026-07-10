"""Bit-level pack/unpack primitives (MSB-first) — the DRY foundation under every
storage codec. A payload is chunked into field-width symbols by a ``BitWriter``
and reassembled by a ``BitReader``; field order on the wire is most-significant
bit first, matching how RFC packet diagrams number bits."""

from __future__ import annotations


class BitWriter:
    """Accumulate integer values of given bit widths, MSB-first, into bytes."""

    def __init__(self) -> None:
        self._acc = 0
        self._nbits = 0

    def write(self, value: int, width: int) -> None:
        if width < 0:
            raise ValueError("width must be >= 0")
        if width == 0:
            return
        if not 0 <= value < (1 << width):
            raise ValueError(f"value {value} does not fit in {width} bits")
        self._acc = (self._acc << width) | value
        self._nbits += width

    @property
    def nbits(self) -> int:
        return self._nbits

    def getvalue(self) -> bytes:
        """Accumulated bits, MSB-first, zero-padded up to a byte boundary."""
        if self._nbits == 0:
            return b""
        pad = (-self._nbits) % 8
        nbytes = (self._nbits + pad) // 8
        return (self._acc << pad).to_bytes(nbytes, "big")


class BitReader:
    """Read integer values of given bit widths, MSB-first, from a byte buffer."""

    def __init__(self, data: bytes) -> None:
        self._value = int.from_bytes(data, "big") if data else 0
        self._total = len(data) * 8
        self._pos = 0  # bits consumed from the MSB end

    def read(self, width: int) -> int:
        if width < 0:
            raise ValueError("width must be >= 0")
        if width == 0:
            return 0
        if self._pos + width > self._total:
            raise EOFError("read past end of bit buffer")
        shift = self._total - self._pos - width
        self._pos += width
        return (self._value >> shift) & ((1 << width) - 1)

    @property
    def remaining(self) -> int:
        return self._total - self._pos
