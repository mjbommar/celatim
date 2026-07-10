"""Codecs: map a covert *symbol* (an integer in ``[0, 2**capacity_bits)``) to and
from the on-wire field value of one mechanism.

The codec owns only the field semantics; the :class:`~celatim.channel.framer.Framer`
owns splitting a payload into symbols, so the bit-stream machinery stays in one place
and the codecs stay tiny. Working backwards from the ~90 mechanisms, three shapes
cover every carrier class:

* :class:`FixedWidthCodec` — Class A reserved/MBZ bits and small Class C fields; the
  symbol *is* the field value.
* :class:`SymbolChoiceCodec` — Class D reserved codepoints and Class F count/timing
  channels; the covert content is *which* of ``num_symbols`` options, so capacity is
  ``floor(log2(num_symbols))`` (a fixed-width field parameterised by alphabet size).
* :class:`VariableLengthCodec` — Class B padding, Class E blobs, Class G salt/nonce,
  and large opaque Class C fields; the symbol is a big integer rendered to bytes."""

from __future__ import annotations

from abc import ABC, abstractmethod


class Codec[T](ABC):
    """Maps a covert symbol to/from a field value of wire type ``T``."""

    @property
    @abstractmethod
    def capacity_bits(self) -> int:
        """Covert bits carried per use of this field."""

    @abstractmethod
    def encode_symbol(self, symbol: int) -> T:
        """Render a symbol in ``[0, 2**capacity_bits)`` to its on-wire field value."""

    @abstractmethod
    def decode_symbol(self, field: T) -> int:
        """Recover the symbol from a received field value."""


class FixedWidthCodec(Codec[int]):
    """A field of ``width`` bits whose entire value range is settable; symbol == value."""

    def __init__(self, width: int) -> None:
        if width <= 0:
            raise ValueError(f"width must be positive, got {width}")
        self._width = width

    @property
    def capacity_bits(self) -> int:
        return self._width

    def encode_symbol(self, symbol: int) -> int:
        if not 0 <= symbol < (1 << self._width):
            raise ValueError(f"symbol {symbol} does not fit in {self._width} bits")
        return symbol

    def decode_symbol(self, field: int) -> int:
        return field


class SymbolChoiceCodec(FixedWidthCodec):
    """Encode bits by choosing one of ``num_symbols`` discrete options (a reserved
    codepoint, a padding-frame count, a timing bucket). Capacity is the largest
    whole-bit field that fits the alphabet, ``floor(log2(num_symbols))``."""

    def __init__(self, num_symbols: int) -> None:
        if num_symbols < 2:
            raise ValueError(f"need at least 2 symbols to carry a bit, got {num_symbols}")
        super().__init__(num_symbols.bit_length() - 1)
        self.num_symbols = num_symbols


class VariableLengthCodec(Codec[bytes]):
    """``length`` free bytes (padding / blob / salt); capacity is ``length * 8`` bits."""

    def __init__(self, length: int) -> None:
        if length <= 0:
            raise ValueError(f"length must be positive, got {length}")
        self._length = length

    @property
    def capacity_bits(self) -> int:
        return self._length * 8

    def encode_symbol(self, symbol: int) -> bytes:
        if not 0 <= symbol < (1 << self.capacity_bits):
            raise ValueError(f"symbol does not fit in {self.capacity_bits} bits")
        return symbol.to_bytes(self._length, "big")

    def decode_symbol(self, field: bytes) -> int:
        return int.from_bytes(field, "big")
