"""Carry a whole payload across many carrier units.

A single field holds only ``codec.capacity_bits`` bits, so a real message is split
across many carrier units (packets, segments, records). The :class:`Framer` prefixes
a length header so the stream is self-delimiting, reads one symbol's worth of bits per
carrier unit (zero-padding the final symbol), hands each symbol to the codec, and
reverses the process on receipt. It is generic over the codec's wire type, so it
serves the int-valued and bytes-valued codecs unchanged."""

from __future__ import annotations

from math import ceil

from .bits import BitReader, BitWriter
from .codec import Codec

_LENGTH_BYTES = 2  # payload length prefix; supports payloads up to 65535 bytes
_MAX_PAYLOAD = (1 << (_LENGTH_BYTES * 8)) - 1
MAX_PAYLOAD_BYTES = _MAX_PAYLOAD


class Framer[T]:
    """Split a length-prefixed payload into carrier-unit symbols and back."""

    def __init__(self, codec: Codec[T]) -> None:
        self._codec = codec

    def encode(self, payload: bytes) -> list[T]:
        """Return one field value per carrier unit needed to carry ``payload``."""
        if len(payload) > _MAX_PAYLOAD:
            raise ValueError(f"payload exceeds {_MAX_PAYLOAD} bytes")
        framed = len(payload).to_bytes(_LENGTH_BYTES, "big") + payload
        cap = self._codec.capacity_bits
        reader = BitReader(framed)
        n_symbols = ceil(len(framed) * 8 / cap)

        fields: list[T] = []
        for _ in range(n_symbols):
            take = min(cap, reader.remaining)
            symbol = reader.read(take) << (cap - take)  # left-justify; pad low bits with 0
            fields.append(self._codec.encode_symbol(symbol))
        return fields

    def encoded_symbol_count(self, payload_len: int) -> int:
        """Return the carrier-unit count needed for a payload of ``payload_len`` bytes."""
        if not 0 <= payload_len <= _MAX_PAYLOAD:
            raise ValueError(f"payload length must be in [0, {_MAX_PAYLOAD}]")
        return ceil((_LENGTH_BYTES + payload_len) * 8 / self._codec.capacity_bits)

    def decode_one(self, fields: list[T], offset: int = 0) -> tuple[bytes, int]:
        """Decode one length-prefixed frame from ``fields[offset:]``.

        Returns ``(payload, consumed_symbols)``. This preserves ``decode`` semantics
        for a single frame while letting the session layer concatenate multiple
        independently framed chunks on one transport stream.
        """
        if offset < 0:
            raise ValueError("offset must be >= 0")
        prefix_symbols = ceil(_LENGTH_BYTES * 8 / self._codec.capacity_bits)
        if len(fields) - offset < prefix_symbols:
            raise ValueError("not enough symbols for frame length prefix")
        prefix_bytes = self._decode_raw(fields[offset : offset + prefix_symbols])
        length = int.from_bytes(prefix_bytes[:_LENGTH_BYTES], "big")
        needed = self.encoded_symbol_count(length)
        if len(fields) - offset < needed:
            raise ValueError("frame truncated before declared payload length")
        return self.decode(fields[offset : offset + needed]), needed

    def decode(self, fields: list[T]) -> bytes:
        """Reassemble the payload from received field values."""
        framed = self._decode_raw(fields)
        length = int.from_bytes(framed[:_LENGTH_BYTES], "big")
        return framed[_LENGTH_BYTES : _LENGTH_BYTES + length]

    def _decode_raw(self, fields: list[T]) -> bytes:
        cap = self._codec.capacity_bits
        writer = BitWriter()
        for field in fields:
            writer.write(self._codec.decode_symbol(field), cap)
        return writer.getvalue()
