"""MSB-first bit-field placement and extraction at a wire offset.

Every located packet-class mechanism shares the same primitive: take an
otherwise-real PDU and write covert bits into the field a ``FieldLocator`` names
(``bit_offset``/``bit_width``, MSB-first from a header base), then read them back.
Bit 0 is the most significant bit of byte 0, matching the ``FieldLocator`` /
nftables raw-payload model. Pure stdlib, so it is deterministic and independent of
Scapy: Scapy builds the realistic surrounding bytes; this module owns the covert
field, and the two compose without either depending on the other.
"""

from __future__ import annotations


def _check_field(buffer_len: int, bit_offset: int, bit_width: int) -> None:
    if bit_offset < 0:
        raise ValueError("bit_offset must be >= 0")
    if bit_width <= 0:
        raise ValueError("bit_width must be positive")
    if bit_offset + bit_width > buffer_len * 8:
        raise ValueError(
            f"field [{bit_offset}, {bit_offset + bit_width}) exceeds buffer of {buffer_len} bytes"
        )


def place_bits(buffer: bytes, *, bit_offset: int, bit_width: int, value: int) -> bytes:
    """Return a copy of ``buffer`` with ``value`` written MSB-first into the field.

    Only the targeted bits change; every neighboring bit is preserved, which is
    what keeps the surrounding PDU a real carrier rather than a zero blob.
    """

    _check_field(len(buffer), bit_offset, bit_width)
    if value < 0 or value >= (1 << bit_width):
        raise ValueError(f"value {value} does not fit in {bit_width} bits")

    bits = list(buffer)
    for i in range(bit_width):
        bit = (value >> (bit_width - 1 - i)) & 1
        pos = bit_offset + i
        byte_index, bit_in_byte = divmod(pos, 8)
        mask = 1 << (7 - bit_in_byte)
        if bit:
            bits[byte_index] |= mask
        else:
            bits[byte_index] &= ~mask & 0xFF
    return bytes(bits)


def extract_bits(buffer: bytes, *, bit_offset: int, bit_width: int) -> int:
    """Read ``bit_width`` bits MSB-first at ``bit_offset`` from ``buffer``."""

    _check_field(len(buffer), bit_offset, bit_width)
    value = 0
    for i in range(bit_width):
        pos = bit_offset + i
        byte_index, bit_in_byte = divmod(pos, 8)
        bit = (buffer[byte_index] >> (7 - bit_in_byte)) & 1
        value = (value << 1) | bit
    return value


__all__ = ["extract_bits", "place_bits"]
