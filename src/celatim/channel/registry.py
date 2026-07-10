"""Map each catalog mechanism to the codec that carries its bits.

Working backwards from the ~90 mechanisms, the seven carrier classes collapse onto
three codec shapes, so this is a small deterministic dispatch keyed to the catalog
(the single source of truth), not ninety bespoke implementations:

* fixed-width value  — Class A reserved/MBZ bits, small Class C opaque fields;
* variable-length bytes — Class B padding, Class E blobs, Class G salt/nonce, large
  opaque Class C, and payload-carrying (unbounded) Class D frames;
* choose-one-of-K — Class D reserved codepoints and Class F count/timing channels.

Timing (F) and subliminal (G) differ from storage only at the *transport* layer
(how the symbol is placed on the wire); at the bit-packing layer they reuse these
shapes, so the dispatch stays DRY."""

from __future__ import annotations

from ..model import CarrierClass, Mechanism
from .codec import Codec, FixedWidthCodec, SymbolChoiceCodec, VariableLengthCodec

type AnyCodec = Codec[int] | Codec[bytes]

_SMALL_FIELD_BITS = 32  # at/below this, a Class C field is carried as a fixed-width value


def _byte_or_bit_codec(bits: int) -> AnyCodec:
    """Whole bytes get a byte field (natural for a blob/padding/salt); a non-byte
    width gets a bit field. Either way codec capacity equals the catalog's raw bits."""
    return VariableLengthCodec(bits // 8) if bits % 8 == 0 else FixedWidthCodec(bits)


def codec_for(mechanism: Mechanism) -> AnyCodec:
    """Return the codec that encodes/decodes ``mechanism``'s covert bits."""
    cls = mechanism.carrier_class
    bits = mechanism.raw_capacity_bits

    # bytes-oriented carriers: padding, blobs, salt/nonce
    if cls in (CarrierClass.B, CarrierClass.E, CarrierClass.G):
        return _byte_or_bit_codec(bits)
    if cls is CarrierClass.C:
        return FixedWidthCodec(bits) if bits <= _SMALL_FIELD_BITS else _byte_or_bit_codec(bits)
    if cls is CarrierClass.D:
        # a small reserved-codepoint space is a choice; a large/unbounded one carries a payload.
        if mechanism.unbounded or bits > _SMALL_FIELD_BITS:
            return _byte_or_bit_codec(bits)
        return SymbolChoiceCodec(1 << bits)

    # value/symbol carriers
    if cls is CarrierClass.A:
        return FixedWidthCodec(bits)
    if cls is CarrierClass.F:
        return SymbolChoiceCodec(1 << bits)

    raise ValueError(f"{mechanism.id}: no codec mapping for class {cls.value}")


def build_registry(mechanisms: list[Mechanism]) -> dict[str, AnyCodec]:
    """Codec per mechanism id — the channel-layer view of the whole catalog."""
    return {m.id: codec_for(m) for m in mechanisms}
