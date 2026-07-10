"""Capacity metrics for storage-channel carrier classes (A–E).

All capacities are STRUCTURAL upper bounds (raw field width), not effective
goodput; survivability and cooperating-vs-unwitting caveats live on the
mechanism's ``reach`` field, not here."""

from __future__ import annotations

from ..model import CapacityModel, Mechanism


def _require_storage(m: Mechanism) -> None:
    """Width-based density is meaningful only for storage channels (A–E). For a
    timing (F) or subliminal (G) channel the covert content is not packed into a
    fixed-width field, so dividing bits by a header size is a category error —
    those families have their own estimators."""
    if m.capacity_model is not CapacityModel.STORAGE:
        raise ValueError(
            f"{m.id}: width-based density is defined only for storage channels; "
            f"class {m.carrier_class.value} is {m.capacity_model.value} "
            f"(use the timing/subliminal estimator instead)"
        )


def raw_bits(m: Mechanism) -> int:
    """Representative covert bits per carrier unit (packet / segment / handshake / ...)."""
    return m.raw_capacity_bits


def density_header(m: Mechanism) -> float:
    """Covert bits per bit of this protocol's header (header-relative density)."""
    _require_storage(m)
    return m.raw_capacity_bits / m.header_bits


def density_wire(m: Mechanism) -> float:
    """Covert bits per bit of a typical full on-wire PDU (on-wire density)."""
    _require_storage(m)
    return m.raw_capacity_bits / m.wire_bits_typical


def throughput_bps(m: Mechanism, carrier_units_per_second: float) -> float:
    """Covert bits/second at a stated carrier-unit rate (structural upper bound)."""
    return m.raw_capacity_bits * carrier_units_per_second
