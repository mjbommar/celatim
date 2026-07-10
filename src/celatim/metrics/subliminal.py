"""Capacity metrics for Class G subliminal crypto channels.

Class G capacity is bounded by entropy available in a cryptographic choice
(nonce, salt, signature randomness), not by packet-header density. Broadband
channels use the catalog entropy range. Narrowband channels require a caller-
supplied conservative bound because the usable subchannel is intentionally small
and mechanism/protocol dependent.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..model import CapacityModel, Mechanism


class SubliminalMode(str, Enum):
    BROADBAND = "broadband"
    NARROWBAND = "narrowband"


def _require_subliminal(m: Mechanism) -> None:
    if m.capacity_model is not CapacityModel.SUBLIMINAL:
        raise ValueError(
            f"{m.id}: subliminal capacity is defined only for Class G crypto channels; "
            f"class {m.carrier_class.value} is {m.capacity_model.value}"
        )


def _require_positive(name: str, value: float) -> None:
    if value <= 0:
        raise ValueError(f"{name} must be > 0")


@dataclass(frozen=True)
class SubliminalCapacityBound:
    """Entropy-bound covert capacity for a subliminal carrier."""

    mechanism_id: str
    carrier_unit: str
    mode: SubliminalMode
    min_bits_per_unit: float
    representative_bits_per_unit: float
    max_bits_per_unit: float | None
    unbounded: bool = False
    bound_status: str = "catalog_entropy_range"

    def throughput_bps(self, carrier_units_per_second: float) -> float:
        """Representative bits/s at a stated signature/operation rate."""
        _require_positive("carrier_units_per_second", carrier_units_per_second)
        return self.representative_bits_per_unit * carrier_units_per_second

    def to_json(self) -> dict[str, Any]:
        return {
            "mechanism_id": self.mechanism_id,
            "carrier_unit": self.carrier_unit,
            "mode": self.mode.value,
            "min_bits_per_unit": self.min_bits_per_unit,
            "representative_bits_per_unit": self.representative_bits_per_unit,
            "max_bits_per_unit": self.max_bits_per_unit,
            "unbounded": self.unbounded,
            "bound_status": self.bound_status,
        }


def broadband_entropy_bound(m: Mechanism) -> SubliminalCapacityBound:
    """Catalog entropy range for a broadband Simmons-style subliminal channel."""
    _require_subliminal(m)
    return SubliminalCapacityBound(
        mechanism_id=m.id,
        carrier_unit=m.carrier_unit,
        mode=SubliminalMode.BROADBAND,
        min_bits_per_unit=float(m.bits_min if m.bits_min is not None else m.raw_capacity_bits),
        representative_bits_per_unit=float(m.raw_capacity_bits),
        max_bits_per_unit=None
        if m.unbounded
        else float(m.bits_max if m.bits_max is not None else m.raw_capacity_bits),
        unbounded=m.unbounded,
        bound_status="catalog_entropy_range",
    )


def narrowband_entropy_bound(
    m: Mechanism,
    *,
    bits_per_unit: float,
) -> SubliminalCapacityBound:
    """Caller-supplied conservative narrowband subliminal bound."""
    _require_subliminal(m)
    _require_positive("bits_per_unit", bits_per_unit)
    broadband = broadband_entropy_bound(m)
    if broadband.max_bits_per_unit is not None and bits_per_unit > broadband.max_bits_per_unit:
        raise ValueError(
            f"{m.id}: narrowband bound must not exceed broadband max "
            f"({broadband.max_bits_per_unit:g} bits/{m.carrier_unit})"
        )
    return SubliminalCapacityBound(
        mechanism_id=m.id,
        carrier_unit=m.carrier_unit,
        mode=SubliminalMode.NARROWBAND,
        min_bits_per_unit=float(bits_per_unit),
        representative_bits_per_unit=float(bits_per_unit),
        max_bits_per_unit=float(bits_per_unit),
        unbounded=False,
        bound_status="caller_supplied_narrowband_bound",
    )


def subliminal_entropy_bound(
    m: Mechanism,
    *,
    mode: SubliminalMode | str = SubliminalMode.BROADBAND,
    narrowband_bits_per_unit: float | None = None,
) -> SubliminalCapacityBound:
    """Dispatch to the broadband or narrowband Class G entropy estimator."""
    selected_mode = mode if isinstance(mode, SubliminalMode) else SubliminalMode(mode)
    if selected_mode is SubliminalMode.BROADBAND:
        return broadband_entropy_bound(m)
    if narrowband_bits_per_unit is None:
        raise ValueError("narrowband_bits_per_unit is required for narrowband estimates")
    return narrowband_entropy_bound(m, bits_per_unit=narrowband_bits_per_unit)


__all__ = [
    "SubliminalCapacityBound",
    "SubliminalMode",
    "broadband_entropy_bound",
    "narrowband_entropy_bound",
    "subliminal_entropy_bound",
]
