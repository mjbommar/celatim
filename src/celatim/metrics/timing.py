"""Capacity metrics for Class F timing/count channels.

These estimators deliberately do not produce header-relative density. Timing
channels are modeled as rates over an observed path: the queue-theoretic bound
uses the Anantharam-Verdu single-server timing-channel result, while the local
symbol-rate bound is the measured unit rate times the catalog's bits/symbol.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from ..model import CapacityModel, Mechanism

ANANTHARAM_VERDU_MODEL = "anantharam_verdu_single_server_mu_over_e"
LOCAL_SYMBOL_RATE_MODEL = "raw_bits_per_symbol_times_observed_unit_rate"


def _require_timing(m: Mechanism) -> None:
    if m.capacity_model is not CapacityModel.TIMING:
        raise ValueError(
            f"{m.id}: timing capacity is defined only for Class F timing/count channels; "
            f"class {m.carrier_class.value} is {m.capacity_model.value}"
        )


def _require_positive(name: str, value: float) -> None:
    if value <= 0:
        raise ValueError(f"{name} must be > 0")


def nats_to_bits(nats: float) -> float:
    """Convert nats to bits."""
    return nats / math.log(2.0)


def bits_to_nats(bits: float) -> float:
    """Convert bits to nats."""
    return bits * math.log(2.0)


def queue_capacity_nats_per_second(service_rate_hz: float) -> float:
    """Anantharam-Verdu single-server timing-channel bound: mu/e nats/s."""
    _require_positive("service_rate_hz", service_rate_hz)
    return service_rate_hz / math.e


def queue_capacity_bps(service_rate_hz: float) -> float:
    """Anantharam-Verdu single-server timing-channel bound in bits/s."""
    return nats_to_bits(queue_capacity_nats_per_second(service_rate_hz))


def symbol_rate_upper_bound_bps(m: Mechanism, observed_unit_rate_hz: float) -> float:
    """Local raw bits/s upper bound from a measured carrier-unit rate."""
    _require_timing(m)
    _require_positive("observed_unit_rate_hz", observed_unit_rate_hz)
    return m.raw_capacity_bits * observed_unit_rate_hz


@dataclass(frozen=True)
class TimingCapacityEstimate:
    """Timing-channel capacity comparison for a measured or assumed path."""

    mechanism_id: str
    carrier_unit: str
    service_rate_hz: float
    queue_capacity_nats_per_s: float
    queue_capacity_bps: float
    observed_unit_rate_hz: float | None = None
    symbol_rate_upper_bound_bps: float | None = None
    queue_model: str = ANANTHARAM_VERDU_MODEL
    symbol_rate_model: str = LOCAL_SYMBOL_RATE_MODEL

    @property
    def limiting_upper_bound_bps(self) -> float:
        """The lower of the queue bound and local symbol-rate bound, if both exist."""
        if self.symbol_rate_upper_bound_bps is None:
            return self.queue_capacity_bps
        return min(self.queue_capacity_bps, self.symbol_rate_upper_bound_bps)

    @property
    def comparison_status(self) -> str:
        if self.symbol_rate_upper_bound_bps is None:
            return "queue_model_upper_bound_without_observed_symbol_rate"
        if self.symbol_rate_upper_bound_bps <= self.queue_capacity_bps:
            return "observed_symbol_rate_below_queue_bound"
        return "queue_bound_below_observed_symbol_rate"

    def to_json(self) -> dict[str, Any]:
        return {
            "mechanism_id": self.mechanism_id,
            "carrier_unit": self.carrier_unit,
            "service_rate_hz": self.service_rate_hz,
            "queue_model": self.queue_model,
            "queue_capacity_nats_per_s": self.queue_capacity_nats_per_s,
            "queue_capacity_bps": self.queue_capacity_bps,
            "observed_unit_rate_hz": self.observed_unit_rate_hz,
            "symbol_rate_model": self.symbol_rate_model,
            "symbol_rate_upper_bound_bps": self.symbol_rate_upper_bound_bps,
            "limiting_upper_bound_bps": self.limiting_upper_bound_bps,
            "comparison_status": self.comparison_status,
        }


def timing_capacity_estimate(
    m: Mechanism,
    *,
    service_rate_hz: float,
    observed_unit_rate_hz: float | None = None,
) -> TimingCapacityEstimate:
    """Return a Class F queue-model estimate, optionally compared to observed symbols/s."""
    _require_timing(m)
    queue_nats = queue_capacity_nats_per_second(service_rate_hz)
    symbol_bps = (
        None
        if observed_unit_rate_hz is None
        else symbol_rate_upper_bound_bps(m, observed_unit_rate_hz)
    )
    return TimingCapacityEstimate(
        mechanism_id=m.id,
        carrier_unit=m.carrier_unit,
        service_rate_hz=service_rate_hz,
        queue_capacity_nats_per_s=queue_nats,
        queue_capacity_bps=nats_to_bits(queue_nats),
        observed_unit_rate_hz=observed_unit_rate_hz,
        symbol_rate_upper_bound_bps=symbol_bps,
    )


__all__ = [
    "ANANTHARAM_VERDU_MODEL",
    "LOCAL_SYMBOL_RATE_MODEL",
    "TimingCapacityEstimate",
    "bits_to_nats",
    "nats_to_bits",
    "queue_capacity_bps",
    "queue_capacity_nats_per_second",
    "symbol_rate_upper_bound_bps",
    "timing_capacity_estimate",
]
