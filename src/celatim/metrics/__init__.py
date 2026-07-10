"""Capacity metrics, dispatched by carrier class.

Storage classes (A-E) use bits-per-field arithmetic. Timing/count (F) and
subliminal crypto (G) channels use separate rate/entropy estimators so reports
do not apply width-based density to non-storage mechanisms."""

from .storage import density_header, density_wire, raw_bits, throughput_bps
from .subliminal import (
    SubliminalCapacityBound,
    SubliminalMode,
    broadband_entropy_bound,
    narrowband_entropy_bound,
    subliminal_entropy_bound,
)
from .timing import (
    ANANTHARAM_VERDU_MODEL,
    LOCAL_SYMBOL_RATE_MODEL,
    TimingCapacityEstimate,
    bits_to_nats,
    nats_to_bits,
    queue_capacity_bps,
    queue_capacity_nats_per_second,
    symbol_rate_upper_bound_bps,
    timing_capacity_estimate,
)

__all__ = [
    "ANANTHARAM_VERDU_MODEL",
    "LOCAL_SYMBOL_RATE_MODEL",
    "SubliminalCapacityBound",
    "SubliminalMode",
    "TimingCapacityEstimate",
    "bits_to_nats",
    "broadband_entropy_bound",
    "density_header",
    "density_wire",
    "narrowband_entropy_bound",
    "nats_to_bits",
    "queue_capacity_bps",
    "queue_capacity_nats_per_second",
    "raw_bits",
    "subliminal_entropy_bound",
    "symbol_rate_upper_bound_bps",
    "throughput_bps",
    "timing_capacity_estimate",
]
