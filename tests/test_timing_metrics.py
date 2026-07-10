"""Class F timing/count-channel capacity metrics."""

import math
from pathlib import Path

import pytest

from celatim.catalog import load_mechanisms
from celatim.metrics import (
    ANANTHARAM_VERDU_MODEL,
    bits_to_nats,
    nats_to_bits,
    queue_capacity_bps,
    queue_capacity_nats_per_second,
    symbol_rate_upper_bound_bps,
    timing_capacity_estimate,
)

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def mechs():
    return {m.id: m for m in load_mechanisms(DATA)}


def test_queue_capacity_uses_anantharam_verdu_mu_over_e():
    assert math.isclose(queue_capacity_nats_per_second(100.0), 100.0 / math.e)
    assert math.isclose(queue_capacity_bps(100.0), 100.0 / (math.e * math.log(2.0)))
    assert math.isclose(nats_to_bits(bits_to_nats(7.5)), 7.5)


def test_timing_capacity_estimate_compares_queue_and_symbol_rates():
    m = mechs()["quic-padding-frame-count"]
    observed_rate = 25.0
    service_rate = 100.0

    estimate = timing_capacity_estimate(
        m,
        service_rate_hz=service_rate,
        observed_unit_rate_hz=observed_rate,
    )
    doc = estimate.to_json()

    assert estimate.queue_model == ANANTHARAM_VERDU_MODEL
    assert estimate.symbol_rate_upper_bound_bps == m.raw_capacity_bits * observed_rate
    assert estimate.limiting_upper_bound_bps == min(
        queue_capacity_bps(service_rate),
        m.raw_capacity_bits * observed_rate,
    )
    assert doc["mechanism_id"] == "quic-padding-frame-count"
    assert doc["carrier_unit"] == m.carrier_unit
    assert doc["comparison_status"] in {
        "observed_symbol_rate_below_queue_bound",
        "queue_bound_below_observed_symbol_rate",
    }


def test_symbol_rate_upper_bound_rejects_non_timing_rows_and_bad_rates():
    storage = mechs()["http2-ping-opaque"]
    timing = mechs()["dns-timing"]

    with pytest.raises(ValueError, match="Class F"):
        symbol_rate_upper_bound_bps(storage, 100.0)
    with pytest.raises(ValueError, match="must be > 0"):
        symbol_rate_upper_bound_bps(timing, 0.0)
    with pytest.raises(ValueError, match="must be > 0"):
        timing_capacity_estimate(timing, service_rate_hz=-1.0)
