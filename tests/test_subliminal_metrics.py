"""Class G subliminal crypto-channel capacity metrics."""

from pathlib import Path

import pytest

from celatim.catalog import load_mechanisms
from celatim.metrics import (
    SubliminalMode,
    broadband_entropy_bound,
    narrowband_entropy_bound,
    subliminal_entropy_bound,
)

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def mechs():
    return {m.id: m for m in load_mechanisms(DATA)}


def test_broadband_subliminal_bound_uses_catalog_entropy_range():
    m = mechs()["rsa-pss-salt"]

    bound = broadband_entropy_bound(m)
    doc = bound.to_json()

    assert bound.mode is SubliminalMode.BROADBAND
    assert bound.min_bits_per_unit == 160.0
    assert bound.representative_bits_per_unit == 256.0
    assert bound.max_bits_per_unit == 512.0
    assert bound.throughput_bps(2.0) == 512.0
    assert doc["mode"] == "broadband"
    assert doc["bound_status"] == "catalog_entropy_range"


def test_narrowband_subliminal_bound_is_caller_supplied_and_conservative():
    m = mechs()["rsa-pss-salt"]

    bound = narrowband_entropy_bound(m, bits_per_unit=1.0)
    dispatched = subliminal_entropy_bound(
        m,
        mode="narrowband",
        narrowband_bits_per_unit=2.0,
    )

    assert bound.mode is SubliminalMode.NARROWBAND
    assert bound.min_bits_per_unit == 1.0
    assert bound.representative_bits_per_unit == 1.0
    assert bound.max_bits_per_unit == 1.0
    assert bound.bound_status == "caller_supplied_narrowband_bound"
    assert dispatched.representative_bits_per_unit == 2.0


def test_subliminal_estimators_reject_wrong_rows_and_bad_bounds():
    storage = mechs()["http2-ping-opaque"]
    subliminal = mechs()["rsa-pss-salt"]

    with pytest.raises(ValueError, match="Class G"):
        broadband_entropy_bound(storage)
    with pytest.raises(ValueError, match="must be > 0"):
        narrowband_entropy_bound(subliminal, bits_per_unit=0.0)
    with pytest.raises(ValueError, match="must not exceed broadband max"):
        narrowband_entropy_bound(subliminal, bits_per_unit=513.0)
    with pytest.raises(ValueError, match="narrowband_bits_per_unit is required"):
        subliminal_entropy_bound(subliminal, mode=SubliminalMode.NARROWBAND)
