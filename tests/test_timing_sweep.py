"""Timing baseline and quantum-sweep evidence."""

from pathlib import Path

import pytest

from celatim import (
    ChannelSession,
    InMemoryTransport,
    MechanismProfile,
    ObservedTimingCaseInput,
    PacingConfig,
    run_observed_timing_sweep,
    run_timing_sweep,
)
from celatim.errors import ConfigurationError

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


class JitterClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.index = 0
        self.jitter = (0.0, 0.0004, 0.0001, 0.0007)

    def __call__(self) -> float:
        return self.now

    def sleep(self, delay_s: float) -> None:
        self.now += max(0.0, delay_s) + self.jitter[self.index % len(self.jitter)]
        self.index += 1


def test_timing_sweep_records_baseline_trials_and_conservative_claims():
    clock = JitterClock()
    profile = MechanismProfile.from_catalog("dns-timing", DATA)

    report = run_timing_sweep(
        profile,
        b"\x00\xfftiming",
        quanta_s=(0.01, 0.002),
        base_pacing=PacingConfig(unit_rate_hz=100.0, jitter_sample_window=4),
        run_id="sweep-test",
        clock=clock,
        sleeper=clock.sleep,
    )
    doc = report.to_json()

    assert doc["schema_version"] == "celatim.timing_sweep.v1"
    assert doc["run_id"] == "sweep-test"
    assert doc["mechanism_id"] == "dns-timing"
    assert doc["path_kind"] == "timed_memory"
    assert doc["claim_status"] == "local_timed_memory_scheme_demonstration_not_capacity"
    assert doc["capacity_model"] == "raw_bits_per_symbol_times_observed_local_unit_rate"
    assert doc["capacity_model_comparison_status"] == "local_model_only_not_medium_capacity"
    assert doc["ok"] is True
    assert doc["baseline"]["quantum_s"] is None
    assert doc["baseline"]["timing_profile"]["timing_quantum_s"] is None
    assert doc["baseline"]["timing_profile"]["jitter_sample_count"] > 0
    assert len(doc["trials"]) == 2
    assert [trial["quantum_s"] for trial in doc["trials"]] == [0.01, 0.002]
    for trial in doc["trials"]:
        assert trial["payload_error_rate"] == 0.0
        assert trial["claim_status"] == "local_timed_memory_scheme_demonstration_not_capacity"
        assert trial["capacity_model_upper_bound_bps"] is not None
        assert trial["achieved_goodput_bps"] is not None
        assert trial["timing_profile"]["rate_status"] == "local_scheme_demonstration_not_capacity"
        assert trial["timing_profile"]["symbol_error_rate"] is not None


def test_observed_timing_sweep_ingests_trace_offsets_and_recovered_bytes():
    profile = MechanismProfile.from_catalog("dns-timing", DATA)
    payload = b"\x00\xfftiming"
    baseline_payload = bytes(len(payload))
    base_pacing = PacingConfig(unit_rate_hz=100.0, jitter_sample_window=4)
    baseline_count = _carrier_count(profile, baseline_payload, base_pacing)
    trial_count = _carrier_count(profile, payload, base_pacing)

    report = run_observed_timing_sweep(
        profile,
        payload,
        baseline=ObservedTimingCaseInput(
            observed_offsets_s=_offsets(baseline_count),
            recovered_payload=baseline_payload,
            session_id="observed-test:baseline",
        ),
        trials=(
            ObservedTimingCaseInput(
                observed_offsets_s=_offsets(trial_count),
                recovered_payload=payload,
                quantum_s=0.01,
                session_id="observed-test:q1",
            ),
        ),
        base_pacing=base_pacing,
        baseline_payload=baseline_payload,
        run_id="observed-test",
        path_metadata={"tap": "unit-test-pcap"},
    )
    doc = report.to_json()

    assert doc["schema_version"] == "celatim.timing_sweep.v1"
    assert doc["run_id"] == "observed-test"
    assert doc["path_kind"] == "observed_trace"
    assert (
        doc["claim_status"]
        == "observed_trace_timing_sweep_not_capacity_until_trace_provenance_review"
    )
    assert doc["capacity_model"] == "raw_bits_per_symbol_times_observed_trace_unit_rate"
    assert (
        doc["capacity_model_comparison_status"] == "observed_trace_model_only_not_medium_capacity"
    )
    assert doc["path_metadata"] == {"tap": "unit-test-pcap"}
    assert doc["ok"] is True
    assert doc["baseline"]["session_id"] == "observed-test:baseline"
    assert doc["baseline"]["quantum_s"] is None
    assert doc["baseline"]["carrier_units"] == baseline_count
    assert doc["trials"][0]["session_id"] == "observed-test:q1"
    assert doc["trials"][0]["quantum_s"] == 0.01
    assert doc["trials"][0]["carrier_units"] == trial_count
    assert doc["trials"][0]["payload_error_rate"] == 0.0
    assert doc["trials"][0]["timing_profile"]["observed_unit_rate_hz"] is not None


def test_observed_timing_sweep_validates_trace_contract():
    profile = MechanismProfile.from_catalog("dns-timing", DATA)
    payload = b"payload"
    base_pacing = PacingConfig(unit_rate_hz=100.0)
    baseline_payload = bytes(len(payload))
    baseline_count = _carrier_count(profile, baseline_payload, base_pacing)
    trial_count = _carrier_count(profile, payload, base_pacing)

    with pytest.raises(ConfigurationError, match="observed offset count"):
        run_observed_timing_sweep(
            profile,
            payload,
            baseline=ObservedTimingCaseInput(
                observed_offsets_s=_offsets(baseline_count),
                recovered_payload=baseline_payload,
            ),
            trials=(
                ObservedTimingCaseInput(
                    observed_offsets_s=_offsets(trial_count - 1),
                    recovered_payload=payload,
                    quantum_s=0.01,
                ),
            ),
            base_pacing=base_pacing,
            baseline_payload=baseline_payload,
        )
    with pytest.raises(ConfigurationError, match="nondecreasing"):
        ObservedTimingCaseInput(
            observed_offsets_s=(0.0, 0.02, 0.01),
            recovered_payload=payload,
            quantum_s=0.01,
        )
    with pytest.raises(ConfigurationError, match="offsets must be >= 0"):
        ObservedTimingCaseInput(
            observed_offsets_s=(-0.001,),
            recovered_payload=payload,
            quantum_s=0.01,
        )
    with pytest.raises(ConfigurationError, match="trials require quantum_s"):
        run_observed_timing_sweep(
            profile,
            payload,
            baseline=ObservedTimingCaseInput(
                observed_offsets_s=_offsets(baseline_count),
                recovered_payload=baseline_payload,
            ),
            trials=(
                ObservedTimingCaseInput(
                    observed_offsets_s=_offsets(trial_count),
                    recovered_payload=payload,
                ),
            ),
            base_pacing=base_pacing,
            baseline_payload=baseline_payload,
        )


def test_timing_sweep_requires_timing_mechanism_and_positive_quantum():
    storage_profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    timing_profile = MechanismProfile.from_catalog("dns-timing", DATA)

    with pytest.raises(ConfigurationError, match="timing-capable"):
        run_timing_sweep(
            storage_profile,
            b"payload",
            quanta_s=(0.01,),
            base_pacing=PacingConfig(unit_rate_hz=100.0),
        )
    with pytest.raises(ConfigurationError, match="quanta must be > 0"):
        run_timing_sweep(
            timing_profile,
            b"payload",
            quanta_s=(0.0,),
            base_pacing=PacingConfig(unit_rate_hz=100.0),
        )


def _carrier_count(profile: MechanismProfile, payload: bytes, pacing: PacingConfig) -> int:
    return (
        ChannelSession(profile, InMemoryTransport())
        .send_message(
            payload,
            session_id="count",
            pacing=pacing,
        )
        .carrier_units
    )


def _offsets(count: int, period_s: float = 0.01) -> tuple[float, ...]:
    return tuple(index * period_s + (0.0001 if index % 2 else 0.0) for index in range(count))
