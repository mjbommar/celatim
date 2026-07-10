"""Local timing baseline and quantum-sweep evidence."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from typing import Any
from uuid import uuid4

from .adapter import AdapterCapability
from .errors import ConfigurationError
from .session import (
    ChannelSession,
    InMemoryTransport,
    MechanismProfile,
    PacingConfig,
    ReceiveResult,
    TimingProfile,
    TimingSample,
    TimingTrace,
)
from .transports import TimedMemoryTransport

TIMING_SWEEP_SCHEMA_VERSION = "celatim.timing_sweep.v1"
TIMING_SWEEP_CLAIM_STATUS = "local_timed_memory_scheme_demonstration_not_capacity"
TIMING_SWEEP_PATH_KIND = "timed_memory"
TIMING_SWEEP_CAPACITY_MODEL = "raw_bits_per_symbol_times_observed_local_unit_rate"
TIMING_SWEEP_CAPACITY_STATUS = "local_model_only_not_medium_capacity"
OBSERVED_TRACE_TIMING_SWEEP_CLAIM_STATUS = (
    "observed_trace_timing_sweep_not_capacity_until_trace_provenance_review"
)
OBSERVED_TRACE_TIMING_SWEEP_PATH_KIND = "observed_trace"
OBSERVED_TRACE_TIMING_SWEEP_CAPACITY_MODEL = "raw_bits_per_symbol_times_observed_trace_unit_rate"
OBSERVED_TRACE_TIMING_SWEEP_CAPACITY_STATUS = "observed_trace_model_only_not_medium_capacity"

type Clock = Callable[[], float]
type Sleeper = Callable[[float], None]


@dataclass(frozen=True)
class TimingSweepCase:
    """One baseline or quantum-sweep timing run."""

    session_id: str
    payload_len: int
    recovered_len: int
    carrier_units: int
    pacing: PacingConfig
    timing_trace: TimingTrace
    timing_profile: TimingProfile
    matches: bool
    payload_error_count: int
    payload_error_rate: float
    quantum_s: float | None = None
    capacity_model_upper_bound_bps: float | None = None
    achieved_goodput_bps: float | None = None
    claim_status: str = TIMING_SWEEP_CLAIM_STATUS

    @classmethod
    def from_result(
        cls,
        *,
        result: ReceiveResult,
        expected_payload: bytes,
        pacing: PacingConfig,
        quantum_s: float | None,
        raw_capacity_bits: int,
    ) -> TimingSweepCase:
        trace = result.evidence.timing_trace
        profile = result.evidence.timing_profile
        if trace is None or profile is None:
            raise ConfigurationError("timing sweep requires timing_trace and timing_profile")
        matches = result.payload == expected_payload
        payload_error_count = 0 if matches else 1
        capacity_model_upper_bound_bps = (
            raw_capacity_bits * profile.observed_unit_rate_hz
            if profile.observed_unit_rate_hz is not None
            else None
        )
        return cls(
            session_id=result.session_id,
            payload_len=len(expected_payload),
            recovered_len=len(result.payload),
            carrier_units=result.evidence.carrier_units,
            pacing=pacing,
            timing_trace=trace,
            timing_profile=profile,
            matches=matches,
            payload_error_count=payload_error_count,
            payload_error_rate=float(payload_error_count),
            quantum_s=quantum_s,
            capacity_model_upper_bound_bps=capacity_model_upper_bound_bps,
            achieved_goodput_bps=profile.effective_goodput_bps,
        )

    @classmethod
    def from_observed_trace(
        cls,
        *,
        profile: MechanismProfile,
        expected_payload: bytes,
        recovered_payload: bytes,
        session_id: str,
        pacing: PacingConfig,
        quantum_s: float | None,
        observed_offsets_s: tuple[float, ...],
        claim_status: str,
    ) -> TimingSweepCase:
        carrier_units = _carrier_units_for_payload(profile, expected_payload, session_id, pacing)
        if len(observed_offsets_s) != carrier_units:
            raise ConfigurationError(
                f"{session_id}: observed offset count {len(observed_offsets_s)} "
                f"does not match encoded carrier units {carrier_units}"
            )
        trace = TimingTrace.from_offsets(
            _scheduled_offsets(pacing, carrier_units),
            observed_offsets_s,
        )
        timing_profile = TimingProfile.from_trace(
            trace,
            pacing,
            payload_len=len(expected_payload),
        )
        matches = recovered_payload == expected_payload
        payload_error_count = 0 if matches else 1
        capacity_model_upper_bound_bps = (
            profile.mechanism.raw_capacity_bits * timing_profile.observed_unit_rate_hz
            if timing_profile.observed_unit_rate_hz is not None
            else None
        )
        return cls(
            session_id=session_id,
            payload_len=len(expected_payload),
            recovered_len=len(recovered_payload),
            carrier_units=carrier_units,
            pacing=pacing,
            timing_trace=trace,
            timing_profile=timing_profile,
            matches=matches,
            payload_error_count=payload_error_count,
            payload_error_rate=float(payload_error_count),
            quantum_s=quantum_s,
            capacity_model_upper_bound_bps=capacity_model_upper_bound_bps,
            achieved_goodput_bps=timing_profile.effective_goodput_bps,
            claim_status=claim_status,
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "payload_len": self.payload_len,
            "recovered_len": self.recovered_len,
            "carrier_units": self.carrier_units,
            "pacing": _pacing_to_json(self.pacing),
            "quantum_s": self.quantum_s,
            "matches": self.matches,
            "payload_error_count": self.payload_error_count,
            "payload_error_rate": self.payload_error_rate,
            "capacity_model_upper_bound_bps": self.capacity_model_upper_bound_bps,
            "achieved_goodput_bps": self.achieved_goodput_bps,
            "claim_status": self.claim_status,
            "timing_trace": _timing_trace_to_json(self.timing_trace),
            "timing_profile": _timing_profile_to_json(self.timing_profile),
        }


@dataclass(frozen=True)
class TimingSweepReport:
    """Machine-readable local timing sweep evidence."""

    run_id: str
    mechanism_id: str
    payload_len: int
    payload_sha256: str
    baseline: TimingSweepCase
    trials: tuple[TimingSweepCase, ...]
    path_kind: str = TIMING_SWEEP_PATH_KIND
    claim_status: str = TIMING_SWEEP_CLAIM_STATUS
    capacity_model: str = TIMING_SWEEP_CAPACITY_MODEL
    capacity_model_comparison_status: str = TIMING_SWEEP_CAPACITY_STATUS
    path_metadata: dict[str, Any] | None = None

    @property
    def ok(self) -> bool:
        return self.baseline.matches and all(trial.matches for trial in self.trials)

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": TIMING_SWEEP_SCHEMA_VERSION,
            "run_id": self.run_id,
            "mechanism_id": self.mechanism_id,
            "path_kind": self.path_kind,
            "claim_status": self.claim_status,
            "capacity_model": self.capacity_model,
            "capacity_model_comparison_status": self.capacity_model_comparison_status,
            "path_metadata": self.path_metadata,
            "payload_len": self.payload_len,
            "payload_sha256": self.payload_sha256,
            "baseline": self.baseline.to_json(),
            "trials": [trial.to_json() for trial in self.trials],
            "ok": self.ok,
        }


def run_timing_sweep(
    profile: MechanismProfile,
    payload: bytes,
    *,
    quanta_s: Iterable[float],
    base_pacing: PacingConfig,
    baseline_payload: bytes | None = None,
    run_id: str | None = None,
    clock: Clock | None = None,
    sleeper: Sleeper | None = None,
) -> TimingSweepReport:
    """Run a local baseline and quantum sweep over ``TimedMemoryTransport``.

    The result is intentionally a scheme-demonstration artifact. It records the
    numbers needed for timing-discipline reviews, but the claim status prevents
    local in-process timings from being cited as medium-capacity measurements.
    """

    if AdapterCapability.TIMING not in profile.adapter.capabilities:
        raise ConfigurationError("timing sweep requires a timing-capable mechanism")
    if base_pacing.effective_symbol_period_s is None:
        raise ConfigurationError("timing sweep requires unit_rate_hz or symbol_period_s")
    quanta = tuple(float(quantum) for quantum in quanta_s)
    if not quanta:
        raise ConfigurationError("timing sweep requires at least one quantum")
    if any(quantum <= 0 for quantum in quanta):
        raise ConfigurationError("timing sweep quanta must be > 0")

    active_run_id = run_id or uuid4().hex
    baseline_bytes = (
        baseline_payload if baseline_payload is not None else bytes(max(1, len(payload)))
    )
    baseline_pacing = replace(base_pacing, timing_quantum_s=None, decode_tolerance_s=None)
    baseline = _run_sweep_case(
        profile,
        baseline_bytes,
        session_id=f"{active_run_id}:baseline",
        pacing=baseline_pacing,
        quantum_s=None,
        raw_capacity_bits=profile.mechanism.raw_capacity_bits,
        clock=clock,
        sleeper=sleeper,
    )
    trials = tuple(
        _run_sweep_case(
            profile,
            payload,
            session_id=f"{active_run_id}:q{index}",
            pacing=replace(base_pacing, timing_quantum_s=quantum),
            quantum_s=quantum,
            raw_capacity_bits=profile.mechanism.raw_capacity_bits,
            clock=clock,
            sleeper=sleeper,
        )
        for index, quantum in enumerate(quanta, start=1)
    )
    return TimingSweepReport(
        run_id=active_run_id,
        mechanism_id=profile.id,
        payload_len=len(payload),
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        baseline=baseline,
        trials=trials,
    )


@dataclass(frozen=True)
class ObservedTimingCaseInput:
    """Observed tap timing for one baseline or trial case."""

    observed_offsets_s: tuple[float, ...]
    recovered_payload: bytes
    quantum_s: float | None = None
    session_id: str | None = None

    def __post_init__(self) -> None:
        _validate_observed_offsets(self.observed_offsets_s)
        if self.quantum_s is not None and self.quantum_s <= 0:
            raise ConfigurationError("observed timing case quantum_s must be > 0")


def run_observed_timing_sweep(
    profile: MechanismProfile,
    payload: bytes,
    *,
    baseline: ObservedTimingCaseInput,
    trials: Iterable[ObservedTimingCaseInput],
    base_pacing: PacingConfig,
    baseline_payload: bytes | None = None,
    run_id: str | None = None,
    path_kind: str = OBSERVED_TRACE_TIMING_SWEEP_PATH_KIND,
    path_metadata: dict[str, Any] | None = None,
) -> TimingSweepReport:
    """Build a timing sweep from observed tap timestamps and recovered bytes.

    This is the ingestion path for netns, daemon, and VM timing experiments: external
    code performs the actual send/tap/recovery, then hands the observed offsets and
    recovered bytes to the same timing report model. The claim status remains
    conservative until the caller supplies reviewer-grade trace provenance.
    """

    if AdapterCapability.TIMING not in profile.adapter.capabilities:
        raise ConfigurationError("observed timing sweep requires a timing-capable mechanism")
    if base_pacing.effective_symbol_period_s is None:
        raise ConfigurationError("observed timing sweep requires unit_rate_hz or symbol_period_s")
    active_run_id = run_id or uuid4().hex
    baseline_bytes = (
        baseline_payload if baseline_payload is not None else bytes(max(1, len(payload)))
    )
    if baseline.quantum_s is not None:
        raise ConfigurationError("observed timing baseline quantum_s must be null")
    trial_inputs = tuple(trials)
    if not trial_inputs:
        raise ConfigurationError("observed timing sweep requires at least one trial")
    if any(trial.quantum_s is None for trial in trial_inputs):
        raise ConfigurationError("observed timing sweep trials require quantum_s")

    baseline_case = TimingSweepCase.from_observed_trace(
        profile=profile,
        expected_payload=baseline_bytes,
        recovered_payload=baseline.recovered_payload,
        session_id=baseline.session_id or f"{active_run_id}:baseline",
        pacing=replace(base_pacing, timing_quantum_s=None, decode_tolerance_s=None),
        quantum_s=None,
        observed_offsets_s=baseline.observed_offsets_s,
        claim_status=OBSERVED_TRACE_TIMING_SWEEP_CLAIM_STATUS,
    )
    trial_cases = tuple(
        TimingSweepCase.from_observed_trace(
            profile=profile,
            expected_payload=payload,
            recovered_payload=trial.recovered_payload,
            session_id=trial.session_id or f"{active_run_id}:q{index}",
            pacing=replace(base_pacing, timing_quantum_s=trial.quantum_s),
            quantum_s=trial.quantum_s,
            observed_offsets_s=trial.observed_offsets_s,
            claim_status=OBSERVED_TRACE_TIMING_SWEEP_CLAIM_STATUS,
        )
        for index, trial in enumerate(trial_inputs, start=1)
    )
    return TimingSweepReport(
        run_id=active_run_id,
        mechanism_id=profile.id,
        payload_len=len(payload),
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        baseline=baseline_case,
        trials=trial_cases,
        path_kind=path_kind,
        claim_status=OBSERVED_TRACE_TIMING_SWEEP_CLAIM_STATUS,
        capacity_model=OBSERVED_TRACE_TIMING_SWEEP_CAPACITY_MODEL,
        capacity_model_comparison_status=OBSERVED_TRACE_TIMING_SWEEP_CAPACITY_STATUS,
        path_metadata=None if path_metadata is None else dict(path_metadata),
    )


def _run_sweep_case(
    profile: MechanismProfile,
    payload: bytes,
    *,
    session_id: str,
    pacing: PacingConfig,
    quantum_s: float | None,
    raw_capacity_bits: int,
    clock: Clock | None,
    sleeper: Sleeper | None,
) -> TimingSweepCase:
    transport = TimedMemoryTransport(clock=clock, sleeper=sleeper)
    result = ChannelSession(profile, transport).run_roundtrip(
        payload,
        session_id=session_id,
        pacing=pacing,
    )
    return TimingSweepCase.from_result(
        result=result,
        expected_payload=payload,
        pacing=pacing,
        quantum_s=quantum_s,
        raw_capacity_bits=raw_capacity_bits,
    )


def _carrier_units_for_payload(
    profile: MechanismProfile,
    payload: bytes,
    session_id: str,
    pacing: PacingConfig,
) -> int:
    receipt = ChannelSession(profile, InMemoryTransport()).send_message(
        payload,
        session_id=session_id,
        pacing=pacing,
    )
    return receipt.carrier_units


def _scheduled_offsets(pacing: PacingConfig, symbol_count: int) -> tuple[float, ...]:
    if symbol_count < 0:
        raise ConfigurationError("symbol_count must be >= 0")
    period = pacing.effective_symbol_period_s
    if period is None:
        raise ConfigurationError("timing sweep requires unit_rate_hz or symbol_period_s")
    return tuple(pacing.base_delay_s + index * period for index in range(symbol_count))


def _validate_observed_offsets(observed_offsets_s: tuple[float, ...]) -> None:
    previous: float | None = None
    for offset in observed_offsets_s:
        if offset < 0:
            raise ConfigurationError("observed timing offsets must be >= 0")
        if previous is not None and offset < previous:
            raise ConfigurationError("observed timing offsets must be nondecreasing")
        previous = offset


def _pacing_to_json(pacing: PacingConfig) -> dict[str, Any]:
    return {
        "unit_rate_hz": pacing.unit_rate_hz,
        "symbol_period_s": pacing.symbol_period_s,
        "base_delay_s": pacing.base_delay_s,
        "timing_quantum_s": pacing.timing_quantum_s,
        "decode_tolerance_s": pacing.decode_tolerance_s,
        "timeout_s": pacing.timeout_s,
        "adaptive": pacing.adaptive,
        "jitter_sample_window": pacing.jitter_sample_window,
    }


def _timing_trace_to_json(trace: TimingTrace) -> dict[str, Any]:
    return {
        "sample_count": len(trace.samples),
        "scheduled_duration_s": trace.scheduled_duration_s,
        "observed_duration_s": trace.observed_duration_s,
        "mean_abs_error_s": trace.mean_abs_error_s,
        "max_abs_error_s": trace.max_abs_error_s,
        "inter_arrival_s": list(trace.inter_arrival_s),
        "inter_arrival_error_s": list(trace.inter_arrival_error_s),
        "samples": [_timing_sample_to_json(sample) for sample in trace.samples],
    }


def _timing_profile_to_json(profile: TimingProfile) -> dict[str, Any]:
    return {
        "sample_count": profile.sample_count,
        "nominal_symbol_period_s": profile.nominal_symbol_period_s,
        "timing_quantum_s": profile.timing_quantum_s,
        "decode_tolerance_s": profile.decode_tolerance_s,
        "tolerance_source": profile.tolerance_source,
        "error_basis": profile.error_basis,
        "jitter_sample_count": profile.jitter_sample_count,
        "jitter_mean_abs_s": profile.jitter_mean_abs_s,
        "jitter_p50_abs_s": profile.jitter_p50_abs_s,
        "jitter_p95_abs_s": profile.jitter_p95_abs_s,
        "jitter_max_abs_s": profile.jitter_max_abs_s,
        "jitter_stddev_s": profile.jitter_stddev_s,
        "snr_db": profile.snr_db,
        "symbol_error_count": profile.symbol_error_count,
        "symbol_error_rate": profile.symbol_error_rate,
        "scheduled_unit_rate_hz": profile.scheduled_unit_rate_hz,
        "observed_unit_rate_hz": profile.observed_unit_rate_hz,
        "effective_goodput_bps": profile.effective_goodput_bps,
        "rate_status": profile.rate_status,
    }


def _timing_sample_to_json(sample: TimingSample) -> dict[str, Any]:
    return {
        "index": sample.index,
        "scheduled_offset_s": sample.scheduled_offset_s,
        "observed_offset_s": sample.observed_offset_s,
        "error_s": sample.error_s,
    }


__all__ = [
    "OBSERVED_TRACE_TIMING_SWEEP_CAPACITY_MODEL",
    "OBSERVED_TRACE_TIMING_SWEEP_CAPACITY_STATUS",
    "OBSERVED_TRACE_TIMING_SWEEP_CLAIM_STATUS",
    "OBSERVED_TRACE_TIMING_SWEEP_PATH_KIND",
    "TIMING_SWEEP_CAPACITY_MODEL",
    "TIMING_SWEEP_CAPACITY_STATUS",
    "TIMING_SWEEP_CLAIM_STATUS",
    "TIMING_SWEEP_PATH_KIND",
    "TIMING_SWEEP_SCHEMA_VERSION",
    "ObservedTimingCaseInput",
    "TimingSweepCase",
    "TimingSweepReport",
    "run_observed_timing_sweep",
    "run_timing_sweep",
]
