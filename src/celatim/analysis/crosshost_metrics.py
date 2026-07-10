"""Efficiency and timing metrics for Alice/Bob cross-host evidence artifacts."""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

METRICS_SCHEMA_VERSION = "celatim.alice_bob_metrics.v1"

ETHERNET_HEADER_BYTES = 14
IPV4_HEADER_BYTES = 20
TCP_HEADER_BYTES = 20
UDP_HEADER_BYTES = 8
VXLAN_UNDERLAY_OVERHEAD_NO_FCS_BYTES = 50


@dataclass(frozen=True)
class MechanismMetricInput:
    mechanism_id: str
    suite: str
    result: str
    payload_bytes: int
    recovered_bytes: int | None
    carrier_units: int | None
    raw_capacity_bits: int | None = None
    carrier_wire_bytes: int | None = None
    method_wire_bytes: int | None = None
    method_wire_basis: str | None = None
    vxlan_underlay_bytes_no_fcs: int | None = None
    measured_window_s: float | None = None
    measured_window_basis: str | None = None
    scheduled_unit_rate_hz: float | None = None
    scheduled_duration_s: float | None = None
    timing_claim_status: str = "not_measured"


def packet_method_wire_bytes(
    mechanism_id: str,
    carrier_lengths: Sequence[int],
    protocol: str,
) -> int:
    """Return inner Ethernet L2 bytes, excluding FCS, for packet-path carriers."""

    if mechanism_id == "tcp-reserved-bits":
        return sum(ETHERNET_HEADER_BYTES + IPV4_HEADER_BYTES + length for length in carrier_lengths)
    l4_header = TCP_HEADER_BYTES if protocol == "tcp" else UDP_HEADER_BYTES
    return sum(
        ETHERNET_HEADER_BYTES + IPV4_HEADER_BYTES + l4_header + length for length in carrier_lengths
    )


def carrier_lengths_from_envelope(envelope: Mapping[str, Any]) -> tuple[int, ...]:
    """Extract carrier byte lengths from a send envelope with hex carrier bytes."""

    if envelope.get("carrier_encoding") != "hex":
        return ()
    carriers = envelope.get("carriers")
    if not isinstance(carriers, list):
        return ()
    lengths: list[int] = []
    for carrier in carriers:
        if not isinstance(carrier, str):
            return ()
        lengths.append(len(bytes.fromhex(carrier)))
    return tuple(lengths)


def metric_record(input: MechanismMetricInput) -> dict[str, Any]:
    payload_bits = input.payload_bytes * 8
    carrier_capacity_bits = (
        input.carrier_units * input.raw_capacity_bits
        if input.carrier_units is not None and input.raw_capacity_bits is not None
        else None
    )
    return {
        "mechanism": input.mechanism_id,
        "suite": input.suite,
        "result": input.result,
        "payload_bytes": input.payload_bytes,
        "payload_bits": payload_bits,
        "recovered_bytes": input.recovered_bytes,
        "carrier_units": input.carrier_units,
        "raw_capacity_bits_per_unit": input.raw_capacity_bits,
        "carrier_capacity_bits": carrier_capacity_bits,
        "carrier_bit_efficiency": _ratio(payload_bits, carrier_capacity_bits),
        "carrier_wire_bytes": input.carrier_wire_bytes,
        "method_wire_bytes": input.method_wire_bytes,
        "method_wire_basis": input.method_wire_basis,
        "vxlan_underlay_bytes_no_fcs": input.vxlan_underlay_bytes_no_fcs,
        "payload_to_method_wire_ratio": _ratio(input.payload_bytes, input.method_wire_bytes),
        "method_wire_overhead": _ratio(input.method_wire_bytes, input.payload_bytes),
        "payload_to_vxlan_underlay_ratio": _ratio(
            input.payload_bytes, input.vxlan_underlay_bytes_no_fcs
        ),
        "vxlan_underlay_overhead": _ratio(input.vxlan_underlay_bytes_no_fcs, input.payload_bytes),
        "timing": {
            "measured_window_s": input.measured_window_s,
            "measured_window_basis": input.measured_window_basis,
            "scheduled_unit_rate_hz": input.scheduled_unit_rate_hz,
            "scheduled_duration_s": input.scheduled_duration_s,
            "observed_unit_rate_hz": _ratio(input.carrier_units, input.measured_window_s),
            "payload_bytes_per_s": _ratio(input.recovered_bytes, input.measured_window_s),
            "payload_bits_per_s": (
                _ratio(input.recovered_bytes * 8, input.measured_window_s)
                if input.recovered_bytes is not None
                else None
            ),
            "claim_status": input.timing_claim_status,
        },
    }


def metrics_summary(
    records: Sequence[Mapping[str, Any]],
    *,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Build compact aggregate statistics for a metrics record set."""

    pass_records = [record for record in records if record.get("result") == "pass"]
    measured = [
        record
        for record in pass_records
        if _nested_number(record, ("timing", "payload_bits_per_s")) is not None
    ]
    return {
        "schema_version": METRICS_SCHEMA_VERSION,
        "payload": dict(payload),
        "record_count": len(records),
        "pass_count": len(pass_records),
        "suite_counts": _counts(record.get("suite") for record in records),
        "timing_claim_status_counts": _counts(
            _nested_value(record, ("timing", "claim_status")) for record in records
        ),
        "method_wire_overhead": _stats(
            _number(record.get("method_wire_overhead")) for record in pass_records
        ),
        "payload_to_method_wire_ratio": _stats(
            _number(record.get("payload_to_method_wire_ratio")) for record in pass_records
        ),
        "payload_bits_per_s": _stats(
            _nested_number(record, ("timing", "payload_bits_per_s")) for record in measured
        ),
        "observed_unit_rate_hz": _stats(
            _nested_number(record, ("timing", "observed_unit_rate_hz")) for record in measured
        ),
        "fastest_payload_bits_per_s": _extreme(
            measured, ("timing", "payload_bits_per_s"), reverse=True
        ),
        "slowest_payload_bits_per_s": _extreme(
            measured, ("timing", "payload_bits_per_s"), reverse=False
        ),
    }


def _ratio(numerator: int | float | None, denominator: int | float | None) -> float | None:
    if numerator is None or denominator is None or denominator <= 0:
        return None
    return float(numerator) / float(denominator)


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
        return None
    return float(value)


def _nested_value(record: Mapping[str, Any], path: Sequence[str]) -> Any:
    value: Any = record
    for key in path:
        if not isinstance(value, Mapping):
            return None
        value = value.get(key)
    return value


def _nested_number(record: Mapping[str, Any], path: Sequence[str]) -> float | None:
    return _number(_nested_value(record, path))


def _counts(values: Iterable[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value) if value is not None else "unknown"
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def _stats(values: Iterable[float | None]) -> dict[str, float | None]:
    series = sorted(value for value in values if value is not None)
    if not series:
        return {"min": None, "median": None, "max": None}
    return {
        "min": series[0],
        "median": _median(series),
        "max": series[-1],
    }


def _median(series: Sequence[float]) -> float:
    midpoint = len(series) // 2
    if len(series) % 2:
        return series[midpoint]
    return (series[midpoint - 1] + series[midpoint]) / 2.0


def _extreme(
    records: Sequence[Mapping[str, Any]],
    path: Sequence[str],
    *,
    reverse: bool,
) -> dict[str, Any] | None:
    keyed = [
        (value, record) for record in records if (value := _nested_number(record, path)) is not None
    ]
    if not keyed:
        return None
    value, record = sorted(keyed, key=lambda item: item[0], reverse=reverse)[0]
    return {
        "mechanism": record.get("mechanism"),
        "suite": record.get("suite"),
        "value": value,
    }


__all__ = [
    "METRICS_SCHEMA_VERSION",
    "MechanismMetricInput",
    "carrier_lengths_from_envelope",
    "metric_record",
    "metrics_summary",
    "packet_method_wire_bytes",
]
