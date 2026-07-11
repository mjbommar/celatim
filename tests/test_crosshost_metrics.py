"""Derived efficiency/timing metrics for Alice/Bob artifacts."""

from __future__ import annotations

import pytest

from celatim.analysis.crosshost_metrics import (
    MechanismMetricInput,
    carrier_lengths_from_envelope,
    metric_record,
    metrics_summary,
    packet_method_wire_bytes,
)


def test_carrier_lengths_from_hex_envelope():
    assert carrier_lengths_from_envelope(
        {"carrier_encoding": "hex", "carriers": ["00ff", "abcd12"]}
    ) == (2, 3)
    assert carrier_lengths_from_envelope({"carrier_encoding": None, "carriers": []}) == ()


def test_packet_method_wire_bytes_handles_payload_and_tcp_reserved_modes():
    assert packet_method_wire_bytes("http2-ping-opaque", [8, 8], "tcp") == 124
    assert packet_method_wire_bytes("quic-connection-id", [12], "udp") == 54
    assert packet_method_wire_bytes("tcp-reserved-bits", [20, 20], "tcp") == 108


def test_metric_record_computes_efficiency_and_timing_ratios():
    record = metric_record(
        MechanismMetricInput(
            mechanism_id="demo",
            suite="packet",
            result="pass",
            payload_bytes=100,
            recovered_bytes=100,
            carrier_units=20,
            raw_capacity_bits=64,
            carrier_wire_bytes=200,
            method_wire_bytes=400,
            method_wire_basis="unit-test",
            measured_window_s=2.0,
            measured_window_basis="unit-test-window",
            scheduled_unit_rate_hz=10.0,
            scheduled_duration_s=1.9,
            timing_claim_status="unit-test",
        )
    )

    assert record["packing_efficiency_diagnostic"] == pytest.approx(800 / 1280)
    assert record["useful_payload_ratio"] == pytest.approx(0.25)
    assert record["wire_expansion"] == pytest.approx(4.0)
    assert record["carrier_units_per_payload_byte"] == pytest.approx(0.2)
    assert record["timing"]["observed_unit_rate_hz"] == pytest.approx(10.0)
    assert record["timing"]["observed_recovery_rate_bps"] == pytest.approx(400.0)
    assert record["timing"]["native_goodput_bps"] is None


def test_metrics_summary_counts_suites_and_timing_claims():
    records = [
        metric_record(
            MechanismMetricInput(
                mechanism_id="fast",
                suite="packet",
                result="pass",
                payload_bytes=100,
                recovered_bytes=100,
                carrier_units=10,
                method_wire_bytes=200,
                method_wire_basis="unit-test",
                measured_window_s=1.0,
                timing_claim_status="measured",
            )
        ),
        metric_record(
            MechanismMetricInput(
                mechanism_id="unmeasured",
                suite="envelope",
                result="pass",
                payload_bytes=100,
                recovered_bytes=100,
                carrier_units=10,
                method_wire_bytes=500,
                method_wire_basis="unit-test",
                timing_claim_status="not_measured",
            )
        ),
    ]

    summary = metrics_summary(records, payload={"len": 100, "sha256": "abc"})

    assert summary["record_count"] == 2
    assert summary["suite_counts"] == {"envelope": 1, "packet": 1}
    assert summary["timing_claim_status_counts"] == {"measured": 1, "not_measured": 1}
    assert summary["fastest_observed_recovery_rate_bps"]["mechanism"] == "fast"
    assert summary["wire_expansion"] == {
        "n": 2,
        "min": 2.0,
        "q1": 2.75,
        "median": 3.5,
        "q3": 4.25,
        "max": 5.0,
    }
