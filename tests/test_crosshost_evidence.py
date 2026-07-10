"""Public-safe Alice/Bob evidence indexes and claim-ledger counts."""

from __future__ import annotations

import json
from pathlib import Path

from celatim.analysis.crosshost_evidence import (
    ALL_USABLE_EXACT_RECOVERY_CLAIM,
    ENVELOPE_EXECUTED_CLAIM,
    MESSAGE_CARRIER_EXECUTED_CLAIM,
    PACKET_PATH_EXECUTED_CLAIM,
    REAL_DAEMON_OR_CRYPTO_CAPABLE_CLAIM,
    REAL_DAEMON_OR_CRYPTO_EXECUTED_CLAIM,
    REAL_PDU_CAPABLE_CLAIM,
    REAL_PDU_EXECUTED_CLAIM,
    build_claim_ledger,
    build_crosshost_public_index,
    claim_count,
)
from celatim.catalog import load_mechanisms

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def test_crosshost_public_index_strips_payload_and_counts_run_backed_buckets(tmp_path):
    run_dir = _write_minimal_run(tmp_path / "run1")
    index = build_crosshost_public_index(
        [run_dir],
        load_mechanisms(DATA),
        generated_at_unix_s=1.0,
    )

    assert index["schema_version"] == "celatim.alice_bob_public_index.v1"
    assert index["run_count"] == 1
    assert index["exact_recovery_count"] == 2
    assert index["exact_recovery_evidence_bucket_counts"] == {
        "real_daemon_or_crypto_path": 1,
        "real_pdu_packet_path": 1,
    }
    run = index["runs"][0]
    assert run["private_artifacts_excluded"] == ["payload.bin"]
    assert all(not artifact["path"].endswith("payload.bin") for artifact in run["file_artifacts"])
    assert run["pass_counts_by_suite"] == {
        "envelope": 1,
        "message_carrier": 1,
        "negative": 1,
        "packet": 1,
    }
    assert index["mechanism_pass_counts_by_suite"] == {
        "envelope": 1,
        "message_carrier": 1,
        "packet": 1,
    }
    assert run["timing_claim_status_counts"] == {
        "artifact_elapsed_not_native_network_goodput": 1,
        "crosshost_control_exchange_not_native_protocol_goodput": 1,
        "sender_process_afpacket_send_symbols_exact_recovery": 1,
    }


def test_claim_ledger_separates_capability_counts_from_run_backed_counts(tmp_path):
    index = build_crosshost_public_index(
        [_write_minimal_run(tmp_path / "run1")],
        load_mechanisms(DATA),
        generated_at_unix_s=1.0,
    )
    ledger = build_claim_ledger(
        load_mechanisms(DATA),
        crosshost_indexes=[index],
        generated_at_unix_s=1.0,
    )

    assert ledger["schema_version"] == "celatim.claim_ledger.v1"
    assert claim_count(ledger, REAL_PDU_CAPABLE_CLAIM) == 130
    assert claim_count(ledger, REAL_DAEMON_OR_CRYPTO_CAPABLE_CLAIM) == 8
    assert claim_count(ledger, ALL_USABLE_EXACT_RECOVERY_CLAIM) == 2
    assert claim_count(ledger, REAL_PDU_EXECUTED_CLAIM) == 1
    assert claim_count(ledger, REAL_DAEMON_OR_CRYPTO_EXECUTED_CLAIM) == 1
    assert claim_count(ledger, PACKET_PATH_EXECUTED_CLAIM) == 1
    assert claim_count(ledger, ENVELOPE_EXECUTED_CLAIM) == 1
    assert claim_count(ledger, MESSAGE_CARRIER_EXECUTED_CLAIM) == 1


def _write_minimal_run(run_dir: Path) -> Path:
    run_dir.mkdir()
    payload = {
        "len": 1024,
        "schema_version": "celatim.alice_bob_payload.v1",
        "sha256": "abc",
        "source": "/dev/urandom",
    }
    summary = {
        "schema_version": "celatim.alice_bob_crosshost.v1",
        "alice": "alice",
        "bob": "bob",
        "payload": {"len": 1024, "sha256": "abc"},
        "required_pass": True,
        "all_usable": 142,
        "usable_covered_by_required_suites": 2,
        "missing_usable": [],
        "packet": {"enabled": True, "pass": 1, "total": 1},
        "envelope": {"pass": 1, "total": 1},
        "message_carrier": {"enabled": True, "pass": 1, "total": 1},
        "negative": {"enabled": True, "pass": 1, "total": 1},
    }
    packet = [
        {
            "mechanism": "http2-ping-opaque",
            "result": "pass",
            "payload_len": 1024,
            "expected_sha256": "abc",
            "recovered_sha256": "abc",
        }
    ]
    envelope = [
        {
            "mechanism": "rsa-pss-salt",
            "result": "pass",
            "payload_len": 1024,
            "expected_sha256": "abc",
            "recovered_sha256": "abc",
        }
    ]
    message = [{"mechanism": "dns-txt-tunnel", "result": "pass"}]
    negative = [{"mechanism": "negative", "result": "pass"}]
    metric_records = [
        _metric(
            "http2-ping-opaque", "packet", "sender_process_afpacket_send_symbols_exact_recovery"
        ),
        _metric("rsa-pss-salt", "envelope", "artifact_elapsed_not_native_network_goodput"),
        _metric(
            "dns-txt-tunnel",
            "message_carrier",
            "crosshost_control_exchange_not_native_protocol_goodput",
        ),
    ]
    documents = {
        "payload.json": payload,
        "summary.json": summary,
        "packet-results.json": packet,
        "envelope-results.json": envelope,
        "message-results.json": message,
        "negative-results.json": negative,
        "metrics-results.json": {
            "schema_version": "celatim.alice_bob_metrics.v1",
            "payload": payload,
            "records": metric_records,
        },
        "metrics-summary.json": {
            "schema_version": "celatim.alice_bob_metrics.v1",
            "record_count": 3,
        },
    }
    for name, document in documents.items():
        (run_dir / name).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    (run_dir / "payload.bin").write_bytes(b"private")
    (run_dir / "run.log").write_text("[alice-bob] test log\n")
    return run_dir


def _metric(mechanism: str, suite: str, claim_status: str) -> dict[str, object]:
    return {
        "mechanism": mechanism,
        "suite": suite,
        "result": "pass",
        "payload_bytes": 1024,
        "recovered_bytes": 1024,
        "carrier_units": 1,
        "method_wire_bytes": 2048,
        "method_wire_basis": "unit-test",
        "timing": {
            "claim_status": claim_status,
            "payload_bits_per_s": 4096.0,
        },
    }
