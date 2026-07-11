"""Session CLI covers caller-supplied payload bytes and JSON handoff."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest

import celatim.cli as cli_module
import celatim.testbed.qemu as qemu_module
from celatim import ChannelSession, InMemoryTransport, MechanismProfile, PacingConfig
from celatim.cli import main, session_main
from celatim.errors import EnvelopeValidationError
from celatim.testbed import NetnsPairConfig

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"
SCENARIOS = Path(__file__).resolve().parents[1] / "scenarios"


def test_session_cli_roundtrips_text_payload_with_pacing(tmp_path):
    out = tmp_path / "roundtrip.json"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "roundtrip",
                "--mechanism",
                "tcp-reserved-bits",
                "--session-id",
                "cli-text",
                "--message",
                "reviewer-grade test",
                "--unit-rate-hz",
                "50",
                "--timing-quantum-s",
                "0.005",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    doc = json.loads(out.read_text())
    assert doc["command"] == "roundtrip"
    assert doc["session_id"] == "cli-text"
    assert doc["matches"] is True
    assert bytes.fromhex(doc["recovered_hex"]) == b"reviewer-grade test"
    assert doc["evidence"]["adapter_status"] == "minimal_packet_template"
    assert doc["evidence"]["pacing"]["unit_rate_hz"] == 50.0
    assert doc["evidence"]["pacing"]["timing_quantum_s"] == 0.005
    assert doc["evidence"]["scheduled_duration_s"] is not None


def test_session_cli_uses_packaged_catalog_default_outside_measurement_tree(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "roundtrip.json"

    assert (
        session_main(
            [
                "roundtrip",
                "--mechanism",
                "http2-ping-opaque",
                "--hex",
                "00 ff 80 41",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    doc = json.loads(out.read_text())
    assert doc["matches"] is True
    assert doc["mechanism_id"] == "http2-ping-opaque"
    assert bytes.fromhex(doc["recovered_hex"]) == b"\x00\xff\x80A"


def test_comm_cli_alias_roundtrips_and_records_program_name(tmp_path, monkeypatch):
    out = tmp_path / "comm-scenario.json"
    seen_commands: list[tuple[str, ...]] = []

    class FakeEvidenceResult:
        def to_json(self) -> dict[str, Any]:
            return {"ok": True, "command": list(seen_commands[0])}

    def fake_run_evidence(config, catalog, command=()):
        assert config.scenario_id == "comm-smoke"
        assert config.mechanism_id == "http2-ping-opaque"
        assert catalog == DATA
        seen_commands.append(tuple(command))
        return FakeEvidenceResult()

    monkeypatch.setattr(cli_module, "run_evidence", fake_run_evidence)

    assert (
        main(
            [
                "--catalog",
                str(DATA),
                "evidence",
                "run",
                "--scenario-id",
                "comm-smoke",
                "--mechanism",
                "http2-ping-opaque",
                "--hex",
                "00 ff 80 41",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    doc = json.loads(out.read_text())
    assert doc["ok"] is True
    assert seen_commands == [
        (
            "celatim",
            "--catalog",
            str(DATA),
            "evidence",
            "run",
            "--scenario-id",
            "comm-smoke",
            "--mechanism",
            "http2-ping-opaque",
            "--hex",
            "00 ff 80 41",
            "--output",
            str(out),
        )
    ]
    assert doc["command"][0] == "celatim"


def test_session_cli_timing_sweep_outputs_baseline_and_trials(tmp_path):
    out = tmp_path / "timing-sweep.json"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "timing",
                "sweep",
                "--mechanism",
                "dns-timing",
                "--hex",
                "00 ff 80 41",
                "--unit-rate-hz",
                "100",
                "--quantum-s",
                "0.01",
                "--quantum-s",
                "0.005",
                "--run-id",
                "cli-sweep",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    doc = json.loads(out.read_text())
    assert doc["schema_version"] == "celatim.timing_sweep.v1"
    assert doc["run_id"] == "cli-sweep"
    assert doc["mechanism_id"] == "dns-timing"
    assert doc["claim_status"] == "local_timed_memory_scheme_demonstration_not_capacity"
    assert doc["baseline"]["timing_profile"]["timing_quantum_s"] is None
    assert [trial["quantum_s"] for trial in doc["trials"]] == [0.01, 0.005]
    assert all(trial["payload_error_rate"] == 0.0 for trial in doc["trials"])


def test_session_cli_observed_timing_sweep_ingests_trace_json(tmp_path):
    out = tmp_path / "observed-timing-sweep.json"
    trace_path = tmp_path / "trace.json"
    profile = MechanismProfile.from_catalog("dns-timing", DATA)
    payload = bytes.fromhex("00 ff 80 41")
    baseline_payload = bytes(len(payload))
    pacing = PacingConfig(unit_rate_hz=100.0)
    baseline_count = _carrier_count(profile, baseline_payload, pacing)
    trial_count = _carrier_count(profile, payload, pacing)
    trace_path.write_text(
        json.dumps(
            {
                "path_kind": "dns_netns_pcap",
                "path_metadata": {"tap": "unit-test-pcap", "stack": "netns"},
                "baseline_payload_hex": baseline_payload.hex(),
                "baseline": {
                    "session_id": "cli-observed:baseline",
                    "observed_offsets_s": list(_offsets(baseline_count)),
                    "recovered_hex": baseline_payload.hex(),
                },
                "trials": [
                    {
                        "session_id": "cli-observed:q1",
                        "quantum_s": 0.01,
                        "observed_offsets_s": list(_offsets(trial_count)),
                        "recovered_hex": payload.hex(),
                    }
                ],
            },
            sort_keys=True,
        )
        + "\n"
    )

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "timing",
                "observed-sweep",
                "--mechanism",
                "dns-timing",
                "--hex",
                "00 ff 80 41",
                "--unit-rate-hz",
                "100",
                "--trace-json",
                str(trace_path),
                "--run-id",
                "cli-observed",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    doc = json.loads(out.read_text())
    assert doc["schema_version"] == "celatim.timing_sweep.v1"
    assert doc["run_id"] == "cli-observed"
    assert doc["path_kind"] == "dns_netns_pcap"
    assert (
        doc["claim_status"]
        == "observed_trace_timing_sweep_not_capacity_until_trace_provenance_review"
    )
    assert doc["path_metadata"] == {"tap": "unit-test-pcap", "stack": "netns"}
    assert doc["ok"] is True
    assert doc["baseline"]["session_id"] == "cli-observed:baseline"
    assert doc["baseline"]["carrier_units"] == baseline_count
    assert doc["trials"][0]["session_id"] == "cli-observed:q1"
    assert doc["trials"][0]["quantum_s"] == 0.01
    assert doc["trials"][0]["carrier_units"] == trial_count
    assert doc["trials"][0]["payload_error_rate"] == 0.0


def test_session_cli_send_recv_hex_payload(tmp_path):
    sent = tmp_path / "send.json"
    received = tmp_path / "recv.json"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "send",
                "--mechanism",
                "rtp-rtcp-ext-app",
                "--session-id",
                "cli-hex",
                "--hex",
                "00 ff 80 41",
                "--output",
                str(sent),
            ]
        )
        == 0
    )

    sent_doc = json.loads(sent.read_text())
    assert sent_doc["command"] == "send"
    assert sent_doc["adapter_status"] == "real_pdu_fixture"
    assert "parser_validated" in sent_doc["adapter_capabilities"]
    assert sent_doc["symbol_encoding"] == "hex"
    assert sent_doc["carrier_encoding"] == "hex"
    assert sent_doc["payload_len"] == 4
    assert sent_doc["carrier_units"] > 0
    assert sent_doc["carrier_units_with_bytes"] == sent_doc["carrier_units"]
    assert len(sent_doc["carriers"]) == sent_doc["carrier_units"]
    assert len(sent_doc["carrier_unit_sha256"]) == sent_doc["carrier_units"]

    assert (
        session_main(
            ["--catalog", str(DATA), "recv", "--input", str(sent), "--output", str(received)]
        )
        == 0
    )

    received_doc = json.loads(received.read_text())
    assert received_doc["command"] == "recv"
    assert received_doc["session_id"] == "cli-hex"
    assert bytes.fromhex(received_doc["recovered_hex"]) == b"\x00\xff\x80A"
    assert received_doc["carrier_input_used"] is True
    assert received_doc["parser_validated"] is True
    assert received_doc["carrier_units_with_bytes"] == sent_doc["carrier_units_with_bytes"]
    assert received_doc["carrier_unit_sha256"] == sent_doc["carrier_unit_sha256"]
    assert received_doc["evidence"]["adapter_status"] == "real_pdu_fixture"
    assert received_doc["evidence"]["payload_len"] == 4


def test_session_cli_send_recv_via_file_transport(tmp_path):
    sent = tmp_path / "send.json"
    received = tmp_path / "recv.json"
    transport_dir = tmp_path / "transport"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "send",
                "--mechanism",
                "http2-ping-opaque",
                "--session-id",
                "file-cli",
                "--hex",
                "00 ff 80 41",
                "--unit-rate-hz",
                "20",
                "--transport-dir",
                str(transport_dir),
                "--output",
                str(sent),
            ]
        )
        == 0
    )

    sent_doc = json.loads(sent.read_text())
    transport_record = Path(sent_doc["transport_record"])
    assert sent_doc["transport"] == "file"
    assert transport_record.is_file()
    assert transport_record.is_relative_to(transport_dir)
    assert sent_doc["carrier_encoding"] == "hex"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "recv",
                "--mechanism",
                "http2-ping-opaque",
                "--session-id",
                "file-cli",
                "--transport-dir",
                str(transport_dir),
                "--output",
                str(received),
            ]
        )
        == 0
    )

    received_doc = json.loads(received.read_text())
    assert received_doc["transport"] == "file"
    assert received_doc["transport_record"] == str(transport_record)
    assert bytes.fromhex(received_doc["recovered_hex"]) == b"\x00\xff\x80A"
    assert received_doc["carrier_input_used"] is True
    assert received_doc["parser_validated"] is True
    assert received_doc["carrier_unit_sha256"] == sent_doc["carrier_unit_sha256"]
    assert received_doc["evidence"]["pacing"]["unit_rate_hz"] == 20.0


def test_session_cli_send_recv_via_pcap_transport(tmp_path):
    sent = tmp_path / "send.json"
    received = tmp_path / "recv.json"
    pcap_dir = tmp_path / "pcaps"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "send",
                "--mechanism",
                "http2-ping-opaque",
                "--session-id",
                "pcap-cli",
                "--hex",
                "00 ff 80 41",
                "--pcap-dir",
                str(pcap_dir),
                "--output",
                str(sent),
            ]
        )
        == 0
    )

    sent_doc = json.loads(sent.read_text())
    transport_record = Path(sent_doc["transport_record"])
    assert sent_doc["transport"] == "pcap"
    assert transport_record.is_file()
    assert transport_record.is_relative_to(pcap_dir)

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "recv",
                "--mechanism",
                "http2-ping-opaque",
                "--session-id",
                "pcap-cli",
                "--pcap-dir",
                str(pcap_dir),
                "--output",
                str(received),
            ]
        )
        == 0
    )

    received_doc = json.loads(received.read_text())
    assert received_doc["transport"] == "pcap"
    assert received_doc["transport_record"] == str(transport_record)
    assert bytes.fromhex(received_doc["recovered_hex"]) == b"\x00\xff\x80A"
    assert received_doc["evidence"]["carrier_units"] == sent_doc["carrier_units"]


def test_session_cli_pcap_decode_reads_standalone_capture(tmp_path):
    sent = tmp_path / "send.json"
    decoded = tmp_path / "pcap-decode.json"
    pcap_dir = tmp_path / "pcaps"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "send",
                "--mechanism",
                "http2-ping-opaque",
                "--session-id",
                "pcap-decode-cli",
                "--hex",
                "00 ff 80 41",
                "--pcap-dir",
                str(pcap_dir),
                "--output",
                str(sent),
            ]
        )
        == 0
    )
    pcap_path = Path(json.loads(sent.read_text())["transport_record"])

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "pcap",
                "decode",
                "--mechanism",
                "http2-ping-opaque",
                "--pcap",
                str(pcap_path),
                "--session-id",
                "pcap-decode-cli",
                "--tshark-binary",
                "tshark-definitely-not-installed",
                "--expected-hex",
                "00 ff 80 41",
                "--output",
                str(decoded),
            ]
        )
        == 0
    )

    doc = json.loads(decoded.read_text())
    assert doc["schema_version"] == "celatim.pcap_decode.v1"
    assert doc["mechanism_id"] == "http2-ping-opaque"
    assert doc["claim_status"] == "same_code_pcap_decode_not_independent_trace_validation"
    assert doc["pcap"]["path"] == str(pcap_path)
    assert doc["pcap"]["packet_count"] == doc["carrier_units"]
    assert bytes.fromhex(doc["recovered_hex"]) == b"\x00\xff\x80A"
    assert doc["matches_expected"] is True
    assert doc["parser_validated"] is True
    assert doc["parser_provenance_count"] == 1
    assert doc["parser_provenance_executed_count"] == 0
    assert doc["parser_provenance"][0]["result"] == "tool_missing"
    assert doc["parser_provenance"][0]["command"][0] == "tshark-definitely-not-installed"
    assert doc["evidence"]["endpoint_os"]["topology_kind"] == "same_host_artifact"


def test_session_cli_afpacket_recv_requires_expected_frames_before_socket_open(tmp_path):
    out = tmp_path / "recv.json"

    try:
        session_main(
            [
                "--catalog",
                str(DATA),
                "recv",
                "--mechanism",
                "http2-ping-opaque",
                "--session-id",
                "live",
                "--afpacket-ipv4",
                "--output",
                str(out),
            ]
        )
    except ValueError as exc:
        assert "--expected-frames" in str(exc)
    else:
        raise AssertionError(
            "AF_PACKET recv without expected frame count should fail before socket open"
        )


def test_session_cli_recv_rejects_tampered_real_pdu_carrier(tmp_path):
    sent = tmp_path / "send.json"
    received = tmp_path / "recv.json"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "send",
                "--mechanism",
                "http2-ping-opaque",
                "--session-id",
                "tamper",
                "--hex",
                "00 ff 80 41",
                "--output",
                str(sent),
            ]
        )
        == 0
    )

    sent_doc = json.loads(sent.read_text())
    carrier = bytearray.fromhex(sent_doc["carriers"][0])
    carrier[-1] ^= 0x01
    sent_doc["carriers"][0] = carrier.hex()
    sent.write_text(json.dumps(sent_doc))

    try:
        session_main(
            ["--catalog", str(DATA), "recv", "--input", str(sent), "--output", str(received)]
        )
    except EnvelopeValidationError as exc:
        assert "carrier hashes do not match carrier bytes" in str(exc)
    else:
        raise AssertionError("tampered carrier should fail parser validation")


def test_session_cli_roundtrips_binary_file_payload(tmp_path):
    payload = b"\x00file\xffpayload\x80"
    payload_file = tmp_path / "payload.bin"
    out = tmp_path / "file-roundtrip.json"
    payload_file.write_bytes(payload)

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "roundtrip",
                "--mechanism",
                "quic-connection-id",
                "--session-id",
                "cli-file",
                "--file",
                str(payload_file),
                "--output",
                str(out),
            ]
        )
        == 0
    )

    doc = json.loads(out.read_text())
    assert doc["matches"] is True
    assert bytes.fromhex(doc["recovered_hex"]) == payload


def test_session_cli_evidence_run_emits_covert_and_control_results(tmp_path):
    out = tmp_path / "evidence.json"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "evidence",
                "run",
                "--scenario-id",
                "cli-evidence",
                "--mechanism",
                "http2-ping-opaque",
                "--hex",
                "00 ff 80 41",
                "--control-message",
                "control",
                "--unit-rate-hz",
                "10",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    doc = json.loads(out.read_text())
    assert doc["schema_version"] == "celatim.evidence_run.v1"
    assert doc["ok"] is True
    assert doc["scenario_id"] == "cli-evidence"
    assert doc["adapter_status"] == "real_pdu_fixture"
    assert doc["control_kind"] == "control_message"
    assert bytes.fromhex(doc["covert"]["recovered_hex"]) == b"\x00\xff\x80A"
    assert doc["covert"]["parser_validated"] is True
    assert bytes.fromhex(doc["benign_control"]["recovered_hex"]) == b"control"
    assert doc["benign_control"]["parser_validated"] is True
    assert doc["covert"]["evidence"]["pacing"]["unit_rate_hz"] == 10.0
    assert doc["reproducibility"]["command"][:4] == [
        "celatim",
        "--catalog",
        str(DATA),
        "evidence",
    ]
    assert doc["reproducibility"]["catalog_sha256"]


def test_session_cli_evidence_run_accepts_random_control_payload(tmp_path):
    out = tmp_path / "evidence-random-control.json"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "evidence",
                "run",
                "--scenario-id",
                "cli-random-control",
                "--mechanism",
                "http2-ping-opaque",
                "--hex",
                "00 ff 80 41",
                "--control-random-bytes",
                "12",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    doc = json.loads(out.read_text())
    control_payload = bytes.fromhex(doc["benign_control"]["recovered_hex"])
    assert doc["ok"] is True
    assert doc["control_kind"] == "control_random_bytes"
    assert len(control_payload) == 12
    assert doc["benign_control"]["evidence"]["payload_len"] == 12


def test_session_cli_evidence_run_writes_carrier_artifacts(tmp_path):
    out = tmp_path / "evidence.json"
    artifact_dir = tmp_path / "artifacts"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "evidence",
                "run",
                "--scenario-id",
                "cli-artifacts",
                "--mechanism",
                "http2-ping-opaque",
                "--hex",
                "00 ff 80 41",
                "--control-message",
                "control",
                "--artifact-dir",
                str(artifact_dir),
                "--run-id",
                "cli-artifact-run",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    doc = json.loads(out.read_text())
    assert doc["ok"] is True
    assert doc["run_id"] == "cli-artifact-run"
    assert doc["run_log"] is not None
    assert Path(doc["run_log"]["path"]).is_file()
    assert Path(doc["run_log"]["path"]).is_relative_to(artifact_dir)
    assert doc["covert"]["artifacts"]
    assert doc["benign_control"]["artifacts"]
    assert Path(doc["covert"]["artifacts"][0]["path"]).is_file()
    assert Path(doc["covert"]["artifacts"][0]["path"]).is_relative_to(artifact_dir)
    assert doc["covert"]["artifacts"][0]["sha256"] in doc["covert"]["carrier_unit_sha256"]


def test_session_cli_evidence_run_writes_explicit_log_dir(tmp_path):
    out = tmp_path / "evidence.json"
    log_dir = tmp_path / "logs"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "evidence",
                "run",
                "--scenario-id",
                "cli-logs",
                "--mechanism",
                "http2-ping-opaque",
                "--hex",
                "00 ff 80 41",
                "--control-message",
                "control",
                "--run-id",
                "cli-log-run",
                "--log-dir",
                str(log_dir),
                "--output",
                str(out),
            ]
        )
        == 0
    )

    doc = json.loads(out.read_text())
    assert doc["run_id"] == "cli-log-run"
    assert doc["run_log"] is not None
    log_path = Path(doc["run_log"]["path"])
    assert log_path.is_file()
    assert log_path.is_relative_to(log_dir)
    events = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert [event["event"] for event in events] == [
        "run_started",
        "case_finished",
        "case_finished",
        "run_finished",
    ]
    assert events[0]["command"][:4] == [
        "celatim",
        "--catalog",
        str(DATA),
        "evidence",
    ]


def test_session_cli_evidence_run_uses_file_transport(tmp_path):
    out = tmp_path / "evidence.json"
    transport_dir = tmp_path / "wire"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "evidence",
                "run",
                "--scenario-id",
                "cli-file-evidence",
                "--mechanism",
                "http2-ping-opaque",
                "--hex",
                "00 ff 80 41",
                "--control-message",
                "control",
                "--transport-dir",
                str(transport_dir),
                "--output",
                str(out),
            ]
        )
        == 0
    )

    doc = json.loads(out.read_text())
    assert doc["ok"] is True
    assert doc["covert"]["transport_kind"] == "file"
    assert Path(doc["covert"]["transport_record"]).is_file()
    assert Path(doc["covert"]["transport_record"]).is_relative_to(transport_dir)
    _assert_transport_artifact(doc["covert"], transport_dir)
    assert doc["covert"]["parser_validated"] is True
    assert doc["benign_control"]["transport_kind"] == "file"
    assert Path(doc["benign_control"]["transport_record"]).is_file()
    _assert_transport_artifact(doc["benign_control"], transport_dir)


def test_session_cli_evidence_run_uses_pcap_transport(tmp_path):
    out = tmp_path / "evidence.json"
    pcap_dir = tmp_path / "pcaps"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "evidence",
                "run",
                "--scenario-id",
                "cli-pcap-evidence",
                "--mechanism",
                "http2-ping-opaque",
                "--hex",
                "00 ff 80 41",
                "--control-message",
                "control",
                "--pcap-dir",
                str(pcap_dir),
                "--output",
                str(out),
            ]
        )
        == 0
    )

    doc = json.loads(out.read_text())
    assert doc["ok"] is True
    assert doc["covert"]["transport_kind"] == "pcap"
    assert Path(doc["covert"]["transport_record"]).is_file()
    assert Path(doc["covert"]["transport_record"]).is_relative_to(pcap_dir)
    _assert_transport_artifact(doc["covert"], pcap_dir)
    assert doc["covert"]["parser_validated"] is True
    assert doc["benign_control"]["transport_kind"] == "pcap"
    assert Path(doc["benign_control"]["transport_record"]).is_file()
    _assert_transport_artifact(doc["benign_control"], pcap_dir)


def test_session_cli_evidence_index_summarizes_reviewer_artifacts(tmp_path):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    evidence_path = evidence_dir / "pcap-evidence.json"
    ignored_path = evidence_dir / "not-evidence.json"
    index_path = tmp_path / "index.json"
    rooted_index_path = tmp_path / "index-rooted.json"
    pcap_dir = tmp_path / "pcaps"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "evidence",
                "run",
                "--scenario-id",
                "cli-pcap-index",
                "--mechanism",
                "http2-ping-opaque",
                "--hex",
                "00 ff 80 41",
                "--control-message",
                "control",
                "--pcap-dir",
                str(pcap_dir),
                "--output",
                str(evidence_path),
            ]
        )
        == 0
    )
    ignored_path.write_text(json.dumps({"schema_version": "not-evidence"}) + "\n")

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "evidence",
                "index",
                str(evidence_dir),
                "--output",
                str(index_path),
            ]
        )
        == 0
    )

    evidence_doc = json.loads(evidence_path.read_text())
    index_doc = json.loads(index_path.read_text())
    assert index_doc["schema_version"] == "celatim.evidence_index.v1"
    assert index_doc["evidence_count"] == 1
    assert index_doc["ok_count"] == 1
    assert index_doc["skipped_json_count"] == 1
    assert index_doc["transport_artifact_count"] == 2
    assert index_doc["observer_validation_count"] == 2
    assert index_doc["observer_validation_ok_count"] == 2
    assert index_doc["detector_count"] == 2
    assert index_doc["detector_executed_count"] == 2
    assert index_doc["mutation_control_count"] == 4
    assert index_doc["mutation_control_ok_count"] == 4
    assert index_doc["evidence_tier_counts"] == {"in_memory_regression": 1}
    assert index_doc["privilege_counts"] == {"none": 1}
    assert index_doc["expected_runtime_s_total"] is None
    assert index_doc["required_tools"] == []
    assert index_doc["required_extras"] == []
    item = index_doc["items"][0]
    assert item["scenario_id"] == "cli-pcap-index"
    assert item["mechanism_id"] == "http2-ping-opaque"
    assert item["sha256"] == hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    assert item["package_version"] == evidence_doc["reproducibility"]["package_version"]
    assert item["release"] == evidence_doc["reproducibility"]["release"]
    assert item["scenario_metadata"] == evidence_doc["scenario_metadata"]
    assert item["transport_artifacts"] == [
        evidence_doc["covert"]["transport_artifact"],
        evidence_doc["benign_control"]["transport_artifact"],
    ]
    assert item["cases"][0]["observer_validators"] == ["second_parser"]
    assert item["cases"][0]["detector_count"] == 1
    assert item["cases"][0]["detector_executed_count"] == 1
    assert item["cases"][0]["detector_implementation_kinds"] == ["same_code"]
    assert item["cases"][0]["mutation_control_count"] == 2
    assert item["cases"][0]["mutation_control_ok_count"] == 2

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "evidence",
                "index",
                str(evidence_dir),
                "--path-root",
                str(tmp_path),
                "--output",
                str(rooted_index_path),
            ]
        )
        == 0
    )
    rooted_doc = json.loads(rooted_index_path.read_text())
    assert rooted_doc["evidence_roots"] == ["evidence"]
    assert rooted_doc["items"][0]["path"] == "evidence/pcap-evidence.json"
    assert rooted_doc["items"][0]["transport_artifacts"][0]["path"].startswith("pcaps/")


def test_session_cli_detector_replay_writes_source_labeled_report(tmp_path):
    pcap_dir = tmp_path / "pcaps"
    replay_out = tmp_path / "detector-replay.json"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "send",
                "--mechanism",
                "tcp-reserved-bits",
                "--session-id",
                "detector-replay",
                "--message",
                "trace",
                "--pcap-dir",
                str(pcap_dir),
            ]
        )
        == 0
    )

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "detector",
                "replay",
                "--pcap",
                str(pcap_dir / "detector-replay.pcap"),
                "--source-kind",
                "local_generated_control",
                "--mechanism",
                "tcp-reserved-bits",
                "--filtering-assumption",
                "CLI fixture, not a real benign-trace FP estimate",
                "--tcpdump-binary",
                "tcpdump-definitely-not-installed",
                "--output",
                str(replay_out),
            ]
        )
        == 1
    )

    doc = json.loads(replay_out.read_text())
    assert doc["schema_version"] == "celatim.detector_replay.v1"
    assert doc["ok"] is False
    assert doc["trace"]["source_kind"] == "local_generated_control"
    assert doc["trace"]["filtering_assumptions"] == [
        "CLI fixture, not a real benign-trace FP estimate"
    ]
    assert doc["mechanism_count"] == 1
    assert doc["executed_count"] == 0
    assert doc["false_positive_claim_status"] == "not_false_positive_estimate"
    assert doc["false_positive_claim_blockers"] == [
        "not_false_positive_source",
        "detector_execution_incomplete",
    ]
    result = doc["mechanisms"][0]
    assert result["mechanism_id"] == "tcp-reserved-bits"
    assert result["false_positive_estimate"] is False
    assert result["detector_provenance"]["result"] == "tool_missing"


def test_session_cli_detector_replay_tshark_backend_writes_source_labeled_report(tmp_path):
    pcap_dir = tmp_path / "pcaps"
    replay_out = tmp_path / "detector-replay-tshark.json"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "send",
                "--mechanism",
                "tcp-reserved-bits",
                "--session-id",
                "detector-replay-tshark",
                "--message",
                "trace",
                "--pcap-dir",
                str(pcap_dir),
            ]
        )
        == 0
    )

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "detector",
                "replay",
                "--pcap",
                str(pcap_dir / "detector-replay-tshark.pcap"),
                "--source-kind",
                "public_benign_trace",
                "--backend",
                "tshark_display_filter",
                "--tshark-binary",
                "tshark-definitely-not-installed",
                "--output",
                str(replay_out),
            ]
        )
        == 1
    )

    doc = json.loads(replay_out.read_text())
    assert doc["schema_version"] == "celatim.detector_replay.v1"
    assert doc["ok"] is False
    assert doc["false_positive_estimate"] is False
    assert doc["false_positive_claim_status"] == "not_false_positive_estimate"
    assert doc["false_positive_claim_blockers"] == [
        "missing_trace_name",
        "missing_trace_license",
        "missing_filtering_assumptions",
        "missing_public_trace_origin",
        "detector_execution_incomplete",
    ]
    result = doc["mechanisms"][0]
    assert result["mechanism_id"] == "tcp-reserved-bits"
    provenance = result["detector_provenance"]
    assert provenance["implementation_kind"] == "independent_tool_output"
    assert provenance["detector_family"] == "display_filter"
    assert provenance["rule_format"] == "tshark-display-filter"
    assert provenance["rule"] == "tcp.flags.res != 0"
    assert provenance["result"] == "tool_missing"
    assert provenance["false_positive_estimate"] is False


def test_session_cli_detector_replay_suricata_backend_writes_source_labeled_report(tmp_path):
    pcap_dir = tmp_path / "pcaps"
    replay_out = tmp_path / "detector-replay-suricata.json"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "send",
                "--mechanism",
                "tcp-reserved-bits",
                "--session-id",
                "detector-replay-suricata",
                "--message",
                "trace",
                "--pcap-dir",
                str(pcap_dir),
            ]
        )
        == 0
    )

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "detector",
                "replay",
                "--pcap",
                str(pcap_dir / "detector-replay-suricata.pcap"),
                "--source-kind",
                "public_benign_trace",
                "--backend",
                "suricata_rule",
                "--suricata-binary",
                "suricata-definitely-not-installed",
                "--output",
                str(replay_out),
            ]
        )
        == 1
    )

    doc = json.loads(replay_out.read_text())
    assert doc["schema_version"] == "celatim.detector_replay.v1"
    assert doc["ok"] is False
    assert doc["false_positive_estimate"] is False
    assert doc["false_positive_claim_status"] == "not_false_positive_estimate"
    assert doc["false_positive_claim_blockers"] == [
        "missing_trace_name",
        "missing_trace_license",
        "missing_filtering_assumptions",
        "missing_public_trace_origin",
        "detector_execution_incomplete",
    ]
    result = doc["mechanisms"][0]
    assert result["mechanism_id"] == "tcp-reserved-bits"
    provenance = result["detector_provenance"]
    assert provenance["implementation_kind"] == "independent_tool_output"
    assert provenance["detector_family"] == "ids_rule"
    assert provenance["rule_format"] == "suricata"
    assert "tcp.hdr" in provenance["rule"]
    assert provenance["result"] == "tool_missing"
    assert provenance["false_positive_estimate"] is False


def test_session_cli_detector_replay_corpus_writes_aggregate_report(tmp_path):
    pcap_dir = tmp_path / "pcaps"
    manifest = tmp_path / "trace-manifest.json"
    replay_out = tmp_path / "detector-replay-corpus.json"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "send",
                "--mechanism",
                "tcp-reserved-bits",
                "--session-id",
                "detector-corpus",
                "--message",
                "trace",
                "--pcap-dir",
                str(pcap_dir),
            ]
        )
        == 0
    )
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "celatim.detector_trace_manifest.v1",
                "traces": [
                    {
                        "path": "pcaps/detector-corpus.pcap",
                        "source_kind": "public_benign_trace",
                        "trace_name": "cli-public-clean",
                        "origin_url": "https://example.invalid/public-trace",
                        "license": "unit-test fixture",
                        "filtering_assumptions": [
                            "CLI fixture, not a real benign-trace FP estimate"
                        ],
                    }
                ],
            },
            sort_keys=True,
        )
        + "\n"
    )

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "detector",
                "replay-corpus",
                "--trace-manifest",
                str(manifest),
                "--mechanism",
                "tcp-reserved-bits",
                "--tcpdump-binary",
                "tcpdump-definitely-not-installed",
                "--output",
                str(replay_out),
            ]
        )
        == 1
    )

    doc = json.loads(replay_out.read_text())
    assert doc["schema_version"] == "celatim.detector_replay_corpus.v1"
    assert doc["ok"] is False
    assert doc["trace_count"] == 1
    assert doc["result_count"] == 1
    assert doc["executed_count"] == 0
    assert doc["false_positive_estimate"] is False
    assert doc["false_positive_claim_status"] == "not_false_positive_estimate"
    assert doc["false_positive_claim_blockers"] == ["detector_execution_incomplete"]
    assert doc["trace_source_kind_counts"] == {"public_benign_trace": 1}
    assert len(doc["mechanisms"]) == 1
    assert doc["mechanisms"][0]["mechanism_id"] == "tcp-reserved-bits"
    assert doc["mechanisms"][0]["false_positive_estimate"] is False
    trace = doc["traces"][0]
    assert trace["trace"]["trace_name"] == "cli-public-clean"
    assert trace["trace"]["packet_count"] > 0
    assert trace["false_positive_estimate"] is False
    assert trace["false_positive_claim_status"] == "not_false_positive_estimate"
    assert trace["false_positive_claim_blockers"] == ["detector_execution_incomplete"]


def test_session_cli_scrub_pcap_writes_report_and_scrubbed_pcap(tmp_path):
    pcap_dir = tmp_path / "pcaps"
    scrubbed_pcap = tmp_path / "scrubbed.pcap"
    scrub_report = tmp_path / "scrub-report.json"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "send",
                "--mechanism",
                "tcp-reserved-bits",
                "--session-id",
                "scrub-me",
                "--hex",
                "0f",
                "--pcap-dir",
                str(pcap_dir),
            ]
        )
        == 0
    )

    assert (
        session_main(
            [
                "scrub",
                "pcap",
                "--mechanism",
                "tcp-reserved-bits",
                "--input-pcap",
                str(pcap_dir / "scrub-me.pcap"),
                "--output-pcap",
                str(scrubbed_pcap),
                "--output",
                str(scrub_report),
            ]
        )
        == 0
    )

    doc = json.loads(scrub_report.read_text())
    assert doc["schema_version"] == "celatim.scrub_report.v1"
    assert doc["ok"] is True
    assert doc["mechanism_id"] == "tcp-reserved-bits"
    assert doc["before_matched_unit_count"] > 0
    assert doc["after_matched_unit_count"] == 0
    assert doc["scrubbed_unit_count"] == doc["before_matched_unit_count"]
    assert doc["output"]["sha256"] == hashlib.sha256(scrubbed_pcap.read_bytes()).hexdigest()


def test_session_cli_detector_rules_writes_manifest_and_rule_files(tmp_path):
    output_dir = tmp_path / "rules"
    manifest_out = tmp_path / "detector-rules-manifest.json"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "detector",
                "rules",
                "--output-dir",
                str(output_dir),
                "--output",
                str(manifest_out),
            ]
        )
        == 0
    )

    manifest = json.loads(manifest_out.read_text())
    assert manifest["schema_version"] == "celatim.detector_rules.v1"
    assert manifest["rule_mechanism_count"] == 68
    assert manifest["stateful_plan_mechanism_count"] == 52
    assert manifest["claim_status"] == "generated_not_executed_no_false_positive_estimate"
    assert manifest["stateful_claim_status"] == "generated_not_executed_requires_trace_baseline"
    assert (output_dir / "detector-rules.md").is_file()
    assert (
        "0>>22&0x3C@12>>24&0x0E=0x1:0x0E"
        in (output_dir / "detector-rules.iptables-u32").read_text()
    )
    assert "tcp[12] & 0x0e != 0" in (output_dir / "detector-rules.bpf").read_text()
    assert "padding_entropy" in (output_dir / "detector-stateful-plan.md").read_text()
    assert "const detector_plan" in (output_dir / "detector-stateful.zeek").read_text()
    assert (
        "generated_not_executed_requires_trace_baseline"
        in (output_dir / "detector-stateful.suricata.rules").read_text()
    )


def test_session_cli_detector_windows_guidance_writes_markdown(tmp_path):
    out = tmp_path / "windows-pktmon-etw-guidance.md"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "detector",
                "windows-guidance",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    markdown = out.read_text()
    assert "# Windows pktmon / ETW Capture Guidance" in markdown
    assert "capture_guidance_not_header_bit_filter" in markdown
    assert "not a Windows firewall detector" in markdown
    assert "pktmon etl2pcap" in markdown


def test_session_cli_bundle_manifest_hashes_reviewer_artifacts(tmp_path):
    catalog = tmp_path / "mechanisms.jsonl"
    support_matrix = tmp_path / "evidence-support-matrix.md"
    detector_scrub_guidance = tmp_path / "detector-scrub-guidance.md"
    detector_rules_manifest = tmp_path / "detector-rules-manifest.json"
    detector_rules_markdown = tmp_path / "detector-rules" / "detector-rules.md"
    windows_capture_guidance = tmp_path / "windows-pktmon-etw-guidance.md"
    doctor = tmp_path / "doctor.json"
    scenarios = tmp_path / "scenarios.json"
    execution_plan = tmp_path / "execution-plan.json"
    testbed_requirements = tmp_path / "testbed-requirements.json"
    evidence_index = tmp_path / "evidence-index.json"
    public_evidence_index = tmp_path / "public-evidence-index.json"
    detector_replay = tmp_path / "detector-replay.json"
    scrub_report = tmp_path / "scrub-report.json"
    paper_table = tmp_path / "field-catalog-longtable.tex"
    package_wheel = tmp_path / "celatim-0.2.0-py3-none-any.whl"
    lockfile = tmp_path / "uv.lock"
    scenario_spec = tmp_path / "http2-ping-opaque.toml"
    testbed_package = tmp_path / "Dockerfile"
    testbed_preflight = tmp_path / "qemu-preflight.json"
    out = tmp_path / "bundle-manifest.json"
    verify_out = tmp_path / "bundle-verify.json"
    public_out = tmp_path / "public-bundle-manifest.json"
    public_verify_out = tmp_path / "public-bundle-verify.json"
    public_verify_bad_out = tmp_path / "public-bundle-verify-bad.json"
    semantic_bad_manifest = tmp_path / "bundle-manifest-semantic-bad.json"
    verify_semantic_bad_out = tmp_path / "bundle-verify-semantic-bad.json"
    verify_bad_out = tmp_path / "bundle-verify-bad.json"

    catalog.write_text(DATA.read_text())
    support_matrix.write_text("# Evidence Support Matrix\n")
    detector_scrub_guidance.write_text("# Detector and Scrub Guidance\n")
    detector_rules_manifest.write_text('{"schema_version":"celatim.detector_rules.v1"}\n')
    detector_rules_markdown.parent.mkdir()
    detector_rules_markdown.write_text("# Detector Rule Appendix\n")
    windows_capture_guidance.write_text("# Windows pktmon/ETW Capture Guidance\n")
    doctor.write_text(
        json.dumps(
            {
                "schema_version": "celatim.doctor.v1",
                "ok": True,
            },
            sort_keys=True,
        )
        + "\n"
    )
    scenarios.write_text(
        json.dumps(
            {
                "schema_version": "celatim.scenario_inventory.v1",
                "scenario_count": 1,
            },
            sort_keys=True,
        )
        + "\n"
    )
    execution_plan.write_text(
        json.dumps(
            {
                "schema_version": "celatim.scenario_execution_plan.v1",
                "scenario_count": 1,
            },
            sort_keys=True,
        )
        + "\n"
    )
    testbed_requirements.write_text(
        json.dumps(
            {
                "schema_version": "celatim.testbed_requirements.v1",
                "profile_count": 1,
            },
            sort_keys=True,
        )
        + "\n"
    )
    evidence_index.write_text(
        json.dumps(
            {
                "schema_version": "celatim.evidence_index.v1",
                "evidence_count": 1,
                "ok_count": 1,
                "failed_count": 0,
                "run_log_artifact_count": 1,
                "transport_artifact_count": 2,
                "evidence_tier_counts": {"real_pdu_packet_path": 1},
                "privilege_counts": {"none": 1},
                "expected_runtime_s_total": 5.0,
                "required_tools": [],
                "required_extras": [],
            },
            sort_keys=True,
        )
        + "\n"
    )
    detector_replay.write_text('{"schema_version":"celatim.detector_replay.v1"}\n')
    scrub_report.write_text('{"schema_version":"celatim.scrub_report.v1"}\n')
    paper_table.write_text("% table\n")
    package_wheel.write_bytes(b"wheel bytes\n")
    lockfile.write_text("# lockfile\n")
    scenario_spec.write_text('scenario_id = "http2-ping-opaque-real-pdu-smoke"\n')
    testbed_package.write_text("FROM debian:stable-slim\n")
    testbed_preflight.write_text('{"schema_version":"celatim.qemu_tap_preflight.v1"}\n')

    assert (
        session_main(
            [
                "bundle",
                "manifest",
                "--bundle-name",
                "cli-bundle",
                "--bundle-root",
                str(tmp_path),
                "--doctor",
                str(doctor),
                "--scenarios",
                str(scenarios),
                "--evidence-index",
                str(evidence_index),
                "--paper-table",
                str(paper_table),
                "--package-wheel",
                str(package_wheel),
                "--lockfile",
                str(lockfile),
                "--detector-replay",
                str(detector_replay),
                "--scrub-report",
                str(scrub_report),
                "--scenario-spec",
                str(scenario_spec),
                "--testbed-package",
                str(testbed_package),
                "--testbed-preflight",
                str(testbed_preflight),
                "--output",
                str(out),
            ]
        )
        == 0
    )

    manifest = json.loads(out.read_text())
    assert manifest["schema_version"] == "celatim.reviewer_bundle.v1"
    assert manifest["bundle_name"] == "cli-bundle"
    assert manifest["doctor_ok"] is True
    assert manifest["scenario_count"] == 1
    assert manifest["evidence_count"] == 1
    assert manifest["artifact_count"] == 11
    assert manifest["evidence_tier_counts"] == {"real_pdu_packet_path": 1}
    assert manifest["privilege_counts"] == {"none": 1}
    assert manifest["expected_runtime_s_total"] == 5.0
    artifacts = {artifact["kind"]: artifact for artifact in manifest["artifacts"]}
    assert artifacts["doctor_report"]["path"] == "doctor.json"
    assert artifacts["doctor_report"]["sha256"] == hashlib.sha256(doctor.read_bytes()).hexdigest()
    assert artifacts["paper_table"]["size_bytes"] == paper_table.stat().st_size
    assert (
        artifacts["package_wheel"]["sha256"]
        == hashlib.sha256(package_wheel.read_bytes()).hexdigest()
    )
    assert artifacts["lockfile"]["sha256"] == hashlib.sha256(lockfile.read_bytes()).hexdigest()
    assert (
        artifacts["detector_replay"]["sha256"]
        == hashlib.sha256(detector_replay.read_bytes()).hexdigest()
    )
    assert (
        artifacts["scrub_report"]["sha256"] == hashlib.sha256(scrub_report.read_bytes()).hexdigest()
    )
    assert (
        artifacts["scenario_spec"]["sha256"]
        == hashlib.sha256(scenario_spec.read_bytes()).hexdigest()
    )
    assert (
        artifacts["testbed_package"]["sha256"]
        == hashlib.sha256(testbed_package.read_bytes()).hexdigest()
    )
    assert (
        artifacts["testbed_preflight"]["sha256"]
        == hashlib.sha256(testbed_preflight.read_bytes()).hexdigest()
    )

    assert (
        session_main(
            [
                "bundle",
                "verify",
                "--manifest",
                str(out),
                "--output",
                str(verify_out),
            ]
        )
        == 0
    )
    verification = json.loads(verify_out.read_text())
    assert verification["schema_version"] == "celatim.reviewer_bundle_verify.v1"
    assert verification["ok"] is True
    assert verification["artifact_count"] == 11
    assert verification["ok_count"] == 11
    assert verification["mismatch_count"] == 0
    assert verification["consistency_check_count"] == 12
    assert verification["consistency_ok_count"] == 12
    assert verification["consistency_failed_count"] == 0

    assert (
        session_main(
            [
                "evidence",
                "public-index",
                "--evidence-index",
                str(evidence_index),
                "--output",
                str(public_evidence_index),
            ]
        )
        == 0
    )
    public_index = json.loads(public_evidence_index.read_text())
    assert public_index["schema_version"] == "celatim.public_evidence_index.v1"
    assert public_index["evidence_count"] == 1

    assert (
        session_main(
            [
                "--catalog",
                str(catalog),
                "bundle",
                "public-manifest",
                "--bundle-name",
                "public-cli-bundle",
                "--bundle-root",
                str(tmp_path),
                "--support-matrix",
                str(support_matrix),
                "--detector-scrub-guidance",
                str(detector_scrub_guidance),
                "--detector-rule-artifact",
                str(detector_rules_manifest),
                str(detector_rules_markdown),
                "--windows-capture-guidance",
                str(windows_capture_guidance),
                "--scenarios",
                str(scenarios),
                "--execution-plan",
                str(execution_plan),
                "--testbed-requirements",
                str(testbed_requirements),
                "--evidence-index",
                str(public_evidence_index),
                "--paper-table",
                str(paper_table),
                "--reviewer-manifest",
                str(out),
                "--reviewer-verification",
                str(verify_out),
                "--output",
                str(public_out),
            ]
        )
        == 0
    )
    public_manifest = json.loads(public_out.read_text())
    assert public_manifest["schema_version"] == "celatim.public_bundle.v1"
    assert public_manifest["bundle_name"] == "public-cli-bundle"
    assert public_manifest["release_scope"] == "public_safe"
    assert public_manifest["private_reference_policy"] == "hash_only_no_channel_artifacts"
    assert public_manifest["private_reviewer_bundle_name"] == "cli-bundle"
    assert public_manifest["private_reviewer_bundle_verified"] is True
    assert public_manifest["private_reviewer_artifact_count"] == 11
    assert public_manifest["private_reviewer_artifact_kinds"] == [
        "detector_replay",
        "doctor_report",
        "evidence_index",
        "lockfile",
        "package_wheel",
        "paper_table",
        "scenario_inventory",
        "scenario_spec",
        "scrub_report",
        "testbed_package",
        "testbed_preflight",
    ]
    assert public_manifest["artifact_count"] == 13
    public_artifacts = {artifact["kind"]: artifact for artifact in public_manifest["artifacts"]}
    public_artifact_kinds = [artifact["kind"] for artifact in public_manifest["artifacts"]]
    assert public_artifacts["mechanism_catalog"]["path"] == "mechanisms.jsonl"
    assert public_artifacts["support_matrix"]["path"] == "evidence-support-matrix.md"
    assert public_artifacts["detector_scrub_guidance"]["path"] == "detector-scrub-guidance.md"
    assert public_artifact_kinds.count("detector_rule_artifact") == 2
    assert public_artifacts["windows_capture_guidance"]["path"] == "windows-pktmon-etw-guidance.md"
    assert public_artifacts["scenario_execution_plan"]["path"] == "execution-plan.json"
    assert public_artifacts["testbed_requirements"]["path"] == "testbed-requirements.json"
    assert (
        public_artifacts["reviewer_bundle_manifest"]["sha256"]
        == hashlib.sha256(out.read_bytes()).hexdigest()
    )

    assert (
        session_main(
            [
                "bundle",
                "public-verify",
                "--manifest",
                str(public_out),
                "--output",
                str(public_verify_out),
            ]
        )
        == 0
    )
    public_verification = json.loads(public_verify_out.read_text())
    assert public_verification["schema_version"] == "celatim.public_bundle_verify.v1"
    assert public_verification["ok"] is True
    assert public_verification["artifact_count"] == 13
    assert public_verification["ok_count"] == 13
    assert public_verification["policy_check_count"] == 7
    assert public_verification["policy_failed_count"] == 0

    leak = tmp_path / "pcaps" / "leak.pcap"
    leak.parent.mkdir()
    leak.write_bytes(b"private capture")
    assert (
        session_main(
            [
                "bundle",
                "public-verify",
                "--manifest",
                str(public_out),
                "--output",
                str(public_verify_bad_out),
            ]
        )
        == 1
    )
    public_failed = json.loads(public_verify_bad_out.read_text())
    assert public_failed["ok"] is False
    assert public_failed["error"] == "public_policy_verification_failed"
    failed_policy_checks = {
        check["check"]: check for check in public_failed["policy_checks"] if not check["ok"]
    }
    assert failed_policy_checks["public_bundle.forbidden_bundle_files"]["actual"] == [
        "pcaps/leak.pcap"
    ]

    semantic_bad = dict(manifest)
    semantic_bad["evidence_count"] = 999
    semantic_bad_manifest.write_text(json.dumps(semantic_bad, sort_keys=True) + "\n")
    assert (
        session_main(
            [
                "bundle",
                "verify",
                "--manifest",
                str(semantic_bad_manifest),
                "--output",
                str(verify_semantic_bad_out),
            ]
        )
        == 1
    )
    semantic_failed = json.loads(verify_semantic_bad_out.read_text())
    assert semantic_failed["ok"] is False
    assert semantic_failed["error"] == "consistency_verification_failed"
    assert semantic_failed["mismatch_count"] == 0
    assert semantic_failed["consistency_failed_count"] == 1
    failed_checks = {
        check["check"]: check for check in semantic_failed["consistency_checks"] if not check["ok"]
    }
    assert failed_checks["evidence_index.evidence_count"]["expected"] == 999
    assert failed_checks["evidence_index.evidence_count"]["actual"] == 1

    doctor.write_text(json.dumps({"schema_version": "celatim.doctor.v1", "ok": False}) + "\n")
    assert (
        session_main(
            [
                "bundle",
                "verify",
                "--manifest",
                str(out),
                "--output",
                str(verify_bad_out),
            ]
        )
        == 1
    )
    failed = json.loads(verify_bad_out.read_text())
    assert failed["ok"] is False
    assert failed["mismatch_count"] == 1
    failed_artifacts = {artifact["kind"]: artifact for artifact in failed["artifacts"]}
    assert failed_artifacts["doctor_report"]["ok"] is False


def test_session_cli_evidence_run_uses_timed_transport(tmp_path):
    out = tmp_path / "evidence.json"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "evidence",
                "run",
                "--scenario-id",
                "cli-timed-evidence",
                "--mechanism",
                "http2-ping-opaque",
                "--hex",
                "00 ff 80 41",
                "--control-message",
                "control",
                "--timed-transport",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    doc = json.loads(out.read_text())
    assert doc["ok"] is True
    assert doc["covert"]["transport_kind"] == "timed_memory"
    assert (
        doc["covert"]["evidence"]["timing_trace"]["sample_count"]
        == doc["covert"]["evidence"]["carrier_units"]
    )
    assert doc["benign_control"]["transport_kind"] == "timed_memory"
    assert doc["benign_control"]["evidence"]["timing_trace"] is not None


def test_session_cli_evidence_run_accepts_reliability_policy(tmp_path):
    out = tmp_path / "evidence.json"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "evidence",
                "run",
                "--scenario-id",
                "cli-reliability",
                "--mechanism",
                "http2-ping-opaque",
                "--hex",
                "00 ff 80 41",
                "--max-receive-attempts",
                "3",
                "--retry-backoff-s",
                "0.0",
                "--max-retransmissions",
                "2",
                "--no-duplicate-suppression",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    doc = json.loads(out.read_text())
    policy = doc["covert"]["evidence"]["reliability"]["policy"]
    assert policy["max_receive_attempts"] == 3
    assert policy["retry_backoff_s"] == 0.0
    assert policy["suppress_duplicate_chunks"] is False
    assert policy["max_retransmissions"] == 2
    assert doc["covert"]["evidence"]["reliability"]["receive_attempts"] == 1


def test_session_cli_scenario_list_and_run(tmp_path):
    listed = tmp_path / "scenarios.json"
    planned = tmp_path / "execution-plan.json"
    run = tmp_path / "scenario-run.json"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "scenario",
                "list",
                "--scenario-dir",
                str(SCENARIOS),
                "--output",
                str(listed),
            ]
        )
        == 0
    )
    listed_doc = json.loads(listed.read_text())
    assert listed_doc["schema_version"] == "celatim.scenario_inventory.v1"
    assert listed_doc["path"] == str(SCENARIOS)
    assert listed_doc["scenario_count"] == 17
    assert listed_doc["scenario_ids"] == [
        "http2-ping-opaque-real-pdu-smoke",
        "quic-connection-id-real-pdu-smoke",
        "rtp-rtcp-ext-app-real-pdu-smoke",
        "tcp-reserved-bits-real-pdu-smoke",
        "edns0-padding-dnsmasq-dig-real-daemon",
        "http2-ping-opaque-hyper-h2",
        "http3-reserved-settings-aioquic",
        "quic-connection-id-aioquic",
        "tcp-reserved-bits-afpacket-netns",
        "ecdsa-nonce-local-crypto-transcript",
        "rsa-pss-salt-local-crypto-transcript",
        "bgp-optional-transitive-scapy",
        "coap-tunnel-aiocoap",
        "dns-null-dnspython",
        "dns-txt-dnspython",
        "ssh-kexinit-paramiko",
        "websocket-websockets",
    ]
    assert listed_doc["evidence_tier_counts"] == {
        "real_daemon_path": 9,
        "real_crypto_path": 2,
        "real_pdu_packet_path": 6,
    }
    assert listed_doc["privilege_counts"] == {"cap_net_admin": 1, "none": 15, "root": 1}
    assert listed_doc["expected_runtime_s_total"] == 115.0
    assert listed_doc["required_tools"] == ["dig", "dnsmasq", "ip", "tcpdump"]
    assert listed_doc["required_extras"] == [
        "crypto",
        "daemon",
        "dns",
        "iot",
        "packet",
        "realtime",
        "ssh",
    ]
    assert [item["scenario_id"] for item in listed_doc["scenarios"]] == [
        "http2-ping-opaque-real-pdu-smoke",
        "quic-connection-id-real-pdu-smoke",
        "rtp-rtcp-ext-app-real-pdu-smoke",
        "tcp-reserved-bits-real-pdu-smoke",
        "edns0-padding-dnsmasq-dig-real-daemon",
        "http2-ping-opaque-hyper-h2",
        "http3-reserved-settings-aioquic",
        "quic-connection-id-aioquic",
        "tcp-reserved-bits-afpacket-netns",
        "ecdsa-nonce-local-crypto-transcript",
        "rsa-pss-salt-local-crypto-transcript",
        "bgp-optional-transitive-scapy",
        "coap-tunnel-aiocoap",
        "dns-null-dnspython",
        "dns-txt-dnspython",
        "ssh-kexinit-paramiko",
        "websocket-websockets",
    ]
    default_scenarios = listed_doc["scenarios"][:4]
    dns_scenario = listed_doc["scenarios"][4]
    assert all(item["evidence_tier"] == "real_pdu_packet_path" for item in default_scenarios)
    assert all(item["privilege"] == "none" for item in default_scenarios)
    assert all(item["expected_runtime_s"] == 5.0 for item in default_scenarios)
    assert all(item["requires_tools"] == [] for item in default_scenarios)
    assert all(item["requires_extras"] == [] for item in default_scenarios)
    assert dns_scenario["evidence_tier"] == "real_daemon_path"
    assert dns_scenario["privilege"] == "cap_net_admin"
    assert dns_scenario["requires_tools"] == ["dig", "dnsmasq", "ip", "tcpdump"]
    assert dns_scenario["requires_extras"] == ["packet"]
    http2_h2_scenario = listed_doc["scenarios"][5]
    assert http2_h2_scenario["scenario_id"] == "http2-ping-opaque-hyper-h2"
    assert http2_h2_scenario["evidence_tier"] == "real_daemon_path"
    assert http2_h2_scenario["privilege"] == "none"
    assert http2_h2_scenario["requires_tools"] == []
    assert http2_h2_scenario["requires_extras"] == ["daemon"]
    http3_aioquic_scenario = listed_doc["scenarios"][6]
    assert http3_aioquic_scenario["scenario_id"] == "http3-reserved-settings-aioquic"
    assert http3_aioquic_scenario["evidence_tier"] == "real_daemon_path"
    assert http3_aioquic_scenario["privilege"] == "none"
    assert http3_aioquic_scenario["requires_tools"] == []
    assert http3_aioquic_scenario["requires_extras"] == ["daemon"]
    quic_aioquic_scenario = listed_doc["scenarios"][7]
    assert quic_aioquic_scenario["scenario_id"] == "quic-connection-id-aioquic"
    assert quic_aioquic_scenario["evidence_tier"] == "real_daemon_path"
    assert quic_aioquic_scenario["privilege"] == "none"
    assert quic_aioquic_scenario["requires_tools"] == []
    assert quic_aioquic_scenario["requires_extras"] == ["daemon"]
    afpacket_scenario = listed_doc["scenarios"][8]
    assert afpacket_scenario["scenario_id"] == "tcp-reserved-bits-afpacket-netns"
    assert afpacket_scenario["privilege"] == "root"
    assert afpacket_scenario["requires_tools"] == ["ip", "tcpdump"]
    crypto_scenario = listed_doc["scenarios"][9]
    assert crypto_scenario["scenario_id"] == "ecdsa-nonce-local-crypto-transcript"
    assert crypto_scenario["evidence_tier"] == "real_crypto_path"
    assert crypto_scenario["privilege"] == "none"
    assert crypto_scenario["requires_tools"] == []
    assert crypto_scenario["requires_extras"] == ["crypto"]
    rsa_crypto_scenario = listed_doc["scenarios"][10]
    assert rsa_crypto_scenario["scenario_id"] == "rsa-pss-salt-local-crypto-transcript"
    assert rsa_crypto_scenario["evidence_tier"] == "real_crypto_path"
    assert rsa_crypto_scenario["privilege"] == "none"
    assert rsa_crypto_scenario["requires_tools"] == []
    assert rsa_crypto_scenario["requires_extras"] == ["crypto"]
    assert listed_doc["scenarios"][0]["description"].startswith("Non-privileged HTTP/2")

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "scenario",
                "plan",
                "--scenario-dir",
                str(SCENARIOS),
                "--output",
                str(planned),
            ]
        )
        == 0
    )
    planned_doc = json.loads(planned.read_text())
    assert planned_doc["schema_version"] == "celatim.scenario_execution_plan.v1"
    assert planned_doc["scenario_count"] == 17
    assert planned_doc["default_included_count"] == 4
    assert planned_doc["manual_review_count"] == 13
    assert planned_doc["execution_mode_counts"] == {
        "default_non_privileged": 4,
        "non_privileged_with_dependencies": 11,
        "requires_linux_capability": 1,
        "requires_root": 1,
    }
    assert planned_doc["scenarios"][0]["default_included"] is True
    assert planned_doc["scenarios"][0]["reviewer_command"][0:5] == [
        "celatim",
        "scenario",
        "run",
        "--scenario-id",
        "http2-ping-opaque-real-pdu-smoke",
    ]
    assert planned_doc["scenarios"][4]["default_included"] is False
    assert (
        planned_doc["scenarios"][4]["skip_reason"]
        == "requires privilege cap_net_admin; requires tools dig, dnsmasq, ip, tcpdump; requires extras packet"
    )
    assert planned_doc["scenarios"][5]["default_included"] is False
    assert planned_doc["scenarios"][5]["skip_reason"] == "requires extras daemon"
    assert planned_doc["scenarios"][6]["default_included"] is False
    assert planned_doc["scenarios"][6]["skip_reason"] == "requires extras daemon"
    assert planned_doc["scenarios"][7]["default_included"] is False
    assert planned_doc["scenarios"][7]["skip_reason"] == "requires extras daemon"
    assert planned_doc["scenarios"][8]["default_included"] is False
    assert (
        planned_doc["scenarios"][8]["skip_reason"]
        == "requires privilege root; requires tools ip, tcpdump"
    )
    assert planned_doc["scenarios"][9]["default_included"] is False
    assert planned_doc["scenarios"][9]["skip_reason"] == "requires extras crypto"
    assert planned_doc["scenarios"][10]["default_included"] is False
    assert planned_doc["scenarios"][10]["skip_reason"] == "requires extras crypto"

    ids = tmp_path / "scenario-ids.txt"
    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "scenario",
                "ids",
                "--scenario-dir",
                str(SCENARIOS),
                "--default-included",
                "--output",
                str(ids),
            ]
        )
        == 0
    )
    assert ids.read_text().splitlines() == [
        "http2-ping-opaque-real-pdu-smoke",
        "quic-connection-id-real-pdu-smoke",
        "rtp-rtcp-ext-app-real-pdu-smoke",
        "tcp-reserved-bits-real-pdu-smoke",
    ]

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "scenario",
                "run",
                "--scenario",
                str(SCENARIOS / "rtp-rtcp-ext-app.toml"),
                "--output",
                str(run),
            ]
        )
        == 0
    )
    run_doc = json.loads(run.read_text())
    assert run_doc["ok"] is True
    assert run_doc["scenario_id"] == "rtp-rtcp-ext-app-real-pdu-smoke"
    assert run_doc["adapter_status"] == "real_pdu_fixture"
    assert run_doc["covert"]["parser_validated"] is True
    assert bytes.fromhex(run_doc["benign_control"]["recovered_hex"]) == b"control"
    assert run_doc["reproducibility"]["scenario_spec_path"] == str(
        SCENARIOS / "rtp-rtcp-ext-app.toml"
    )
    assert run_doc["reproducibility"]["command"][:4] == [
        "celatim",
        "--catalog",
        str(DATA),
        "scenario",
    ]


def test_session_cli_scenario_run_accepts_scenario_id(tmp_path):
    run = tmp_path / "scenario-run.json"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "scenario",
                "run",
                "--scenario-id",
                "rtp-rtcp-ext-app-real-pdu-smoke",
                "--scenario-dir",
                str(SCENARIOS),
                "--output",
                str(run),
            ]
        )
        == 0
    )

    run_doc = json.loads(run.read_text())
    assert run_doc["ok"] is True
    assert run_doc["scenario_id"] == "rtp-rtcp-ext-app-real-pdu-smoke"
    assert run_doc["mechanism_id"] == "rtp-rtcp-ext-app"
    assert run_doc["covert"]["parser_validated"] is True


def test_session_cli_scenario_run_overrides_payload(tmp_path):
    run = tmp_path / "scenario-run.json"
    payload = bytes(range(64))
    payload_path = tmp_path / "payload.bin"
    payload_path.write_bytes(payload)

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "scenario",
                "run",
                "--scenario-id",
                "http2-ping-opaque-real-pdu-smoke",
                "--scenario-dir",
                str(SCENARIOS),
                "--file",
                str(payload_path),
                "--output",
                str(run),
            ]
        )
        == 0
    )

    run_doc = json.loads(run.read_text())
    assert run_doc["ok"] is True
    assert run_doc["covert"]["evidence"]["payload_len"] == len(payload)
    assert bytes.fromhex(run_doc["covert"]["recovered_hex"]) == payload


def test_session_cli_scenario_run_writes_crypto_transcripts_with_override(tmp_path):
    pytest.importorskip("cryptography")
    run = tmp_path / "scenario-run.json"
    transcript_template = tmp_path / "transcripts" / "{scenario_id}-{case}.json"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "scenario",
                "run",
                "--scenario-id",
                "ecdsa-nonce-local-crypto-transcript",
                "--scenario-dir",
                str(SCENARIOS),
                "--transport-transcript-json",
                str(transcript_template),
                "--output",
                str(run),
            ]
        )
        == 0
    )

    doc = json.loads(run.read_text())
    assert doc["ok"] is True
    assert doc["scenario_id"] == "ecdsa-nonce-local-crypto-transcript"
    assert doc["mechanism_id"] == "ecdsa-nonce"
    for case in ("covert", "benign_control"):
        record = Path(str(doc[case]["transport_record"]))
        artifact = doc[case]["transport_artifact"]
        metadata = doc[case]["transport_metadata"]
        assert doc[case]["transport_kind"] == "crypto_ecdsa_nonce"
        assert (
            record == tmp_path / "transcripts" / f"ecdsa-nonce-local-crypto-transcript-{case}.json"
        )
        assert record.is_file()
        assert artifact["kind"] == "crypto_transcript"
        assert artifact["sha256"] == hashlib.sha256(record.read_bytes()).hexdigest()
        assert metadata["schema_version"] == "celatim.transport_metadata.crypto_ecdsa_nonce.v1"
        assert metadata["transcript_sha256"] == artifact["sha256"]


def test_session_cli_scenario_run_writes_rsa_pss_crypto_transcripts_with_override(tmp_path):
    pytest.importorskip("cryptography")
    run = tmp_path / "scenario-run.json"
    transcript_template = tmp_path / "transcripts" / "{scenario_id}-{case}.json"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "scenario",
                "run",
                "--scenario-id",
                "rsa-pss-salt-local-crypto-transcript",
                "--scenario-dir",
                str(SCENARIOS),
                "--transport-transcript-json",
                str(transcript_template),
                "--output",
                str(run),
            ]
        )
        == 0
    )

    doc = json.loads(run.read_text())
    assert doc["ok"] is True
    assert doc["scenario_id"] == "rsa-pss-salt-local-crypto-transcript"
    assert doc["mechanism_id"] == "rsa-pss-salt"
    for case in ("covert", "benign_control"):
        record = Path(str(doc[case]["transport_record"]))
        artifact = doc[case]["transport_artifact"]
        metadata = doc[case]["transport_metadata"]
        assert doc[case]["transport_kind"] == "crypto_rsa_pss_salt"
        assert record == (
            tmp_path / "transcripts" / f"rsa-pss-salt-local-crypto-transcript-{case}.json"
        )
        assert record.is_file()
        assert artifact["kind"] == "crypto_transcript"
        assert artifact["sha256"] == hashlib.sha256(record.read_bytes()).hexdigest()
        assert metadata["schema_version"] == "celatim.transport_metadata.crypto_rsa_pss_salt.v1"
        assert metadata["transcript_sha256"] == artifact["sha256"]


def test_session_cli_scenario_run_overrides_transport_capture_pcap(tmp_path, monkeypatch):
    out = tmp_path / "scenario-run.json"
    capture_template = tmp_path / "pcaps" / "{scenario_id}-{case}.pcap"
    seen: list[str | None] = []

    class FakeEvidenceResult:
        def to_json(self) -> dict[str, Any]:
            return {"ok": True}

    def fake_run_evidence(config, catalog, command=()):
        seen.append(config.transport.capture_pcap)
        assert catalog == DATA
        assert command[:4] == (
            "celatim",
            "--catalog",
            str(DATA),
            "scenario",
        )
        return FakeEvidenceResult()

    monkeypatch.setattr(cli_module, "run_evidence", fake_run_evidence)

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "scenario",
                "run",
                "--scenario-id",
                "edns0-padding-dnsmasq-dig-real-daemon",
                "--scenario-dir",
                str(SCENARIOS),
                "--transport-capture-pcap",
                str(capture_template),
                "--output",
                str(out),
            ]
        )
        == 0
    )

    assert seen == [str(capture_template)]
    assert json.loads(out.read_text()) == {"ok": True}


def test_session_cli_uses_packaged_scenario_default_outside_measurement_tree(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    listed = tmp_path / "scenarios.json"

    assert session_main(["scenario", "list", "--output", str(listed)]) == 0

    listed_doc = json.loads(listed.read_text())
    assert listed_doc["schema_version"] == "celatim.scenario_inventory.v1"
    assert listed_doc["scenario_count"] == 17
    assert listed_doc["privilege_counts"] == {"cap_net_admin": 1, "none": 15, "root": 1}
    assert [item["scenario_id"] for item in listed_doc["scenarios"]] == [
        "http2-ping-opaque-real-pdu-smoke",
        "quic-connection-id-real-pdu-smoke",
        "rtp-rtcp-ext-app-real-pdu-smoke",
        "tcp-reserved-bits-real-pdu-smoke",
        "edns0-padding-dnsmasq-dig-real-daemon",
        "http2-ping-opaque-hyper-h2",
        "http3-reserved-settings-aioquic",
        "quic-connection-id-aioquic",
        "tcp-reserved-bits-afpacket-netns",
        "ecdsa-nonce-local-crypto-transcript",
        "rsa-pss-salt-local-crypto-transcript",
        "bgp-optional-transitive-scapy",
        "coap-tunnel-aiocoap",
        "dns-null-dnspython",
        "dns-txt-dnspython",
        "ssh-kexinit-paramiko",
        "websocket-websockets",
    ]
    assert all(item["privilege"] == "none" for item in listed_doc["scenarios"][:4])
    assert listed_doc["scenarios"][4]["privilege"] == "cap_net_admin"
    assert listed_doc["scenarios"][5]["requires_extras"] == ["daemon"]
    assert listed_doc["scenarios"][6]["requires_extras"] == ["daemon"]
    assert listed_doc["scenarios"][7]["requires_extras"] == ["daemon"]
    assert listed_doc["scenarios"][8]["privilege"] == "root"
    assert listed_doc["scenarios"][9]["requires_extras"] == ["crypto"]
    assert listed_doc["scenarios"][10]["requires_extras"] == ["crypto"]


def test_session_cli_runs_packaged_scenario_by_id_outside_measurement_tree(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "scenario-run.json"
    pcap_dir = tmp_path / "pcaps"

    assert (
        session_main(
            [
                "scenario",
                "run",
                "--scenario-id",
                "http2-ping-opaque-real-pdu-smoke",
                "--pcap-dir",
                str(pcap_dir),
                "--output",
                str(out),
            ]
        )
        == 0
    )

    doc = json.loads(out.read_text())
    assert doc["ok"] is True
    assert doc["scenario_id"] == "http2-ping-opaque-real-pdu-smoke"
    assert doc["covert"]["transport_kind"] == "pcap"
    assert doc["covert"]["parser_validated"] is True
    _assert_transport_artifact(doc["covert"], pcap_dir)


def test_session_cli_schema_show_writes_evidence_schema(tmp_path):
    out = tmp_path / "schema.json"

    assert session_main(["schema", "show", "--output", str(out)]) == 0

    schema = json.loads(out.read_text())
    assert schema["title"] == "celatim evidence run result"
    assert schema["properties"]["schema_version"]["const"] == "celatim.evidence_run.v1"


def test_session_cli_schema_show_writes_detector_replay_schema(tmp_path):
    out = tmp_path / "schema.json"

    assert (
        session_main(
            [
                "schema",
                "show",
                "--name",
                "detector-replay-v1",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    schema = json.loads(out.read_text())
    assert schema["title"] == "celatim detector replay result"
    assert schema["properties"]["schema_version"]["const"] == "celatim.detector_replay.v1"


def test_session_cli_schema_show_writes_detector_replay_corpus_schema(tmp_path):
    out = tmp_path / "schema.json"

    assert (
        session_main(
            [
                "schema",
                "show",
                "--name",
                "detector-replay-corpus-v1",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    schema = json.loads(out.read_text())
    assert schema["title"] == "celatim detector replay corpus result"
    assert schema["properties"]["schema_version"]["const"] == "celatim.detector_replay_corpus.v1"


def test_session_cli_schema_show_writes_detector_trace_manifest_schema(tmp_path):
    out = tmp_path / "schema.json"

    assert (
        session_main(
            [
                "schema",
                "show",
                "--name",
                "detector-trace-manifest-v1",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    schema = json.loads(out.read_text())
    assert schema["title"] == "celatim detector trace manifest"
    assert schema["properties"]["schema_version"]["const"] == "celatim.detector_trace_manifest.v1"


def test_session_cli_schema_show_writes_scenario_inventory_schema(tmp_path):
    out = tmp_path / "schema.json"

    assert (
        session_main(
            [
                "schema",
                "show",
                "--name",
                "scenario-inventory-v1",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    schema = json.loads(out.read_text())
    assert schema["title"] == "celatim scenario inventory"
    assert schema["properties"]["schema_version"]["const"] == "celatim.scenario_inventory.v1"


def test_session_cli_schema_show_writes_scrub_report_schema(tmp_path):
    out = tmp_path / "schema.json"

    assert (
        session_main(
            [
                "schema",
                "show",
                "--name",
                "scrub-report-v1",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    schema = json.loads(out.read_text())
    assert schema["title"] == "celatim pcap scrub report"
    assert schema["properties"]["schema_version"]["const"] == "celatim.scrub_report.v1"


def test_session_cli_schema_show_writes_scenario_execution_plan_schema(tmp_path):
    out = tmp_path / "schema.json"

    assert (
        session_main(
            [
                "schema",
                "show",
                "--name",
                "scenario-execution-plan-v1",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    schema = json.loads(out.read_text())
    assert schema["title"] == "celatim scenario execution plan"
    assert schema["properties"]["schema_version"]["const"] == "celatim.scenario_execution_plan.v1"


def test_session_cli_schema_show_writes_testbed_requirements_schema(tmp_path):
    out = tmp_path / "schema.json"

    assert (
        session_main(
            [
                "schema",
                "show",
                "--name",
                "testbed-requirements-v1",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    schema = json.loads(out.read_text())
    assert schema["title"] == "celatim testbed requirements inventory"
    assert schema["properties"]["schema_version"]["const"] == "celatim.testbed_requirements.v1"


def test_session_cli_schema_show_writes_reviewer_bundle_schema(tmp_path):
    out = tmp_path / "schema.json"

    assert (
        session_main(
            [
                "schema",
                "show",
                "--name",
                "reviewer-bundle-v1",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    schema = json.loads(out.read_text())
    assert schema["title"] == "celatim reviewer bundle manifest"
    assert schema["properties"]["schema_version"]["const"] == "celatim.reviewer_bundle.v1"


def test_session_cli_schema_show_writes_public_bundle_schema(tmp_path):
    out = tmp_path / "schema.json"

    assert (
        session_main(
            [
                "schema",
                "show",
                "--name",
                "public-bundle-v1",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    schema = json.loads(out.read_text())
    assert schema["title"] == "celatim public-safe bundle manifest"
    assert schema["properties"]["schema_version"]["const"] == "celatim.public_bundle.v1"


def test_session_cli_schema_show_writes_public_bundle_verify_schema(tmp_path):
    out = tmp_path / "schema.json"

    assert (
        session_main(
            [
                "schema",
                "show",
                "--name",
                "public-bundle-verify-v1",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    schema = json.loads(out.read_text())
    assert schema["title"] == "celatim public-safe bundle verification"
    assert schema["properties"]["schema_version"]["const"] == "celatim.public_bundle_verify.v1"


def test_session_cli_schema_show_writes_qemu_tap_preflight_schema(tmp_path):
    out = tmp_path / "schema.json"

    assert (
        session_main(
            [
                "schema",
                "show",
                "--name",
                "qemu-tap-preflight-v1",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    schema = json.loads(out.read_text())
    assert schema["title"] == "celatim QEMU TAP preflight report"
    assert schema["properties"]["schema_version"]["const"] == "celatim.qemu_tap_preflight.v1"
    assert schema["properties"]["claim_status"]["const"] == "preflight_only_no_vm_started"


def test_session_cli_schema_show_writes_reviewer_bundle_verify_schema(tmp_path):
    out = tmp_path / "schema.json"

    assert (
        session_main(
            [
                "schema",
                "show",
                "--name",
                "reviewer-bundle-verify-v1",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    schema = json.loads(out.read_text())
    assert schema["title"] == "celatim reviewer bundle verification"
    assert schema["properties"]["schema_version"]["const"] == "celatim.reviewer_bundle_verify.v1"


def test_session_cli_schema_show_uses_packaged_schema_outside_measurement_tree(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "schema.json"

    assert session_main(["schema", "show", "--output", str(out)]) == 0

    schema = json.loads(out.read_text())
    assert schema["properties"]["schema_version"]["const"] == "celatim.evidence_run.v1"


def test_session_cli_schema_show_writes_evidence_index_schema(tmp_path):
    out = tmp_path / "schema.json"

    assert (
        session_main(["schema", "show", "--name", "evidence-index-v1", "--output", str(out)]) == 0
    )

    schema = json.loads(out.read_text())
    assert schema["title"] == "celatim evidence index result"
    assert schema["properties"]["schema_version"]["const"] == "celatim.evidence_index.v1"


def test_session_cli_schema_show_writes_public_evidence_index_schema(tmp_path):
    out = tmp_path / "schema.json"

    assert (
        session_main(["schema", "show", "--name", "public-evidence-index-v1", "--output", str(out)])
        == 0
    )

    schema = json.loads(out.read_text())
    assert schema["title"] == "celatim public-safe evidence index"
    assert schema["properties"]["schema_version"]["const"] == "celatim.public_evidence_index.v1"


def test_session_cli_schema_show_writes_doctor_schema(tmp_path):
    out = tmp_path / "schema.json"

    assert session_main(["schema", "show", "--name", "doctor-v1", "--output", str(out)]) == 0

    schema = json.loads(out.read_text())
    assert schema["title"] == "celatim doctor result"
    assert schema["properties"]["schema_version"]["const"] == "celatim.doctor.v1"


def test_session_cli_schema_show_writes_support_matrix_schema(tmp_path):
    out = tmp_path / "schema.json"

    assert (
        session_main(["schema", "show", "--name", "support-matrix-v1", "--output", str(out)]) == 0
    )

    schema = json.loads(out.read_text())
    assert schema["title"] == "celatim support matrix"
    assert schema["properties"]["schema_version"]["const"] == "celatim.support_matrix.v1"


def test_session_cli_schema_show_writes_scenario_schema(tmp_path):
    out = tmp_path / "schema.json"

    assert session_main(["schema", "show", "--name", "scenario-v1", "--output", str(out)]) == 0

    schema = json.loads(out.read_text())
    assert schema["title"] == "celatim scenario spec"
    assert schema["properties"]["schema_version"]["const"] == "celatim.scenario.v1"


def test_session_cli_docs_list_and_show(tmp_path):
    listed = tmp_path / "docs.json"
    shown = tmp_path / "api.md"

    assert session_main(["docs", "list", "--output", str(listed)]) == 0
    listed_doc = json.loads(listed.read_text())
    assert [item["name"] for item in listed_doc["docs"]] == [
        "api-guide",
        "reviewer-quickstart",
        "scenario-authoring",
        "troubleshooting",
    ]

    assert session_main(["docs", "show", "--name", "api-guide", "--output", str(shown)]) == 0
    assert shown.read_text().startswith("# celatim API Guide\n")
    assert "ChannelSession" in shown.read_text()


def test_session_cli_docs_show_uses_packaged_docs_outside_measurement_tree(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "quickstart.md"

    assert (
        session_main(
            [
                "docs",
                "show",
                "--name",
                "reviewer-quickstart",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    text = out.read_text()
    assert text.startswith("# Reviewer Quickstart\n")
    assert "make reviewer-full" in text


def test_session_cli_doctor_reports_packaged_resource_readiness(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "doctor.json"
    artifact_dir = tmp_path / "artifacts"

    assert session_main(["doctor", "--artifact-dir", str(artifact_dir), "--output", str(out)]) == 0

    doc = json.loads(out.read_text())
    assert doc["schema_version"] == "celatim.doctor.v1"
    assert doc["ok"] is True
    checks = {check["check_id"]: check for check in doc["checks"]}
    assert checks["environment"]["status"] == "pass"
    assert checks["environment"]["details"]["package_version"]
    assert checks["environment"]["details"]["python_version"]
    assert checks["environment"]["details"]["release"]
    assert checks["catalog"]["status"] == "pass"
    assert checks["schemas"]["status"] == "pass"
    assert checks["scenarios"]["status"] == "pass"
    assert checks["artifact_dir"]["status"] == "pass"
    assert artifact_dir.is_dir()


def test_session_cli_doctor_returns_failure_for_missing_required_tool(tmp_path):
    out = tmp_path / "doctor.json"

    assert (
        session_main(
            [
                "doctor",
                "--require-tool",
                "celatim-definitely-missing-tool",
                "--output",
                str(out),
            ]
        )
        == 1
    )

    doc = json.loads(out.read_text())
    assert doc["ok"] is False
    checks = {check["check_id"]: check for check in doc["checks"]}
    assert checks["tool:celatim-definitely-missing-tool"]["status"] == "fail"


def test_session_cli_doctor_reports_optional_package_extra(tmp_path):
    out = tmp_path / "doctor.json"

    assert (
        session_main(
            [
                "doctor",
                "--optional-extra",
                "packet",
                "--optional-extra",
                "daemon",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    doc = json.loads(out.read_text())
    assert doc["ok"] is True
    checks = {check["check_id"]: check for check in doc["checks"]}
    assert checks["extra:packet"]["status"] in {"pass", "warn"}
    assert checks["extra:packet"]["details"]["modules"][0]["module"] == "scapy"
    assert checks["extra:packet"]["details"]["required"] is False
    assert checks["extra:daemon"]["status"] in {"pass", "warn"}
    assert checks["extra:daemon"]["details"]["modules"][0]["module"] == "aioquic"
    assert checks["extra:daemon"]["details"]["modules"][1]["module"] == "h2"
    assert checks["extra:daemon"]["details"]["required"] is False


def test_session_cli_matrix_generate_writes_support_matrix(tmp_path):
    out = tmp_path / "support-matrix.md"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "matrix",
                "generate",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    text = out.read_text()
    assert text.startswith("# Evidence Support Matrix\n")
    assert "| `http2-ping-opaque` | HTTP/2 |" in text
    assert "`real_pdu_fixture`" in text


def test_session_cli_matrix_generate_writes_support_matrix_json(tmp_path):
    out = tmp_path / "support-matrix.json"

    assert (
        session_main(
            [
                "--catalog",
                str(DATA),
                "matrix",
                "generate",
                "--format",
                "json",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    doc = json.loads(out.read_text())
    assert doc["schema_version"] == "celatim.support_matrix.v1"
    assert doc["mechanism_count"] == len(doc["rows"])
    rows = {row["mechanism_id"]: row for row in doc["rows"]}
    assert rows["http2-ping-opaque"]["adapter_status"] == "real_pdu_fixture"
    assert rows["bgp-path-attr-flags"]["evidence_bucket"] == "offset_represented_zero_blob"


def test_session_cli_testbed_requirements_filters_profiles(tmp_path):
    out = tmp_path / "testbed-requirements.json"

    assert (
        session_main(
            [
                "testbed",
                "requirements",
                "--profile",
                "netns-afpacket",
                "--profile",
                "qemu-cross-stack",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    doc = json.loads(out.read_text())
    assert doc["schema_version"] == "celatim.testbed_requirements.v1"
    assert doc["profile_count"] == 2
    assert doc["profile_ids"] == ["netns-afpacket", "qemu-cross-stack"]
    assert doc["required_privileges"] == ["cap_net_admin", "cap_net_raw", "kvm"]
    assert "qemu-system-x86_64" in doc["required_tools"]
    assert doc["profiles"][0]["status"] == "packaged"
    assert doc["profiles"][1]["status"] == "planned_manual"
    assert doc["profiles"][1]["reviewer_commands"] == [["make", "reviewer-qemu-preflight"]]


def test_session_cli_testbed_qemu_preflight_writes_command_plan(
    tmp_path,
    monkeypatch,
):
    disk = tmp_path / "receiver.qcow2"
    disk.touch()
    out = tmp_path / "qemu-preflight.json"
    monkeypatch.setattr(qemu_module.shutil, "which", lambda binary: f"/fake/{binary}")

    assert (
        session_main(
            [
                "testbed",
                "qemu-preflight",
                "--disk-image",
                str(disk),
                "--tap-name",
                "tap-cli",
                "--no-kvm",
                "--no-host-ipv4",
                "--extra-arg=-nographic",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    doc = json.loads(out.read_text())
    checks = {check["check_id"]: check for check in doc["checks"]}
    assert doc["schema_version"] == "celatim.qemu_tap_preflight.v1"
    assert doc["claim_status"] == "preflight_only_no_vm_started"
    assert doc["ok"] is True
    assert checks["tcpdump_binary"]["status"] == "pass"
    assert checks["kvm_device"]["status"] == "skip"
    assert doc["tap_config"]["tap_name"] == "tap-cli"
    assert doc["tap_up_commands"] == [
        ["ip", "tuntap", "add", "dev", "tap-cli", "mode", "tap"],
        ["ip", "link", "set", "dev", "tap-cli", "up", "mtu", "1500"],
    ]
    assert "-enable-kvm" not in doc["qemu_argv"]
    assert doc["qemu_argv"][-1] == "-nographic"


def test_session_cli_lab_up_invokes_netns_pair(monkeypatch, tmp_path):
    out = tmp_path / "lab-up.json"
    calls: list[tuple[str, NetnsPairConfig]] = []

    class FakeNetnsPair:
        def __init__(self, config: NetnsPairConfig) -> None:
            self.config = config

        def up(self) -> None:
            calls.append(("up", self.config))

        def down(self) -> None:
            calls.append(("down", self.config))

    monkeypatch.setattr("celatim.cli.NetnsPair", FakeNetnsPair)

    assert (
        session_main(
            [
                "lab",
                "up",
                "--sender-ns",
                "leftns",
                "--receiver-ns",
                "rightns",
                "--sender-iface",
                "left0",
                "--receiver-iface",
                "right0",
                "--sender-ipv4-cidr",
                "192.0.2.1/24",
                "--receiver-ipv4-cidr",
                "192.0.2.2/24",
                "--mtu",
                "9000",
                "--ip-binary",
                "/sbin/ip",
                "--ethtool-binary",
                "/sbin/ethtool",
                "--keep-offloads",
                "--no-cleanup-existing",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    assert calls == [
        (
            "up",
            NetnsPairConfig(
                sender_ns="leftns",
                receiver_ns="rightns",
                sender_iface="left0",
                receiver_iface="right0",
                sender_ipv4_cidr="192.0.2.1/24",
                receiver_ipv4_cidr="192.0.2.2/24",
                mtu=9000,
                ip_binary="/sbin/ip",
                ethtool_binary="/sbin/ethtool",
                disable_offloads=False,
                cleanup_existing=False,
            ),
        )
    ]
    doc = json.loads(out.read_text())
    assert doc["command"] == "lab up"
    assert doc["topology"]["sender_ns"] == "leftns"
    assert doc["topology"]["disable_offloads"] is False
    assert doc["topology"]["cleanup_existing"] is False


def test_session_cli_lab_down_invokes_netns_pair(monkeypatch, tmp_path):
    out = tmp_path / "lab-down.json"
    calls: list[tuple[str, NetnsPairConfig]] = []

    class FakeNetnsPair:
        def __init__(self, config: NetnsPairConfig) -> None:
            self.config = config

        def up(self) -> None:
            calls.append(("up", self.config))

        def down(self) -> None:
            calls.append(("down", self.config))

    monkeypatch.setattr("celatim.cli.NetnsPair", FakeNetnsPair)

    assert (
        session_main(
            [
                "lab",
                "down",
                "--sender-ns",
                "leftns",
                "--receiver-ns",
                "rightns",
                "--output",
                str(out),
            ]
        )
        == 0
    )

    assert calls == [
        (
            "down",
            NetnsPairConfig(sender_ns="leftns", receiver_ns="rightns"),
        )
    ]
    doc = json.loads(out.read_text())
    assert doc["command"] == "lab down"
    assert doc["topology"]["sender_ns"] == "leftns"
    assert doc["topology"]["receiver_ns"] == "rightns"


def _assert_transport_artifact(case_doc: dict[str, Any], root: Path) -> None:
    record_path = Path(str(case_doc["transport_record"]))
    assert isinstance(case_doc["transport_artifact"], dict)
    artifact = cast(dict[str, Any], case_doc["transport_artifact"])
    data = record_path.read_bytes()
    assert artifact["kind"] == "transport_record"
    assert Path(str(artifact["path"])) == record_path
    assert record_path.is_relative_to(root)
    assert artifact["size_bytes"] == len(data)
    assert artifact["sha256"] == hashlib.sha256(data).hexdigest()


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
