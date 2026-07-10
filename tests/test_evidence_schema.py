"""Evidence JSON schema and checked-in golden examples."""

from __future__ import annotations

import copy
import dataclasses
import json
import re
import struct
import tomllib
from pathlib import Path
from typing import Any

import pytest

from celatim.catalog import load_mechanisms
from celatim.detect import (
    DetectorReplayBackend,
    TraceSourceKind,
    load_trace_manifest,
    replay_detector_corpus,
    replay_detectors_on_pcap,
    scrub_tcp_reserved_bits_pcap,
)
from celatim.doctor import run_doctor
from celatim.evidence_index import build_evidence_index, build_public_evidence_index
from celatim.pcap_decode import decode_pcap
from celatim.report import support_matrix_report
from celatim.reviewer_bundle import (
    build_public_bundle_manifest,
    build_reviewer_bundle_manifest,
    verify_public_bundle_manifest,
    verify_reviewer_bundle_manifest,
)
from celatim.scenario import (
    build_scenario_execution_plan,
    build_scenario_inventory,
    load_scenario,
    run_evidence,
)
from celatim.session import ChannelSession, InMemoryTransport, MechanismProfile, PacingConfig
from celatim.testbed import (
    HostTapConfig,
    QemuGuestConfig,
    build_qemu_tap_preflight_report,
    build_tcp_reserved_bits_frame,
    build_testbed_requirements_inventory,
    default_ipv4_packet_path_config_for,
)
from celatim.timing_sweep import (
    ObservedTimingCaseInput,
    run_observed_timing_sweep,
    run_timing_sweep,
)
from celatim.transports import PcapTransport

PROJECT = Path(__file__).resolve().parents[1]
DETECTOR_REPLAY_SCHEMA = PROJECT / "schemas" / "detector-replay-v1.schema.json"
DETECTOR_REPLAY_CORPUS_SCHEMA = PROJECT / "schemas" / "detector-replay-corpus-v1.schema.json"
DETECTOR_TRACE_MANIFEST_SCHEMA = PROJECT / "schemas" / "detector-trace-manifest-v1.schema.json"
SCHEMA = PROJECT / "schemas" / "evidence-run-v1.schema.json"
INDEX_SCHEMA = PROJECT / "schemas" / "evidence-index-v1.schema.json"
PUBLIC_INDEX_SCHEMA = PROJECT / "schemas" / "public-evidence-index-v1.schema.json"
DOCTOR_SCHEMA = PROJECT / "schemas" / "doctor-v1.schema.json"
PUBLIC_BUNDLE_SCHEMA = PROJECT / "schemas" / "public-bundle-v1.schema.json"
PUBLIC_BUNDLE_VERIFY_SCHEMA = PROJECT / "schemas" / "public-bundle-verify-v1.schema.json"
PCAP_DECODE_SCHEMA = PROJECT / "schemas" / "pcap-decode-v1.schema.json"
QEMU_TAP_PREFLIGHT_SCHEMA = PROJECT / "schemas" / "qemu-tap-preflight-v1.schema.json"
REVIEWER_BUNDLE_SCHEMA = PROJECT / "schemas" / "reviewer-bundle-v1.schema.json"
REVIEWER_BUNDLE_VERIFY_SCHEMA = PROJECT / "schemas" / "reviewer-bundle-verify-v1.schema.json"
SCENARIO_SCHEMA = PROJECT / "schemas" / "scenario-v1.schema.json"
SCENARIO_EXECUTION_PLAN_SCHEMA = PROJECT / "schemas" / "scenario-execution-plan-v1.schema.json"
SCENARIO_INVENTORY_SCHEMA = PROJECT / "schemas" / "scenario-inventory-v1.schema.json"
SCRUB_REPORT_SCHEMA = PROJECT / "schemas" / "scrub-report-v1.schema.json"
SUPPORT_MATRIX_SCHEMA = PROJECT / "schemas" / "support-matrix-v1.schema.json"
TESTBED_REQUIREMENTS_SCHEMA = PROJECT / "schemas" / "testbed-requirements-v1.schema.json"
TIMING_SWEEP_SCHEMA = PROJECT / "schemas" / "timing-sweep-v1.schema.json"
GOLDEN = PROJECT / "examples" / "evidence-run-http2-ping-opaque.json"


def test_evidence_schema_is_checked_in_and_named():
    schema = _read_json(SCHEMA)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "celatim evidence run result"
    assert schema["properties"]["schema_version"]["const"] == "celatim.evidence_run.v1"
    dns_metadata = schema["$defs"]["dns_edns0_transport_metadata"]
    assert "tool_versions" in dns_metadata["required"]
    assert dns_metadata["properties"]["tool_versions"]["items"]["$ref"] == (
        "#/$defs/tool_version_record"
    )
    crypto_metadata = schema["$defs"]["crypto_ecdsa_nonce_transport_metadata"]
    assert (
        crypto_metadata["properties"]["schema_version"]["const"]
        == "celatim.transport_metadata.crypto_ecdsa_nonce.v1"
    )
    assert crypto_metadata["properties"]["transcript_schema_version"]["const"] == (
        "celatim.crypto_transcript.ecdsa_nonce.v1"
    )
    rsa_crypto_metadata = schema["$defs"]["crypto_rsa_pss_salt_transport_metadata"]
    assert (
        rsa_crypto_metadata["properties"]["schema_version"]["const"]
        == "celatim.transport_metadata.crypto_rsa_pss_salt.v1"
    )
    assert rsa_crypto_metadata["properties"]["transcript_schema_version"]["const"] == (
        "celatim.crypto_transcript.rsa_pss_salt.v1"
    )


def test_detector_replay_schema_is_checked_in_and_named():
    schema = _read_json(DETECTOR_REPLAY_SCHEMA)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "celatim detector replay result"
    assert schema["properties"]["schema_version"]["const"] == "celatim.detector_replay.v1"


def test_detector_replay_corpus_schema_is_checked_in_and_named():
    schema = _read_json(DETECTOR_REPLAY_CORPUS_SCHEMA)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "celatim detector replay corpus result"
    assert schema["properties"]["schema_version"]["const"] == "celatim.detector_replay_corpus.v1"


def test_detector_trace_manifest_schema_is_checked_in_and_named():
    schema = _read_json(DETECTOR_TRACE_MANIFEST_SCHEMA)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "celatim detector trace manifest"
    assert schema["properties"]["schema_version"]["const"] == "celatim.detector_trace_manifest.v1"


def test_evidence_index_schema_is_checked_in_and_named():
    schema = _read_json(INDEX_SCHEMA)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "celatim evidence index result"
    assert schema["properties"]["schema_version"]["const"] == "celatim.evidence_index.v1"


def test_public_evidence_index_schema_is_checked_in_and_named():
    schema = _read_json(PUBLIC_INDEX_SCHEMA)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "celatim public-safe evidence index"
    assert schema["properties"]["schema_version"]["const"] == "celatim.public_evidence_index.v1"


def test_doctor_schema_is_checked_in_and_named():
    schema = _read_json(DOCTOR_SCHEMA)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "celatim doctor result"
    assert schema["properties"]["schema_version"]["const"] == "celatim.doctor.v1"


def test_public_bundle_schema_is_checked_in_and_named():
    schema = _read_json(PUBLIC_BUNDLE_SCHEMA)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "celatim public-safe bundle manifest"
    assert schema["properties"]["schema_version"]["const"] == "celatim.public_bundle.v1"
    artifact_kinds = set(schema["$defs"]["artifact"]["properties"]["kind"]["enum"])
    assert "detector_rule_artifact" in artifact_kinds
    assert "windows_capture_guidance" in artifact_kinds


def test_public_bundle_verify_schema_is_checked_in_and_named():
    schema = _read_json(PUBLIC_BUNDLE_VERIFY_SCHEMA)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "celatim public-safe bundle verification"
    assert schema["properties"]["schema_version"]["const"] == "celatim.public_bundle_verify.v1"


def test_qemu_tap_preflight_schema_is_checked_in_and_named():
    schema = _read_json(QEMU_TAP_PREFLIGHT_SCHEMA)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "celatim QEMU TAP preflight report"
    assert schema["properties"]["schema_version"]["const"] == "celatim.qemu_tap_preflight.v1"
    assert schema["properties"]["claim_status"]["const"] == "preflight_only_no_vm_started"


def test_support_matrix_schema_is_checked_in_and_named():
    schema = _read_json(SUPPORT_MATRIX_SCHEMA)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "celatim support matrix"
    assert schema["properties"]["schema_version"]["const"] == "celatim.support_matrix.v1"


def test_reviewer_bundle_schema_is_checked_in_and_named():
    schema = _read_json(REVIEWER_BUNDLE_SCHEMA)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "celatim reviewer bundle manifest"
    assert schema["properties"]["schema_version"]["const"] == "celatim.reviewer_bundle.v1"


def test_reviewer_bundle_verify_schema_is_checked_in_and_named():
    schema = _read_json(REVIEWER_BUNDLE_VERIFY_SCHEMA)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "celatim reviewer bundle verification"
    assert schema["properties"]["schema_version"]["const"] == "celatim.reviewer_bundle_verify.v1"


def test_scenario_schema_is_checked_in_and_named():
    schema = _read_json(SCENARIO_SCHEMA)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "celatim scenario spec"
    assert schema["properties"]["schema_version"]["const"] == "celatim.scenario.v1"


def test_scenario_inventory_schema_is_checked_in_and_named():
    schema = _read_json(SCENARIO_INVENTORY_SCHEMA)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "celatim scenario inventory"
    assert schema["properties"]["schema_version"]["const"] == "celatim.scenario_inventory.v1"


def test_scrub_report_schema_is_checked_in_and_named():
    schema = _read_json(SCRUB_REPORT_SCHEMA)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "celatim pcap scrub report"
    assert schema["properties"]["schema_version"]["const"] == "celatim.scrub_report.v1"
    assert (
        schema["properties"]["claim_status"]["const"]
        == "same_code_offline_pcap_scrub_smoke_not_live_middlebox"
    )


def test_pcap_decode_schema_is_checked_in_and_named():
    schema = _read_json(PCAP_DECODE_SCHEMA)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "celatim pcap decode result"
    assert schema["properties"]["schema_version"]["const"] == "celatim.pcap_decode.v1"
    assert (
        schema["properties"]["claim_status"]["const"]
        == "same_code_pcap_decode_not_independent_trace_validation"
    )


def test_scenario_execution_plan_schema_is_checked_in_and_named():
    schema = _read_json(SCENARIO_EXECUTION_PLAN_SCHEMA)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "celatim scenario execution plan"
    assert schema["properties"]["schema_version"]["const"] == "celatim.scenario_execution_plan.v1"


def test_testbed_requirements_schema_is_checked_in_and_named():
    schema = _read_json(TESTBED_REQUIREMENTS_SCHEMA)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "celatim testbed requirements inventory"
    assert schema["properties"]["schema_version"]["const"] == "celatim.testbed_requirements.v1"


def test_timing_sweep_schema_is_checked_in_and_named():
    schema = _read_json(TIMING_SWEEP_SCHEMA)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "celatim timing sweep result"
    assert schema["properties"]["schema_version"]["const"] == "celatim.timing_sweep.v1"


def test_checked_in_scenarios_match_scenario_schema():
    schema = _read_json(SCENARIO_SCHEMA)

    for scenario in sorted((PROJECT / "scenarios").glob("*.toml")):
        _assert_valid(schema, tomllib.loads(scenario.read_text()))


def test_generated_scenario_inventory_matches_schema():
    schema = _read_json(SCENARIO_INVENTORY_SCHEMA)
    inventory = build_scenario_inventory(PROJECT / "scenarios").to_json()

    _assert_valid(schema, inventory)


def test_generated_scenario_execution_plan_matches_schema():
    schema = _read_json(SCENARIO_EXECUTION_PLAN_SCHEMA)
    plan = build_scenario_execution_plan(PROJECT / "scenarios").to_json()

    _assert_valid(schema, plan)


def test_generated_testbed_requirements_matches_schema():
    schema = _read_json(TESTBED_REQUIREMENTS_SCHEMA)
    inventory = build_testbed_requirements_inventory().to_json()

    _assert_valid(schema, inventory)


def test_generated_qemu_tap_preflight_matches_schema(tmp_path):
    schema = _read_json(QEMU_TAP_PREFLIGHT_SCHEMA)
    disk = tmp_path / "receiver.qcow2"
    disk.touch()
    report = build_qemu_tap_preflight_report(
        QemuGuestConfig(disk_image=disk, enable_kvm=False),
        HostTapConfig(tap_name="tap-schema", host_ipv4_cidr=None),
        kvm_device=tmp_path / "missing-kvm",
    ).to_json()

    _assert_valid(schema, report)


def test_generated_detector_replay_matches_schema(tmp_path):
    schema = _read_json(DETECTOR_REPLAY_SCHEMA)
    mechanism = {m.id: m for m in load_mechanisms(PROJECT / "data" / "mechanisms.jsonl")}[
        "tcp-reserved-bits"
    ]
    pcap = tmp_path / "clean-control.pcap"
    _write_test_ethernet_pcap(
        pcap,
        [
            build_tcp_reserved_bits_frame(
                default_ipv4_packet_path_config_for("tcp-reserved-bits"),
                0,
                index=0,
            )
        ],
    )

    report = replay_detectors_on_pcap(
        [mechanism],
        pcap,
        source_kind=TraceSourceKind.LOCAL_GENERATED_CONTROL,
        trace_name="schema-clean-control",
        tcpdump_path="tcpdump-definitely-not-installed",
    ).to_json()

    _assert_valid(schema, report)


def test_generated_tshark_detector_replay_matches_schema(tmp_path):
    schema = _read_json(DETECTOR_REPLAY_SCHEMA)
    mechanism = {m.id: m for m in load_mechanisms(PROJECT / "data" / "mechanisms.jsonl")}[
        "tcp-reserved-bits"
    ]
    pcap = tmp_path / "clean-control.pcap"
    _write_test_ethernet_pcap(
        pcap,
        [
            build_tcp_reserved_bits_frame(
                default_ipv4_packet_path_config_for("tcp-reserved-bits"),
                0,
                index=0,
            )
        ],
    )

    report = replay_detectors_on_pcap(
        [mechanism],
        pcap,
        source_kind=TraceSourceKind.PUBLIC_BENIGN_TRACE,
        backend=DetectorReplayBackend.TSHARK_DISPLAY_FILTER,
        tshark_path="tshark-definitely-not-installed",
    ).to_json()

    _assert_valid(schema, report)


def test_generated_suricata_detector_replay_matches_schema(tmp_path):
    schema = _read_json(DETECTOR_REPLAY_SCHEMA)
    mechanism = {m.id: m for m in load_mechanisms(PROJECT / "data" / "mechanisms.jsonl")}[
        "tcp-reserved-bits"
    ]
    pcap = tmp_path / "clean-control.pcap"
    _write_test_ethernet_pcap(
        pcap,
        [
            build_tcp_reserved_bits_frame(
                default_ipv4_packet_path_config_for("tcp-reserved-bits"),
                0,
                index=0,
            )
        ],
    )

    report = replay_detectors_on_pcap(
        [mechanism],
        pcap,
        source_kind=TraceSourceKind.PUBLIC_BENIGN_TRACE,
        backend=DetectorReplayBackend.SURICATA_RULE,
        suricata_path="suricata-definitely-not-installed",
    ).to_json()

    _assert_valid(schema, report)


def test_generated_detector_trace_manifest_matches_schema(tmp_path):
    schema = _read_json(DETECTOR_TRACE_MANIFEST_SCHEMA)
    pcap = tmp_path / "clean-control.pcap"
    _write_test_ethernet_pcap(
        pcap,
        [
            build_tcp_reserved_bits_frame(
                default_ipv4_packet_path_config_for("tcp-reserved-bits"),
                0,
                index=0,
            )
        ],
    )
    manifest = {
        "schema_version": "celatim.detector_trace_manifest.v1",
        "traces": [
            {
                "path": str(pcap),
                "source_kind": "authorized_benign_trace",
                "trace_name": "schema-authorized-clean",
                "origin_url": None,
                "license": "unit-test fixture",
                "filtering_assumptions": [
                    "fixture stands in for an authorized benign-trace campaign"
                ],
            }
        ],
    }

    _assert_valid(schema, manifest)


def test_generated_detector_replay_corpus_matches_schema(tmp_path):
    schema = _read_json(DETECTOR_REPLAY_CORPUS_SCHEMA)
    mechanism = {m.id: m for m in load_mechanisms(PROJECT / "data" / "mechanisms.jsonl")}[
        "tcp-reserved-bits"
    ]
    pcap = tmp_path / "clean-control.pcap"
    _write_test_ethernet_pcap(
        pcap,
        [
            build_tcp_reserved_bits_frame(
                default_ipv4_packet_path_config_for("tcp-reserved-bits"),
                0,
                index=0,
            )
        ],
    )
    manifest_path = tmp_path / "detector-traces.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": "celatim.detector_trace_manifest.v1",
                "traces": [
                    {
                        "path": "clean-control.pcap",
                        "source_kind": "authorized_benign_trace",
                        "trace_name": "schema-authorized-clean",
                        "origin_url": None,
                        "license": "unit-test fixture",
                        "filtering_assumptions": [
                            "fixture stands in for an authorized benign-trace campaign"
                        ],
                    }
                ],
            },
            sort_keys=True,
        )
        + "\n"
    )

    report = replay_detector_corpus(
        [mechanism],
        load_trace_manifest(manifest_path),
        tcpdump_path="tcpdump-definitely-not-installed",
    ).to_json()

    _assert_valid(schema, report)


def test_generated_scrub_report_matches_schema(tmp_path):
    schema = _read_json(SCRUB_REPORT_SCHEMA)
    pcap = tmp_path / "dirty.pcap"
    scrubbed = tmp_path / "scrubbed.pcap"
    _write_test_ethernet_pcap(
        pcap,
        [
            build_tcp_reserved_bits_frame(
                default_ipv4_packet_path_config_for("tcp-reserved-bits"),
                0x0A,
                index=0,
            )
        ],
    )

    report = scrub_tcp_reserved_bits_pcap(pcap, scrubbed).to_json()

    _assert_valid(schema, report)


def test_generated_support_matrix_report_matches_schema():
    schema = _read_json(SUPPORT_MATRIX_SCHEMA)
    report = support_matrix_report(load_mechanisms(PROJECT / "data" / "mechanisms.jsonl")).to_json()

    _assert_valid(schema, report)
    assert report["schema_version"] == "celatim.support_matrix.v1"
    assert report["mechanism_count"] == len(report["rows"])
    assert report["evidence_bucket_counts"]["offset_represented_zero_blob"] > 0
    rows = {row["mechanism_id"]: row for row in report["rows"]}
    assert rows["http2-ping-opaque"]["adapter_status"] == "real_pdu_fixture"
    assert rows["http2-ping-opaque"]["carrier_structure"] == "real_protocol_pdu"
    assert rows["bgp-path-attr-flags"]["evidence_bucket"] == "offset_represented_zero_blob"


def test_generated_timing_sweep_matches_schema():
    schema = _read_json(TIMING_SWEEP_SCHEMA)
    report = run_timing_sweep(
        MechanismProfile.from_catalog("dns-timing", PROJECT / "data" / "mechanisms.jsonl"),
        b"\x00\xfftiming",
        quanta_s=(0.01, 0.005),
        base_pacing=PacingConfig(unit_rate_hz=100.0, jitter_sample_window=4),
        run_id="schema-timing-sweep",
    ).to_json()

    _assert_valid(schema, report)


def test_generated_pcap_decode_matches_schema(tmp_path):
    schema = _read_json(PCAP_DECODE_SCHEMA)
    profile = MechanismProfile.from_catalog(
        "http2-ping-opaque",
        PROJECT / "data" / "mechanisms.jsonl",
    )
    payload = b"\x00\xffpcap"
    transport = PcapTransport(profile, tmp_path / "pcaps")
    ChannelSession(profile, transport).send_message(payload, session_id="schema-pcap-decode")
    report = decode_pcap(
        profile,
        transport.path_for("schema-pcap-decode"),
        expected_payload=payload,
        session_id="schema-pcap-decode",
        tshark_path="tshark-definitely-not-installed",
    ).to_json()

    _assert_valid(schema, report)
    assert report["parser_provenance_count"] == 1
    assert report["parser_provenance"][0]["result"] == "tool_missing"


def test_generated_observed_timing_sweep_matches_schema():
    schema = _read_json(TIMING_SWEEP_SCHEMA)
    profile = MechanismProfile.from_catalog("dns-timing", PROJECT / "data" / "mechanisms.jsonl")
    payload = b"\x00\xfftiming"
    baseline_payload = bytes(len(payload))
    pacing = PacingConfig(unit_rate_hz=100.0)
    baseline_count = _carrier_count(profile, baseline_payload, pacing)
    trial_count = _carrier_count(profile, payload, pacing)
    report = run_observed_timing_sweep(
        profile,
        payload,
        baseline=ObservedTimingCaseInput(
            observed_offsets_s=_timing_offsets(baseline_count),
            recovered_payload=baseline_payload,
        ),
        trials=(
            ObservedTimingCaseInput(
                observed_offsets_s=_timing_offsets(trial_count),
                recovered_payload=payload,
                quantum_s=0.01,
            ),
        ),
        base_pacing=pacing,
        baseline_payload=baseline_payload,
        run_id="schema-observed-timing-sweep",
        path_metadata={"tap": "schema-fixture"},
    ).to_json()

    _assert_valid(schema, report)


def test_generated_crypto_transcript_evidence_matches_schema(tmp_path):
    pytest.importorskip("ecdsa")
    schema = _read_json(SCHEMA)
    config = load_scenario(PROJECT / "scenarios" / "zz-ecdsa-nonce-local.toml")
    config = dataclasses.replace(
        config,
        transport=dataclasses.replace(
            config.transport,
            crypto_transcript_json=str(tmp_path / "transcripts" / "{scenario_id}-{case}.json"),
        ),
    )

    report = run_evidence(config, PROJECT / "data" / "mechanisms.jsonl").to_json()

    _assert_valid(schema, report)
    assert report["ok"] is True
    assert report["scenario_metadata"]["evidence_tier"] == "real_crypto_path"
    assert report["covert"]["transport_kind"] == "crypto_ecdsa_nonce"
    assert report["covert"]["transport_artifact"]["kind"] == "crypto_transcript"
    assert (
        report["covert"]["transport_metadata"]["schema_version"]
        == "celatim.transport_metadata.crypto_ecdsa_nonce.v1"
    )


def test_generated_rsa_pss_crypto_transcript_evidence_matches_schema(tmp_path):
    pytest.importorskip("cryptography")
    schema = _read_json(SCHEMA)
    config = load_scenario(PROJECT / "scenarios" / "zz-rsa-pss-salt-local.toml")
    config = dataclasses.replace(
        config,
        transport=dataclasses.replace(
            config.transport,
            crypto_transcript_json=str(tmp_path / "transcripts" / "{scenario_id}-{case}.json"),
        ),
    )

    report = run_evidence(config, PROJECT / "data" / "mechanisms.jsonl").to_json()

    _assert_valid(schema, report)
    assert report["ok"] is True
    assert report["scenario_metadata"]["evidence_tier"] == "real_crypto_path"
    assert report["covert"]["transport_kind"] == "crypto_rsa_pss_salt"
    assert report["covert"]["transport_artifact"]["kind"] == "crypto_transcript"
    assert (
        report["covert"]["transport_metadata"]["schema_version"]
        == "celatim.transport_metadata.crypto_rsa_pss_salt.v1"
    )


def test_full_afpacket_capture_scenario_shape_matches_schema():
    schema = _read_json(SCENARIO_SCHEMA)
    data = {
        "schema_version": "celatim.scenario.v1",
        "scenario_id": "afpacket-full-shape",
        "mechanism_id": "http2-ping-opaque",
        "description": "Full shape metadata",
        "evidence_tier": "crafted_production_path",
        "privilege": "cap_net_raw",
        "expected_runtime_s": 30.0,
        "requires_tools": ["ip", "tcpdump"],
        "requires_extras": ["packet"],
        "payload_hex": "00 ff 80 41",
        "control_message": "control",
        "artifact_dir": "artifacts",
        "log_dir": "logs",
        "run_id": "afpacket-full-shape-run",
        "pacing": {
            "unit_rate_hz": 20.0,
            "timing_quantum_s": 0.005,
            "decode_tolerance_s": 0.001,
            "adaptive": False,
            "jitter_sample_window": 4,
        },
        "reliability": {
            "max_receive_attempts": 3,
            "retry_backoff_s": 0.01,
            "suppress_duplicate_chunks": True,
            "max_retransmissions": 1,
        },
        "transport": {
            "kind": "afpacket_ipv4",
            "sender_interface": "left",
            "receiver_interface": "right",
            "src_mac": "02:00:00:00:00:11",
            "dst_mac": "02:00:00:00:00:22",
            "src_ip": "192.0.2.1",
            "dst_ip": "192.0.2.2",
            "src_port": 41000,
            "dst_port": 8443,
            "protocol": "tcp",
            "timeout_s": 1.5,
            "expected_frames": 3,
            "require_expected_frames": False,
            "capture_pcap": "captures/live.pcap",
            "capture_namespace": "rcvns",
            "capture_interface": "tap0",
            "capture_filter": ["tcp", "port", "8443"],
            "capture_snaplen": 4096,
            "capture_require_output": False,
        },
    }

    _assert_valid(schema, data)


def test_checked_in_golden_example_matches_evidence_schema():
    schema = _read_json(SCHEMA)
    golden = _read_json(GOLDEN)

    _assert_valid(schema, golden)


def test_generated_evidence_index_matches_schema(tmp_path):
    schema = _read_json(INDEX_SCHEMA)
    evidence_path = tmp_path / "evidence.json"
    result = run_evidence(
        load_scenario(PROJECT / "scenarios" / "http2-ping-opaque.toml"),
        PROJECT / "data" / "mechanisms.jsonl",
    )
    evidence_path.write_text(json.dumps(result.to_json(), sort_keys=True) + "\n")

    index = build_evidence_index([tmp_path]).to_json()

    _assert_valid(schema, index)
    case = index["items"][0]["cases"][0]
    assert case["endpoint_topology_kind"] == "same_process"
    assert case["independent_receiver_os"] is False
    assert case["carrier_structure"] == "real_protocol_pdu"
    assert case["control_strength"] == "nonzero_surrounding_bytes"


def test_generated_public_evidence_index_is_hash_only_and_schema_valid(tmp_path):
    schema = _read_json(PUBLIC_INDEX_SCHEMA)
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    pcap_dir = tmp_path / "pcaps"
    carrier_dir = tmp_path / "carriers"
    evidence_path = evidence_dir / "http2-ping-opaque.json"
    evidence_index_path = tmp_path / "evidence-index.json"
    config = load_scenario(PROJECT / "scenarios" / "http2-ping-opaque.toml")
    config = dataclasses.replace(
        config,
        artifact_dir=str(carrier_dir),
        transport=dataclasses.replace(config.transport, kind="pcap", root=str(pcap_dir)),
    )
    result = run_evidence(
        config,
        PROJECT / "data" / "mechanisms.jsonl",
        command=(
            "celatim",
            "scenario",
            "run",
            "--pcap-dir",
            str(pcap_dir),
            "--artifact-dir",
            str(carrier_dir),
        ),
    )
    evidence_path.write_text(json.dumps(result.to_json(), sort_keys=True) + "\n")
    evidence_index_path.write_text(
        json.dumps(
            build_evidence_index([evidence_dir], path_root=tmp_path).to_json(),
            sort_keys=True,
        )
        + "\n"
    )

    public_index = build_public_evidence_index(evidence_index_path).to_json()

    _assert_valid(schema, public_index)
    serialized = json.dumps(public_index, sort_keys=True)
    assert public_index["schema_version"] == "celatim.public_evidence_index.v1"
    assert public_index["evidence_count"] == 1
    assert public_index["items"][0]["evidence_sha256"]
    assert public_index["items"][0]["run_log_sha256"]
    public_case = public_index["items"][0]["cases"][0]
    assert public_case["carrier_structure"] == "real_protocol_pdu"
    assert public_case["control_strength"] == "nonzero_surrounding_bytes"
    assert public_case["transport_artifact_sha256"]
    assert "pcaps/" not in serialized
    assert "carriers/" not in serialized
    assert "run-logs/" not in serialized
    assert "rfc" + "tunnel" not in serialized


def test_generated_doctor_output_matches_schema(tmp_path):
    schema = _read_json(DOCTOR_SCHEMA)
    doctor = run_doctor(artifact_dir=tmp_path / "artifacts", optional_tools=()).to_json()

    _assert_valid(schema, doctor)


def test_generated_reviewer_bundle_manifest_matches_schema(tmp_path):
    schema = _read_json(REVIEWER_BUNDLE_SCHEMA)
    scenario_inventory_path = tmp_path / "scenarios.json"
    doctor_path = tmp_path / "doctor.json"
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    evidence_path = evidence_dir / "http2-ping-opaque.json"
    evidence_index_path = tmp_path / "evidence-index.json"
    detector_replay_path = tmp_path / "detector-replay.json"
    scrub_report_path = tmp_path / "scrub-report.json"
    paper_table_path = tmp_path / "field-catalog-longtable.tex"
    package_wheel_path = tmp_path / "celatim-0.1.0-py3-none-any.whl"
    lockfile_path = tmp_path / "uv.lock"
    scenario_spec_path = tmp_path / "http2-ping-opaque.toml"
    testbed_package_path = tmp_path / "Dockerfile"
    testbed_preflight_path = tmp_path / "qemu-preflight.json"

    scenario_inventory_path.write_text(
        json.dumps(
            build_scenario_inventory(PROJECT / "scenarios").to_json(),
            sort_keys=True,
        )
        + "\n"
    )
    doctor_path.write_text(
        json.dumps(
            run_doctor(
                scenario_dir=PROJECT / "scenarios",
                artifact_dir=tmp_path / "artifacts",
                optional_tools=(),
            ).to_json(),
            sort_keys=True,
        )
        + "\n"
    )
    evidence_path.write_text(
        json.dumps(
            run_evidence(
                load_scenario(PROJECT / "scenarios" / "http2-ping-opaque.toml"),
                PROJECT / "data" / "mechanisms.jsonl",
            ).to_json(),
            sort_keys=True,
        )
        + "\n"
    )
    evidence_index_path.write_text(
        json.dumps(build_evidence_index([evidence_dir]).to_json(), sort_keys=True) + "\n"
    )
    detector_replay_path.write_text('{"schema_version":"celatim.detector_replay_corpus.v1"}\n')
    scrub_report_path.write_text('{"schema_version":"celatim.scrub_report.v1"}\n')
    paper_table_path.write_text("% generated table\n")
    package_wheel_path.write_bytes(b"wheel bytes\n")
    lockfile_path.write_text("# lockfile\n")
    scenario_spec_path.write_text('scenario_id = "http2-ping-opaque-real-pdu-smoke"\n')
    testbed_package_path.write_text("FROM debian:stable-slim\n")
    testbed_preflight_path.write_text('{"schema_version":"celatim.qemu_tap_preflight.v1"}\n')

    manifest = build_reviewer_bundle_manifest(
        bundle_name="schema-test",
        bundle_root=tmp_path,
        doctor_path=doctor_path,
        scenario_inventory_path=scenario_inventory_path,
        evidence_index_path=evidence_index_path,
        paper_table_path=paper_table_path,
        package_wheel_path=package_wheel_path,
        lockfile_path=lockfile_path,
        detector_replay_paths=(detector_replay_path,),
        scrub_report_paths=(scrub_report_path,),
        scenario_spec_paths=(scenario_spec_path,),
        testbed_package_paths=(testbed_package_path,),
        testbed_preflight_paths=(testbed_preflight_path,),
    ).to_json()

    _assert_valid(schema, manifest)
    assert manifest["bundle_name"] == "schema-test"
    assert manifest["doctor_ok"] is True
    assert manifest["scenario_count"] == 17
    assert manifest["evidence_count"] == 1
    assert manifest["artifact_count"] == 11
    assert [artifact["kind"] for artifact in manifest["artifacts"]] == [
        "doctor_report",
        "scenario_inventory",
        "evidence_index",
        "detector_replay",
        "scrub_report",
        "paper_table",
        "package_wheel",
        "lockfile",
        "scenario_spec",
        "testbed_package",
        "testbed_preflight",
    ]


def test_generated_reviewer_bundle_verification_matches_schema(tmp_path):
    schema = _read_json(REVIEWER_BUNDLE_VERIFY_SCHEMA)
    doctor_path = tmp_path / "doctor.json"
    scenario_inventory_path = tmp_path / "scenarios.json"
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    evidence_path = evidence_dir / "http2-ping-opaque.json"
    evidence_index_path = tmp_path / "evidence-index.json"
    package_wheel_path = tmp_path / "celatim-0.1.0-py3-none-any.whl"
    detector_replay_path = tmp_path / "detector-replay.json"
    lockfile_path = tmp_path / "uv.lock"
    scenario_spec_path = tmp_path / "http2-ping-opaque.toml"
    testbed_package_path = tmp_path / "Dockerfile"
    testbed_preflight_path = tmp_path / "qemu-preflight.json"
    manifest_path = tmp_path / "bundle-manifest.json"

    doctor_path.write_text(json.dumps({"schema_version": "celatim.doctor.v1", "ok": True}) + "\n")
    scenario_inventory_path.write_text(
        json.dumps(
            {
                "schema_version": "celatim.scenario_inventory.v1",
                "scenario_count": 1,
            }
        )
        + "\n"
    )
    evidence_path.write_text(
        json.dumps(
            run_evidence(
                load_scenario(PROJECT / "scenarios" / "http2-ping-opaque.toml"),
                PROJECT / "data" / "mechanisms.jsonl",
            ).to_json(),
            sort_keys=True,
        )
        + "\n"
    )
    evidence_index_path.write_text(
        json.dumps(build_evidence_index([evidence_dir]).to_json(), sort_keys=True) + "\n"
    )
    package_wheel_path.write_bytes(b"wheel bytes\n")
    detector_replay_path.write_text('{"schema_version":"celatim.detector_replay.v1"}\n')
    lockfile_path.write_text("# lockfile\n")
    scenario_spec_path.write_text('scenario_id = "http2-ping-opaque-real-pdu-smoke"\n')
    testbed_package_path.write_text("FROM debian:stable-slim\n")
    testbed_preflight_path.write_text('{"schema_version":"celatim.qemu_tap_preflight.v1"}\n')
    manifest_path.write_text(
        json.dumps(
            build_reviewer_bundle_manifest(
                bundle_name="verify-schema-test",
                bundle_root=tmp_path,
                doctor_path=doctor_path,
                scenario_inventory_path=scenario_inventory_path,
                evidence_index_path=evidence_index_path,
                package_wheel_path=package_wheel_path,
                detector_replay_paths=(detector_replay_path,),
                lockfile_path=lockfile_path,
                scenario_spec_paths=(scenario_spec_path,),
                testbed_package_paths=(testbed_package_path,),
                testbed_preflight_paths=(testbed_preflight_path,),
            ).to_json(),
            sort_keys=True,
        )
        + "\n"
    )

    ok_report = verify_reviewer_bundle_manifest(manifest_path).to_json()
    _assert_valid(schema, ok_report)
    assert ok_report["ok"] is True
    assert ok_report["ok_count"] == 10
    assert ok_report["consistency_check_count"] == 12
    assert ok_report["consistency_ok_count"] == 12
    assert ok_report["consistency_failed_count"] == 0
    assert [artifact["kind"] for artifact in ok_report["artifacts"]] == [
        "doctor_report",
        "scenario_inventory",
        "evidence_index",
        "detector_replay",
        "package_wheel",
        "lockfile",
        "scenario_spec",
        "testbed_package",
        "testbed_preflight",
        "evidence_run",
    ]

    doctor_path.write_text("tampered\n")
    failed_report = verify_reviewer_bundle_manifest(manifest_path).to_json()
    _assert_valid(schema, failed_report)
    assert failed_report["ok"] is False
    assert failed_report["mismatch_count"] == 1
    assert failed_report["consistency_failed_count"] == 1


def test_generated_public_bundle_manifest_matches_schema(tmp_path):
    schema = _read_json(PUBLIC_BUNDLE_SCHEMA)
    catalog_path = tmp_path / "mechanisms.jsonl"
    support_matrix_path = tmp_path / "evidence-support-matrix.md"
    detector_scrub_guidance_path = tmp_path / "detector-scrub-guidance.md"
    detector_rules_manifest_path = tmp_path / "detector-rules-manifest.json"
    detector_rules_markdown_path = tmp_path / "detector-rules.md"
    windows_capture_guidance_path = tmp_path / "windows-pktmon-etw-guidance.md"
    scenario_inventory_path = tmp_path / "scenarios.json"
    scenario_execution_plan_path = tmp_path / "execution-plan.json"
    testbed_requirements_path = tmp_path / "testbed-requirements.json"
    doctor_path = tmp_path / "doctor.json"
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    evidence_path = evidence_dir / "http2-ping-opaque.json"
    private_evidence_index_path = tmp_path / "private-evidence-index.json"
    evidence_index_path = tmp_path / "evidence-index.json"
    paper_table_path = tmp_path / "field-catalog-longtable.tex"
    reviewer_manifest_path = tmp_path / "bundle-manifest.json"
    reviewer_verification_path = tmp_path / "bundle-verify.json"

    catalog_path.write_text((PROJECT / "data" / "mechanisms.jsonl").read_text())
    support_matrix_path.write_text("# Evidence Support Matrix\n")
    detector_scrub_guidance_path.write_text("# Detector and Scrub Guidance\n")
    detector_rules_manifest_path.write_text('{"schema_version":"celatim.detector_rules.v1"}\n')
    detector_rules_markdown_path.write_text("# Detector Rule Appendix\n")
    windows_capture_guidance_path.write_text("# Windows pktmon/ETW Capture Guidance\n")
    scenario_inventory_path.write_text(
        json.dumps(
            build_scenario_inventory(PROJECT / "scenarios").to_json(),
            sort_keys=True,
        )
        + "\n"
    )
    scenario_execution_plan_path.write_text(
        json.dumps(
            build_scenario_execution_plan(PROJECT / "scenarios").to_json(),
            sort_keys=True,
        )
        + "\n"
    )
    testbed_requirements_path.write_text(
        json.dumps(build_testbed_requirements_inventory().to_json(), sort_keys=True) + "\n"
    )
    doctor_path.write_text(
        json.dumps(
            run_doctor(
                scenario_dir=PROJECT / "scenarios",
                artifact_dir=tmp_path / "artifacts",
                optional_tools=(),
            ).to_json(),
            sort_keys=True,
        )
        + "\n"
    )
    evidence_path.write_text(
        json.dumps(
            run_evidence(
                load_scenario(PROJECT / "scenarios" / "http2-ping-opaque.toml"),
                PROJECT / "data" / "mechanisms.jsonl",
            ).to_json(),
            sort_keys=True,
        )
        + "\n"
    )
    private_evidence_index_path.write_text(
        json.dumps(build_evidence_index([evidence_dir]).to_json(), sort_keys=True) + "\n"
    )
    evidence_index_path.write_text(
        json.dumps(
            build_public_evidence_index(private_evidence_index_path).to_json(), sort_keys=True
        )
        + "\n"
    )
    paper_table_path.write_text("% generated table\n")
    reviewer_manifest_path.write_text(
        json.dumps(
            build_reviewer_bundle_manifest(
                bundle_name="private-reviewer-test",
                bundle_root=tmp_path,
                doctor_path=doctor_path,
                scenario_inventory_path=scenario_inventory_path,
                evidence_index_path=private_evidence_index_path,
                paper_table_path=paper_table_path,
            ).to_json(),
            sort_keys=True,
        )
        + "\n"
    )
    reviewer_verification_path.write_text(
        json.dumps(
            verify_reviewer_bundle_manifest(reviewer_manifest_path).to_json(),
            sort_keys=True,
        )
        + "\n"
    )

    manifest = build_public_bundle_manifest(
        bundle_name="public-schema-test",
        bundle_root=tmp_path,
        catalog_path=catalog_path,
        support_matrix_path=support_matrix_path,
        detector_scrub_guidance_path=detector_scrub_guidance_path,
        detector_rule_artifact_paths=(
            detector_rules_manifest_path,
            detector_rules_markdown_path,
        ),
        windows_capture_guidance_path=windows_capture_guidance_path,
        scenario_inventory_path=scenario_inventory_path,
        scenario_execution_plan_path=scenario_execution_plan_path,
        testbed_requirements_path=testbed_requirements_path,
        evidence_index_path=evidence_index_path,
        reviewer_manifest_path=reviewer_manifest_path,
        reviewer_verification_path=reviewer_verification_path,
        paper_table_path=paper_table_path,
    ).to_json()

    _assert_valid(schema, manifest)
    assert manifest["schema_version"] == "celatim.public_bundle.v1"
    assert manifest["release_scope"] == "public_safe"
    assert manifest["private_reference_policy"] == "hash_only_no_channel_artifacts"
    assert manifest["private_reviewer_bundle_name"] == "private-reviewer-test"
    assert manifest["private_reviewer_bundle_verified"] is True
    assert manifest["private_reviewer_artifact_count"] == 5
    assert "evidence_run" in manifest["private_reviewer_artifact_kinds"]
    assert manifest["artifact_count"] == 13
    assert [artifact["kind"] for artifact in manifest["artifacts"]] == [
        "mechanism_catalog",
        "support_matrix",
        "detector_scrub_guidance",
        "detector_rule_artifact",
        "detector_rule_artifact",
        "windows_capture_guidance",
        "scenario_inventory",
        "scenario_execution_plan",
        "testbed_requirements",
        "evidence_index",
        "paper_table",
        "reviewer_bundle_manifest",
        "reviewer_bundle_verification",
    ]


def test_generated_public_bundle_verification_matches_schema(tmp_path, monkeypatch):
    schema = _read_json(PUBLIC_BUNDLE_VERIFY_SCHEMA)
    workspace = tmp_path / "measurement"
    public_dir = tmp_path / "artifacts" / "reviewer" / "public"
    workspace.mkdir()
    public_dir.mkdir(parents=True)
    catalog_path = public_dir / "mechanisms.jsonl"
    support_matrix_path = public_dir / "evidence-support-matrix.md"
    detector_scrub_guidance_path = public_dir / "detector-scrub-guidance.md"
    detector_rules_manifest_path = public_dir / "detector-rules-manifest.json"
    detector_rules_markdown_path = public_dir / "detector-rules" / "detector-rules.md"
    windows_capture_guidance_path = public_dir / "windows-pktmon-etw-guidance.md"
    scenario_inventory_path = public_dir / "scenarios.json"
    scenario_execution_plan_path = public_dir / "execution-plan.json"
    testbed_requirements_path = public_dir / "testbed-requirements.json"
    private_evidence_index_path = public_dir / "private-evidence-index.json"
    evidence_index_path = public_dir / "evidence-index.json"
    paper_table_path = public_dir / "field-catalog-longtable.tex"
    reviewer_manifest_path = public_dir / "private-reviewer-bundle-manifest.json"
    reviewer_verification_path = public_dir / "private-reviewer-bundle-verify.json"
    public_manifest_path = public_dir / "public-bundle-manifest.json"

    catalog_path.write_text((PROJECT / "data" / "mechanisms.jsonl").read_text())
    support_matrix_path.write_text("# Evidence Support Matrix\n")
    detector_scrub_guidance_path.write_text("# Detector and Scrub Guidance\n")
    detector_rules_manifest_path.write_text('{"schema_version":"celatim.detector_rules.v1"}\n')
    detector_rules_markdown_path.parent.mkdir()
    detector_rules_markdown_path.write_text("# Detector Rule Appendix\n")
    windows_capture_guidance_path.write_text("# Windows pktmon/ETW Capture Guidance\n")
    scenario_inventory_path.write_text(
        json.dumps(
            {
                "schema_version": "celatim.scenario_inventory.v1",
                "scenario_count": 1,
            },
            sort_keys=True,
        )
        + "\n"
    )
    scenario_execution_plan_path.write_text(
        json.dumps(
            build_scenario_execution_plan(PROJECT / "scenarios").to_json(),
            sort_keys=True,
        )
        + "\n"
    )
    testbed_requirements_path.write_text(
        json.dumps(build_testbed_requirements_inventory().to_json(), sort_keys=True) + "\n"
    )
    evidence_summary = {
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
    }
    private_evidence_index_path.write_text(json.dumps(evidence_summary, sort_keys=True) + "\n")
    evidence_index_path.write_text(
        json.dumps(
            build_public_evidence_index(private_evidence_index_path).to_json(), sort_keys=True
        )
        + "\n"
    )
    paper_table_path.write_text("% generated table\n")
    reviewer_manifest_path.write_text(
        json.dumps(
            {
                **evidence_summary,
                "schema_version": "celatim.reviewer_bundle.v1",
                "bundle_name": "private-reviewer-test",
            },
            sort_keys=True,
        )
        + "\n"
    )
    reviewer_verification_path.write_text(
        json.dumps(
            {
                "schema_version": "celatim.reviewer_bundle_verify.v1",
                "ok": True,
                "artifact_count": 0,
                "artifacts": [],
            },
            sort_keys=True,
        )
        + "\n"
    )
    monkeypatch.chdir(workspace)
    public_manifest_path.write_text(
        json.dumps(
            build_public_bundle_manifest(
                bundle_name="public-verify-test",
                bundle_root="../artifacts/reviewer/public",
                catalog_path=catalog_path,
                support_matrix_path=support_matrix_path,
                detector_scrub_guidance_path=detector_scrub_guidance_path,
                detector_rule_artifact_paths=(
                    detector_rules_manifest_path,
                    detector_rules_markdown_path,
                ),
                windows_capture_guidance_path=windows_capture_guidance_path,
                scenario_inventory_path=scenario_inventory_path,
                scenario_execution_plan_path=scenario_execution_plan_path,
                testbed_requirements_path=testbed_requirements_path,
                evidence_index_path=evidence_index_path,
                reviewer_manifest_path=reviewer_manifest_path,
                reviewer_verification_path=reviewer_verification_path,
                paper_table_path=paper_table_path,
            ).to_json(),
            sort_keys=True,
        )
        + "\n"
    )
    monkeypatch.chdir(tmp_path)
    ok_report = verify_public_bundle_manifest(public_manifest_path).to_json()
    _assert_valid(schema, ok_report)
    assert ok_report["ok"] is True
    assert ok_report["artifact_count"] == 13
    assert ok_report["ok_count"] == 13
    assert ok_report["policy_check_count"] == 7
    assert ok_report["policy_failed_count"] == 0

    leak = public_dir / "pcaps" / "leak.pcap"
    leak.parent.mkdir()
    leak.write_bytes(b"not public safe")
    failed_report = verify_public_bundle_manifest(public_manifest_path).to_json()
    _assert_valid(schema, failed_report)
    assert failed_report["ok"] is False
    assert failed_report["error"] == "public_policy_verification_failed"
    failed_checks = {
        check["check"]: check for check in failed_report["policy_checks"] if not check["ok"]
    }
    assert failed_checks["public_bundle.forbidden_bundle_files"]["actual"] == ["pcaps/leak.pcap"]


def test_http2_scenario_output_matches_golden_example(monkeypatch):
    monkeypatch.chdir(PROJECT)
    schema = _read_json(SCHEMA)
    golden = _read_json(GOLDEN)
    command = (
        "celatim",
        "--catalog",
        "data/mechanisms.jsonl",
        "scenario",
        "run",
        "--scenario",
        "scenarios/http2-ping-opaque.toml",
    )

    result = run_evidence(
        load_scenario(Path("scenarios/http2-ping-opaque.toml")),
        Path("data/mechanisms.jsonl"),
        command=command,
    )
    live = result.to_json()

    _assert_valid(schema, live)
    assert _normalize_for_golden(live) == golden


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _write_test_ethernet_pcap(path: Path, frames: list[bytes]) -> None:
    global_header = struct.Struct("<IHHIIII")
    packet_header = struct.Struct("<IIII")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        fh.write(global_header.pack(0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames):
            fh.write(packet_header.pack(index, 0, len(frame), len(frame)))
            fh.write(frame)


def _carrier_count(profile: MechanismProfile, payload: bytes, pacing: PacingConfig) -> int:
    return (
        ChannelSession(profile, InMemoryTransport())
        .send_message(
            payload,
            session_id="schema-count",
            pacing=pacing,
        )
        .carrier_units
    )


def _timing_offsets(count: int, period_s: float = 0.01) -> tuple[float, ...]:
    return tuple(index * period_s + (0.0001 if index % 2 else 0.0) for index in range(count))


def _normalize_for_golden(document: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(document)
    normalized["run_id"] = "NORMALIZED"
    normalized["started_at_unix_s"] = 0.0
    for case in ("covert", "benign_control"):
        normalized[case]["evidence"]["elapsed_s"] = 0.0
        _normalize_endpoint_os(normalized[case]["evidence"]["endpoint_os"])
    for key in ("package_version", "python_version", "platform", "system", "release", "machine"):
        normalized["reproducibility"][key] = "NORMALIZED"
    return normalized


def _normalize_endpoint_os(endpoint_os: dict[str, Any]) -> None:
    for endpoint_key in ("sender", "receiver", "tap"):
        endpoint = endpoint_os.get(endpoint_key)
        if endpoint is None:
            continue
        for key in ("system", "release", "version", "machine", "platform", "node"):
            endpoint[key] = "NORMALIZED"


def _assert_valid(schema: dict[str, Any], document: Any) -> None:
    errors: list[str] = []
    _validate_node(schema, document, schema, "$", errors)
    assert not errors, "\n".join(errors)


def _validate_node(
    schema: dict[str, Any], value: Any, root: dict[str, Any], path: str, errors: list[str]
) -> None:
    if "$ref" in schema:
        _validate_node(_resolve_ref(root, str(schema["$ref"])), value, root, path, errors)
        return

    any_of = schema.get("anyOf")
    if isinstance(any_of, list):
        if not any(
            _schema_matches(option, value, root, path)
            for option in any_of
            if isinstance(option, dict)
        ):
            errors.append(f"{path}: did not match any anyOf branch")
        return

    if_schema = schema.get("if")
    then_schema = schema.get("then")
    if (
        isinstance(if_schema, dict)
        and isinstance(then_schema, dict)
        and _schema_matches(if_schema, value, root, path)
    ):
        _validate_node(then_schema, value, root, path, errors)

    all_of = schema.get("allOf")
    if isinstance(all_of, list):
        for option in all_of:
            if isinstance(option, dict):
                _validate_node(option, value, root, path, errors)

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}, got {value!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: expected one of {schema['enum']!r}, got {value!r}")

    if "type" in schema:
        expected = schema["type"]
        expected_types = expected if isinstance(expected, list) else [expected]
        if not any(
            _matches_json_type(value, str(expected_type)) for expected_type in expected_types
        ):
            errors.append(f"{path}: expected type {expected_types!r}, got {type(value).__name__}")
            return

    pattern = schema.get("pattern")
    if isinstance(pattern, str) and isinstance(value, str) and re.fullmatch(pattern, value) is None:
        errors.append(f"{path}: value does not match pattern {pattern!r}")

    properties = schema.get("properties")
    if isinstance(properties, dict) and isinstance(value, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                errors.append(f"{path}: missing required key {key!r}")
        if schema.get("additionalProperties") is False:
            for key in sorted(set(value) - set(properties)):
                errors.append(f"{path}: unexpected key {key!r}")
        for key, child_schema in properties.items():
            if key in value:
                _validate_node(child_schema, value[key], root, f"{path}.{key}", errors)

    items = schema.get("items")
    if isinstance(items, dict) and isinstance(value, list):
        for index, item in enumerate(value):
            _validate_node(items, item, root, f"{path}[{index}]", errors)


def _schema_matches(schema: dict[str, Any], value: Any, root: dict[str, Any], path: str) -> bool:
    errors: list[str] = []
    _validate_node(schema, value, root, path, errors)
    return not errors


def _resolve_ref(root: dict[str, Any], ref: str) -> dict[str, Any]:
    if not ref.startswith("#/"):
        raise AssertionError(f"unsupported schema ref: {ref}")
    node: Any = root
    for raw_part in ref[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        node = node[part]
    if not isinstance(node, dict):
        raise AssertionError(f"schema ref is not an object: {ref}")
    return node


def _matches_json_type(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "number":
        return isinstance(value, int | float) and not isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    raise AssertionError(f"unsupported schema type: {expected}")
