"""Scenario evidence-run API."""

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any, cast

import pytest

import celatim.scenario as scenario_module
from celatim.scenario import (
    SCENARIO_EVIDENCE_TIERS,
    SCENARIO_EXECUTION_PLAN_SCHEMA_VERSION,
    SCENARIO_PRIVILEGE_LEVELS,
    SCHEMA_VERSION,
    SPEC_SCHEMA_VERSION,
    ScenarioConfig,
    TransportConfig,
    build_scenario_execution_plan,
    discover_scenarios,
    find_scenario,
    load_scenario,
    load_scenario_by_id,
    run_evidence,
)
from celatim.session import ChannelSession, InMemoryTransport, PacingConfig
from celatim.testbed import (
    AfpacketRoundtripResult,
    AioquicConnectionIdRoundtripResult,
    AioquicH3SettingsRoundtripResult,
    DnsEdnsPaddingRoundtripResult,
    DnsToolVersionRecord,
    HyperH2PingRoundtripResult,
)

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"
SCENARIOS = Path(__file__).resolve().parents[1] / "scenarios"


def test_run_evidence_returns_covert_and_benign_control_results():
    result = run_evidence(
        ScenarioConfig(
            scenario_id="scenario-api",
            mechanism_id="rtp-rtcp-ext-app",
            payload=b"\x00\xffpayload",
            pacing=PacingConfig(unit_rate_hz=20.0),
        ),
        DATA,
        command=("celatim", "evidence", "run"),
    )

    doc = result.to_json()
    assert result.ok is True
    assert doc["schema_version"] == SCHEMA_VERSION
    assert isinstance(doc["run_id"], str)
    assert doc["run_log"] is None
    assert doc["scenario_id"] == "scenario-api"
    assert doc["mechanism_id"] == "rtp-rtcp-ext-app"
    assert doc["adapter_status"] == "real_pdu_fixture"
    assert doc["control_kind"] == "empty_payload"
    assert doc["scenario_metadata"] == {
        "description": None,
        "evidence_tier": "in_memory_regression",
        "privilege": "none",
        "expected_runtime_s": None,
        "requires_tools": [],
        "requires_extras": [],
    }
    assert doc["covert"]["matches"] is True
    assert bytes.fromhex(doc["covert"]["recovered_hex"]) == b"\x00\xffpayload"
    assert doc["covert"]["parser_validated"] is True
    assert doc["covert"]["parser_provenance"] == []
    assert doc["covert"]["detector_provenance"]
    assert doc["covert"]["detector_provenance"][0]["implementation_kind"] == "same_code"
    assert doc["covert"]["detector_provenance"][0]["false_positive_estimate"] is False
    assert (
        doc["covert"]["detector_provenance"][0]["benign_basis"]
        == "scenario_control_fixture_not_fp_estimate"
    )
    assert doc["covert"]["observer_validations"]
    assert doc["covert"]["observer_validations"][0]["ok"] is True
    assert doc["covert"]["observer_validations"][0]["validator"] == "second_parser"
    assert len(doc["covert"]["mutation_controls"]) == 2
    assert all(control["ok"] for control in doc["covert"]["mutation_controls"])
    assert {control["control_type"] for control in doc["covert"]["mutation_controls"]} == {
        "wrong_nominal_offset",
        "zero_surrounding_bytes",
    }
    assert doc["covert"]["carrier_units_with_bytes"] > 0
    assert doc["covert"]["transport_kind"] == "memory"
    assert doc["covert"]["transport_record"] is None
    assert doc["covert"]["transport_artifact"] is None
    assert doc["covert"]["evidence"]["endpoint_os"]["topology_kind"] == "same_process"
    assert doc["covert"]["evidence"]["endpoint_os"]["independent_receiver_os"] is False
    assert doc["benign_control"]["matches"] is True
    assert bytes.fromhex(doc["benign_control"]["recovered_hex"]) == b""
    assert doc["benign_control"]["parser_validated"] is True
    assert doc["covert"]["evidence"]["pacing"]["unit_rate_hz"] == 20.0
    assert doc["covert"]["evidence"]["reliability"]["policy"]["max_receive_attempts"] == 1
    assert doc["covert"]["evidence"]["reliability"]["receive_attempts"] == 1
    assert doc["reproducibility"]["catalog_path"] == str(DATA)
    assert doc["reproducibility"]["catalog_sha256"] == hashlib.sha256(DATA.read_bytes()).hexdigest()
    assert doc["reproducibility"]["package_version"]
    assert doc["reproducibility"]["python_version"]
    assert doc["reproducibility"]["command"] == ["celatim", "evidence", "run"]


def test_run_evidence_uses_packaged_catalog_by_default():
    result = run_evidence(
        ScenarioConfig(
            scenario_id="packaged-catalog-api",
            mechanism_id="http2-ping-opaque",
            payload=b"\x00\xffpayload",
            control_payload=b"control",
            control_kind="control_message",
        )
    )
    doc = result.to_json()

    assert result.ok is True
    assert doc["mechanism_id"] == "http2-ping-opaque"
    assert doc["covert"]["parser_validated"] is True
    assert doc["reproducibility"]["catalog_path"].endswith("mechanisms.jsonl")
    assert doc["reproducibility"]["catalog_sha256"]


def test_run_evidence_symbol_only_adapter_reports_no_parser_validation():
    result = run_evidence(
        ScenarioConfig(
            scenario_id="symbol-only",
            mechanism_id="bgp-path-attr-flags",
            payload=b"offset represented",
            control_payload=b"control",
            control_kind="explicit_control_payload",
        ),
        DATA,
    )
    doc = result.to_json()

    assert result.ok is True
    assert doc["adapter_status"] == "offset_represented_zero_blob"
    assert doc["control_kind"] == "explicit_control_payload"
    assert doc["covert"]["parser_validated"] is None
    assert doc["covert"]["parser_provenance"] == []
    assert len(doc["covert"]["detector_provenance"]) == 4
    assert doc["covert"]["detector_provenance"][0]["result"] == "failed"
    assert {record["rule_format"] for record in doc["covert"]["detector_provenance"][1:]} == {
        "nftables",
        "iptables-u32",
        "bpf",
    }
    assert doc["covert"]["observer_validations"] == []
    assert doc["covert"]["mutation_controls"] == []
    assert doc["covert"]["carrier_units_with_bytes"] == 0
    assert doc["benign_control"]["parser_validated"] is None
    assert doc["benign_control"]["parser_provenance"] == []
    assert doc["benign_control"]["observer_validations"] == []
    assert doc["benign_control"]["mutation_controls"] == []
    assert bytes.fromhex(doc["benign_control"]["recovered_hex"]) == b"control"


def test_run_evidence_records_chunked_large_case():
    result = run_evidence(
        ScenarioConfig(
            scenario_id="large",
            mechanism_id="tcp-reserved-bits",
            payload=b"x" * 70000,
            control_payload=b"control",
            control_kind="control_message",
        ),
        DATA,
    )
    doc = result.to_json()

    assert result.ok is True
    assert doc["covert"]["matches"] is True
    assert doc["covert"]["recovered_len"] == 70000
    assert doc["covert"]["parser_validated"] is True
    assert [record["rule_format"] for record in doc["covert"]["detector_provenance"]] == [
        None,
        "nftables",
        "iptables-u32",
        "bpf",
    ]
    assert doc["covert"]["detector_provenance"][0]["executed"] is True
    assert doc["covert"]["detector_provenance"][0]["matched_units"] > 0
    assert doc["covert"]["detector_provenance"][1]["executed"] is False
    assert "generated filter provenance only" in doc["covert"]["detector_provenance"][1]["notes"]
    assert doc["covert"]["evidence"]["ok"] is True
    assert doc["covert"]["evidence"]["payload_len"] == 70000
    assert doc["covert"]["evidence"]["session_framing"] == "chunked"
    assert doc["covert"]["evidence"]["chunk_count"] > 1
    assert doc["covert"]["evidence"]["integrity_sha256"] == doc["covert"]["expected_sha256"]
    assert doc["benign_control"]["matches"] is True
    assert doc["benign_control"]["evidence"]["ok"] is True


def test_run_evidence_executes_tcpdump_detector_for_tcp_reserved_pcap(tmp_path):
    result = run_evidence(
        ScenarioConfig(
            scenario_id="tcpdump-detector",
            mechanism_id="tcp-reserved-bits",
            payload=b"\x00\xfftcpdump",
            control_payload=b"control",
            control_kind="control_message",
            transport=TransportConfig("pcap", str(tmp_path / "pcaps")),
        ),
        DATA,
    )
    doc = result.to_json()
    detectors = doc["covert"]["detector_provenance"]

    assert result.ok is True
    linktype = int.from_bytes(
        Path(doc["covert"]["transport_record"]).read_bytes()[20:24],
        "little",
    )
    assert linktype == 1
    assert [record["implementation_kind"] for record in detectors] == [
        "same_code",
        "generated_kernel_rule",
        "generated_kernel_rule",
        "generated_kernel_rule",
        "independent_tool_output",
    ]
    tcpdump = detectors[-1]
    assert tcpdump["name"] == "tcp-reserved-bits-tcpdump-bpf"
    assert tcpdump["rule"] == "tcp[12] & 0x0f != 0"
    assert tcpdump["command"][-1] == "tcp[12] & 0x0f != 0"
    assert tcpdump["false_positive_estimate"] is False
    assert tcpdump["benign_basis"] == "scenario_control_fixture_not_fp_estimate"
    if shutil.which("tcpdump") is None:
        assert tcpdump["executed"] is False
        assert tcpdump["result"] == "tool_missing"
    else:
        assert tcpdump["executed"] is True
        assert tcpdump["result"] == "matched"
        assert tcpdump["returncode"] == 0
        assert tcpdump["matched_units"] > 0
        assert tcpdump["stdout_sha256"] is not None
        assert tcpdump["stderr_sha256"] is not None
    parsers = doc["covert"]["parser_provenance"]
    assert len(parsers) == 1
    tshark = parsers[0]
    assert tshark["name"] == "tcp-reserved-bits-tshark-dissector"
    assert tshark["implementation_kind"] == "independent_tool_output"
    assert tshark["field_paths"] == ["tcp.flags.res"]
    assert tshark["display_filter"] == "tcp"
    assert tshark["checked_units"] > 0
    if shutil.which("tshark") is None:
        assert tshark["executed"] is False
        assert tshark["result"] == "tool_missing"
    else:
        assert tshark["returncode"] == 0
        assert tshark["stdout_sha256"] is not None


def test_run_evidence_records_failed_case_instead_of_aborting():
    result = run_evidence(
        ScenarioConfig(
            scenario_id="bad-transport",
            mechanism_id="tcp-reserved-bits",
            payload=b"payload",
            transport=TransportConfig("unsupported"),
        ),
        DATA,
    )
    doc = result.to_json()

    assert result.ok is False
    assert doc["covert"]["matches"] is False
    assert doc["covert"]["evidence"]["ok"] is False
    assert doc["covert"]["evidence"]["payload_len"] == len(b"payload")
    assert doc["covert"]["evidence"]["error"].startswith("ValueError:")
    assert (
        "transport 'unsupported' is not registered for this adapter"
        in doc["covert"]["evidence"]["error"]
    )
    assert "supported transports:" in doc["covert"]["evidence"]["error"]


def test_load_checked_in_scenario_spec_and_run_it():
    config = load_scenario(SCENARIOS / "http2-ping-opaque.toml")

    assert config.scenario_id == "http2-ping-opaque-real-pdu-smoke"
    assert config.mechanism_id == "http2-ping-opaque"
    assert config.payload == b"\x00\xff\x80ABC"
    assert config.description == "Non-privileged HTTP/2 PING opaque-bytes real-PDU smoke scenario."
    assert config.evidence_tier == "real_pdu_packet_path"
    assert config.privilege == "none"
    assert config.expected_runtime_s == 5.0
    assert config.requires_tools == ()
    assert config.requires_extras == ()
    assert config.control_payload == b"control"
    assert config.control_kind == "control_message"
    assert config.spec_path == str(SCENARIOS / "http2-ping-opaque.toml")
    assert config.pacing is not None
    assert config.pacing.unit_rate_hz == 20.0

    result = run_evidence(config, DATA)
    assert result.ok is True
    assert result.covert.parser_validated is True
    assert result.to_json()["scenario_metadata"] == {
        "description": "Non-privileged HTTP/2 PING opaque-bytes real-PDU smoke scenario.",
        "evidence_tier": "real_pdu_packet_path",
        "privilege": "none",
        "expected_runtime_s": 5.0,
        "requires_tools": [],
        "requires_extras": [],
    }
    assert result.to_json()["reproducibility"]["scenario_spec_path"] == str(
        SCENARIOS / "http2-ping-opaque.toml"
    )


def test_run_evidence_writes_real_pdu_carrier_artifacts(tmp_path):
    artifact_dir = tmp_path / "artifacts"
    result = run_evidence(
        ScenarioConfig(
            scenario_id="artifact-run",
            mechanism_id="quic-connection-id",
            payload=b"\x00\xffartifact",
            control_payload=b"control",
            control_kind="control_message",
            artifact_dir=str(artifact_dir),
            run_id="artifact-test-run",
        ),
        DATA,
    )
    doc = result.to_json()

    assert result.ok is True
    assert doc["run_id"] == "artifact-test-run"
    assert doc["run_log"] is not None
    log_artifact = doc["run_log"]
    assert log_artifact["kind"] == "run_log"
    log_path = Path(log_artifact["path"])
    assert log_path.is_file()
    assert log_path.is_relative_to(artifact_dir)
    log_events = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert [event["event"] for event in log_events] == [
        "run_started",
        "case_finished",
        "case_finished",
        "run_finished",
    ]
    assert {event["run_id"] for event in log_events} == {"artifact-test-run"}
    assert log_events[0]["command"] == []
    assert log_events[0]["scenario_metadata"]["evidence_tier"] == "in_memory_regression"
    assert log_events[0]["scenario_metadata"]["privilege"] == "none"
    assert log_events[-1]["ok"] is True
    assert doc["covert"]["artifacts"]
    assert doc["benign_control"]["artifacts"]
    assert len(doc["covert"]["artifacts"]) == doc["covert"]["carrier_units_with_bytes"]

    for artifact in doc["covert"]["artifacts"] + doc["benign_control"]["artifacts"]:
        path = Path(artifact["path"])
        data = path.read_bytes()
        assert path.is_file()
        assert path.is_relative_to(artifact_dir)
        assert artifact["kind"] == "carrier_unit"
        assert artifact["size_bytes"] == len(data)
        assert artifact["sha256"] == hashlib.sha256(data).hexdigest()


def test_run_evidence_can_write_log_to_explicit_log_dir(tmp_path):
    log_dir = tmp_path / "logs"
    result = run_evidence(
        ScenarioConfig(
            scenario_id="explicit-log-run",
            mechanism_id="http2-ping-opaque",
            payload=b"\x00\xfflog",
            control_payload=b"control",
            control_kind="control_message",
            log_dir=str(log_dir),
            run_id="explicit-log",
        ),
        DATA,
        command=("celatim", "scenario", "run"),
    )
    doc = result.to_json()

    assert doc["run_id"] == "explicit-log"
    assert doc["run_log"] is not None
    assert Path(doc["run_log"]["path"]).is_relative_to(log_dir)
    events = [json.loads(line) for line in Path(doc["run_log"]["path"]).read_text().splitlines()]
    assert events[0]["command"] == ["celatim", "scenario", "run"]
    assert events[1]["case"] == "covert"
    assert events[2]["case"] == "benign_control"
    assert events[3]["event"] == "run_finished"


def test_run_evidence_uses_file_transport_when_configured(tmp_path):
    transport_dir = tmp_path / "wire"
    result = run_evidence(
        ScenarioConfig(
            scenario_id="file-transport-run",
            mechanism_id="http2-ping-opaque",
            payload=b"\x00\xfffile",
            control_payload=b"control",
            control_kind="control_message",
            transport=TransportConfig("file", str(transport_dir)),
        ),
        DATA,
    )
    doc = result.to_json()

    assert result.ok is True
    assert doc["covert"]["transport_kind"] == "file"
    assert doc["benign_control"]["transport_kind"] == "file"
    assert doc["covert"]["transport_record"]
    assert doc["benign_control"]["transport_record"]
    assert Path(doc["covert"]["transport_record"]).is_file()
    assert Path(doc["benign_control"]["transport_record"]).is_file()
    assert Path(doc["covert"]["transport_record"]).is_relative_to(transport_dir)
    _assert_transport_artifact(doc["covert"], transport_dir)
    _assert_transport_artifact(doc["benign_control"], transport_dir)
    assert doc["covert"]["parser_validated"] is True
    assert doc["covert"]["carrier_unit_sha256"]


def test_run_evidence_uses_pcap_transport_when_configured(tmp_path):
    pcap_dir = tmp_path / "pcaps"
    result = run_evidence(
        ScenarioConfig(
            scenario_id="pcap-transport-run",
            mechanism_id="http2-ping-opaque",
            payload=b"\x00\xffpcap",
            control_payload=b"control",
            control_kind="control_message",
            transport=TransportConfig("pcap", str(pcap_dir)),
        ),
        DATA,
    )
    doc = result.to_json()

    assert result.ok is True
    assert doc["covert"]["transport_kind"] == "pcap"
    assert doc["benign_control"]["transport_kind"] == "pcap"
    assert Path(doc["covert"]["transport_record"]).is_file()
    assert Path(doc["benign_control"]["transport_record"]).is_file()
    assert Path(doc["covert"]["transport_record"]).is_relative_to(pcap_dir)
    _assert_transport_artifact(doc["covert"], pcap_dir)
    _assert_transport_artifact(doc["benign_control"], pcap_dir)
    assert doc["covert"]["parser_validated"] is True
    assert doc["covert"]["carrier_unit_sha256"]


def test_run_evidence_rejects_unregistered_transport_for_adapter(tmp_path):
    result = run_evidence(
        ScenarioConfig(
            scenario_id="unsupported-transport",
            mechanism_id="bgp-path-attr-flags",
            payload=b"\x00\xffunsupported",
            control_payload=b"control",
            control_kind="control_message",
            transport=TransportConfig("pcap", str(tmp_path / "pcaps")),
        ),
        DATA,
    )
    doc = result.to_json()

    assert result.ok is False
    assert doc["covert"]["matches"] is False
    assert (
        "transport 'pcap' is not registered for this adapter" in doc["covert"]["evidence"]["error"]
    )
    assert "supported transports: file, memory, timed_memory" in doc["covert"]["evidence"]["error"]
    assert doc["benign_control"]["matches"] is False


def test_run_evidence_uses_timed_memory_transport_when_configured():
    result = run_evidence(
        ScenarioConfig(
            scenario_id="timed-transport-run",
            mechanism_id="http2-ping-opaque",
            payload=b"\x00\xfftimed",
            control_payload=b"control",
            control_kind="control_message",
            pacing=PacingConfig(unit_rate_hz=500.0, timing_quantum_s=0.002),
            transport=TransportConfig("timed_memory"),
        ),
        DATA,
    )
    doc = result.to_json()

    assert result.ok is True
    assert doc["covert"]["transport_kind"] == "timed_memory"
    assert doc["covert"]["transport_record"] is None
    assert doc["covert"]["transport_artifact"] is None
    assert doc["covert"]["evidence"]["timing_trace"] is not None
    assert (
        doc["covert"]["evidence"]["timing_trace"]["sample_count"]
        == doc["covert"]["evidence"]["carrier_units"]
    )
    assert doc["covert"]["evidence"]["timing_profile"] is not None
    assert doc["covert"]["evidence"]["timing_profile"]["timing_quantum_s"] == 0.002
    assert (
        doc["covert"]["evidence"]["timing_profile"]["rate_status"]
        == "local_scheme_demonstration_not_capacity"
    )
    assert doc["benign_control"]["transport_kind"] == "timed_memory"
    assert doc["benign_control"]["evidence"]["timing_trace"] is not None
    assert doc["benign_control"]["evidence"]["timing_profile"] is not None


def test_run_evidence_records_afpacket_tcpdump_capture_artifacts(tmp_path, monkeypatch):
    capture_dir = tmp_path / "captures"
    seen_outputs: list[Path] = []

    def fake_run_afpacket_roundtrip(
        profile,
        payload,
        *,
        session_id=None,
        config=None,
        pacing=None,
        reliability=None,
        socket_factory=None,
        capture=None,
    ):
        assert config is not None
        assert config.receiver_interface == "right"
        assert socket_factory is None
        assert capture is not None
        assert capture.config.namespace == "rcvns"
        assert capture.config.interface == "tap0"
        assert capture.config.filter_expr == ("tcp", "port", "8443")
        assert capture.config.snaplen == 4096
        assert capture.config.require_output is True
        seen_outputs.append(capture.config.output)
        capture.config.output.parent.mkdir(parents=True, exist_ok=True)
        capture.config.output.write_bytes(b"pcap:" + str(session_id).encode())

        memory_transport = InMemoryTransport()
        receipt = ChannelSession(profile, memory_transport).send_message(
            payload,
            session_id=session_id,
            pacing=pacing,
        )
        symbols = memory_transport.receive_symbols(receipt.session_id)
        result = ChannelSession(
            profile,
            memory_transport,
            reliability=reliability,
        ).receive_message(receipt.session_id)
        return AfpacketRoundtripResult(
            receipt=receipt,
            result=result,
            symbols=tuple(symbols),
            expected_frames=receipt.carrier_units,
        )

    monkeypatch.setattr(scenario_module, "run_afpacket_roundtrip", fake_run_afpacket_roundtrip)

    result = run_evidence(
        ScenarioConfig(
            scenario_id="afpacket-capture-run",
            mechanism_id="http2-ping-opaque",
            payload=b"\x00\xfflive",
            control_payload=b"control",
            control_kind="control_message",
            transport=TransportConfig(
                "afpacket_ipv4",
                sender_interface="left",
                receiver_interface="right",
                dst_port=8443,
                capture_pcap=str(capture_dir),
                capture_namespace="rcvns",
                capture_interface="tap0",
                capture_filter=("tcp", "port", "8443"),
                capture_snaplen=4096,
            ),
        ),
        DATA,
    )
    doc = result.to_json()

    assert result.ok is True
    assert seen_outputs == [
        capture_dir / "afpacket-capture-run-covert.pcap",
        capture_dir / "afpacket-capture-run-benign_control.pcap",
    ]
    for case in ("covert", "benign_control"):
        record = Path(str(doc[case]["transport_record"]))
        artifact = cast(dict[str, Any], doc[case]["transport_artifact"])
        assert record.is_file()
        assert record.is_relative_to(capture_dir)
        assert artifact["kind"] == "transport_capture"
        assert artifact["path"] == str(record)
        assert artifact["size_bytes"] == len(record.read_bytes())
        assert artifact["sha256"] == hashlib.sha256(record.read_bytes()).hexdigest()


def test_run_evidence_records_dns_daemon_capture_artifacts(tmp_path, monkeypatch):
    capture_dir = tmp_path / "dns-captures"
    seen_outputs: list[Path] = []

    def fake_run_dns_edns0_padding_roundtrip(
        profile,
        payload,
        *,
        session_id=None,
        config=None,
        pacing=None,
        reliability=None,
        command_runner=None,
        process_runner=None,
        pcap_decoder=None,
        sleeper=None,
    ):
        assert config is not None
        assert config.sender_namespace == "leftns"
        assert config.resolver_namespace == "rightns"
        assert config.sender_address == "192.0.2.1"
        assert config.resolver_address == "192.0.2.2"
        assert config.query_name == "covert.example"
        assert config.answer_address == "192.0.2.2"
        assert config.port == 5353
        assert config.padding_optcode == 12
        assert config.capture_interface == "tapdns"
        assert config.capture_filter == ("udp", "port", "5353")
        assert config.capture_start_delay_s == 0.0
        assert config.capture_pcap is not None
        seen_outputs.append(config.capture_pcap)
        config.capture_pcap.parent.mkdir(parents=True, exist_ok=True)
        config.capture_pcap.write_bytes(b"dns-pcap:" + str(session_id).encode())

        memory_transport = InMemoryTransport()
        receipt = ChannelSession(profile, memory_transport).send_message(
            payload,
            session_id=session_id,
            pacing=pacing,
        )
        symbols = memory_transport.receive_symbols(receipt.session_id)
        result = ChannelSession(
            profile,
            memory_transport,
            reliability=reliability,
        ).receive_message(receipt.session_id)
        return DnsEdnsPaddingRoundtripResult(
            receipt=receipt,
            result=result,
            symbols=tuple(symbols),
            capture_pcap=config.capture_pcap,
            answers=("192.0.2.2",),
            daemon_readiness={"ok": True},
            tool_versions=(
                DnsToolVersionRecord(
                    tool="dnsmasq",
                    argv=("dnsmasq", "--version"),
                    returncode=0,
                    stdout_sha256="0" * 64,
                    stderr_sha256="1" * 64,
                    stdout_excerpt="Dnsmasq version test",
                    stderr_excerpt=None,
                ),
                DnsToolVersionRecord(
                    tool="dig",
                    argv=("dig", "-v"),
                    returncode=0,
                    stdout_sha256="2" * 64,
                    stderr_sha256="3" * 64,
                    stdout_excerpt="DiG test",
                    stderr_excerpt=None,
                ),
            ),
        )

    monkeypatch.setattr(
        scenario_module,
        "run_dns_edns0_padding_roundtrip",
        fake_run_dns_edns0_padding_roundtrip,
    )

    result = run_evidence(
        ScenarioConfig(
            scenario_id="dns-daemon-run",
            mechanism_id="edns0-padding",
            payload=b"\x00\xffdns",
            transport=TransportConfig(
                "dns_edns0_padding",
                src_ip="192.0.2.1",
                dst_ip="192.0.2.2",
                dst_port=5353,
                capture_pcap=str(capture_dir),
                capture_interface="tapdns",
                capture_filter=("udp", "port", "5353"),
                dns_sender_namespace="leftns",
                dns_resolver_namespace="rightns",
                dns_query_name="covert.example",
                dns_answer_address="192.0.2.2",
                dns_capture_start_delay_s=0.0,
            ),
        ),
        DATA,
    )
    doc = result.to_json()

    assert result.ok is True
    assert seen_outputs == [
        capture_dir / "dns-daemon-run-covert.pcap",
        capture_dir / "dns-daemon-run-benign_control.pcap",
    ]
    assert doc["covert"]["transport_kind"] == "dns_edns0_padding"
    for case in ("covert", "benign_control"):
        metadata = cast(dict[str, Any], doc[case]["transport_metadata"])
        record = Path(str(doc[case]["transport_record"]))
        artifact = cast(dict[str, Any], doc[case]["transport_artifact"])
        assert metadata["schema_version"] == "celatim.transport_metadata.dns_edns0_padding.v1"
        assert metadata["query_name"] == "covert.example"
        assert metadata["resolver_address"] == "192.0.2.2"
        assert metadata["port"] == 5353
        assert metadata["padding_optcode"] == 12
        assert metadata["answer_count"] == 1
        assert metadata["answers"] == ["192.0.2.2"]
        assert metadata["daemon_readiness"] == {"ok": True}
        assert [record["tool"] for record in metadata["tool_versions"]] == ["dnsmasq", "dig"]
        assert metadata["tool_versions"][0]["argv"] == ["dnsmasq", "--version"]
        assert metadata["tool_versions"][0]["stdout_excerpt"] == "Dnsmasq version test"
        assert artifact["kind"] == "transport_capture"
        assert artifact["path"] == str(record)
        assert artifact["size_bytes"] == len(record.read_bytes())
        assert artifact["sha256"] == hashlib.sha256(record.read_bytes()).hexdigest()


def test_run_evidence_records_http2_hyper_h2_transcript_artifacts(tmp_path, monkeypatch):
    transcript_dir = tmp_path / "http2-transcripts"
    seen_outputs: list[Path] = []

    def fake_run_hyper_h2_ping_roundtrip(
        profile,
        payload,
        *,
        session_id=None,
        config=None,
        pacing=None,
        reliability=None,
    ):
        assert config is not None
        assert config.validate_ack is True
        assert config.transcript_json is not None
        seen_outputs.append(config.transcript_json)
        config.transcript_json.parent.mkdir(parents=True, exist_ok=True)
        config.transcript_json.write_text(
            json.dumps(
                {
                    "schema_version": "celatim.http2_hyper_h2_transcript.v1",
                    "session_id": session_id,
                    "ping_count": 1,
                    "ping_ack_count": 1,
                }
            )
            + "\n"
        )

        memory_transport = InMemoryTransport()
        receipt = ChannelSession(profile, memory_transport).send_message(
            payload,
            session_id=session_id,
            pacing=pacing,
        )
        symbols = memory_transport.receive_symbols(receipt.session_id)
        result = ChannelSession(
            profile,
            memory_transport,
            reliability=reliability,
        ).receive_message(receipt.session_id)
        return HyperH2PingRoundtripResult(
            receipt=receipt,
            result=result,
            symbols=tuple(symbols),
            transcript_json=config.transcript_json,
            transport_metadata={
                "schema_version": "celatim.transport_metadata.http2_hyper_h2.v1",
                "implementation": "hyper-h2",
                "claim_status": "local_hyper_h2_client_server_ping_path",
                "validate_ack": True,
                "ping_count": receipt.carrier_units,
                "ping_ack_count": receipt.carrier_units,
                "transcript_schema_version": "celatim.http2_hyper_h2_transcript.v1",
                "transcript_json": str(config.transcript_json),
            },
        )

    monkeypatch.setattr(
        scenario_module,
        "run_hyper_h2_ping_roundtrip",
        fake_run_hyper_h2_ping_roundtrip,
    )

    result = run_evidence(
        ScenarioConfig(
            scenario_id="http2-hyper-h2-run",
            mechanism_id="http2-ping-opaque",
            payload=b"\x00\xffh2",
            control_payload=b"control",
            control_kind="control_message",
            evidence_tier="real_daemon_path",
            requires_extras=("daemon",),
            transport=TransportConfig(
                "http2_hyper_h2",
                http2_transcript_json=str(transcript_dir),
                http2_validate_ack=True,
            ),
        ),
        DATA,
    )
    doc = result.to_json()

    assert result.ok is True
    assert seen_outputs == [
        transcript_dir / "http2-hyper-h2-run-covert.json",
        transcript_dir / "http2-hyper-h2-run-benign_control.json",
    ]
    assert doc["covert"]["transport_kind"] == "http2_hyper_h2"
    assert doc["covert"]["evidence"]["endpoint_os"]["topology_kind"] == "same_process"
    for case in ("covert", "benign_control"):
        metadata = cast(dict[str, Any], doc[case]["transport_metadata"])
        record = Path(str(doc[case]["transport_record"]))
        artifact = cast(dict[str, Any], doc[case]["transport_artifact"])
        assert record.is_file()
        assert record.is_relative_to(transcript_dir)
        assert artifact["kind"] == "http2_hyper_h2_transcript"
        assert artifact["path"] == str(record)
        assert artifact["size_bytes"] == len(record.read_bytes())
        assert artifact["sha256"] == hashlib.sha256(record.read_bytes()).hexdigest()
        assert metadata["schema_version"] == "celatim.transport_metadata.http2_hyper_h2.v1"
        assert metadata["implementation"] == "hyper-h2"
        assert metadata["claim_status"] == "local_hyper_h2_client_server_ping_path"
        assert metadata["transcript_json"] == str(record)


def test_run_evidence_records_http3_aioquic_settings_transcript_artifacts(
    tmp_path,
    monkeypatch,
):
    transcript_dir = tmp_path / "h3-transcripts"
    seen_outputs: list[Path] = []

    def fake_run_aioquic_h3_settings_roundtrip(
        profile,
        payload,
        *,
        session_id=None,
        config=None,
        pacing=None,
        reliability=None,
    ):
        assert config is not None
        assert config.validate_receiver_settings is True
        assert config.transcript_json is not None
        seen_outputs.append(config.transcript_json)
        config.transcript_json.parent.mkdir(parents=True, exist_ok=True)
        config.transcript_json.write_text(
            json.dumps(
                {
                    "schema_version": "celatim.http3_aioquic_settings_transcript.v1",
                    "session_id": session_id,
                    "symbol_count": 1,
                    "observed_setting_values": [1],
                }
            )
            + "\n"
        )

        memory_transport = InMemoryTransport()
        receipt = ChannelSession(profile, memory_transport).send_message(
            payload,
            session_id=session_id,
            pacing=pacing,
        )
        symbols = memory_transport.receive_symbols(receipt.session_id)
        result = ChannelSession(
            profile,
            memory_transport,
            reliability=reliability,
        ).receive_message(receipt.session_id)
        return AioquicH3SettingsRoundtripResult(
            receipt=receipt,
            result=result,
            symbols=tuple(symbols),
            transcript_json=config.transcript_json,
            transport_metadata={
                "schema_version": "celatim.transport_metadata.http3_aioquic_reserved_settings.v1",
                "implementation": "aioquic.h3",
                "aioquic_version": "test",
                "claim_status": "local_aioquic_h3_settings_reserved_value_controlled_hook",
                "controlled_hook": "test local SETTINGS hook",
                "validate_receiver_settings": True,
                "reserved_setting_id": 33,
                "symbol_count": receipt.carrier_units,
                "transcript_schema_version": "celatim.http3_aioquic_settings_transcript.v1",
                "transcript_json": str(config.transcript_json),
            },
        )

    monkeypatch.setattr(
        scenario_module,
        "run_aioquic_h3_settings_roundtrip",
        fake_run_aioquic_h3_settings_roundtrip,
    )

    result = run_evidence(
        ScenarioConfig(
            scenario_id="http3-aioquic-run",
            mechanism_id="http3-reserved-settings",
            payload=b"\x00\xffh3",
            control_payload=b"control",
            control_kind="control_message",
            evidence_tier="real_daemon_path",
            requires_extras=("daemon",),
            transport=TransportConfig(
                "http3_aioquic_reserved_settings",
                http3_transcript_json=str(transcript_dir),
                http3_validate_receiver_settings=True,
            ),
        ),
        DATA,
    )
    doc = result.to_json()

    assert result.ok is True
    assert seen_outputs == [
        transcript_dir / "http3-aioquic-run-covert.json",
        transcript_dir / "http3-aioquic-run-benign_control.json",
    ]
    assert doc["covert"]["transport_kind"] == "http3_aioquic_reserved_settings"
    assert doc["covert"]["evidence"]["endpoint_os"]["topology_kind"] == "same_process"
    for case in ("covert", "benign_control"):
        metadata = cast(dict[str, Any], doc[case]["transport_metadata"])
        record = Path(str(doc[case]["transport_record"]))
        artifact = cast(dict[str, Any], doc[case]["transport_artifact"])
        assert record.is_file()
        assert record.is_relative_to(transcript_dir)
        assert artifact["kind"] == "http3_aioquic_settings_transcript"
        assert artifact["path"] == str(record)
        assert artifact["size_bytes"] == len(record.read_bytes())
        assert artifact["sha256"] == hashlib.sha256(record.read_bytes()).hexdigest()
        assert metadata["schema_version"] == (
            "celatim.transport_metadata.http3_aioquic_reserved_settings.v1"
        )
        assert metadata["implementation"] == "aioquic.h3"
        assert metadata["claim_status"] == (
            "local_aioquic_h3_settings_reserved_value_controlled_hook"
        )
        assert metadata["reserved_setting_id"] == 33
        assert metadata["transcript_json"] == str(record)


def test_run_evidence_records_quic_aioquic_transcript_artifacts(tmp_path, monkeypatch):
    transcript_dir = tmp_path / "quic-transcripts"
    seen_outputs: list[Path] = []

    def fake_run_aioquic_connection_id_roundtrip(
        profile,
        payload,
        *,
        session_id=None,
        config=None,
        pacing=None,
        reliability=None,
    ):
        assert config is not None
        assert config.validate_server_response is True
        assert config.transcript_json is not None
        seen_outputs.append(config.transcript_json)
        config.transcript_json.parent.mkdir(parents=True, exist_ok=True)
        config.transcript_json.write_text(
            json.dumps(
                {
                    "schema_version": "celatim.quic_aioquic_transcript.v1",
                    "session_id": session_id,
                    "symbol_count": 1,
                    "observed_dcid_hex": ["00" * 20],
                }
            )
            + "\n"
        )

        memory_transport = InMemoryTransport()
        receipt = ChannelSession(profile, memory_transport).send_message(
            payload,
            session_id=session_id,
            pacing=pacing,
        )
        symbols = memory_transport.receive_symbols(receipt.session_id)
        result = ChannelSession(
            profile,
            memory_transport,
            reliability=reliability,
        ).receive_message(receipt.session_id)
        return AioquicConnectionIdRoundtripResult(
            receipt=receipt,
            result=result,
            symbols=tuple(symbols),
            transcript_json=config.transcript_json,
            transport_metadata={
                "schema_version": "celatim.transport_metadata.quic_aioquic_connection_id.v1",
                "implementation": "aioquic",
                "aioquic_version": "test",
                "claim_status": "local_aioquic_client_server_initial_dcid_controlled_hook",
                "controlled_hook": "test pre-connect peer CID hook",
                "validate_server_response": True,
                "symbol_count": receipt.carrier_units,
                "transcript_schema_version": "celatim.quic_aioquic_transcript.v1",
                "transcript_json": str(config.transcript_json),
            },
        )

    monkeypatch.setattr(
        scenario_module,
        "run_aioquic_connection_id_roundtrip",
        fake_run_aioquic_connection_id_roundtrip,
    )

    result = run_evidence(
        ScenarioConfig(
            scenario_id="quic-aioquic-run",
            mechanism_id="quic-connection-id",
            payload=b"\x00\xffquic",
            control_payload=b"control",
            control_kind="control_message",
            evidence_tier="real_daemon_path",
            requires_extras=("daemon",),
            transport=TransportConfig(
                "quic_aioquic_connection_id",
                quic_transcript_json=str(transcript_dir),
                quic_validate_server_response=True,
            ),
        ),
        DATA,
    )
    doc = result.to_json()

    assert result.ok is True
    assert seen_outputs == [
        transcript_dir / "quic-aioquic-run-covert.json",
        transcript_dir / "quic-aioquic-run-benign_control.json",
    ]
    assert doc["covert"]["transport_kind"] == "quic_aioquic_connection_id"
    assert doc["covert"]["evidence"]["endpoint_os"]["topology_kind"] == "same_process"
    for case in ("covert", "benign_control"):
        metadata = cast(dict[str, Any], doc[case]["transport_metadata"])
        record = Path(str(doc[case]["transport_record"]))
        artifact = cast(dict[str, Any], doc[case]["transport_artifact"])
        assert record.is_file()
        assert record.is_relative_to(transcript_dir)
        assert artifact["kind"] == "quic_aioquic_transcript"
        assert artifact["path"] == str(record)
        assert artifact["size_bytes"] == len(record.read_bytes())
        assert artifact["sha256"] == hashlib.sha256(record.read_bytes()).hexdigest()
        assert metadata["schema_version"] == (
            "celatim.transport_metadata.quic_aioquic_connection_id.v1"
        )
        assert metadata["implementation"] == "aioquic"
        assert metadata["claim_status"] == (
            "local_aioquic_client_server_initial_dcid_controlled_hook"
        )
        assert metadata["transcript_json"] == str(record)


def test_run_evidence_records_ecdsa_crypto_transcript_artifacts(tmp_path):
    pytest.importorskip("ecdsa")
    transcript_dir = tmp_path / "transcripts"

    result = run_evidence(
        ScenarioConfig(
            scenario_id="ecdsa-local-run",
            mechanism_id="ecdsa-nonce",
            payload=b"\x00\xffcrypto",
            control_payload=b"control",
            control_kind="control_message",
            evidence_tier="real_crypto_path",
            requires_extras=("crypto",),
            transport=TransportConfig(
                "crypto_ecdsa_nonce",
                crypto_transcript_json=str(transcript_dir),
            ),
        ),
        DATA,
    )
    doc = result.to_json()

    assert result.ok is True
    assert doc["adapter_status"] == "real_crypto_path"
    assert doc["adapter_capabilities"] == [
        "codec_session",
        "crypto_transcript",
        "json_envelope",
    ]
    assert doc["scenario_metadata"]["evidence_tier"] == "real_crypto_path"
    assert doc["scenario_metadata"]["requires_extras"] == ["crypto"]
    assert doc["covert"]["transport_kind"] == "crypto_ecdsa_nonce"
    assert doc["covert"]["parser_validated"] is None
    assert doc["covert"]["evidence"]["carrier_structure"] == "crypto_transcript"
    assert doc["covert"]["evidence"]["control_strength"] == "honest_random_control"
    assert doc["covert"]["evidence"]["independent_validator"] == "real_crypto_verify"
    assert doc["covert"]["evidence"]["endpoint_os"]["topology_kind"] == "same_process"
    for case in ("covert", "benign_control"):
        metadata = cast(dict[str, Any], doc[case]["transport_metadata"])
        record = Path(str(doc[case]["transport_record"]))
        artifact = cast(dict[str, Any], doc[case]["transport_artifact"])
        transcript = json.loads(record.read_text())
        assert record.is_file()
        assert record.is_relative_to(transcript_dir)
        assert artifact["kind"] == "crypto_transcript"
        assert artifact["path"] == str(record)
        assert artifact["size_bytes"] == len(record.read_bytes())
        assert artifact["sha256"] == hashlib.sha256(record.read_bytes()).hexdigest()
        assert metadata["schema_version"] == "celatim.transport_metadata.crypto_ecdsa_nonce.v1"
        assert metadata["transcript_schema_version"] == "celatim.crypto_transcript.ecdsa_nonce.v1"
        assert metadata["transcript_sha256"] == artifact["sha256"]
        assert metadata["transcript_size_bytes"] == artifact["size_bytes"]
        assert metadata["signature_count"] == transcript["signature_count"]
        assert metadata["verified_signature_count"] == transcript["signature_count"]
        assert metadata["recovered_symbol_count"] == transcript["signature_count"]
        assert metadata["honest_random_control"]["signature_count"] == 2
        assert metadata["honest_random_control"]["verified_signature_count"] == 2
        assert metadata["honest_random_control"]["embedded_symbol_like_count"] == 0


def test_run_evidence_records_rsa_pss_crypto_transcript_artifacts(tmp_path):
    pytest.importorskip("cryptography")
    transcript_dir = tmp_path / "transcripts"

    result = run_evidence(
        ScenarioConfig(
            scenario_id="rsa-pss-local-run",
            mechanism_id="rsa-pss-salt",
            payload=b"\x00\xffcrypto",
            control_payload=b"control",
            control_kind="control_message",
            evidence_tier="real_crypto_path",
            requires_extras=("crypto",),
            transport=TransportConfig(
                "crypto_rsa_pss_salt",
                crypto_transcript_json=str(transcript_dir),
            ),
        ),
        DATA,
    )
    doc = result.to_json()

    assert result.ok is True
    assert doc["adapter_status"] == "real_crypto_path"
    assert doc["adapter_capabilities"] == [
        "codec_session",
        "crypto_transcript",
        "json_envelope",
    ]
    assert doc["scenario_metadata"]["evidence_tier"] == "real_crypto_path"
    assert doc["scenario_metadata"]["requires_extras"] == ["crypto"]
    assert doc["covert"]["transport_kind"] == "crypto_rsa_pss_salt"
    assert doc["covert"]["parser_validated"] is None
    assert doc["covert"]["evidence"]["carrier_structure"] == "crypto_transcript"
    assert doc["covert"]["evidence"]["control_strength"] == "honest_random_control"
    assert doc["covert"]["evidence"]["independent_validator"] == "real_crypto_verify"
    assert doc["covert"]["evidence"]["endpoint_os"]["topology_kind"] == "same_process"
    for case in ("covert", "benign_control"):
        metadata = cast(dict[str, Any], doc[case]["transport_metadata"])
        record = Path(str(doc[case]["transport_record"]))
        artifact = cast(dict[str, Any], doc[case]["transport_artifact"])
        transcript = json.loads(record.read_text())
        assert record.is_file()
        assert record.is_relative_to(transcript_dir)
        assert artifact["kind"] == "crypto_transcript"
        assert artifact["path"] == str(record)
        assert artifact["size_bytes"] == len(record.read_bytes())
        assert artifact["sha256"] == hashlib.sha256(record.read_bytes()).hexdigest()
        assert metadata["schema_version"] == "celatim.transport_metadata.crypto_rsa_pss_salt.v1"
        assert metadata["transcript_schema_version"] == "celatim.crypto_transcript.rsa_pss_salt.v1"
        assert metadata["transcript_sha256"] == artifact["sha256"]
        assert metadata["transcript_size_bytes"] == artifact["size_bytes"]
        assert metadata["signature_count"] == transcript["signature_count"]
        assert metadata["verified_signature_count"] == transcript["signature_count"]
        assert metadata["recovered_symbol_count"] == transcript["signature_count"]
        assert metadata["honest_random_control"]["signature_count"] == 2
        assert metadata["honest_random_control"]["verified_signature_count"] == 2
        assert metadata["honest_random_control"]["recovered_salt_count"] == 2
        assert metadata["honest_random_control"]["distinct_recovered_salt_sha256_count"] == 2
        assert metadata["honest_random_control"]["embedded_payload_match_count"] == 0


def test_run_evidence_does_not_emit_artifacts_for_symbol_only_adapter(tmp_path):
    result = run_evidence(
        ScenarioConfig(
            scenario_id="symbol-artifact-run",
            mechanism_id="bgp-path-attr-flags",
            payload=b"offset represented",
            artifact_dir=str(tmp_path / "artifacts"),
        ),
        DATA,
    )
    doc = result.to_json()

    assert doc["covert"]["artifacts"] == []
    assert doc["benign_control"]["artifacts"] == []


def test_discover_scenarios_lists_checked_in_specs():
    infos = discover_scenarios(SCENARIOS)

    assert [info.scenario_id for info in infos] == [
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
    assert all(info.path.suffix == ".toml" for info in infos)
    assert all(info.evidence_tier == "real_pdu_packet_path" for info in infos[:4])
    assert all(info.privilege == "none" for info in infos[:4])
    assert all(info.expected_runtime_s == 5.0 for info in infos[:4])
    assert all(info.requires_tools == () for info in infos[:4])
    assert all(info.requires_extras == () for info in infos[:4])
    assert infos[4].evidence_tier == "real_daemon_path"
    assert infos[4].privilege == "cap_net_admin"
    assert infos[4].requires_tools == ("dig", "dnsmasq", "ip", "tcpdump")
    assert infos[4].requires_extras == ("packet",)
    assert infos[5].evidence_tier == "real_daemon_path"
    assert infos[5].privilege == "none"
    assert infos[5].requires_tools == ()
    assert infos[5].requires_extras == ("daemon",)
    assert infos[6].evidence_tier == "real_daemon_path"
    assert infos[6].privilege == "none"
    assert infos[6].requires_tools == ()
    assert infos[6].requires_extras == ("daemon",)
    assert infos[7].evidence_tier == "real_daemon_path"
    assert infos[7].privilege == "none"
    assert infos[7].requires_tools == ()
    assert infos[7].requires_extras == ("daemon",)
    assert infos[8].evidence_tier == "real_pdu_packet_path"
    assert infos[8].privilege == "root"
    assert infos[8].requires_tools == ("ip", "tcpdump")
    assert infos[8].requires_extras == ()
    assert all(info.evidence_tier == "real_crypto_path" for info in infos[9:11])
    assert all(info.privilege == "none" for info in infos[9:11])
    assert all(info.requires_tools == () for info in infos[9:11])
    assert all(info.requires_extras == ("crypto",) for info in infos[9:11])
    # paired real-codec message-carrier scenarios (positions 11..16)
    message_carriers = infos[11:]
    assert [info.scenario_id for info in message_carriers] == [
        "bgp-optional-transitive-scapy",
        "coap-tunnel-aiocoap",
        "dns-null-dnspython",
        "dns-txt-dnspython",
        "ssh-kexinit-paramiko",
        "websocket-websockets",
    ]
    assert all(info.privilege == "none" for info in message_carriers)
    assert all(info.requires_tools == () for info in message_carriers)
    assert [info.requires_extras for info in message_carriers] == [
        ("packet",),
        ("iot",),
        ("dns",),
        ("dns",),
        ("ssh",),
        ("realtime",),
    ]
    assert infos[11].evidence_tier == "real_pdu_packet_path"
    assert all(info.evidence_tier == "real_daemon_path" for info in infos[12:])


def test_build_scenario_execution_plan_summarizes_reviewer_run_shape():
    plan = build_scenario_execution_plan(SCENARIOS)
    doc = plan.to_json()

    assert doc["schema_version"] == SCENARIO_EXECUTION_PLAN_SCHEMA_VERSION
    assert doc["scenario_count"] == 17
    assert doc["scenario_ids"] == [
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
    assert doc["default_included_count"] == 4
    assert doc["manual_review_count"] == 13
    assert doc["privilege_counts"] == {"cap_net_admin": 1, "none": 15, "root": 1}
    assert doc["execution_mode_counts"] == {
        "default_non_privileged": 4,
        "non_privileged_with_dependencies": 11,
        "requires_linux_capability": 1,
        "requires_root": 1,
    }
    assert doc["expected_runtime_s_total"] == 115.0
    assert doc["required_tools"] == ["dig", "dnsmasq", "ip", "tcpdump"]
    assert doc["required_extras"] == [
        "crypto",
        "daemon",
        "dns",
        "iot",
        "packet",
        "realtime",
        "ssh",
    ]
    first = doc["scenarios"][0]
    assert first["execution_mode"] == "default_non_privileged"
    assert first["default_included"] is True
    assert first["skip_reason"] is None
    assert first["reviewer_command"][:5] == [
        "celatim",
        "scenario",
        "run",
        "--scenario-id",
        "http2-ping-opaque-real-pdu-smoke",
    ]
    assert "--pcap-dir" in first["reviewer_command"]
    manual = doc["scenarios"][4]
    assert manual["execution_mode"] == "requires_linux_capability"
    assert manual["default_included"] is False
    assert "--pcap-dir" not in manual["reviewer_command"]
    h2_manual = doc["scenarios"][5]
    assert h2_manual["execution_mode"] == "non_privileged_with_dependencies"
    assert h2_manual["default_included"] is False
    assert h2_manual["skip_reason"] == "requires extras daemon"
    http3_manual = doc["scenarios"][6]
    assert http3_manual["execution_mode"] == "non_privileged_with_dependencies"
    assert http3_manual["default_included"] is False
    assert http3_manual["skip_reason"] == "requires extras daemon"
    quic_manual = doc["scenarios"][7]
    assert quic_manual["execution_mode"] == "non_privileged_with_dependencies"
    assert quic_manual["default_included"] is False
    assert quic_manual["skip_reason"] == "requires extras daemon"
    root_manual = doc["scenarios"][8]
    assert root_manual["execution_mode"] == "requires_root"
    assert root_manual["default_included"] is False
    assert root_manual["skip_reason"] == "requires privilege root; requires tools ip, tcpdump"
    crypto_manual = doc["scenarios"][9]
    assert crypto_manual["execution_mode"] == "non_privileged_with_dependencies"
    assert crypto_manual["default_included"] is False
    assert crypto_manual["skip_reason"] == "requires extras crypto"
    rsa_crypto_manual = doc["scenarios"][10]
    assert rsa_crypto_manual["execution_mode"] == "non_privileged_with_dependencies"
    assert rsa_crypto_manual["default_included"] is False
    assert rsa_crypto_manual["skip_reason"] == "requires extras crypto"


def test_find_and_load_scenario_by_id():
    info = find_scenario(SCENARIOS, "quic-connection-id-real-pdu-smoke")
    config = load_scenario_by_id(SCENARIOS, "quic-connection-id-real-pdu-smoke")

    assert info.path == SCENARIOS / "quic-connection-id.toml"
    assert info.mechanism_id == "quic-connection-id"
    assert info.description == "Non-privileged QUIC connection-ID real-PDU smoke scenario."
    assert info.evidence_tier == "real_pdu_packet_path"
    assert info.privilege == "none"
    assert config.scenario_id == "quic-connection-id-real-pdu-smoke"
    assert config.mechanism_id == "quic-connection-id"


def test_load_scenario_supports_reviewer_metadata(tmp_path):
    spec = tmp_path / "scenario.toml"
    spec.write_text(
        "\n".join(
            [
                f'schema_version = "{SPEC_SCHEMA_VERSION}"',
                'scenario_id = "metadata-spec"',
                'mechanism_id = "http2-ping-opaque"',
                'description = "Privileged packet path"',
                'evidence_tier = "crafted_production_path"',
                'privilege = "cap_net_raw"',
                "expected_runtime_s = 12.5",
                'requires_tools = ["ip", "tcpdump"]',
                'requires_extras = ["packet"]',
                'payload_hex = "00 ff 80 41"',
            ]
        )
    )

    config = load_scenario(spec)

    assert config.description == "Privileged packet path"
    assert config.evidence_tier == "crafted_production_path"
    assert config.privilege == "cap_net_raw"
    assert config.expected_runtime_s == 12.5
    assert config.requires_tools == ("ip", "tcpdump")
    assert config.requires_extras == ("packet",)
    assert "crafted_production_path" in SCENARIO_EVIDENCE_TIERS
    assert "cap_net_raw" in SCENARIO_PRIVILEGE_LEVELS


def test_find_scenario_rejects_missing_id():
    with pytest.raises(ValueError, match="scenario id not found"):
        find_scenario(SCENARIOS, "missing-scenario")


def test_load_scenario_supports_relative_binary_payload_files(tmp_path):
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"\x00file\xff")
    spec = tmp_path / "scenario.toml"
    spec.write_text(
        "\n".join(
            [
                f'schema_version = "{SPEC_SCHEMA_VERSION}"',
                'scenario_id = "file-spec"',
                'mechanism_id = "quic-connection-id"',
                'payload_file = "payload.bin"',
                'control_hex = "00 01"',
            ]
        )
    )

    config = load_scenario(spec)

    assert config.payload == b"\x00file\xff"
    assert config.control_payload == b"\x00\x01"
    assert config.control_kind == "control_hex"


def test_load_scenario_supports_relative_file_transport_root(tmp_path):
    spec = tmp_path / "scenario.toml"
    spec.write_text(
        "\n".join(
            [
                f'schema_version = "{SPEC_SCHEMA_VERSION}"',
                'scenario_id = "file-transport-spec"',
                'mechanism_id = "http2-ping-opaque"',
                'payload_hex = "00 ff 80 41"',
                "[transport]",
                'kind = "file"',
                'root = "wire"',
            ]
        )
    )

    config = load_scenario(spec)

    assert config.transport.kind == "file"
    assert config.transport.root == str(tmp_path / "wire")


def test_load_scenario_supports_timed_memory_transport(tmp_path):
    spec = tmp_path / "scenario.toml"
    spec.write_text(
        "\n".join(
            [
                f'schema_version = "{SPEC_SCHEMA_VERSION}"',
                'scenario_id = "timed-transport-spec"',
                'mechanism_id = "http2-ping-opaque"',
                'payload_hex = "00 ff 80 41"',
                "[transport]",
                'kind = "timed_memory"',
            ]
        )
    )

    config = load_scenario(spec)

    assert config.transport.kind == "timed_memory"
    assert config.transport.root is None


def test_load_scenario_supports_relative_pcap_transport_root(tmp_path):
    spec = tmp_path / "scenario.toml"
    spec.write_text(
        "\n".join(
            [
                f'schema_version = "{SPEC_SCHEMA_VERSION}"',
                'scenario_id = "pcap-transport-spec"',
                'mechanism_id = "http2-ping-opaque"',
                'payload_hex = "00 ff 80 41"',
                "[transport]",
                'kind = "pcap"',
                'root = "pcaps"',
            ]
        )
    )

    config = load_scenario(spec)

    assert config.transport.kind == "pcap"
    assert config.transport.root == str(tmp_path / "pcaps")


def test_load_scenario_supports_afpacket_ipv4_transport(tmp_path):
    spec = tmp_path / "scenario.toml"
    spec.write_text(
        "\n".join(
            [
                f'schema_version = "{SPEC_SCHEMA_VERSION}"',
                'scenario_id = "afpacket-spec"',
                'mechanism_id = "http2-ping-opaque"',
                'payload_hex = "00 ff 80 41"',
                "[transport]",
                'kind = "afpacket_ipv4"',
                'sender_interface = "left"',
                'receiver_interface = "right"',
                'src_mac = "02:00:00:00:00:11"',
                'dst_mac = "02:00:00:00:00:22"',
                'src_ip = "192.0.2.1"',
                'dst_ip = "192.0.2.2"',
                "src_port = 41000",
                "dst_port = 8443",
                'protocol = "udp"',
                "timeout_s = 1.5",
                "expected_frames = 3",
                "require_expected_frames = false",
                'capture_pcap = "captures/live.pcap"',
                'capture_namespace = "rcvns"',
                'capture_interface = "tap0"',
                'capture_filter = ["udp", "port", "8443"]',
                "capture_snaplen = 4096",
                "capture_require_output = false",
            ]
        )
    )

    config = load_scenario(spec)

    assert config.transport.kind == "afpacket_ipv4"
    assert config.transport.sender_interface == "left"
    assert config.transport.receiver_interface == "right"
    assert config.transport.src_mac == "02:00:00:00:00:11"
    assert config.transport.dst_mac == "02:00:00:00:00:22"
    assert config.transport.src_ip == "192.0.2.1"
    assert config.transport.dst_ip == "192.0.2.2"
    assert config.transport.src_port == 41000
    assert config.transport.dst_port == 8443
    assert config.transport.protocol == "udp"
    assert config.transport.timeout_s == 1.5
    assert config.transport.expected_frames == 3
    assert config.transport.require_expected_frames is False
    assert config.transport.capture_pcap == str(tmp_path / "captures/live.pcap")
    assert config.transport.capture_namespace == "rcvns"
    assert config.transport.capture_interface == "tap0"
    assert config.transport.capture_filter == ("udp", "port", "8443")
    assert config.transport.capture_snaplen == 4096
    assert config.transport.capture_require_output is False


def test_load_scenario_supports_dns_edns0_padding_transport(tmp_path):
    spec = tmp_path / "scenario.toml"
    spec.write_text(
        "\n".join(
            [
                f'schema_version = "{SPEC_SCHEMA_VERSION}"',
                'scenario_id = "dns-edns-spec"',
                'mechanism_id = "edns0-padding"',
                'payload_message = "dns payload"',
                "[transport]",
                'kind = "dns_edns0_padding"',
                'src_ip = "192.0.2.1"',
                'dst_ip = "192.0.2.2"',
                "dst_port = 5353",
                "timeout_s = 1.5",
                'capture_pcap = "captures/dns.pcap"',
                'capture_namespace = "ignored"',
                'capture_interface = "tapdns"',
                'capture_filter = ["udp", "port", "5353"]',
                "capture_snaplen = 4096",
                "capture_require_output = false",
                'dns_sender_namespace = "leftns"',
                'dns_resolver_namespace = "rightns"',
                'dns_query_name = "covert.example"',
                'dns_answer_address = "192.0.2.2"',
                "dns_padding_optcode = 12",
                "dns_tries = 2",
                "dns_capture_start_delay_s = 0.0",
                "dns_require_answer = false",
            ]
        )
    )

    config = load_scenario(spec)

    assert config.transport.kind == "dns_edns0_padding"
    assert config.transport.src_ip == "192.0.2.1"
    assert config.transport.dst_ip == "192.0.2.2"
    assert config.transport.dst_port == 5353
    assert config.transport.timeout_s == 1.5
    assert config.transport.capture_pcap == str(tmp_path / "captures/dns.pcap")
    assert config.transport.capture_interface == "tapdns"
    assert config.transport.capture_filter == ("udp", "port", "5353")
    assert config.transport.capture_snaplen == 4096
    assert config.transport.capture_require_output is False
    assert config.transport.dns_sender_namespace == "leftns"
    assert config.transport.dns_resolver_namespace == "rightns"
    assert config.transport.dns_query_name == "covert.example"
    assert config.transport.dns_answer_address == "192.0.2.2"
    assert config.transport.dns_padding_optcode == 12
    assert config.transport.dns_tries == 2
    assert config.transport.dns_capture_start_delay_s == 0.0
    assert config.transport.dns_require_answer is False


def test_load_scenario_supports_crypto_ecdsa_nonce_transport(tmp_path):
    spec = tmp_path / "scenario.toml"
    spec.write_text(
        "\n".join(
            [
                f'schema_version = "{SPEC_SCHEMA_VERSION}"',
                'scenario_id = "ecdsa-spec"',
                'mechanism_id = "ecdsa-nonce"',
                'payload_message = "crypto payload"',
                "[transport]",
                'kind = "crypto_ecdsa_nonce"',
                'transcript_json = "transcripts/{scenario_id}-{case}.json"',
                'curve = "NIST521p"',
                'hash_name = "sha256"',
                "nonce_payload_bits = 256",
                "honest_random_control_signatures = 3",
                'message_prefix = "celatim/test-ecdsa"',
            ]
        )
    )

    config = load_scenario(spec)

    assert config.transport.kind == "crypto_ecdsa_nonce"
    assert config.transport.crypto_transcript_json == str(
        tmp_path / "transcripts/{scenario_id}-{case}.json"
    )
    assert config.transport.crypto_curve == "NIST521p"
    assert config.transport.crypto_hash_name == "sha256"
    assert config.transport.crypto_nonce_payload_bits == 256
    assert config.transport.crypto_honest_random_control_signatures == 3
    assert config.transport.crypto_message_prefix == "celatim/test-ecdsa"


def test_load_scenario_supports_http2_hyper_h2_transport(tmp_path):
    spec = tmp_path / "scenario.toml"
    spec.write_text(
        "\n".join(
            [
                f'schema_version = "{SPEC_SCHEMA_VERSION}"',
                'scenario_id = "http2-h2-spec"',
                'mechanism_id = "http2-ping-opaque"',
                'payload_message = "http2 payload"',
                "[transport]",
                'kind = "http2_hyper_h2"',
                'transcript_json = "transcripts/{scenario_id}-{case}.json"',
                "validate_ack = false",
            ]
        )
    )

    config = load_scenario(spec)

    assert config.transport.kind == "http2_hyper_h2"
    assert config.transport.http2_transcript_json == str(
        tmp_path / "transcripts/{scenario_id}-{case}.json"
    )
    assert config.transport.http2_validate_ack is False


def test_load_scenario_supports_http3_aioquic_settings_transport(tmp_path):
    spec = tmp_path / "scenario.toml"
    spec.write_text(
        "\n".join(
            [
                f'schema_version = "{SPEC_SCHEMA_VERSION}"',
                'scenario_id = "http3-aioquic-spec"',
                'mechanism_id = "http3-reserved-settings"',
                'payload_message = "http3 payload"',
                "[transport]",
                'kind = "http3_aioquic_reserved_settings"',
                'transcript_json = "transcripts/{scenario_id}-{case}.json"',
                "validate_receiver_settings = false",
            ]
        )
    )

    config = load_scenario(spec)

    assert config.transport.kind == "http3_aioquic_reserved_settings"
    assert config.transport.http3_transcript_json == str(
        tmp_path / "transcripts/{scenario_id}-{case}.json"
    )
    assert config.transport.http3_validate_receiver_settings is False


def test_load_scenario_supports_quic_aioquic_transport(tmp_path):
    spec = tmp_path / "scenario.toml"
    spec.write_text(
        "\n".join(
            [
                f'schema_version = "{SPEC_SCHEMA_VERSION}"',
                'scenario_id = "quic-aioquic-spec"',
                'mechanism_id = "quic-connection-id"',
                'payload_message = "quic payload"',
                "[transport]",
                'kind = "quic_aioquic_connection_id"',
                'transcript_json = "transcripts/{scenario_id}-{case}.json"',
                "validate_server_response = false",
            ]
        )
    )

    config = load_scenario(spec)

    assert config.transport.kind == "quic_aioquic_connection_id"
    assert config.transport.quic_transcript_json == str(
        tmp_path / "transcripts/{scenario_id}-{case}.json"
    )
    assert config.transport.quic_validate_server_response is False


def test_load_scenario_supports_crypto_rsa_pss_salt_transport(tmp_path):
    spec = tmp_path / "scenario.toml"
    spec.write_text(
        "\n".join(
            [
                f'schema_version = "{SPEC_SCHEMA_VERSION}"',
                'scenario_id = "rsa-pss-spec"',
                'mechanism_id = "rsa-pss-salt"',
                'payload_message = "crypto payload"',
                "[transport]",
                'kind = "crypto_rsa_pss_salt"',
                'transcript_json = "transcripts/{scenario_id}-{case}.json"',
                "key_bits = 3072",
                "public_exponent = 65537",
                'hash_name = "sha384"',
                'mgf_hash_name = "sha256"',
                "salt_payload_bits = 384",
                "honest_random_control_signatures = 3",
                'message_prefix = "celatim/test-rsa-pss"',
            ]
        )
    )

    config = load_scenario(spec)

    assert config.transport.kind == "crypto_rsa_pss_salt"
    assert config.transport.crypto_transcript_json == str(
        tmp_path / "transcripts/{scenario_id}-{case}.json"
    )
    assert config.transport.crypto_key_bits == 3072
    assert config.transport.crypto_public_exponent == 65537
    assert config.transport.crypto_hash_name == "sha384"
    assert config.transport.crypto_mgf_hash_name == "sha256"
    assert config.transport.crypto_salt_payload_bits == 384
    assert config.transport.crypto_honest_random_control_signatures == 3
    assert config.transport.crypto_message_prefix == "celatim/test-rsa-pss"


def test_load_scenario_supports_reliability_policy(tmp_path):
    spec = tmp_path / "scenario.toml"
    spec.write_text(
        "\n".join(
            [
                f'schema_version = "{SPEC_SCHEMA_VERSION}"',
                'scenario_id = "reliability-spec"',
                'mechanism_id = "http2-ping-opaque"',
                'payload_hex = "00 ff 80 41"',
                "[reliability]",
                "max_receive_attempts = 3",
                "retry_backoff_s = 0.01",
                "suppress_duplicate_chunks = false",
                "max_retransmissions = 2",
            ]
        )
    )

    config = load_scenario(spec)

    assert config.reliability is not None
    assert config.reliability.max_receive_attempts == 3
    assert config.reliability.retry_backoff_s == 0.01
    assert config.reliability.suppress_duplicate_chunks is False
    assert config.reliability.max_retransmissions == 2


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


def test_load_scenario_rejects_missing_payload(tmp_path):
    spec = tmp_path / "bad.toml"
    spec.write_text(
        "\n".join(
            [
                f'schema_version = "{SPEC_SCHEMA_VERSION}"',
                'scenario_id = "bad"',
                'mechanism_id = "http2-ping-opaque"',
            ]
        )
    )

    with pytest.raises(ValueError, match="payload_message"):
        load_scenario(spec)
