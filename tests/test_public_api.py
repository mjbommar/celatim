"""Public API coverage for the unified Celatim distribution."""

from __future__ import annotations

import hashlib
import json
import tomllib
from importlib.metadata import entry_points, version
from pathlib import Path
from typing import Any

import pytest

import celatim
import celatim.testbed.qemu as qemu_module
from celatim import (
    CelatimError,
    Channel,
    ChannelSession,
    CommandResult,
    ConfigurationError,
    ControlFailureError,
    DetectorRuleArtifact,
    DoctorResult,
    DocumentSummary,
    EcdsaNonceTranscriptReplayTransport,
    Framer,
    HostTapConfig,
    IdealWire,
    InMemoryTransport,
    LabTopologyResult,
    MechanismDetail,
    MechanismProfile,
    MechanismSummary,
    NetnsPairConfig,
    ObservedTimingCaseInput,
    PacingConfig,
    PayloadSource,
    PcapScrubReport,
    ProtocolRate,
    ProtocolThroughputEstimate,
    QemuGuestConfig,
    QemuTapPreflightReport,
    Receiver,
    ReceiveTimeoutError,
    RetransmitCapableTransport,
    RsaPssSaltTranscriptReplayTransport,
    ScenarioConfig,
    ScenarioExecutionPlan,
    ScenarioInventory,
    ScenarioSpecInfo,
    SchemaSummary,
    ScrubArtifact,
    Sender,
    SupportMatrixReport,
    TimeoutAwareTap,
    TransportConfig,
    TransportError,
    catalog_path,
    check_installation,
    codec_for,
    decode_pcap_payload,
    get_detector_rule_artifacts,
    get_detector_rule_manifest,
    get_detector_scrub_guidance_markdown,
    get_document_text,
    get_mechanism_detail,
    get_protocol_rates_markdown,
    get_protocol_throughput_estimates,
    get_qemu_tap_preflight_report,
    get_scenario,
    get_schema_text,
    get_support_matrix_markdown,
    get_support_matrix_report,
    get_testbed_requirements,
    get_windows_capture_guidance_markdown,
    list_documents,
    list_mechanism_summaries,
    list_protocol_rates,
    list_scenario_ids,
    list_scenarios,
    list_schemas,
    load_mechanisms,
    manage_netns_lab,
    netns_lab_config_to_json,
    payload_from_file,
    payload_from_hex,
    payload_from_text,
    plan_scenarios,
    random_payload,
    receive_payload,
    receive_scenario_payload,
    roundtrip_payload,
    roundtrip_scenario_payload,
    run_evidence,
    run_evidence_payload,
    run_observed_timing_sweep_payload,
    run_timing_sweep_payload,
    scrub_pcap_payload,
    send_payload,
    send_scenario_payload,
    write_detector_rule_files,
)
from celatim import (
    TestbedRequirementInventory as RequirementInventory,
)
from celatim import (
    TimingSweepReport as SweepReport,
)
from celatim import cli_endpoints as endpoint_cli_module
from celatim.cli import main as celatim_main
from celatim.transports import (
    AfpacketRoundtripResult,
    AioquicConnectionIdRoundtripResult,
    AioquicH3SettingsRoundtripResult,
    DnsEdnsPaddingReceiveResult,
    DnsEdnsPaddingRoundtripResult,
    DnsEdnsPaddingSendResult,
    DnsToolVersionRecord,
    FileTransport,
    HyperH2PingRoundtripResult,
    PacketPath,
    PcapTap,
)

PACKAGE_ROOT = Path(__file__).resolve().parents[1]


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


class RecordingRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], bool]] = []

    def run(self, argv, *, check=True):
        call = (tuple(argv), check)
        self.calls.append(call)
        return CommandResult(argv=tuple(argv), returncode=0, stdout="ok\n", stderr="")


def test_package_exposes_versioned_facade_metadata():
    assert version("celatim") == celatim.__version__
    assert celatim.__version__ == "0.2.5"
    assert any(
        entry_point.value == "celatim.cli:main"
        for entry_point in entry_points(group="console_scripts")
        if entry_point.name == "celatim"
    )


def test_package_docs_lock_install_profiles_and_release_workflow():
    pyproject = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text())
    readme = (PACKAGE_ROOT / "README.md").read_text()

    assert pyproject["project"]["name"] == "celatim"
    assert pyproject["project"]["requires-python"] == ">=3.14"
    assert pyproject["project"]["dependencies"] == []
    assert pyproject["project"]["optional-dependencies"] == {
        "transfer": ["cryptography>=46.0.3"],
        "packet": ["scapy>=2.6.1"],
        "crypto": ["cryptography>=46.0.3"],
        "daemon": ["aioquic>=1.3.0", "h2>=4.3.0"],
        "dns": ["dnspython>=2.8.0"],
        "ssh": ["paramiko>=3.5.0"],
        "iot": ["aiocoap>=0.4.12", "paho-mqtt>=2.1.0"],
        "realtime": ["websockets>=13.0"],
    }
    assert pyproject["project"]["scripts"]["celatim"] == "celatim.cli:main"
    assert pyproject["tool"]["uv"]["build-backend"]["module-name"] == ["celatim"]
    assert "## Install profiles" in readme
    assert "## Release workflow" in readme
    assert ".github/workflows/release.yml" in readme
    for target in (
        "make ci",
        "uv build --out-dir dist",
        "uvx twine check dist/*",
        "uvx check-wheel-contents dist/*.whl",
    ):
        assert target in readme


def test_package_loads_catalog_builds_codec_frames_and_decodes_payload():
    with catalog_path() as catalog:
        mechanisms = load_mechanisms(catalog)
    mechanism = {item.id: item for item in mechanisms}["http2-ping-opaque"]

    codec = codec_for(mechanism)
    framer = Framer(codec)
    payload = b"\x00package-local codec/frame\xff"
    symbols = framer.encode(payload)

    assert symbols
    assert framer.decode(symbols) == payload
    assert Channel(codec, IdealWire()).transmit(payload) == payload


def test_package_mechanism_discovery_api_exposes_adapter_metadata():
    summaries = list_mechanism_summaries(transport_kind="http2_hyper_h2")
    assert len(summaries) == 1

    summary = summaries[0]
    assert isinstance(summary, MechanismSummary)
    assert summary.id == "http2-ping-opaque"
    assert summary.analysis_population == "primary_rfc_carrier"
    assert summary.adapter_status == "real_pdu_fixture"
    assert "http2_hyper_h2" in summary.transport_kinds
    assert "http2-ping-opaque-hyper-h2" in summary.scenario_ids
    assert summary.to_json()["transport_kinds"] == list(summary.transport_kinds)

    detail = get_mechanism_detail("http2-ping-opaque")
    detail_json = detail.to_json()
    assert isinstance(detail, MechanismDetail)
    assert detail.mechanism_id == "http2-ping-opaque"
    assert detail_json["command"] == "mechanism show"
    assert detail_json["mechanism"]["id"] == "http2-ping-opaque"
    assert detail_json["mechanism"]["analysis_population"] == "primary_rfc_carrier"
    assert detail_json["mechanism"]["on_path_visibility"] == "deployment_dependent"
    assert detail_json["adapter"]["evidence"]["bucket"] == "real_pdu_packet_path"

    with pytest.raises(KeyError, match="unknown mechanism: no-such-mechanism"):
        get_mechanism_detail("no-such-mechanism")


def test_package_scenario_discovery_api_exposes_packaged_scenarios():
    inventory = list_scenarios()
    plan = plan_scenarios()
    all_ids = list_scenario_ids()
    default_ids = list_scenario_ids(default_included_only=True)
    scenario = get_scenario("http2-ping-opaque-real-pdu-smoke")

    assert isinstance(inventory, ScenarioInventory)
    assert isinstance(plan, ScenarioExecutionPlan)
    assert isinstance(inventory.scenarios[0], ScenarioSpecInfo)
    assert "http2-ping-opaque-real-pdu-smoke" in inventory.scenario_ids
    assert "edns0-padding-dnsmasq-dig-real-daemon" in all_ids
    assert "edns0-padding-dnsmasq-dig-real-daemon" not in default_ids
    assert scenario.scenario_id == "http2-ping-opaque-real-pdu-smoke"
    assert scenario.mechanism_id == "http2-ping-opaque"
    assert scenario.payload == b"\x00\xff\x80ABC"
    assert inventory.to_json()["scenario_count"] == len(all_ids)
    assert plan.to_json()["default_included_count"] == len(default_ids)

    with pytest.raises(ValueError, match="scenario id not found"):
        get_scenario("no-such-scenario")


def test_package_resource_facade_exposes_docs_and_support_matrix():
    documents = list_documents()
    schemas = list_schemas()
    rates = list_protocol_rates()
    estimates = get_protocol_throughput_estimates()
    rates_markdown = get_protocol_rates_markdown()
    detector_artifacts = get_detector_rule_artifacts()
    detector_manifest = get_detector_rule_manifest(output_dir="detector-rules")
    detector_guidance = get_detector_scrub_guidance_markdown()
    windows_guidance = get_windows_capture_guidance_markdown()
    report = get_support_matrix_report()
    markdown = get_support_matrix_markdown()

    assert DocumentSummary("api-guide") in documents
    assert SchemaSummary("evidence-run-v1") in schemas
    assert SchemaSummary("doctor-v1") in schemas
    assert get_document_text("api-guide").startswith("# celatim API Guide")
    assert '"celatim.evidence_run.v1"' in get_schema_text("evidence-run-v1")
    assert '"celatim.doctor.v1"' in get_schema_text("doctor-v1")
    assert len(rates) == 4
    assert all(isinstance(rate, ProtocolRate) for rate in rates)
    assert {rate.mechanism_id for rate in rates} >= {"dns-timing", "ipv6-flow-label"}
    assert estimates
    assert all(isinstance(estimate, ProtocolThroughputEstimate) for estimate in estimates)
    assert rates_markdown.startswith("# Protocol Rate Assumptions")
    assert "structural_upper_bound_not_measured_goodput" in rates_markdown
    assert "payload_rate_bps" not in rates_markdown
    assert detector_artifacts
    assert all(isinstance(artifact, DetectorRuleArtifact) for artifact in detector_artifacts)
    assert {artifact.filename for artifact in detector_artifacts} >= {
        "detector-rules.md",
        "detector-rules.nft",
        "detector-stateful-plan.md",
    }
    assert detector_manifest["schema_version"] == "celatim.detector_rules.v1"
    assert detector_manifest["output_dir"] == "detector-rules"
    assert detector_manifest["claim_status"] == (
        "generated_not_executed_no_false_positive_estimate"
    )
    assert detector_guidance.startswith("# Detector and Scrub Guidance")
    assert "channel implementation code" in detector_guidance
    assert windows_guidance.startswith("# Windows pktmon / ETW Capture Guidance")
    assert "capture_guidance_not_header_bit_filter" in windows_guidance
    assert isinstance(report, SupportMatrixReport)
    assert report.schema_version == "celatim.support_matrix.v1"
    assert report.mechanism_count > 0
    assert report.to_json()["rows"]
    assert markdown.startswith("# Evidence Support Matrix")

    with pytest.raises(ValueError, match="unknown doc"):
        get_document_text("no-such-doc")
    with pytest.raises(ValueError, match="unknown schema"):
        get_schema_text("no-such-schema")


def test_package_resource_facade_writes_detector_rule_artifacts(tmp_path):
    paths = write_detector_rule_files(tmp_path / "rules")

    assert {path.name for path in paths} >= {
        "detector-rules.md",
        "detector-rules.nft",
        "detector-stateful-plan.md",
        "detector-stateful.suricata.rules",
    }
    assert "# Detector Rule Appendix" in (tmp_path / "rules" / "detector-rules.md").read_text()
    assert (
        "# Stateful Detector Plan" in (tmp_path / "rules" / "detector-stateful-plan.md").read_text()
    )


def test_package_testbed_facade_exposes_requirements_and_qemu_preflight(
    tmp_path,
    monkeypatch,
):
    disk = tmp_path / "receiver.qcow2"
    disk.touch()
    monkeypatch.setattr(qemu_module.shutil, "which", lambda binary: f"/fake/{binary}")

    inventory = get_testbed_requirements(("netns-afpacket", "qemu-cross-stack"))
    report = get_qemu_tap_preflight_report(
        QemuGuestConfig(disk_image=disk, enable_kvm=False),
        HostTapConfig(tap_name="tap-private", host_ipv4_cidr=None),
    )
    inventory_doc = inventory.to_json()
    report_doc = report.to_json()
    checks = {check["check_id"]: check for check in report_doc["checks"]}

    assert isinstance(inventory, RequirementInventory)
    assert isinstance(report, QemuTapPreflightReport)
    assert inventory_doc["schema_version"] == "celatim.testbed_requirements.v1"
    assert inventory_doc["profile_ids"] == ["netns-afpacket", "qemu-cross-stack"]
    assert inventory_doc["required_privileges"] == [
        "cap_net_admin",
        "cap_net_raw",
        "kvm",
    ]
    assert report_doc["schema_version"] == "celatim.qemu_tap_preflight.v1"
    assert report_doc["claim_status"] == "preflight_only_no_vm_started"
    assert report_doc["ok"] is True
    assert checks["kvm_device"]["status"] == "skip"
    assert report_doc["tap_config"]["tap_name"] == "tap-private"
    assert "-enable-kvm" not in report_doc["qemu_argv"]


def test_package_timing_sweep_facade_runs_local_and_observed_reports():
    clock = JitterClock()
    payload = PayloadSource.hex("00 ff 80 41")
    base_pacing = PacingConfig(unit_rate_hz=100.0, jitter_sample_window=4)
    local = run_timing_sweep_payload(
        "dns-timing",
        payload,
        quanta_s=(0.01, 0.005),
        base_pacing=base_pacing,
        run_id="pkg-sweep",
        clock=clock,
        sleeper=clock.sleep,
    )
    profile = MechanismProfile.from_catalog("dns-timing")
    payload_bytes = payload.read_bytes()
    baseline_payload = bytes(len(payload_bytes))
    baseline_count = _carrier_count(profile, baseline_payload, base_pacing)
    trial_count = _carrier_count(profile, payload_bytes, base_pacing)
    observed = run_observed_timing_sweep_payload(
        profile,
        payload,
        baseline=ObservedTimingCaseInput(
            observed_offsets_s=_offsets(baseline_count),
            recovered_payload=baseline_payload,
            session_id="pkg-observed:baseline",
        ),
        trials=[
            ObservedTimingCaseInput(
                observed_offsets_s=_offsets(trial_count),
                recovered_payload=payload_bytes,
                quantum_s=0.01,
                session_id="pkg-observed:q1",
            )
        ],
        base_pacing=base_pacing,
        baseline_payload=baseline_payload,
        run_id="pkg-observed",
        path_kind="dns_netns_pcap",
        path_metadata={"tap": "package-test"},
    )
    local_doc = local.to_json()
    observed_doc = observed.to_json()

    assert isinstance(local, SweepReport)
    assert isinstance(observed, SweepReport)
    assert local_doc["schema_version"] == "celatim.timing_sweep.v1"
    assert local_doc["run_id"] == "pkg-sweep"
    assert local_doc["path_kind"] == "timed_memory"
    assert local_doc["claim_status"] == "local_timed_memory_scheme_demonstration_not_capacity"
    assert [trial["quantum_s"] for trial in local_doc["trials"]] == [0.01, 0.005]
    assert observed_doc["run_id"] == "pkg-observed"
    assert observed_doc["path_kind"] == "dns_netns_pcap"
    assert observed_doc["path_metadata"] == {"tap": "package-test"}
    assert observed_doc["baseline"]["carrier_units"] == baseline_count
    assert observed_doc["trials"][0]["carrier_units"] == trial_count
    assert observed_doc["ok"] is True


def test_package_check_installation_facade_runs_doctor(tmp_path):
    result = check_installation(
        artifact_dir=tmp_path / "artifacts",
        optional_tools=(),
    )
    document = result.to_json()

    assert isinstance(result, DoctorResult)
    assert result.ok is True
    assert document["schema_version"] == "celatim.doctor.v1"
    assert {check["check_id"] for check in document["checks"]} == {
        "environment",
        "catalog",
        "schemas",
        "scenarios",
        "artifact_dir",
    }
    assert all(check["status"] == "pass" for check in document["checks"])


def test_package_facade_exports_session_api_and_version():
    profile = MechanismProfile.from_catalog("http2-ping-opaque")
    result = ChannelSession(profile, InMemoryTransport()).run_roundtrip(
        b"\x00facade\xff",
        session_id="unified-api",
    )

    assert result.payload == b"\x00facade\xff"
    assert result.evidence.mechanism_id == "http2-ping-opaque"
    assert ReceiveTimeoutError.__name__ == "ReceiveTimeoutError"
    assert isinstance(ChannelSession(profile, InMemoryTransport()), Sender)
    assert isinstance(ChannelSession(profile, InMemoryTransport()), Receiver)
    assert RetransmitCapableTransport.__name__ == "RetransmitCapableTransport"
    assert TimeoutAwareTap.__name__ == "TimeoutAwareTap"


def test_package_payload_source_helpers_load_endpoint_bytes(tmp_path):
    payload_path = tmp_path / "payload.bin"
    payload_path.write_bytes(b"\x00file\xffpayload\x80")

    assert payload_from_text("plain text") == b"plain text"
    assert payload_from_hex("00 ff 80 41") == b"\x00\xff\x80A"
    assert payload_from_file(payload_path) == b"\x00file\xffpayload\x80"
    random_bytes = random_payload(12)
    assert isinstance(random_bytes, bytes)
    assert len(random_bytes) == 12
    with pytest.raises(ConfigurationError, match="random payload length must be > 0"):
        random_payload(0)


def test_package_payload_source_object_loads_endpoint_bytes(tmp_path):
    payload_path = tmp_path / "payload.bin"
    payload_path.write_bytes(b"\x00source-file\xff")

    assert PayloadSource.text("plain text").read_bytes() == b"plain text"
    assert PayloadSource.hex("00 ff 80 41").read_bytes() == b"\x00\xff\x80A"
    assert PayloadSource.file(payload_path).read_bytes() == b"\x00source-file\xff"
    assert len(PayloadSource.random(8).read_bytes()) == 8
    assert PayloadSource.file(payload_path).to_json() == {
        "kind": "file",
        "value": str(payload_path),
        "encoding": None,
    }

    with pytest.raises(ConfigurationError, match="unknown payload source kind"):
        PayloadSource("unknown", "payload").read_bytes()


def test_package_endpoint_roundtrip_and_result_json():
    profile = MechanismProfile.from_catalog("http2-ping-opaque")
    result = roundtrip_payload(profile, b"\x00Celatim package test\xff")
    document = result.to_json()

    assert result.ok is True
    assert result.payload == b"\x00Celatim package test\xff"
    assert document["command"] == "roundtrip_payload"
    assert document["ok"] is True
    assert document["received"]["recovered_hex"] == b"\x00Celatim package test\xff".hex()
    assert "pcap_artifact" in {path.kind.value for path in profile.adapter.paths}


def test_package_send_receive_payload_helpers_roundtrip_envelope():
    sent = send_payload(
        "http2-ping-opaque",
        PayloadSource.hex("00 68 65 6c 70 65 72 ff"),
        session_id="helper-envelope",
    )
    received = receive_payload(
        sent.envelope, expected_payload=PayloadSource.hex("00 68 65 6c 70 65 72 ff")
    )

    assert sent.session_id == "helper-envelope"
    assert sent.envelope["command"] == "send"
    assert sent.envelope["transport"] == "memory"
    assert received.payload == b"\x00helper\xff"
    assert received.transport_kind == "envelope"
    assert received.carrier_input_used is True
    assert received.parser_validated is True
    assert received.carrier_units_with_bytes == sent.envelope["carrier_units_with_bytes"]
    assert received.expected_payload == b"\x00helper\xff"
    assert received.to_json()["expected_matches"] is True

    with pytest.raises(ControlFailureError, match="expected payload mismatch"):
        receive_payload(sent.envelope, expected_payload=PayloadSource.text("wrong"))


def test_package_endpoint_helpers_accept_payload_source_inputs(tmp_path):
    payload_path = tmp_path / "payload.bin"
    payload_path.write_bytes(b"\x00file-source\xff")

    text_result = roundtrip_payload(
        "http2-ping-opaque",
        PayloadSource.text("text-source"),
    )
    file_result = roundtrip_payload(
        "http2-ping-opaque",
        PayloadSource.file(payload_path),
        transport_dir=tmp_path / "wire",
    )
    random_result = roundtrip_payload(
        "http2-ping-opaque",
        PayloadSource.random(10),
    )
    expected_result = roundtrip_payload(
        "http2-ping-opaque",
        PayloadSource.hex("00 ff 80 41"),
        expected_payload=b"\x00\xff\x80A",
    )

    assert text_result.payload == b"text-source"
    assert file_result.payload == b"\x00file-source\xff"
    assert file_result.sent.transport_record is not None
    assert file_result.sent.transport_record.is_file()
    assert random_result.ok is True
    assert len(random_result.payload) == 10
    assert expected_result.expected_matches is True
    assert expected_result.to_json()["expected_payload_len"] == 4

    with pytest.raises(ControlFailureError, match="expected payload mismatch"):
        roundtrip_payload(
            "http2-ping-opaque",
            PayloadSource.hex("00 ff 80 41"),
            expected_payload=PayloadSource.hex("00 ff 80 42"),
        )


def test_package_scenario_endpoint_helpers_use_packaged_defaults():
    result = roundtrip_scenario_payload("http2-ping-opaque-real-pdu-smoke")
    document = result.to_json()

    assert result.ok is True
    assert result.sent.session_id == "http2-ping-opaque-real-pdu-smoke"
    assert result.sent.mechanism_id == "http2-ping-opaque"
    assert result.sent.transport_kind == "memory"
    assert result.payload == b"\x00\xff\x80ABC"
    assert document["matches_sent_payload"] is True


def test_package_scenario_endpoint_helpers_apply_overrides(tmp_path):
    result = roundtrip_scenario_payload(
        "http2-ping-opaque-real-pdu-smoke",
        payload=PayloadSource.hex("00 ff 80 42"),
        pcap_dir=tmp_path / "pcaps",
        expected_payload=PayloadSource.hex("00 ff 80 42"),
    )

    assert result.ok is True
    assert result.expected_matches is True
    assert result.payload == b"\x00\xff\x80B"
    assert result.sent.session_id == "http2-ping-opaque-real-pdu-smoke"
    assert result.sent.transport_kind == "pcap"
    assert result.sent.transport_record == (
        tmp_path / "pcaps" / "http2-ping-opaque-real-pdu-smoke.pcap"
    )


def test_package_scenario_endpoint_send_receive_file_transport(tmp_path):
    sent = send_scenario_payload(
        "http2-ping-opaque-real-pdu-smoke",
        payload=PayloadSource.text("scenario-file"),
        transport_dir=tmp_path / "wire",
    )
    received = receive_scenario_payload(
        "http2-ping-opaque-real-pdu-smoke",
        transport_dir=tmp_path / "wire",
        expected_payload=PayloadSource.text("scenario-file"),
    )

    assert sent.session_id == "http2-ping-opaque-real-pdu-smoke"
    assert sent.transport_kind == "file"
    assert sent.transport_record == tmp_path / "wire" / "http2-ping-opaque-real-pdu-smoke.json"
    assert sent.transport_record is not None
    assert sent.transport_record.is_file()
    assert received.payload == b"scenario-file"
    assert received.expected_payload == b"scenario-file"
    assert received.transport_kind == "file"


def test_package_scenario_endpoint_helpers_reject_unsupported_transport():
    with pytest.raises(ConfigurationError, match="do not support transport 'http2_hyper_h2'"):
        roundtrip_scenario_payload("http2-ping-opaque-hyper-h2")


def test_package_helper_results_are_json_serializable(tmp_path):
    sent = send_payload(
        "http2-ping-opaque",
        b"\x00json-helper\xff",
        session_id="helper-json-file",
        transport_dir=tmp_path / "wire",
    )
    received = receive_payload(sent)
    roundtrip = roundtrip_payload(
        "http2-ping-opaque",
        b"\x00json-roundtrip\xff",
        session_id="helper-json-pcap",
        pcap_dir=tmp_path / "pcaps",
    )

    sent_doc = sent.to_json()
    received_doc = received.to_json()
    roundtrip_doc = roundtrip.to_json()
    serialized = json.loads(
        json.dumps(
            {
                "sent": sent_doc,
                "received": received_doc,
                "roundtrip": roundtrip_doc,
            },
            sort_keys=True,
        )
    )

    assert sent_doc["command"] == "send_payload"
    assert sent_doc["transport"] == "file"
    assert sent_doc["transport_record"] == str(tmp_path / "wire" / "helper-json-file.json")
    assert sent_doc["receipt"]["adapter_status"] == sent.receipt.adapter_status.value
    assert received_doc["command"] == "receive_payload"
    assert received_doc["transport"] == "file"
    assert received_doc["carrier_input_used"] is True
    assert received_doc["parser_validated"] is True
    assert received_doc["evidence"]["ok"] is True
    assert roundtrip_doc["command"] == "roundtrip_payload"
    assert roundtrip_doc["transport"] == "pcap"
    assert roundtrip_doc["transport_record"] == str(tmp_path / "pcaps" / "helper-json-pcap.pcap")
    assert roundtrip_doc["matches_sent_payload"] is True
    assert roundtrip_doc["ok"] is True
    assert serialized["roundtrip"]["received"]["recovered_hex"] == b"\x00json-roundtrip\xff".hex()


def test_package_roundtrip_payload_helper_uses_file_transport(tmp_path):
    result = roundtrip_payload(
        "http2-ping-opaque",
        b"\x00file-helper\xff",
        session_id="helper-file",
        transport_dir=tmp_path / "wire",
    )

    assert result.ok is True
    assert result.payload == b"\x00file-helper\xff"
    assert result.sent.transport_kind == "file"
    assert result.received.transport_kind == "file"
    assert result.sent.transport_record == tmp_path / "wire" / "helper-file.json"
    assert result.received.transport_record == result.sent.transport_record
    assert result.sent.transport_record is not None
    assert result.sent.transport_record.is_file()


def test_package_roundtrip_payload_helper_uses_pcap_transport(tmp_path):
    result = roundtrip_payload(
        "http2-ping-opaque",
        b"\x00pcap-helper\xff",
        session_id="helper-pcap",
        pcap_dir=tmp_path / "pcaps",
    )

    assert result.ok is True
    assert result.payload == b"\x00pcap-helper\xff"
    assert result.sent.transport_kind == "pcap"
    assert result.received.transport_kind == "pcap"
    assert result.sent.transport_record == tmp_path / "pcaps" / "helper-pcap.pcap"
    assert result.sent.transport_record is not None
    assert result.sent.transport_record.is_file()


def test_package_decode_pcap_payload_helper_reads_transport_artifact(tmp_path):
    sent = send_payload(
        "http2-ping-opaque",
        PayloadSource.hex("00 ff 80 41"),
        session_id="helper-pcap-decode",
        pcap_dir=tmp_path / "pcaps",
    )
    assert sent.transport_record is not None

    report = decode_pcap_payload(
        "http2-ping-opaque",
        sent.transport_record,
        expected_payload=PayloadSource.hex("00 ff 80 41"),
        session_id="helper-pcap-decode",
        tshark_path="tshark-definitely-not-installed",
    )
    document = report.to_json()

    assert report.ok is True
    assert report.matches_expected is True
    assert report.recovered_payload == b"\x00\xff\x80A"
    assert document["schema_version"] == "celatim.pcap_decode.v1"
    assert document["pcap"]["path"] == str(sent.transport_record)
    assert document["pcap"]["packet_count"] == document["carrier_units"]
    assert document["parser_validated"] is True
    assert document["parser_provenance"][0]["result"] == "tool_missing"


def test_package_scrub_pcap_payload_helper_writes_scrubbed_artifact(tmp_path):
    sent = send_payload(
        "tcp-reserved-bits",
        PayloadSource.hex("0f"),
        session_id="helper-pcap-scrub",
        pcap_dir=tmp_path / "pcaps",
    )
    assert sent.transport_record is not None
    scrubbed_pcap = tmp_path / "scrubbed.pcap"

    report = scrub_pcap_payload(
        "tcp-reserved-bits",
        sent.transport_record,
        scrubbed_pcap,
    )
    document = report.to_json()

    assert isinstance(report, PcapScrubReport)
    assert isinstance(report.output, ScrubArtifact)
    assert report.ok is True
    assert report.after_matched_unit_count == 0
    assert report.scrubbed_unit_count == report.before_matched_unit_count
    assert document["schema_version"] == "celatim.scrub_report.v1"
    assert document["mechanism_id"] == "tcp-reserved-bits"
    assert document["claim_status"] == ("same_code_offline_pcap_scrub_smoke_not_live_middlebox")
    assert document["before_matched_unit_count"] > 0
    assert document["output"]["path"] == str(scrubbed_pcap)
    assert document["output"]["sha256"] == hashlib.sha256(scrubbed_pcap.read_bytes()).hexdigest()


def test_package_send_payload_rejects_multiple_transport_choices(tmp_path):
    try:
        send_payload(
            "http2-ping-opaque",
            b"conflict",
            transport_dir=tmp_path / "wire",
            pcap_dir=tmp_path / "pcaps",
        )
    except ConfigurationError as exc:
        assert "select only one transport" in str(exc)
    else:
        raise AssertionError("expected ConfigurationError")


def test_package_exports_evidence_run_api(tmp_path):
    result = run_evidence(
        ScenarioConfig(
            scenario_id="unified-evidence",
            mechanism_id="http2-ping-opaque",
            payload=b"\x00\xffpayload",
            control_payload=b"control",
            control_kind="control_message",
            transport=TransportConfig(kind="file", root=str(tmp_path / "wire")),
        )
    )

    doc = result.to_json()
    assert result.ok is True
    assert doc["covert"]["transport_kind"] == "file"
    assert bytes.fromhex(doc["covert"]["recovered_hex"]) == b"\x00\xffpayload"


def test_package_evidence_helper_runs_ad_hoc_payload(tmp_path):
    result = run_evidence_payload(
        scenario_id="unified-evidence-helper",
        mechanism="http2-ping-opaque",
        payload=PayloadSource.hex("00 ff 80 41"),
        control_payload=PayloadSource.text("benign"),
        transport_dir=tmp_path / "wire",
        log_dir=tmp_path / "logs",
        run_id="helper-ad-hoc",
    )
    doc = result.to_json()

    assert result.ok is True
    assert result.run_id == "helper-ad-hoc"
    assert result.control_kind == "control_message"
    assert doc["covert"]["transport_kind"] == "file"
    assert doc["covert"]["recovered_hex"] == "00ff8041"
    assert doc["benign_control"]["recovered_hex"] == b"benign".hex()
    assert doc["run_log"]["path"].endswith("helper-ad-hoc.jsonl")


def test_package_evidence_helper_loads_scenario_and_applies_overrides(tmp_path):
    result = run_evidence_payload(
        "http2-ping-opaque-real-pdu-smoke",
        payload=PayloadSource.hex("00 ff 80 42"),
        control_payload=PayloadSource.random(6),
        pcap_dir=tmp_path / "pcaps",
        artifact_dir=tmp_path / "carriers",
        log_dir=tmp_path / "logs",
        run_id="helper-scenario",
    )
    doc = result.to_json()

    assert result.ok is True
    assert result.scenario_id == "http2-ping-opaque-real-pdu-smoke"
    assert result.control_kind == "control_random_bytes"
    assert doc["covert"]["transport_kind"] == "pcap"
    assert doc["covert"]["recovered_hex"] == "00ff8042"
    assert doc["benign_control"]["evidence"]["payload_len"] == 6

    with pytest.raises(ConfigurationError, match="does not match scenario mechanism"):
        run_evidence_payload(
            "http2-ping-opaque-real-pdu-smoke",
            mechanism="tcp-reserved-bits",
        )


def test_package_exposes_transport_aliases_and_errors(tmp_path):
    packet_path = PacketPath(src_ip="192.0.2.10", dst_ip="192.0.2.20")
    pcap_tap = PcapTap(namespace="receiver", interface="veth-r", output=tmp_path / "tap.pcap")

    assert packet_path.src_ip == "192.0.2.10"
    assert packet_path.dst_ip == "192.0.2.20"
    assert pcap_tap.output == tmp_path / "tap.pcap"
    assert issubclass(TransportError, CelatimError)
    assert EcdsaNonceTranscriptReplayTransport.__name__ == "EcdsaNonceTranscriptReplayTransport"
    assert RsaPssSaltTranscriptReplayTransport.__name__ == "RsaPssSaltTranscriptReplayTransport"


def test_package_submodule_exports_existing_transport_classes(tmp_path):
    profile = MechanismProfile.from_catalog("http2-ping-opaque")
    transport = FileTransport(profile, tmp_path / "wire")

    receipt = ChannelSession(profile, transport).send_message(
        b"\x00\xffvia unified transport",
        session_id="unified-file",
    )

    assert transport.path_for(receipt.session_id).is_file()


def test_package_endpoint_cli_roundtrip_writes_json(tmp_path):
    output = tmp_path / "roundtrip.json"

    assert (
        celatim_main(
            [
                "roundtrip",
                "--mechanism",
                "http2-ping-opaque",
                "--hex",
                "00 ff 80 41",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    document = json.loads(output.read_text())

    assert document["command"] == "roundtrip"
    assert document["mechanism_id"] == "http2-ping-opaque"
    assert document["matches"] is True
    assert document["evidence"]["ok"] is True
    assert document["recovered_hex"] == "00ff8041"


def test_package_endpoint_cli_send_recv_writes_json(tmp_path):
    sent = tmp_path / "send.json"
    received = tmp_path / "recv.json"

    assert (
        celatim_main(
            [
                "send",
                "--mechanism",
                "http2-ping-opaque",
                "--session-id",
                "pkg-cli-envelope",
                "--hex",
                "00 ff 80 41",
                "--output",
                str(sent),
            ]
        )
        == 0
    )
    sent_document = json.loads(sent.read_text())
    assert sent_document["command"] == "send"
    assert sent_document["session_id"] == "pkg-cli-envelope"
    assert sent_document["mechanism_id"] == "http2-ping-opaque"
    assert sent_document["payload_sha256"] == (
        "3507b01e644277ad3cd10dadd6e33cb801151e62e3cb899a67409ef701d6079c"
    )

    assert celatim_main(["recv", "--input", str(sent), "--output", str(received)]) == 0
    received_document = json.loads(received.read_text())

    assert received_document["command"] == "recv"
    assert received_document["session_id"] == "pkg-cli-envelope"
    assert received_document["mechanism_id"] == "http2-ping-opaque"
    assert received_document["recovered_hex"] == "00ff8041"
    assert received_document["evidence"]["ok"] is True
    assert received_document["carrier_input_used"] is True


def test_package_endpoint_cli_recv_enforces_expected_payload(tmp_path):
    sent = tmp_path / "send.json"
    received = tmp_path / "recv.json"

    assert (
        celatim_main(
            [
                "send",
                "--mechanism",
                "http2-ping-opaque",
                "--session-id",
                "pkg-cli-expect",
                "--hex",
                "00 ff 80 41",
                "--output",
                str(sent),
            ]
        )
        == 0
    )
    assert (
        celatim_main(
            [
                "recv",
                "--input",
                str(sent),
                "--expect-hex",
                "00 ff 80 41",
                "--output",
                str(received),
            ]
        )
        == 0
    )
    document = json.loads(received.read_text())

    assert document["recovered_hex"] == "00ff8041"
    assert document["expected_payload_len"] == 4
    assert document["expected_payload_sha256"] == (
        "3507b01e644277ad3cd10dadd6e33cb801151e62e3cb899a67409ef701d6079c"
    )
    assert document["expected_matches"] is True

    with pytest.raises(ControlFailureError, match="expected payload mismatch"):
        celatim_main(
            [
                "recv",
                "--input",
                str(sent),
                "--expect-hex",
                "00 ff 80 42",
            ]
        )


def test_package_endpoint_cli_roundtrip_enforces_expected_file_payload(tmp_path):
    expected = tmp_path / "expected.bin"
    expected.write_bytes(b"\x00\xff\x80A")
    output = tmp_path / "roundtrip-expect.json"

    assert (
        celatim_main(
            [
                "roundtrip",
                "--mechanism",
                "http2-ping-opaque",
                "--hex",
                "00 ff 80 41",
                "--expect-file",
                str(expected),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    document = json.loads(output.read_text())

    assert document["matches"] is True
    assert document["expected_payload_len"] == 4
    assert document["expected_matches"] is True


def test_package_endpoint_cli_file_transport_recv_writes_parser_metadata(tmp_path):
    transport_dir = tmp_path / "wire"
    received = tmp_path / "file-recv.json"

    assert (
        celatim_main(
            [
                "send",
                "--mechanism",
                "http2-ping-opaque",
                "--session-id",
                "pkg-cli-file",
                "--hex",
                "00 ff 80 41",
                "--transport-dir",
                str(transport_dir),
            ]
        )
        == 0
    )
    assert (
        celatim_main(
            [
                "recv",
                "--mechanism",
                "http2-ping-opaque",
                "--session-id",
                "pkg-cli-file",
                "--transport-dir",
                str(transport_dir),
                "--output",
                str(received),
            ]
        )
        == 0
    )
    document = json.loads(received.read_text())

    assert document["command"] == "recv"
    assert document["transport"] == "file"
    assert document["recovered_hex"] == "00ff8041"
    assert document["parser_validated"] is True
    assert document["carrier_units_with_bytes"] > 0
    assert document["evidence"]["ok"] is True


def test_package_endpoint_cli_send_recv_uses_scenario_defaults(tmp_path):
    transport_dir = tmp_path / "wire"
    sent = tmp_path / "scenario-send.json"
    received = tmp_path / "scenario-recv.json"

    assert (
        celatim_main(
            [
                "send",
                "--scenario-id",
                "http2-ping-opaque-real-pdu-smoke",
                "--transport-dir",
                str(transport_dir),
                "--output",
                str(sent),
            ]
        )
        == 0
    )
    assert (
        celatim_main(
            [
                "recv",
                "--scenario-id",
                "http2-ping-opaque-real-pdu-smoke",
                "--transport-dir",
                str(transport_dir),
                "--output",
                str(received),
            ]
        )
        == 0
    )
    sent_document = json.loads(sent.read_text())
    received_document = json.loads(received.read_text())

    assert sent_document["scenario_id"] == "http2-ping-opaque-real-pdu-smoke"
    assert sent_document["session_id"] == "http2-ping-opaque-real-pdu-smoke"
    assert sent_document["mechanism_id"] == "http2-ping-opaque"
    assert sent_document["payload_sha256"] == (
        "a5c487f4182e1d621fa1a896443c19b6118cd7ed60f92b7e6d7c7413c93fc4a0"
    )
    assert received_document["scenario_id"] == "http2-ping-opaque-real-pdu-smoke"
    assert received_document["transport"] == "file"
    assert received_document["session_id"] == "http2-ping-opaque-real-pdu-smoke"
    assert received_document["mechanism_id"] == "http2-ping-opaque"
    assert received_document["recovered_hex"] == "00ff80414243"
    assert received_document["parser_validated"] is True
    assert received_document["evidence"]["ok"] is True


def test_package_endpoint_cli_roundtrip_uses_scenario_defaults_and_payload_override(tmp_path):
    output = tmp_path / "scenario-roundtrip.json"

    assert (
        celatim_main(
            [
                "roundtrip",
                "--scenario-id",
                "http2-ping-opaque-real-pdu-smoke",
                "--hex",
                "00 ff 80 42",
                "--pcap-dir",
                str(tmp_path / "pcaps"),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    document = json.loads(output.read_text())

    assert document["scenario_id"] == "http2-ping-opaque-real-pdu-smoke"
    assert document["session_id"] == "http2-ping-opaque-real-pdu-smoke"
    assert document["mechanism_id"] == "http2-ping-opaque"
    assert document["transport"] == "pcap"
    assert document["recovered_hex"] == "00ff8042"
    assert document["matches"] is True
    assert document["evidence"]["ok"] is True


def test_package_endpoint_cli_pcap_decode_writes_json(tmp_path):
    sent = send_payload(
        "http2-ping-opaque",
        PayloadSource.hex("00 ff 80 41"),
        session_id="pkg-cli-pcap-decode",
        pcap_dir=tmp_path / "pcaps",
    )
    assert sent.transport_record is not None
    output = tmp_path / "pcap-decode.json"

    assert (
        celatim_main(
            [
                "pcap",
                "decode",
                "--mechanism",
                "http2-ping-opaque",
                "--pcap",
                str(sent.transport_record),
                "--session-id",
                "pkg-cli-pcap-decode",
                "--tshark-binary",
                "tshark-definitely-not-installed",
                "--expect-hex",
                "00 ff 80 41",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    document = json.loads(output.read_text())

    assert document["schema_version"] == "celatim.pcap_decode.v1"
    assert document["mechanism_id"] == "http2-ping-opaque"
    assert document["session_id"] == "pkg-cli-pcap-decode"
    assert document["recovered_hex"] == "00ff8041"
    assert document["matches_expected"] is True
    assert document["ok"] is True
    assert document["parser_provenance"][0]["result"] == "tool_missing"


def test_package_endpoint_cli_scrub_pcap_writes_json(tmp_path):
    sent = send_payload(
        "tcp-reserved-bits",
        PayloadSource.hex("0f"),
        session_id="pkg-cli-pcap-scrub",
        pcap_dir=tmp_path / "pcaps",
    )
    assert sent.transport_record is not None
    scrubbed_pcap = tmp_path / "scrubbed.pcap"
    output = tmp_path / "scrub-report.json"

    assert (
        celatim_main(
            [
                "scrub",
                "pcap",
                "--mechanism",
                "tcp-reserved-bits",
                "--input-pcap",
                str(sent.transport_record),
                "--output-pcap",
                str(scrubbed_pcap),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    document = json.loads(output.read_text())

    assert document["schema_version"] == "celatim.scrub_report.v1"
    assert document["mechanism_id"] == "tcp-reserved-bits"
    assert document["command"][:3] == ["celatim", "scrub", "pcap"]
    assert document["ok"] is True
    assert document["before_matched_unit_count"] > 0
    assert document["after_matched_unit_count"] == 0
    assert document["scrubbed_unit_count"] == document["before_matched_unit_count"]
    assert document["output"]["sha256"] == hashlib.sha256(scrubbed_pcap.read_bytes()).hexdigest()


def test_package_endpoint_cli_testbed_requirements_and_qemu_preflight(
    tmp_path,
    monkeypatch,
):
    requirements_out = tmp_path / "testbed-requirements.json"
    preflight_out = tmp_path / "qemu-preflight.json"
    disk = tmp_path / "receiver.qcow2"
    disk.touch()
    monkeypatch.setattr(qemu_module.shutil, "which", lambda binary: f"/fake/{binary}")

    assert (
        celatim_main(
            [
                "testbed",
                "requirements",
                "--profile",
                "netns-afpacket",
                "--profile",
                "qemu-cross-stack",
                "--output",
                str(requirements_out),
            ]
        )
        == 0
    )
    assert (
        celatim_main(
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
                str(preflight_out),
            ]
        )
        == 0
    )
    requirements = json.loads(requirements_out.read_text())
    preflight = json.loads(preflight_out.read_text())
    checks = {check["check_id"]: check for check in preflight["checks"]}

    assert requirements["schema_version"] == "celatim.testbed_requirements.v1"
    assert requirements["profile_count"] == 2
    assert requirements["profile_ids"] == ["netns-afpacket", "qemu-cross-stack"]
    assert "qemu-system-x86_64" in requirements["required_tools"]
    assert preflight["schema_version"] == "celatim.qemu_tap_preflight.v1"
    assert preflight["ok"] is True
    assert checks["tcpdump_binary"]["status"] == "pass"
    assert checks["kvm_device"]["status"] == "skip"
    assert preflight["tap_config"]["tap_name"] == "tap-cli"
    assert "-enable-kvm" not in preflight["qemu_argv"]
    assert preflight["qemu_argv"][-1] == "-nographic"


def test_package_endpoint_cli_timing_sweep_and_observed_sweep_write_json(tmp_path):
    sweep_out = tmp_path / "timing-sweep.json"
    observed_out = tmp_path / "observed-timing-sweep.json"
    trace_path = tmp_path / "trace.json"
    profile = MechanismProfile.from_catalog("dns-timing")
    payload = bytes.fromhex("00 ff 80 41")
    baseline_payload = bytes(len(payload))
    pacing = PacingConfig(unit_rate_hz=100.0)
    baseline_count = _carrier_count(profile, baseline_payload, pacing)
    trial_count = _carrier_count(profile, payload, pacing)
    trace_path.write_text(
        json.dumps(
            {
                "path_kind": "dns_netns_pcap",
                "path_metadata": {"tap": "package-cli-pcap", "stack": "netns"},
                "baseline_payload_hex": baseline_payload.hex(),
                "baseline": {
                    "session_id": "pkg-cli-observed:baseline",
                    "observed_offsets_s": list(_offsets(baseline_count)),
                    "recovered_hex": baseline_payload.hex(),
                },
                "trials": [
                    {
                        "session_id": "pkg-cli-observed:q1",
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
        celatim_main(
            [
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
                "pkg-cli-sweep",
                "--output",
                str(sweep_out),
            ]
        )
        == 0
    )
    assert (
        celatim_main(
            [
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
                "pkg-cli-observed",
                "--output",
                str(observed_out),
            ]
        )
        == 0
    )
    sweep = json.loads(sweep_out.read_text())
    observed = json.loads(observed_out.read_text())

    assert sweep["schema_version"] == "celatim.timing_sweep.v1"
    assert sweep["run_id"] == "pkg-cli-sweep"
    assert sweep["mechanism_id"] == "dns-timing"
    assert sweep["path_kind"] == "timed_memory"
    assert [trial["quantum_s"] for trial in sweep["trials"]] == [0.01, 0.005]
    assert observed["schema_version"] == "celatim.timing_sweep.v1"
    assert observed["run_id"] == "pkg-cli-observed"
    assert observed["path_kind"] == "dns_netns_pcap"
    assert observed["path_metadata"] == {"tap": "package-cli-pcap", "stack": "netns"}
    assert observed["baseline"]["carrier_units"] == baseline_count
    assert observed["trials"][0]["carrier_units"] == trial_count
    assert observed["ok"] is True


def test_package_endpoint_cli_afpacket_scenario_roundtrip_uses_live_runner(
    tmp_path,
    monkeypatch,
):
    seen: list[dict[str, Any]] = []

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
        assert config.sender_interface == "vs"
        assert config.receiver_interface == "vr"
        assert config.dst_port == 443
        assert config.protocol.value == "tcp"
        assert capture is not None
        capture.config.output.parent.mkdir(parents=True, exist_ok=True)
        capture.config.output.write_bytes(b"afpacket-endpoint")
        seen.append(
            {
                "session_id": session_id,
                "payload": payload,
                "capture_output": capture.config.output,
                "capture_namespace": capture.config.namespace,
                "capture_interface": capture.config.interface,
                "capture_filter": capture.config.filter_expr,
            }
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
        return AfpacketRoundtripResult(
            receipt=receipt,
            result=result,
            symbols=tuple(symbols),
            expected_frames=receipt.carrier_units,
        )

    monkeypatch.setattr(endpoint_cli_module, "run_afpacket_roundtrip", fake_run_afpacket_roundtrip)
    output = tmp_path / "afpacket-roundtrip.json"
    capture = tmp_path / "capture.pcap"

    assert (
        celatim_main(
            [
                "roundtrip",
                "--scenario-id",
                "tcp-reserved-bits-afpacket-netns",
                "--capture-pcap",
                str(capture),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    document = json.loads(output.read_text())

    assert seen == [
        {
            "session_id": "tcp-reserved-bits-afpacket-netns",
            "payload": b"\x00\xff\x80TCP",
            "capture_output": capture,
            "capture_namespace": "rcv",
            "capture_interface": "vr",
            "capture_filter": ("tcp", "port", "443"),
        }
    ]
    assert document["scenario_id"] == "tcp-reserved-bits-afpacket-netns"
    assert document["transport"] == "afpacket_ipv4"
    assert document["packet_path"]["receiver_interface"] == "vr"
    assert document["packet_path"]["protocol"] == "tcp"
    assert document["transport_record"] == str(capture)
    assert document["transport_artifact"]["sha256"] == (
        "1941d7a51f8a882beb293b9dfcb459d699b7597fb08af61dbfba9dd91e811a38"
    )
    assert document["recovered_hex"] == "00ff80544350"
    assert document["matches"] is True
    assert document["evidence"]["ok"] is True


def test_package_endpoint_cli_afpacket_scenario_split_send_recv_uses_transport(
    tmp_path,
    monkeypatch,
):
    scenario_id = "tcp-reserved-bits-afpacket-netns"
    payload = b"\x00\xff\x80TCP"
    profile = MechanismProfile.from_catalog("tcp-reserved-bits")
    memory_transport = InMemoryTransport()
    receipt = ChannelSession(profile, memory_transport).send_message(
        payload,
        session_id=scenario_id,
    )
    expected_symbols = tuple(memory_transport.receive_symbols(receipt.session_id))
    calls: list[dict[str, Any]] = []

    class FakeAfpacketTransport:
        def __init__(self, profile, config):
            self.profile = profile
            self.config = config
            calls.append(
                {
                    "event": "init",
                    "mechanism": profile.id,
                    "dst_port": config.dst_port,
                    "protocol": config.protocol.value,
                    "expected_frames": config.expected_frames,
                }
            )

        def send_symbols(self, session_id, symbols, pacing=None):
            calls.append(
                {
                    "event": "send",
                    "session_id": session_id,
                    "symbols": tuple(symbols),
                    "unit_rate_hz": None if pacing is None else pacing.unit_rate_hz,
                }
            )

        def receive_symbols(self, session_id):
            calls.append(
                {
                    "event": "receive",
                    "session_id": session_id,
                    "expected_frames": self.config.expected_frames,
                }
            )
            return list(expected_symbols)

    monkeypatch.setattr(endpoint_cli_module, "AfpacketCarrierTransport", FakeAfpacketTransport)
    sent = tmp_path / "afpacket-send.json"
    received = tmp_path / "afpacket-recv.json"

    assert (
        celatim_main(
            [
                "send",
                "--scenario-id",
                scenario_id,
                "--output",
                str(sent),
            ]
        )
        == 0
    )
    sent_document = json.loads(sent.read_text())
    expected_frames = sent_document["expected_frames"]
    assert expected_frames == len(expected_symbols)

    assert (
        celatim_main(
            [
                "recv",
                "--scenario-id",
                scenario_id,
                "--expected-frames",
                str(expected_frames),
                "--output",
                str(received),
            ]
        )
        == 0
    )
    received_document = json.loads(received.read_text())

    assert calls[0] == {
        "event": "init",
        "mechanism": "tcp-reserved-bits",
        "dst_port": 443,
        "protocol": "tcp",
        "expected_frames": None,
    }
    assert calls[1]["event"] == "send"
    assert calls[1]["session_id"] == scenario_id
    assert calls[1]["symbols"] == expected_symbols
    assert calls[2] == {
        "event": "init",
        "mechanism": "tcp-reserved-bits",
        "dst_port": 443,
        "protocol": "tcp",
        "expected_frames": expected_frames,
    }
    assert calls[3] == {
        "event": "receive",
        "session_id": scenario_id,
        "expected_frames": expected_frames,
    }
    assert sent_document["scenario_id"] == scenario_id
    assert sent_document["transport"] == "afpacket_ipv4"
    assert sent_document["packet_path"]["receiver_interface"] == "vr"
    assert sent_document["packet_path"]["protocol"] == "tcp"
    assert received_document["scenario_id"] == scenario_id
    assert received_document["transport"] == "afpacket_ipv4"
    assert received_document["expected_frames"] == expected_frames
    assert received_document["packet_path"]["expected_frames"] == expected_frames
    assert received_document["recovered_hex"] == payload.hex()
    assert received_document["evidence"]["ok"] is True


def test_package_endpoint_cli_afpacket_scenario_recv_requires_expected_frames(tmp_path):
    output = tmp_path / "afpacket-recv.json"

    with pytest.raises(ValueError, match="--expected-frames"):
        celatim_main(
            [
                "recv",
                "--scenario-id",
                "tcp-reserved-bits-afpacket-netns",
                "--output",
                str(output),
            ]
        )


def test_package_endpoint_cli_dns_daemon_scenario_roundtrip_uses_live_runner(
    tmp_path,
    monkeypatch,
):
    seen: list[dict[str, Any]] = []

    def fake_run_dns_roundtrip(
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
        assert config.sender_namespace == "snd"
        assert config.resolver_namespace == "rcv"
        assert config.query_name == "covert.test"
        assert config.answer_address == "10.10.0.2"
        assert config.padding_optcode == 12
        assert config.port == 53
        assert config.capture_interface == "vr"
        assert config.capture_filter == ("udp", "port", "53", "and", "src", "host", "10.10.0.1")
        config.capture_pcap.parent.mkdir(parents=True, exist_ok=True)
        config.capture_pcap.write_bytes(b"dns-daemon-endpoint")
        seen.append(
            {
                "session_id": session_id,
                "payload": payload,
                "capture_output": config.capture_pcap,
            }
        )
        memory_transport = InMemoryTransport()
        receipt = ChannelSession(profile, memory_transport).send_message(
            payload,
            session_id=session_id,
            pacing=pacing,
        )
        symbols = tuple(memory_transport.receive_symbols(receipt.session_id))
        receiver_transport = InMemoryTransport()
        receiver_transport.send_symbols(receipt.session_id, list(symbols), pacing)
        result = ChannelSession(
            profile,
            receiver_transport,
            reliability=reliability,
        ).receive_message(receipt)
        return DnsEdnsPaddingRoundtripResult(
            receipt=receipt,
            result=result,
            symbols=symbols,
            capture_pcap=config.capture_pcap,
            answers=("10.10.0.2",),
            daemon_readiness={"ok": True, "probe": "dig"},
            tool_versions=(
                DnsToolVersionRecord(
                    tool="dnsmasq",
                    argv=("dnsmasq", "--version"),
                    returncode=0,
                    stdout_sha256="dnsmasq-stdout",
                    stderr_sha256="dnsmasq-stderr",
                    stdout_excerpt="Dnsmasq version test",
                    stderr_excerpt=None,
                ),
            ),
        )

    monkeypatch.setattr(
        endpoint_cli_module,
        "run_dns_edns0_padding_roundtrip",
        fake_run_dns_roundtrip,
    )
    output = tmp_path / "dns-roundtrip.json"
    capture = tmp_path / "dns.pcap"

    assert (
        celatim_main(
            [
                "roundtrip",
                "--scenario-id",
                "edns0-padding-dnsmasq-dig-real-daemon",
                "--capture-pcap",
                str(capture),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    document = json.loads(output.read_text())

    assert seen == [
        {
            "session_id": "edns0-padding-dnsmasq-dig-real-daemon",
            "payload": b"realistic-dns-channel",
            "capture_output": capture,
        }
    ]
    assert document["scenario_id"] == "edns0-padding-dnsmasq-dig-real-daemon"
    assert document["transport"] == "dns_edns0_padding"
    assert document["transport_record"] == str(capture)
    assert document["transport_artifact"]["sha256"] == (
        "a1bd4051a4ad6eb1fefb6e5bb63c2151062754d91da218ad205db5752024bb7f"
    )
    assert document["dns_path"]["query_name"] == "covert.test"
    assert document["dns_path"]["capture_pcap"] == str(capture)
    assert document["transport_metadata"]["schema_version"] == (
        "celatim.transport_metadata.dns_edns0_padding.v1"
    )
    assert document["transport_metadata"]["answers"] == ["10.10.0.2"]
    assert document["transport_metadata"]["tool_versions"][0]["tool"] == "dnsmasq"
    assert document["recovered_hex"] == "7265616c69737469632d646e732d6368616e6e656c"
    assert document["matches"] is True
    assert document["evidence"]["ok"] is True


def test_package_endpoint_cli_dns_daemon_scenario_split_send_recv_uses_live_helpers(
    tmp_path,
    monkeypatch,
):
    scenario_id = "edns0-padding-dnsmasq-dig-real-daemon"
    payload = b"realistic-dns-channel"
    profile = MechanismProfile.from_catalog("edns0-padding")
    memory_transport = InMemoryTransport()
    receipt = ChannelSession(profile, memory_transport).send_message(
        payload,
        session_id=scenario_id,
    )
    expected_symbols = tuple(memory_transport.receive_symbols(receipt.session_id))
    calls: list[dict[str, Any]] = []

    def fake_send_dns(
        profile,
        payload,
        *,
        session_id=None,
        config=None,
        pacing=None,
        command_runner=None,
        sleeper=None,
    ):
        assert config is not None
        calls.append(
            {
                "event": "send",
                "mechanism": profile.id,
                "session_id": session_id,
                "payload": payload,
                "capture_pcap": config.capture_pcap,
                "query_name": config.query_name,
                "unit_rate_hz": None if pacing is None else pacing.unit_rate_hz,
            }
        )
        return DnsEdnsPaddingSendResult(
            receipt=receipt,
            symbols=expected_symbols,
            answers=("10.10.0.2",) * len(expected_symbols),
            tool_versions=(
                DnsToolVersionRecord(
                    tool="dig",
                    argv=("dig", "-v"),
                    returncode=0,
                    stdout_sha256="dig-stdout",
                    stderr_sha256="dig-stderr",
                    stdout_excerpt="DiG test",
                    stderr_excerpt=None,
                ),
            ),
        )

    def fake_receive_dns(
        profile,
        session_id,
        *,
        expected_queries,
        config=None,
        pacing=None,
        reliability=None,
        command_runner=None,
        process_runner=None,
        pcap_decoder=None,
        sleeper=None,
    ):
        assert config is not None
        config.capture_pcap.parent.mkdir(parents=True, exist_ok=True)
        config.capture_pcap.write_bytes(b"dns-split-capture")
        calls.append(
            {
                "event": "recv",
                "mechanism": profile.id,
                "session_id": session_id,
                "expected_queries": expected_queries,
                "capture_pcap": config.capture_pcap,
                "query_name": config.query_name,
                "unit_rate_hz": None if pacing is None else pacing.unit_rate_hz,
            }
        )
        receiver_transport = InMemoryTransport()
        receiver_transport.send_symbols(session_id, list(expected_symbols), pacing)
        result = ChannelSession(
            profile,
            receiver_transport,
            reliability=reliability,
        ).receive_message(session_id)
        return DnsEdnsPaddingReceiveResult(
            result=result,
            symbols=expected_symbols,
            capture_pcap=config.capture_pcap,
            daemon_readiness={"ok": True, "probe": "dig"},
            tool_versions=(
                DnsToolVersionRecord(
                    tool="dnsmasq",
                    argv=("dnsmasq", "--version"),
                    returncode=0,
                    stdout_sha256="dnsmasq-stdout",
                    stderr_sha256="dnsmasq-stderr",
                    stdout_excerpt="Dnsmasq version test",
                    stderr_excerpt=None,
                ),
            ),
        )

    monkeypatch.setattr(endpoint_cli_module, "send_dns_edns0_padding", fake_send_dns)
    monkeypatch.setattr(endpoint_cli_module, "receive_dns_edns0_padding", fake_receive_dns)
    sent = tmp_path / "dns-send.json"
    received = tmp_path / "dns-recv.json"
    capture = tmp_path / "dns-split.pcap"

    assert (
        celatim_main(
            [
                "send",
                "--scenario-id",
                scenario_id,
                "--output",
                str(sent),
            ]
        )
        == 0
    )
    sent_document = json.loads(sent.read_text())
    expected_frames = sent_document["expected_frames"]

    assert (
        celatim_main(
            [
                "recv",
                "--scenario-id",
                scenario_id,
                "--expected-frames",
                str(expected_frames),
                "--capture-pcap",
                str(capture),
                "--output",
                str(received),
            ]
        )
        == 0
    )
    received_document = json.loads(received.read_text())

    assert calls == [
        {
            "event": "send",
            "mechanism": "edns0-padding",
            "session_id": scenario_id,
            "payload": payload,
            "capture_pcap": None,
            "query_name": "covert.test",
            "unit_rate_hz": 5.0,
        },
        {
            "event": "recv",
            "mechanism": "edns0-padding",
            "session_id": scenario_id,
            "expected_queries": expected_frames,
            "capture_pcap": capture,
            "query_name": "covert.test",
            "unit_rate_hz": 5.0,
        },
    ]
    assert sent_document["scenario_id"] == scenario_id
    assert sent_document["transport"] == "dns_edns0_padding"
    assert sent_document["expected_frames"] == len(expected_symbols)
    assert sent_document["dns_path"]["capture_pcap"] is None
    assert sent_document["transport_metadata"]["answers"] == ["10.10.0.2"] * len(expected_symbols)
    assert received_document["scenario_id"] == scenario_id
    assert received_document["transport"] == "dns_edns0_padding"
    assert received_document["expected_frames"] == expected_frames
    assert received_document["transport_record"] == str(capture)
    assert received_document["transport_artifact"]["sha256"] == (
        "d351702e6b00f4de216c5298a195b9c81ceb666cfda93c8ae44970975e8081ba"
    )
    assert received_document["transport_metadata"]["daemon_readiness"] == {
        "ok": True,
        "probe": "dig",
    }
    assert received_document["recovered_hex"] == payload.hex()
    assert received_document["evidence"]["ok"] is True


def test_package_endpoint_cli_dns_daemon_scenario_recv_requires_expected_frames(tmp_path):
    with pytest.raises(ValueError, match="--expected-frames"):
        celatim_main(
            [
                "recv",
                "--scenario-id",
                "edns0-padding-dnsmasq-dig-real-daemon",
                "--capture-pcap",
                str(tmp_path / "dns.pcap"),
            ]
        )


def test_package_endpoint_cli_crypto_scenario_send_recv_replays_transcript(tmp_path):
    pytest.importorskip("cryptography")
    transcript = tmp_path / "ecdsa-transcript.json"
    sent = tmp_path / "ecdsa-send.json"
    received = tmp_path / "ecdsa-recv.json"

    assert (
        celatim_main(
            [
                "send",
                "--scenario-id",
                "ecdsa-nonce-local-crypto-transcript",
                "--transcript-json",
                str(transcript),
                "--output",
                str(sent),
            ]
        )
        == 0
    )
    assert (
        celatim_main(
            [
                "recv",
                "--scenario-id",
                "ecdsa-nonce-local-crypto-transcript",
                "--transcript-json",
                str(transcript),
                "--output",
                str(received),
            ]
        )
        == 0
    )
    sent_document = json.loads(sent.read_text())
    received_document = json.loads(received.read_text())
    transcript_path = transcript.with_name("ecdsa-transcript-endpoint.json")

    assert transcript_path.is_file()
    assert sent_document["scenario_id"] == "ecdsa-nonce-local-crypto-transcript"
    assert sent_document["mechanism_id"] == "ecdsa-nonce"
    assert sent_document["transport"] == "crypto_ecdsa_nonce"
    assert sent_document["transport_record"] == str(transcript_path)
    assert received_document["scenario_id"] == "ecdsa-nonce-local-crypto-transcript"
    assert received_document["transport"] == "crypto_ecdsa_nonce"
    assert received_document["transport_record"] == str(transcript_path)
    assert received_document["recovered_hex"] == "00ff804543445341"
    assert received_document["evidence"]["ok"] is True


def test_package_endpoint_cli_evidence_run_writes_command_provenance(tmp_path):
    output = tmp_path / "evidence.json"

    assert (
        celatim_main(
            [
                "evidence",
                "run",
                "--scenario-id",
                "pkg-cli-evidence",
                "--mechanism",
                "http2-ping-opaque",
                "--hex",
                "00 ff 80 41",
                "--control-message",
                "benign",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    document = json.loads(output.read_text())

    assert document["scenario_id"] == "pkg-cli-evidence"
    assert document["mechanism_id"] == "http2-ping-opaque"
    assert document["control_kind"] == "control_message"
    assert document["ok"] is True
    assert document["reproducibility"]["command"][:3] == [
        "celatim",
        "evidence",
        "run",
    ]


def test_package_endpoint_cli_evidence_run_accepts_random_control_payload(tmp_path):
    output = tmp_path / "random-control-evidence.json"

    assert (
        celatim_main(
            [
                "evidence",
                "run",
                "--scenario-id",
                "pkg-random-control",
                "--mechanism",
                "http2-ping-opaque",
                "--hex",
                "00 ff 80 41",
                "--control-random-bytes",
                "12",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    document = json.loads(output.read_text())
    control_payload = bytes.fromhex(document["benign_control"]["recovered_hex"])

    assert document["scenario_id"] == "pkg-random-control"
    assert document["control_kind"] == "control_random_bytes"
    assert document["ok"] is True
    assert len(control_payload) == 12
    assert document["benign_control"]["evidence"]["payload_len"] == 12


def test_package_endpoint_cli_evidence_run_uses_scenario_id(tmp_path):
    output = tmp_path / "scenario-evidence.json"

    assert (
        celatim_main(
            [
                "evidence",
                "run",
                "--scenario-id",
                "http2-ping-opaque-real-pdu-smoke",
                "--pcap-dir",
                str(tmp_path / "pcaps"),
                "--artifact-dir",
                str(tmp_path / "carriers"),
                "--log-dir",
                str(tmp_path / "logs"),
                "--run-id",
                "scenario-evidence",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    document = json.loads(output.read_text())

    assert document["run_id"] == "scenario-evidence"
    assert document["scenario_id"] == "http2-ping-opaque-real-pdu-smoke"
    assert document["mechanism_id"] == "http2-ping-opaque"
    assert document["control_kind"] == "control_message"
    assert document["covert"]["transport_kind"] == "pcap"
    assert document["covert"]["recovered_hex"] == "00ff80414243"
    assert document["ok"] is True
    assert document["reproducibility"]["command"][:3] == [
        "celatim",
        "evidence",
        "run",
    ]


def test_package_endpoint_cli_docs_scenario_and_matrix_commands(tmp_path):
    docs = tmp_path / "docs.json"
    api_doc = tmp_path / "api-guide.md"
    schemas = tmp_path / "schemas.json"
    schema_doc = tmp_path / "evidence-run.schema.json"
    rates = tmp_path / "rates.json"
    rates_markdown = tmp_path / "rates.md"
    detector_guidance = tmp_path / "detector-scrub-guidance.md"
    windows_guidance = tmp_path / "windows-pktmon-etw-guidance.md"
    detector_rules_dir = tmp_path / "detector-rules"
    detector_rules_manifest = tmp_path / "detector-rules-manifest.json"
    scenarios = tmp_path / "scenarios.json"
    scenario_ids = tmp_path / "scenario-ids.txt"
    plan = tmp_path / "plan.json"
    matrix = tmp_path / "matrix.json"

    assert celatim_main(["docs", "list", "--output", str(docs)]) == 0
    assert celatim_main(["docs", "show", "--name", "api-guide", "--output", str(api_doc)]) == 0
    assert celatim_main(["schema", "list", "--output", str(schemas)]) == 0
    assert (
        celatim_main(
            [
                "schema",
                "show",
                "--name",
                "evidence-run-v1",
                "--output",
                str(schema_doc),
            ]
        )
        == 0
    )
    assert celatim_main(["rates", "show", "--format", "json", "--output", str(rates)]) == 0
    assert (
        celatim_main(["rates", "show", "--format", "markdown", "--output", str(rates_markdown)])
        == 0
    )
    assert celatim_main(["guidance", "generate", "--output", str(detector_guidance)]) == 0
    assert celatim_main(["guidance", "windows-capture", "--output", str(windows_guidance)]) == 0
    assert (
        celatim_main(
            [
                "detector",
                "rules",
                "--output-dir",
                str(detector_rules_dir),
                "--output",
                str(detector_rules_manifest),
            ]
        )
        == 0
    )
    assert celatim_main(["scenario", "list", "--output", str(scenarios)]) == 0
    assert (
        celatim_main(["scenario", "ids", "--default-included", "--output", str(scenario_ids)]) == 0
    )
    assert celatim_main(["scenario", "plan", "--output", str(plan)]) == 0
    assert celatim_main(["matrix", "generate", "--format", "json", "--output", str(matrix)]) == 0

    docs_document = json.loads(docs.read_text())
    schemas_document = json.loads(schemas.read_text())
    rates_document = json.loads(rates.read_text())
    detector_rules_document = json.loads(detector_rules_manifest.read_text())
    scenario_document = json.loads(scenarios.read_text())
    plan_document = json.loads(plan.read_text())
    matrix_document = json.loads(matrix.read_text())

    assert {"name": "api-guide"} in docs_document["docs"]
    assert api_doc.read_text().startswith("# celatim API Guide")
    assert {"name": "evidence-run-v1"} in schemas_document["schemas"]
    assert '"celatim.evidence_run.v1"' in schema_doc.read_text()
    assert rates_document["command"] == "rates_show"
    assert rates_document["rate_count"] == 4
    assert {rate["mechanism_id"] for rate in rates_document["rates"]} >= {
        "dns-timing",
        "ipv6-flow-label",
    }
    assert rates_markdown.read_text().startswith("# Protocol Rate Assumptions")
    assert detector_guidance.read_text().startswith("# Detector and Scrub Guidance")
    assert windows_guidance.read_text().startswith("# Windows pktmon / ETW Capture Guidance")
    assert detector_rules_document["schema_version"] == "celatim.detector_rules.v1"
    assert detector_rules_document["command"] == "detector_rules"
    assert detector_rules_document["claim_status"] == (
        "generated_not_executed_no_false_positive_estimate"
    )
    assert (detector_rules_dir / "detector-rules.md").is_file()
    assert (detector_rules_dir / "detector-rules.nft").is_file()
    assert (detector_rules_dir / "detector-stateful.suricata.rules").is_file()
    assert "http2-ping-opaque-real-pdu-smoke" in scenario_document["scenario_ids"]
    assert "http2-ping-opaque-real-pdu-smoke" in scenario_ids.read_text()
    assert plan_document["schema_version"] == "celatim.scenario_execution_plan.v1"
    assert matrix_document["schema_version"] == "celatim.support_matrix.v1"
    assert matrix_document["mechanism_count"] > 0


def test_package_endpoint_cli_doctor_writes_preflight_report(tmp_path):
    doctor = tmp_path / "doctor.json"

    assert (
        celatim_main(
            [
                "doctor",
                "--artifact-dir",
                str(tmp_path / "artifacts"),
                "--output",
                str(doctor),
            ]
        )
        == 0
    )
    document = json.loads(doctor.read_text())

    assert document["schema_version"] == "celatim.doctor.v1"
    assert document["ok"] is True
    assert "environment" in {check["check_id"] for check in document["checks"]}
    assert "catalog" in {check["check_id"] for check in document["checks"]}
    assert "scenarios" in {check["check_id"] for check in document["checks"]}

    failure = tmp_path / "doctor-fail.json"
    assert (
        celatim_main(
            [
                "doctor",
                "--require-tool",
                "celatim-definitely-missing-tool",
                "--output",
                str(failure),
            ]
        )
        == 1
    )
    failure_document = json.loads(failure.read_text())
    failed_checks = {check["check_id"]: check for check in failure_document["checks"]}
    assert failure_document["ok"] is False
    assert failed_checks["tool:celatim-definitely-missing-tool"]["status"] == "fail"


def test_package_endpoint_cli_mechanism_discovery_commands(tmp_path):
    mechanism_list = tmp_path / "mechanisms.json"
    mechanism_text = tmp_path / "mechanisms.txt"
    mechanism_show = tmp_path / "http2-ping-opaque.json"

    assert (
        celatim_main(
            [
                "mechanism",
                "list",
                "--transport-kind",
                "http2_hyper_h2",
                "--output",
                str(mechanism_list),
            ]
        )
        == 0
    )
    assert (
        celatim_main(
            [
                "mechanism",
                "list",
                "--format",
                "text",
                "--transport-kind",
                "http2_hyper_h2",
                "--output",
                str(mechanism_text),
            ]
        )
        == 0
    )
    assert (
        celatim_main(
            [
                "mechanism",
                "show",
                "http2-ping-opaque",
                "--output",
                str(mechanism_show),
            ]
        )
        == 0
    )

    list_document = json.loads(mechanism_list.read_text())
    show_document = json.loads(mechanism_show.read_text())

    assert list_document["command"] == "mechanism list"
    assert list_document["filters"] == {
        "transport_kind": "http2_hyper_h2",
        "usable_only": False,
    }
    assert list_document["mechanism_count"] == 1
    assert list_document["mechanisms"][0]["id"] == "http2-ping-opaque"
    assert "http2_hyper_h2" in list_document["mechanisms"][0]["transport_kinds"]
    assert "http2-ping-opaque-hyper-h2" in list_document["mechanisms"][0]["scenario_ids"]
    assert mechanism_text.read_text().startswith("http2-ping-opaque\tHTTP/2\t")
    assert show_document["command"] == "mechanism show"
    assert show_document["mechanism"]["id"] == "http2-ping-opaque"
    assert show_document["mechanism"]["capacity_model"] == "storage"
    assert show_document["mechanism"]["on_path_visibility"] == "deployment_dependent"
    assert show_document["adapter"]["status"] == "real_pdu_fixture"
    assert show_document["adapter"]["supports_carrier_bytes"] is True
    assert "pcap" in show_document["adapter"]["transport_kinds"]
    assert show_document["adapter"]["evidence"]["bucket"] == "real_pdu_packet_path"

    with pytest.raises(KeyError, match="unknown mechanism: no-such-mechanism"):
        celatim_main(["mechanism", "show", "no-such-mechanism"])


def test_package_endpoint_cli_scenario_run_writes_evidence(tmp_path):
    output = tmp_path / "scenario-run.json"

    assert (
        celatim_main(
            [
                "scenario",
                "run",
                "--scenario-id",
                "http2-ping-opaque-real-pdu-smoke",
                "--pcap-dir",
                str(tmp_path / "pcaps"),
                "--artifact-dir",
                str(tmp_path / "carriers"),
                "--log-dir",
                str(tmp_path / "logs"),
                "--run-id",
                "pkg-cli-scenario",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    document = json.loads(output.read_text())

    assert document["run_id"] == "pkg-cli-scenario"
    assert document["scenario_id"] == "http2-ping-opaque-real-pdu-smoke"
    assert document["mechanism_id"] == "http2-ping-opaque"
    assert document["ok"] is True
    assert document["reproducibility"]["command"][:3] == [
        "celatim",
        "scenario",
        "run",
    ]


def test_package_endpoint_cli_http2_hyper_h2_scenario_roundtrip_uses_live_helper(
    tmp_path,
    monkeypatch,
):
    output = tmp_path / "http2-roundtrip.json"
    transcript_template = tmp_path / "{scenario_id}-{case}.json"
    calls: list[Path | None] = []

    def fake_run_hyper_h2_ping_roundtrip(
        profile,
        payload,
        *,
        session_id=None,
        config=None,
        pacing=None,
        reliability=None,
    ):
        assert profile.id == "http2-ping-opaque"
        assert payload == b"\x00\xff\x80ABC"
        assert session_id == "http2-ping-opaque-hyper-h2"
        assert pacing is not None
        assert reliability is None
        assert config is not None
        assert config.validate_ack is True
        calls.append(config.transcript_json)
        assert config.transcript_json == tmp_path / "http2-ping-opaque-hyper-h2-endpoint.json"
        config.transcript_json.parent.mkdir(parents=True, exist_ok=True)
        config.transcript_json.write_text(
            '{"schema_version":"celatim.http2_hyper_h2_transcript.v1"}\n'
        )

        memory_transport = InMemoryTransport()
        receipt = ChannelSession(profile, memory_transport).send_message(
            payload,
            session_id=session_id,
            pacing=pacing,
        )
        result = ChannelSession(profile, memory_transport).receive_message(receipt)
        symbols = memory_transport.receive_symbols(receipt.session_id)
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
        endpoint_cli_module,
        "run_hyper_h2_ping_roundtrip",
        fake_run_hyper_h2_ping_roundtrip,
    )

    assert (
        celatim_main(
            [
                "roundtrip",
                "--scenario-id",
                "http2-ping-opaque-hyper-h2",
                "--transcript-json",
                str(transcript_template),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    document = json.loads(output.read_text())

    assert calls == [tmp_path / "http2-ping-opaque-hyper-h2-endpoint.json"]
    assert document["scenario_id"] == "http2-ping-opaque-hyper-h2"
    assert document["mechanism_id"] == "http2-ping-opaque"
    assert document["transport"] == "http2_hyper_h2"
    assert document["matches"] is True
    assert document["transport_record"] == str(calls[0])
    assert document["transport_artifact"]["kind"] == "http2_hyper_h2_transcript"
    assert document["transport_metadata"]["schema_version"] == (
        "celatim.transport_metadata.http2_hyper_h2.v1"
    )


def test_package_endpoint_cli_http3_aioquic_scenario_roundtrip_uses_live_helper(
    tmp_path,
    monkeypatch,
):
    output = tmp_path / "h3-roundtrip.json"
    transcript_template = tmp_path / "{scenario_id}-{case}.json"
    calls: list[Path | None] = []

    def fake_run_aioquic_h3_settings_roundtrip(
        profile,
        payload,
        *,
        session_id=None,
        config=None,
        pacing=None,
        reliability=None,
    ):
        assert profile.id == "http3-reserved-settings"
        assert payload == b"\x00\xff\x80H3"
        assert session_id == "http3-reserved-settings-aioquic"
        assert pacing is not None
        assert reliability is None
        assert config is not None
        assert config.validate_receiver_settings is True
        calls.append(config.transcript_json)
        assert config.transcript_json == tmp_path / "http3-reserved-settings-aioquic-endpoint.json"
        config.transcript_json.parent.mkdir(parents=True, exist_ok=True)
        config.transcript_json.write_text(
            '{"schema_version":"celatim.http3_aioquic_settings_transcript.v1"}\n'
        )

        memory_transport = InMemoryTransport()
        receipt = ChannelSession(profile, memory_transport).send_message(
            payload,
            session_id=session_id,
            pacing=pacing,
        )
        result = ChannelSession(profile, memory_transport).receive_message(receipt)
        symbols = memory_transport.receive_symbols(receipt.session_id)
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
        endpoint_cli_module,
        "run_aioquic_h3_settings_roundtrip",
        fake_run_aioquic_h3_settings_roundtrip,
    )

    assert (
        celatim_main(
            [
                "roundtrip",
                "--scenario-id",
                "http3-reserved-settings-aioquic",
                "--transcript-json",
                str(transcript_template),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    document = json.loads(output.read_text())

    assert calls == [tmp_path / "http3-reserved-settings-aioquic-endpoint.json"]
    assert document["scenario_id"] == "http3-reserved-settings-aioquic"
    assert document["mechanism_id"] == "http3-reserved-settings"
    assert document["transport"] == "http3_aioquic_reserved_settings"
    assert document["matches"] is True
    assert document["transport_record"] == str(calls[0])
    assert document["transport_artifact"]["kind"] == "http3_aioquic_settings_transcript"
    assert document["transport_metadata"]["schema_version"] == (
        "celatim.transport_metadata.http3_aioquic_reserved_settings.v1"
    )


def test_package_endpoint_cli_quic_aioquic_scenario_roundtrip_uses_live_helper(
    tmp_path,
    monkeypatch,
):
    output = tmp_path / "quic-roundtrip.json"
    transcript_template = tmp_path / "{scenario_id}-{case}.json"
    calls: list[Path | None] = []

    def fake_run_aioquic_connection_id_roundtrip(
        profile,
        payload,
        *,
        session_id=None,
        config=None,
        pacing=None,
        reliability=None,
    ):
        assert profile.id == "quic-connection-id"
        assert payload == b"\x00\xff\x80QUIC"
        assert session_id == "quic-connection-id-aioquic"
        assert pacing is not None
        assert reliability is None
        assert config is not None
        assert config.validate_server_response is True
        calls.append(config.transcript_json)
        assert config.transcript_json == tmp_path / "quic-connection-id-aioquic-endpoint.json"
        config.transcript_json.parent.mkdir(parents=True, exist_ok=True)
        config.transcript_json.write_text(
            '{"schema_version":"celatim.quic_aioquic_transcript.v1"}\n'
        )

        memory_transport = InMemoryTransport()
        receipt = ChannelSession(profile, memory_transport).send_message(
            payload,
            session_id=session_id,
            pacing=pacing,
        )
        result = ChannelSession(profile, memory_transport).receive_message(receipt)
        symbols = memory_transport.receive_symbols(receipt.session_id)
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
        endpoint_cli_module,
        "run_aioquic_connection_id_roundtrip",
        fake_run_aioquic_connection_id_roundtrip,
    )

    assert (
        celatim_main(
            [
                "roundtrip",
                "--scenario-id",
                "quic-connection-id-aioquic",
                "--transcript-json",
                str(transcript_template),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    document = json.loads(output.read_text())

    assert calls == [tmp_path / "quic-connection-id-aioquic-endpoint.json"]
    assert document["scenario_id"] == "quic-connection-id-aioquic"
    assert document["mechanism_id"] == "quic-connection-id"
    assert document["transport"] == "quic_aioquic_connection_id"
    assert document["matches"] is True
    assert document["transport_record"] == str(calls[0])
    assert document["transport_artifact"]["kind"] == "quic_aioquic_transcript"
    assert document["transport_metadata"]["schema_version"] == (
        "celatim.transport_metadata.quic_aioquic_connection_id.v1"
    )


def test_package_netns_lab_facade_plans_and_runs_with_injected_runner():
    config = NetnsPairConfig(sender_ns="sender", receiver_ns="receiver", mtu=9000)
    dry = manage_netns_lab("up", config, dry_run=True)

    assert isinstance(dry, LabTopologyResult)
    assert dry.schema_version == "celatim.netns_lab.v1"
    assert dry.command == "lab up"
    assert dry.executed is False
    assert dry.command_results == ()
    assert dry.topology == config
    assert dry.commands[0].argv == ("ip", "netns", "del", "sender")
    assert dry.commands[0].check is False
    assert dry.commands[4].argv[:5] == ("ip", "link", "add", "vs", "type")
    assert dry.to_json()["topology"]["sender_ns"] == "sender"
    assert dry.to_json()["commands"][0]["argv"] == ["ip", "netns", "del", "sender"]

    runner = RecordingRunner()
    executed = manage_netns_lab("down", config, runner=runner)

    assert executed.executed is True
    assert [command.argv for command in executed.commands] == [
        ("ip", "netns", "del", "sender"),
        ("ip", "netns", "del", "receiver"),
    ]
    assert runner.calls == [
        (("ip", "netns", "del", "sender"), False),
        (("ip", "netns", "del", "receiver"), False),
    ]
    assert executed.to_json()["command_results"][0]["stdout"] == "ok\n"
    assert netns_lab_config_to_json(config)["mtu"] == 9000

    with pytest.raises(ConfigurationError, match="action must be 'up' or 'down'"):
        manage_netns_lab("restart", config)


def test_package_endpoint_cli_lab_command_dry_run_uses_netns_pair_config(tmp_path):
    output = tmp_path / "lab.json"

    assert (
        celatim_main(
            [
                "lab",
                "up",
                "--sender-ns",
                "sender",
                "--receiver-ns",
                "receiver",
                "--mtu",
                "9000",
                "--keep-offloads",
                "--no-cleanup-existing",
                "--dry-run",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    document = json.loads(output.read_text())

    assert document["schema_version"] == "celatim.netns_lab.v1"
    assert document["command"] == "lab up"
    assert document["executed"] is False
    assert document["topology"]["sender_ns"] == "sender"
    assert document["topology"]["mtu"] == 9000
    assert document["topology"]["disable_offloads"] is False
    assert document["topology"]["cleanup_existing"] is False
    assert document["commands"][0]["argv"] == ["ip", "netns", "add", "sender"]
    assert document["command_results"] == []


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
