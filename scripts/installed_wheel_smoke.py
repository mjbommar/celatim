"""Build and smoke-test the Celatim release artifacts outside the checkout."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from pathlib import Path
from typing import Any

EXPECTED_EXTRAS = ("crypto", "daemon", "dns", "iot", "packet", "realtime", "ssh")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build the Celatim sdist and wheel, install the wheel in a fresh venv, "
            "and exercise the public API and CLI outside the checkout."
        )
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        help="Directory for dist, venv, and smoke outputs. Defaults to a temporary directory.",
    )
    parser.add_argument(
        "--keep-work-dir",
        action="store_true",
        help="Keep a temporary work directory after success or failure.",
    )
    parser.add_argument(
        "--uv",
        default=os.environ.get("UV", "uv"),
        help="uv executable used for building wheels. Defaults to UV or uv.",
    )
    args = parser.parse_args(argv)

    project_dir = Path(__file__).resolve().parents[1]
    owns_work_dir = args.work_dir is None
    work_dir = args.work_dir or Path(tempfile.mkdtemp(prefix="celatim-installed-smoke-"))
    work_dir = work_dir.resolve()
    commands: list[dict[str, Any]] = []
    try:
        celatim_sdist, celatim_wheel = _build_release(
            args.uv,
            project_dir,
            work_dir / "celatim-dist",
            commands,
        )
        _assert_release_members(celatim_sdist, celatim_wheel)

        venv_dir = work_dir / "venv"
        venv.EnvBuilder(with_pip=True, clear=True).create(venv_dir)
        python = _venv_executable(venv_dir, "python")
        _run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-deps",
                str(celatim_wheel),
            ],
            cwd=work_dir,
            commands=commands,
        )

        smoke_dir = work_dir / "outside-checkout"
        _fresh_dir(smoke_dir)
        macro_sources = _write_macro_source_fixtures(smoke_dir)
        celatim_cli = _venv_executable(venv_dir, "celatim")
        paper_figures = _venv_executable(venv_dir, "celatim-paper-figures")
        paper_macros = _venv_executable(venv_dir, "celatim-paper-macros")
        paper_tables = _venv_executable(venv_dir, "celatim-paper-tables")
        support_matrix = _venv_executable(venv_dir, "celatim-support-matrix")
        _run(
            [
                str(python),
                "-c",
                (
                    "import json, sys, time; from pathlib import Path; "
                    "started = time.perf_counter(); import celatim; "
                    "import_seconds = time.perf_counter() - started; "
                    "from celatim import ChannelSession, InMemoryTransport, MechanismProfile; "
                    "profile = MechanismProfile.from_catalog('http2-ping-opaque'); "
                    "started = time.perf_counter(); "
                    "result = ChannelSession(profile, InMemoryTransport()).run_roundtrip(b'perf'); "
                    "roundtrip_seconds = time.perf_counter() - started; "
                    "optional = ('aiocoap', 'aioquic', 'cryptography', 'dns', 'paramiko', "
                    "'paho', 'scapy', 'websockets'); "
                    "loaded = [name for name in optional if name in sys.modules]; "
                    "assert result.payload == b'perf'; assert not loaded; "
                    "assert import_seconds < 5.0; assert roundtrip_seconds < 5.0; "
                    "Path('performance.json').write_text(json.dumps({"
                    "'python_version': sys.version.split()[0], "
                    "'import_seconds': import_seconds, "
                    "'roundtrip_seconds': roundtrip_seconds, "
                    "'optional_modules_loaded': loaded}, sort_keys=True) + '\\n')"
                ),
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(python),
                "-c",
                (
                    "import importlib.metadata as metadata, json; "
                    "from pathlib import Path; "
                    "import celatim; "
                    "from celatim import ChannelSession, InMemoryTransport, "
                    "DetectorRuleArtifact, DoctorResult, MechanismDetail, MechanismProfile, MechanismSummary, "
                    "HostTapConfig, LabTopologyResult, "
                    "NetnsPairConfig, "
                    "ObservedTimingCaseInput, PacingConfig, "
                    "PayloadSource, PcapScrubReport, ProtocolRate, ProtocolThroughputEstimate, "
                    "QemuGuestConfig, QemuTapPreflightReport, "
                    "SchemaSummary, "
                    "ScenarioExecutionPlan, ScenarioInventory, "
                    "ScrubArtifact, "
                    "SupportMatrixReport, "
                    "TestbedRequirementInventory, "
                    "TimingSweepReport, "
                    "ReceiveTimeoutError, Receiver, "
                    "RetransmitCapableTransport, Sender, TimeoutAwareTap, TransportError, "
                    "get_detector_rule_artifacts, get_detector_rule_manifest, "
                    "get_detector_scrub_guidance_markdown, get_document_text, "
                    "get_mechanism_detail, get_protocol_rates_markdown, "
                    "get_protocol_throughput_estimates, get_scenario, "
                    "get_schema_text, "
                    "get_support_matrix_markdown, get_support_matrix_report, "
                    "get_qemu_tap_preflight_report, get_testbed_requirements, "
                    "get_windows_capture_guidance_markdown, "
                    "list_documents, list_scenario_ids, "
                    "list_mechanism_summaries, list_protocol_rates, list_scenarios, "
                    "list_schemas, plan_scenarios, "
                    "check_installation, decode_pcap_payload, payload_from_hex, "
                    "manage_netns_lab, netns_lab_config_to_json, "
                    "payload_from_text, random_payload, roundtrip_payload, "
                    "roundtrip_scenario_payload, run_evidence_payload, "
                    "run_observed_timing_sweep_payload, run_timing_sweep_payload, "
                    "scrub_pcap_payload, "
                    "write_detector_rule_files; "
                    "from celatim.transports import AioquicH3SettingsPathConfig, "
                    "AioquicH3SettingsRoundtripResult; "
                    "from celatim.transports import AioquicConnectionIdPathConfig, "
                    "AioquicConnectionIdRoundtripResult; "
                    "from celatim.transports import DnsEdnsPaddingPathConfig, "
                    "DnsEdnsPaddingReceiveResult, DnsEdnsPaddingSendResult, "
                    "DnsToolVersionRecord, HyperH2PingPathConfig, "
                    "HyperH2PingRoundtripResult, HyperH2PingTransport, PacketPath, PcapTap; "
                    "profile = MechanismProfile.from_catalog('http2-ping-opaque'); "
                    "h3_profile = MechanismProfile.from_catalog('http3-reserved-settings'); "
                    "quic_profile = MechanismProfile.from_catalog('quic-connection-id'); "
                    "endpoint = ChannelSession(profile, InMemoryTransport()); "
                    "result = roundtrip_payload(profile, PayloadSource.text('Celatim package')); "
                    "source_result = roundtrip_payload(profile, PayloadSource.hex('00 ff 80 41'), "
                    "expected_payload=PayloadSource.hex('00 ff 80 41')); "
                    "scenario_result = roundtrip_scenario_payload("
                    "'http2-ping-opaque-real-pdu-smoke', payload=PayloadSource.hex('00 ff 80 42'), "
                    "pcap_dir='helper-scenario-pcaps', expected_payload=PayloadSource.hex('00 ff 80 42')); "
                    "scrub_source = roundtrip_payload('tcp-reserved-bits', PayloadSource.hex('0f'), "
                    "session_id='installed-helper-scrub', pcap_dir='helper-scrub-pcaps'); "
                    "scrub_result = scrub_pcap_payload('tcp-reserved-bits', "
                    "scrub_source.sent.transport_record, 'helper-scrubbed.pcap'); "
                    "Path('helper-receiver.qcow2').touch(); "
                    "lab_plan = manage_netns_lab('up', "
                    "NetnsPairConfig(sender_ns='helper-snd', receiver_ns='helper-rcv', mtu=9000), "
                    "dry_run=True); "
                    "testbed_requirements = get_testbed_requirements(('netns-afpacket',)); "
                    "qemu_preflight = get_qemu_tap_preflight_report("
                    "QemuGuestConfig(disk_image='helper-receiver.qcow2', enable_kvm=False), "
                    "HostTapConfig(tap_name='tap-helper', host_ipv4_cidr=None)); "
                    "timing_pacing = PacingConfig(unit_rate_hz=1000.0); "
                    "timing_payload = PayloadSource.hex('00 ff'); "
                    "timing_result = run_timing_sweep_payload('dns-timing', timing_payload, "
                    "quanta_s=(0.001,), base_pacing=timing_pacing, run_id='installed-helper-timing'); "
                    "timing_profile = MechanismProfile.from_catalog('dns-timing'); "
                    "timing_payload_bytes = timing_payload.read_bytes(); "
                    "timing_baseline_payload = bytes(len(timing_payload_bytes)); "
                    "timing_baseline_units = ChannelSession(timing_profile, InMemoryTransport()).send_message("
                    "timing_baseline_payload, session_id='timing-baseline-count', "
                    "pacing=timing_pacing).carrier_units; "
                    "timing_trial_units = ChannelSession(timing_profile, InMemoryTransport()).send_message("
                    "timing_payload_bytes, session_id='timing-trial-count', pacing=timing_pacing).carrier_units; "
                    "timing_observed = run_observed_timing_sweep_payload("
                    "timing_profile, timing_payload, "
                    "baseline=ObservedTimingCaseInput("
                    "observed_offsets_s=tuple(index * 0.001 for index in range(timing_baseline_units)), "
                    "recovered_payload=timing_baseline_payload, session_id='installed-helper-observed:baseline'), "
                    "trials=(ObservedTimingCaseInput("
                    "observed_offsets_s=tuple(index * 0.001 for index in range(timing_trial_units)), "
                    "recovered_payload=timing_payload_bytes, quantum_s=0.001, "
                    "session_id='installed-helper-observed:q1'),), "
                    "base_pacing=timing_pacing, baseline_payload=timing_baseline_payload, "
                    "run_id='installed-helper-observed', path_metadata={'tap': 'helper'}); "
                    "decode_result = decode_pcap_payload('http2-ping-opaque', "
                    "scenario_result.sent.transport_record, "
                    "expected_payload=PayloadSource.hex('00 ff 80 42'), "
                    "session_id='installed-helper-pcap-decode', "
                    "tshark_path='tshark-definitely-not-installed'); "
                    "doctor_result = check_installation("
                    "artifact_dir='helper-doctor-artifacts', optional_tools=()); "
                    "evidence_result = run_evidence_payload(scenario_id='installed-helper-evidence', "
                    "mechanism='http2-ping-opaque', payload=PayloadSource.hex('00 ff'), "
                    "control_payload=PayloadSource.text('control'), transport_dir='helper-evidence-wire', "
                    "log_dir='helper-evidence-logs', run_id='installed-helper-evidence'); "
                    "summary = list_mechanism_summaries(transport_kind='http2_hyper_h2')[0]; "
                    "detail = get_mechanism_detail('http2-ping-opaque'); "
                    "inventory = list_scenarios(); "
                    "plan = plan_scenarios(); "
                    "documents = list_documents(); "
                    "schemas = list_schemas(); "
                    "rates = list_protocol_rates(); "
                    "estimates = get_protocol_throughput_estimates(); "
                    "rates_markdown = get_protocol_rates_markdown(); "
                    "detector_artifacts = get_detector_rule_artifacts(); "
                    "detector_manifest = get_detector_rule_manifest(output_dir='helper-detector-rules'); "
                    "detector_paths = write_detector_rule_files('helper-detector-rules'); "
                    "detector_guidance = get_detector_scrub_guidance_markdown(); "
                    "windows_guidance = get_windows_capture_guidance_markdown(); "
                    "support_matrix = get_support_matrix_report(); "
                    "support_markdown = get_support_matrix_markdown(); "
                    "default_scenario_ids = list_scenario_ids(default_included_only=True); "
                    "scenario = get_scenario('http2-ping-opaque-real-pdu-smoke'); "
                    "dns_path = DnsEdnsPaddingPathConfig(capture_pcap=None); "
                    "dns_version = DnsToolVersionRecord('dig', ('dig', '-v'), 0, "
                    "'stdout', 'stderr', 'dig test', None); "
                    "paths = sorted(path.kind.value for path in profile.adapter.paths); "
                    "h3_paths = sorted(path.kind.value for path in h3_profile.adapter.paths); "
                    "quic_paths = sorted(path.kind.value for path in quic_profile.adapter.paths); "
                    "scripts = sorted(ep.value for ep in metadata.entry_points(group='console_scripts') "
                    "if ep.name == 'celatim'); "
                    "assert result.ok and result.payload == b'Celatim package'; "
                    "assert source_result.payload == b'\\x00\\xff\\x80A'; "
                    "assert source_result.expected_matches is True; "
                    "assert scenario_result.ok and scenario_result.expected_matches is True; "
                    "assert scenario_result.sent.transport_kind == 'pcap'; "
                    "assert scrub_source.ok and scrub_source.sent.transport_kind == 'pcap'; "
                    "assert isinstance(scrub_result, PcapScrubReport); "
                    "assert isinstance(scrub_result.output, ScrubArtifact); "
                    "assert scrub_result.ok is True; "
                    "assert scrub_result.scrubbed_unit_count == scrub_result.before_matched_unit_count; "
                    "assert scrub_result.after_matched_unit_count == 0; "
                    "assert isinstance(testbed_requirements, TestbedRequirementInventory); "
                    "assert isinstance(qemu_preflight, QemuTapPreflightReport); "
                    "assert isinstance(lab_plan, LabTopologyResult); "
                    "assert lab_plan.executed is False; "
                    "assert lab_plan.commands[0].argv == ('ip', 'netns', 'del', 'helper-snd'); "
                    "assert netns_lab_config_to_json(lab_plan.topology)['mtu'] == 9000; "
                    "assert testbed_requirements.profile_ids == ('netns-afpacket',); "
                    "assert qemu_preflight.tap_config.tap_name == 'tap-helper'; "
                    "assert qemu_preflight.claim_status == 'preflight_only_no_vm_started'; "
                    "assert isinstance(timing_result, TimingSweepReport); "
                    "assert isinstance(timing_observed, TimingSweepReport); "
                    "assert timing_result.ok is True; "
                    "assert timing_observed.ok is True; "
                    "assert timing_observed.path_metadata == {'tap': 'helper'}; "
                    "assert decode_result.ok and decode_result.matches_expected is True; "
                    "assert decode_result.recovered_payload == b'\\x00\\xff\\x80B'; "
                    "assert isinstance(doctor_result, DoctorResult); "
                    "assert doctor_result.ok is True; "
                    "assert evidence_result.ok and evidence_result.control_kind == 'control_message'; "
                    "assert isinstance(endpoint, Sender); "
                    "assert isinstance(endpoint, Receiver); "
                    "assert isinstance(summary, MechanismSummary); "
                    "assert isinstance(detail, MechanismDetail); "
                    "assert isinstance(inventory, ScenarioInventory); "
                    "assert isinstance(plan, ScenarioExecutionPlan); "
                    "assert isinstance(support_matrix, SupportMatrixReport); "
                    "assert SchemaSummary('evidence-run-v1') in schemas; "
                    "assert len(rates) == 4; "
                    "assert all(isinstance(rate, ProtocolRate) for rate in rates); "
                    "assert all(isinstance(estimate, ProtocolThroughputEstimate) "
                    "for estimate in estimates); "
                    "assert all(isinstance(artifact, DetectorRuleArtifact) "
                    "for artifact in detector_artifacts); "
                    "assert detector_manifest['schema_version'] == 'celatim.detector_rules.v1'; "
                    "assert detector_manifest['claim_status'] == "
                    "'generated_not_executed_no_false_positive_estimate'; "
                    "assert any(path.name == 'detector-rules.md' for path in detector_paths); "
                    "assert summary.id == 'http2-ping-opaque'; "
                    "assert detail.to_json()['adapter']['status'] == 'real_pdu_fixture'; "
                    "assert 'api-guide' in {doc.name for doc in documents}; "
                    "assert get_document_text('api-guide').startswith('# celatim API Guide'); "
                    "assert 'celatim.evidence_run.v1' in get_schema_text('evidence-run-v1'); "
                    "assert 'structural_upper_bound_not_measured_goodput' in rates_markdown; "
                    "assert detector_guidance.startswith('# Detector and Scrub Guidance'); "
                    "assert windows_guidance.startswith('# Windows pktmon / ETW Capture Guidance'); "
                    "assert support_matrix.schema_version == 'celatim.support_matrix.v1'; "
                    "assert support_markdown.startswith('# Evidence Support Matrix'); "
                    "assert scenario.mechanism_id == 'http2-ping-opaque'; "
                    "assert 'http2-ping-opaque-real-pdu-smoke' in default_scenario_ids; "
                    "assert payload_from_text('hello') == b'hello'; "
                    "assert payload_from_hex('00 ff') == b'\\x00\\xff'; "
                    "assert len(random_payload(4)) == 4; "
                    "assert 'pcap_artifact' in paths; "
                    "assert 'http3_aioquic_reserved_settings' in h3_paths; "
                    "assert 'quic_aioquic_connection_id' in quic_paths; "
                    "assert 'celatim.cli:main' in scripts; "
                    "assert dns_path.query_name == 'covert.test'; "
                    "assert dns_version.to_json()['tool'] == 'dig'; "
                    "print(json.dumps({'distribution_version': metadata.version('celatim'), "
                    "'package_version': celatim.__version__, "
                    "'roundtrip_ok': result.ok, "
                    "'payload_source_ok': source_result.ok, "
                    "'payload_source_expected_matches': source_result.expected_matches, "
                    "'scenario_endpoint_helper_ok': scenario_result.ok, "
                    "'scrub_helper_ok': scrub_result.ok, "
                    "'testbed_requirements_count': testbed_requirements.profile_count, "
                    "'lab_dry_run_command_count': len(lab_plan.commands), "
                    "'qemu_preflight_claim_status': qemu_preflight.claim_status, "
                    "'timing_sweep_ok': timing_result.ok, "
                    "'observed_timing_sweep_ok': timing_observed.ok, "
                    "'pcap_decode_helper_ok': decode_result.ok, "
                    "'doctor_helper_ok': doctor_result.ok, "
                    "'evidence_helper_ok': evidence_result.ok, "
                    "'payload_hex': result.payload.hex(), "
                    "'adapter_paths': paths, "
                    "'h3_adapter_paths': h3_paths, "
                    "'quic_adapter_paths': quic_paths, "
                    "'has_pcap_path': 'pcap_artifact' in paths, "
                    "'has_h3_aioquic_path': 'http3_aioquic_reserved_settings' in h3_paths, "
                    "'has_quic_aioquic_path': 'quic_aioquic_connection_id' in quic_paths, "
                    "'owns_celatim_script': 'celatim.cli:main' in scripts, "
                    "'scenario_count': inventory.scenario_count, "
                    "'default_scenario_count': len(default_scenario_ids), "
                    "'document_count': len(documents), "
                    "'schema_count': len(schemas), "
                    "'protocol_rate_count': len(rates), "
                    "'protocol_estimate_count': len(estimates), "
                    "'detector_artifact_count': len(detector_artifacts), "
                    "'support_matrix_count': support_matrix.mechanism_count, "
                    "'payload_from_hex': payload_from_hex('00 ff').hex(), "
                    "'payload_from_text': payload_from_text('hello').decode(), "
                    "'random_payload_len': len(random_payload(4)), "
                    "'h3_path_config': AioquicH3SettingsPathConfig.__name__, "
                    "'h3_roundtrip_result': AioquicH3SettingsRoundtripResult.__name__, "
                    "'quic_path_config': AioquicConnectionIdPathConfig.__name__, "
                    "'quic_roundtrip_result': AioquicConnectionIdRoundtripResult.__name__, "
                    "'dns_path_config': DnsEdnsPaddingPathConfig.__name__, "
                    "'dns_receive_result': DnsEdnsPaddingReceiveResult.__name__, "
                    "'dns_send_result': DnsEdnsPaddingSendResult.__name__, "
                    "'dns_tool_version_record': DnsToolVersionRecord.__name__, "
                    "'http2_path_config': HyperH2PingPathConfig.__name__, "
                    "'http2_roundtrip_result': HyperH2PingRoundtripResult.__name__, "
                    "'http2_transport': HyperH2PingTransport.__name__, "
                    "'packet_path_alias': PacketPath.__name__, "
                    "'pcap_tap_alias': PcapTap.__name__, "
                    "'receive_timeout_error': ReceiveTimeoutError.__name__, "
                    "'receiver_protocol': Receiver.__name__, "
                    "'retransmit_protocol': RetransmitCapableTransport.__name__, "
                    "'sender_protocol': Sender.__name__, "
                    "'timeout_tap_protocol': TimeoutAwareTap.__name__, "
                    "'transport_error': TransportError.__name__, "
                    "'mechanism_summary': summary.to_json(), "
                    "'mechanism_detail_status': detail.to_json()['adapter']['status']}))"
                ),
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "roundtrip",
                "--mechanism",
                "http2-ping-opaque",
                "--hex",
                "00 ff 80 41",
                "--output",
                "celatim-roundtrip.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [str(support_matrix), "--format", "json", "--output", "support-matrix.json"],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [str(paper_tables), "--output", "field-catalog-longtable.tex"],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(paper_figures),
                "--output-dir",
                "figures",
                "--manifest",
                "figures-manifest.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(paper_macros),
                "--research-catalog",
                str(macro_sources["research_catalog"]),
                "--rfc-index",
                str(macro_sources["rfc_index"]),
                "--wiki-dir",
                str(macro_sources["wiki_dir"]),
                "--output",
                "survey-scale-macros.tex",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "send",
                "--mechanism",
                "http2-ping-opaque",
                "--session-id",
                "celatim-envelope",
                "--hex",
                "00 ff 80 41",
                "--output",
                "celatim-send.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "recv",
                "--input",
                "celatim-send.json",
                "--expect-hex",
                "00 ff 80 41",
                "--output",
                "celatim-recv.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "send",
                "--scenario-id",
                "http2-ping-opaque-real-pdu-smoke",
                "--transport-dir",
                "celatim-scenario-wire",
                "--output",
                "celatim-scenario-send.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "recv",
                "--scenario-id",
                "http2-ping-opaque-real-pdu-smoke",
                "--transport-dir",
                "celatim-scenario-wire",
                "--output",
                "celatim-scenario-recv.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "roundtrip",
                "--scenario-id",
                "http2-ping-opaque-real-pdu-smoke",
                "--hex",
                "00 ff 80 42",
                "--expect-hex",
                "00 ff 80 42",
                "--pcap-dir",
                "celatim-scenario-roundtrip-pcaps",
                "--output",
                "celatim-scenario-roundtrip.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "pcap",
                "decode",
                "--mechanism",
                "http2-ping-opaque",
                "--pcap",
                "celatim-scenario-roundtrip-pcaps/http2-ping-opaque-real-pdu-smoke.pcap",
                "--session-id",
                "celatim-pcap-decode",
                "--tshark-binary",
                "tshark-definitely-not-installed",
                "--expect-hex",
                "00 ff 80 42",
                "--output",
                "celatim-pcap-decode.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "send",
                "--mechanism",
                "tcp-reserved-bits",
                "--session-id",
                "celatim-scrub",
                "--hex",
                "0f",
                "--pcap-dir",
                "celatim-scrub-pcaps",
                "--output",
                "celatim-scrub-source.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "scrub",
                "pcap",
                "--mechanism",
                "tcp-reserved-bits",
                "--input-pcap",
                "celatim-scrub-pcaps/celatim-scrub.pcap",
                "--output-pcap",
                "celatim-scrubbed.pcap",
                "--output",
                "celatim-scrub-report.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [str(celatim_cli), "docs", "list", "--output", "celatim-docs.json"],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [str(celatim_cli), "schema", "list", "--output", "celatim-schemas.json"],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "schema",
                "show",
                "--name",
                "evidence-run-v1",
                "--output",
                "celatim-evidence-run.schema.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "rates",
                "show",
                "--format",
                "json",
                "--output",
                "celatim-rates.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "rates",
                "show",
                "--format",
                "markdown",
                "--output",
                "celatim-rates.md",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(python),
                "-c",
                (
                    "import json; "
                    "from celatim import ChannelSession, InMemoryTransport, "
                    "MechanismProfile, PacingConfig; "
                    "profile = MechanismProfile.from_catalog('dns-timing'); "
                    "pacing = PacingConfig(unit_rate_hz=100.0); "
                    "payload = bytes.fromhex('00ff'); "
                    "baseline = bytes(len(payload)); "
                    "baseline_count = ChannelSession(profile, InMemoryTransport()).send_message("
                    "baseline, session_id='celatim-observed-baseline-count', pacing=pacing).carrier_units; "
                    "trial_count = ChannelSession(profile, InMemoryTransport()).send_message("
                    "payload, session_id='celatim-observed-trial-count', pacing=pacing).carrier_units; "
                    "offsets = lambda count: [index * 0.01 + (0.0001 if index % 2 else 0.0) "
                    "for index in range(count)]; "
                    "open('celatim-observed-timing-trace.json', 'w').write(json.dumps({"
                    "'path_kind': 'dns_netns_pcap', "
                    "'path_metadata': {'tap': 'celatim-pcap'}, "
                    "'baseline_payload_hex': baseline.hex(), "
                    "'baseline': {'session_id': 'celatim-observed:baseline', "
                    "'observed_offsets_s': offsets(baseline_count), "
                    "'recovered_hex': baseline.hex()}, "
                    "'trials': [{'session_id': 'celatim-observed:q1', "
                    "'quantum_s': 0.01, 'observed_offsets_s': offsets(trial_count), "
                    "'recovered_hex': payload.hex()}]}, sort_keys=True) + '\\n')"
                ),
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "timing",
                "sweep",
                "--mechanism",
                "dns-timing",
                "--hex",
                "00 ff",
                "--unit-rate-hz",
                "100",
                "--quantum-s",
                "0.01",
                "--run-id",
                "celatim-timing",
                "--output",
                "celatim-timing-sweep.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "timing",
                "observed-sweep",
                "--mechanism",
                "dns-timing",
                "--hex",
                "00 ff",
                "--unit-rate-hz",
                "100",
                "--trace-json",
                "celatim-observed-timing-trace.json",
                "--run-id",
                "celatim-observed",
                "--output",
                "celatim-observed-timing-sweep.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "guidance",
                "generate",
                "--output",
                "celatim-detector-scrub-guidance.md",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "guidance",
                "windows-capture",
                "--output",
                "celatim-windows-pktmon-etw-guidance.md",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "detector",
                "rules",
                "--output-dir",
                "celatim-detector-rules",
                "--output",
                "celatim-detector-rules-manifest.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "doctor",
                "--artifact-dir",
                "celatim-doctor-artifacts",
                "--output",
                "celatim-doctor.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        (smoke_dir / "celatim-receiver.qcow2").touch()
        _run(
            [
                str(celatim_cli),
                "testbed",
                "requirements",
                "--profile",
                "netns-afpacket",
                "--profile",
                "qemu-cross-stack",
                "--output",
                "celatim-testbed-requirements.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "testbed",
                "qemu-preflight",
                "--disk-image",
                "celatim-receiver.qcow2",
                "--tap-name",
                "tap-celatim",
                "--no-kvm",
                "--no-host-ipv4",
                "--extra-arg=-nographic",
                "--output",
                "celatim-qemu-preflight.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "lab",
                "up",
                "--sender-ns",
                "celatim-snd",
                "--receiver-ns",
                "celatim-rcv",
                "--mtu",
                "9000",
                "--dry-run",
                "--output",
                "celatim-lab-dry-run.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "mechanism",
                "list",
                "--transport-kind",
                "http2_hyper_h2",
                "--output",
                "celatim-mechanisms.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "mechanism",
                "show",
                "http2-ping-opaque",
                "--output",
                "celatim-mechanism-http2.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [str(celatim_cli), "scenario", "list", "--output", "celatim-scenarios.json"],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "matrix",
                "generate",
                "--format",
                "json",
                "--output",
                "celatim-matrix.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "scenario",
                "run",
                "--scenario-id",
                "http2-ping-opaque-real-pdu-smoke",
                "--pcap-dir",
                "celatim-pcaps",
                "--artifact-dir",
                "celatim-carriers",
                "--log-dir",
                "celatim-logs",
                "--run-id",
                "celatim-scenario",
                "--output",
                "celatim-scenario-run.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "evidence",
                "run",
                "--scenario-id",
                "http2-ping-opaque-real-pdu-smoke",
                "--pcap-dir",
                "celatim-evidence-pcaps",
                "--artifact-dir",
                "celatim-evidence-carriers",
                "--log-dir",
                "celatim-evidence-logs",
                "--run-id",
                "celatim-evidence-scenario",
                "--output",
                "celatim-evidence-scenario-run.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "evidence",
                "index",
                "celatim-evidence-scenario-run.json",
                "--path-root",
                ".",
                "--output",
                "celatim-evidence-index.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(celatim_cli),
                "evidence",
                "public-index",
                "--evidence-index",
                "celatim-evidence-index.json",
                "--output",
                "celatim-public-evidence-index.json",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(python),
                "-c",
                (
                    "import hashlib, json; "
                    "doc = json.load(open('celatim-roundtrip.json')); "
                    "assert doc['command'] == 'roundtrip'; "
                    "assert doc['matches'] is True; "
                    "assert doc['evidence']['ok'] is True; "
                    "assert doc['recovered_hex'] == '00ff8041'; "
                    "send_doc = json.load(open('celatim-send.json')); "
                    "recv_doc = json.load(open('celatim-recv.json')); "
                    "assert send_doc['command'] == 'send'; "
                    "assert send_doc['session_id'] == 'celatim-envelope'; "
                    "assert recv_doc['command'] == 'recv'; "
                    "assert recv_doc['session_id'] == 'celatim-envelope'; "
                    "assert recv_doc['evidence']['ok'] is True; "
                    "assert recv_doc['recovered_hex'] == '00ff8041'; "
                    "assert recv_doc['expected_matches'] is True; "
                    "assert recv_doc['expected_payload_sha256'] == "
                    "'3507b01e644277ad3cd10dadd6e33cb801151e62e3cb899a67409ef701d6079c'; "
                    "scenario_send = json.load(open('celatim-scenario-send.json')); "
                    "scenario_recv = json.load(open('celatim-scenario-recv.json')); "
                    "scenario_roundtrip = json.load(open('celatim-scenario-roundtrip.json')); "
                    "pcap_decode = json.load(open('celatim-pcap-decode.json')); "
                    "scrub_report = json.load(open('celatim-scrub-report.json')); "
                    "doctor = json.load(open('celatim-doctor.json')); "
                    "assert scenario_send['scenario_id'] == 'http2-ping-opaque-real-pdu-smoke'; "
                    "assert scenario_send['session_id'] == 'http2-ping-opaque-real-pdu-smoke'; "
                    "assert scenario_recv['recovered_hex'] == '00ff80414243'; "
                    "assert scenario_recv['evidence']['ok'] is True; "
                    "assert scenario_roundtrip['scenario_id'] == 'http2-ping-opaque-real-pdu-smoke'; "
                    "assert scenario_roundtrip['transport'] == 'pcap'; "
                    "assert scenario_roundtrip['recovered_hex'] == '00ff8042'; "
                    "assert scenario_roundtrip['expected_matches'] is True; "
                    "assert pcap_decode['schema_version'] == 'celatim.pcap_decode.v1'; "
                    "assert pcap_decode['session_id'] == 'celatim-pcap-decode'; "
                    "assert pcap_decode['recovered_hex'] == '00ff8042'; "
                    "assert pcap_decode['matches_expected'] is True; "
                    "assert pcap_decode['parser_provenance'][0]['result'] == 'tool_missing'; "
                    "assert scrub_report['schema_version'] == 'celatim.scrub_report.v1'; "
                    "assert scrub_report['mechanism_id'] == 'tcp-reserved-bits'; "
                    "assert scrub_report['command'][:3] == ['celatim', 'scrub', 'pcap']; "
                    "assert scrub_report['ok'] is True; "
                    "assert scrub_report['after_matched_unit_count'] == 0; "
                    "assert scrub_report['scrubbed_unit_count'] == "
                    "scrub_report['before_matched_unit_count']; "
                    "assert scrub_report['output']['sha256'] == "
                    "hashlib.sha256(open('celatim-scrubbed.pcap', 'rb').read()).hexdigest(); "
                    "assert doctor['schema_version'] == 'celatim.doctor.v1'; "
                    "assert doctor['ok'] is True; "
                    "assert 'catalog' in {check['check_id'] for check in doctor['checks']}; "
                    "docs = json.load(open('celatim-docs.json')); "
                    "schemas = json.load(open('celatim-schemas.json')); "
                    "schema_doc = json.load(open('celatim-evidence-run.schema.json')); "
                    "rates = json.load(open('celatim-rates.json')); "
                    "rates_markdown = open('celatim-rates.md').read(); "
                    "timing_sweep = json.load(open('celatim-timing-sweep.json')); "
                    "observed_timing_sweep = json.load(open('celatim-observed-timing-sweep.json')); "
                    "detector_guidance = open('celatim-detector-scrub-guidance.md').read(); "
                    "windows_guidance = open('celatim-windows-pktmon-etw-guidance.md').read(); "
                    "detector_rules = json.load(open('celatim-detector-rules-manifest.json')); "
                    "testbed_requirements = json.load(open('celatim-testbed-requirements.json')); "
                    "qemu_preflight = json.load(open('celatim-qemu-preflight.json')); "
                    "lab_dry_run = json.load(open('celatim-lab-dry-run.json')); "
                    "mechanisms = json.load(open('celatim-mechanisms.json')); "
                    "mechanism = json.load(open('celatim-mechanism-http2.json')); "
                    "scenarios = json.load(open('celatim-scenarios.json')); "
                    "matrix = json.load(open('celatim-matrix.json')); "
                    "scenario_run = json.load(open('celatim-scenario-run.json')); "
                    "evidence_scenario_run = json.load(open('celatim-evidence-scenario-run.json')); "
                    "evidence_index = json.load(open('celatim-evidence-index.json')); "
                    "public_evidence_index = json.load(open('celatim-public-evidence-index.json')); "
                    "assert {'name': 'api-guide'} in docs['docs']; "
                    "assert {'name': 'evidence-run-v1'} in schemas['schemas']; "
                    "assert schema_doc['properties']['schema_version']['const'] == "
                    "'celatim.evidence_run.v1'; "
                    "assert rates['command'] == 'rates_show'; "
                    "assert rates['rate_count'] == 4; "
                    "assert 'structural_upper_bound_not_measured_goodput' in rates_markdown; "
                    "assert 'payload_rate_bps' not in rates_markdown; "
                    "assert timing_sweep['schema_version'] == 'celatim.timing_sweep.v1'; "
                    "assert timing_sweep['run_id'] == 'celatim-timing'; "
                    "assert timing_sweep['path_kind'] == 'timed_memory'; "
                    "assert timing_sweep['ok'] is True; "
                    "assert observed_timing_sweep['schema_version'] == "
                    "'celatim.timing_sweep.v1'; "
                    "assert observed_timing_sweep['run_id'] == 'celatim-observed'; "
                    "assert observed_timing_sweep['path_kind'] == 'dns_netns_pcap'; "
                    "assert observed_timing_sweep['path_metadata'] == {'tap': 'celatim-pcap'}; "
                    "assert observed_timing_sweep['ok'] is True; "
                    "assert detector_guidance.startswith('# Detector and Scrub Guidance'); "
                    "assert windows_guidance.startswith('# Windows pktmon / ETW Capture Guidance'); "
                    "assert 'capture_guidance_not_header_bit_filter' in windows_guidance; "
                    "assert detector_rules['schema_version'] == 'celatim.detector_rules.v1'; "
                    "assert detector_rules['command'] == 'detector_rules'; "
                    "assert detector_rules['claim_status'] == "
                    "'generated_not_executed_no_false_positive_estimate'; "
                    "assert open('celatim-detector-rules/detector-rules.md').read().startswith("
                    "'# Detector Rule Appendix'); "
                    "assert open('celatim-detector-rules/detector-stateful-plan.md').read().startswith("
                    "'# Stateful Detector Plan'); "
                    "assert testbed_requirements['schema_version'] == "
                    "'celatim.testbed_requirements.v1'; "
                    "assert testbed_requirements['profile_ids'] == "
                    "['netns-afpacket', 'qemu-cross-stack']; "
                    "assert qemu_preflight['schema_version'] == "
                    "'celatim.qemu_tap_preflight.v1'; "
                    "assert qemu_preflight['claim_status'] == 'preflight_only_no_vm_started'; "
                    "assert qemu_preflight['tap_config']['tap_name'] == 'tap-celatim'; "
                    "assert '-enable-kvm' not in qemu_preflight['qemu_argv']; "
                    "assert qemu_preflight['qemu_argv'][-1] == '-nographic'; "
                    "assert lab_dry_run['schema_version'] == 'celatim.netns_lab.v1'; "
                    "assert lab_dry_run['command'] == 'lab up'; "
                    "assert lab_dry_run['executed'] is False; "
                    "assert lab_dry_run['topology']['sender_ns'] == 'celatim-snd'; "
                    "assert lab_dry_run['topology']['mtu'] == 9000; "
                    "assert lab_dry_run['commands'][0]['argv'] == ['ip', 'netns', 'del', 'celatim-snd']; "
                    "assert mechanisms['mechanism_count'] == 1; "
                    "assert mechanisms['mechanisms'][0]['id'] == 'http2-ping-opaque'; "
                    "assert mechanism['adapter']['status'] == 'real_pdu_fixture'; "
                    "assert 'http2_hyper_h2' in mechanism['adapter']['transport_kinds']; "
                    "assert 'http2-ping-opaque-real-pdu-smoke' in scenarios['scenario_ids']; "
                    "assert 'edns0-padding-dnsmasq-dig-real-daemon' in scenarios['scenario_ids']; "
                    "assert matrix['schema_version'] == 'celatim.support_matrix.v1'; "
                    "assert scenario_run['run_id'] == 'celatim-scenario'; "
                    "assert scenario_run['ok'] is True; "
                    "assert evidence_scenario_run['run_id'] == 'celatim-evidence-scenario'; "
                    "assert evidence_scenario_run['scenario_id'] == 'http2-ping-opaque-real-pdu-smoke'; "
                    "assert evidence_scenario_run['ok'] is True; "
                    "assert evidence_index['schema_version'] == 'celatim.evidence_index.v1'; "
                    "assert public_evidence_index['schema_version'] == "
                    "'celatim.public_evidence_index.v1'; "
                    "support_matrix = json.load(open('support-matrix.json')); "
                    "figures_manifest = json.load(open('figures-manifest.json')); "
                    "assert support_matrix['schema_version'] == 'celatim.support_matrix.v1'; "
                    "assert figures_manifest['figure_count'] == 3; "
                    "assert '<svg' in open('figures/capacity-by-class.svg').read(); "
                    "assert '\\\\begin{longtable}' in open('field-catalog-longtable.tex').read(); "
                    "assert '\\\\newcommand{\\\\nmech}' in open('survey-scale-macros.tex').read()"
                ),
            ],
            cwd=smoke_dir,
            commands=commands,
        )

        extras = _wheel_extras(celatim_wheel)
        if extras != EXPECTED_EXTRAS:
            raise RuntimeError(f"unexpected wheel extras: {extras}; expected {EXPECTED_EXTRAS}")
        _run(
            [
                args.uv,
                "pip",
                "install",
                "--python",
                str(python),
                f"{celatim_wheel}[{','.join(extras)}]",
            ],
            cwd=smoke_dir,
            commands=commands,
        )
        _run(
            [
                str(python),
                "-c",
                (
                    "import importlib.metadata as metadata, json; "
                    "import aiocoap, aioquic, cryptography, dns, ecdsa, h2, "
                    "paho.mqtt, paramiko, scapy, websockets; "
                    "from pathlib import Path; "
                    f"extras = {extras!r}; "
                    "distributions = ('aiocoap', 'aioquic', 'cryptography', 'dnspython', "
                    "'ecdsa', 'h2', 'paho-mqtt', 'paramiko', 'scapy', 'websockets'); "
                    "versions = {name: metadata.version(name) for name in distributions}; "
                    "Path('all-extras.json').write_text(json.dumps({"
                    "'extras': extras, 'versions': versions}, sort_keys=True) + '\\n')"
                ),
            ],
            cwd=smoke_dir,
            commands=commands,
        )

        performance = json.loads((smoke_dir / "performance.json").read_text())
        extras_report = json.loads((smoke_dir / "all-extras.json").read_text())
        summary = {
            "ok": True,
            "work_dir": str(work_dir),
            "celatim_sdist": str(celatim_sdist),
            "celatim_wheel": str(celatim_wheel),
            "performance": performance,
            "extras": extras_report,
            "commands": commands,
        }
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    finally:
        if owns_work_dir and not args.keep_work_dir and work_dir.exists():
            shutil.rmtree(work_dir)


def _build_release(
    uv: str,
    project_dir: Path,
    dist_dir: Path,
    commands: list[dict[str, Any]],
) -> tuple[Path, Path]:
    _fresh_dir(dist_dir)
    _run(
        [uv, "build", "--out-dir", str(dist_dir)],
        cwd=project_dir,
        commands=commands,
    )
    sdists = sorted(dist_dir.glob("celatim-*.tar.gz"))
    wheels = sorted(dist_dir.glob("celatim-*.whl"))
    if len(sdists) != 1 or len(wheels) != 1:
        raise RuntimeError(f"expected one Celatim sdist and wheel in {dist_dir}")
    return sdists[0], wheels[0]


def _assert_release_members(sdist: Path, wheel: Path) -> None:
    with tarfile.open(sdist) as archive:
        sdist_members = archive.getnames()
    with zipfile.ZipFile(wheel) as archive:
        wheel_members = archive.namelist()

    retired_core = "rfc" + "tunnel"
    retired_wrapper = "bu" + "bo"
    forbidden = (
        retired_core,
        retired_wrapper,
        "packages/",
        "/.venv/",
        "/__pycache__/",
        "/.pytest_cache/",
        "/.ruff_cache/",
    )
    for artifact, members in ((sdist, sdist_members), (wheel, wheel_members)):
        joined = "\n".join(members).lower()
        present = [fragment for fragment in forbidden if fragment in joined]
        if present:
            raise RuntimeError(f"{artifact}: forbidden release paths: {present}")
    if not any(name.endswith("/src/celatim/py.typed") for name in sdist_members):
        raise RuntimeError(f"{sdist}: missing typed-package marker")
    if "celatim/py.typed" not in wheel_members:
        raise RuntimeError(f"{wheel}: missing typed-package marker")
    if not any(name.endswith(".dist-info/entry_points.txt") for name in wheel_members):
        raise RuntimeError(f"{wheel}: missing console entry-point metadata")


def _wheel_extras(wheel: Path) -> tuple[str, ...]:
    with zipfile.ZipFile(wheel) as archive:
        metadata_name = next(
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        )
        metadata = archive.read(metadata_name).decode()
    return tuple(
        sorted(
            line.partition(":")[2].strip()
            for line in metadata.splitlines()
            if line.startswith("Provides-Extra:")
        )
    )


def _run(
    cmd: list[str], cwd: Path, commands: list[dict[str, Any]]
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=True,
    )
    commands.append(
        {
            "cmd": cmd,
            "cwd": str(cwd),
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    )
    return result


def _venv_executable(venv_dir: Path, name: str) -> Path:
    if sys.platform == "win32":
        return venv_dir / "Scripts" / f"{name}.exe"
    return venv_dir / "bin" / name


def _fresh_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)


def _write_macro_source_fixtures(smoke_dir: Path) -> dict[str, Path]:
    root = smoke_dir / "macro-sources"
    wiki_dir = root / "wiki"
    wiki_dir.mkdir(parents=True)
    research_catalog = root / "rfc-field-catalog.md"
    rfc_index = root / "INDEX.md"
    research_catalog.write_text(
        "Master catalog from a full sweep of the IETF RFC corpus "
        "(`rfc1`-`rfc9937`, ~9,695 documents).\n"
    )
    rfc_index.write_text("# Cited RFC primary sources\n\n**140 RFCs** copied.\n")
    for index in range(17):
        (wiki_dir / f"page-{index:02d}.md").write_text("# Prior wiki page\n")
    return {
        "research_catalog": research_catalog,
        "rfc_index": rfc_index,
        "wiki_dir": wiki_dir,
    }


if __name__ == "__main__":
    raise SystemExit(main())
