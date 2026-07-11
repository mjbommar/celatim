"""Small command-line entry points for generated reviewer artifacts and sessions."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import replace
from datetime import UTC
from importlib import metadata
from pathlib import Path
from typing import Any

from . import cli_endpoints
from .analysis.crosshost_evidence import (
    build_claim_ledger,
    build_crosshost_public_index,
    load_crosshost_public_index,
    load_subliminal_control_report,
)
from .analysis.subliminal_controls import (
    DEFAULT_MIN_CONTROL_SIGNATURES,
    DEFAULT_MIN_P_VALUE,
    build_subliminal_control_report,
)
from .api import (
    manage_netns_lab,
)
from .catalog import load_mechanisms
from .detect import (
    DetectorReplayBackend,
    TraceSourceKind,
    default_replay_mechanisms,
    load_trace_manifest,
    replay_detector_corpus,
    replay_detectors_on_pcap,
    scrub_pcap,
)
from .discovery import get_mechanism_detail, list_mechanism_summaries
from .doctor import PACKAGE_EXTRA_MODULES, run_doctor
from .evidence_index import build_evidence_index, build_public_evidence_index
from .inspection import list_schemas
from .model import Mechanism
from .pcap_decode import decode_pcap
from .report import (
    catalog_figure_artifacts,
    count_wiki_pages,
    detector_rule_manifest,
    detector_scrub_guidance_markdown,
    load_protocol_rates,
    mechanisms_to_longtable,
    parse_cited_rfc_count,
    parse_rfc_corpus_swept_count,
    protocol_rates_markdown,
    support_matrix_markdown,
    support_matrix_report,
    survey_scale_macros,
    survey_scale_macros_tex,
    windows_pktmon_guidance_markdown,
    write_catalog_figures,
    write_detector_rule_artifacts,
)
from .resources import (
    catalog_path,
    doc_names,
    doc_text,
    protocol_rates_path,
    scenario_dir_path,
    schema_text,
)
from .reviewer_bundle import (
    build_public_bundle_manifest,
    build_reviewer_bundle_manifest,
    verify_public_bundle_manifest,
    verify_reviewer_bundle_manifest,
)
from .scenario import (
    TransportConfig,
    build_scenario_execution_plan,
    build_scenario_inventory,
    load_scenario,
    load_scenario_by_id,
    run_evidence,
    scenario_execution_ids,
)
from .session import (
    MechanismProfile,
    PacingConfig,
    ReliabilityPolicy,
)
from .testbed import (
    HostTapConfig,
    NetnsPair,
    NetnsPairConfig,
    QemuGuestConfig,
    build_qemu_tap_preflight_report,
    build_testbed_requirements_inventory,
    testbed_profile_ids,
)
from .timing_sweep import ObservedTimingCaseInput, run_observed_timing_sweep, run_timing_sweep
from .transfer import cli as transfer_cli


def support_matrix_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the evidence support matrix.")
    parser.add_argument(
        "--catalog",
        type=Path,
        help="Path to mechanisms.jsonl. Defaults to the packaged catalog.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write output to this path. Defaults to stdout.",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Output format. Defaults to markdown.",
    )
    args = parser.parse_args(argv)

    with catalog_path(args.catalog) as catalog:
        mechanisms = load_mechanisms(catalog)
    if args.format == "json":
        return _write_json(support_matrix_report(mechanisms).to_json(), args.output)
    return _write_text(support_matrix_markdown(mechanisms), args.output)


def paper_tables_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate LaTeX paper tables from the catalog.")
    parser.add_argument(
        "--catalog",
        type=Path,
        help="Path to mechanisms.jsonl. Defaults to the packaged catalog.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write LaTeX to this path. Defaults to stdout.",
    )
    args = parser.parse_args(argv)

    with catalog_path(args.catalog) as catalog:
        return _write_text(mechanisms_to_longtable(load_mechanisms(catalog)), args.output)


def paper_macros_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate LaTeX paper scale macros.")
    parser.add_argument(
        "--catalog",
        type=Path,
        help="Path to mechanisms.jsonl. Defaults to the packaged catalog.",
    )
    parser.add_argument(
        "--research-catalog",
        type=Path,
        required=True,
        help="Path to research/rfc-field-catalog.md for the RFC corpus sweep count.",
    )
    parser.add_argument(
        "--rfc-index",
        type=Path,
        required=True,
        help="Path to sources/rfc/INDEX.md for the cited RFC primary-source count.",
    )
    parser.add_argument(
        "--wiki-dir",
        type=Path,
        required=True,
        help="Directory containing prior wiki baseline Markdown pages.",
    )
    parser.add_argument(
        "--claim-ledger",
        type=Path,
        help="Optional claim-ledger JSON that supplies run-backed paper counts.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write LaTeX macros to this path. Defaults to stdout.",
    )
    args = parser.parse_args(argv)

    with catalog_path(args.catalog) as catalog:
        macros = survey_scale_macros(
            load_mechanisms(catalog),
            rfc_corpus_swept_count=parse_rfc_corpus_swept_count(args.research_catalog),
            cited_rfc_count=parse_cited_rfc_count(args.rfc_index),
            wiki_page_count=count_wiki_pages(args.wiki_dir),
            claim_ledger=args.claim_ledger,
        )
    return _write_text(survey_scale_macros_tex(macros), args.output)


def paper_figures_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate paper SVG figures from the catalog.")
    parser.add_argument(
        "--catalog",
        type=Path,
        help="Path to mechanisms.jsonl. Defaults to the packaged catalog.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory that receives generated SVG figure files.",
    )
    parser.add_argument(
        "--rates",
        type=Path,
        help="Path to protocol_rates.toml. Defaults to the packaged rate table.",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        help="Write a JSON manifest of generated figures. Defaults to stdout.",
    )
    args = parser.parse_args(argv)

    with catalog_path(args.catalog) as catalog, protocol_rates_path(args.rates) as rates_path:
        mechanisms = load_mechanisms(catalog)
        rates = load_protocol_rates(rates_path)
    write_catalog_figures(mechanisms, args.output_dir, protocol_rates=rates)
    return _write_json(
        {
            "command": "paper_figures",
            "figure_count": len(catalog_figure_artifacts(mechanisms, rates)),
            "output_dir": str(args.output_dir),
            "figures": [
                artifact.to_json() for artifact in catalog_figure_artifacts(mechanisms, rates)
            ],
        },
        args.manifest,
    )


def main(argv: list[str] | None = None) -> int:
    return _session_main(argv, program_name="celatim")


def session_main(argv: list[str] | None = None) -> int:
    """Run the Celatim command surface from Python."""

    return main(argv)


def _session_main(argv: list[str] | None = None, *, program_name: str) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(
        prog=program_name, description="Encode/decode payloads through celatim sessions."
    )
    parser.add_argument(
        "--catalog",
        type=Path,
        help="Path to mechanisms.jsonl. Defaults to the packaged catalog.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    send = subparsers.add_parser("send", help="Encode payload bytes into carrier symbols.")
    _add_profile_args(send, required=False)
    _add_scenario_source_args(send)
    _add_payload_args(send, required=False)
    _add_pacing_args(send)
    _add_transport_arg(send)
    _add_output_arg(send)

    recv = subparsers.add_parser("recv", help="Decode a send envelope back into payload bytes.")
    recv.add_argument("--input", type=Path, help="JSON envelope produced by send.")
    _add_scenario_source_args(recv)
    recv.add_argument("--mechanism", help="Mechanism id for --transport-dir receive.")
    recv.add_argument("--session-id", help="Session id for --transport-dir receive.")
    recv.add_argument(
        "--capture-pcap",
        type=Path,
        help="Capture live daemon receiver traffic to this pcap path.",
    )
    _add_reliability_args(recv)
    _add_transport_arg(recv)
    _add_expected_payload_args(recv)
    _add_output_arg(recv)

    transfer_cli.add_transfer_parser(subparsers)

    evidence = subparsers.add_parser("evidence", help="Run scenario evidence commands.")
    evidence_subparsers = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_run = evidence_subparsers.add_parser(
        "run",
        help="Run covert and benign-control cases and emit JSON evidence.",
    )
    _add_scenario_source_args(evidence_run)
    evidence_run.add_argument("--mechanism", help="Mechanism id from the catalog.")
    _add_payload_args(evidence_run, required=False)
    _add_control_payload_args(evidence_run)
    _add_pacing_args(evidence_run)
    _add_reliability_args(evidence_run)
    _add_artifact_arg(evidence_run)
    _add_log_args(evidence_run)
    _add_transport_arg(evidence_run)
    _add_output_arg(evidence_run)
    evidence_index = evidence_subparsers.add_parser(
        "index",
        help="Index evidence-run JSON files for a reviewer artifact bundle.",
    )
    evidence_index.add_argument(
        "paths",
        nargs="+",
        type=Path,
        help="Evidence JSON file(s) or directory/directories to index.",
    )
    evidence_index.add_argument(
        "--path-root",
        type=Path,
        help="Rewrite artifact paths relative to this root for portable bundles.",
    )
    _add_output_arg(evidence_index)
    evidence_public_index = evidence_subparsers.add_parser(
        "public-index",
        help="Project a private reviewer evidence index into a public-safe hash-only index.",
    )
    evidence_public_index.add_argument(
        "--evidence-index",
        type=Path,
        required=True,
        help="Private reviewer evidence-index JSON to project.",
    )
    _add_output_arg(evidence_public_index)

    bundle = subparsers.add_parser("bundle", help="Build reviewer bundle manifests.")
    bundle_subparsers = bundle.add_subparsers(dest="bundle_command", required=True)
    bundle_manifest = bundle_subparsers.add_parser(
        "manifest",
        help="Hash reviewer artifact files into a top-level bundle manifest.",
    )
    bundle_manifest.add_argument("--bundle-name", required=True, help="Reviewer bundle name.")
    bundle_manifest.add_argument(
        "--bundle-root",
        type=Path,
        default=Path("."),
        help="Root used for display paths in the manifest. Defaults to cwd.",
    )
    bundle_manifest.add_argument("--doctor", type=Path, required=True, help="doctor.json path.")
    bundle_manifest.add_argument(
        "--scenarios",
        type=Path,
        required=True,
        help="scenario inventory JSON path.",
    )
    bundle_manifest.add_argument(
        "--evidence-index",
        type=Path,
        required=True,
        help="evidence-index.json path.",
    )
    bundle_manifest.add_argument(
        "--paper-table",
        type=Path,
        help="generated paper table path to include in the manifest.",
    )
    bundle_manifest.add_argument(
        "--package-wheel",
        type=Path,
        help="Built celatim wheel to include in the private reviewer manifest.",
    )
    bundle_manifest.add_argument(
        "--lockfile",
        type=Path,
        help="Dependency lockfile to include in the private reviewer manifest.",
    )
    bundle_manifest.add_argument(
        "--detector-replay",
        type=Path,
        nargs="+",
        help="Schema-backed detector replay report(s) to include in the private reviewer manifest.",
    )
    bundle_manifest.add_argument(
        "--scrub-report",
        type=Path,
        nargs="+",
        help="Schema-backed scrub report(s) to include in the private reviewer manifest.",
    )
    bundle_manifest.add_argument(
        "--scenario-spec",
        type=Path,
        nargs="+",
        help="Scenario TOML spec file(s) to include in the private reviewer manifest.",
    )
    bundle_manifest.add_argument(
        "--testbed-package",
        type=Path,
        nargs="+",
        help="Testbed packaging/configuration file(s) to include in the private reviewer manifest.",
    )
    bundle_manifest.add_argument(
        "--testbed-preflight",
        type=Path,
        nargs="+",
        help="Schema-backed testbed preflight report(s) to include in the private reviewer manifest.",
    )
    _add_output_arg(bundle_manifest)
    bundle_verify = bundle_subparsers.add_parser(
        "verify",
        help="Verify files referenced by a reviewer bundle manifest.",
    )
    bundle_verify.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="Reviewer bundle manifest JSON path.",
    )
    _add_output_arg(bundle_verify)
    bundle_public = bundle_subparsers.add_parser(
        "public-manifest",
        help="Hash public-safe paper artifacts and hash-only reviewer bundle references.",
    )
    bundle_public.add_argument("--bundle-name", required=True, help="Public bundle name.")
    bundle_public.add_argument(
        "--bundle-root",
        type=Path,
        default=Path("."),
        help="Root used for display paths in the public manifest. Defaults to cwd.",
    )
    bundle_public.add_argument(
        "--support-matrix",
        type=Path,
        required=True,
        help="Generated public evidence support matrix path.",
    )
    bundle_public.add_argument(
        "--detector-scrub-guidance",
        type=Path,
        required=True,
        help="Generated public detector/scrub guidance Markdown path.",
    )
    bundle_public.add_argument(
        "--detector-rule-artifact",
        type=Path,
        nargs="+",
        help="Generated public detector rule artifact(s) to include in the manifest.",
    )
    bundle_public.add_argument(
        "--windows-capture-guidance",
        type=Path,
        help="Generated Windows pktmon/ETW capture guidance Markdown path.",
    )
    bundle_public.add_argument(
        "--scenarios",
        type=Path,
        required=True,
        help="Public scenario inventory JSON path.",
    )
    bundle_public.add_argument(
        "--execution-plan",
        type=Path,
        help="Public-safe scenario execution plan JSON path.",
    )
    bundle_public.add_argument(
        "--testbed-requirements",
        type=Path,
        help="Public-safe testbed requirements JSON path.",
    )
    bundle_public.add_argument(
        "--evidence-index",
        type=Path,
        required=True,
        help="Public evidence-index JSON path carrying evidence hashes.",
    )
    bundle_public.add_argument(
        "--reviewer-manifest",
        type=Path,
        required=True,
        help="Private reviewer bundle manifest reference path.",
    )
    bundle_public.add_argument(
        "--reviewer-verification",
        type=Path,
        required=True,
        help="Private reviewer bundle verification reference path.",
    )
    bundle_public.add_argument(
        "--paper-table",
        type=Path,
        help="Generated paper table path to include in the public manifest.",
    )
    _add_output_arg(bundle_public)
    bundle_public_verify = bundle_subparsers.add_parser(
        "public-verify",
        help="Verify a public-safe bundle manifest and public artifact policy.",
    )
    bundle_public_verify.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="Public bundle manifest JSON path.",
    )
    _add_output_arg(bundle_public_verify)

    scenario = subparsers.add_parser("scenario", help="List and run checked-in scenario specs.")
    scenario_subparsers = scenario.add_subparsers(dest="scenario_command", required=True)
    scenario_list = scenario_subparsers.add_parser("list", help="List TOML scenario specs.")
    scenario_list.add_argument(
        "--scenario-dir",
        type=Path,
        help="Directory of *.toml scenario specs. Defaults to packaged smoke scenarios.",
    )
    _add_output_arg(scenario_list)
    scenario_plan = scenario_subparsers.add_parser(
        "plan",
        help="Write a reviewer execution plan from TOML scenario specs.",
    )
    scenario_plan.add_argument(
        "--scenario-dir",
        type=Path,
        help="Directory of *.toml scenario specs. Defaults to packaged smoke scenarios.",
    )
    _add_output_arg(scenario_plan)
    scenario_ids = scenario_subparsers.add_parser(
        "ids",
        help="Write scenario ids, one per line.",
    )
    scenario_ids.add_argument(
        "--scenario-dir",
        type=Path,
        help="Directory of *.toml scenario specs. Defaults to packaged smoke scenarios.",
    )
    scenario_ids.add_argument(
        "--default-included",
        action="store_true",
        help="Only emit scenarios included by the default reviewer run.",
    )
    _add_output_arg(scenario_ids)
    scenario_run = scenario_subparsers.add_parser("run", help="Run one TOML scenario spec.")
    scenario_run_source = scenario_run.add_mutually_exclusive_group(required=True)
    scenario_run_source.add_argument("--scenario", type=Path, help="Path to scenario TOML.")
    scenario_run_source.add_argument(
        "--scenario-id",
        help="Scenario id to resolve from --scenario-dir or packaged smoke scenarios.",
    )
    scenario_run.add_argument(
        "--scenario-dir",
        type=Path,
        help="Directory of *.toml scenario specs for --scenario-id. Defaults to packaged smoke scenarios.",
    )
    _add_payload_args(scenario_run, required=False)
    _add_artifact_arg(scenario_run)
    _add_log_args(scenario_run)
    _add_reliability_args(scenario_run)
    _add_transport_arg(scenario_run)
    _add_output_arg(scenario_run)

    mechanism = subparsers.add_parser(
        "mechanism",
        help="Discover catalog mechanisms and endpoint transport support.",
    )
    mechanism_subparsers = mechanism.add_subparsers(dest="mechanism_command", required=True)
    mechanism_list = mechanism_subparsers.add_parser(
        "list", help="List catalog mechanisms with adapter and transport summaries."
    )
    mechanism_list.add_argument("--format", choices=("json", "text"), default="json")
    mechanism_list.add_argument("--usable-only", action="store_true")
    mechanism_list.add_argument("--transport-kind")
    _add_output_arg(mechanism_list)
    mechanism_show = mechanism_subparsers.add_parser(
        "show", help="Show one mechanism's catalog and adapter details."
    )
    mechanism_show.add_argument("mechanism_id", help="Mechanism id from the catalog.")
    mechanism_show.add_argument("--format", choices=("json", "text"), default="json")
    _add_output_arg(mechanism_show)

    lab = subparsers.add_parser("lab", help="Create or tear down reusable lab topologies.")
    lab_subparsers = lab.add_subparsers(dest="lab_command", required=True)
    lab_up = lab_subparsers.add_parser("up", help="Create the snd<->rcv netns/veth lab.")
    _add_lab_args(lab_up)
    _add_output_arg(lab_up)
    lab_down = lab_subparsers.add_parser("down", help="Tear down the snd<->rcv netns/veth lab.")
    _add_lab_args(lab_down)
    _add_output_arg(lab_down)

    testbed = subparsers.add_parser("testbed", help="Inspect privileged testbed requirements.")
    testbed_subparsers = testbed.add_subparsers(dest="testbed_command", required=True)
    testbed_requirements = testbed_subparsers.add_parser(
        "requirements",
        help="Show machine-readable requirements for live, daemon, and VM testbeds.",
    )
    testbed_requirements.add_argument(
        "--profile",
        action="append",
        choices=testbed_profile_ids(),
        help="Limit output to a named testbed profile; may be repeated.",
    )
    _add_output_arg(testbed_requirements)
    qemu_preflight = testbed_subparsers.add_parser(
        "qemu-preflight",
        help="Show a non-mutating QEMU/TAP readiness report and command plan.",
    )
    qemu_preflight.add_argument(
        "--disk-image",
        type=Path,
        required=True,
        help="Guest disk image path to pass to QEMU.",
    )
    qemu_preflight.add_argument("--qemu-binary", default="qemu-system-x86_64")
    qemu_preflight.add_argument("--ip-binary", default="ip")
    qemu_preflight.add_argument("--tap-name", default="rfctap0")
    qemu_preflight.add_argument("--host-ipv4-cidr", default="10.77.0.1/24")
    qemu_preflight.add_argument(
        "--no-host-ipv4",
        action="store_true",
        help="Do not include an ip addr add command for the host TAP.",
    )
    qemu_preflight.add_argument("--mtu", type=int, default=1500)
    qemu_preflight.add_argument("--owner")
    qemu_preflight.add_argument("--group")
    qemu_preflight.add_argument("--memory-mib", type=int, default=1024)
    qemu_preflight.add_argument("--smp", type=int, default=1)
    qemu_preflight.add_argument("--mac-address", default="52:54:00:72:63:74")
    qemu_preflight.add_argument("--netdev-id", default="net0")
    qemu_preflight.add_argument("--network-device", default="virtio-net-pci")
    qemu_preflight.add_argument("--drive-interface", default="virtio")
    qemu_preflight.add_argument("--disk-format", default="qcow2")
    qemu_preflight.add_argument("--no-kvm", action="store_true")
    qemu_preflight.add_argument("--no-snapshot", action="store_true")
    qemu_preflight.add_argument("--tcpdump-binary", default="tcpdump")
    qemu_preflight.add_argument("--display", default="none")
    qemu_preflight.add_argument("--no-display", action="store_true")
    qemu_preflight.add_argument("--machine")
    qemu_preflight.add_argument("--cpu")
    qemu_preflight.add_argument(
        "--extra-arg",
        action="append",
        default=[],
        help="Additional QEMU argv token; use --extra-arg=-flag for values starting with '-'.",
    )
    qemu_preflight.add_argument("--dev-kvm", type=Path, default=Path("/dev/kvm"))
    qemu_preflight.add_argument("--no-cleanup-existing", action="store_true")
    _add_output_arg(qemu_preflight)

    detector = subparsers.add_parser("detector", help="Run detector replay/report commands.")
    detector_subparsers = detector.add_subparsers(dest="detector_command", required=True)
    detector_replay = detector_subparsers.add_parser(
        "replay",
        help="Run generated detector rules over a pcap trace.",
    )
    detector_replay.add_argument("--pcap", type=Path, required=True, help="Input pcap trace.")
    detector_replay.add_argument(
        "--source-kind",
        choices=[kind.value for kind in TraceSourceKind],
        required=True,
        help="Trace provenance. Only real benign traces support FP estimates.",
    )
    detector_replay.add_argument(
        "--mechanism",
        action="append",
        default=[],
        help="Mechanism id to replay; may repeat. Defaults to all mechanisms supported by the backend.",
    )
    detector_replay.add_argument(
        "--backend",
        choices=[backend.value for backend in DetectorReplayBackend],
        default=DetectorReplayBackend.BPF.value,
        help="Independent detector backend. Defaults to bpf.",
    )
    detector_replay.add_argument("--trace-name", help="Human-readable trace name.")
    detector_replay.add_argument("--origin-url", help="Trace source URL or citation.")
    detector_replay.add_argument("--trace-license", help="Trace license or access policy.")
    detector_replay.add_argument(
        "--filtering-assumption",
        action="append",
        default=[],
        help="Assumption applied before interpreting matches/base rates; may repeat.",
    )
    detector_replay.add_argument(
        "--tcpdump-binary",
        default="tcpdump",
        help="tcpdump binary path. Defaults to tcpdump.",
    )
    detector_replay.add_argument(
        "--tshark-binary",
        default="tshark",
        help="tshark binary path for --backend tshark_display_filter. Defaults to tshark.",
    )
    detector_replay.add_argument(
        "--suricata-binary",
        default="suricata",
        help="Suricata binary path for --backend suricata_rule. Defaults to suricata.",
    )
    _add_output_arg(detector_replay)
    detector_replay_corpus = detector_subparsers.add_parser(
        "replay-corpus",
        help="Run generated detector rules over a JSON manifest of pcap traces.",
    )
    detector_replay_corpus.add_argument(
        "--trace-manifest",
        type=Path,
        required=True,
        help="JSON detector trace manifest with pcap paths and source provenance.",
    )
    detector_replay_corpus.add_argument(
        "--mechanism",
        action="append",
        default=[],
        help="Mechanism id to replay; may repeat. Defaults to all mechanisms supported by the backend.",
    )
    detector_replay_corpus.add_argument(
        "--backend",
        choices=[backend.value for backend in DetectorReplayBackend],
        default=DetectorReplayBackend.BPF.value,
        help="Independent detector backend. Defaults to bpf.",
    )
    detector_replay_corpus.add_argument(
        "--tcpdump-binary",
        default="tcpdump",
        help="tcpdump binary path. Defaults to tcpdump.",
    )
    detector_replay_corpus.add_argument(
        "--tshark-binary",
        default="tshark",
        help="tshark binary path for --backend tshark_display_filter. Defaults to tshark.",
    )
    detector_replay_corpus.add_argument(
        "--suricata-binary",
        default="suricata",
        help="Suricata binary path for --backend suricata_rule. Defaults to suricata.",
    )
    _add_output_arg(detector_replay_corpus)
    detector_rules = detector_subparsers.add_parser(
        "rules",
        help="Generate public-safe detector rule artifacts from catalog locators.",
    )
    detector_rules.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory that receives generated detector rule files.",
    )
    _add_output_arg(detector_rules)
    detector_windows = detector_subparsers.add_parser(
        "windows-guidance",
        help="Generate Windows pktmon/ETW capture guidance for detector replay.",
    )
    _add_output_arg(detector_windows)

    scrub = subparsers.add_parser("scrub", help="Run offline scrubber helpers.")
    scrub_subparsers = scrub.add_subparsers(dest="scrub_command", required=True)
    scrub_pcap_cmd = scrub_subparsers.add_parser(
        "pcap",
        help="Scrub a supported mechanism from a classic Ethernet pcap.",
    )
    scrub_pcap_cmd.add_argument("--mechanism", required=True, help="Mechanism id to scrub.")
    scrub_pcap_cmd.add_argument(
        "--input-pcap",
        type=Path,
        required=True,
        help="Input classic Ethernet pcap.",
    )
    scrub_pcap_cmd.add_argument(
        "--output-pcap",
        type=Path,
        required=True,
        help="Output pcap after scrubbing.",
    )
    _add_output_arg(scrub_pcap_cmd)

    pcap = subparsers.add_parser("pcap", help="Decode pcap/tap carrier artifacts.")
    pcap_subparsers = pcap.add_subparsers(dest="pcap_command", required=True)
    pcap_decode = pcap_subparsers.add_parser(
        "decode",
        help="Decode one parser-visible carrier pcap into a payload report.",
    )
    pcap_decode.add_argument("--mechanism", required=True, help="Mechanism id to decode.")
    pcap_decode.add_argument("--pcap", type=Path, required=True, help="Input classic pcap.")
    pcap_decode.add_argument("--session-id", help="Stable session id for the decode report.")
    pcap_decode.add_argument(
        "--tshark-binary",
        default="tshark",
        help="tshark binary for optional dissector provenance. Defaults to tshark.",
    )
    _add_expected_payload_args(pcap_decode)
    _add_reliability_args(pcap_decode)
    _add_output_arg(pcap_decode)

    timing = subparsers.add_parser("timing", help="Run timing-channel measurement helpers.")
    timing_subparsers = timing.add_subparsers(dest="timing_command", required=True)
    timing_sweep = timing_subparsers.add_parser(
        "sweep",
        help="Run a local baseline jitter run and timing-quantum sweep.",
    )
    timing_sweep.add_argument("--mechanism", required=True, help="Timing mechanism id.")
    _add_payload_args(timing_sweep, required=True)
    timing_sweep.add_argument("--run-id", help="Stable run id for the sweep.")
    timing_sweep.add_argument(
        "--quantum-s",
        action="append",
        type=float,
        required=True,
        help="Timing quantum in seconds; repeat to sweep multiple quanta.",
    )
    _add_timing_sweep_pacing_args(timing_sweep)
    _add_output_arg(timing_sweep)
    timing_observed_sweep = timing_subparsers.add_parser(
        "observed-sweep",
        help="Ingest observed timing traces and recovered bytes into a sweep report.",
    )
    timing_observed_sweep.add_argument("--mechanism", required=True, help="Timing mechanism id.")
    _add_payload_args(timing_observed_sweep, required=True)
    timing_observed_sweep.add_argument("--run-id", help="Stable run id for the sweep.")
    timing_observed_sweep.add_argument(
        "--trace-json",
        type=Path,
        required=True,
        help="Observed trace JSON with baseline/trials offsets and recovered_hex bytes.",
    )
    _add_timing_sweep_pacing_args(timing_observed_sweep)
    _add_output_arg(timing_observed_sweep)

    matrix = subparsers.add_parser("matrix", help="Generate support/reviewer matrices.")
    matrix_subparsers = matrix.add_subparsers(dest="matrix_command", required=True)
    matrix_generate = matrix_subparsers.add_parser(
        "generate",
        help="Generate the evidence support matrix.",
    )
    matrix_generate.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Output format. Defaults to markdown.",
    )
    _add_output_arg(matrix_generate)

    crosshost = subparsers.add_parser(
        "crosshost",
        help="Index Alice/Bob cross-host evidence artifacts.",
    )
    crosshost_subparsers = crosshost.add_subparsers(dest="crosshost_command", required=True)
    crosshost_public_index = crosshost_subparsers.add_parser(
        "public-index",
        help="Write a public-safe index for Alice/Bob run directories.",
    )
    crosshost_public_index.add_argument(
        "--run-dir",
        type=Path,
        action="append",
        required=True,
        help="Alice/Bob result directory; may be repeated.",
    )
    _add_output_arg(crosshost_public_index)

    claims = subparsers.add_parser(
        "claims",
        help="Generate paper claim ledgers from public-safe evidence indexes.",
    )
    claims_subparsers = claims.add_subparsers(dest="claims_command", required=True)
    claims_ledger = claims_subparsers.add_parser(
        "ledger",
        help="Write a claim ledger from one or more cross-host public indexes.",
    )
    claims_ledger.add_argument(
        "--crosshost-index",
        type=Path,
        action="append",
        default=[],
        help="Public-safe Alice/Bob index; may be repeated.",
    )
    claims_ledger.add_argument(
        "--subliminal-control-report",
        type=Path,
        action="append",
        default=[],
        help="Subliminal-control report; may be repeated.",
    )
    _add_output_arg(claims_ledger)
    subliminal_controls = claims_subparsers.add_parser(
        "subliminal-controls",
        help="Summarize Class-G crypto transcript honest-random controls.",
    )
    subliminal_controls.add_argument(
        "--transcript-json",
        type=Path,
        action="append",
        required=True,
        help="ECDSA or RSA-PSS crypto transcript JSON; may be repeated.",
    )
    subliminal_controls.add_argument(
        "--min-control-signatures",
        type=int,
        default=DEFAULT_MIN_CONTROL_SIGNATURES,
        help=f"Minimum honest-random controls required. Defaults to {DEFAULT_MIN_CONTROL_SIGNATURES}.",
    )
    subliminal_controls.add_argument(
        "--min-p-value",
        type=float,
        default=DEFAULT_MIN_P_VALUE,
        help=f"Minimum two-sided bit-balance p-value. Defaults to {DEFAULT_MIN_P_VALUE}.",
    )
    _add_output_arg(subliminal_controls)

    dataset = subparsers.add_parser("dataset", help="Build the reusable telemetry dataset.")
    dataset_subparsers = dataset.add_subparsers(dest="dataset_command", required=True)
    dataset_build = dataset_subparsers.add_parser(
        "build",
        help="Round-trip every usable mechanism and write a versioned dataset corpus.",
    )
    dataset_build.add_argument("--run-id", required=True, help="Stable dataset run id.")
    dataset_build.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory that receives the <run-id>/ dataset corpus.",
    )
    dataset_build.add_argument(
        "--payload",
        default="celatim",
        help="UTF-8 probe payload round-tripped through each mechanism. Defaults to 'celatim'.",
    )
    dataset_build.add_argument(
        "--generated-at",
        default="",
        help="ISO-8601 provenance timestamp. Defaults to the current UTC time.",
    )
    _add_output_arg(dataset_build)

    scorecard = subparsers.add_parser(
        "scorecard", help="Generate the technique deployment-readiness scorecard."
    )
    scorecard_subparsers = scorecard.add_subparsers(dest="scorecard_command", required=True)
    scorecard_generate = scorecard_subparsers.add_parser(
        "generate",
        help="Score every usable mechanism against the H1-H10/S1-S10 requirements.",
    )
    scorecard_generate.add_argument(
        "--format",
        choices=("markdown", "matrix", "json"),
        default="markdown",
        help="markdown summary, full per-mechanism matrix, or json. Defaults to markdown.",
    )
    scorecard_generate.add_argument(
        "--claim-ledger",
        type=Path,
        help="Claim-ledger v2 JSON used as the scorecard's execution evidence source.",
    )
    _add_output_arg(scorecard_generate)

    guidance = subparsers.add_parser("guidance", help="Generate public guidance artifacts.")
    guidance_subparsers = guidance.add_subparsers(dest="guidance_command", required=True)
    guidance_generate = guidance_subparsers.add_parser(
        "generate",
        help="Generate detector and scrubber guidance Markdown.",
    )
    _add_output_arg(guidance_generate)
    guidance_windows = guidance_subparsers.add_parser(
        "windows-capture",
        help="Generate Windows pktmon/ETW capture guidance Markdown.",
    )
    _add_output_arg(guidance_windows)

    figures = subparsers.add_parser("figures", help="Generate catalog-derived paper figures.")
    figures_subparsers = figures.add_subparsers(dest="figures_command", required=True)
    figures_generate = figures_subparsers.add_parser(
        "generate",
        help="Generate SVG paper figures from the catalog.",
    )
    figures_generate.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory that receives generated SVG figure files.",
    )
    figures_generate.add_argument(
        "--rates",
        type=Path,
        help="Path to protocol_rates.toml. Defaults to the packaged rate table.",
    )
    _add_output_arg(figures_generate)

    rates = subparsers.add_parser("rates", help="Inspect protocol rate assumptions.")
    rates_subparsers = rates.add_subparsers(dest="rates_command", required=True)
    rates_show = rates_subparsers.add_parser(
        "show",
        help="Show carrier-unit rate assumptions used for throughput figures.",
    )
    rates_show.add_argument(
        "--rates",
        type=Path,
        help="Path to protocol_rates.toml. Defaults to the packaged rate table.",
    )
    rates_show.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="json",
        help="Output format. Defaults to json.",
    )
    _add_output_arg(rates_show)

    schema = subparsers.add_parser("schema", help="Show checked-in JSON schemas.")
    schema_subparsers = schema.add_subparsers(dest="schema_command", required=True)
    schema_list = schema_subparsers.add_parser("list", help="List packaged JSON schemas.")
    _add_output_arg(schema_list)
    schema_show = schema_subparsers.add_parser("show", help="Show one JSON schema.")
    schema_show.add_argument(
        "--name",
        choices=[summary.name for summary in list_schemas()],
        default="evidence-run-v1",
        help="Schema name. Defaults to evidence-run-v1.",
    )
    _add_output_arg(schema_show)

    docs = subparsers.add_parser("docs", help="Show packaged documentation.")
    docs_subparsers = docs.add_subparsers(dest="docs_command", required=True)
    docs_list = docs_subparsers.add_parser("list", help="List packaged docs.")
    _add_output_arg(docs_list)
    docs_show = docs_subparsers.add_parser("show", help="Show one packaged doc.")
    docs_show.add_argument(
        "--name",
        choices=doc_names(),
        required=True,
        help="Packaged doc name.",
    )
    _add_output_arg(docs_show)

    doctor = subparsers.add_parser(
        "doctor",
        help="Run non-invasive preflight checks for reviewer artifact scenarios.",
    )
    doctor.add_argument(
        "--scenario-dir",
        type=Path,
        help="Directory of *.toml scenario specs. Defaults to packaged smoke scenarios.",
    )
    doctor.add_argument(
        "--artifact-dir",
        type=Path,
        help="Check that this artifact directory can be created and written.",
    )
    doctor.add_argument(
        "--require-tool",
        action="append",
        default=[],
        help="Require an external command to be installed; may be repeated.",
    )
    doctor.add_argument(
        "--optional-extra",
        action="append",
        choices=sorted(PACKAGE_EXTRA_MODULES),
        default=[],
        help="Warn if a package extra's Python modules are unavailable; may be repeated.",
    )
    doctor.add_argument(
        "--require-extra",
        action="append",
        choices=sorted(PACKAGE_EXTRA_MODULES),
        default=[],
        help="Require a package extra's Python modules to be importable; may be repeated.",
    )
    doctor.add_argument(
        "--require-testbed-profile",
        action="append",
        choices=testbed_profile_ids(),
        default=[],
        help="Require tools, extras, and privileges for a named testbed profile; may be repeated.",
    )
    _add_output_arg(doctor)

    roundtrip = subparsers.add_parser(
        "roundtrip", help="Encode and decode payload bytes in one run."
    )
    _add_profile_args(roundtrip, required=False)
    _add_scenario_source_args(roundtrip)
    _add_payload_args(roundtrip, required=False)
    _add_pacing_args(roundtrip)
    _add_reliability_args(roundtrip)
    _add_transport_arg(roundtrip)
    roundtrip.add_argument(
        "--capture-pcap",
        type=Path,
        help="Capture live endpoint traffic for packet or daemon transports.",
    )
    _add_expected_payload_args(roundtrip)
    _add_output_arg(roundtrip)

    args = parser.parse_args(raw_argv)
    args._invocation = (program_name, *raw_argv)
    if args.command == "transfer":
        return transfer_cli.run_transfer_command(args)
    with catalog_path(args.catalog) as catalog:
        args.catalog = catalog
        if args.command == "send":
            return cli_endpoints.send_main(args)
        if args.command == "recv":
            return cli_endpoints.recv_main(args)
        if args.command == "evidence" and args.evidence_command == "run":
            return _evidence_run_main(args)
        if args.command == "evidence" and args.evidence_command == "index":
            return _evidence_index_main(args)
        if args.command == "evidence" and args.evidence_command == "public-index":
            return _evidence_public_index_main(args)
        if args.command == "bundle" and args.bundle_command == "manifest":
            return _bundle_manifest_main(args)
        if args.command == "bundle" and args.bundle_command == "verify":
            return _bundle_verify_main(args)
        if args.command == "bundle" and args.bundle_command == "public-manifest":
            return _bundle_public_manifest_main(args)
        if args.command == "bundle" and args.bundle_command == "public-verify":
            return _bundle_public_verify_main(args)
        if args.command == "scenario" and args.scenario_command == "list":
            return _scenario_list_main(args)
        if args.command == "scenario" and args.scenario_command == "plan":
            return _scenario_plan_main(args)
        if args.command == "scenario" and args.scenario_command == "ids":
            return _scenario_ids_main(args)
        if args.command == "scenario" and args.scenario_command == "run":
            return _scenario_run_main(args)
        if args.command == "mechanism" and args.mechanism_command == "list":
            return _mechanism_list_main(args)
        if args.command == "mechanism" and args.mechanism_command == "show":
            return _mechanism_show_main(args)
        if args.command == "lab":
            return _lab_main(args)
        if args.command == "testbed" and args.testbed_command == "requirements":
            return _testbed_requirements_main(args)
        if args.command == "testbed" and args.testbed_command == "qemu-preflight":
            return _testbed_qemu_preflight_main(args)
        if args.command == "detector" and args.detector_command == "replay":
            return _detector_replay_main(args)
        if args.command == "detector" and args.detector_command == "replay-corpus":
            return _detector_replay_corpus_main(args)
        if args.command == "detector" and args.detector_command == "rules":
            return _detector_rules_main(args)
        if args.command == "detector" and args.detector_command == "windows-guidance":
            return _detector_windows_guidance_main(args)
        if args.command == "scrub" and args.scrub_command == "pcap":
            return _scrub_pcap_main(args)
        if args.command == "pcap" and args.pcap_command == "decode":
            return _pcap_decode_main(args)
        if args.command == "timing" and args.timing_command == "sweep":
            return _timing_sweep_main(args)
        if args.command == "timing" and args.timing_command == "observed-sweep":
            return _timing_observed_sweep_main(args)
        if args.command == "matrix" and args.matrix_command == "generate":
            return _matrix_generate_main(args)
        if args.command == "crosshost" and args.crosshost_command == "public-index":
            return _crosshost_public_index_main(args)
        if args.command == "claims" and args.claims_command == "ledger":
            return _claim_ledger_main(args)
        if args.command == "claims" and args.claims_command == "subliminal-controls":
            return _subliminal_controls_main(args)
        if args.command == "dataset" and args.dataset_command == "build":
            return _dataset_build_main(args)
        if args.command == "scorecard" and args.scorecard_command == "generate":
            return _scorecard_generate_main(args)
        if args.command == "guidance" and args.guidance_command == "generate":
            return _guidance_generate_main(args)
        if args.command == "guidance" and args.guidance_command == "windows-capture":
            return _detector_windows_guidance_main(args)
        if args.command == "figures" and args.figures_command == "generate":
            return _figures_generate_main(args)
        if args.command == "rates" and args.rates_command == "show":
            return _rates_show_main(args)
        if args.command == "schema" and args.schema_command == "show":
            return _schema_show_main(args)
        if args.command == "schema" and args.schema_command == "list":
            return _schema_list_main(args)
        if args.command == "docs" and args.docs_command == "list":
            return _docs_list_main(args)
        if args.command == "docs" and args.docs_command == "show":
            return _docs_show_main(args)
        if args.command == "doctor":
            return _doctor_main(args)
        if args.command == "roundtrip":
            return cli_endpoints.roundtrip_main(args)
    raise AssertionError(f"unknown command: {args.command}")


def _add_profile_args(parser: argparse.ArgumentParser, *, required: bool) -> None:
    parser.add_argument(
        "--mechanism",
        required=required,
        help="Mechanism id from the catalog. Defaults to the selected scenario mechanism.",
    )
    parser.add_argument("--session-id", help="Stable session id. Defaults to a random id.")


def _add_scenario_source_args(parser: argparse.ArgumentParser) -> None:
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--scenario", type=Path, help="Path to a scenario TOML spec.")
    source.add_argument(
        "--scenario-id",
        help="Scenario id to resolve from --scenario-dir or packaged smoke scenarios.",
    )
    parser.add_argument(
        "--scenario-dir",
        type=Path,
        help="Directory of *.toml scenario specs for --scenario-id.",
    )


def _add_payload_args(parser: argparse.ArgumentParser, *, required: bool) -> None:
    group = parser.add_mutually_exclusive_group(required=required)
    group.add_argument("--message", help="UTF-8 text payload. Defaults to scenario payload.")
    group.add_argument("--hex", dest="hex_payload", help="Hex-encoded binary payload.")
    group.add_argument("--file", type=Path, help="Binary payload file.")


def _add_control_payload_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--control-message", help="UTF-8 benign-control payload.")
    group.add_argument("--control-hex", help="Hex-encoded benign-control payload.")
    group.add_argument("--control-file", type=Path, help="Binary benign-control payload file.")
    group.add_argument(
        "--control-random-bytes",
        type=_positive_int,
        metavar="N",
        help="Generate N random benign-control payload bytes.",
    )


def _add_expected_payload_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--expect",
        "--expected-message",
        dest="expect_message",
        help="UTF-8 expected decoded payload.",
    )
    group.add_argument(
        "--expect-hex",
        "--expected-hex",
        dest="expect_hex",
        help="Hex-encoded expected decoded payload.",
    )
    group.add_argument(
        "--expect-file",
        "--expected-file",
        dest="expect_file",
        type=Path,
        help="Binary expected decoded payload file.",
    )


def _add_pacing_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--unit-rate-hz", type=float, help="Carrier units per second.")
    parser.add_argument("--symbol-period-s", type=float, help="Seconds between carrier units.")
    parser.add_argument(
        "--base-delay-s", type=float, default=0.0, help="Initial delay before sending."
    )
    parser.add_argument("--timing-quantum-s", type=float, help="Timing-channel quantum in seconds.")
    parser.add_argument(
        "--decode-tolerance-s", type=float, help="Timing decode tolerance in seconds."
    )
    parser.add_argument("--timeout-s", type=float, help="Receive timeout in seconds.")
    parser.add_argument("--adaptive", action="store_true", help="Allow adaptive pacing.")
    parser.add_argument(
        "--jitter-sample-window",
        type=int,
        default=0,
        help="Number of samples to reserve for jitter/noise-floor measurement.",
    )


def _add_timing_sweep_pacing_args(parser: argparse.ArgumentParser) -> None:
    rate = parser.add_mutually_exclusive_group(required=True)
    rate.add_argument("--unit-rate-hz", type=float, help="Carrier units per second.")
    rate.add_argument("--symbol-period-s", type=float, help="Seconds between carrier units.")
    parser.add_argument(
        "--base-delay-s", type=float, default=0.0, help="Initial delay before sending."
    )
    parser.add_argument(
        "--decode-tolerance-s", type=float, help="Timing decode tolerance in seconds."
    )
    parser.add_argument("--timeout-s", type=float, help="Receive timeout in seconds.")
    parser.add_argument("--adaptive", action="store_true", help="Allow adaptive pacing.")
    parser.add_argument(
        "--jitter-sample-window",
        type=int,
        default=0,
        help="Number of baseline samples requested for jitter/noise-floor measurement.",
    )


def _add_reliability_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-receive-attempts", type=int, help="Receive attempts before failure.")
    parser.add_argument("--retry-backoff-s", type=float, help="Seconds between receive retries.")
    parser.add_argument(
        "--max-retransmissions",
        type=int,
        help="Maximum loss-triggered retransmit requests for capable transports.",
    )
    parser.add_argument(
        "--no-duplicate-suppression",
        action="store_true",
        help="Reject retransmitted duplicate chunks instead of suppressing identical duplicates.",
    )


def _add_output_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", type=Path, help="Write JSON to this path. Defaults to stdout.")


def _add_artifact_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        help="Write carrier artifacts under this directory and include their hashes in JSON.",
    )


def _add_log_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--run-id", help="Stable run id for evidence/log correlation.")
    parser.add_argument(
        "--log-dir",
        type=Path,
        help="Write structured JSONL run logs under this directory.",
    )


def _add_lab_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--sender-ns", default="snd", help="Sender network namespace name.")
    parser.add_argument("--receiver-ns", default="rcv", help="Receiver network namespace name.")
    parser.add_argument("--sender-iface", default="vs", help="Sender veth interface name.")
    parser.add_argument("--receiver-iface", default="vr", help="Receiver veth interface name.")
    parser.add_argument("--sender-ipv4-cidr", default="10.10.0.1/24", help="Sender IPv4 CIDR.")
    parser.add_argument(
        "--receiver-ipv4-cidr",
        default="10.10.0.2/24",
        help="Receiver IPv4 CIDR.",
    )
    parser.add_argument("--mtu", type=int, default=16000, help="Veth MTU.")
    parser.add_argument("--ip-binary", default="ip", help="iproute2 binary path.")
    parser.add_argument("--ethtool-binary", default="ethtool", help="ethtool binary path.")
    parser.add_argument(
        "--keep-offloads",
        action="store_true",
        help="Leave veth offload settings unchanged.",
    )
    parser.add_argument(
        "--no-cleanup-existing",
        action="store_true",
        help="Do not delete existing namespaces before lab up.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Write the command plan without changing host network state.",
    )


def _add_transport_arg(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--transport-dir",
        type=Path,
        help="Use file transport records in this directory instead of only JSON envelope handoff.",
    )
    group.add_argument(
        "--pcap-dir",
        type=Path,
        help="Use pcap capture artifacts in this directory.",
    )
    group.add_argument(
        "--timed-transport",
        action="store_true",
        help="Use a timed in-process transport and include per-symbol timing evidence.",
    )
    group.add_argument(
        "--transcript-json",
        help="Use or write a transcript JSON path/template for transcript transports.",
    )
    group.add_argument(
        "--afpacket-ipv4",
        action="store_true",
        help="Use privileged AF_PACKET Ethernet/IPv4 TCP/UDP frame I/O.",
    )
    parser.add_argument("--afpacket-sender-interface", default="vs", help=argparse.SUPPRESS)
    parser.add_argument("--afpacket-receiver-interface", default="vr", help=argparse.SUPPRESS)
    parser.add_argument("--afpacket-src-mac", default="02:00:00:00:00:01", help=argparse.SUPPRESS)
    parser.add_argument("--afpacket-dst-mac", default="02:00:00:00:00:02", help=argparse.SUPPRESS)
    parser.add_argument("--afpacket-src-ip", default="10.10.0.1", help=argparse.SUPPRESS)
    parser.add_argument("--afpacket-dst-ip", default="10.10.0.2", help=argparse.SUPPRESS)
    parser.add_argument("--afpacket-src-port", type=int, default=40000, help=argparse.SUPPRESS)
    parser.add_argument("--afpacket-dst-port", type=int, default=443, help=argparse.SUPPRESS)
    parser.add_argument(
        "--afpacket-protocol",
        choices=["tcp", "udp"],
        default="tcp",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--afpacket-timeout-s", type=float, default=10.0, help=argparse.SUPPRESS)
    parser.add_argument("--expected-frames", type=int, help=argparse.SUPPRESS)
    parser.add_argument(
        "--allow-partial-afpacket",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--afpacket-capture-pcap", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--afpacket-capture-namespace", default="rcv", help=argparse.SUPPRESS)
    parser.add_argument("--afpacket-capture-interface", help=argparse.SUPPRESS)
    parser.add_argument(
        "--afpacket-capture-filter",
        nargs="*",
        default=(),
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--afpacket-capture-snaplen",
        type=int,
        default=65535,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--allow-missing-afpacket-capture",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--transport-capture-pcap", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--transport-transcript-json", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--endpoint-cross-host", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--endpoint-sender-node", help=argparse.SUPPRESS)
    parser.add_argument("--endpoint-sender-ip", help=argparse.SUPPRESS)
    parser.add_argument("--endpoint-sender-mac", help=argparse.SUPPRESS)
    parser.add_argument("--endpoint-receiver-node", help=argparse.SUPPRESS)
    parser.add_argument("--endpoint-receiver-ip", help=argparse.SUPPRESS)
    parser.add_argument("--endpoint-receiver-mac", help=argparse.SUPPRESS)


def _evidence_run_main(args: argparse.Namespace) -> int:
    config = cli_endpoints.evidence_config_from_args(args)
    result = run_evidence(
        config,
        args.catalog,
        command=args._invocation,
    )
    return _write_json(result.to_json(), args.output)


def _evidence_index_main(args: argparse.Namespace) -> int:
    result = build_evidence_index(args.paths, path_root=args.path_root)
    return _write_json(result.to_json(), args.output)


def _evidence_public_index_main(args: argparse.Namespace) -> int:
    result = build_public_evidence_index(args.evidence_index)
    return _write_json(result.to_json(), args.output)


def _bundle_manifest_main(args: argparse.Namespace) -> int:
    manifest = build_reviewer_bundle_manifest(
        bundle_name=args.bundle_name,
        bundle_root=args.bundle_root,
        doctor_path=args.doctor,
        scenario_inventory_path=args.scenarios,
        evidence_index_path=args.evidence_index,
        paper_table_path=args.paper_table,
        package_wheel_path=args.package_wheel,
        lockfile_path=args.lockfile,
        detector_replay_paths=args.detector_replay or (),
        scrub_report_paths=args.scrub_report or (),
        scenario_spec_paths=args.scenario_spec or (),
        testbed_package_paths=args.testbed_package or (),
        testbed_preflight_paths=args.testbed_preflight or (),
    )
    return _write_json(manifest.to_json(), args.output)


def _bundle_verify_main(args: argparse.Namespace) -> int:
    result = verify_reviewer_bundle_manifest(args.manifest)
    write_status = _write_json(result.to_json(), args.output)
    if write_status != 0:
        return write_status
    return 0 if result.ok else 1


def _bundle_public_manifest_main(args: argparse.Namespace) -> int:
    with catalog_path(args.catalog) as catalog:
        manifest = build_public_bundle_manifest(
            bundle_name=args.bundle_name,
            bundle_root=args.bundle_root,
            catalog_path=catalog,
            support_matrix_path=args.support_matrix,
            detector_scrub_guidance_path=args.detector_scrub_guidance,
            scenario_inventory_path=args.scenarios,
            scenario_execution_plan_path=args.execution_plan,
            testbed_requirements_path=args.testbed_requirements,
            evidence_index_path=args.evidence_index,
            reviewer_manifest_path=args.reviewer_manifest,
            reviewer_verification_path=args.reviewer_verification,
            paper_table_path=args.paper_table,
            detector_rule_artifact_paths=args.detector_rule_artifact or (),
            windows_capture_guidance_path=args.windows_capture_guidance,
        )
    return _write_json(manifest.to_json(), args.output)


def _bundle_public_verify_main(args: argparse.Namespace) -> int:
    result = verify_public_bundle_manifest(args.manifest)
    write_status = _write_json(result.to_json(), args.output)
    if write_status != 0:
        return write_status
    return 0 if result.ok else 1


def _scenario_list_main(args: argparse.Namespace) -> int:
    with scenario_dir_path(args.scenario_dir) as scenario_dir:
        inventory = build_scenario_inventory(scenario_dir)
    return _write_json(inventory.to_json(), args.output)


def _scenario_plan_main(args: argparse.Namespace) -> int:
    with scenario_dir_path(args.scenario_dir) as scenario_dir:
        plan = build_scenario_execution_plan(scenario_dir)
    return _write_json(plan.to_json(), args.output)


def _scenario_ids_main(args: argparse.Namespace) -> int:
    with scenario_dir_path(args.scenario_dir) as scenario_dir:
        ids = scenario_execution_ids(
            scenario_dir,
            default_included_only=args.default_included,
        )
    return _write_text("".join(f"{scenario_id}\n" for scenario_id in ids), args.output)


def _scenario_run_main(args: argparse.Namespace) -> int:
    if args.scenario is not None:
        config = load_scenario(args.scenario)
    else:
        with scenario_dir_path(args.scenario_dir) as scenario_dir:
            config = load_scenario_by_id(scenario_dir, args.scenario_id)
    if any(value is not None for value in (args.message, args.hex_payload, args.file)):
        config = replace(config, payload=_payload_from_args(args))
    if args.artifact_dir is not None:
        config = replace(config, artifact_dir=str(args.artifact_dir))
    if args.log_dir is not None or args.run_id is not None:
        config = replace(
            config,
            log_dir=str(args.log_dir) if args.log_dir is not None else config.log_dir,
            run_id=args.run_id if args.run_id is not None else config.run_id,
        )
    reliability = _reliability_from_args(args)
    if reliability is not None:
        config = replace(config, reliability=reliability)
    if (
        args.transport_dir is not None
        or args.pcap_dir is not None
        or args.timed_transport
        or args.afpacket_ipv4
    ):
        config = replace(config, transport=_transport_config_from_args(args))
    if getattr(args, "transport_capture_pcap", None) is not None:
        config = replace(
            config,
            transport=replace(
                config.transport,
                capture_pcap=str(args.transport_capture_pcap),
            ),
        )
    if getattr(args, "transport_transcript_json", None) is not None:
        if config.transport.kind == "http2_hyper_h2":
            config = replace(
                config,
                transport=replace(
                    config.transport,
                    http2_transcript_json=str(args.transport_transcript_json),
                ),
            )
            result = run_evidence(config, args.catalog, command=args._invocation)
            return _write_json(result.to_json(), args.output)
        if config.transport.kind == "http3_aioquic_reserved_settings":
            config = replace(
                config,
                transport=replace(
                    config.transport,
                    http3_transcript_json=str(args.transport_transcript_json),
                ),
            )
            result = run_evidence(config, args.catalog, command=args._invocation)
            return _write_json(result.to_json(), args.output)
        if config.transport.kind == "quic_aioquic_connection_id":
            config = replace(
                config,
                transport=replace(
                    config.transport,
                    quic_transcript_json=str(args.transport_transcript_json),
                ),
            )
            result = run_evidence(config, args.catalog, command=args._invocation)
            return _write_json(result.to_json(), args.output)
        config = replace(
            config,
            transport=replace(
                config.transport,
                crypto_transcript_json=str(args.transport_transcript_json),
            ),
        )
    result = run_evidence(config, args.catalog, command=args._invocation)
    return _write_json(result.to_json(), args.output)


def _mechanism_list_main(args: argparse.Namespace) -> int:
    summaries = list_mechanism_summaries(
        catalog_path=args.catalog,
        usable_only=args.usable_only,
        transport_kind=args.transport_kind,
    )
    documents = [summary.to_json() for summary in summaries]
    if args.format == "text":
        lines = []
        for summary in documents:
            transports = ",".join(summary["transport_kinds"]) or "-"
            scenarios = ",".join(summary["scenario_ids"]) or "-"
            lines.append(
                "\t".join(
                    (
                        summary["id"],
                        summary["protocol"],
                        f"class={summary['carrier_class']}",
                        f"status={summary['adapter_status']}",
                        f"transports={transports}",
                        f"scenarios={scenarios}",
                    )
                )
            )
        return _write_text("".join(f"{line}\n" for line in lines), args.output)
    return _write_json(
        {
            "command": "mechanism list",
            "mechanism_count": len(documents),
            "filters": {
                "usable_only": args.usable_only,
                "transport_kind": args.transport_kind,
            },
            "mechanisms": documents,
        },
        args.output,
    )


def _mechanism_show_main(args: argparse.Namespace) -> int:
    document = get_mechanism_detail(args.mechanism_id, catalog_path=args.catalog).to_json()
    if args.format == "json":
        return _write_json(document, args.output)
    mechanism = document["mechanism"]
    adapter = document["adapter"]
    scenario_ids = sorted(
        path["scenario_id"] for path in adapter["paths"] if path["scenario_id"] is not None
    )
    lines = [
        f"id: {mechanism['id']}",
        f"name: {mechanism['name']}",
        f"protocol: {mechanism['protocol']}",
        f"layer: {mechanism['layer']}",
        f"carrier_class: {mechanism['carrier_class']}",
        f"capacity_model: {mechanism['capacity_model']}",
        f"raw_capacity_bits: {mechanism['raw_capacity_bits']}",
        f"usable: {mechanism['usable']}",
        f"adapter_status: {adapter['status']}",
        f"transports: {','.join(adapter['transport_kinds']) or '-'}",
        f"scenarios: {','.join(scenario_ids) or '-'}",
    ]
    return _write_text("".join(f"{line}\n" for line in lines), args.output)


def _lab_main(args: argparse.Namespace) -> int:
    config = _netns_pair_config_from_args(args)
    if args.dry_run:
        return _write_json(
            manage_netns_lab(args.lab_command, config, dry_run=True).to_json(),
            args.output,
        )
    pair = NetnsPair(config)
    if args.lab_command == "up":
        pair.up()
    else:
        pair.down()
    return _write_json(
        {
            "command": f"lab {args.lab_command}",
            "topology": _netns_pair_config_to_json(config),
        },
        args.output,
    )


def _testbed_requirements_main(args: argparse.Namespace) -> int:
    inventory = build_testbed_requirements_inventory(args.profile)
    return _write_json(inventory.to_json(), args.output)


def _testbed_qemu_preflight_main(args: argparse.Namespace) -> int:
    guest_config = QemuGuestConfig(
        disk_image=args.disk_image,
        qemu_binary=args.qemu_binary,
        memory_mib=args.memory_mib,
        smp=args.smp,
        mac_address=args.mac_address,
        netdev_id=args.netdev_id,
        network_device=args.network_device,
        drive_interface=args.drive_interface,
        disk_format=args.disk_format or None,
        enable_kvm=not args.no_kvm,
        snapshot=not args.no_snapshot,
        display=None if args.no_display else args.display,
        machine=args.machine,
        cpu=args.cpu,
        extra_args=tuple(args.extra_arg),
    )
    tap_config = HostTapConfig(
        tap_name=args.tap_name,
        host_ipv4_cidr=None if args.no_host_ipv4 else args.host_ipv4_cidr,
        mtu=args.mtu,
        ip_binary=args.ip_binary,
        owner=args.owner,
        group=args.group,
        cleanup_existing=not args.no_cleanup_existing,
    )
    report = build_qemu_tap_preflight_report(
        guest_config,
        tap_config,
        tcpdump_binary=args.tcpdump_binary,
        kvm_device=args.dev_kvm,
    )
    return _write_json(report.to_json(), args.output)


def _detector_replay_main(args: argparse.Namespace) -> int:
    selected = _detector_replay_mechanisms(args)
    report = replay_detectors_on_pcap(
        selected,
        args.pcap,
        source_kind=args.source_kind,
        trace_name=args.trace_name,
        origin_url=args.origin_url,
        license=args.trace_license,
        filtering_assumptions=tuple(args.filtering_assumption),
        backend=args.backend,
        tcpdump_path=args.tcpdump_binary,
        tshark_path=args.tshark_binary,
        suricata_path=args.suricata_binary,
        command=args._invocation,
    )
    write_status = _write_json(report.to_json(), args.output)
    if write_status != 0:
        return write_status
    return 0 if report.ok else 1


def _detector_replay_corpus_main(args: argparse.Namespace) -> int:
    selected = _detector_replay_mechanisms(args)
    report = replay_detector_corpus(
        selected,
        load_trace_manifest(args.trace_manifest),
        backend=args.backend,
        tcpdump_path=args.tcpdump_binary,
        tshark_path=args.tshark_binary,
        suricata_path=args.suricata_binary,
        command=args._invocation,
    )
    write_status = _write_json(report.to_json(), args.output)
    if write_status != 0:
        return write_status
    return 0 if report.ok else 1


def _detector_replay_mechanisms(args: argparse.Namespace) -> list[Mechanism]:
    mechanisms = load_mechanisms(args.catalog)
    mechanisms_by_id = {mechanism.id: mechanism for mechanism in mechanisms}
    if not args.mechanism:
        return default_replay_mechanisms(mechanisms, backend=args.backend)
    selected = []
    for mechanism_id in args.mechanism:
        try:
            selected.append(mechanisms_by_id[mechanism_id])
        except KeyError as exc:
            raise ValueError(f"unknown mechanism: {mechanism_id}") from exc
    return selected


def _detector_rules_main(args: argparse.Namespace) -> int:
    mechanisms = load_mechanisms(args.catalog)
    write_detector_rule_artifacts(mechanisms, args.output_dir)
    manifest = detector_rule_manifest(mechanisms, output_dir=args.output_dir)
    return _write_json({"command": "detector_rules", **manifest}, args.output)


def _detector_windows_guidance_main(args: argparse.Namespace) -> int:
    return _write_text(windows_pktmon_guidance_markdown(), args.output)


def _scrub_pcap_main(args: argparse.Namespace) -> int:
    report = scrub_pcap(
        args.mechanism,
        args.input_pcap,
        args.output_pcap,
        command=args._invocation,
    )
    write_status = _write_json(report.to_json(), args.output)
    if write_status != 0:
        return write_status
    return 0 if report.ok else 1


def _pcap_decode_main(args: argparse.Namespace) -> int:
    report = decode_pcap(
        _profile(args.mechanism, args.catalog),
        args.pcap,
        expected_payload=_expected_payload_from_args(args),
        session_id=args.session_id,
        reliability=_reliability_from_args(args),
        tshark_path=args.tshark_binary,
    )
    write_status = _write_json(report.to_json(), args.output)
    if write_status != 0:
        return write_status
    return 0 if report.ok else 1


def _timing_sweep_main(args: argparse.Namespace) -> int:
    profile = _profile(args.mechanism, args.catalog)
    report = run_timing_sweep(
        profile,
        _payload_from_args(args),
        quanta_s=args.quantum_s,
        base_pacing=_timing_sweep_pacing_from_args(args),
        run_id=args.run_id,
    )
    return _write_json(report.to_json(), args.output)


def _timing_observed_sweep_main(args: argparse.Namespace) -> int:
    profile = _profile(args.mechanism, args.catalog)
    payload = _payload_from_args(args)
    trace = _read_json_mapping(args.trace_json)
    report = run_observed_timing_sweep(
        profile,
        payload,
        baseline=_observed_timing_case_from_mapping(
            _required_mapping(trace, "baseline", args.trace_json),
            args.trace_json,
            "baseline",
        ),
        trials=tuple(
            _observed_timing_case_from_mapping(trial, args.trace_json, f"trials[{index}]")
            for index, trial in enumerate(
                _required_sequence(trace, "trials", args.trace_json),
            )
        ),
        base_pacing=_timing_sweep_pacing_from_args(args),
        baseline_payload=_baseline_payload_from_trace(trace, args.trace_json),
        run_id=args.run_id or _optional_str(trace, "run_id", args.trace_json),
        path_kind=_optional_str(trace, "path_kind", args.trace_json) or "observed_trace",
        path_metadata=_optional_mapping(trace, "path_metadata", args.trace_json),
    )
    return _write_json(report.to_json(), args.output)


def _matrix_generate_main(args: argparse.Namespace) -> int:
    mechanisms = load_mechanisms(args.catalog)
    if args.format == "json":
        return _write_json(support_matrix_report(mechanisms).to_json(), args.output)
    return _write_text(support_matrix_markdown(mechanisms), args.output)


def _crosshost_public_index_main(args: argparse.Namespace) -> int:
    document = build_crosshost_public_index(args.run_dir, load_mechanisms(args.catalog))
    return _write_json(document, args.output)


def _claim_ledger_main(args: argparse.Namespace) -> int:
    indexes = [load_crosshost_public_index(path) for path in args.crosshost_index]
    subliminal_reports = [
        load_subliminal_control_report(path) for path in args.subliminal_control_report
    ]
    document = build_claim_ledger(
        load_mechanisms(args.catalog),
        crosshost_indexes=indexes,
        subliminal_control_reports=subliminal_reports,
    )
    return _write_json(document, args.output)


def _subliminal_controls_main(args: argparse.Namespace) -> int:
    document = build_subliminal_control_report(
        args.transcript_json,
        min_control_signatures=args.min_control_signatures,
        min_p_value=args.min_p_value,
    )
    write_status = _write_json(document, args.output)
    if write_status != 0:
        return write_status
    return 0 if document["ok"] else 1


def _dataset_build_main(args: argparse.Namespace) -> int:
    from datetime import datetime

    from .analysis.dataset import build_manifest, build_records, carriers_by_id, write_dataset

    mechanisms = [m for m in load_mechanisms(args.catalog) if m.is_usable_channel]
    payload = args.payload.encode("utf-8")
    catalog_sha256 = hashlib.sha256(Path(args.catalog).read_bytes()).hexdigest()
    generated_at = args.generated_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        generator_version = metadata.version("celatim")
    except metadata.PackageNotFoundError:
        generator_version = "0+unknown"

    records = build_records(mechanisms, payload=payload)
    carriers = carriers_by_id(mechanisms, payload=payload)
    manifest = build_manifest(
        records,
        run_id=args.run_id,
        generated_at=generated_at,
        catalog_sha256=catalog_sha256,
        generator_version=generator_version,
    )
    root = write_dataset(
        args.output_dir,
        run_id=args.run_id,
        records=records,
        manifest=manifest,
        carriers=carriers,
    )
    return _write_json(
        {
            "command": "dataset_build",
            "run_id": args.run_id,
            "dataset_root": str(root),
            "total_usable": manifest["total_usable"],
            "substantiated": manifest["substantiated"],
            "round_trip_ok": manifest["round_trip_ok"],
            "carrier_bytes_records": manifest["carrier_bytes_records"],
            "tier_counts": manifest["tier_counts"],
        },
        args.output,
    )


def _scorecard_generate_main(args: argparse.Namespace) -> int:
    from .assurance.scorecard import (
        build_scorecard,
        scorecard_markdown,
        scorecard_matrix_markdown,
    )

    claim_ledger = json.loads(args.claim_ledger.read_text()) if args.claim_ledger else None
    report = build_scorecard(load_mechanisms(args.catalog), claim_ledger=claim_ledger)
    if args.format == "json":
        return _write_json(report.to_json(), args.output)
    if args.format == "matrix":
        return _write_text(scorecard_matrix_markdown(report), args.output)
    return _write_text(scorecard_markdown(report), args.output)


def _guidance_generate_main(args: argparse.Namespace) -> int:
    return _write_text(detector_scrub_guidance_markdown(load_mechanisms(args.catalog)), args.output)


def _figures_generate_main(args: argparse.Namespace) -> int:
    mechanisms = load_mechanisms(args.catalog)
    with protocol_rates_path(args.rates) as rates_path:
        rates = load_protocol_rates(rates_path)
    write_catalog_figures(mechanisms, args.output_dir, protocol_rates=rates)
    return _write_json(
        {
            "command": "figures_generate",
            "figure_count": len(catalog_figure_artifacts(mechanisms, rates)),
            "output_dir": str(args.output_dir),
            "figures": [
                artifact.to_json() for artifact in catalog_figure_artifacts(mechanisms, rates)
            ],
        },
        args.output,
    )


def _rates_show_main(args: argparse.Namespace) -> int:
    mechanisms = load_mechanisms(args.catalog)
    with protocol_rates_path(args.rates) as rates_path:
        rates = load_protocol_rates(rates_path)
    if args.format == "markdown":
        return _write_text(protocol_rates_markdown(mechanisms, rates), args.output)
    return _write_json(
        {
            "command": "rates_show",
            "rate_count": len(rates),
            "rates": [rate.to_json() for rate in rates],
        },
        args.output,
    )


def _schema_show_main(args: argparse.Namespace) -> int:
    return _write_text(schema_text(args.name), args.output)


def _schema_list_main(args: argparse.Namespace) -> int:
    return _write_json({"schemas": [summary.to_json() for summary in list_schemas()]}, args.output)


def _docs_list_main(args: argparse.Namespace) -> int:
    return _write_json({"docs": [{"name": name} for name in doc_names()]}, args.output)


def _docs_show_main(args: argparse.Namespace) -> int:
    return _write_text(doc_text(args.name), args.output)


def _doctor_main(args: argparse.Namespace) -> int:
    result = run_doctor(
        catalog=args.catalog,
        scenario_dir=args.scenario_dir,
        artifact_dir=args.artifact_dir,
        required_tools=tuple(args.require_tool),
        optional_extras=tuple(args.optional_extra),
        required_extras=tuple(args.require_extra),
        testbed_profiles=tuple(args.require_testbed_profile),
    )
    write_status = _write_json(result.to_json(), args.output)
    if write_status != 0:
        return write_status
    return 0 if result.ok else 1


def _profile(mechanism_id: str, catalog: Path) -> MechanismProfile:
    return MechanismProfile.from_catalog(mechanism_id, catalog)


def _payload_from_args(args: argparse.Namespace) -> bytes:
    if args.message is not None:
        return args.message.encode()
    if args.hex_payload is not None:
        return bytes.fromhex(args.hex_payload)
    return args.file.read_bytes()


def _expected_payload_from_args(args: argparse.Namespace) -> bytes | None:
    if args.expect_message is not None:
        return args.expect_message.encode()
    if args.expect_hex is not None:
        return bytes.fromhex(args.expect_hex)
    if args.expect_file is not None:
        return args.expect_file.read_bytes()
    return None


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return parsed


def _read_json_mapping(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text())
    except OSError as exc:
        raise SystemExit(f"{path}: could not read JSON trace: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"{path}: invalid JSON at line {exc.lineno} column {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(document, dict):
        raise SystemExit(f"{path}: expected a JSON object")
    return document


def _required_mapping(mapping: dict[str, Any], key: str, path: Path) -> dict[str, Any]:
    if key not in mapping:
        raise SystemExit(f"{path}: missing required object '{key}'")
    value = mapping[key]
    if not isinstance(value, dict):
        raise SystemExit(f"{path}: '{key}' must be an object")
    return value


def _optional_mapping(mapping: dict[str, Any], key: str, path: Path) -> dict[str, Any] | None:
    if key not in mapping or mapping[key] is None:
        return None
    value = mapping[key]
    if not isinstance(value, dict):
        raise SystemExit(f"{path}: '{key}' must be an object or null")
    return value


def _required_sequence(mapping: dict[str, Any], key: str, path: Path) -> list[Any]:
    if key not in mapping:
        raise SystemExit(f"{path}: missing required array '{key}'")
    value = mapping[key]
    if not isinstance(value, list):
        raise SystemExit(f"{path}: '{key}' must be an array")
    return value


def _optional_str(mapping: dict[str, Any], key: str, path: Path) -> str | None:
    if key not in mapping or mapping[key] is None:
        return None
    value = mapping[key]
    if not isinstance(value, str):
        raise SystemExit(f"{path}: '{key}' must be a string or null")
    return value


def _optional_float(mapping: dict[str, Any], key: str, path: Path, context: str) -> float | None:
    if key not in mapping or mapping[key] is None:
        return None
    return _json_number(mapping[key], path, f"{context}.{key}")


def _observed_timing_case_from_mapping(
    value: Any,
    path: Path,
    context: str,
) -> ObservedTimingCaseInput:
    if not isinstance(value, dict):
        raise SystemExit(f"{path}: {context} must be an object")
    if "observed_offsets_s" not in value:
        raise SystemExit(f"{path}: {context}.observed_offsets_s is required")
    if "recovered_hex" not in value:
        raise SystemExit(f"{path}: {context}.recovered_hex is required")
    observed_offsets = _observed_offsets_from_value(
        value["observed_offsets_s"],
        path,
        f"{context}.observed_offsets_s",
    )
    recovered = _hex_bytes_from_value(value["recovered_hex"], path, f"{context}.recovered_hex")
    return ObservedTimingCaseInput(
        observed_offsets_s=observed_offsets,
        recovered_payload=recovered,
        quantum_s=_optional_float(value, "quantum_s", path, context),
        session_id=_optional_str(value, "session_id", path),
    )


def _observed_offsets_from_value(value: Any, path: Path, context: str) -> tuple[float, ...]:
    if not isinstance(value, list):
        raise SystemExit(f"{path}: {context} must be an array")
    return tuple(
        _json_number(offset, path, f"{context}[{index}]") for index, offset in enumerate(value)
    )


def _baseline_payload_from_trace(
    trace: dict[str, Any],
    path: Path,
) -> bytes | None:
    if "baseline_payload_hex" not in trace or trace["baseline_payload_hex"] is None:
        return None
    return _hex_bytes_from_value(trace["baseline_payload_hex"], path, "baseline_payload_hex")


def _hex_bytes_from_value(value: Any, path: Path, context: str) -> bytes:
    if not isinstance(value, str):
        raise SystemExit(f"{path}: {context} must be a hex string")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise SystemExit(f"{path}: {context} is not valid hex: {exc}") from exc


def _json_number(value: Any, path: Path, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise SystemExit(f"{path}: {context} must be a number")
    return float(value)


def _transport_config_from_args(args: argparse.Namespace) -> TransportConfig:
    if getattr(args, "afpacket_ipv4", False):
        return TransportConfig(
            "afpacket_ipv4",
            sender_interface=args.afpacket_sender_interface,
            receiver_interface=args.afpacket_receiver_interface,
            src_mac=args.afpacket_src_mac,
            dst_mac=args.afpacket_dst_mac,
            src_ip=args.afpacket_src_ip,
            dst_ip=args.afpacket_dst_ip,
            src_port=args.afpacket_src_port,
            dst_port=args.afpacket_dst_port,
            protocol=args.afpacket_protocol,
            timeout_s=args.afpacket_timeout_s,
            expected_frames=args.expected_frames,
            require_expected_frames=not args.allow_partial_afpacket,
            capture_pcap=None
            if args.afpacket_capture_pcap is None
            else str(args.afpacket_capture_pcap),
            capture_namespace=args.afpacket_capture_namespace,
            capture_interface=args.afpacket_capture_interface,
            capture_filter=tuple(args.afpacket_capture_filter),
            capture_snaplen=args.afpacket_capture_snaplen,
            capture_require_output=not args.allow_missing_afpacket_capture,
        )
    if getattr(args, "timed_transport", False):
        return TransportConfig("timed_memory")
    if getattr(args, "pcap_dir", None) is not None:
        return TransportConfig("pcap", str(args.pcap_dir))
    if getattr(args, "transport_dir", None) is None:
        return TransportConfig()
    return TransportConfig("file", str(args.transport_dir))


def _netns_pair_config_from_args(args: argparse.Namespace) -> NetnsPairConfig:
    return NetnsPairConfig(
        sender_ns=args.sender_ns,
        receiver_ns=args.receiver_ns,
        sender_iface=args.sender_iface,
        receiver_iface=args.receiver_iface,
        sender_ipv4_cidr=args.sender_ipv4_cidr,
        receiver_ipv4_cidr=args.receiver_ipv4_cidr,
        mtu=args.mtu,
        ip_binary=args.ip_binary,
        ethtool_binary=args.ethtool_binary,
        disable_offloads=not args.keep_offloads,
        cleanup_existing=not args.no_cleanup_existing,
    )


def _netns_pair_config_to_json(config: NetnsPairConfig) -> dict[str, Any]:
    return {
        "sender_ns": config.sender_ns,
        "receiver_ns": config.receiver_ns,
        "sender_iface": config.sender_iface,
        "receiver_iface": config.receiver_iface,
        "sender_ipv4_cidr": config.sender_ipv4_cidr,
        "receiver_ipv4_cidr": config.receiver_ipv4_cidr,
        "mtu": config.mtu,
        "ip_binary": config.ip_binary,
        "ethtool_binary": config.ethtool_binary,
        "disable_offloads": config.disable_offloads,
        "cleanup_existing": config.cleanup_existing,
    }


def _reliability_from_args(args: argparse.Namespace) -> ReliabilityPolicy | None:
    if (
        getattr(args, "max_receive_attempts", None) is None
        and getattr(args, "retry_backoff_s", None) is None
        and getattr(args, "max_retransmissions", None) is None
        and not getattr(args, "no_duplicate_suppression", False)
    ):
        return None
    return ReliabilityPolicy(
        max_receive_attempts=args.max_receive_attempts
        if args.max_receive_attempts is not None
        else 1,
        retry_backoff_s=args.retry_backoff_s if args.retry_backoff_s is not None else 0.0,
        suppress_duplicate_chunks=not args.no_duplicate_suppression,
        max_retransmissions=args.max_retransmissions if args.max_retransmissions is not None else 0,
    )


def _timing_sweep_pacing_from_args(args: argparse.Namespace) -> PacingConfig:
    return PacingConfig(
        unit_rate_hz=args.unit_rate_hz,
        symbol_period_s=args.symbol_period_s,
        base_delay_s=args.base_delay_s,
        decode_tolerance_s=args.decode_tolerance_s,
        timeout_s=args.timeout_s,
        adaptive=args.adaptive,
        jitter_sample_window=args.jitter_sample_window,
    )


def _write_json(document: dict[str, Any], output: Path | None) -> int:
    text = json.dumps(document, sort_keys=True) + "\n"
    return _write_text(text, output)


def _write_text(text: str, output: Path | None) -> int:
    if output is None:
        sys.stdout.write(text)
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text)
    return 0


__all__ = [
    "main",
    "paper_figures_main",
    "paper_macros_main",
    "paper_tables_main",
    "session_main",
    "support_matrix_main",
]
