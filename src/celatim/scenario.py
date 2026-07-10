"""Scenario-level evidence runs.

This module gives the library a stable "run evidence" shape: one scenario executes a
covert payload and a benign control payload through the same mechanism, records
byte-for-byte recovery, and includes adapter/parser validation metadata when available.
Privileged packet paths and daemon-backed scenarios can plug into the same result
schema as their transports are extracted from ``experiments/``.
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
import sys
import tomllib
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field, replace
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from time import monotonic, time
from typing import Any
from uuid import uuid4

from .adapter import CarrierUnit
from .crypto_transcript import (
    ECDSA_NONCE_TRANSPORT_KIND,
    RSA_PSS_SALT_TRANSPORT_KIND,
    EcdsaNonceTranscriptConfig,
    EcdsaNonceTranscriptTransport,
    RsaPssSaltTranscriptConfig,
    RsaPssSaltTranscriptTransport,
)
from .detect import DetectorProvenanceRecord, detector_provenance_for
from .observer import (
    ObserverMutationControlRecord,
    ObserverValidationRecord,
    ParserProvenanceRecord,
    observer_mutation_controls_for,
    observer_validations_for,
    parser_provenance_for,
)
from .resources import catalog_path as packaged_catalog_path
from .session import (
    ChannelSession,
    EndpointOsMetadata,
    EvidenceRecord,
    InMemoryTransport,
    MechanismProfile,
    PacingConfig,
    ReliabilityPolicy,
    Symbol,
    ThroughputProfile,
    TimingProfile,
    TimingSample,
    TimingTrace,
    local_endpoint_os,
)
from .testbed import (
    HTTP2_HYPER_H2_TRANSPORT_KIND,
    HTTP3_AIOQUIC_SETTINGS_TRANSPORT_KIND,
    MESSAGE_CARRIER_KINDS,
    QUIC_AIOQUIC_TRANSPORT_KIND,
    AioquicConnectionIdPathConfig,
    AioquicH3SettingsPathConfig,
    DnsEdnsPaddingPathConfig,
    HyperH2PingPathConfig,
    Ipv4PacketPathConfig,
    MessageCarrierTransport,
    PacketProtocol,
    TcpdumpCapture,
    TcpdumpCaptureConfig,
    run_afpacket_roundtrip,
    run_aioquic_connection_id_roundtrip,
    run_aioquic_h3_settings_roundtrip,
    run_dns_edns0_padding_roundtrip,
    run_hyper_h2_ping_roundtrip,
)
from .transports import FileTransport, PcapTransport, TimedMemoryTransport

SCHEMA_VERSION = "celatim.evidence_run.v1"
RUN_LOG_SCHEMA_VERSION = "celatim.run_log.v1"
SPEC_SCHEMA_VERSION = "celatim.scenario.v1"
SCENARIO_INVENTORY_SCHEMA_VERSION = "celatim.scenario_inventory.v1"
SCENARIO_EXECUTION_PLAN_SCHEMA_VERSION = "celatim.scenario_execution_plan.v1"
SCENARIO_EVIDENCE_TIERS = (
    "in_memory_regression",
    "crafted_production_path",
    "real_pdu_packet_path",
    "real_daemon_path",
    "real_crypto_path",
    "timing_path",
    "cross_stack_vm_path",
)
SCENARIO_PRIVILEGE_LEVELS = (
    "none",
    "cap_net_raw",
    "cap_net_admin",
    "root",
    "docker",
    "kvm",
)
SCENARIO_EXECUTION_MODES = (
    "default_non_privileged",
    "non_privileged_with_dependencies",
    "requires_linux_capability",
    "requires_root",
    "requires_docker",
    "requires_kvm",
    "manual",
)
SCENARIO_EXECUTION_PLAN_TARGETS = (
    "make reviewer-doctor",
    "make reviewer-scenarios",
    "make reviewer-full",
    "make public-bundle",
)


@dataclass(frozen=True)
class TransportConfig:
    kind: str = "memory"
    root: str | None = None
    sender_interface: str = "vs"
    receiver_interface: str = "vr"
    src_mac: str = "02:00:00:00:00:01"
    dst_mac: str = "02:00:00:00:00:02"
    src_ip: str = "10.10.0.1"
    dst_ip: str = "10.10.0.2"
    src_port: int = 40000
    dst_port: int = 443
    protocol: str = "tcp"
    timeout_s: float | None = 10.0
    expected_frames: int | None = None
    require_expected_frames: bool = True
    capture_pcap: str | None = None
    capture_namespace: str = "rcv"
    capture_interface: str | None = None
    capture_filter: tuple[str, ...] = ()
    capture_snaplen: int = 65535
    capture_require_output: bool = True
    dns_sender_namespace: str = "snd"
    dns_resolver_namespace: str = "rcv"
    dns_query_name: str = "covert.test"
    dns_answer_address: str | None = None
    dns_padding_optcode: int = 12
    dns_tries: int = 1
    dns_capture_start_delay_s: float = 1.0
    dns_require_answer: bool = True
    crypto_transcript_json: str | None = None
    crypto_curve: str = "NIST521p"
    crypto_hash_name: str = "sha256"
    crypto_mgf_hash_name: str = "sha256"
    crypto_nonce_payload_bits: int = 256
    crypto_salt_payload_bits: int = 256
    crypto_key_bits: int = 2048
    crypto_public_exponent: int = 65537
    crypto_honest_random_control_signatures: int = 2
    crypto_message_prefix: str = "celatim/ecdsa-nonce"
    http2_transcript_json: str | None = None
    http2_validate_ack: bool = True
    http3_transcript_json: str | None = None
    http3_validate_receiver_settings: bool = True
    quic_transcript_json: str | None = None
    quic_validate_server_response: bool = True


@dataclass(frozen=True)
class ScenarioConfig:
    scenario_id: str
    mechanism_id: str
    payload: bytes
    description: str | None = None
    evidence_tier: str = "in_memory_regression"
    privilege: str = "none"
    expected_runtime_s: float | None = None
    requires_tools: tuple[str, ...] = ()
    requires_extras: tuple[str, ...] = ()
    control_payload: bytes = b""
    control_kind: str = "empty_payload"
    pacing: PacingConfig | None = None
    reliability: ReliabilityPolicy | None = None
    spec_path: str | None = None
    artifact_dir: str | None = None
    log_dir: str | None = None
    run_id: str | None = None
    transport: TransportConfig = field(default_factory=TransportConfig)


@dataclass(frozen=True)
class ScenarioMetadata:
    description: str | None
    evidence_tier: str
    privilege: str
    expected_runtime_s: float | None
    requires_tools: tuple[str, ...]
    requires_extras: tuple[str, ...]

    @classmethod
    def from_config(cls, config: ScenarioConfig) -> ScenarioMetadata:
        return cls(
            description=config.description,
            evidence_tier=config.evidence_tier,
            privilege=config.privilege,
            expected_runtime_s=config.expected_runtime_s,
            requires_tools=config.requires_tools,
            requires_extras=config.requires_extras,
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "evidence_tier": self.evidence_tier,
            "privilege": self.privilege,
            "expected_runtime_s": self.expected_runtime_s,
            "requires_tools": list(self.requires_tools),
            "requires_extras": list(self.requires_extras),
        }


@dataclass(frozen=True)
class ArtifactRecord:
    kind: str
    path: str
    sha256: str
    size_bytes: int

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class ReproducibilityMetadata:
    catalog_path: str
    catalog_sha256: str
    package_version: str
    python_version: str
    platform: str
    system: str
    release: str
    machine: str
    command: tuple[str, ...] = ()
    scenario_spec_path: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "catalog_path": self.catalog_path,
            "catalog_sha256": self.catalog_sha256,
            "package_version": self.package_version,
            "python_version": self.python_version,
            "platform": self.platform,
            "system": self.system,
            "release": self.release,
            "machine": self.machine,
            "command": list(self.command),
            "scenario_spec_path": self.scenario_spec_path,
        }


@dataclass(frozen=True)
class ScenarioSpecInfo:
    path: Path
    scenario_id: str
    mechanism_id: str
    description: str | None = None
    evidence_tier: str = "in_memory_regression"
    privilege: str = "none"
    expected_runtime_s: float | None = None
    requires_tools: tuple[str, ...] = ()
    requires_extras: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "scenario_id": self.scenario_id,
            "mechanism_id": self.mechanism_id,
            "description": self.description,
            "evidence_tier": self.evidence_tier,
            "privilege": self.privilege,
            "expected_runtime_s": self.expected_runtime_s,
            "requires_tools": list(self.requires_tools),
            "requires_extras": list(self.requires_extras),
        }


@dataclass(frozen=True)
class ScenarioInventory:
    schema_version: str
    path: str
    scenario_count: int
    scenario_ids: tuple[str, ...]
    evidence_tier_counts: dict[str, int]
    privilege_counts: dict[str, int]
    expected_runtime_s_total: float | None
    required_tools: tuple[str, ...]
    required_extras: tuple[str, ...]
    scenarios: tuple[ScenarioSpecInfo, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "path": self.path,
            "scenario_count": self.scenario_count,
            "scenario_ids": list(self.scenario_ids),
            "evidence_tier_counts": dict(self.evidence_tier_counts),
            "privilege_counts": dict(self.privilege_counts),
            "expected_runtime_s_total": self.expected_runtime_s_total,
            "required_tools": list(self.required_tools),
            "required_extras": list(self.required_extras),
            "scenarios": [scenario.to_json() for scenario in self.scenarios],
        }


@dataclass(frozen=True)
class ScenarioExecutionPlanItem:
    path: str
    scenario_id: str
    mechanism_id: str
    description: str | None
    evidence_tier: str
    privilege: str
    expected_runtime_s: float | None
    requires_tools: tuple[str, ...]
    requires_extras: tuple[str, ...]
    execution_mode: str
    default_included: bool
    skip_reason: str | None
    reviewer_command: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "scenario_id": self.scenario_id,
            "mechanism_id": self.mechanism_id,
            "description": self.description,
            "evidence_tier": self.evidence_tier,
            "privilege": self.privilege,
            "expected_runtime_s": self.expected_runtime_s,
            "requires_tools": list(self.requires_tools),
            "requires_extras": list(self.requires_extras),
            "execution_mode": self.execution_mode,
            "default_included": self.default_included,
            "skip_reason": self.skip_reason,
            "reviewer_command": list(self.reviewer_command),
        }


@dataclass(frozen=True)
class ScenarioExecutionPlan:
    schema_version: str
    generated_at_unix_s: float
    path: str
    scenario_count: int
    scenario_ids: tuple[str, ...]
    default_included_count: int
    manual_review_count: int
    evidence_tier_counts: dict[str, int]
    privilege_counts: dict[str, int]
    execution_mode_counts: dict[str, int]
    expected_runtime_s_total: float | None
    required_tools: tuple[str, ...]
    required_extras: tuple[str, ...]
    recommended_targets: tuple[str, ...]
    scenarios: tuple[ScenarioExecutionPlanItem, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at_unix_s": self.generated_at_unix_s,
            "path": self.path,
            "scenario_count": self.scenario_count,
            "scenario_ids": list(self.scenario_ids),
            "default_included_count": self.default_included_count,
            "manual_review_count": self.manual_review_count,
            "evidence_tier_counts": dict(self.evidence_tier_counts),
            "privilege_counts": dict(self.privilege_counts),
            "execution_mode_counts": dict(self.execution_mode_counts),
            "expected_runtime_s_total": self.expected_runtime_s_total,
            "required_tools": list(self.required_tools),
            "required_extras": list(self.required_extras),
            "recommended_targets": list(self.recommended_targets),
            "scenarios": [scenario.to_json() for scenario in self.scenarios],
        }


@dataclass(frozen=True)
class EvidenceCaseResult:
    case: str
    session_id: str
    expected_len: int
    recovered_len: int
    expected_sha256: str
    recovered_sha256: str
    matches: bool
    recovered_hex: str
    evidence: EvidenceRecord
    parser_validated: bool | None
    carrier_units_with_bytes: int
    carrier_unit_sha256: list[str]
    transport_kind: str
    transport_metadata: dict[str, Any] | None = None
    detector_provenance: tuple[DetectorProvenanceRecord, ...] = ()
    parser_provenance: tuple[ParserProvenanceRecord, ...] = ()
    observer_validations: tuple[ObserverValidationRecord, ...] = ()
    mutation_controls: tuple[ObserverMutationControlRecord, ...] = ()
    transport_record: str | None = None
    transport_artifact: ArtifactRecord | None = None
    artifacts: tuple[ArtifactRecord, ...] = ()


@dataclass(frozen=True)
class EvidenceRunResult:
    schema_version: str
    run_id: str
    scenario_id: str
    mechanism_id: str
    adapter_status: str
    adapter_capabilities: tuple[str, ...]
    started_at_unix_s: float
    control_kind: str
    scenario_metadata: ScenarioMetadata
    reproducibility: ReproducibilityMetadata
    run_log: ArtifactRecord | None
    covert: EvidenceCaseResult
    benign_control: EvidenceCaseResult

    @property
    def ok(self) -> bool:
        return self.covert.matches and self.benign_control.matches

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "mechanism_id": self.mechanism_id,
            "adapter_status": self.adapter_status,
            "adapter_capabilities": list(self.adapter_capabilities),
            "started_at_unix_s": self.started_at_unix_s,
            "control_kind": self.control_kind,
            "scenario_metadata": self.scenario_metadata.to_json(),
            "reproducibility": self.reproducibility.to_json(),
            "run_log": None if self.run_log is None else self.run_log.to_json(),
            "ok": self.ok,
            "covert": _case_to_json(self.covert),
            "benign_control": _case_to_json(self.benign_control),
        }


def run_evidence(
    config: ScenarioConfig,
    catalog_path: Path | str | None = None,
    command: tuple[str, ...] = (),
) -> EvidenceRunResult:
    with packaged_catalog_path(catalog_path) as catalog:
        run_id = _run_id(config.run_id)
        started_at = time()
        profile = MechanismProfile.from_catalog(config.mechanism_id, catalog)
        scenario_metadata = ScenarioMetadata.from_config(config)
        reproducibility = _reproducibility(catalog, command, config.spec_path)
        covert = _run_case(
            profile,
            "covert",
            config.scenario_id,
            payload=config.payload,
            pacing=config.pacing,
            reliability=config.reliability,
            artifact_dir=config.artifact_dir,
            transport=config.transport,
        )
        benign_control = _run_case(
            profile,
            "benign_control",
            config.scenario_id,
            config.control_payload,
            config.pacing,
            config.reliability,
            config.artifact_dir,
            config.transport,
        )
        run_log = _write_run_log(
            _effective_log_dir(config),
            run_id=run_id,
            scenario_id=config.scenario_id,
            mechanism_id=config.mechanism_id,
            started_at_unix_s=started_at,
            control_kind=config.control_kind,
            scenario_metadata=scenario_metadata,
            reproducibility=reproducibility,
            covert=covert,
            benign_control=benign_control,
        )
        return EvidenceRunResult(
            schema_version=SCHEMA_VERSION,
            run_id=run_id,
            scenario_id=config.scenario_id,
            mechanism_id=config.mechanism_id,
            adapter_status=profile.adapter.status.value,
            adapter_capabilities=tuple(sorted(c.value for c in profile.adapter.capabilities)),
            started_at_unix_s=started_at,
            control_kind=config.control_kind,
            scenario_metadata=scenario_metadata,
            reproducibility=reproducibility,
            run_log=run_log,
            covert=covert,
            benign_control=benign_control,
        )


def load_scenario(path: Path | str) -> ScenarioConfig:
    spec_path = Path(path)
    data = tomllib.loads(spec_path.read_text())
    schema_version = data.get("schema_version")
    if schema_version != SPEC_SCHEMA_VERSION:
        raise ValueError(f"{spec_path}: expected schema_version {SPEC_SCHEMA_VERSION!r}")
    return ScenarioConfig(
        scenario_id=_required_str(data, "scenario_id", spec_path),
        mechanism_id=_required_str(data, "mechanism_id", spec_path),
        payload=_payload_from_mapping(data, "payload", spec_path, required=True),
        description=_optional_str_from_mapping(data, "description", spec_path),
        evidence_tier=_enum_str_from_mapping(
            data,
            "evidence_tier",
            "in_memory_regression",
            SCENARIO_EVIDENCE_TIERS,
            spec_path,
        ),
        privilege=_enum_str_from_mapping(
            data,
            "privilege",
            "none",
            SCENARIO_PRIVILEGE_LEVELS,
            spec_path,
        ),
        expected_runtime_s=_optional_nonnegative_float_from_mapping(
            data,
            "expected_runtime_s",
            spec_path,
        ),
        requires_tools=_optional_str_tuple_from_mapping(data, "requires_tools", spec_path),
        requires_extras=_optional_str_tuple_from_mapping(data, "requires_extras", spec_path),
        control_payload=_payload_from_mapping(data, "control", spec_path, required=False),
        control_kind=_control_kind_from_mapping(data),
        pacing=_pacing_from_mapping(data.get("pacing"), spec_path),
        reliability=_reliability_from_mapping(data.get("reliability"), spec_path),
        spec_path=str(spec_path),
        artifact_dir=_artifact_dir_from_mapping(data, spec_path),
        log_dir=_optional_dir_from_mapping(data, "log_dir", spec_path),
        run_id=_optional_str_from_mapping(data, "run_id", spec_path),
        transport=_transport_from_mapping(data, spec_path),
    )


def discover_scenarios(directory: Path | str) -> list[ScenarioSpecInfo]:
    root = Path(directory)
    specs: list[ScenarioSpecInfo] = []
    for path in sorted(root.glob("*.toml")):
        config = load_scenario(path)
        specs.append(
            ScenarioSpecInfo(
                path,
                config.scenario_id,
                config.mechanism_id,
                description=config.description,
                evidence_tier=config.evidence_tier,
                privilege=config.privilege,
                expected_runtime_s=config.expected_runtime_s,
                requires_tools=config.requires_tools,
                requires_extras=config.requires_extras,
            )
        )
    return specs


def build_scenario_inventory(directory: Path | str) -> ScenarioInventory:
    root = Path(directory)
    scenarios = tuple(discover_scenarios(root))
    return ScenarioInventory(
        schema_version=SCENARIO_INVENTORY_SCHEMA_VERSION,
        path=str(root),
        scenario_count=len(scenarios),
        scenario_ids=tuple(scenario.scenario_id for scenario in scenarios),
        evidence_tier_counts=_scenario_counts(scenario.evidence_tier for scenario in scenarios),
        privilege_counts=_scenario_counts(scenario.privilege for scenario in scenarios),
        expected_runtime_s_total=_scenario_runtime_total(scenarios),
        required_tools=tuple(
            sorted({tool for scenario in scenarios for tool in scenario.requires_tools})
        ),
        required_extras=tuple(
            sorted({extra for scenario in scenarios for extra in scenario.requires_extras})
        ),
        scenarios=scenarios,
    )


def build_scenario_execution_plan(directory: Path | str) -> ScenarioExecutionPlan:
    root = Path(directory)
    scenarios = tuple(discover_scenarios(root))
    plan_items = tuple(_scenario_execution_plan_item(root, scenario) for scenario in scenarios)
    default_included_count = sum(1 for item in plan_items if item.default_included)
    return ScenarioExecutionPlan(
        schema_version=SCENARIO_EXECUTION_PLAN_SCHEMA_VERSION,
        generated_at_unix_s=time(),
        path=str(root),
        scenario_count=len(plan_items),
        scenario_ids=tuple(item.scenario_id for item in plan_items),
        default_included_count=default_included_count,
        manual_review_count=len(plan_items) - default_included_count,
        evidence_tier_counts=_scenario_counts(item.evidence_tier for item in plan_items),
        privilege_counts=_scenario_counts(item.privilege for item in plan_items),
        execution_mode_counts=_scenario_counts(item.execution_mode for item in plan_items),
        expected_runtime_s_total=_scenario_runtime_total(scenarios),
        required_tools=tuple(sorted({tool for item in plan_items for tool in item.requires_tools})),
        required_extras=tuple(
            sorted({extra for item in plan_items for extra in item.requires_extras})
        ),
        recommended_targets=SCENARIO_EXECUTION_PLAN_TARGETS,
        scenarios=plan_items,
    )


def scenario_execution_ids(
    directory: Path | str,
    *,
    default_included_only: bool = False,
) -> tuple[str, ...]:
    plan = build_scenario_execution_plan(directory)
    return tuple(
        item.scenario_id
        for item in plan.scenarios
        if item.default_included or not default_included_only
    )


def find_scenario(directory: Path | str, scenario_id: str) -> ScenarioSpecInfo:
    specs = [info for info in discover_scenarios(directory) if info.scenario_id == scenario_id]
    if not specs:
        raise ValueError(f"{scenario_id}: scenario id not found")
    if len(specs) > 1:
        paths = ", ".join(str(info.path) for info in specs)
        raise ValueError(f"{scenario_id}: scenario id is ambiguous: {paths}")
    return specs[0]


def load_scenario_by_id(directory: Path | str, scenario_id: str) -> ScenarioConfig:
    return load_scenario(find_scenario(directory, scenario_id).path)


def _scenario_counts(values: Iterable[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        label = str(value)
        counts[label] = counts.get(label, 0) + 1
    return dict(sorted(counts.items()))


def _scenario_runtime_total(scenarios: tuple[ScenarioSpecInfo, ...]) -> float | None:
    total = 0.0
    for scenario in scenarios:
        runtime = scenario.expected_runtime_s
        if runtime is None:
            return None
        total += runtime
    return total


def _scenario_execution_plan_item(
    root: Path,
    scenario: ScenarioSpecInfo,
) -> ScenarioExecutionPlanItem:
    execution_mode = _scenario_execution_mode(scenario)
    default_included = execution_mode == "default_non_privileged"
    config = load_scenario(scenario.path)
    return ScenarioExecutionPlanItem(
        path=str(scenario.path),
        scenario_id=scenario.scenario_id,
        mechanism_id=scenario.mechanism_id,
        description=scenario.description,
        evidence_tier=scenario.evidence_tier,
        privilege=scenario.privilege,
        expected_runtime_s=scenario.expected_runtime_s,
        requires_tools=scenario.requires_tools,
        requires_extras=scenario.requires_extras,
        execution_mode=execution_mode,
        default_included=default_included,
        skip_reason=None if default_included else _scenario_skip_reason(scenario),
        reviewer_command=_scenario_reviewer_command(
            root,
            scenario,
            default_included=default_included,
            transport_kind=config.transport.kind,
        ),
    )


def _scenario_execution_mode(scenario: ScenarioSpecInfo) -> str:
    if scenario.privilege == "none":
        if scenario.requires_tools or scenario.requires_extras:
            return "non_privileged_with_dependencies"
        return "default_non_privileged"
    if scenario.privilege in {"cap_net_raw", "cap_net_admin"}:
        return "requires_linux_capability"
    if scenario.privilege == "root":
        return "requires_root"
    if scenario.privilege == "docker":
        return "requires_docker"
    if scenario.privilege == "kvm":
        return "requires_kvm"
    return "manual"


def _scenario_skip_reason(scenario: ScenarioSpecInfo) -> str:
    reasons: list[str] = []
    if scenario.privilege != "none":
        reasons.append(f"requires privilege {scenario.privilege}")
    if scenario.requires_tools:
        reasons.append("requires tools " + ", ".join(scenario.requires_tools))
    if scenario.requires_extras:
        reasons.append("requires extras " + ", ".join(scenario.requires_extras))
    return "; ".join(reasons) or "requires manual review"


def _scenario_reviewer_command(
    root: Path,
    scenario: ScenarioSpecInfo,
    *,
    default_included: bool,
    transport_kind: str,
) -> tuple[str, ...]:
    command = [
        "celatim",
        "scenario",
        "run",
        "--scenario-id",
        scenario.scenario_id,
        "--scenario-dir",
        str(root),
        "--artifact-dir",
        "out/carriers",
        "--output",
        f"out/evidence/{scenario.scenario_id}.json",
    ]
    if default_included and transport_kind in {"memory", "timed_memory"}:
        command[7:7] = ["--pcap-dir", "out/pcaps"]
    return tuple(command)


def _run_case(
    profile: MechanismProfile,
    case: str,
    scenario_id: str,
    payload: bytes,
    pacing: PacingConfig | None,
    reliability: ReliabilityPolicy | None,
    artifact_dir: str | None,
    transport: TransportConfig,
) -> EvidenceCaseResult:
    session_id = f"{scenario_id}:{case}"
    failure_session = ChannelSession(profile, InMemoryTransport(), reliability=reliability)
    transport_record: str | None = None
    transport_artifact: ArtifactRecord | None = None
    transport_metadata: dict[str, Any] | None = None
    start = monotonic()
    try:
        _ensure_transport_supported(profile, transport.kind)
        if transport.kind == "file":
            if transport.root is None:
                raise ValueError("file transport requires a root directory")
            sender_transport = FileTransport(profile, Path(transport.root))
            receiver_transport = FileTransport(profile, Path(transport.root))
            sender = ChannelSession(profile, sender_transport, reliability=reliability)
            receipt = sender.send_message(payload, session_id=session_id, pacing=pacing)
            transport_record = str(sender_transport.path_for(receipt.session_id))
            transport_artifact = _file_artifact_record(transport_record, kind="transport_record")
            result = ChannelSession(
                profile, receiver_transport, reliability=reliability
            ).receive_message(receipt.session_id)
            symbols = receiver_transport.receive_symbols(receipt.session_id)
        elif transport.kind == "pcap":
            if transport.root is None:
                raise ValueError("pcap transport requires a root directory")
            sender_transport = PcapTransport(profile, Path(transport.root))
            receiver_transport = PcapTransport(profile, Path(transport.root))
            sender = ChannelSession(profile, sender_transport, reliability=reliability)
            receipt = sender.send_message(payload, session_id=session_id, pacing=pacing)
            transport_record = str(sender_transport.path_for(receipt.session_id))
            transport_artifact = _file_artifact_record(transport_record, kind="transport_record")
            result = ChannelSession(
                profile, receiver_transport, reliability=reliability
            ).receive_message(receipt.session_id)
            symbols = receiver_transport.receive_symbols(receipt.session_id)
        elif transport.kind == "memory":
            memory_transport = InMemoryTransport()
            session = ChannelSession(profile, memory_transport, reliability=reliability)
            result = session.run_roundtrip(payload, session_id=session_id, pacing=pacing)
            symbols = memory_transport.receive_symbols(session_id)
        elif transport.kind == "timed_memory":
            timed_transport = TimedMemoryTransport()
            session = ChannelSession(profile, timed_transport, reliability=reliability)
            result = session.run_roundtrip(payload, session_id=session_id, pacing=pacing)
            symbols = timed_transport.receive_symbols(session_id)
        elif transport.kind == "afpacket_ipv4":
            capture_path = _capture_path_for_case(transport, scenario_id, case)
            live = run_afpacket_roundtrip(
                profile,
                payload,
                session_id=session_id,
                config=_packet_path_config_from_transport(transport),
                pacing=pacing,
                reliability=reliability,
                capture=_capture_from_transport(transport, capture_path),
            )
            result = live.result
            symbols = list(live.symbols)
            transport_record = capture_path
            transport_artifact = _existing_file_artifact_record(
                transport_record,
                kind="transport_capture",
            )
        elif transport.kind == "dns_edns0_padding":
            capture_path = _capture_path_for_case(transport, scenario_id, case)
            if capture_path is None:
                raise ValueError("dns_edns0_padding transport requires capture_pcap")
            live = run_dns_edns0_padding_roundtrip(
                profile,
                payload,
                session_id=session_id,
                config=_dns_edns0_config_from_transport(transport, capture_path),
                pacing=pacing,
                reliability=reliability,
            )
            result = live.result
            symbols = list(live.symbols)
            transport_record = str(live.capture_pcap)
            transport_artifact = _existing_file_artifact_record(
                transport_record,
                kind="transport_capture",
            )
            transport_metadata = _dns_edns0_transport_metadata(transport, live)
        elif transport.kind in MESSAGE_CARRIER_KINDS:
            message_transport = MessageCarrierTransport(
                transport.kind, qname=transport.dns_query_name
            )
            session = ChannelSession(profile, message_transport, reliability=reliability)
            result = session.run_roundtrip(payload, session_id=session_id, pacing=pacing)
            symbols = message_transport.receive_symbols(session_id)
            transport_metadata = message_transport.metadata_for(session_id)
        elif transport.kind == HTTP2_HYPER_H2_TRANSPORT_KIND:
            transcript_path = _http2_transcript_path_for_case(transport, scenario_id, case)
            live = run_hyper_h2_ping_roundtrip(
                profile,
                payload,
                session_id=session_id,
                config=_http2_hyper_h2_config_from_transport(transport, transcript_path),
                pacing=pacing,
                reliability=reliability,
            )
            result = live.result
            symbols = list(live.symbols)
            transport_record = None if live.transcript_json is None else str(live.transcript_json)
            transport_artifact = _existing_file_artifact_record(
                transport_record,
                kind="http2_hyper_h2_transcript",
            )
            transport_metadata = live.transport_metadata
        elif transport.kind == HTTP3_AIOQUIC_SETTINGS_TRANSPORT_KIND:
            transcript_path = _http3_transcript_path_for_case(transport, scenario_id, case)
            live = run_aioquic_h3_settings_roundtrip(
                profile,
                payload,
                session_id=session_id,
                config=_http3_aioquic_settings_config_from_transport(
                    transport,
                    transcript_path,
                ),
                pacing=pacing,
                reliability=reliability,
            )
            result = live.result
            symbols = list(live.symbols)
            transport_record = None if live.transcript_json is None else str(live.transcript_json)
            transport_artifact = _existing_file_artifact_record(
                transport_record,
                kind="http3_aioquic_settings_transcript",
            )
            transport_metadata = live.transport_metadata
        elif transport.kind == QUIC_AIOQUIC_TRANSPORT_KIND:
            transcript_path = _quic_transcript_path_for_case(transport, scenario_id, case)
            live = run_aioquic_connection_id_roundtrip(
                profile,
                payload,
                session_id=session_id,
                config=_quic_aioquic_config_from_transport(transport, transcript_path),
                pacing=pacing,
                reliability=reliability,
            )
            result = live.result
            symbols = list(live.symbols)
            transport_record = None if live.transcript_json is None else str(live.transcript_json)
            transport_artifact = _existing_file_artifact_record(
                transport_record,
                kind="quic_aioquic_transcript",
            )
            transport_metadata = live.transport_metadata
        elif transport.kind == ECDSA_NONCE_TRANSPORT_KIND:
            transcript_path = _transcript_path_for_case(transport, scenario_id, case)
            crypto_transport = EcdsaNonceTranscriptTransport(
                profile,
                EcdsaNonceTranscriptConfig(
                    transcript_path=None if transcript_path is None else Path(transcript_path),
                    curve=transport.crypto_curve,
                    hash_name=transport.crypto_hash_name,
                    nonce_payload_bits=transport.crypto_nonce_payload_bits,
                    honest_random_control_signatures=(
                        transport.crypto_honest_random_control_signatures
                    ),
                    message_prefix=transport.crypto_message_prefix,
                ),
            )
            session = ChannelSession(profile, crypto_transport, reliability=reliability)
            result = session.run_roundtrip(payload, session_id=session_id, pacing=pacing)
            symbols = crypto_transport.receive_symbols(session_id)
            transport_record = transcript_path
            transport_artifact = _existing_file_artifact_record(
                transport_record,
                kind="crypto_transcript",
            )
            transport_metadata = crypto_transport.metadata_for(session_id)
        elif transport.kind == RSA_PSS_SALT_TRANSPORT_KIND:
            transcript_path = _transcript_path_for_case(transport, scenario_id, case)
            crypto_transport = RsaPssSaltTranscriptTransport(
                profile,
                RsaPssSaltTranscriptConfig(
                    transcript_path=None if transcript_path is None else Path(transcript_path),
                    key_bits=transport.crypto_key_bits,
                    public_exponent=transport.crypto_public_exponent,
                    hash_name=transport.crypto_hash_name,
                    mgf_hash_name=transport.crypto_mgf_hash_name,
                    salt_payload_bits=transport.crypto_salt_payload_bits,
                    honest_random_control_signatures=(
                        transport.crypto_honest_random_control_signatures
                    ),
                    message_prefix=transport.crypto_message_prefix,
                ),
            )
            session = ChannelSession(profile, crypto_transport, reliability=reliability)
            result = session.run_roundtrip(payload, session_id=session_id, pacing=pacing)
            symbols = crypto_transport.receive_symbols(session_id)
            transport_record = transcript_path
            transport_artifact = _existing_file_artifact_record(
                transport_record,
                kind="crypto_transcript",
            )
            transport_metadata = crypto_transport.metadata_for(session_id)
        else:
            raise ValueError(f"unsupported transport kind: {transport.kind}")
        units = _carrier_units_from_symbols(profile, symbols)
        carrier_hashes = [_carrier_hash(unit) for unit in units if unit.carrier is not None]
        artifacts = _write_artifacts(artifact_dir, scenario_id, case, units)
        parser_validated = _parser_validated(profile, session_id, units, payload)
        observer_validations = observer_validations_for(profile.id, units)
        mutation_controls = observer_mutation_controls_for(profile.id, units)
        parser_provenance = parser_provenance_for(
            profile.id,
            transport_record
            if transport.kind in {"pcap", "afpacket_ipv4", "dns_edns0_padding"}
            else None,
        )
        detector_provenance = detector_provenance_for(
            profile.mechanism,
            units,
            pcap_path=transport_record if transport.kind in {"pcap", "afpacket_ipv4"} else None,
        )
    except Exception as exc:
        result = failure_session.failure_result(
            session_id,
            exc,
            expected_payload_len=len(payload),
            elapsed_s=monotonic() - start,
            pacing=pacing,
        )
        carrier_hashes = []
        artifacts = ()
        parser_validated = False
        detector_provenance = ()
        parser_provenance = ()
        observer_validations = ()
        mutation_controls = ()
    result = replace(
        result,
        evidence=replace(result.evidence, endpoint_os=_endpoint_os_for_transport(transport)),
    )
    return EvidenceCaseResult(
        case=case,
        session_id=session_id,
        expected_len=len(payload),
        recovered_len=len(result.payload),
        expected_sha256=hashlib.sha256(payload).hexdigest(),
        recovered_sha256=hashlib.sha256(result.payload).hexdigest(),
        matches=result.payload == payload,
        recovered_hex=result.payload.hex(),
        evidence=result.evidence,
        parser_validated=parser_validated,
        observer_validations=observer_validations,
        carrier_units_with_bytes=len(carrier_hashes),
        carrier_unit_sha256=carrier_hashes,
        transport_kind=transport.kind,
        transport_metadata=transport_metadata,
        detector_provenance=detector_provenance,
        parser_provenance=parser_provenance,
        transport_record=transport_record,
        transport_artifact=transport_artifact,
        mutation_controls=mutation_controls,
        artifacts=artifacts,
    )


def _ensure_transport_supported(profile: MechanismProfile, transport_kind: str) -> None:
    if profile.adapter.supports_transport(transport_kind):
        return
    supported = ", ".join(profile.adapter.transport_kinds) or "none"
    raise ValueError(
        f"{profile.id}: transport {transport_kind!r} is not registered for this adapter; "
        f"supported transports: {supported}"
    )


def _endpoint_os_for_transport(transport: TransportConfig) -> EndpointOsMetadata:
    if transport.kind in {"memory", "timed_memory"}:
        return local_endpoint_os(
            "same_process",
            notes=("sender, receiver, and tap execute in one local Python process",),
        )
    if transport.kind in {"file", "pcap"}:
        return local_endpoint_os(
            "same_host_artifact",
            include_tap=True,
            notes=(
                "sender writes a local transport artifact; receiver decodes it on the same host",
            ),
        )
    if transport.kind == "afpacket_ipv4":
        return local_endpoint_os(
            "same_kernel_netns",
            sender_interface=transport.sender_interface,
            receiver_interface=transport.receiver_interface,
            tap_namespace=transport.capture_namespace,
            tap_interface=transport.capture_interface or transport.receiver_interface,
            include_tap=transport.capture_pcap is not None,
            notes=(
                "live AF_PACKET path uses Linux interfaces on one host; checked-in privileged scenario runs over netns/veth",
            ),
        )
    if transport.kind == "dns_edns0_padding":
        return local_endpoint_os(
            "same_kernel_netns",
            sender_namespace=transport.dns_sender_namespace,
            receiver_namespace=transport.dns_resolver_namespace,
            tap_namespace=transport.capture_namespace,
            tap_interface=transport.capture_interface or transport.receiver_interface,
            include_tap=True,
            notes=(
                "real dig client and dnsmasq resolver run in Linux network namespaces on the same kernel",
            ),
        )
    if transport.kind in MESSAGE_CARRIER_KINDS:
        return local_endpoint_os(
            "same_process",
            notes=(MESSAGE_CARRIER_KINDS[transport.kind].endpoint_note,),
        )
    if transport.kind == HTTP2_HYPER_H2_TRANSPORT_KIND:
        return local_endpoint_os(
            "same_process",
            notes=(
                "client and receiver are independent hyper-h2 H2Connection instances in one Python process",
            ),
        )
    if transport.kind == HTTP3_AIOQUIC_SETTINGS_TRANSPORT_KIND:
        return local_endpoint_os(
            "same_process",
            notes=(
                "client and receiver are independent aioquic H3Connection instances in one Python process",
                "client reserved SETTINGS value is set through a controlled local-settings hook before aioquic serializes the H3 control stream",
            ),
        )
    if transport.kind == QUIC_AIOQUIC_TRANSPORT_KIND:
        return local_endpoint_os(
            "same_process",
            notes=(
                "client and receiver are independent aioquic QuicConnection instances in one Python process",
                "client peer CID is set through a controlled pre-connect library hook before aioquic serializes the Initial datagram",
            ),
        )
    if transport.kind == ECDSA_NONCE_TRANSPORT_KIND:
        return local_endpoint_os(
            "same_process",
            notes=("local ECDSA signing, verification, and nonce-recovery transcript",),
        )
    if transport.kind == RSA_PSS_SALT_TRANSPORT_KIND:
        return local_endpoint_os(
            "same_process",
            notes=("local RSA-PSS signing, verification, and salt-recovery transcript",),
        )
    return local_endpoint_os("unknown", notes=(f"unrecognized transport kind: {transport.kind}",))


def _required_str(data: dict[str, Any], key: str, path: Path) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path}: {key} must be a non-empty string")
    return value


def _payload_from_mapping(
    data: dict[str, Any],
    prefix: str,
    path: Path,
    *,
    required: bool,
) -> bytes:
    message_key = f"{prefix}_message"
    hex_key = f"{prefix}_hex"
    file_key = f"{prefix}_file"
    present = [key for key in (message_key, hex_key, file_key) if key in data]
    if not present:
        if required:
            raise ValueError(f"{path}: one of {message_key}, {hex_key}, or {file_key} is required")
        return b""
    if len(present) != 1:
        raise ValueError(f"{path}: only one of {message_key}, {hex_key}, or {file_key} may be set")
    key = present[0]
    value = data[key]
    if not isinstance(value, str):
        raise ValueError(f"{path}: {key} must be a string")
    if key == message_key:
        return value.encode()
    if key == hex_key:
        return bytes.fromhex(value)
    payload_path = Path(value)
    if not payload_path.is_absolute():
        payload_path = path.parent / payload_path
    return payload_path.read_bytes()


def _control_kind_from_mapping(data: dict[str, Any]) -> str:
    if "control_message" in data:
        return "control_message"
    if "control_hex" in data:
        return "control_hex"
    if "control_file" in data:
        return "control_file"
    return "empty_payload"


def _artifact_dir_from_mapping(data: dict[str, Any], path: Path) -> str | None:
    return _optional_dir_from_mapping(data, "artifact_dir", path)


def _optional_dir_from_mapping(data: dict[str, Any], key: str, path: Path) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path}: {key} must be a non-empty string")
    artifact_dir = Path(value)
    if not artifact_dir.is_absolute():
        artifact_dir = path.parent / artifact_dir
    return str(artifact_dir)


def _optional_str_from_mapping(data: dict[str, Any], key: str, path: Path) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path}: {key} must be a non-empty string")
    return value


def _enum_str_from_mapping(
    data: dict[str, Any],
    key: str,
    default: str,
    allowed: tuple[str, ...],
    path: Path,
) -> str:
    value = data.get(key, default)
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{path}: {key} must be one of {', '.join(allowed)}")
    return value


def _optional_nonnegative_float_from_mapping(
    data: dict[str, Any],
    key: str,
    path: Path,
) -> float | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, int | float) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{path}: {key} must be a non-negative number")
    return float(value)


def _optional_str_tuple_from_mapping(data: dict[str, Any], key: str, path: Path) -> tuple[str, ...]:
    value = data.get(key, ())
    if not isinstance(value, list | tuple):
        raise ValueError(f"{path}: {key} must be an array of strings")
    values: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise ValueError(f"{path}: {key} must be an array of non-empty strings")
        values.append(item)
    return tuple(values)


def _transport_from_mapping(data: dict[str, Any], path: Path) -> TransportConfig:
    legacy_dir = data.get("transport_dir")
    raw = data.get("transport")
    if legacy_dir is not None and raw is not None:
        raise ValueError(f"{path}: set transport or transport_dir, not both")
    if legacy_dir is not None:
        if not isinstance(legacy_dir, str) or not legacy_dir:
            raise ValueError(f"{path}: transport_dir must be a non-empty string")
        return TransportConfig("file", _resolve_relative_path(legacy_dir, path))
    if raw is None:
        return TransportConfig()
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: transport must be a table")
    kind = raw.get("kind", "memory")
    allowed = {
        "memory",
        "file",
        "pcap",
        "timed_memory",
        "afpacket_ipv4",
        "dns_edns0_padding",
        *MESSAGE_CARRIER_KINDS,
        HTTP2_HYPER_H2_TRANSPORT_KIND,
        HTTP3_AIOQUIC_SETTINGS_TRANSPORT_KIND,
        QUIC_AIOQUIC_TRANSPORT_KIND,
        ECDSA_NONCE_TRANSPORT_KIND,
        RSA_PSS_SALT_TRANSPORT_KIND,
    }
    if not isinstance(kind, str) or kind not in allowed:
        raise ValueError(
            f"{path}: transport.kind must be memory, timed_memory, file, pcap, "
            f"afpacket_ipv4, dns_edns0_padding, a message-carrier kind, "
            f"{HTTP2_HYPER_H2_TRANSPORT_KIND}, "
            f"{HTTP3_AIOQUIC_SETTINGS_TRANSPORT_KIND}, {QUIC_AIOQUIC_TRANSPORT_KIND}, "
            f"{ECDSA_NONCE_TRANSPORT_KIND}, or {RSA_PSS_SALT_TRANSPORT_KIND}"
        )
    root = raw.get("root")
    if kind in {"memory", "timed_memory"}:
        if root is not None:
            raise ValueError(f"{path}: {kind} transport must not set root")
        return TransportConfig(kind)
    if kind == "afpacket_ipv4":
        if root is not None:
            raise ValueError(f"{path}: afpacket_ipv4 transport must not set root")
        allowed_keys = {
            "kind",
            "sender_interface",
            "receiver_interface",
            "src_mac",
            "dst_mac",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "timeout_s",
            "expected_frames",
            "require_expected_frames",
            "capture_pcap",
            "capture_namespace",
            "capture_interface",
            "capture_filter",
            "capture_snaplen",
            "capture_require_output",
        }
        unknown = sorted(set(raw) - allowed_keys)
        if unknown:
            raise ValueError(f"{path}: unknown afpacket_ipv4 transport keys: {', '.join(unknown)}")
        return TransportConfig(
            kind,
            sender_interface=_transport_str(raw, "sender_interface", "vs", path),
            receiver_interface=_transport_str(raw, "receiver_interface", "vr", path),
            src_mac=_transport_str(raw, "src_mac", "02:00:00:00:00:01", path),
            dst_mac=_transport_str(raw, "dst_mac", "02:00:00:00:00:02", path),
            src_ip=_transport_str(raw, "src_ip", "10.10.0.1", path),
            dst_ip=_transport_str(raw, "dst_ip", "10.10.0.2", path),
            src_port=_transport_int(raw, "src_port", 40000, path),
            dst_port=_transport_int(raw, "dst_port", 443, path),
            protocol=_transport_str(raw, "protocol", "tcp", path),
            timeout_s=_transport_optional_float(raw, "timeout_s", 10.0, path),
            expected_frames=_transport_optional_int(raw, "expected_frames", path),
            require_expected_frames=_transport_bool(raw, "require_expected_frames", True, path),
            capture_pcap=_transport_optional_path(raw, "capture_pcap", path),
            capture_namespace=_transport_str(raw, "capture_namespace", "rcv", path),
            capture_interface=_transport_optional_str(raw, "capture_interface", path),
            capture_filter=_transport_str_tuple(raw, "capture_filter", path),
            capture_snaplen=_transport_int(raw, "capture_snaplen", 65535, path),
            capture_require_output=_transport_bool(raw, "capture_require_output", True, path),
        )
    if kind == "dns_edns0_padding":
        if root is not None:
            raise ValueError(f"{path}: dns_edns0_padding transport must not set root")
        allowed_keys = {
            "kind",
            "src_ip",
            "dst_ip",
            "dst_port",
            "timeout_s",
            "capture_pcap",
            "capture_namespace",
            "capture_interface",
            "capture_filter",
            "capture_snaplen",
            "capture_require_output",
            "dns_sender_namespace",
            "dns_resolver_namespace",
            "dns_query_name",
            "dns_answer_address",
            "dns_padding_optcode",
            "dns_tries",
            "dns_capture_start_delay_s",
            "dns_require_answer",
        }
        unknown = sorted(set(raw) - allowed_keys)
        if unknown:
            raise ValueError(
                f"{path}: unknown dns_edns0_padding transport keys: {', '.join(unknown)}"
            )
        return TransportConfig(
            kind,
            src_ip=_transport_str(raw, "src_ip", "10.10.0.1", path),
            dst_ip=_transport_str(raw, "dst_ip", "10.10.0.2", path),
            dst_port=_transport_int(raw, "dst_port", 53, path),
            timeout_s=_transport_optional_float(raw, "timeout_s", 2.0, path),
            capture_pcap=_transport_optional_path(raw, "capture_pcap", path),
            capture_namespace=_transport_str(raw, "capture_namespace", "rcv", path),
            capture_interface=_transport_optional_str(raw, "capture_interface", path),
            capture_filter=_transport_str_tuple(raw, "capture_filter", path),
            capture_snaplen=_transport_int(raw, "capture_snaplen", 65535, path),
            capture_require_output=_transport_bool(raw, "capture_require_output", True, path),
            dns_sender_namespace=_transport_str(raw, "dns_sender_namespace", "snd", path),
            dns_resolver_namespace=_transport_str(raw, "dns_resolver_namespace", "rcv", path),
            dns_query_name=_transport_str(raw, "dns_query_name", "covert.test", path),
            dns_answer_address=_transport_optional_str(raw, "dns_answer_address", path),
            dns_padding_optcode=_transport_int(raw, "dns_padding_optcode", 12, path),
            dns_tries=_transport_int(raw, "dns_tries", 1, path),
            dns_capture_start_delay_s=_transport_float(raw, "dns_capture_start_delay_s", 1.0, path),
            dns_require_answer=_transport_bool(raw, "dns_require_answer", True, path),
        )
    if kind in MESSAGE_CARRIER_KINDS:
        if root is not None:
            raise ValueError(f"{path}: {kind} transport must not set root")
        allowed_keys = {"kind", "dns_query_name"}
        unknown = sorted(set(raw) - allowed_keys)
        if unknown:
            raise ValueError(f"{path}: unknown {kind} transport keys: {', '.join(unknown)}")
        return TransportConfig(
            kind,
            dns_query_name=_transport_str(raw, "dns_query_name", "covert.example.", path),
        )
    if kind == HTTP2_HYPER_H2_TRANSPORT_KIND:
        if root is not None:
            raise ValueError(f"{path}: {HTTP2_HYPER_H2_TRANSPORT_KIND} transport must not set root")
        allowed_keys = {
            "kind",
            "transcript_json",
            "validate_ack",
        }
        unknown = sorted(set(raw) - allowed_keys)
        if unknown:
            raise ValueError(
                f"{path}: unknown {HTTP2_HYPER_H2_TRANSPORT_KIND} transport keys: "
                f"{', '.join(unknown)}"
            )
        return TransportConfig(
            kind,
            http2_transcript_json=_transport_optional_path(raw, "transcript_json", path),
            http2_validate_ack=_transport_bool(raw, "validate_ack", True, path),
        )
    if kind == HTTP3_AIOQUIC_SETTINGS_TRANSPORT_KIND:
        if root is not None:
            raise ValueError(
                f"{path}: {HTTP3_AIOQUIC_SETTINGS_TRANSPORT_KIND} transport must not set root"
            )
        allowed_keys = {
            "kind",
            "transcript_json",
            "validate_receiver_settings",
        }
        unknown = sorted(set(raw) - allowed_keys)
        if unknown:
            raise ValueError(
                f"{path}: unknown {HTTP3_AIOQUIC_SETTINGS_TRANSPORT_KIND} transport keys: "
                f"{', '.join(unknown)}"
            )
        return TransportConfig(
            kind,
            http3_transcript_json=_transport_optional_path(raw, "transcript_json", path),
            http3_validate_receiver_settings=_transport_bool(
                raw,
                "validate_receiver_settings",
                True,
                path,
            ),
        )
    if kind == QUIC_AIOQUIC_TRANSPORT_KIND:
        if root is not None:
            raise ValueError(f"{path}: {QUIC_AIOQUIC_TRANSPORT_KIND} transport must not set root")
        allowed_keys = {
            "kind",
            "transcript_json",
            "validate_server_response",
        }
        unknown = sorted(set(raw) - allowed_keys)
        if unknown:
            raise ValueError(
                f"{path}: unknown {QUIC_AIOQUIC_TRANSPORT_KIND} transport keys: "
                f"{', '.join(unknown)}"
            )
        return TransportConfig(
            kind,
            quic_transcript_json=_transport_optional_path(raw, "transcript_json", path),
            quic_validate_server_response=_transport_bool(
                raw,
                "validate_server_response",
                True,
                path,
            ),
        )
    if kind == ECDSA_NONCE_TRANSPORT_KIND:
        if root is not None:
            raise ValueError(f"{path}: {ECDSA_NONCE_TRANSPORT_KIND} transport must not set root")
        allowed_keys = {
            "kind",
            "transcript_json",
            "curve",
            "hash_name",
            "nonce_payload_bits",
            "honest_random_control_signatures",
            "message_prefix",
        }
        unknown = sorted(set(raw) - allowed_keys)
        if unknown:
            raise ValueError(
                f"{path}: unknown {ECDSA_NONCE_TRANSPORT_KIND} transport keys: {', '.join(unknown)}"
            )
        return TransportConfig(
            kind,
            crypto_transcript_json=_transport_optional_path(raw, "transcript_json", path),
            crypto_curve=_transport_str(raw, "curve", "NIST521p", path),
            crypto_hash_name=_transport_str(raw, "hash_name", "sha256", path),
            crypto_nonce_payload_bits=_transport_int(raw, "nonce_payload_bits", 256, path),
            crypto_honest_random_control_signatures=_transport_int(
                raw,
                "honest_random_control_signatures",
                2,
                path,
            ),
            crypto_message_prefix=_transport_str(
                raw,
                "message_prefix",
                "celatim/ecdsa-nonce",
                path,
            ),
        )
    if kind == RSA_PSS_SALT_TRANSPORT_KIND:
        if root is not None:
            raise ValueError(f"{path}: {RSA_PSS_SALT_TRANSPORT_KIND} transport must not set root")
        allowed_keys = {
            "kind",
            "transcript_json",
            "key_bits",
            "public_exponent",
            "hash_name",
            "mgf_hash_name",
            "salt_payload_bits",
            "honest_random_control_signatures",
            "message_prefix",
        }
        unknown = sorted(set(raw) - allowed_keys)
        if unknown:
            raise ValueError(
                f"{path}: unknown {RSA_PSS_SALT_TRANSPORT_KIND} transport keys: "
                f"{', '.join(unknown)}"
            )
        return TransportConfig(
            kind,
            crypto_transcript_json=_transport_optional_path(raw, "transcript_json", path),
            crypto_key_bits=_transport_int(raw, "key_bits", 2048, path),
            crypto_public_exponent=_transport_int(raw, "public_exponent", 65537, path),
            crypto_hash_name=_transport_str(raw, "hash_name", "sha256", path),
            crypto_mgf_hash_name=_transport_str(raw, "mgf_hash_name", "sha256", path),
            crypto_salt_payload_bits=_transport_int(raw, "salt_payload_bits", 256, path),
            crypto_honest_random_control_signatures=_transport_int(
                raw,
                "honest_random_control_signatures",
                2,
                path,
            ),
            crypto_message_prefix=_transport_str(
                raw,
                "message_prefix",
                "celatim/rsa-pss-salt",
                path,
            ),
        )
    if not isinstance(root, str) or not root:
        raise ValueError(f"{path}: {kind} transport requires transport.root")
    return TransportConfig(kind, _resolve_relative_path(root, path))


def _packet_path_config_from_transport(transport: TransportConfig) -> Ipv4PacketPathConfig:
    return Ipv4PacketPathConfig(
        sender_interface=transport.sender_interface,
        receiver_interface=transport.receiver_interface,
        src_mac=transport.src_mac,
        dst_mac=transport.dst_mac,
        src_ip=transport.src_ip,
        dst_ip=transport.dst_ip,
        src_port=transport.src_port,
        dst_port=transport.dst_port,
        protocol=PacketProtocol(transport.protocol),
        timeout_s=transport.timeout_s,
        expected_frames=transport.expected_frames,
        require_expected_frames=transport.require_expected_frames,
    )


def _capture_from_transport(
    transport: TransportConfig,
    capture_path: str | None,
) -> TcpdumpCapture | None:
    if capture_path is None:
        return None
    return TcpdumpCapture(
        TcpdumpCaptureConfig(
            namespace=transport.capture_namespace,
            interface=transport.capture_interface or transport.receiver_interface,
            output=Path(capture_path),
            packet_count=transport.expected_frames,
            filter_expr=transport.capture_filter,
            snaplen=transport.capture_snaplen,
            require_output=transport.capture_require_output,
        )
    )


def _capture_path_for_case(
    transport: TransportConfig,
    scenario_id: str,
    case: str,
) -> str | None:
    raw = transport.capture_pcap
    if raw is None:
        return None
    safe_scenario = _safe_artifact_name(scenario_id)
    safe_case = _safe_artifact_name(case)
    if "{" in raw or "}" in raw:
        try:
            return raw.format(scenario_id=safe_scenario, case=safe_case)
        except (KeyError, ValueError) as exc:
            raise ValueError(f"invalid capture_pcap template: {raw}") from exc
    path = Path(raw)
    if path.suffix:
        return str(path.with_name(f"{path.stem}-{safe_case}{path.suffix}"))
    return str(path / f"{safe_scenario}-{safe_case}.pcap")


def _transcript_path_for_case(
    transport: TransportConfig,
    scenario_id: str,
    case: str,
) -> str | None:
    raw = transport.crypto_transcript_json
    if raw is None:
        return None
    safe_scenario = _safe_artifact_name(scenario_id)
    safe_case = _safe_artifact_name(case)
    if "{" in raw or "}" in raw:
        try:
            return raw.format(scenario_id=safe_scenario, case=safe_case)
        except (KeyError, ValueError) as exc:
            raise ValueError(f"invalid transcript_json template: {raw}") from exc
    path = Path(raw)
    if path.suffix:
        return str(path.with_name(f"{path.stem}-{safe_case}{path.suffix}"))
    return str(path / f"{safe_scenario}-{safe_case}.json")


def _http2_transcript_path_for_case(
    transport: TransportConfig,
    scenario_id: str,
    case: str,
) -> str | None:
    raw = transport.http2_transcript_json
    if raw is None:
        return None
    safe_scenario = _safe_artifact_name(scenario_id)
    safe_case = _safe_artifact_name(case)
    if "{" in raw or "}" in raw:
        try:
            return raw.format(scenario_id=safe_scenario, case=safe_case)
        except (KeyError, ValueError) as exc:
            raise ValueError(f"invalid transcript_json template: {raw}") from exc
    path = Path(raw)
    if path.suffix:
        return str(path.with_name(f"{path.stem}-{safe_case}{path.suffix}"))
    return str(path / f"{safe_scenario}-{safe_case}.json")


def _http3_transcript_path_for_case(
    transport: TransportConfig,
    scenario_id: str,
    case: str,
) -> str | None:
    raw = transport.http3_transcript_json
    if raw is None:
        return None
    safe_scenario = _safe_artifact_name(scenario_id)
    safe_case = _safe_artifact_name(case)
    if "{" in raw or "}" in raw:
        try:
            return raw.format(scenario_id=safe_scenario, case=safe_case)
        except (KeyError, ValueError) as exc:
            raise ValueError(f"invalid transcript_json template: {raw}") from exc
    path = Path(raw)
    if path.suffix:
        return str(path.with_name(f"{path.stem}-{safe_case}{path.suffix}"))
    return str(path / f"{safe_scenario}-{safe_case}.json")


def _quic_transcript_path_for_case(
    transport: TransportConfig,
    scenario_id: str,
    case: str,
) -> str | None:
    raw = transport.quic_transcript_json
    if raw is None:
        return None
    safe_scenario = _safe_artifact_name(scenario_id)
    safe_case = _safe_artifact_name(case)
    if "{" in raw or "}" in raw:
        try:
            return raw.format(scenario_id=safe_scenario, case=safe_case)
        except (KeyError, ValueError) as exc:
            raise ValueError(f"invalid transcript_json template: {raw}") from exc
    path = Path(raw)
    if path.suffix:
        return str(path.with_name(f"{path.stem}-{safe_case}{path.suffix}"))
    return str(path / f"{safe_scenario}-{safe_case}.json")


def _http2_hyper_h2_config_from_transport(
    transport: TransportConfig,
    transcript_path: str | None,
) -> HyperH2PingPathConfig:
    return HyperH2PingPathConfig(
        transcript_json=None if transcript_path is None else Path(transcript_path),
        validate_ack=transport.http2_validate_ack,
    )


def _http3_aioquic_settings_config_from_transport(
    transport: TransportConfig,
    transcript_path: str | None,
) -> AioquicH3SettingsPathConfig:
    return AioquicH3SettingsPathConfig(
        transcript_json=None if transcript_path is None else Path(transcript_path),
        validate_receiver_settings=transport.http3_validate_receiver_settings,
    )


def _quic_aioquic_config_from_transport(
    transport: TransportConfig,
    transcript_path: str | None,
) -> AioquicConnectionIdPathConfig:
    return AioquicConnectionIdPathConfig(
        transcript_json=None if transcript_path is None else Path(transcript_path),
        validate_server_response=transport.quic_validate_server_response,
    )


def _dns_edns0_config_from_transport(
    transport: TransportConfig,
    capture_path: str,
) -> DnsEdnsPaddingPathConfig:
    return DnsEdnsPaddingPathConfig(
        sender_namespace=transport.dns_sender_namespace,
        resolver_namespace=transport.dns_resolver_namespace,
        sender_address=transport.src_ip,
        resolver_address=transport.dst_ip,
        query_name=transport.dns_query_name,
        answer_address=transport.dns_answer_address or transport.dst_ip,
        port=transport.dst_port,
        padding_optcode=transport.dns_padding_optcode,
        timeout_s=transport.timeout_s or 2.0,
        tries=transport.dns_tries,
        capture_interface=transport.capture_interface or transport.receiver_interface,
        capture_pcap=Path(capture_path),
        capture_filter=transport.capture_filter,
        capture_snaplen=transport.capture_snaplen,
        capture_require_output=transport.capture_require_output,
        capture_start_delay_s=transport.dns_capture_start_delay_s,
        require_answer=transport.dns_require_answer,
    )


def _dns_edns0_transport_metadata(
    transport: TransportConfig,
    live: Any,
) -> dict[str, Any]:
    return {
        "schema_version": "celatim.transport_metadata.dns_edns0_padding.v1",
        "query_name": transport.dns_query_name,
        "resolver_address": transport.dst_ip,
        "port": transport.dst_port,
        "padding_optcode": transport.dns_padding_optcode,
        "answer_count": len(live.answers),
        "answers": list(live.answers),
        "daemon_readiness": live.daemon_readiness,
        "tool_versions": [record.to_json() for record in live.tool_versions],
    }


def _transport_str(data: dict[str, Any], key: str, default: str, path: Path) -> str:
    value = data.get(key, default)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path}: transport.{key} must be a non-empty string")
    return value


def _transport_float(data: dict[str, Any], key: str, default: float, path: Path) -> float:
    value = data.get(key, default)
    if not isinstance(value, int | float) or isinstance(value, bool):
        raise ValueError(f"{path}: transport.{key} must be a number")
    return float(value)


def _transport_optional_str(data: dict[str, Any], key: str, path: Path) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path}: transport.{key} must be a non-empty string or null")
    return value


def _transport_optional_path(data: dict[str, Any], key: str, path: Path) -> str | None:
    value = _transport_optional_str(data, key, path)
    if value is None:
        return None
    return _resolve_relative_path(value, path)


def _transport_str_tuple(data: dict[str, Any], key: str, path: Path) -> tuple[str, ...]:
    value = data.get(key, ())
    if not isinstance(value, list | tuple):
        raise ValueError(f"{path}: transport.{key} must be an array of strings")
    values: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise ValueError(f"{path}: transport.{key} must be an array of non-empty strings")
        values.append(item)
    return tuple(values)


def _transport_int(data: dict[str, Any], key: str, default: int, path: Path) -> int:
    value = data.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{path}: transport.{key} must be an integer")
    return value


def _transport_optional_int(data: dict[str, Any], key: str, path: Path) -> int | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{path}: transport.{key} must be an integer or null")
    return value


def _transport_optional_float(
    data: dict[str, Any],
    key: str,
    default: float | None,
    path: Path,
) -> float | None:
    value = data.get(key, default)
    if value is None:
        return None
    if not isinstance(value, int | float) or isinstance(value, bool):
        raise ValueError(f"{path}: transport.{key} must be a number or null")
    return float(value)


def _transport_bool(data: dict[str, Any], key: str, default: bool, path: Path) -> bool:
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise ValueError(f"{path}: transport.{key} must be boolean")
    return value


def _resolve_relative_path(value: str, path: Path) -> str:
    resolved = Path(value)
    if not resolved.is_absolute():
        resolved = path.parent / resolved
    return str(resolved)


def _pacing_from_mapping(value: Any, path: Path) -> PacingConfig | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError(f"{path}: pacing must be a table")
    allowed = {
        "unit_rate_hz",
        "symbol_period_s",
        "base_delay_s",
        "timing_quantum_s",
        "decode_tolerance_s",
        "timeout_s",
        "adaptive",
        "jitter_sample_window",
    }
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"{path}: unknown pacing keys: {', '.join(unknown)}")
    return PacingConfig(
        unit_rate_hz=value.get("unit_rate_hz"),
        symbol_period_s=value.get("symbol_period_s"),
        base_delay_s=value.get("base_delay_s", 0.0),
        timing_quantum_s=value.get("timing_quantum_s"),
        decode_tolerance_s=value.get("decode_tolerance_s"),
        timeout_s=value.get("timeout_s"),
        adaptive=value.get("adaptive", False),
        jitter_sample_window=value.get("jitter_sample_window", 0),
    )


def _reliability_from_mapping(value: Any, path: Path) -> ReliabilityPolicy | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError(f"{path}: reliability must be a table")
    allowed = {
        "max_receive_attempts",
        "retry_backoff_s",
        "suppress_duplicate_chunks",
        "max_retransmissions",
    }
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"{path}: unknown reliability keys: {', '.join(unknown)}")
    return ReliabilityPolicy(
        max_receive_attempts=value.get("max_receive_attempts", 1),
        retry_backoff_s=value.get("retry_backoff_s", 0.0),
        suppress_duplicate_chunks=value.get("suppress_duplicate_chunks", True),
        max_retransmissions=value.get("max_retransmissions", 0),
    )


def _carrier_hash(unit: CarrierUnit) -> str:
    if unit.carrier is None:
        raise ValueError("carrier hash requires carrier bytes")
    return hashlib.sha256(unit.carrier).hexdigest()


def _carrier_units_from_symbols(
    profile: MechanismProfile,
    symbols: list[Symbol],
) -> list[CarrierUnit]:
    return [
        CarrierUnit(index, symbol, profile.adapter.build_carrier(symbol))
        for index, symbol in enumerate(symbols)
    ]


def _parser_validated(
    profile: MechanismProfile,
    session_id: str,
    units: list[CarrierUnit],
    expected_payload: bytes,
) -> bool | None:
    if not any(unit.carrier is not None for unit in units):
        return None
    try:
        parsed_symbols = [profile.adapter.parse_carrier(unit.carrier) for unit in units]
        transport = InMemoryTransport()
        transport.send_symbols(session_id, parsed_symbols)
        decoded = ChannelSession(profile, transport).receive_message(session_id).payload
    except Exception:
        return False
    return decoded == expected_payload


def _write_artifacts(
    artifact_dir: str | None,
    scenario_id: str,
    case: str,
    units: list[CarrierUnit],
) -> tuple[ArtifactRecord, ...]:
    if artifact_dir is None:
        return ()
    root = Path(artifact_dir) / _safe_artifact_name(scenario_id) / _safe_artifact_name(case)
    records: list[ArtifactRecord] = []
    for unit in units:
        if unit.carrier is None:
            continue
        path = root / f"carrier-{unit.index:04d}.bin"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(unit.carrier)
        records.append(
            ArtifactRecord(
                kind="carrier_unit",
                path=str(path),
                sha256=hashlib.sha256(unit.carrier).hexdigest(),
                size_bytes=len(unit.carrier),
            )
        )
    return tuple(records)


def _file_artifact_record(path: str | None, *, kind: str) -> ArtifactRecord | None:
    if path is None:
        return None
    artifact_path = Path(path)
    if not artifact_path.is_file():
        raise ValueError(f"{artifact_path}: transport record missing")
    return ArtifactRecord(
        kind=kind,
        path=str(artifact_path),
        sha256=_file_sha256(artifact_path),
        size_bytes=artifact_path.stat().st_size,
    )


def _existing_file_artifact_record(path: str | None, *, kind: str) -> ArtifactRecord | None:
    if path is None or not Path(path).is_file():
        return None
    return _file_artifact_record(path, kind=kind)


def _safe_artifact_name(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return safe or "artifact"


def _run_id(value: str | None) -> str:
    run_id = uuid4().hex if value is None else value
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", run_id):
        raise ValueError("run_id may only contain letters, digits, underscore, dash, dot, or colon")
    return run_id


def _effective_log_dir(config: ScenarioConfig) -> str | None:
    if config.log_dir is not None:
        return config.log_dir
    if config.artifact_dir is not None:
        return str(Path(config.artifact_dir) / "run-logs")
    return None


def _write_run_log(
    log_dir: str | None,
    *,
    run_id: str,
    scenario_id: str,
    mechanism_id: str,
    started_at_unix_s: float,
    control_kind: str,
    scenario_metadata: ScenarioMetadata,
    reproducibility: ReproducibilityMetadata,
    covert: EvidenceCaseResult,
    benign_control: EvidenceCaseResult,
) -> ArtifactRecord | None:
    if log_dir is None:
        return None
    root = Path(log_dir)
    path = root / f"{_safe_artifact_name(scenario_id)}-{_safe_artifact_name(run_id)}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    events = _run_log_events(
        run_id=run_id,
        scenario_id=scenario_id,
        mechanism_id=mechanism_id,
        started_at_unix_s=started_at_unix_s,
        control_kind=control_kind,
        scenario_metadata=scenario_metadata,
        reproducibility=reproducibility,
        covert=covert,
        benign_control=benign_control,
    )
    with path.open("w") as fh:
        for event in events:
            fh.write(json.dumps(event, sort_keys=True) + "\n")
    return _file_artifact_record(str(path), kind="run_log")


def _run_log_events(
    *,
    run_id: str,
    scenario_id: str,
    mechanism_id: str,
    started_at_unix_s: float,
    control_kind: str,
    scenario_metadata: ScenarioMetadata,
    reproducibility: ReproducibilityMetadata,
    covert: EvidenceCaseResult,
    benign_control: EvidenceCaseResult,
) -> tuple[dict[str, Any], ...]:
    finished_at = time()
    cases = (covert, benign_control)
    return (
        {
            "schema_version": RUN_LOG_SCHEMA_VERSION,
            "event": "run_started",
            "run_id": run_id,
            "scenario_id": scenario_id,
            "mechanism_id": mechanism_id,
            "timestamp_unix_s": started_at_unix_s,
            "control_kind": control_kind,
            "scenario_metadata": scenario_metadata.to_json(),
            "command": list(reproducibility.command),
            "catalog_sha256": reproducibility.catalog_sha256,
            "package_version": reproducibility.package_version,
            "platform": reproducibility.platform,
            "system": reproducibility.system,
            "release": reproducibility.release,
            "machine": reproducibility.machine,
        },
        *(_case_log_event(run_id, scenario_id, mechanism_id, case) for case in cases),
        {
            "schema_version": RUN_LOG_SCHEMA_VERSION,
            "event": "run_finished",
            "run_id": run_id,
            "scenario_id": scenario_id,
            "mechanism_id": mechanism_id,
            "timestamp_unix_s": finished_at,
            "ok": all(case.matches for case in cases),
            "case_count": len(cases),
            "elapsed_s": finished_at - started_at_unix_s,
        },
    )


def _case_log_event(
    run_id: str,
    scenario_id: str,
    mechanism_id: str,
    case: EvidenceCaseResult,
) -> dict[str, Any]:
    return {
        "schema_version": RUN_LOG_SCHEMA_VERSION,
        "event": "case_finished",
        "run_id": run_id,
        "scenario_id": scenario_id,
        "mechanism_id": mechanism_id,
        "case": case.case,
        "session_id": case.session_id,
        "timestamp_unix_s": time(),
        "ok": case.matches and case.evidence.ok,
        "matches": case.matches,
        "evidence_ok": case.evidence.ok,
        "transport_kind": case.transport_kind,
        "transport_metadata": case.transport_metadata,
        "carrier_units": case.evidence.carrier_units,
        "carrier_units_with_bytes": case.carrier_units_with_bytes,
        "parser_validated": case.parser_validated,
        "detector_count": len(case.detector_provenance),
        "detector_executed_count": sum(1 for record in case.detector_provenance if record.executed),
        "parser_provenance_count": len(case.parser_provenance),
        "parser_provenance_executed_count": sum(
            1 for record in case.parser_provenance if record.executed
        ),
        "payload_len": case.expected_len,
        "recovered_len": case.recovered_len,
        "elapsed_s": case.evidence.elapsed_s,
        "error": case.evidence.error,
    }


def _reproducibility(
    catalog_path: Path | str,
    command: tuple[str, ...],
    scenario_spec_path: str | None,
) -> ReproducibilityMetadata:
    catalog = Path(catalog_path)
    return ReproducibilityMetadata(
        catalog_path=str(catalog),
        catalog_sha256=_file_sha256(catalog),
        package_version=_package_version(),
        python_version=sys.version.split()[0],
        platform=platform.platform(),
        system=platform.system(),
        release=platform.release(),
        machine=platform.machine(),
        command=command,
        scenario_spec_path=scenario_spec_path,
    )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _package_version() -> str:
    try:
        return version("celatim")
    except PackageNotFoundError:
        return "0.1.0"


def _case_to_json(case: EvidenceCaseResult) -> dict[str, Any]:
    return {
        "case": case.case,
        "session_id": case.session_id,
        "expected_len": case.expected_len,
        "recovered_len": case.recovered_len,
        "expected_sha256": case.expected_sha256,
        "recovered_sha256": case.recovered_sha256,
        "matches": case.matches,
        "recovered_hex": case.recovered_hex,
        "parser_validated": case.parser_validated,
        "parser_provenance": [record.to_json() for record in case.parser_provenance],
        "detector_provenance": [record.to_json() for record in case.detector_provenance],
        "observer_validations": [record.to_json() for record in case.observer_validations],
        "mutation_controls": [record.to_json() for record in case.mutation_controls],
        "carrier_units_with_bytes": case.carrier_units_with_bytes,
        "carrier_unit_sha256": case.carrier_unit_sha256,
        "transport_kind": case.transport_kind,
        "transport_metadata": case.transport_metadata,
        "transport_record": case.transport_record,
        "transport_artifact": None
        if case.transport_artifact is None
        else case.transport_artifact.to_json(),
        "artifacts": [artifact.to_json() for artifact in case.artifacts],
        "evidence": _evidence_to_json(case.evidence),
    }


def _evidence_to_json(evidence: EvidenceRecord) -> dict[str, Any]:
    return {
        "mechanism_id": evidence.mechanism_id,
        "session_id": evidence.session_id,
        "adapter_status": evidence.adapter_status.value,
        "adapter_capabilities": sorted(
            capability.value for capability in evidence.adapter_capabilities
        ),
        "evidence_bucket": evidence.evidence_bucket.value,
        "carrier_structure": evidence.carrier_structure.value,
        "control_strength": evidence.control_strength.value,
        "independent_validator": evidence.independent_validator.value,
        "throughput_status": evidence.throughput_status.value,
        "endpoint_os": evidence.endpoint_os.to_json(),
        "payload_len": evidence.payload_len,
        "recovered_len": evidence.recovered_len,
        "carrier_units": evidence.carrier_units,
        "elapsed_s": evidence.elapsed_s,
        "pacing": None if evidence.pacing is None else asdict(evidence.pacing),
        "scheduled_duration_s": evidence.scheduled_duration_s,
        "timing_trace": _timing_trace_to_json(evidence.timing_trace),
        "timing_profile": _timing_profile_to_json(evidence.timing_profile),
        "throughput_profile": _throughput_profile_to_json(evidence.throughput_profile),
        "session_framing": evidence.session_framing,
        "chunk_count": evidence.chunk_count,
        "integrity_sha256": evidence.integrity_sha256,
        "reliability": _reliability_to_json(evidence.reliability),
        "ok": evidence.ok,
        "error": evidence.error,
    }


def _reliability_to_json(reliability: Any) -> dict[str, Any]:
    return {
        "policy": asdict(reliability.policy),
        "receive_attempts": reliability.receive_attempts,
        "retry_count": reliability.retry_count,
        "retransmit_requests": reliability.retransmit_requests,
        "duplicate_chunks": reliability.duplicate_chunks,
        "loss_detected": reliability.loss_detected,
        "timed_out": reliability.timed_out,
        "expected_chunks": reliability.expected_chunks,
        "recovered_chunks": reliability.recovered_chunks,
        "last_error": reliability.last_error,
    }


def _timing_trace_to_json(trace: TimingTrace | None) -> dict[str, Any] | None:
    if trace is None:
        return None
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


def _timing_profile_to_json(profile: TimingProfile | None) -> dict[str, Any] | None:
    if profile is None:
        return None
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


def _throughput_profile_to_json(profile: ThroughputProfile | None) -> dict[str, Any] | None:
    if profile is None:
        return None
    return {
        "payload_len": profile.payload_len,
        "recovered_len": profile.recovered_len,
        "carrier_units": profile.carrier_units,
        "scheduled_unit_rate_hz": profile.scheduled_unit_rate_hz,
        "measurement_window_s": profile.measurement_window_s,
        "observed_unit_rate_hz": profile.observed_unit_rate_hz,
        "payload_rate_bps": profile.payload_rate_bps,
        "throughput_status": profile.throughput_status.value,
        "rate_basis": profile.rate_basis,
        "claim_status": profile.claim_status,
    }


def _timing_sample_to_json(sample: TimingSample) -> dict[str, Any]:
    return {
        "index": sample.index,
        "scheduled_offset_s": sample.scheduled_offset_s,
        "observed_offset_s": sample.observed_offset_s,
        "error_s": sample.error_s,
    }


__all__ = [
    "RUN_LOG_SCHEMA_VERSION",
    "SCENARIO_EVIDENCE_TIERS",
    "SCENARIO_EXECUTION_MODES",
    "SCENARIO_EXECUTION_PLAN_SCHEMA_VERSION",
    "SCENARIO_EXECUTION_PLAN_TARGETS",
    "SCENARIO_INVENTORY_SCHEMA_VERSION",
    "SCENARIO_PRIVILEGE_LEVELS",
    "SCHEMA_VERSION",
    "SPEC_SCHEMA_VERSION",
    "ArtifactRecord",
    "EvidenceCaseResult",
    "EvidenceRunResult",
    "ReproducibilityMetadata",
    "ScenarioConfig",
    "ScenarioExecutionPlan",
    "ScenarioExecutionPlanItem",
    "ScenarioInventory",
    "ScenarioMetadata",
    "ScenarioSpecInfo",
    "TransportConfig",
    "build_scenario_execution_plan",
    "build_scenario_inventory",
    "discover_scenarios",
    "find_scenario",
    "load_scenario",
    "load_scenario_by_id",
    "run_evidence",
    "scenario_execution_ids",
]
