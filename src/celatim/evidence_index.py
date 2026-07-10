"""Reviewer-bundle evidence index generation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from time import time
from typing import Any

from .scenario import SCHEMA_VERSION as EVIDENCE_RUN_SCHEMA_VERSION

INDEX_SCHEMA_VERSION = "celatim.evidence_index.v1"
PUBLIC_INDEX_SCHEMA_VERSION = "celatim.public_evidence_index.v1"


@dataclass(frozen=True)
class EvidenceArtifactRef:
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
class EvidenceCaseIndex:
    case: str
    session_id: str
    matches: bool
    evidence_ok: bool
    expected_len: int
    recovered_len: int
    expected_sha256: str
    recovered_sha256: str
    parser_validated: bool | None
    observer_validation_count: int
    observer_validation_ok_count: int
    observer_validators: tuple[str, ...]
    detector_count: int
    detector_executed_count: int
    detector_implementation_kinds: tuple[str, ...]
    mutation_control_count: int
    mutation_control_ok_count: int
    carrier_structure: str
    control_strength: str
    endpoint_topology_kind: str
    independent_receiver_os: bool
    transport_kind: str
    transport_metadata: dict[str, Any] | None
    transport_record: str | None
    transport_artifact: EvidenceArtifactRef | None
    carrier_artifact_count: int
    carrier_artifact_sha256: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "case": self.case,
            "session_id": self.session_id,
            "matches": self.matches,
            "evidence_ok": self.evidence_ok,
            "expected_len": self.expected_len,
            "recovered_len": self.recovered_len,
            "expected_sha256": self.expected_sha256,
            "recovered_sha256": self.recovered_sha256,
            "parser_validated": self.parser_validated,
            "observer_validation_count": self.observer_validation_count,
            "observer_validation_ok_count": self.observer_validation_ok_count,
            "observer_validators": list(self.observer_validators),
            "detector_count": self.detector_count,
            "detector_executed_count": self.detector_executed_count,
            "detector_implementation_kinds": list(self.detector_implementation_kinds),
            "mutation_control_count": self.mutation_control_count,
            "mutation_control_ok_count": self.mutation_control_ok_count,
            "carrier_structure": self.carrier_structure,
            "control_strength": self.control_strength,
            "endpoint_topology_kind": self.endpoint_topology_kind,
            "independent_receiver_os": self.independent_receiver_os,
            "transport_kind": self.transport_kind,
            "transport_metadata": self.transport_metadata,
            "transport_record": self.transport_record,
            "transport_artifact": None
            if self.transport_artifact is None
            else self.transport_artifact.to_json(),
            "carrier_artifact_count": self.carrier_artifact_count,
            "carrier_artifact_sha256": list(self.carrier_artifact_sha256),
        }


@dataclass(frozen=True)
class EvidenceScenarioMetadata:
    description: str | None
    evidence_tier: str | None
    privilege: str | None
    expected_runtime_s: float | None
    requires_tools: tuple[str, ...]
    requires_extras: tuple[str, ...]

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
class EvidenceIndexItem:
    path: str
    sha256: str
    size_bytes: int
    run_id: str
    scenario_id: str
    mechanism_id: str
    ok: bool
    adapter_status: str
    adapter_capabilities: tuple[str, ...]
    started_at_unix_s: float
    control_kind: str
    scenario_metadata: EvidenceScenarioMetadata
    catalog_sha256: str | None
    package_version: str | None
    python_version: str | None
    platform: str | None
    system: str | None
    release: str | None
    machine: str | None
    scenario_spec_path: str | None
    command: tuple[str, ...]
    run_log: EvidenceArtifactRef | None
    cases: tuple[EvidenceCaseIndex, ...]

    @property
    def transport_artifacts(self) -> tuple[EvidenceArtifactRef, ...]:
        return tuple(
            case.transport_artifact for case in self.cases if case.transport_artifact is not None
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "mechanism_id": self.mechanism_id,
            "ok": self.ok,
            "adapter_status": self.adapter_status,
            "adapter_capabilities": list(self.adapter_capabilities),
            "started_at_unix_s": self.started_at_unix_s,
            "control_kind": self.control_kind,
            "scenario_metadata": self.scenario_metadata.to_json(),
            "catalog_sha256": self.catalog_sha256,
            "package_version": self.package_version,
            "python_version": self.python_version,
            "platform": self.platform,
            "system": self.system,
            "release": self.release,
            "machine": self.machine,
            "scenario_spec_path": self.scenario_spec_path,
            "command": list(self.command),
            "run_log": None if self.run_log is None else self.run_log.to_json(),
            "transport_artifacts": [artifact.to_json() for artifact in self.transport_artifacts],
            "cases": [case.to_json() for case in self.cases],
        }


@dataclass(frozen=True)
class EvidenceIndexResult:
    schema_version: str
    generated_at_unix_s: float
    evidence_roots: tuple[str, ...]
    evidence_count: int
    ok_count: int
    failed_count: int
    run_log_artifact_count: int
    transport_artifact_count: int
    observer_validation_count: int
    observer_validation_ok_count: int
    detector_count: int
    detector_executed_count: int
    mutation_control_count: int
    mutation_control_ok_count: int
    evidence_tier_counts: dict[str, int]
    privilege_counts: dict[str, int]
    expected_runtime_s_total: float | None
    required_tools: tuple[str, ...]
    required_extras: tuple[str, ...]
    skipped_json_count: int
    items: tuple[EvidenceIndexItem, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at_unix_s": self.generated_at_unix_s,
            "evidence_roots": list(self.evidence_roots),
            "evidence_count": self.evidence_count,
            "ok_count": self.ok_count,
            "failed_count": self.failed_count,
            "run_log_artifact_count": self.run_log_artifact_count,
            "transport_artifact_count": self.transport_artifact_count,
            "observer_validation_count": self.observer_validation_count,
            "observer_validation_ok_count": self.observer_validation_ok_count,
            "detector_count": self.detector_count,
            "detector_executed_count": self.detector_executed_count,
            "mutation_control_count": self.mutation_control_count,
            "mutation_control_ok_count": self.mutation_control_ok_count,
            "evidence_tier_counts": dict(self.evidence_tier_counts),
            "privilege_counts": dict(self.privilege_counts),
            "expected_runtime_s_total": self.expected_runtime_s_total,
            "required_tools": list(self.required_tools),
            "required_extras": list(self.required_extras),
            "skipped_json_count": self.skipped_json_count,
            "items": [item.to_json() for item in self.items],
        }


@dataclass(frozen=True)
class PublicEvidenceCaseIndex:
    case: str
    matches: bool
    evidence_ok: bool
    expected_len: int
    recovered_len: int
    expected_sha256: str
    recovered_sha256: str
    parser_validated: bool | None
    observer_validation_count: int
    observer_validation_ok_count: int
    observer_validators: tuple[str, ...]
    detector_count: int
    detector_executed_count: int
    detector_implementation_kinds: tuple[str, ...]
    mutation_control_count: int
    mutation_control_ok_count: int
    carrier_structure: str
    control_strength: str
    endpoint_topology_kind: str
    independent_receiver_os: bool
    transport_kind: str
    transport_artifact_sha256: str | None
    transport_artifact_size_bytes: int | None
    carrier_artifact_count: int
    carrier_artifact_sha256: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "case": self.case,
            "matches": self.matches,
            "evidence_ok": self.evidence_ok,
            "expected_len": self.expected_len,
            "recovered_len": self.recovered_len,
            "expected_sha256": self.expected_sha256,
            "recovered_sha256": self.recovered_sha256,
            "parser_validated": self.parser_validated,
            "observer_validation_count": self.observer_validation_count,
            "observer_validation_ok_count": self.observer_validation_ok_count,
            "observer_validators": list(self.observer_validators),
            "detector_count": self.detector_count,
            "detector_executed_count": self.detector_executed_count,
            "detector_implementation_kinds": list(self.detector_implementation_kinds),
            "mutation_control_count": self.mutation_control_count,
            "mutation_control_ok_count": self.mutation_control_ok_count,
            "carrier_structure": self.carrier_structure,
            "control_strength": self.control_strength,
            "endpoint_topology_kind": self.endpoint_topology_kind,
            "independent_receiver_os": self.independent_receiver_os,
            "transport_kind": self.transport_kind,
            "transport_artifact_sha256": self.transport_artifact_sha256,
            "transport_artifact_size_bytes": self.transport_artifact_size_bytes,
            "carrier_artifact_count": self.carrier_artifact_count,
            "carrier_artifact_sha256": list(self.carrier_artifact_sha256),
        }


@dataclass(frozen=True)
class PublicEvidenceIndexItem:
    evidence_sha256: str
    evidence_size_bytes: int
    scenario_id: str
    mechanism_id: str
    ok: bool
    adapter_status: str
    adapter_capabilities: tuple[str, ...]
    control_kind: str
    scenario_metadata: EvidenceScenarioMetadata
    catalog_sha256: str | None
    package_version: str | None
    python_version: str | None
    system: str | None
    release: str | None
    machine: str | None
    scenario_spec_name: str | None
    run_log_sha256: str | None
    run_log_size_bytes: int | None
    transport_artifact_sha256: tuple[str, ...]
    cases: tuple[PublicEvidenceCaseIndex, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "evidence_sha256": self.evidence_sha256,
            "evidence_size_bytes": self.evidence_size_bytes,
            "scenario_id": self.scenario_id,
            "mechanism_id": self.mechanism_id,
            "ok": self.ok,
            "adapter_status": self.adapter_status,
            "adapter_capabilities": list(self.adapter_capabilities),
            "control_kind": self.control_kind,
            "scenario_metadata": self.scenario_metadata.to_json(),
            "catalog_sha256": self.catalog_sha256,
            "package_version": self.package_version,
            "python_version": self.python_version,
            "system": self.system,
            "release": self.release,
            "machine": self.machine,
            "scenario_spec_name": self.scenario_spec_name,
            "run_log_sha256": self.run_log_sha256,
            "run_log_size_bytes": self.run_log_size_bytes,
            "transport_artifact_sha256": list(self.transport_artifact_sha256),
            "cases": [case.to_json() for case in self.cases],
        }


@dataclass(frozen=True)
class PublicEvidenceIndexResult:
    schema_version: str
    generated_at_unix_s: float
    source_evidence_index_sha256: str
    source_evidence_index_size_bytes: int
    evidence_count: int
    ok_count: int
    failed_count: int
    run_log_artifact_count: int
    transport_artifact_count: int
    observer_validation_count: int
    observer_validation_ok_count: int
    detector_count: int
    detector_executed_count: int
    mutation_control_count: int
    mutation_control_ok_count: int
    evidence_tier_counts: dict[str, int]
    privilege_counts: dict[str, int]
    expected_runtime_s_total: float | None
    required_tools: tuple[str, ...]
    required_extras: tuple[str, ...]
    skipped_json_count: int
    items: tuple[PublicEvidenceIndexItem, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at_unix_s": self.generated_at_unix_s,
            "source_evidence_index_sha256": self.source_evidence_index_sha256,
            "source_evidence_index_size_bytes": self.source_evidence_index_size_bytes,
            "evidence_count": self.evidence_count,
            "ok_count": self.ok_count,
            "failed_count": self.failed_count,
            "run_log_artifact_count": self.run_log_artifact_count,
            "transport_artifact_count": self.transport_artifact_count,
            "observer_validation_count": self.observer_validation_count,
            "observer_validation_ok_count": self.observer_validation_ok_count,
            "detector_count": self.detector_count,
            "detector_executed_count": self.detector_executed_count,
            "mutation_control_count": self.mutation_control_count,
            "mutation_control_ok_count": self.mutation_control_ok_count,
            "evidence_tier_counts": dict(self.evidence_tier_counts),
            "privilege_counts": dict(self.privilege_counts),
            "expected_runtime_s_total": self.expected_runtime_s_total,
            "required_tools": list(self.required_tools),
            "required_extras": list(self.required_extras),
            "skipped_json_count": self.skipped_json_count,
            "items": [item.to_json() for item in self.items],
        }


def build_public_evidence_index(path: Path | str) -> PublicEvidenceIndexResult:
    """Project a private evidence index into a public-safe, hash-only view.

    The private reviewer index is intentionally path-bearing: it names evidence JSON,
    pcap records, run logs, carrier dumps, and exact commands so a reviewer can
    reproduce and debug runs. The public projection keeps the aggregate counts and
    hashes needed to audit a paper artifact without shipping those private paths or
    command transcripts.
    """

    index_path = Path(path)
    raw = index_path.read_bytes()
    document = json.loads(raw)
    if not isinstance(document, dict):
        raise ValueError("evidence index must be a JSON object")
    if document.get("schema_version") != INDEX_SCHEMA_VERSION:
        raise ValueError(f"evidence index schema_version must be {INDEX_SCHEMA_VERSION!r}")
    return PublicEvidenceIndexResult(
        schema_version=PUBLIC_INDEX_SCHEMA_VERSION,
        generated_at_unix_s=time(),
        source_evidence_index_sha256=hashlib.sha256(raw).hexdigest(),
        source_evidence_index_size_bytes=len(raw),
        evidence_count=int(document.get("evidence_count", 0)),
        ok_count=int(document.get("ok_count", 0)),
        failed_count=int(document.get("failed_count", 0)),
        run_log_artifact_count=int(document.get("run_log_artifact_count", 0)),
        transport_artifact_count=int(document.get("transport_artifact_count", 0)),
        observer_validation_count=int(document.get("observer_validation_count", 0)),
        observer_validation_ok_count=int(document.get("observer_validation_ok_count", 0)),
        detector_count=int(document.get("detector_count", 0)),
        detector_executed_count=int(document.get("detector_executed_count", 0)),
        mutation_control_count=int(document.get("mutation_control_count", 0)),
        mutation_control_ok_count=int(document.get("mutation_control_ok_count", 0)),
        evidence_tier_counts=_count_map(document.get("evidence_tier_counts", {})),
        privilege_counts=_count_map(document.get("privilege_counts", {})),
        expected_runtime_s_total=_optional_float(document.get("expected_runtime_s_total")),
        required_tools=_str_tuple(document.get("required_tools", ()), "required_tools"),
        required_extras=_str_tuple(document.get("required_extras", ()), "required_extras"),
        skipped_json_count=int(document.get("skipped_json_count", 0)),
        items=tuple(_public_index_item(item) for item in document.get("items", ())),
    )


def build_evidence_index(
    roots: Sequence[Path | str],
    *,
    path_root: Path | str | None = None,
) -> EvidenceIndexResult:
    if not roots:
        raise ValueError("at least one evidence JSON file or directory is required")
    display_root = None if path_root is None else Path(path_root)
    evidence_roots = tuple(_display_path(Path(root), display_root) for root in roots)
    items: list[EvidenceIndexItem] = []
    skipped_json_count = 0
    for path in _evidence_json_paths(roots):
        raw = path.read_bytes()
        document = json.loads(raw)
        if document.get("schema_version") != EVIDENCE_RUN_SCHEMA_VERSION:
            skipped_json_count += 1
            continue
        items.append(_index_item(path, raw, document, display_root=display_root))
    if not items:
        raise ValueError("no evidence-run JSON files found")
    ok_count = sum(1 for item in items if item.ok)
    run_log_artifact_count = sum(1 for item in items if item.run_log is not None)
    transport_artifact_count = sum(len(item.transport_artifacts) for item in items)
    observer_validation_count = sum(
        case.observer_validation_count for item in items for case in item.cases
    )
    observer_validation_ok_count = sum(
        case.observer_validation_ok_count for item in items for case in item.cases
    )
    mutation_control_count = sum(
        case.mutation_control_count for item in items for case in item.cases
    )
    mutation_control_ok_count = sum(
        case.mutation_control_ok_count for item in items for case in item.cases
    )
    detector_count = sum(case.detector_count for item in items for case in item.cases)
    detector_executed_count = sum(
        case.detector_executed_count for item in items for case in item.cases
    )
    evidence_tier_counts = _metadata_counts(item.scenario_metadata.evidence_tier for item in items)
    privilege_counts = _metadata_counts(item.scenario_metadata.privilege for item in items)
    expected_runtime_s_total = _expected_runtime_s_total(items)
    required_tools = _required_metadata_values(
        item.scenario_metadata.requires_tools for item in items
    )
    required_extras = _required_metadata_values(
        item.scenario_metadata.requires_extras for item in items
    )
    return EvidenceIndexResult(
        schema_version=INDEX_SCHEMA_VERSION,
        generated_at_unix_s=time(),
        evidence_roots=evidence_roots,
        evidence_count=len(items),
        ok_count=ok_count,
        failed_count=len(items) - ok_count,
        run_log_artifact_count=run_log_artifact_count,
        transport_artifact_count=transport_artifact_count,
        observer_validation_count=observer_validation_count,
        observer_validation_ok_count=observer_validation_ok_count,
        detector_count=detector_count,
        detector_executed_count=detector_executed_count,
        mutation_control_count=mutation_control_count,
        mutation_control_ok_count=mutation_control_ok_count,
        evidence_tier_counts=evidence_tier_counts,
        privilege_counts=privilege_counts,
        expected_runtime_s_total=expected_runtime_s_total,
        required_tools=required_tools,
        required_extras=required_extras,
        skipped_json_count=skipped_json_count,
        items=tuple(items),
    )


def _metadata_counts(values: Iterable[str | None]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        label = value if value is not None else "unknown"
        counts[label] = counts.get(label, 0) + 1
    return dict(sorted(counts.items()))


def _count_map(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        raise ValueError("count map must be an object")
    out: dict[str, int] = {}
    for key, count in value.items():
        if not isinstance(key, str):
            raise ValueError("count map keys must be strings")
        if not isinstance(count, int) or isinstance(count, bool):
            raise ValueError("count map values must be integers")
        out[key] = count
    return dict(sorted(out.items()))


def _public_index_item(value: Any) -> PublicEvidenceIndexItem:
    data = _mapping(value, "items[]")
    run_log = _optional_artifact(data.get("run_log"), "run_log")
    cases = tuple(_public_case_item(case) for case in data.get("cases", ()))
    transport_artifacts = [
        _mapping(artifact, "transport_artifacts[]")
        for artifact in data.get("transport_artifacts", ())
    ]
    return PublicEvidenceIndexItem(
        evidence_sha256=_str(data, "sha256"),
        evidence_size_bytes=int(data.get("size_bytes", 0)),
        scenario_id=_str(data, "scenario_id"),
        mechanism_id=_str(data, "mechanism_id"),
        ok=_bool(data, "ok"),
        adapter_status=_str(data, "adapter_status"),
        adapter_capabilities=_str_tuple(
            data.get("adapter_capabilities", ()), "adapter_capabilities"
        ),
        control_kind=_str(data, "control_kind"),
        scenario_metadata=_scenario_metadata(data.get("scenario_metadata")),
        catalog_sha256=_optional_str(data.get("catalog_sha256")),
        package_version=_optional_str(data.get("package_version")),
        python_version=_optional_str(data.get("python_version")),
        system=_optional_str(data.get("system")),
        release=_optional_str(data.get("release")),
        machine=_optional_str(data.get("machine")),
        scenario_spec_name=_public_scenario_spec_name(data.get("scenario_spec_path")),
        run_log_sha256=None if run_log is None else _str(run_log, "sha256"),
        run_log_size_bytes=None if run_log is None else int(run_log.get("size_bytes", 0)),
        transport_artifact_sha256=tuple(
            _str(artifact, "sha256") for artifact in transport_artifacts
        ),
        cases=cases,
    )


def _public_case_item(value: Any) -> PublicEvidenceCaseIndex:
    data = _mapping(value, "cases[]")
    transport_artifact = _optional_artifact(data.get("transport_artifact"), "transport_artifact")
    return PublicEvidenceCaseIndex(
        case=_str(data, "case"),
        matches=_bool(data, "matches"),
        evidence_ok=_bool(data, "evidence_ok"),
        expected_len=int(data.get("expected_len", 0)),
        recovered_len=int(data.get("recovered_len", 0)),
        expected_sha256=_str(data, "expected_sha256"),
        recovered_sha256=_str(data, "recovered_sha256"),
        parser_validated=_optional_bool(data.get("parser_validated")),
        observer_validation_count=int(data.get("observer_validation_count", 0)),
        observer_validation_ok_count=int(data.get("observer_validation_ok_count", 0)),
        observer_validators=_str_tuple(data.get("observer_validators", ()), "observer_validators"),
        detector_count=int(data.get("detector_count", 0)),
        detector_executed_count=int(data.get("detector_executed_count", 0)),
        detector_implementation_kinds=_str_tuple(
            data.get("detector_implementation_kinds", ()),
            "detector_implementation_kinds",
        ),
        mutation_control_count=int(data.get("mutation_control_count", 0)),
        mutation_control_ok_count=int(data.get("mutation_control_ok_count", 0)),
        carrier_structure=_str(data, "carrier_structure"),
        control_strength=_str(data, "control_strength"),
        endpoint_topology_kind=_str(data, "endpoint_topology_kind"),
        independent_receiver_os=_bool(data, "independent_receiver_os"),
        transport_kind=_str(data, "transport_kind"),
        transport_artifact_sha256=None
        if transport_artifact is None
        else _str(transport_artifact, "sha256"),
        transport_artifact_size_bytes=None
        if transport_artifact is None
        else int(transport_artifact.get("size_bytes", 0)),
        carrier_artifact_count=int(data.get("carrier_artifact_count", 0)),
        carrier_artifact_sha256=_str_tuple(
            data.get("carrier_artifact_sha256", ()),
            "carrier_artifact_sha256",
        ),
    )


def _optional_artifact(value: Any, path: str) -> dict[str, Any] | None:
    if value is None:
        return None
    return _mapping(value, path)


def _public_scenario_spec_name(value: Any) -> str | None:
    path = _optional_str(value)
    if path is None:
        return None
    return Path(path).name


def _expected_runtime_s_total(items: Sequence[EvidenceIndexItem]) -> float | None:
    total = 0.0
    for item in items:
        expected_runtime_s = item.scenario_metadata.expected_runtime_s
        if expected_runtime_s is None:
            return None
        total += expected_runtime_s
    return total


def _required_metadata_values(values: Iterable[Sequence[str]]) -> tuple[str, ...]:
    return tuple(sorted({value for nested in values for value in nested}))


def _evidence_json_paths(roots: Sequence[Path | str]) -> tuple[Path, ...]:
    paths: dict[Path, Path] = {}
    for raw_root in roots:
        root = Path(raw_root)
        if root.is_dir():
            candidates = root.rglob("*.json")
        elif root.is_file():
            candidates = (root,)
        else:
            raise ValueError(f"{root}: evidence path does not exist")
        for candidate in candidates:
            paths[candidate.resolve()] = candidate
    return tuple(paths[key] for key in sorted(paths, key=lambda value: str(value)))


def _index_item(
    path: Path,
    raw: bytes,
    document: dict[str, Any],
    *,
    display_root: Path | None,
) -> EvidenceIndexItem:
    reproducibility = _mapping(document.get("reproducibility"), "reproducibility")
    cases = (
        _case_index(_mapping(document.get("covert"), "covert"), display_root=display_root),
        _case_index(
            _mapping(document.get("benign_control"), "benign_control"),
            display_root=display_root,
        ),
    )
    return EvidenceIndexItem(
        path=_display_path(path, display_root),
        sha256=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
        run_id=_str(document, "run_id"),
        scenario_id=_str(document, "scenario_id"),
        mechanism_id=_str(document, "mechanism_id"),
        ok=_bool(document, "ok"),
        adapter_status=_str(document, "adapter_status"),
        adapter_capabilities=tuple(
            str(value) for value in document.get("adapter_capabilities", [])
        ),
        started_at_unix_s=float(document.get("started_at_unix_s", 0.0)),
        control_kind=_str(document, "control_kind"),
        scenario_metadata=_scenario_metadata(document.get("scenario_metadata")),
        catalog_sha256=_optional_str(reproducibility.get("catalog_sha256")),
        package_version=_optional_str(reproducibility.get("package_version")),
        python_version=_optional_str(reproducibility.get("python_version")),
        platform=_optional_str(reproducibility.get("platform")),
        system=_optional_str(reproducibility.get("system")),
        release=_optional_str(reproducibility.get("release")),
        machine=_optional_str(reproducibility.get("machine")),
        scenario_spec_path=_optional_str(reproducibility.get("scenario_spec_path")),
        command=tuple(str(value) for value in reproducibility.get("command", [])),
        run_log=_artifact_ref(document.get("run_log"), "run_log", display_root=display_root),
        cases=cases,
    )


def _scenario_metadata(value: Any) -> EvidenceScenarioMetadata:
    if value is None:
        return EvidenceScenarioMetadata(
            description=None,
            evidence_tier=None,
            privilege=None,
            expected_runtime_s=None,
            requires_tools=(),
            requires_extras=(),
        )
    data = _mapping(value, "scenario_metadata")
    return EvidenceScenarioMetadata(
        description=_optional_str(data.get("description")),
        evidence_tier=_optional_str(data.get("evidence_tier")),
        privilege=_optional_str(data.get("privilege")),
        expected_runtime_s=_optional_float(data.get("expected_runtime_s")),
        requires_tools=_str_tuple(
            data.get("requires_tools", ()), "scenario_metadata.requires_tools"
        ),
        requires_extras=_str_tuple(
            data.get("requires_extras", ()), "scenario_metadata.requires_extras"
        ),
    )


def _case_index(
    document: dict[str, Any],
    *,
    display_root: Path | None,
) -> EvidenceCaseIndex:
    evidence = _mapping(document.get("evidence"), f"{document.get('case', 'case')}.evidence")
    artifacts = [
        artifact.sha256
        for artifact in (
            _artifact_ref(value, f"{document.get('case', 'case')}.artifacts")
            for value in document.get("artifacts", [])
        )
        if artifact is not None
    ]
    observer_validations = [
        _mapping(value, f"{document.get('case', 'case')}.observer_validations")
        for value in document.get("observer_validations", [])
    ]
    mutation_controls = [
        _mapping(value, f"{document.get('case', 'case')}.mutation_controls")
        for value in document.get("mutation_controls", [])
    ]
    detector_provenance = [
        _mapping(value, f"{document.get('case', 'case')}.detector_provenance")
        for value in document.get("detector_provenance", [])
    ]
    endpoint_os = _optional_endpoint_os(evidence)
    independent_receiver_os = _optional_bool(endpoint_os.get("independent_receiver_os"))
    return EvidenceCaseIndex(
        case=_str(document, "case"),
        session_id=_str(document, "session_id"),
        matches=_bool(document, "matches"),
        evidence_ok=_bool(evidence, "ok"),
        expected_len=int(document.get("expected_len", 0)),
        recovered_len=int(document.get("recovered_len", 0)),
        expected_sha256=_str(document, "expected_sha256"),
        recovered_sha256=_str(document, "recovered_sha256"),
        parser_validated=_optional_bool(document.get("parser_validated")),
        observer_validation_count=len(observer_validations),
        observer_validation_ok_count=sum(
            1 for validation in observer_validations if _bool(validation, "ok")
        ),
        observer_validators=tuple(
            sorted({_str(validation, "validator") for validation in observer_validations})
        ),
        detector_count=len(detector_provenance),
        detector_executed_count=sum(
            1 for record in detector_provenance if _bool(record, "executed")
        ),
        detector_implementation_kinds=tuple(
            sorted({_str(record, "implementation_kind") for record in detector_provenance})
        ),
        mutation_control_count=len(mutation_controls),
        mutation_control_ok_count=sum(1 for control in mutation_controls if _bool(control, "ok")),
        carrier_structure=_str(evidence, "carrier_structure"),
        control_strength=_str(evidence, "control_strength"),
        endpoint_topology_kind=_optional_str(endpoint_os.get("topology_kind")) or "unknown",
        independent_receiver_os=(
            independent_receiver_os if independent_receiver_os is not None else False
        ),
        transport_kind=_str(document, "transport_kind"),
        transport_metadata=_optional_object(document.get("transport_metadata")),
        transport_record=_optional_display_path(
            document.get("transport_record"),
            display_root,
        ),
        transport_artifact=_artifact_ref(
            document.get("transport_artifact"),
            f"{document.get('case', 'case')}.transport_artifact",
            display_root=display_root,
        ),
        carrier_artifact_count=len(artifacts),
        carrier_artifact_sha256=tuple(artifacts),
    )


def _artifact_ref(
    value: Any,
    path: str,
    *,
    display_root: Path | None = None,
) -> EvidenceArtifactRef | None:
    if value is None:
        return None
    data = _mapping(value, path)
    return EvidenceArtifactRef(
        kind=_str(data, "kind"),
        path=_display_path(Path(_str(data, "path")), display_root),
        sha256=_str(data, "sha256"),
        size_bytes=int(data.get("size_bytes", 0)),
    )


def _optional_endpoint_os(evidence: dict[str, Any]) -> dict[str, Any]:
    value = evidence.get("endpoint_os")
    if value is None:
        return {}
    return _mapping(value, "evidence.endpoint_os")


def _display_path(path: Path, root: Path | None) -> str:
    if root is None:
        return str(path)
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def _optional_display_path(value: Any, root: Path | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("expected string or null")
    return _display_path(Path(value), root)


def _mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be an object")
    return value


def _optional_object(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        return None
    return dict(value)


def _str(document: dict[str, Any], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string")
    return value


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("expected string or null")
    return value


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    if not isinstance(value, int | float) or isinstance(value, bool):
        raise ValueError("expected number or null")
    return float(value)


def _str_tuple(value: Any, path: str) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        raise ValueError(f"{path} must be an array")
    values: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{path} must contain strings")
        values.append(item)
    return tuple(values)


def _bool(document: dict[str, Any], key: str) -> bool:
    value = document.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value


def _optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ValueError("expected boolean or null")
    return value


__all__ = [
    "INDEX_SCHEMA_VERSION",
    "PUBLIC_INDEX_SCHEMA_VERSION",
    "EvidenceArtifactRef",
    "EvidenceCaseIndex",
    "EvidenceIndexItem",
    "EvidenceIndexResult",
    "EvidenceScenarioMetadata",
    "PublicEvidenceCaseIndex",
    "PublicEvidenceIndexItem",
    "PublicEvidenceIndexResult",
    "build_evidence_index",
    "build_public_evidence_index",
]
