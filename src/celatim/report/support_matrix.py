"""Render the current evidence/support matrix as Markdown or JSON."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from ..adapter import AdapterPathKind, AdapterStatus, MechanismAdapter, adapter_for
from ..evidence import (
    CarrierStructure,
    ControlStrength,
    EvidenceBucket,
    EvidenceProfile,
    IndependentValidator,
    ThroughputStatus,
    UpgradePriority,
    bucket_counts,
    classify_evidence,
)
from ..model import Mechanism

SUPPORT_MATRIX_SCHEMA_VERSION = "celatim.support_matrix.v1"


@dataclass(frozen=True)
class SupportMatrixRow:
    mechanism_id: str
    protocol: str
    carrier_class: str
    status: str
    adapter_status: str
    adapter_capabilities: tuple[str, ...]
    adapter_paths: tuple[dict[str, Any], ...]
    required_privilege: str
    required_binaries: tuple[str, ...]
    required_extras: tuple[str, ...]
    evidence_bucket: str
    carrier_structure: str
    control_strength: str
    independent_validator: str
    throughput_status: str
    upgrade_priority: str
    negative_result: bool
    notes: str

    def to_json(self) -> dict[str, Any]:
        return {
            "mechanism_id": self.mechanism_id,
            "protocol": self.protocol,
            "carrier_class": self.carrier_class,
            "status": self.status,
            "adapter_status": self.adapter_status,
            "adapter_capabilities": list(self.adapter_capabilities),
            "adapter_paths": list(self.adapter_paths),
            "required_privilege": self.required_privilege,
            "required_binaries": list(self.required_binaries),
            "required_extras": list(self.required_extras),
            "evidence_bucket": self.evidence_bucket,
            "carrier_structure": self.carrier_structure,
            "control_strength": self.control_strength,
            "independent_validator": self.independent_validator,
            "throughput_status": self.throughput_status,
            "upgrade_priority": self.upgrade_priority,
            "negative_result": self.negative_result,
            "notes": self.notes,
        }


@dataclass(frozen=True)
class SupportMatrixReport:
    schema_version: str
    mechanism_count: int
    marquee_count: int
    evidence_bucket_counts: dict[str, int]
    carrier_structure_counts: dict[str, int]
    control_strength_counts: dict[str, int]
    independent_validator_counts: dict[str, int]
    throughput_status_counts: dict[str, int]
    upgrade_priority_counts: dict[str, int]
    adapter_status_counts: dict[str, int]
    adapter_path_kind_counts: dict[str, int]
    rows: tuple[SupportMatrixRow, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "mechanism_count": self.mechanism_count,
            "marquee_count": self.marquee_count,
            "evidence_bucket_counts": dict(self.evidence_bucket_counts),
            "carrier_structure_counts": dict(self.carrier_structure_counts),
            "control_strength_counts": dict(self.control_strength_counts),
            "independent_validator_counts": dict(self.independent_validator_counts),
            "throughput_status_counts": dict(self.throughput_status_counts),
            "upgrade_priority_counts": dict(self.upgrade_priority_counts),
            "adapter_status_counts": dict(self.adapter_status_counts),
            "adapter_path_kind_counts": dict(self.adapter_path_kind_counts),
            "rows": [row.to_json() for row in self.rows],
        }


def support_matrix_markdown(mechanisms: Iterable[Mechanism]) -> str:
    mechs = list(mechanisms)
    profiles = [classify_evidence(m) for m in mechs]
    by_id = {m.id: m for m in mechs}
    adapters = {m.id: adapter_for(m) for m in mechs}
    counts = bucket_counts(profiles)
    rows = [
        "# Evidence Support Matrix",
        "",
        "Generated from the packaged Celatim mechanism catalog and the conservative current",
        "evidence classifier in `celatim.evidence`. This matrix is deliberately stricter",
        "than the old wire-battery headline: zero-filled nominal-offset rows are separated",
        "from real-PDU and real-daemon evidence.",
        "",
        "## Summary",
        "",
        "| Evidence bucket | Count |",
        "|---|---:|",
    ]
    rows.extend(f"| `{bucket.value}` | {counts[bucket]} |" for bucket in EvidenceBucket)
    path_counts = _enum_counts(
        AdapterPathKind,
        (path.kind.value for adapter in adapters.values() for path in adapter.paths),
    )
    rows.extend(
        [
            "",
            "| Adapter path | Count |",
            "|---|---:|",
        ]
    )
    rows.extend(f"| `{kind.value}` | {path_counts[kind.value]} |" for kind in AdapterPathKind)
    rows.extend(
        [
            "",
            "## Marquee Upgrade Subset",
            "",
            "These rows are the pre-submission upgrade gate. Each needs real carrier",
            "structure, a discriminating control, and an independent validator unless it",
            "already has a stronger daemon/crypto path.",
            "",
            _table_header(),
        ]
    )
    rows.extend(
        _profile_row(p, by_id[p.mechanism_id], adapters[p.mechanism_id])
        for p in profiles
        if p.upgrade_priority is UpgradePriority.MARQUEE
    )
    rows.extend(
        [
            "",
            "## Full Matrix",
            "",
            _table_header(),
        ]
    )
    rows.extend(_profile_row(p, by_id[p.mechanism_id], adapters[p.mechanism_id]) for p in profiles)
    rows.append("")
    return "\n".join(rows)


def support_matrix_report(mechanisms: Iterable[Mechanism]) -> SupportMatrixReport:
    mechs = list(mechanisms)
    profiles = [classify_evidence(m) for m in mechs]
    adapters = [adapter_for(m) for m in mechs]
    rows = tuple(
        _report_row(profile, mechanism, adapter)
        for profile, mechanism, adapter in zip(profiles, mechs, adapters, strict=True)
    )
    return SupportMatrixReport(
        schema_version=SUPPORT_MATRIX_SCHEMA_VERSION,
        mechanism_count=len(rows),
        marquee_count=sum(
            1 for row in rows if row.upgrade_priority == UpgradePriority.MARQUEE.value
        ),
        evidence_bucket_counts=_enum_counts(EvidenceBucket, (row.evidence_bucket for row in rows)),
        carrier_structure_counts=_enum_counts(
            CarrierStructure,
            (row.carrier_structure for row in rows),
        ),
        control_strength_counts=_enum_counts(
            ControlStrength,
            (row.control_strength for row in rows),
        ),
        independent_validator_counts=_enum_counts(
            IndependentValidator,
            (row.independent_validator for row in rows),
        ),
        throughput_status_counts=_enum_counts(
            ThroughputStatus,
            (row.throughput_status for row in rows),
        ),
        upgrade_priority_counts=_enum_counts(
            UpgradePriority,
            (row.upgrade_priority for row in rows),
        ),
        adapter_status_counts=_enum_counts(AdapterStatus, (row.adapter_status for row in rows)),
        adapter_path_kind_counts=_enum_counts(
            AdapterPathKind,
            (str(path["kind"]) for row in rows for path in row.adapter_paths),
        ),
        rows=rows,
    )


def _table_header() -> str:
    return (
        "| Mechanism | Protocol | Class | Adapter | Capabilities | Paths | Bucket | "
        "Carrier structure | Control | Independent validator | Throughput | Priority |\n"
        "|---|---|---:|---|---|---|---|---|---|---|---|---|"
    )


def _profile_row(profile: EvidenceProfile, mechanism: Mechanism, adapter: MechanismAdapter) -> str:
    capabilities = ", ".join(
        f"`{capability.value}`"
        for capability in sorted(adapter.capabilities, key=lambda c: c.value)
    )
    paths = ", ".join(f"`{path.kind.value}`" for path in adapter.paths) or "`none`"
    return (
        f"| `{mechanism.id}` | {mechanism.protocol} | {mechanism.carrier_class.value} | "
        f"`{adapter.status.value}` | {capabilities} | "
        f"{paths} | "
        f"`{profile.bucket.value}` | `{profile.carrier_structure.value}` | "
        f"`{profile.control_strength.value}` | `{profile.independent_validator.value}` | "
        f"`{profile.throughput_status.value}` | `{profile.upgrade_priority.value}` |"
    )


def _report_row(
    profile: EvidenceProfile,
    mechanism: Mechanism,
    adapter: MechanismAdapter,
) -> SupportMatrixRow:
    return SupportMatrixRow(
        mechanism_id=mechanism.id,
        protocol=mechanism.protocol,
        carrier_class=mechanism.carrier_class.value,
        status=mechanism.status,
        adapter_status=adapter.status.value,
        adapter_capabilities=tuple(sorted(capability.value for capability in adapter.capabilities)),
        adapter_paths=tuple(path.to_json() for path in adapter.paths),
        required_privilege=adapter.required_privilege,
        required_binaries=tuple(adapter.required_binaries),
        required_extras=tuple(adapter.required_extras),
        evidence_bucket=profile.bucket.value,
        carrier_structure=profile.carrier_structure.value,
        control_strength=profile.control_strength.value,
        independent_validator=profile.independent_validator.value,
        throughput_status=profile.throughput_status.value,
        upgrade_priority=profile.upgrade_priority.value,
        negative_result=mechanism.negative_result,
        notes=profile.notes,
    )


def _enum_counts(enum_type: type[Any], values: Iterable[str]) -> dict[str, int]:
    counts = {item.value: 0 for item in enum_type}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return counts


__all__ = [
    "SUPPORT_MATRIX_SCHEMA_VERSION",
    "SupportMatrixReport",
    "SupportMatrixRow",
    "support_matrix_markdown",
    "support_matrix_report",
]
