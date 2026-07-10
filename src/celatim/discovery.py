"""Mechanism discovery helpers for endpoint-library callers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from celatim.adapter import adapter_for
from celatim.catalog import load_mechanisms
from celatim.errors import UnsupportedMechanismError
from celatim.model import Mechanism
from celatim.resources import catalog_path as packaged_catalog_path
from celatim.resources import scenario_dir_path as packaged_scenario_dir_path
from celatim.scenario import (
    ScenarioConfig,
    ScenarioExecutionPlan,
    ScenarioInventory,
    build_scenario_execution_plan,
    build_scenario_inventory,
    load_scenario_by_id,
    scenario_execution_ids,
)


@dataclass(frozen=True)
class MechanismSummary:
    """Compact mechanism and adapter summary for selection UIs and scripts."""

    id: str
    name: str
    protocol: str
    layer: str
    carrier_class: str
    capacity_model: str
    raw_capacity_bits: int
    usable: bool
    adapter_status: str
    evidence_bucket: str
    carrier_structure: str
    control_strength: str
    transport_kinds: tuple[str, ...]
    scenario_ids: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "protocol": self.protocol,
            "layer": self.layer,
            "carrier_class": self.carrier_class,
            "capacity_model": self.capacity_model,
            "raw_capacity_bits": self.raw_capacity_bits,
            "usable": self.usable,
            "adapter_status": self.adapter_status,
            "evidence_bucket": self.evidence_bucket,
            "carrier_structure": self.carrier_structure,
            "control_strength": self.control_strength,
            "transport_kinds": list(self.transport_kinds),
            "scenario_ids": list(self.scenario_ids),
        }


@dataclass(frozen=True)
class MechanismDetail:
    """Detailed catalog, adapter, and evidence metadata for one mechanism."""

    mechanism_id: str
    mechanism: dict[str, Any]
    adapter: dict[str, Any]

    def to_json(self) -> dict[str, Any]:
        return {
            "command": "mechanism show",
            "mechanism": dict(self.mechanism),
            "adapter": dict(self.adapter),
        }


def list_mechanism_summaries(
    *,
    catalog_path: Path | str | None = None,
    usable_only: bool = False,
    transport_kind: str | None = None,
) -> list[MechanismSummary]:
    """Return catalog mechanism summaries with optional selection filters."""

    summaries = [_mechanism_summary(mechanism) for mechanism in _load_mechanisms(catalog_path)]
    if usable_only:
        summaries = [summary for summary in summaries if summary.usable]
    if transport_kind is not None:
        summaries = [summary for summary in summaries if transport_kind in summary.transport_kinds]
    return summaries


def get_mechanism_detail(
    mechanism_id: str,
    *,
    catalog_path: Path | str | None = None,
) -> MechanismDetail:
    """Return detailed mechanism and adapter metadata for one mechanism id."""

    mechanisms = {mechanism.id: mechanism for mechanism in _load_mechanisms(catalog_path)}
    try:
        mechanism = mechanisms[mechanism_id]
    except KeyError as exc:
        raise UnsupportedMechanismError(f"unknown mechanism: {mechanism_id}") from exc
    return _mechanism_detail(mechanism)


def list_scenarios(
    *,
    scenario_dir: Path | str | None = None,
) -> ScenarioInventory:
    """Return inventory metadata for packaged or caller-supplied scenarios."""

    with packaged_scenario_dir_path(_optional_path(scenario_dir)) as directory:
        return build_scenario_inventory(directory)


def plan_scenarios(
    *,
    scenario_dir: Path | str | None = None,
) -> ScenarioExecutionPlan:
    """Return the reviewer execution plan for packaged or caller-supplied scenarios."""

    with packaged_scenario_dir_path(_optional_path(scenario_dir)) as directory:
        return build_scenario_execution_plan(directory)


def list_scenario_ids(
    *,
    scenario_dir: Path | str | None = None,
    default_included_only: bool = False,
) -> tuple[str, ...]:
    """Return scenario ids from the packaged or caller-supplied scenario set."""

    with packaged_scenario_dir_path(_optional_path(scenario_dir)) as directory:
        return scenario_execution_ids(
            directory,
            default_included_only=default_included_only,
        )


def get_scenario(
    scenario_id: str,
    *,
    scenario_dir: Path | str | None = None,
) -> ScenarioConfig:
    """Load a scenario config by id from packaged or caller-supplied scenarios."""

    with packaged_scenario_dir_path(_optional_path(scenario_dir)) as directory:
        return load_scenario_by_id(directory, scenario_id)


def _load_mechanisms(catalog: Path | str | None) -> list[Mechanism]:
    with packaged_catalog_path(catalog) as path:
        return load_mechanisms(path)


def _optional_path(path: Path | str | None) -> Path | None:
    return Path(path) if path is not None else None


def _mechanism_summary(mechanism: Mechanism) -> MechanismSummary:
    adapter = adapter_for(mechanism)
    return MechanismSummary(
        id=mechanism.id,
        name=mechanism.name,
        protocol=mechanism.protocol,
        layer=mechanism.layer,
        carrier_class=mechanism.carrier_class.value,
        capacity_model=mechanism.capacity_model.value,
        raw_capacity_bits=mechanism.raw_capacity_bits,
        usable=mechanism.is_usable_channel,
        adapter_status=adapter.status.value,
        evidence_bucket=adapter.evidence.bucket.value,
        carrier_structure=adapter.evidence.carrier_structure.value,
        control_strength=adapter.evidence.control_strength.value,
        transport_kinds=adapter.transport_kinds,
        scenario_ids=tuple(
            sorted(path.scenario_id for path in adapter.paths if path.scenario_id is not None)
        ),
    )


def _mechanism_detail(mechanism: Mechanism) -> MechanismDetail:
    adapter = adapter_for(mechanism)
    return MechanismDetail(
        mechanism_id=mechanism.id,
        mechanism={
            "id": mechanism.id,
            "name": mechanism.name,
            "protocol": mechanism.protocol,
            "layer": mechanism.layer,
            "rfcs": list(mechanism.rfcs),
            "carrier_class": mechanism.carrier_class.value,
            "status": mechanism.status.value,
            "carrier_unit": mechanism.carrier_unit,
            "capacity_model": mechanism.capacity_model.value,
            "raw_capacity_bits": mechanism.raw_capacity_bits,
            "bits_min": mechanism.bits_min,
            "bits_max": mechanism.bits_max,
            "unbounded": mechanism.unbounded,
            "header_bits": mechanism.header_bits,
            "wire_bits_typical": mechanism.wire_bits_typical,
            "reach": mechanism.reach.value,
            "survivability": mechanism.survivability.value,
            "on_path_visibility": mechanism.on_path_visibility.value,
            "robust_unwitting": mechanism.robust_unwitting,
            "scrub_strategy": mechanism.scrub_strategy.value,
            "detect_predicate": mechanism.effective_detect_predicate.value,
            "false_positive": mechanism.effective_false_positive.value,
            "detection_annotation_source": mechanism.detection_annotation_source.value,
            "usable": mechanism.is_usable_channel,
            "negative_result": mechanism.negative_result,
            "locator": _locator_to_json(mechanism.locator),
            "spec_quote": mechanism.spec_quote,
        },
        adapter={
            "status": adapter.status.value,
            "capabilities": sorted(capability.value for capability in adapter.capabilities),
            "required_privilege": adapter.required_privilege,
            "required_binaries": list(adapter.required_binaries),
            "required_extras": list(adapter.required_extras),
            "supports_carrier_bytes": adapter.supports_carrier_bytes,
            "transport_kinds": list(adapter.transport_kinds),
            "paths": [path.to_json() for path in adapter.paths],
            "evidence": _evidence_profile_to_json(adapter.evidence),
        },
    )


def _evidence_profile_to_json(evidence: Any) -> dict[str, Any]:
    return {
        "mechanism_id": evidence.mechanism_id,
        "bucket": evidence.bucket.value,
        "carrier_structure": evidence.carrier_structure.value,
        "control_strength": evidence.control_strength.value,
        "independent_validator": evidence.independent_validator.value,
        "throughput_status": evidence.throughput_status.value,
        "upgrade_priority": evidence.upgrade_priority.value,
        "notes": evidence.notes,
    }


def _locator_to_json(locator: Any | None) -> dict[str, Any] | None:
    if locator is None:
        return None
    return {
        "base": locator.base.value,
        "bit_offset": locator.bit_offset,
        "bit_width": locator.bit_width,
        "byte_offset": locator.byte_offset,
        "byte_mask": locator.byte_mask if locator.spans_single_byte else None,
    }


__all__ = [
    "MechanismDetail",
    "MechanismSummary",
    "get_mechanism_detail",
    "get_scenario",
    "list_mechanism_summaries",
    "list_scenario_ids",
    "list_scenarios",
    "plan_scenarios",
]
