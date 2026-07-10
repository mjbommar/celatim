"""Packaged documentation and report helpers for public API callers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from celatim.catalog import load_mechanisms
from celatim.report import (
    DetectorRuleArtifact,
    ProtocolRate,
    ProtocolThroughputEstimate,
    SupportMatrixReport,
    detector_rule_artifacts,
    detector_rule_manifest,
    detector_scrub_guidance_markdown,
    load_protocol_rates,
    protocol_rates_markdown,
    support_matrix_markdown,
    support_matrix_report,
    throughput_estimates,
    windows_pktmon_guidance_markdown,
)
from celatim.report import (
    write_detector_rule_artifacts as write_packaged_detector_rule_artifacts,
)
from celatim.resources import catalog_path as packaged_catalog_path
from celatim.resources import doc_names as packaged_doc_names
from celatim.resources import doc_text as packaged_doc_text
from celatim.resources import protocol_rates_path as packaged_protocol_rates_path
from celatim.resources import schema_text as packaged_schema_text
from celatim.testbed import (
    HostTapConfig,
    QemuGuestConfig,
    QemuTapPreflightReport,
    TestbedRequirementInventory,
    build_qemu_tap_preflight_report,
    build_testbed_requirements_inventory,
)

SCHEMA_NAMES = (
    "detector-replay-v1",
    "detector-replay-corpus-v1",
    "detector-trace-manifest-v1",
    "doctor-v1",
    "evidence-index-v1",
    "evidence-run-v1",
    "pcap-decode-v1",
    "public-bundle-v1",
    "public-bundle-verify-v1",
    "public-evidence-index-v1",
    "qemu-tap-preflight-v1",
    "reviewer-bundle-v1",
    "reviewer-bundle-verify-v1",
    "scenario-execution-plan-v1",
    "scenario-inventory-v1",
    "scenario-v1",
    "scrub-report-v1",
    "support-matrix-v1",
    "testbed-requirements-v1",
    "timing-sweep-v1",
)


@dataclass(frozen=True)
class DocumentSummary:
    """One packaged documentation resource available through the public API."""

    name: str

    def to_json(self) -> dict[str, Any]:
        return {"name": self.name}


@dataclass(frozen=True)
class SchemaSummary:
    """One packaged JSON Schema resource available through the public API."""

    name: str

    def to_json(self) -> dict[str, Any]:
        return {"name": self.name}


def list_documents() -> list[DocumentSummary]:
    """Return the packaged documentation resources available to callers."""

    return [DocumentSummary(name) for name in packaged_doc_names()]


def get_document_text(name: str) -> str:
    """Return the text for one packaged documentation resource."""

    return packaged_doc_text(name)


def list_schemas() -> list[SchemaSummary]:
    """Return packaged JSON Schema resources available to callers."""

    return [SchemaSummary(name) for name in SCHEMA_NAMES]


def get_schema_text(name: str) -> str:
    """Return the JSON Schema text for one packaged schema resource."""

    if name not in SCHEMA_NAMES:
        raise ValueError(f"unknown schema: {name}")
    return packaged_schema_text(name)


def list_protocol_rates(
    *,
    rates_path: Path | str | None = None,
) -> list[ProtocolRate]:
    """Return packaged carrier-unit rate assumptions for structural upper bounds."""

    with packaged_protocol_rates_path(rates_path) as path:
        return list(load_protocol_rates(path))


def get_protocol_throughput_estimates(
    *,
    catalog_path: Path | str | None = None,
    rates_path: Path | str | None = None,
) -> list[ProtocolThroughputEstimate]:
    """Return structural throughput upper-bound estimates from catalog and rates."""

    with (
        packaged_catalog_path(catalog_path) as catalog,
        packaged_protocol_rates_path(rates_path) as rates,
    ):
        return list(throughput_estimates(load_mechanisms(catalog), load_protocol_rates(rates)))


def get_protocol_rates_markdown(
    *,
    catalog_path: Path | str | None = None,
    rates_path: Path | str | None = None,
) -> str:
    """Return reviewer-readable protocol-rate assumptions Markdown."""

    with (
        packaged_catalog_path(catalog_path) as catalog,
        packaged_protocol_rates_path(rates_path) as rates,
    ):
        return protocol_rates_markdown(load_mechanisms(catalog), load_protocol_rates(rates))


def get_detector_scrub_guidance_markdown(
    *,
    catalog_path: Path | str | None = None,
) -> str:
    """Return public-safe detector and scrubber guidance from the catalog."""

    with packaged_catalog_path(catalog_path) as catalog:
        return detector_scrub_guidance_markdown(load_mechanisms(catalog))


def get_windows_capture_guidance_markdown() -> str:
    """Return public-safe Windows pktmon/ETW capture guidance."""

    return windows_pktmon_guidance_markdown()


def get_detector_rule_artifacts(
    *,
    catalog_path: Path | str | None = None,
) -> list[DetectorRuleArtifact]:
    """Return public-safe generated detector rule artifacts for a catalog."""

    with packaged_catalog_path(catalog_path) as catalog:
        return list(detector_rule_artifacts(load_mechanisms(catalog)))


def get_detector_rule_manifest(
    *,
    catalog_path: Path | str | None = None,
    output_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Return the generated detector rule manifest for a catalog."""

    with packaged_catalog_path(catalog_path) as catalog:
        return detector_rule_manifest(load_mechanisms(catalog), output_dir=output_dir)


def write_detector_rule_files(
    output_dir: Path | str,
    *,
    catalog_path: Path | str | None = None,
) -> list[Path]:
    """Write generated detector rule artifacts and return their paths."""

    with packaged_catalog_path(catalog_path) as catalog:
        return list(write_packaged_detector_rule_artifacts(load_mechanisms(catalog), output_dir))


def get_support_matrix_report(
    *,
    catalog_path: Path | str | None = None,
) -> SupportMatrixReport:
    """Return the schema-backed support matrix report for a catalog."""

    with packaged_catalog_path(catalog_path) as catalog:
        return support_matrix_report(load_mechanisms(catalog))


def get_support_matrix_markdown(
    *,
    catalog_path: Path | str | None = None,
) -> str:
    """Return the reviewer-readable support matrix Markdown for a catalog."""

    with packaged_catalog_path(catalog_path) as catalog:
        return support_matrix_markdown(load_mechanisms(catalog))


def get_testbed_requirements(
    profile_ids: tuple[str, ...] | list[str] | None = None,
) -> TestbedRequirementInventory:
    """Return privileged/daemon/VM testbed requirement profiles."""

    return build_testbed_requirements_inventory(profile_ids)


def get_qemu_tap_preflight_report(
    guest_config: QemuGuestConfig,
    tap_config: HostTapConfig | None = None,
    *,
    tcpdump_binary: str = "tcpdump",
    kvm_device: Path | str = Path("/dev/kvm"),
) -> QemuTapPreflightReport:
    """Return a non-mutating QEMU/TAP readiness report."""

    return build_qemu_tap_preflight_report(
        guest_config,
        tap_config,
        tcpdump_binary=tcpdump_binary,
        kvm_device=kvm_device,
    )


__all__ = [
    "SCHEMA_NAMES",
    "DetectorRuleArtifact",
    "DocumentSummary",
    "SchemaSummary",
    "get_detector_rule_artifacts",
    "get_detector_rule_manifest",
    "get_detector_scrub_guidance_markdown",
    "get_document_text",
    "get_protocol_rates_markdown",
    "get_protocol_throughput_estimates",
    "get_qemu_tap_preflight_report",
    "get_schema_text",
    "get_support_matrix_markdown",
    "get_support_matrix_report",
    "get_testbed_requirements",
    "get_windows_capture_guidance_markdown",
    "list_documents",
    "list_protocol_rates",
    "list_schemas",
    "write_detector_rule_files",
]
