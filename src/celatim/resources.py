"""Packaged default data for the command-line tools."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from importlib.resources import as_file, files
from pathlib import Path

DEFAULT_CATALOG = "mechanisms.jsonl"
DEFAULT_PROTOCOL_RATES = "protocol_rates.toml"
DEFAULT_SCENARIO_DIR = "scenarios"
DETECTOR_REPLAY_SCHEMA = "detector-replay-v1.schema.json"
DETECTOR_REPLAY_CORPUS_SCHEMA = "detector-replay-corpus-v1.schema.json"
DETECTOR_TRACE_MANIFEST_SCHEMA = "detector-trace-manifest-v1.schema.json"
DOCTOR_SCHEMA = "doctor-v1.schema.json"
EVIDENCE_RUN_SCHEMA = "evidence-run-v1.schema.json"
EVIDENCE_INDEX_SCHEMA = "evidence-index-v1.schema.json"
PUBLIC_EVIDENCE_INDEX_SCHEMA = "public-evidence-index-v1.schema.json"
PUBLIC_BUNDLE_SCHEMA = "public-bundle-v1.schema.json"
PUBLIC_BUNDLE_VERIFY_SCHEMA = "public-bundle-verify-v1.schema.json"
PCAP_DECODE_SCHEMA = "pcap-decode-v1.schema.json"
QEMU_TAP_PREFLIGHT_SCHEMA = "qemu-tap-preflight-v1.schema.json"
REVIEWER_BUNDLE_SCHEMA = "reviewer-bundle-v1.schema.json"
REVIEWER_BUNDLE_VERIFY_SCHEMA = "reviewer-bundle-verify-v1.schema.json"
SCENARIO_SCHEMA = "scenario-v1.schema.json"
SCENARIO_EXECUTION_PLAN_SCHEMA = "scenario-execution-plan-v1.schema.json"
SCENARIO_INVENTORY_SCHEMA = "scenario-inventory-v1.schema.json"
SCRUB_REPORT_SCHEMA = "scrub-report-v1.schema.json"
SUPPORT_MATRIX_SCHEMA = "support-matrix-v1.schema.json"
TESTBED_REQUIREMENTS_SCHEMA = "testbed-requirements-v1.schema.json"
TIMING_SWEEP_SCHEMA = "timing-sweep-v1.schema.json"
DOC_FILES = {
    "api-guide": "api-guide.md",
    "scenario-authoring": "scenario-authoring.md",
    "reviewer-quickstart": "reviewer-quickstart.md",
    "troubleshooting": "troubleshooting.md",
}


@contextmanager
def catalog_path(path: Path | str | None = None) -> Iterator[Path]:
    if path is not None:
        yield Path(path)
        return
    with as_file(files("celatim.data") / DEFAULT_CATALOG) as resource_path:
        yield resource_path


@contextmanager
def protocol_rates_path(path: Path | str | None = None) -> Iterator[Path]:
    if path is not None:
        yield Path(path)
        return
    with as_file(files("celatim.data") / DEFAULT_PROTOCOL_RATES) as resource_path:
        yield resource_path


@contextmanager
def scenario_dir_path(path: Path | None = None) -> Iterator[Path]:
    if path is not None:
        yield path
        return
    with as_file(files("celatim.scenarios")) as resource_path:
        yield resource_path


def schema_text(name: str) -> str:
    if name == "detector-replay-v1":
        schema_file = DETECTOR_REPLAY_SCHEMA
    elif name == "detector-replay-corpus-v1":
        schema_file = DETECTOR_REPLAY_CORPUS_SCHEMA
    elif name == "detector-trace-manifest-v1":
        schema_file = DETECTOR_TRACE_MANIFEST_SCHEMA
    elif name == "evidence-run-v1":
        schema_file = EVIDENCE_RUN_SCHEMA
    elif name == "evidence-index-v1":
        schema_file = EVIDENCE_INDEX_SCHEMA
    elif name == "public-evidence-index-v1":
        schema_file = PUBLIC_EVIDENCE_INDEX_SCHEMA
    elif name == "doctor-v1":
        schema_file = DOCTOR_SCHEMA
    elif name == "public-bundle-v1":
        schema_file = PUBLIC_BUNDLE_SCHEMA
    elif name == "public-bundle-verify-v1":
        schema_file = PUBLIC_BUNDLE_VERIFY_SCHEMA
    elif name == "pcap-decode-v1":
        schema_file = PCAP_DECODE_SCHEMA
    elif name == "qemu-tap-preflight-v1":
        schema_file = QEMU_TAP_PREFLIGHT_SCHEMA
    elif name == "reviewer-bundle-v1":
        schema_file = REVIEWER_BUNDLE_SCHEMA
    elif name == "reviewer-bundle-verify-v1":
        schema_file = REVIEWER_BUNDLE_VERIFY_SCHEMA
    elif name == "scenario-v1":
        schema_file = SCENARIO_SCHEMA
    elif name == "scenario-execution-plan-v1":
        schema_file = SCENARIO_EXECUTION_PLAN_SCHEMA
    elif name == "scenario-inventory-v1":
        schema_file = SCENARIO_INVENTORY_SCHEMA
    elif name == "scrub-report-v1":
        schema_file = SCRUB_REPORT_SCHEMA
    elif name == "support-matrix-v1":
        schema_file = SUPPORT_MATRIX_SCHEMA
    elif name == "testbed-requirements-v1":
        schema_file = TESTBED_REQUIREMENTS_SCHEMA
    elif name == "timing-sweep-v1":
        schema_file = TIMING_SWEEP_SCHEMA
    else:
        raise ValueError(f"unknown schema: {name}")
    return (files("celatim.schemas") / schema_file).read_text()


def doc_names() -> tuple[str, ...]:
    return tuple(sorted(DOC_FILES))


def doc_text(name: str) -> str:
    try:
        doc_file = DOC_FILES[name]
    except KeyError as exc:
        raise ValueError(f"unknown doc: {name}") from exc
    return (files("celatim.docs") / doc_file).read_text()


__all__ = [
    "DEFAULT_CATALOG",
    "DEFAULT_PROTOCOL_RATES",
    "DEFAULT_SCENARIO_DIR",
    "DETECTOR_REPLAY_CORPUS_SCHEMA",
    "DETECTOR_REPLAY_SCHEMA",
    "DETECTOR_TRACE_MANIFEST_SCHEMA",
    "DOCTOR_SCHEMA",
    "DOC_FILES",
    "EVIDENCE_INDEX_SCHEMA",
    "EVIDENCE_RUN_SCHEMA",
    "PCAP_DECODE_SCHEMA",
    "PUBLIC_BUNDLE_SCHEMA",
    "PUBLIC_BUNDLE_VERIFY_SCHEMA",
    "PUBLIC_EVIDENCE_INDEX_SCHEMA",
    "QEMU_TAP_PREFLIGHT_SCHEMA",
    "REVIEWER_BUNDLE_SCHEMA",
    "REVIEWER_BUNDLE_VERIFY_SCHEMA",
    "SCENARIO_EXECUTION_PLAN_SCHEMA",
    "SCENARIO_INVENTORY_SCHEMA",
    "SCENARIO_SCHEMA",
    "SCRUB_REPORT_SCHEMA",
    "SUPPORT_MATRIX_SCHEMA",
    "TESTBED_REQUIREMENTS_SCHEMA",
    "TIMING_SWEEP_SCHEMA",
    "catalog_path",
    "doc_names",
    "doc_text",
    "protocol_rates_path",
    "scenario_dir_path",
    "schema_text",
]
