"""Packaged default data for the command-line tools."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from importlib.resources import as_file, files
from pathlib import Path

DEFAULT_CATALOG = "mechanisms.jsonl"
DEFAULT_PROTOCOL_RATES = "protocol_rates.toml"
DEFAULT_SCENARIO_DIR = "scenarios"
CARRIER_ENDPOINT_SCHEMA = "carrier-endpoint-v1.schema.json"
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
TRANSFER_OFFER_SCHEMA = "transfer-offer-v1.schema.json"
TRANSFER_MANIFEST_SCHEMA = "transfer-manifest-v1.schema.json"
TRANSFER_STATE_SCHEMA = "transfer-state-v1.schema.json"
TRANSFER_RECEIPT_SCHEMA = "transfer-receipt-v1.schema.json"
TRANSFER_EVENT_SCHEMA = "transfer-event-v1.schema.json"
TRANSFER_ERROR_SCHEMA = "transfer-error-v1.schema.json"
PROVIDER_MANIFEST_SCHEMA = "provider-manifest-v1.schema.json"
PACKET_SERVICE_SCHEMA = "packet-service-v1.schema.json"
PACKET_SERVICE_PREFLIGHT_SCHEMA = "packet-service-preflight-v1.schema.json"
PROVIDER_CONFORMANCE_SCHEMA = "provider-conformance-v1.schema.json"
PROVIDER_INVENTORY_SCHEMA = "provider-inventory-v1.schema.json"
TRANSFER_LISTENER_STATUS_SCHEMA = "transfer-listener-status-v1.schema.json"
TRANSFER_LISTENER_STOP_SCHEMA = "transfer-listener-stop-v1.schema.json"
TRANSFER_STATUS_SCHEMA = "transfer-status-v1.schema.json"
SCHEMA_FILES = {
    "carrier-endpoint-v1": CARRIER_ENDPOINT_SCHEMA,
    "detector-replay-v1": DETECTOR_REPLAY_SCHEMA,
    "detector-replay-corpus-v1": DETECTOR_REPLAY_CORPUS_SCHEMA,
    "detector-trace-manifest-v1": DETECTOR_TRACE_MANIFEST_SCHEMA,
    "doctor-v1": DOCTOR_SCHEMA,
    "evidence-run-v1": EVIDENCE_RUN_SCHEMA,
    "evidence-index-v1": EVIDENCE_INDEX_SCHEMA,
    "packet-service-v1": PACKET_SERVICE_SCHEMA,
    "packet-service-preflight-v1": PACKET_SERVICE_PREFLIGHT_SCHEMA,
    "pcap-decode-v1": PCAP_DECODE_SCHEMA,
    "provider-manifest-v1": PROVIDER_MANIFEST_SCHEMA,
    "provider-conformance-v1": PROVIDER_CONFORMANCE_SCHEMA,
    "provider-inventory-v1": PROVIDER_INVENTORY_SCHEMA,
    "public-evidence-index-v1": PUBLIC_EVIDENCE_INDEX_SCHEMA,
    "public-bundle-v1": PUBLIC_BUNDLE_SCHEMA,
    "public-bundle-verify-v1": PUBLIC_BUNDLE_VERIFY_SCHEMA,
    "qemu-tap-preflight-v1": QEMU_TAP_PREFLIGHT_SCHEMA,
    "reviewer-bundle-v1": REVIEWER_BUNDLE_SCHEMA,
    "reviewer-bundle-verify-v1": REVIEWER_BUNDLE_VERIFY_SCHEMA,
    "scenario-v1": SCENARIO_SCHEMA,
    "scenario-execution-plan-v1": SCENARIO_EXECUTION_PLAN_SCHEMA,
    "scenario-inventory-v1": SCENARIO_INVENTORY_SCHEMA,
    "scrub-report-v1": SCRUB_REPORT_SCHEMA,
    "support-matrix-v1": SUPPORT_MATRIX_SCHEMA,
    "testbed-requirements-v1": TESTBED_REQUIREMENTS_SCHEMA,
    "timing-sweep-v1": TIMING_SWEEP_SCHEMA,
    "transfer-error-v1": TRANSFER_ERROR_SCHEMA,
    "transfer-event-v1": TRANSFER_EVENT_SCHEMA,
    "transfer-manifest-v1": TRANSFER_MANIFEST_SCHEMA,
    "transfer-listener-status-v1": TRANSFER_LISTENER_STATUS_SCHEMA,
    "transfer-listener-stop-v1": TRANSFER_LISTENER_STOP_SCHEMA,
    "transfer-offer-v1": TRANSFER_OFFER_SCHEMA,
    "transfer-receipt-v1": TRANSFER_RECEIPT_SCHEMA,
    "transfer-state-v1": TRANSFER_STATE_SCHEMA,
    "transfer-status-v1": TRANSFER_STATUS_SCHEMA,
}
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
    try:
        schema_file = SCHEMA_FILES[name]
    except KeyError as exc:
        raise ValueError(f"unknown schema: {name}") from exc

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
    "CARRIER_ENDPOINT_SCHEMA",
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
    "PACKET_SERVICE_PREFLIGHT_SCHEMA",
    "PACKET_SERVICE_SCHEMA",
    "PCAP_DECODE_SCHEMA",
    "PROVIDER_CONFORMANCE_SCHEMA",
    "PROVIDER_INVENTORY_SCHEMA",
    "PROVIDER_MANIFEST_SCHEMA",
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
    "TRANSFER_ERROR_SCHEMA",
    "TRANSFER_EVENT_SCHEMA",
    "TRANSFER_LISTENER_STATUS_SCHEMA",
    "TRANSFER_LISTENER_STOP_SCHEMA",
    "TRANSFER_MANIFEST_SCHEMA",
    "TRANSFER_OFFER_SCHEMA",
    "TRANSFER_RECEIPT_SCHEMA",
    "TRANSFER_STATE_SCHEMA",
    "TRANSFER_STATUS_SCHEMA",
    "catalog_path",
    "doc_names",
    "doc_text",
    "protocol_rates_path",
    "scenario_dir_path",
    "schema_text",
]
