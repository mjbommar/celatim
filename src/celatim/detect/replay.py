"""Replay generated detector rules over pcap traces.

This module is intentionally trace-level rather than scenario-level. Scenario
controls remain useful smoke fixtures, while public or otherwise authorized benign
traces can produce false-positive estimates with explicit source provenance.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from enum import Enum
from math import sqrt
from pathlib import Path
from time import time
from typing import Any, cast

from ..model import Detectability, Mechanism
from .rules import (
    DetectorImplementationKind,
    DetectorProvenanceRecord,
    bpf_filter,
    classic_pcap_record_count,
    disposition,
    emittable,
    tcpdump_bpf_provenance_record,
)

DETECTOR_REPLAY_SCHEMA_VERSION = "celatim.detector_replay.v1"
DETECTOR_REPLAY_CORPUS_SCHEMA_VERSION = "celatim.detector_replay_corpus.v1"
DETECTOR_TRACE_MANIFEST_SCHEMA_VERSION = "celatim.detector_trace_manifest.v1"


class TraceSourceKind(str, Enum):
    """Trace provenance bucket for detector replay."""

    PUBLIC_BENIGN_TRACE = "public_benign_trace"
    AUTHORIZED_BENIGN_TRACE = "authorized_benign_trace"
    LOCAL_GENERATED_CONTROL = "local_generated_control"
    SCENARIO_CONTROL_FIXTURE = "scenario_control_fixture"
    UNKNOWN = "unknown"


class DetectorReplayBackend(str, Enum):
    """Independent detector backend used for trace replay."""

    BPF = "bpf"
    TSHARK_DISPLAY_FILTER = "tshark_display_filter"
    SURICATA_RULE = "suricata_rule"


FALSE_POSITIVE_SOURCE_KINDS = {
    TraceSourceKind.PUBLIC_BENIGN_TRACE,
    TraceSourceKind.AUTHORIZED_BENIGN_TRACE,
}
FALSE_POSITIVE_CLAIM_READY = "false_positive_estimate_ready"
FALSE_POSITIVE_CLAIM_NOT_READY = "not_false_positive_estimate"

_TSHARK_DISPLAY_FILTERS = {
    "tcp-reserved-bits": "tcp.flags.res != 0",
}

_BPF_SCOPE_FILTERS = {
    "tcp-reserved-bits": "tcp",
    "ipv4-reserved-flag": "ip",
}

_TSHARK_SCOPE_FILTERS = {
    "tcp-reserved-bits": "tcp",
}

_SURICATA_SCOPE_FILTERS = {
    "tcp-reserved-bits": "tcp",
}

_SURICATA_RULES = {
    "tcp-reserved-bits": (
        9_301_001,
        (
            'alert tcp any any -> any any (msg:"CELATIM tcp-reserved-bits TCP '
            'reserved bits nonzero"; flow:stateless; tcp.hdr; '
            "byte_test:1,&,0x0e,12; classtype:policy-violation; "
            "sid:9301001; rev:1;)"
        ),
    ),
}


@dataclass(frozen=True)
class DetectorReplayTrace:
    path: str
    sha256: str
    size_bytes: int
    packet_count: int
    source_kind: TraceSourceKind
    trace_name: str | None
    origin_url: str | None
    license: str | None
    filtering_assumptions: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "packet_count": self.packet_count,
            "source_kind": self.source_kind.value,
            "trace_name": self.trace_name,
            "origin_url": self.origin_url,
            "license": self.license,
            "filtering_assumptions": list(self.filtering_assumptions),
        }


@dataclass(frozen=True)
class DetectorReplayTraceSpec:
    path: Path
    source_kind: TraceSourceKind
    trace_name: str | None = None
    origin_url: str | None = None
    license: str | None = None
    filtering_assumptions: tuple[str, ...] = ()

    @classmethod
    def from_json(
        cls,
        document: dict[str, Any],
        *,
        base_dir: Path | None = None,
    ) -> DetectorReplayTraceSpec:
        path_value = document.get("path")
        if not isinstance(path_value, str) or not path_value:
            raise ValueError("detector trace manifest entries require a non-empty string path")
        path = Path(path_value)
        if not path.is_absolute() and base_dir is not None:
            path = base_dir / path
        return cls(
            path=path,
            source_kind=_source_kind(_optional_string(document, "source_kind") or "unknown"),
            trace_name=_optional_string(document, "trace_name"),
            origin_url=_optional_string(document, "origin_url"),
            license=_optional_string(document, "license"),
            filtering_assumptions=_string_tuple(document.get("filtering_assumptions", ())),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "source_kind": self.source_kind.value,
            "trace_name": self.trace_name,
            "origin_url": self.origin_url,
            "license": self.license,
            "filtering_assumptions": list(self.filtering_assumptions),
        }


@dataclass(frozen=True)
class DetectorReplayMechanismResult:
    mechanism_id: str
    mechanism_name: str
    ok: bool
    error: str | None
    matched_rate: float | None
    false_positive_estimate: bool
    false_positive_rate: float | None
    detector_provenance: DetectorProvenanceRecord | None

    def to_json(self) -> dict[str, Any]:
        provenance = (
            None if self.detector_provenance is None else self.detector_provenance.to_json()
        )
        return {
            "mechanism_id": self.mechanism_id,
            "mechanism_name": self.mechanism_name,
            "ok": self.ok,
            "error": self.error,
            "matched_rate": self.matched_rate,
            "false_positive_estimate": self.false_positive_estimate,
            "false_positive_rate": self.false_positive_rate,
            "detector_provenance": provenance,
        }


@dataclass(frozen=True)
class DetectorReplayTraceSummary:
    trace: DetectorReplayTrace
    ok: bool
    mechanism_count: int
    executed_count: int
    failed_count: int
    matched_mechanism_count: int
    checked_unit_count: int
    matched_unit_count: int
    aggregate_matched_rate: float | None
    false_positive_estimate: bool
    false_positive_claim_status: str
    false_positive_claim_blockers: tuple[str, ...]
    aggregate_false_positive_rate: float | None

    @classmethod
    def from_report(cls, report: DetectorReplayReport) -> DetectorReplayTraceSummary:
        return cls(
            trace=report.trace,
            ok=report.ok,
            mechanism_count=report.mechanism_count,
            executed_count=report.executed_count,
            failed_count=report.failed_count,
            matched_mechanism_count=report.matched_mechanism_count,
            checked_unit_count=report.checked_unit_count,
            matched_unit_count=report.matched_unit_count,
            aggregate_matched_rate=report.aggregate_matched_rate,
            false_positive_estimate=report.false_positive_estimate,
            false_positive_claim_status=report.false_positive_claim_status,
            false_positive_claim_blockers=report.false_positive_claim_blockers,
            aggregate_false_positive_rate=report.aggregate_false_positive_rate,
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "trace": self.trace.to_json(),
            "ok": self.ok,
            "mechanism_count": self.mechanism_count,
            "executed_count": self.executed_count,
            "failed_count": self.failed_count,
            "matched_mechanism_count": self.matched_mechanism_count,
            "checked_unit_count": self.checked_unit_count,
            "matched_unit_count": self.matched_unit_count,
            "aggregate_matched_rate": self.aggregate_matched_rate,
            "false_positive_estimate": self.false_positive_estimate,
            "false_positive_claim_status": self.false_positive_claim_status,
            "false_positive_claim_blockers": list(self.false_positive_claim_blockers),
            "aggregate_false_positive_rate": self.aggregate_false_positive_rate,
        }


@dataclass(frozen=True)
class DetectorReplayCorpusMechanismSummary:
    mechanism_id: str
    mechanism_name: str
    trace_count: int
    executed_trace_count: int
    failed_trace_count: int
    checked_unit_count: int
    matched_unit_count: int
    false_positive_estimate: bool
    false_positive_rate: float | None
    false_positive_wilson95: tuple[float, float] | None
    trace_false_positive_rates: tuple[float | None, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "mechanism_id": self.mechanism_id,
            "mechanism_name": self.mechanism_name,
            "trace_count": self.trace_count,
            "executed_trace_count": self.executed_trace_count,
            "failed_trace_count": self.failed_trace_count,
            "checked_unit_count": self.checked_unit_count,
            "matched_unit_count": self.matched_unit_count,
            "false_positive_estimate": self.false_positive_estimate,
            "false_positive_rate": self.false_positive_rate,
            "false_positive_wilson95": (
                None if self.false_positive_wilson95 is None else list(self.false_positive_wilson95)
            ),
            "trace_false_positive_rates": list(self.trace_false_positive_rates),
        }


@dataclass(frozen=True)
class DetectorReplayReport:
    schema_version: str
    generated_at_unix_s: float
    ok: bool
    command: tuple[str, ...]
    trace: DetectorReplayTrace
    mechanism_count: int
    executed_count: int
    failed_count: int
    matched_mechanism_count: int
    checked_unit_count: int
    matched_unit_count: int
    aggregate_matched_rate: float | None
    false_positive_estimate: bool
    false_positive_claim_status: str
    false_positive_claim_blockers: tuple[str, ...]
    aggregate_false_positive_rate: float | None
    mechanisms: tuple[DetectorReplayMechanismResult, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at_unix_s": self.generated_at_unix_s,
            "ok": self.ok,
            "command": list(self.command),
            "trace": self.trace.to_json(),
            "mechanism_count": self.mechanism_count,
            "executed_count": self.executed_count,
            "failed_count": self.failed_count,
            "matched_mechanism_count": self.matched_mechanism_count,
            "checked_unit_count": self.checked_unit_count,
            "matched_unit_count": self.matched_unit_count,
            "aggregate_matched_rate": self.aggregate_matched_rate,
            "false_positive_estimate": self.false_positive_estimate,
            "false_positive_claim_status": self.false_positive_claim_status,
            "false_positive_claim_blockers": list(self.false_positive_claim_blockers),
            "aggregate_false_positive_rate": self.aggregate_false_positive_rate,
            "mechanisms": [mechanism.to_json() for mechanism in self.mechanisms],
        }


@dataclass(frozen=True)
class DetectorReplayCorpusReport:
    schema_version: str
    generated_at_unix_s: float
    ok: bool
    command: tuple[str, ...]
    trace_count: int
    ok_trace_count: int
    failed_trace_count: int
    mechanism_count: int
    result_count: int
    executed_count: int
    failed_count: int
    matched_mechanism_count: int
    checked_unit_count: int
    matched_unit_count: int
    aggregate_matched_rate: float | None
    false_positive_estimate: bool
    false_positive_claim_status: str
    false_positive_claim_blockers: tuple[str, ...]
    aggregate_false_positive_rate: float | None
    trace_source_kind_counts: dict[str, int]
    mechanisms: tuple[DetectorReplayCorpusMechanismSummary, ...]
    traces: tuple[DetectorReplayTraceSummary, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at_unix_s": self.generated_at_unix_s,
            "ok": self.ok,
            "command": list(self.command),
            "trace_count": self.trace_count,
            "ok_trace_count": self.ok_trace_count,
            "failed_trace_count": self.failed_trace_count,
            "mechanism_count": self.mechanism_count,
            "result_count": self.result_count,
            "executed_count": self.executed_count,
            "failed_count": self.failed_count,
            "matched_mechanism_count": self.matched_mechanism_count,
            "checked_unit_count": self.checked_unit_count,
            "matched_unit_count": self.matched_unit_count,
            "aggregate_matched_rate": self.aggregate_matched_rate,
            "false_positive_estimate": self.false_positive_estimate,
            "false_positive_claim_status": self.false_positive_claim_status,
            "false_positive_claim_blockers": list(self.false_positive_claim_blockers),
            "aggregate_false_positive_rate": self.aggregate_false_positive_rate,
            "trace_source_kind_counts": dict(sorted(self.trace_source_kind_counts.items())),
            "mechanisms": [mechanism.to_json() for mechanism in self.mechanisms],
            "traces": [trace.to_json() for trace in self.traces],
        }


def replay_detectors_on_pcap(
    mechanisms: list[Mechanism],
    pcap_path: Path | str,
    *,
    source_kind: TraceSourceKind | str,
    trace_name: str | None = None,
    origin_url: str | None = None,
    license: str | None = None,
    filtering_assumptions: tuple[str, ...] = (),
    backend: DetectorReplayBackend | str = DetectorReplayBackend.BPF,
    tcpdump_path: str = "tcpdump",
    tshark_path: str = "tshark",
    suricata_path: str = "suricata",
    command: tuple[str, ...] = (),
) -> DetectorReplayReport:
    """Run generated BPF detectors over one pcap and return a provenance report."""

    source = _source_kind(source_kind)
    replay_backend = _replay_backend(backend)
    path = Path(pcap_path)
    trace = DetectorReplayTrace(
        path=str(path),
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        size_bytes=path.stat().st_size,
        packet_count=classic_pcap_record_count(path),
        source_kind=source,
        trace_name=trace_name,
        origin_url=origin_url,
        license=license,
        filtering_assumptions=filtering_assumptions,
    )
    fp_provenance_ready = _false_positive_provenance_ready(trace)
    results = tuple(
        _replay_mechanism(
            mechanism,
            path,
            source_kind=source,
            false_positive_estimate_allowed=fp_provenance_ready,
            backend=replay_backend,
            tcpdump_path=tcpdump_path,
            tshark_path=tshark_path,
            suricata_path=suricata_path,
        )
        for mechanism in mechanisms
    )
    executed_count = sum(1 for result in results if _executed(result))
    failed_count = sum(1 for result in results if not result.ok)
    matched_count = sum(1 for result in results if _matched(result))
    checked_unit_count = sum(_checked_units(result) for result in results)
    matched_unit_count = sum(_matched_units(result) for result in results)
    aggregate_matched_rate = _rate(matched_unit_count, checked_unit_count)
    fp_blockers = _false_positive_claim_blockers(
        trace,
        result_count=len(results),
        executed_count=executed_count,
    )
    fp_estimate = not fp_blockers
    return DetectorReplayReport(
        schema_version=DETECTOR_REPLAY_SCHEMA_VERSION,
        generated_at_unix_s=time(),
        ok=failed_count == 0,
        command=command,
        trace=trace,
        mechanism_count=len(results),
        executed_count=executed_count,
        failed_count=failed_count,
        matched_mechanism_count=matched_count,
        checked_unit_count=checked_unit_count,
        matched_unit_count=matched_unit_count,
        aggregate_matched_rate=aggregate_matched_rate,
        false_positive_estimate=fp_estimate,
        false_positive_claim_status=_false_positive_claim_status(fp_blockers),
        false_positive_claim_blockers=fp_blockers,
        aggregate_false_positive_rate=aggregate_matched_rate if fp_estimate else None,
        mechanisms=results,
    )


def replay_detector_corpus(
    mechanisms: list[Mechanism],
    traces: list[DetectorReplayTraceSpec],
    *,
    backend: DetectorReplayBackend | str = DetectorReplayBackend.BPF,
    tcpdump_path: str = "tcpdump",
    tshark_path: str = "tshark",
    suricata_path: str = "suricata",
    command: tuple[str, ...] = (),
) -> DetectorReplayCorpusReport:
    """Run independent detector replay across a trace corpus and aggregate rates."""

    reports = tuple(
        replay_detectors_on_pcap(
            mechanisms,
            trace.path,
            source_kind=trace.source_kind,
            trace_name=trace.trace_name,
            origin_url=trace.origin_url,
            license=trace.license,
            filtering_assumptions=trace.filtering_assumptions,
            backend=backend,
            tcpdump_path=tcpdump_path,
            tshark_path=tshark_path,
            suricata_path=suricata_path,
            command=command,
        )
        for trace in traces
    )
    summaries = tuple(DetectorReplayTraceSummary.from_report(report) for report in reports)
    ok_trace_count = sum(1 for report in reports if report.ok)
    failed_trace_count = len(reports) - ok_trace_count
    result_count = sum(report.mechanism_count for report in reports)
    executed_count = sum(report.executed_count for report in reports)
    failed_count = sum(report.failed_count for report in reports)
    matched_mechanism_count = sum(report.matched_mechanism_count for report in reports)
    checked_unit_count = sum(report.checked_unit_count for report in reports)
    matched_unit_count = sum(report.matched_unit_count for report in reports)
    aggregate_matched_rate = _rate(matched_unit_count, checked_unit_count)
    fp_blockers = _corpus_false_positive_claim_blockers(reports)
    fp_estimate = not fp_blockers
    mechanism_summaries = _corpus_mechanism_summaries(mechanisms, reports)
    return DetectorReplayCorpusReport(
        schema_version=DETECTOR_REPLAY_CORPUS_SCHEMA_VERSION,
        generated_at_unix_s=time(),
        ok=failed_trace_count == 0,
        command=command,
        trace_count=len(reports),
        ok_trace_count=ok_trace_count,
        failed_trace_count=failed_trace_count,
        mechanism_count=len(mechanisms),
        result_count=result_count,
        executed_count=executed_count,
        failed_count=failed_count,
        matched_mechanism_count=matched_mechanism_count,
        checked_unit_count=checked_unit_count,
        matched_unit_count=matched_unit_count,
        aggregate_matched_rate=aggregate_matched_rate,
        false_positive_estimate=fp_estimate,
        false_positive_claim_status=_false_positive_claim_status(fp_blockers),
        false_positive_claim_blockers=fp_blockers,
        aggregate_false_positive_rate=aggregate_matched_rate if fp_estimate else None,
        trace_source_kind_counts=_trace_source_kind_counts(reports),
        mechanisms=mechanism_summaries,
        traces=summaries,
    )


def load_trace_manifest(path: Path | str) -> list[DetectorReplayTraceSpec]:
    """Load a detector replay trace manifest with paths relative to the manifest."""

    manifest_path = Path(path)
    document = json.loads(manifest_path.read_text())
    if not isinstance(document, dict):
        raise ValueError("detector trace manifest must be a JSON object")
    version = document.get("schema_version")
    if version != DETECTOR_TRACE_MANIFEST_SCHEMA_VERSION:
        raise ValueError(
            "detector trace manifest schema_version must be "
            f"{DETECTOR_TRACE_MANIFEST_SCHEMA_VERSION!r}"
        )
    traces = document.get("traces")
    if not isinstance(traces, list) or not traces:
        raise ValueError("detector trace manifest requires a non-empty traces array")
    specs: list[DetectorReplayTraceSpec] = []
    for index, trace in enumerate(traces):
        if not isinstance(trace, dict):
            raise ValueError(f"detector trace manifest traces[{index}] must be an object")
        trace_document = cast("dict[str, Any]", trace)
        specs.append(
            DetectorReplayTraceSpec.from_json(trace_document, base_dir=manifest_path.parent)
        )
    return specs


def default_replay_mechanisms(
    mechanisms: list[Mechanism],
    *,
    backend: DetectorReplayBackend | str = DetectorReplayBackend.BPF,
) -> list[Mechanism]:
    """Return catalog mechanisms supported by a detector replay backend."""

    replay_backend = _replay_backend(backend)
    if replay_backend is DetectorReplayBackend.BPF:
        return [mechanism for mechanism in emittable(mechanisms) if _bpf_supported(mechanism)]
    if replay_backend is DetectorReplayBackend.TSHARK_DISPLAY_FILTER:
        return [mechanism for mechanism in mechanisms if _tshark_supported(mechanism)]
    return [mechanism for mechanism in mechanisms if _suricata_supported(mechanism)]


def _replay_mechanism(
    mechanism: Mechanism,
    pcap_path: Path,
    *,
    source_kind: TraceSourceKind,
    false_positive_estimate_allowed: bool,
    backend: DetectorReplayBackend,
    tcpdump_path: str,
    tshark_path: str,
    suricata_path: str,
) -> DetectorReplayMechanismResult:
    if backend is DetectorReplayBackend.BPF:
        supported = _bpf_supported(mechanism)
        support_error = f"{mechanism.id}: no single-byte stateless BPF detector is available"
        record = (
            None
            if not supported
            else _tcpdump_replay_record(
                mechanism,
                pcap_path,
                source_kind=source_kind,
                false_positive_estimate=false_positive_estimate_allowed,
                tcpdump_path=tcpdump_path,
                tshark_path=tshark_path,
                suricata_path=suricata_path,
            )
        )
    elif backend is DetectorReplayBackend.TSHARK_DISPLAY_FILTER:
        supported = _tshark_supported(mechanism)
        support_error = f"{mechanism.id}: no tshark display-filter detector is available"
        record = (
            None
            if not supported
            else _tshark_replay_record(
                mechanism,
                pcap_path,
                source_kind=source_kind,
                false_positive_estimate=false_positive_estimate_allowed,
                tcpdump_path=tcpdump_path,
                tshark_path=tshark_path,
                suricata_path=suricata_path,
            )
        )
    else:
        supported = _suricata_supported(mechanism)
        support_error = f"{mechanism.id}: no Suricata rule detector is available"
        record = (
            None
            if not supported
            else _suricata_replay_record(
                mechanism,
                pcap_path,
                source_kind=source_kind,
                false_positive_estimate=false_positive_estimate_allowed,
                tcpdump_path=tcpdump_path,
                tshark_path=tshark_path,
                suricata_path=suricata_path,
            )
        )

    if not supported:
        return DetectorReplayMechanismResult(
            mechanism_id=mechanism.id,
            mechanism_name=mechanism.name,
            ok=False,
            error=support_error,
            matched_rate=None,
            false_positive_estimate=False,
            false_positive_rate=None,
            detector_provenance=None,
        )
    assert record is not None
    matched_rate = _rate(record.matched_units, record.checked_units)
    fp_estimate = false_positive_estimate_allowed and record.executed
    return DetectorReplayMechanismResult(
        mechanism_id=mechanism.id,
        mechanism_name=mechanism.name,
        ok=record.executed,
        error=None if record.executed else record.result,
        matched_rate=matched_rate,
        false_positive_estimate=fp_estimate,
        false_positive_rate=matched_rate if fp_estimate else None,
        detector_provenance=record,
    )


def _tcpdump_replay_record(
    mechanism: Mechanism,
    pcap_path: Path,
    *,
    source_kind: TraceSourceKind,
    false_positive_estimate: bool,
    tcpdump_path: str,
    tshark_path: str,
    suricata_path: str,
) -> DetectorProvenanceRecord:
    del tshark_path, suricata_path
    record = tcpdump_bpf_provenance_record(
        mechanism,
        pcap_path,
        tcpdump_path=tcpdump_path,
        benign_basis=source_kind.value,
        false_positive_estimate=false_positive_estimate,
        implementation="tcpdump/libpcap BPF execution over detector replay pcap",
        notes=(
            "independent tcpdump/libpcap execution over a detector replay pcap; "
            f"trace source kind is {source_kind.value}"
        ),
        name=f"{mechanism.id}-trace-replay-tcpdump-bpf",
        scope_filter=_BPF_SCOPE_FILTERS[mechanism.id],
    )
    return record


def _tshark_replay_record(
    mechanism: Mechanism,
    pcap_path: Path,
    *,
    source_kind: TraceSourceKind,
    false_positive_estimate: bool,
    tcpdump_path: str,
    tshark_path: str,
    suricata_path: str,
) -> DetectorProvenanceRecord:
    del tcpdump_path, suricata_path
    rule = _TSHARK_DISPLAY_FILTERS[mechanism.id]
    scope_rule = _TSHARK_SCOPE_FILTERS[mechanism.id]
    command = (tshark_path, "-r", str(pcap_path), "-Y", rule, "-T", "fields", "-e", "frame.number")
    checked_units = 0
    if shutil.which(tshark_path) is None:
        return DetectorProvenanceRecord(
            name=f"{mechanism.id}-trace-replay-tshark-display-filter",
            detector_family="display_filter",
            implementation="tshark/Wireshark display-filter execution over detector replay pcap",
            implementation_kind=DetectorImplementationKind.INDEPENDENT_TOOL_OUTPUT,
            executed=False,
            result="tool_missing",
            detectability=mechanism.detectability,
            predicate=mechanism.detect_predicate,
            disposition=disposition(mechanism),
            rule_format="tshark-display-filter",
            rule=rule,
            checked_units=checked_units,
            matched_units=0,
            failed_units=checked_units,
            detected=None,
            benign_basis=source_kind.value,
            false_positive_estimate=False,
            command=command,
            returncode=None,
            stdout_sha256=None,
            stderr_sha256=None,
            stderr_excerpt=f"{tshark_path}: not found",
            notes=(
                "tshark was unavailable; Wireshark display-filter detector replay was "
                f"not executed; trace source kind is {source_kind.value}"
            ),
        )
    scope_completed = subprocess.run(
        (
            tshark_path,
            "-r",
            str(pcap_path),
            "-Y",
            scope_rule,
            "-T",
            "fields",
            "-e",
            "frame.number",
        ),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    checked_units = _line_count(scope_completed.stdout)
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    stdout = completed.stdout
    stderr = completed.stderr
    matched_units = _line_count(stdout)
    command_failed = completed.returncode != 0 or scope_completed.returncode != 0
    effective_returncode = completed.returncode or scope_completed.returncode
    return DetectorProvenanceRecord(
        name=f"{mechanism.id}-trace-replay-tshark-display-filter",
        detector_family="display_filter",
        implementation="tshark/Wireshark display-filter execution over detector replay pcap",
        implementation_kind=DetectorImplementationKind.INDEPENDENT_TOOL_OUTPUT,
        executed=not command_failed,
        result=_tool_result(effective_returncode, matched_units),
        detectability=mechanism.detectability,
        predicate=mechanism.detect_predicate,
        disposition=disposition(mechanism),
        rule_format="tshark-display-filter",
        rule=rule,
        checked_units=checked_units,
        matched_units=matched_units,
        failed_units=checked_units if command_failed else 0,
        detected=matched_units > 0 if not command_failed else None,
        benign_basis=source_kind.value,
        false_positive_estimate=false_positive_estimate and not command_failed,
        command=command,
        returncode=effective_returncode,
        stdout_sha256=hashlib.sha256(stdout.encode()).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr.encode()).hexdigest(),
        stderr_excerpt=_excerpt(stderr),
        notes=(
            "independent tshark/Wireshark display-filter execution over a detector "
            f"replay pcap; trace source kind is {source_kind.value}; eligible display "
            f"filter {scope_rule!r} checked {checked_units} packets"
        ),
    )


def _suricata_replay_record(
    mechanism: Mechanism,
    pcap_path: Path,
    *,
    source_kind: TraceSourceKind,
    false_positive_estimate: bool,
    tcpdump_path: str,
    tshark_path: str,
    suricata_path: str,
) -> DetectorProvenanceRecord:
    del tshark_path
    sid, rule = _SURICATA_RULES[mechanism.id]
    checked_units = 0
    if shutil.which(suricata_path) is None or shutil.which(tcpdump_path) is None:
        missing_tool = suricata_path if shutil.which(suricata_path) is None else tcpdump_path
        return DetectorProvenanceRecord(
            name=f"{mechanism.id}-trace-replay-suricata-rule",
            detector_family="ids_rule",
            implementation="Suricata rule execution over detector replay pcap",
            implementation_kind=DetectorImplementationKind.INDEPENDENT_TOOL_OUTPUT,
            executed=False,
            result="tool_missing",
            detectability=mechanism.detectability,
            predicate=mechanism.detect_predicate,
            disposition=disposition(mechanism),
            rule_format="suricata",
            rule=rule,
            checked_units=checked_units,
            matched_units=0,
            failed_units=checked_units,
            detected=None,
            benign_basis=source_kind.value,
            false_positive_estimate=False,
            command=(
                suricata_path,
                "-r",
                str(pcap_path),
                "-S",
                "<generated-rule>",
                "-l",
                "<log-dir>",
                "-k",
                "none",
            ),
            returncode=None,
            stdout_sha256=None,
            stderr_sha256=None,
            stderr_excerpt=f"{missing_tool}: not found",
            notes=(
                "Suricata was unavailable; IDS rule detector replay was not executed; "
                f"trace source kind is {source_kind.value}"
            ),
        )
    scope_rule = _SURICATA_SCOPE_FILTERS[mechanism.id]
    scope_completed = subprocess.run(
        (tcpdump_path, "-tt", "-n", "-r", str(pcap_path), scope_rule),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    checked_units = _line_count(scope_completed.stdout)
    with tempfile.TemporaryDirectory(prefix="celatim-suricata-replay-") as tmp:
        tmpdir = Path(tmp)
        rule_path = tmpdir / "celatim.rules"
        log_dir = tmpdir / "logs"
        log_dir.mkdir()
        rule_path.write_text(rule + "\n")
        command = (
            suricata_path,
            "-r",
            str(pcap_path),
            "-S",
            str(rule_path),
            "-l",
            str(log_dir),
            "-k",
            "none",
        )
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        stdout = completed.stdout
        stderr = completed.stderr
        matched_units = _suricata_alert_count(log_dir / "eve.json", sid)
    command_failed = completed.returncode != 0 or scope_completed.returncode != 0
    effective_returncode = completed.returncode or scope_completed.returncode
    return DetectorProvenanceRecord(
        name=f"{mechanism.id}-trace-replay-suricata-rule",
        detector_family="ids_rule",
        implementation="Suricata rule execution over detector replay pcap",
        implementation_kind=DetectorImplementationKind.INDEPENDENT_TOOL_OUTPUT,
        executed=not command_failed,
        result=_tool_result(effective_returncode, matched_units),
        detectability=mechanism.detectability,
        predicate=mechanism.detect_predicate,
        disposition=disposition(mechanism),
        rule_format="suricata",
        rule=rule,
        checked_units=checked_units,
        matched_units=matched_units,
        failed_units=checked_units if command_failed else 0,
        detected=matched_units > 0 if not command_failed else None,
        benign_basis=source_kind.value,
        false_positive_estimate=false_positive_estimate and not command_failed,
        command=command,
        returncode=effective_returncode,
        stdout_sha256=hashlib.sha256(stdout.encode()).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr.encode()).hexdigest(),
        stderr_excerpt=_excerpt(stderr),
        notes=(
            "independent Suricata IDS rule execution over a detector replay pcap; "
            f"trace source kind is {source_kind.value}; eligible BPF filter "
            f"{scope_rule!r} checked {checked_units} packets"
        ),
    )


def _bpf_supported(mechanism: Mechanism) -> bool:
    if mechanism.id not in _BPF_SCOPE_FILTERS:
        return False
    if mechanism.detectability is not Detectability.STATELESS_FILTER:
        return False
    try:
        bpf_filter(mechanism)
    except ValueError:
        return False
    return True


def _tshark_supported(mechanism: Mechanism) -> bool:
    return mechanism.id in _TSHARK_DISPLAY_FILTERS


def _suricata_supported(mechanism: Mechanism) -> bool:
    return mechanism.id in _SURICATA_RULES


def _false_positive_provenance_ready(trace: DetectorReplayTrace) -> bool:
    return not _false_positive_claim_blockers(trace)


def _false_positive_claim_status(blockers: tuple[str, ...]) -> str:
    return FALSE_POSITIVE_CLAIM_NOT_READY if blockers else FALSE_POSITIVE_CLAIM_READY


def _false_positive_claim_blockers(
    trace: DetectorReplayTrace,
    *,
    result_count: int | None = None,
    executed_count: int | None = None,
) -> tuple[str, ...]:
    blockers: list[str] = []
    if trace.source_kind not in FALSE_POSITIVE_SOURCE_KINDS:
        blockers.append("not_false_positive_source")
    else:
        if not trace.trace_name:
            blockers.append("missing_trace_name")
        if not trace.license:
            blockers.append("missing_trace_license")
        if not trace.filtering_assumptions:
            blockers.append("missing_filtering_assumptions")
        if trace.source_kind is TraceSourceKind.PUBLIC_BENIGN_TRACE and not trace.origin_url:
            blockers.append("missing_public_trace_origin")
    if result_count is not None:
        if result_count == 0:
            blockers.append("empty_mechanism_set")
        elif executed_count != result_count:
            blockers.append("detector_execution_incomplete")
    return tuple(blockers)


def _corpus_false_positive_claim_blockers(
    reports: tuple[DetectorReplayReport, ...],
) -> tuple[str, ...]:
    if not reports:
        return ("empty_trace_corpus",)
    blockers = {blocker for report in reports for blocker in report.false_positive_claim_blockers}
    return tuple(sorted(blockers))


def _corpus_mechanism_summaries(
    mechanisms: list[Mechanism],
    reports: tuple[DetectorReplayReport, ...],
) -> tuple[DetectorReplayCorpusMechanismSummary, ...]:
    summaries: list[DetectorReplayCorpusMechanismSummary] = []
    for mechanism in mechanisms:
        results = tuple(
            result
            for report in reports
            for result in report.mechanisms
            if result.mechanism_id == mechanism.id
        )
        executed_count = sum(1 for result in results if _executed(result))
        checked_count = sum(_checked_units(result) for result in results)
        matched_count = sum(_matched_units(result) for result in results)
        fp_estimate = bool(results) and all(result.false_positive_estimate for result in results)
        rate = _rate(matched_count, checked_count) if fp_estimate else None
        summaries.append(
            DetectorReplayCorpusMechanismSummary(
                mechanism_id=mechanism.id,
                mechanism_name=mechanism.name,
                trace_count=len(reports),
                executed_trace_count=executed_count,
                failed_trace_count=len(reports) - executed_count,
                checked_unit_count=checked_count,
                matched_unit_count=matched_count,
                false_positive_estimate=fp_estimate,
                false_positive_rate=rate,
                false_positive_wilson95=(
                    _wilson95(matched_count, checked_count)
                    if rate is not None and checked_count
                    else None
                ),
                trace_false_positive_rates=tuple(result.false_positive_rate for result in results),
            )
        )
    return tuple(summaries)


def _wilson95(successes: int, trials: int) -> tuple[float, float]:
    if trials <= 0:
        raise ValueError("Wilson interval requires at least one trial")
    z = 1.959963984540054
    proportion = successes / trials
    denominator = 1 + z * z / trials
    center = (proportion + z * z / (2 * trials)) / denominator
    radius = (
        z
        * sqrt(proportion * (1 - proportion) / trials + z * z / (4 * trials * trials))
        / denominator
    )
    lower = 0.0 if successes == 0 else max(0.0, center - radius)
    upper = 1.0 if successes == trials else min(1.0, center + radius)
    return lower, upper


def _suricata_alert_count(eve_path: Path, sid: int) -> int:
    if not eve_path.is_file():
        return 0
    count = 0
    for line in eve_path.read_text().splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict) or event.get("event_type") != "alert":
            continue
        alert = event.get("alert")
        if isinstance(alert, dict) and alert.get("signature_id") == sid:
            count += 1
    return count


def _source_kind(value: TraceSourceKind | str) -> TraceSourceKind:
    if isinstance(value, TraceSourceKind):
        return value
    return TraceSourceKind(value)


def _replay_backend(value: DetectorReplayBackend | str) -> DetectorReplayBackend:
    if isinstance(value, DetectorReplayBackend):
        return value
    return DetectorReplayBackend(value)


def _line_count(stdout: str) -> int:
    return sum(1 for line in stdout.splitlines() if line.strip())


def _tool_result(returncode: int, matched_units: int) -> str:
    if returncode != 0:
        return "tool_failed"
    if matched_units:
        return "matched"
    return "not_matched"


def _excerpt(value: str, limit: int = 240) -> str | None:
    text = " ".join(value.split())
    if not text:
        return None
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _optional_string(document: dict[str, Any], key: str) -> str | None:
    value = document.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string or null")
    return value


def _string_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        raise ValueError("filtering_assumptions must be an array of strings")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError("filtering_assumptions must be an array of strings")
        result.append(item)
    return tuple(result)


def _rate(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return numerator / denominator


def _executed(result: DetectorReplayMechanismResult) -> bool:
    record = result.detector_provenance
    return record is not None and record.executed


def _matched(result: DetectorReplayMechanismResult) -> bool:
    record = result.detector_provenance
    return record is not None and record.executed and record.matched_units > 0


def _checked_units(result: DetectorReplayMechanismResult) -> int:
    record = result.detector_provenance
    if record is None or not record.executed:
        return 0
    return record.checked_units


def _matched_units(result: DetectorReplayMechanismResult) -> int:
    record = result.detector_provenance
    if record is None or not record.executed:
        return 0
    return record.matched_units


def _trace_source_kind_counts(reports: tuple[DetectorReplayReport, ...]) -> dict[str, int]:
    counts = {kind.value: 0 for kind in TraceSourceKind}
    for report in reports:
        counts[report.trace.source_kind.value] += 1
    return {kind: count for kind, count in counts.items() if count}


__all__ = [
    "DETECTOR_REPLAY_CORPUS_SCHEMA_VERSION",
    "DETECTOR_REPLAY_SCHEMA_VERSION",
    "DETECTOR_TRACE_MANIFEST_SCHEMA_VERSION",
    "FALSE_POSITIVE_SOURCE_KINDS",
    "DetectorReplayBackend",
    "DetectorReplayCorpusReport",
    "DetectorReplayMechanismResult",
    "DetectorReplayReport",
    "DetectorReplayTrace",
    "DetectorReplayTraceSpec",
    "DetectorReplayTraceSummary",
    "TraceSourceKind",
    "default_replay_mechanisms",
    "load_trace_manifest",
    "replay_detector_corpus",
    "replay_detectors_on_pcap",
]
