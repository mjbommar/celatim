"""Public-safe Alice/Bob evidence indexes and paper-claim ledgers."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from time import time
from typing import Any

from celatim.evidence import classify_evidence
from celatim.model import Mechanism

from .subliminal_controls import SUBLIMINAL_CONTROL_REPORT_SCHEMA_VERSION

CROSSHOST_PUBLIC_INDEX_SCHEMA_VERSION = "celatim.alice_bob_public_index.v2"
CLAIM_LEDGER_SCHEMA_VERSION = "celatim.claim_ledger.v2"

ALL_USABLE_EXACT_RECOVERY_CLAIM = "all_usable_binary_exact_recovery"
REAL_PDU_CAPABLE_CLAIM = "adapter_real_pdu_capable"
REAL_DAEMON_OR_CRYPTO_CAPABLE_CLAIM = "adapter_real_daemon_or_crypto_capable"
TIMING_SCHEME_CAPABLE_CLAIM = "timing_scheme_capable"
PACKET_PATH_EXECUTED_CLAIM = "crosshost_afpacket_exact_recovery"
ENVELOPE_EXECUTED_CLAIM = "crosshost_envelope_artifact_roundtrip"
MESSAGE_CARRIER_EXECUTED_CLAIM = "crosshost_message_control_exchange"
SUBLIMINAL_CONTROLS_CLAIM = "subliminal_crypto_distributional_controls"

SAFE_RUN_FILES = (
    "summary.json",
    "packet-results.json",
    "envelope-results.json",
    "message-results.json",
    "negative-results.json",
    "metrics-results.json",
    "metrics-summary.json",
    "payload.json",
    "run.log",
)


def build_crosshost_public_index(
    run_dirs: Sequence[Path | str],
    mechanisms: Iterable[Mechanism],
    *,
    generated_at_unix_s: float | None = None,
) -> dict[str, Any]:
    """Summarize Alice/Bob run directories without copying payload or carrier bodies."""

    if not run_dirs:
        raise ValueError("at least one Alice/Bob run directory is required")
    mechanism_map = {mechanism.id: mechanism for mechanism in mechanisms}
    usable_ids = sorted(
        mechanism.id for mechanism in mechanism_map.values() if mechanism.is_usable_channel
    )
    runs = [_index_run(Path(run_dir), mechanism_map) for run_dir in run_dirs]
    exact_sets = [set(run["required_suite_pass_mechanisms"]) for run in runs]
    exact_recovery_mechanisms = sorted(set.intersection(*exact_sets)) if exact_sets else []
    exact_capability_buckets = _bucket_counts(exact_recovery_mechanisms, mechanism_map)
    suite_counts = Counter[str]()
    mechanism_pass_counts_by_suite = _mechanism_pass_counts_by_suite(runs)
    timing_claims = Counter[str]()
    for run in runs:
        for suite, count in run["pass_counts_by_suite"].items():
            suite_counts[suite] += int(count)
        for status, count in run["timing_claim_status_counts"].items():
            timing_claims[status] += int(count)
    return {
        "schema_version": CROSSHOST_PUBLIC_INDEX_SCHEMA_VERSION,
        "generated_at_unix_s": time() if generated_at_unix_s is None else generated_at_unix_s,
        "run_count": len(runs),
        "all_runs_required_pass": all(run["summary"].get("required_pass") is True for run in runs),
        "usable_mechanism_count": len(usable_ids),
        "exact_recovery_count": len(exact_recovery_mechanisms),
        "exact_recovery_mechanisms": exact_recovery_mechanisms,
        "exact_recovery_capability_bucket_counts": dict(sorted(exact_capability_buckets.items())),
        "execution_path_counts": {
            "afpacket_generated_frames_over_vxlan": mechanism_pass_counts_by_suite["packet"],
            "json_carrier_artifact_handoff_over_ssh": mechanism_pass_counts_by_suite["envelope"],
            "json_hex_pdu_control_exchange_over_tcp": mechanism_pass_counts_by_suite[
                "message_carrier"
            ],
        },
        "execution_path_count_semantics": (
            "The AF_PACKET and JSON artifact paths partition required exact recovery; "
            "the JSON-wrapped message-control path is additional evidence for an overlapping "
            "subset. Capability buckets describe adapters, not the transport used in a run."
        ),
        "pass_counts_by_suite": dict(sorted(suite_counts.items())),
        "mechanism_pass_counts_by_suite": mechanism_pass_counts_by_suite,
        "timing_claim_status_counts": dict(sorted(timing_claims.items())),
        "runs": runs,
    }


def build_claim_ledger(
    mechanisms: Iterable[Mechanism],
    *,
    crosshost_indexes: Sequence[Mapping[str, Any]] = (),
    subliminal_control_reports: Sequence[Mapping[str, Any]] = (),
    generated_at_unix_s: float | None = None,
) -> dict[str, Any]:
    """Build a paper-facing claim ledger from capabilities and run-backed indexes."""

    mechs = tuple(mechanisms)
    usable = tuple(mechanism for mechanism in mechs if mechanism.is_usable_channel)
    capability_buckets = Counter(classify_evidence(mechanism).bucket.value for mechanism in usable)
    exact_recovery_ids = _intersection_from_indexes(crosshost_indexes, "exact_recovery_mechanisms")
    exact_capability_bucket_counts = _bucket_counts(
        exact_recovery_ids, {mechanism.id: mechanism for mechanism in mechs}
    )
    suite_mechanism_ids = {
        suite: _suite_intersection_from_indexes(crosshost_indexes, suite)
        for suite in ("packet", "envelope", "message_carrier")
    }
    timing_claims = Counter[str]()
    evidence_refs: list[dict[str, Any]] = []
    run_count = 0
    all_required_pass = True
    for index in crosshost_indexes:
        run_count += int(index.get("run_count", 0))
        all_required_pass = all_required_pass and bool(index.get("all_runs_required_pass", False))
        evidence_refs.append(_index_ref(index))
        timing_claims.update(_count_map(index.get("timing_claim_status_counts")))
    subliminal_refs = [_subliminal_ref(report) for report in subliminal_control_reports]
    subliminal_passed_count = sum(
        int(report.get("passed_count", 0)) for report in subliminal_control_reports
    )
    subliminal_status = (
        "distributional_smoke_controls_passed"
        if subliminal_control_reports
        and all(report.get("ok") is True for report in subliminal_control_reports)
        else "underpowered_or_anomalous_controls"
    )

    claims = [
        _claim(
            ALL_USABLE_EXACT_RECOVERY_CLAIM,
            len(exact_recovery_ids),
            "mixed_execution_path_exact_recovery",
            evidence_refs,
            "Every usable mechanism recovered the exact binary payload through either the "
            "AF_PACKET path or the JSON artifact handoff in each indexed Alice/Bob run; use "
            "the path-specific claims for transport conclusions.",
            exact_recovery_ids,
        ),
        _claim(
            REAL_PDU_CAPABLE_CLAIM,
            capability_buckets["real_pdu_packet_path"],
            "capability_classification_not_run_count",
            [],
            "Mechanisms classified as having a real-PDU or packet-template adapter.",
            _ids_for_bucket(usable, "real_pdu_packet_path"),
        ),
        _claim(
            REAL_DAEMON_OR_CRYPTO_CAPABLE_CLAIM,
            capability_buckets["real_daemon_or_crypto_path"],
            "capability_classification_not_run_count",
            [],
            "Mechanisms classified as having a real daemon or cryptographic transcript path.",
            _ids_for_bucket(usable, "real_daemon_or_crypto_path"),
        ),
        _claim(
            TIMING_SCHEME_CAPABLE_CLAIM,
            capability_buckets["timing_scheme"],
            "capability_classification_not_run_count",
            [],
            "Mechanisms classified as timing or count schemes.",
            _ids_for_bucket(usable, "timing_scheme"),
        ),
        _claim(
            PACKET_PATH_EXECUTED_CLAIM,
            len(suite_mechanism_ids["packet"]),
            "afpacket_generated_frame_crosshost_exact_recovery",
            evidence_refs,
            "Parser-visible carrier PDUs crossed two hosts inside generated Ethernet/IPv4 "
            "TCP or UDP frames over VXLAN. This is not native-daemon execution, and the "
            "sender-process timing is not native-protocol goodput.",
            suite_mechanism_ids["packet"],
        ),
        _claim(
            ENVELOPE_EXECUTED_CLAIM,
            len(suite_mechanism_ids["envelope"]),
            "json_artifact_handoff_over_ssh_exact_recovery",
            evidence_refs,
            "Alice serialized carrier units in a JSON envelope and the harness handed that "
            "envelope to Bob over SSH. This is a cross-host codec/serialization check, not "
            "transit through the nominal protocol.",
            suite_mechanism_ids["envelope"],
        ),
        _claim(
            MESSAGE_CARRIER_EXECUTED_CLAIM,
            len(suite_mechanism_ids["message_carrier"]),
            "json_hex_pdu_control_exchange_over_tcp_exact_recovery",
            evidence_refs,
            "Protocol-library PDU bytes were hex-encoded inside length-prefixed JSON over a "
            "TCP control connection and independently parsed on Bob. This overlapping subset "
            "does not establish native-protocol delivery or goodput.",
            suite_mechanism_ids["message_carrier"],
        ),
        _claim(
            SUBLIMINAL_CONTROLS_CLAIM,
            subliminal_passed_count,
            subliminal_status,
            subliminal_refs,
            "Class-G crypto transcript controls with aggregate signature bit-balance smoke tests.",
        ),
    ]
    return {
        "schema_version": CLAIM_LEDGER_SCHEMA_VERSION,
        "generated_at_unix_s": time() if generated_at_unix_s is None else generated_at_unix_s,
        "mechanism_count": len(mechs),
        "usable_mechanism_count": len(usable),
        "crosshost_run_count": run_count,
        "crosshost_all_required_pass": all_required_pass if crosshost_indexes else False,
        "subliminal_control_report_count": len(subliminal_control_reports),
        "capability_evidence_bucket_counts": dict(sorted(capability_buckets.items())),
        "exact_recovery_capability_bucket_counts": dict(
            sorted(exact_capability_bucket_counts.items())
        ),
        "execution_path_counts": {
            "afpacket_generated_frames_over_vxlan": len(suite_mechanism_ids["packet"]),
            "json_carrier_artifact_handoff_over_ssh": len(suite_mechanism_ids["envelope"]),
            "json_hex_pdu_control_exchange_over_tcp": len(suite_mechanism_ids["message_carrier"]),
        },
        "timing_claim_status_counts": dict(sorted(timing_claims.items())),
        "claims": claims,
    }


def claim_count(ledger: Mapping[str, Any] | None, claim_id: str) -> int:
    if ledger is None:
        return 0
    for claim in ledger.get("claims", ()):
        if isinstance(claim, Mapping) and claim.get("id") == claim_id:
            value = claim.get("count", 0)
            return value if isinstance(value, int) and not isinstance(value, bool) else 0
    return 0


def load_claim_ledger(path: Path | str | None) -> dict[str, Any] | None:
    if path is None:
        return None
    document = json.loads(Path(path).read_text())
    if document.get("schema_version") != CLAIM_LEDGER_SCHEMA_VERSION:
        raise ValueError(f"{path}: not a claim ledger")
    return document


def load_crosshost_public_index(path: Path | str) -> dict[str, Any]:
    document = json.loads(Path(path).read_text())
    if document.get("schema_version") != CROSSHOST_PUBLIC_INDEX_SCHEMA_VERSION:
        raise ValueError(f"{path}: not an Alice/Bob public index")
    return document


def load_subliminal_control_report(path: Path | str) -> dict[str, Any]:
    document = json.loads(Path(path).read_text())
    if document.get("schema_version") != SUBLIMINAL_CONTROL_REPORT_SCHEMA_VERSION:
        raise ValueError(f"{path}: not a subliminal control report")
    return document


def write_json(path: Path | str, document: Mapping[str, Any]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


def _index_run(run_dir: Path, mechanism_map: Mapping[str, Mechanism]) -> dict[str, Any]:
    summary = _load_json(run_dir / "summary.json")
    metrics_summary = _load_json(run_dir / "metrics-summary.json")
    metrics_doc = _load_json(run_dir / "metrics-results.json")
    packet_results = _load_json(run_dir / "packet-results.json")
    envelope_results = _load_json(run_dir / "envelope-results.json")
    message_results = _load_json(run_dir / "message-results.json")
    negative_results = _load_json(run_dir / "negative-results.json")
    pass_mechanisms_by_suite = {
        "packet": _pass_mechanisms(packet_results),
        "envelope": _pass_mechanisms(envelope_results),
        "message_carrier": _pass_mechanisms(message_results),
    }
    required_pass_ids = pass_mechanisms_by_suite["packet"] | pass_mechanisms_by_suite["envelope"]
    metric_records = [
        _public_metric_record(record)
        for record in metrics_doc.get("records", ())
        if isinstance(record, Mapping)
    ]
    timing_claims = Counter(
        str(record.get("timing", {}).get("claim_status", "unknown"))
        for record in metric_records
        if isinstance(record.get("timing"), Mapping)
    )
    run_id = run_dir.name
    return {
        "run_id": run_id,
        "path": str(run_dir),
        "alice": summary.get("alice"),
        "bob": summary.get("bob"),
        "summary": summary,
        "metrics_summary": metrics_summary,
        "file_artifacts": [
            _file_ref(run_dir / name) for name in SAFE_RUN_FILES if (run_dir / name).is_file()
        ],
        "private_artifacts_excluded": ["payload.bin"],
        "pass_counts_by_suite": {
            "packet": _count_pass(packet_results),
            "envelope": _count_pass(envelope_results),
            "message_carrier": _count_pass(message_results),
            "negative": _count_pass(negative_results),
        },
        "pass_mechanisms_by_suite": {
            suite: sorted(mechanism_ids)
            for suite, mechanism_ids in pass_mechanisms_by_suite.items()
        },
        "required_suite_pass_mechanisms": sorted(required_pass_ids),
        "required_suite_evidence_bucket_counts": dict(
            sorted(_bucket_counts(required_pass_ids, mechanism_map).items())
        ),
        "timing_claim_status_counts": dict(sorted(timing_claims.items())),
        "metrics_records": metric_records,
    }


def _public_metric_record(record: Mapping[str, Any]) -> dict[str, Any]:
    timing = record.get("timing")
    timing_map = timing if isinstance(timing, Mapping) else {}
    return {
        "mechanism": record.get("mechanism"),
        "suite": record.get("suite"),
        "result": record.get("result"),
        "payload_bytes": record.get("payload_bytes"),
        "recovered_bytes": record.get("recovered_bytes"),
        "carrier_units": record.get("carrier_units"),
        "raw_capacity_bits_per_unit": record.get("raw_capacity_bits_per_unit"),
        "carrier_bit_efficiency": record.get("carrier_bit_efficiency"),
        "method_wire_bytes": record.get("method_wire_bytes"),
        "method_wire_basis": record.get("method_wire_basis"),
        "method_wire_overhead": record.get("method_wire_overhead"),
        "payload_to_method_wire_ratio": record.get("payload_to_method_wire_ratio"),
        "vxlan_underlay_bytes_no_fcs": record.get("vxlan_underlay_bytes_no_fcs"),
        "payload_to_vxlan_underlay_ratio": record.get("payload_to_vxlan_underlay_ratio"),
        "timing": {
            "claim_status": timing_map.get("claim_status"),
            "measured_window_s": timing_map.get("measured_window_s"),
            "measured_window_basis": timing_map.get("measured_window_basis"),
            "observed_unit_rate_hz": timing_map.get("observed_unit_rate_hz"),
            "payload_bytes_per_s": timing_map.get("payload_bytes_per_s"),
            "payload_bits_per_s": timing_map.get("payload_bits_per_s"),
            "scheduled_unit_rate_hz": timing_map.get("scheduled_unit_rate_hz"),
            "scheduled_duration_s": timing_map.get("scheduled_duration_s"),
        },
    }


def _claim(
    claim_id: str,
    count: int,
    claim_status: str,
    evidence: Sequence[Mapping[str, Any]],
    notes: str,
    mechanism_ids: Sequence[str] = (),
) -> dict[str, Any]:
    return {
        "id": claim_id,
        "count": count,
        "claim_status": claim_status,
        "evidence": [dict(ref) for ref in evidence],
        "notes": notes,
        "mechanism_ids": list(mechanism_ids),
    }


def _index_ref(index: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": index.get("schema_version"),
        "run_count": index.get("run_count"),
        "all_runs_required_pass": index.get("all_runs_required_pass"),
        "exact_recovery_count": index.get("exact_recovery_count"),
        "execution_path_counts": index.get("execution_path_counts"),
    }


def _suite_intersection_from_indexes(
    indexes: Sequence[Mapping[str, Any]], suite: str
) -> tuple[str, ...]:
    sets: list[set[str]] = []
    for index in indexes:
        runs = index.get("runs")
        if not isinstance(runs, Sequence) or isinstance(runs, str | bytes):
            continue
        for run in runs:
            if not isinstance(run, Mapping):
                continue
            by_suite = run.get("pass_mechanisms_by_suite")
            if isinstance(by_suite, Mapping):
                sets.append(set(_str_sequence(by_suite.get(suite))))
    if not sets:
        return ()
    return tuple(sorted(set.intersection(*sets)))


def _mechanism_pass_counts_by_suite(runs: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for suite in ("packet", "envelope", "message_carrier"):
        sets: list[set[str]] = []
        for run in runs:
            by_suite = run.get("pass_mechanisms_by_suite")
            if not isinstance(by_suite, Mapping):
                continue
            sets.append(set(_str_sequence(by_suite.get(suite))))
        counts[suite] = len(set.intersection(*sets)) if sets else 0
    return dict(sorted(counts.items()))


def _subliminal_ref(report: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": report.get("schema_version"),
        "case_count": report.get("case_count"),
        "passed_count": report.get("passed_count"),
        "ok": report.get("ok"),
        "claim_status": report.get("claim_status"),
        "min_control_signatures": report.get("min_control_signatures"),
    }


def _intersection_from_indexes(indexes: Sequence[Mapping[str, Any]], field: str) -> tuple[str, ...]:
    sets = [set(_str_sequence(index.get(field))) for index in indexes]
    if not sets:
        return ()
    return tuple(sorted(set.intersection(*sets)))


def _ids_for_bucket(mechanisms: Iterable[Mechanism], bucket: str) -> tuple[str, ...]:
    return tuple(
        sorted(
            mechanism.id
            for mechanism in mechanisms
            if classify_evidence(mechanism).bucket.value == bucket
        )
    )


def _bucket_counts(
    mechanism_ids: Iterable[str],
    mechanism_map: Mapping[str, Mechanism],
) -> Counter[str]:
    counts = Counter[str]()
    for mechanism_id in mechanism_ids:
        mechanism = mechanism_map.get(mechanism_id)
        if mechanism is not None:
            counts[classify_evidence(mechanism).bucket.value] += 1
    return counts


def _pass_mechanisms(results: Any) -> set[str]:
    if not isinstance(results, list):
        return set()
    return {
        str(record["mechanism"])
        for record in results
        if isinstance(record, Mapping)
        and record.get("result") == "pass"
        and isinstance(record.get("mechanism"), str)
    }


def _count_pass(results: Any) -> int:
    if not isinstance(results, list):
        return 0
    return sum(
        1 for record in results if isinstance(record, Mapping) and record.get("result") == "pass"
    )


def _count_map(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    out: dict[str, int] = {}
    for key, count in value.items():
        if isinstance(key, str) and isinstance(count, int) and not isinstance(count, bool):
            out[key] = count
    return out


def _str_sequence(value: Any) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        return ()
    return tuple(str(item) for item in value if isinstance(item, str))


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _file_ref(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    return {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
    }


__all__ = [
    "ALL_USABLE_EXACT_RECOVERY_CLAIM",
    "CLAIM_LEDGER_SCHEMA_VERSION",
    "CROSSHOST_PUBLIC_INDEX_SCHEMA_VERSION",
    "ENVELOPE_EXECUTED_CLAIM",
    "MESSAGE_CARRIER_EXECUTED_CLAIM",
    "PACKET_PATH_EXECUTED_CLAIM",
    "REAL_DAEMON_OR_CRYPTO_CAPABLE_CLAIM",
    "REAL_PDU_CAPABLE_CLAIM",
    "SUBLIMINAL_CONTROLS_CLAIM",
    "TIMING_SCHEME_CAPABLE_CLAIM",
    "build_claim_ledger",
    "build_crosshost_public_index",
    "claim_count",
    "load_claim_ledger",
    "load_crosshost_public_index",
    "load_subliminal_control_report",
    "write_json",
]
