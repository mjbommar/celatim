#!/usr/bin/env python3
"""Reproduce the public benign-trace detector population campaign.

Raw CSE-CIC-IDS2018 captures remain outside the repository. The checked-in public
report contains only source/member identifiers, hashes, counts, detector metrics,
and tool provenance.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import math
import platform
import struct
import subprocess
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path
from typing import Any

from celatim.analysis.detector_metrics import (
    LabeledDetectionScore,
    detector_metric_report,
    detector_threshold_metrics,
)
from celatim.catalog import load_mechanisms
from celatim.detect import (
    DetectorReplayBackend,
    DetectorReplayTraceSpec,
    TraceSourceKind,
    default_replay_mechanisms,
    replay_detector_corpus,
    replay_detectors_on_pcap,
)
from celatim.testbed import build_tcp_reserved_bits_frame, default_ipv4_packet_path_config_for

SCHEMA_VERSION = "celatim.detector_population_campaign.v1"
SOURCE_PAGE = "https://www.unb.ca/cic/datasets/ids-2018.html"
SOURCE_ARCHIVE = (
    "https://cse-cic-ids2018.s3.amazonaws.com/"
    "Original%20Network%20Traffic%20and%20Log%20data/Friday-02-03-2018/pcap.zip"
)
SOURCE_LICENSE = (
    "CSE-CIC-IDS2018 redistribution and republication permitted with citation and source link"
)
FILTER_CUTOFF_UNIX_S = 1_520_012_400.0  # 2018-03-02T15:00:00Z / 10:00 EST
FIRST_ATTACK_UNIX_S = 1_520_013_060.0  # published Friday start: 10:11 EST
WINDOW_SIZE = 16
CALIBRATION_TARGET_FPR = 0.01
POSITIVE_PACKET_COUNT = 1_024
_PCAP_PACKET = struct.Struct("<IIII")


@dataclass(frozen=True)
class TraceDefinition:
    member: str
    role: str
    source_sha256: str
    filtered_sha256: str
    filtered_packet_count: int

    @property
    def filename(self) -> str:
        return f"{Path(self.member).name}.pcap"


TRACES = (
    TraceDefinition(
        "pcap/capDESKTOP-AN3U28N-172.31.66.42",
        "calibration",
        "529ebd2176a6afdf858991d26cba915d3f31559c68909940c83d5d9342f267f1",
        "bda1f0cedd89fb47dbc3b92904b6573bf4a92cfaad0945f99c2244f3ea1fc008",
        92_868,
    ),
    TraceDefinition(
        "pcap/capDESKTOP-AN3U28N-172.31.67.32",
        "calibration",
        "b8c32693b261b475381e43d8bebe01ae9e428d1b61417562ff579e901e1d8394",
        "1feb6cd9c6ac13ac32bbaec4fa1d21372593e3d8a8e9cd9dc9ac3a79e1bc1f52",
        25_184,
    ),
    TraceDefinition(
        "pcap/capEC2AMAZ-O4EL3NG-172.31.66.60",
        "calibration",
        "9b4e87489c5ab4b44cafa2b531cfecc37cb9a7788fdb555848358c0e950dcfcc",
        "6daf367c6c67cb805d11dc3676f8666b5d8e3b199d73ea346404083e4324cfe0",
        24_975,
    ),
    TraceDefinition(
        "pcap/capEC2AMAZ-O4EL3NG-172.31.67.120",
        "calibration",
        "a40a374aff98b04c288f9af1e9d7a218a4b44ecb3d48aabf11bec17c686860e7",
        "23e8787d48444010a77c449898929e59dff7c80080cb78070a1d70063b90d6a3",
        30_419,
    ),
    TraceDefinition(
        "pcap/capPC1-172.31.65.20",
        "calibration",
        "d395eac76e2321807e5aa1419bf1f336c547156c888fe01124a82e6907a95b3c",
        "4ea8b9e6e03ee51d4e107ee35f1bb8f892d6b4606e612727f172e9c6d140fe31",
        33_834,
    ),
    TraceDefinition(
        "pcap/capPC1-172.31.65.67",
        "test",
        "b6d233b8fce5fd4225b237ac64e2bb3bb552b69277fbcd63724e535d611fbec0",
        "80c9d51e9fd6a79afe95b333267e0376932245a6a6de72878b9f7a636e27d615",
        86_142,
    ),
    TraceDefinition(
        "pcap/capWIN-J6GMIG1DQE5-172.31.64.47",
        "test",
        "870e62e2307ca412bc7d3e4ed1d5ce203aba4905cdef0b08faf1e2ddd71ada29",
        "355ccdc2613a4ffc1a96313c30acecca4274adc4fdee7d2d655434a0ec39a34a",
        43_096,
    ),
    TraceDefinition(
        "pcap/capWIN-J6GMIG1DQE5-172.31.65.103",
        "test",
        "d99ef94d59702cf06ef4d4df6e4398d7c208cf4d57a51cae8336a5ff128b066e",
        "b618cb5ffa3d7be39e99dac257c83daafb497154fa553f6c525ec3f463e0431e",
        28_321,
    ),
    TraceDefinition(
        "pcap/capWIN-J6GMIG1DQE5-172.31.65.9",
        "test",
        "22dc7ba9174373d44e3bec1c03d3be9d4017acd943e4c5758cbd3d31a7340da9",
        "9cd1848eb189a0b63a99e6ddf5820256aaa39c8129966e2160803555fff21c14",
        26_368,
    ),
    TraceDefinition(
        "pcap/capWIN-J6GMIG1DQE5-172.31.67.19",
        "test",
        "a1ed49e74d54f7dd405a16e6f2a424c50c1e7f3864d1bb0652332b2d737e8759",
        "a3808503f9111acb0220720e3278d998fa6531cfa5046749335a3e3f0bc566ec",
        22_891,
    ),
)


def prepare_corpus(output_dir: Path) -> None:
    try:
        remotezip = importlib.import_module("remotezip")
    except ImportError as exc:  # pragma: no cover - acquisition-only dependency
        raise SystemExit(
            "run with: uv run --with remotezip experiments/detector_population_campaign.py prepare ..."
        ) from exc

    raw_dir = output_dir / "raw"
    trace_dir = output_dir / "traces"
    raw_dir.mkdir(parents=True, exist_ok=True)
    trace_dir.mkdir(parents=True, exist_ok=True)
    with remotezip.RemoteZip(SOURCE_ARCHIVE) as archive:
        for definition in TRACES:
            raw_path = raw_dir / definition.filename
            with archive.open(definition.member) as source, raw_path.open("wb") as sink:
                while chunk := source.read(1024 * 1024):
                    sink.write(chunk)
            _require_hash(raw_path, definition.source_sha256, "source member")
            filtered_path = trace_dir / definition.filename
            kept = _filter_classic_pcap(raw_path, filtered_path, FILTER_CUTOFF_UNIX_S)
            if kept != definition.filtered_packet_count:
                raise ValueError(
                    f"{definition.filename}: expected {definition.filtered_packet_count} packets, got {kept}"
                )
            _require_hash(filtered_path, definition.filtered_sha256, "filtered trace")
    _write_trace_manifest(output_dir)


def analyze_corpus(
    corpus_dir: Path,
    *,
    catalog_path: Path,
    tcpdump_path: str,
    tshark_path: str,
    suricata_path: str,
    tool_provenance: dict[str, str] | None = None,
) -> dict[str, Any]:
    trace_specs = _trace_specs(corpus_dir)
    catalog = load_mechanisms(catalog_path)
    fixed: dict[str, Any] = {}
    backend_tools = (
        (DetectorReplayBackend.BPF, tcpdump_path),
        (DetectorReplayBackend.TSHARK_DISPLAY_FILTER, tshark_path),
        (DetectorReplayBackend.SURICATA_RULE, suricata_path),
    )
    provenance = tool_provenance or {}
    with _positive_pcaps(corpus_dir / "positive-controls") as positives:
        for backend, tool in backend_tools:
            mechanisms = default_replay_mechanisms(catalog, backend=backend)
            negative = replay_detector_corpus(
                mechanisms,
                trace_specs,
                backend=backend,
                tcpdump_path=tcpdump_path,
                tshark_path=tshark_path,
                suricata_path=suricata_path,
            )
            if not negative.ok:
                raise RuntimeError(f"{backend.value} benign replay did not complete")
            positive_rows: dict[str, Any] = {}
            for mechanism in mechanisms:
                positive = replay_detectors_on_pcap(
                    [mechanism],
                    positives[mechanism.id],
                    source_kind=TraceSourceKind.LOCAL_GENERATED_CONTROL,
                    trace_name=f"{mechanism.id} deterministic positive control",
                    filtering_assumptions=("all eligible packets carry a nonzero target field",),
                    backend=backend,
                    tcpdump_path=tcpdump_path,
                    tshark_path=tshark_path,
                    suricata_path=suricata_path,
                )
                if not positive.ok:
                    raise RuntimeError(f"{backend.value} positive replay did not complete")
                row = positive.mechanisms[0]
                assert row.detector_provenance is not None
                positive_rows[mechanism.id] = row.detector_provenance
            fixed[backend.value] = _fixed_backend_summary(
                negative,
                positive_rows,
                tool_version=_tool_version(backend, tool),
                tool_executable=tool,
                tool_provenance=provenance.get(backend.value, "not supplied"),
            )

    statistical = _ipv4_id_statistical_evaluation(corpus_dir / "traces")
    return {
        "schema_version": SCHEMA_VERSION,
        "implementation": {
            "campaign_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "catalog_sha256": hashlib.sha256(catalog_path.read_bytes()).hexdigest(),
            "python_version": platform.python_version(),
        },
        "source": {
            "dataset": "CSE-CIC-IDS2018",
            "source_page": SOURCE_PAGE,
            "source_archive": SOURCE_ARCHIVE,
            "license": SOURCE_LICENSE,
            "capture_day": "Friday-02-03-2018",
            "filter_cutoff_unix_s": FILTER_CUTOFF_UNIX_S,
            "first_published_attack_unix_s": FIRST_ATTACK_UNIX_S,
            "pre_attack_margin_s": FIRST_ATTACK_UNIX_S - FILTER_CUTOFF_UNIX_S,
            "selection": (
                "ten internal endpoint captures not listed as Friday attackers or victims; "
                "only packets before the first published attack interval"
            ),
        },
        "traces": [_trace_public_record(corpus_dir / "traces", item) for item in TRACES],
        "fixed_predicates": fixed,
        "statistical_ipv4_id": statistical,
        "claim_boundary": [
            "The cohort is generated enterprise background from one testbed, day, and time block, not a representative deployment population.",
            "Fixed-predicate estimates cover only TCP reserved bits and the IPv4 reserved flag; other generated offset expressions are not population detectors.",
            "The IPv4-ID positive class replaces every ID in each 16-packet window and is an easier case than sparse or adaptive embedding.",
            "No result establishes active-probe resistance or Internet-path covertness.",
        ],
    }


def _fixed_backend_summary(
    report: Any,
    positives: dict[str, Any],
    *,
    tool_version: str,
    tool_executable: str,
    tool_provenance: str,
) -> dict[str, Any]:
    rows = []
    for negative in report.mechanisms:
        positive = positives[negative.mechanism_id]
        fp = negative.matched_unit_count
        negatives = negative.checked_unit_count
        tp = positive.matched_units
        positive_count = positive.checked_units
        fpr = fp / negatives
        tpr = tp / positive_count
        fpr_wilson95 = _wilson95(fp, negatives)
        tpr_wilson95 = _wilson95(tp, positive_count)
        rows.append(
            {
                "mechanism_id": negative.mechanism_id,
                "negative_trace_count": negative.trace_count,
                "negative_checked_unit_count": negatives,
                "false_positive_count": fp,
                "false_positive_rate": fpr,
                "fpr_wilson95": list(fpr_wilson95),
                "positive_checked_unit_count": positive_count,
                "true_positive_count": tp,
                "true_positive_rate": tpr,
                "tpr_wilson95": list(tpr_wilson95),
                "prevalence_adjusted_precision_point": {
                    f"{prevalence:g}": _prevalence_precision(tpr, fpr, prevalence)
                    for prevalence in (0.0001, 0.001, 0.01)
                },
                "prevalence_adjusted_precision_wilson95_lower": {
                    f"{prevalence:g}": _prevalence_precision(
                        tpr_wilson95[0], fpr_wilson95[1], prevalence
                    )
                    for prevalence in (0.0001, 0.001, 0.01)
                },
            }
        )
    return {
        "tool_executable": tool_executable,
        "tool_provenance": tool_provenance,
        "tool_version": tool_version,
        "mechanisms": rows,
    }


def _ipv4_id_statistical_evaluation(trace_dir: Path) -> dict[str, Any]:
    by_trace = {item.filename: _trace_window_scores(trace_dir / item.filename) for item in TRACES}
    calibration_negative = [
        score
        for item in TRACES
        if item.role == "calibration"
        for score in by_trace[item.filename][0]
    ]
    calibration_positive = [
        score
        for item in TRACES
        if item.role == "calibration"
        for score in by_trace[item.filename][1]
    ]
    test_negative = [
        score for item in TRACES if item.role == "test" for score in by_trace[item.filename][0]
    ]
    test_positive = [
        score for item in TRACES if item.role == "test" for score in by_trace[item.filename][1]
    ]
    quantile_index = math.ceil((1 - CALIBRATION_TARGET_FPR) * len(calibration_negative)) - 1
    quantile = sorted(calibration_negative)[quantile_index]
    threshold = math.nextafter(quantile, math.inf)
    observations = (
        *(LabeledDetectionScore(False, score) for score in test_negative),
        *(LabeledDetectionScore(True, score) for score in test_positive),
    )
    metrics = detector_metric_report(observations)
    selected = detector_threshold_metrics(observations, threshold)
    selected_document = selected.to_json()
    selected_document["prevalence_adjusted_precision_wilson95_lower"] = {
        f"{prevalence:g}": _prevalence_precision(
            selected.tpr_wilson95[0], selected.fpr_wilson95[1], prevalence
        )
        for prevalence in (0.0001, 0.001, 0.01)
    }
    curve = [
        {
            "threshold": row.threshold,
            "true_positive_rate": row.true_positive_rate,
            "false_positive_rate": row.false_positive_rate,
            "precision": row.precision,
            "recall": row.recall,
        }
        for row in metrics.thresholds
        if math.isfinite(row.threshold)
    ]
    per_trace = []
    for item in TRACES:
        negative, positive = by_trace[item.filename]
        per_trace.append(
            {
                "trace": item.filename,
                "role": item.role,
                "negative_window_count": len(negative),
                "positive_window_count": len(positive),
                "selected_false_positive_count": sum(score >= threshold for score in negative),
                "selected_true_positive_count": sum(score >= threshold for score in positive),
            }
        )
    return {
        "mechanism_id": "ipv4-id-atomic",
        "detector_family": "stateful_statistical",
        "feature": (
            "mean absolute circular difference between adjacent IPv4 IDs, normalized "
            "by 32768, in a directional five-tuple window"
        ),
        "window_size_packets": WINDOW_SIZE,
        "positive_construction": (
            "deterministic SHA-256-derived 16-bit IDs replace every observed ID in a "
            "held-out window; all other window membership is unchanged"
        ),
        "split_unit": "endpoint trace",
        "calibration_trace_count": sum(item.role == "calibration" for item in TRACES),
        "test_trace_count": sum(item.role == "test" for item in TRACES),
        "calibration_negative_count": len(calibration_negative),
        "calibration_positive_count": len(calibration_positive),
        "calibration_target_false_positive_rate": CALIBRATION_TARGET_FPR,
        "calibration_empirical_quantile": quantile,
        "selected_threshold": threshold,
        "test_positive_count": metrics.positive_count,
        "test_negative_count": metrics.negative_count,
        "roc_auc": metrics.roc_auc,
        "average_precision": metrics.average_precision,
        "selected_operating_point": selected_document,
        "roc_pr_curve": curve,
        "per_trace": per_trace,
    }


def _trace_window_scores(path: Path) -> tuple[list[float], list[float]]:
    flows: dict[bytes, list[int]] = defaultdict(list)
    for _timestamp, packet in _iter_classic_pcap(path):
        record = _ipv4_id_record(packet)
        if record is not None:
            flow, identifier = record
            flows[flow].append(identifier)
    negative: list[float] = []
    positive: list[float] = []
    for flow in sorted(flows):
        identifiers = flows[flow]
        for start in range(0, len(identifiers) - WINDOW_SIZE + 1, WINDOW_SIZE):
            window = identifiers[start : start + WINDOW_SIZE]
            negative.append(_ipv4_id_score(window))
            seed = hashlib.sha256(
                path.name.encode()
                + flow
                + start.to_bytes(8, "big")
                + b"celatim-ipv4-id-positive-v1"
            ).digest()
            positive_ids = [
                int.from_bytes(hashlib.sha256(seed + index.to_bytes(4, "big")).digest()[:2], "big")
                for index in range(WINDOW_SIZE)
            ]
            positive.append(_ipv4_id_score(positive_ids))
    return negative, positive


def _ipv4_id_record(packet: bytes) -> tuple[bytes, int] | None:
    if len(packet) < 34:
        return None
    offset = 14
    ether_type = int.from_bytes(packet[12:14], "big")
    while ether_type in (0x8100, 0x88A8, 0x9100) and len(packet) >= offset + 4:
        ether_type = int.from_bytes(packet[offset + 2 : offset + 4], "big")
        offset += 4
    if ether_type != 0x0800 or len(packet) < offset + 20 or packet[offset] >> 4 != 4:
        return None
    header_length = (packet[offset] & 0x0F) * 4
    if header_length < 20 or len(packet) < offset + header_length:
        return None
    protocol = packet[offset + 9]
    source_port = destination_port = 0
    if protocol in (6, 17) and len(packet) >= offset + header_length + 4:
        source_port = int.from_bytes(
            packet[offset + header_length : offset + header_length + 2], "big"
        )
        destination_port = int.from_bytes(
            packet[offset + header_length + 2 : offset + header_length + 4], "big"
        )
    flow = (
        packet[offset + 12 : offset + 20]
        + bytes((protocol,))
        + source_port.to_bytes(2, "big")
        + destination_port.to_bytes(2, "big")
    )
    return flow, int.from_bytes(packet[offset + 4 : offset + 6], "big")


def _ipv4_id_score(identifiers: list[int]) -> float:
    differences = [(right - left) & 0xFFFF for left, right in pairwise(identifiers)]
    circular = [min(value, 65_536 - value) for value in differences]
    return sum(circular) / (len(circular) * 32_768)


class _PositivePcapContext:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir

    def __enter__(self) -> dict[str, Path]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        config = default_ipv4_packet_path_config_for("tcp-reserved-bits")
        tcp_frames = [
            build_tcp_reserved_bits_frame(config, index % 7 + 1, index=index)
            for index in range(POSITIVE_PACKET_COUNT)
        ]
        ipv4_frames = []
        for index in range(POSITIVE_PACKET_COUNT):
            frame = bytearray(build_tcp_reserved_bits_frame(config, 0, index=index))
            frame[14 + 6] |= 0x80
            ipv4_frames.append(bytes(frame))
        paths = {
            "tcp-reserved-bits": self.output_dir / "tcp-reserved-bits.pcap",
            "ipv4-reserved-flag": self.output_dir / "ipv4-reserved-flag.pcap",
        }
        _write_classic_pcap(paths["tcp-reserved-bits"], tcp_frames)
        _write_classic_pcap(paths["ipv4-reserved-flag"], ipv4_frames)
        return paths

    def __exit__(self, *_args: object) -> None:
        for path in self.output_dir.glob("*.pcap"):
            path.unlink()
        self.output_dir.rmdir()


def _positive_pcaps(output_dir: Path) -> _PositivePcapContext:
    return _PositivePcapContext(output_dir)


def _trace_specs(corpus_dir: Path) -> list[DetectorReplayTraceSpec]:
    assumptions = (
        "Endpoint is not listed as a Friday-02-03-2018 attacker or victim.",
        "Packets end at 2018-03-02T15:00:00Z, eleven minutes before the first published attack interval.",
        "The source calls B-Profile traffic realistic benign background; covert use was not independently ruled out.",
        "One generated enterprise testbed and time block is not a deployment population.",
    )
    return [
        DetectorReplayTraceSpec(
            path=corpus_dir / "traces" / item.filename,
            source_kind=TraceSourceKind.PUBLIC_BENIGN_TRACE,
            trace_name=f"CSE-CIC-IDS2018 pre-attack {item.filename}",
            origin_url=SOURCE_PAGE,
            license=SOURCE_LICENSE,
            filtering_assumptions=assumptions,
        )
        for item in TRACES
    ]


def _trace_public_record(trace_dir: Path, item: TraceDefinition) -> dict[str, Any]:
    path = trace_dir / item.filename
    _require_hash(path, item.filtered_sha256, "filtered trace")
    return {
        "source_member": item.member,
        "role": item.role,
        "source_sha256": item.source_sha256,
        "filtered_sha256": item.filtered_sha256,
        "filtered_size_bytes": path.stat().st_size,
        "filtered_packet_count": item.filtered_packet_count,
    }


def _write_trace_manifest(output_dir: Path) -> None:
    traces = []
    for spec in _trace_specs(output_dir):
        document = spec.to_json()
        document["path"] = str(Path("traces") / Path(document["path"]).name)
        traces.append(document)
    (output_dir / "detector-traces.json").write_text(
        json.dumps(
            {"schema_version": "celatim.detector_trace_manifest.v1", "traces": traces},
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _filter_classic_pcap(source: Path, destination: Path, cutoff_unix_s: float) -> int:
    with source.open("rb") as src, destination.open("wb") as dst:
        global_header = src.read(24)
        endian, scale = _pcap_format(global_header)
        dst.write(global_header)
        packet_header = struct.Struct(f"{endian}IIII")
        kept = 0
        while header := src.read(16):
            seconds, fraction, captured_length, _original_length = packet_header.unpack(header)
            packet = src.read(captured_length)
            if seconds + fraction / scale < cutoff_unix_s:
                dst.write(header)
                dst.write(packet)
                kept += 1
        return kept


def _iter_classic_pcap(path: Path) -> Iterator[tuple[float, bytes]]:
    with path.open("rb") as source:
        global_header = source.read(24)
        endian, scale = _pcap_format(global_header)
        packet_header = struct.Struct(f"{endian}IIII")
        while header := source.read(16):
            seconds, fraction, captured_length, _original_length = packet_header.unpack(header)
            yield seconds + fraction / scale, source.read(captured_length)


def _pcap_format(global_header: bytes) -> tuple[str, int]:
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    try:
        return formats[global_header[:4]]
    except KeyError as exc:
        raise ValueError("expected a classic pcap file") from exc


def _write_classic_pcap(path: Path, frames: list[bytes]) -> None:
    global_header = struct.Struct("<IHHIIII")
    with path.open("wb") as output:
        output.write(global_header.pack(0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1))
        for index, frame in enumerate(frames):
            output.write(_PCAP_PACKET.pack(index, 0, len(frame), len(frame)))
            output.write(frame)


def _tool_version(backend: DetectorReplayBackend, path: str) -> str:
    args = ("--build-info",) if backend is DetectorReplayBackend.SURICATA_RULE else ("--version",)
    completed = subprocess.run(
        (path, *args), check=True, capture_output=True, text=True, timeout=30
    )
    return " ".join(completed.stdout.splitlines()[:2])


def _require_hash(path: Path, expected: str, kind: str) -> None:
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise ValueError(f"{path}: {kind} SHA-256 {actual} != expected {expected}")


def _wilson95(successes: int, trials: int) -> tuple[float, float]:
    z = 1.959963984540054
    proportion = successes / trials
    denominator = 1 + z * z / trials
    center = (proportion + z * z / (2 * trials)) / denominator
    radius = (
        z
        * math.sqrt(proportion * (1 - proportion) / trials + z * z / (4 * trials * trials))
        / denominator
    )
    lower = 0.0 if successes == 0 else max(0.0, center - radius)
    upper = 1.0 if successes == trials else min(1.0, center + radius)
    return lower, upper


def _prevalence_precision(tpr: float, fpr: float, prevalence: float) -> float | None:
    denominator = tpr * prevalence + fpr * (1 - prevalence)
    return tpr * prevalence / denominator if denominator else None


def render_markdown(report: dict[str, Any]) -> str:
    statistical = report["statistical_ipv4_id"]
    selected = statistical["selected_operating_point"]
    lines = [
        "# Public Benign-Trace Detector Evaluation",
        "",
        "CSE-CIC-IDS2018 Friday 2 March 2018; ten untargeted endpoint captures,",
        "truncated eleven minutes before the first published attack interval.",
        "Raw packet data is not committed; the JSON report records source and filtered hashes.",
        "",
        "## Fixed predicates",
        "",
        "| Backend | Mechanism | Benign units | FP | FPR (Wilson 95%) | Positive units | TP | TPR (Wilson 95%) |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for backend, backend_report in report["fixed_predicates"].items():
        for row in backend_report["mechanisms"]:
            lines.append(
                f"| {backend} | `{row['mechanism_id']}` | {row['negative_checked_unit_count']:,} "
                f"| {row['false_positive_count']} | {row['false_positive_rate']:.6f} "
                f"[{row['fpr_wilson95'][0]:.6f}, {row['fpr_wilson95'][1]:.6f}] "
                f"| {row['positive_checked_unit_count']:,} | {row['true_positive_count']:,} "
                f"| {row['true_positive_rate']:.6f} "
                f"[{row['tpr_wilson95'][0]:.6f}, {row['tpr_wilson95'][1]:.6f}] |"
            )
    lines.extend(
        [
            "",
            "## Stateful IPv4-ID detector",
            "",
            f"- Calibration/test split: {statistical['calibration_trace_count']}/"
            f"{statistical['test_trace_count']} endpoint traces.",
            f"- Test windows: {statistical['test_negative_count']:,} benign and "
            f"{statistical['test_positive_count']:,} deterministic full-rate replacements.",
            f"- ROC AUC: {statistical['roc_auc']:.6f}; average precision: "
            f"{statistical['average_precision']:.6f}.",
            f"- Selected operating point: TPR {selected['true_positive_rate']:.6f}, FPR "
            f"{selected['false_positive_rate']:.6f}; 95% Wilson intervals "
            f"[{selected['tpr_wilson95'][0]:.6f}, {selected['tpr_wilson95'][1]:.6f}] and "
            f"[{selected['fpr_wilson95'][0]:.6f}, {selected['fpr_wilson95'][1]:.6f}].",
            "- Prevalence-adjusted precision (point estimate): "
            + ", ".join(
                f"{float(key) * 100:g}% -> {value:.6f}"
                for key, value in selected["prevalence_adjusted_precision"].items()
            )
            + ".",
            "- Conservative prevalence-adjusted precision (Wilson 95% lower bound): "
            + ", ".join(
                f"{float(key) * 100:g}% -> {value:.6f}"
                for key, value in selected["prevalence_adjusted_precision_wilson95_lower"].items()
            )
            + ".",
            "",
            "## Claim boundary",
            "",
            *(f"- {item}" for item in report["claim_boundary"]),
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--output-dir", type=Path, required=True)
    analyze = subparsers.add_parser("analyze")
    analyze.add_argument("--corpus-dir", type=Path, required=True)
    analyze.add_argument("--catalog", type=Path, default=Path("data/mechanisms.jsonl"))
    analyze.add_argument("--tcpdump", default="tcpdump")
    analyze.add_argument("--tcpdump-provenance", default="host executable")
    analyze.add_argument("--tshark", default="tshark")
    analyze.add_argument("--tshark-provenance", default="local executable")
    analyze.add_argument("--suricata", default="suricata")
    analyze.add_argument("--suricata-provenance", default="local executable")
    analyze.add_argument("--output-json", type=Path, required=True)
    analyze.add_argument("--output-markdown", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        prepare_corpus(args.output_dir)
        return 0
    report = analyze_corpus(
        args.corpus_dir,
        catalog_path=args.catalog,
        tcpdump_path=args.tcpdump,
        tshark_path=args.tshark,
        suricata_path=args.suricata,
        tool_provenance={
            DetectorReplayBackend.BPF.value: args.tcpdump_provenance,
            DetectorReplayBackend.TSHARK_DISPLAY_FILTER.value: args.tshark_provenance,
            DetectorReplayBackend.SURICATA_RULE.value: args.suricata_provenance,
        },
    )
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_markdown.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    args.output_markdown.write_text(render_markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
