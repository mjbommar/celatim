"""Stateful detector planning for mechanisms that need parsing or baselines."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..model import (
    CarrierClass,
    Detectability,
    DetectionAnnotationSource,
    DetectPredicate,
    FalsePositive,
    Mechanism,
)

STATEFUL_DETECTOR_CLAIM_STATUS = "generated_not_executed_requires_trace_baseline"


class StatefulDetectorKind(str, Enum):
    PARSED_RESERVED_NONZERO = "parsed_reserved_nonzero"
    PADDING_ENTROPY = "padding_entropy"
    OPAQUE_VALUE_BASELINE = "opaque_value_baseline"
    RESERVED_CODEPOINT = "reserved_codepoint"
    ELEMENT_PRESENCE = "element_presence"
    TIMING_OR_COUNT_BASELINE = "timing_or_count_baseline"


@dataclass(frozen=True)
class StatefulDetectorPlan:
    mechanism_id: str
    protocol: str
    carrier_class: CarrierClass
    detectability: Detectability
    detector_kind: StatefulDetectorKind
    predicate: DetectPredicate
    false_positive_posture: FalsePositive
    annotation_source: DetectionAnnotationSource
    disposition: str
    scrub_strategy: str
    zeek_hook: str
    suricata_strategy: str
    baseline_required: bool
    claim_status: str = STATEFUL_DETECTOR_CLAIM_STATUS

    def to_json(self) -> dict[str, Any]:
        return {
            "mechanism_id": self.mechanism_id,
            "protocol": self.protocol,
            "carrier_class": self.carrier_class.value,
            "detectability": self.detectability.value,
            "detector_kind": self.detector_kind.value,
            "predicate": self.predicate.value,
            "false_positive_posture": self.false_positive_posture.value,
            "annotation_source": self.annotation_source.value,
            "disposition": self.disposition,
            "scrub_strategy": self.scrub_strategy,
            "zeek_hook": self.zeek_hook,
            "suricata_strategy": self.suricata_strategy,
            "baseline_required": self.baseline_required,
            "claim_status": self.claim_status,
        }


def stateful_detector_plan_for(mechanism: Mechanism) -> StatefulDetectorPlan | None:
    """Return a generated stateful-detector plan for observable non-stateless rows."""
    if mechanism.detectability not in {
        Detectability.STATEFUL_DPI,
        Detectability.STATISTICAL,
    }:
        return None
    detector_kind = _detector_kind(mechanism)
    return StatefulDetectorPlan(
        mechanism_id=mechanism.id,
        protocol=mechanism.protocol,
        carrier_class=mechanism.carrier_class,
        detectability=mechanism.detectability,
        detector_kind=detector_kind,
        predicate=mechanism.effective_detect_predicate,
        false_positive_posture=mechanism.effective_false_positive,
        annotation_source=mechanism.detection_annotation_source,
        disposition=_disposition(mechanism),
        scrub_strategy=mechanism.scrub_strategy.value,
        zeek_hook=_zeek_hook(mechanism),
        suricata_strategy=_suricata_strategy(detector_kind),
        baseline_required=_baseline_required(mechanism, detector_kind),
    )


def stateful_detector_plans(
    mechanisms: Iterable[Mechanism],
) -> tuple[StatefulDetectorPlan, ...]:
    plans = [
        plan
        for mechanism in sorted(mechanisms, key=lambda item: item.id)
        if (plan := stateful_detector_plan_for(mechanism)) is not None
    ]
    return tuple(plans)


def _detector_kind(mechanism: Mechanism) -> StatefulDetectorKind:
    if mechanism.carrier_class is CarrierClass.B:
        return StatefulDetectorKind.PADDING_ENTROPY
    if mechanism.carrier_class is CarrierClass.C:
        return StatefulDetectorKind.OPAQUE_VALUE_BASELINE
    if mechanism.carrier_class is CarrierClass.D:
        return StatefulDetectorKind.RESERVED_CODEPOINT
    if mechanism.carrier_class is CarrierClass.E:
        return StatefulDetectorKind.ELEMENT_PRESENCE
    if mechanism.carrier_class is CarrierClass.F:
        return StatefulDetectorKind.TIMING_OR_COUNT_BASELINE
    return StatefulDetectorKind.PARSED_RESERVED_NONZERO


def _disposition(mechanism: Mechanism) -> str:
    if mechanism.effective_false_positive in {
        FalsePositive.BENIGN_NEVER,
        FalsePositive.BENIGN_RARE,
    }:
        return "alert"
    return "log"


def _baseline_required(
    mechanism: Mechanism,
    detector_kind: StatefulDetectorKind,
) -> bool:
    if mechanism.detectability is Detectability.STATISTICAL:
        return True
    if detector_kind in {
        StatefulDetectorKind.PADDING_ENTROPY,
        StatefulDetectorKind.OPAQUE_VALUE_BASELINE,
        StatefulDetectorKind.ELEMENT_PRESENCE,
        StatefulDetectorKind.TIMING_OR_COUNT_BASELINE,
    }:
        return True
    return mechanism.effective_false_positive is not FalsePositive.BENIGN_NEVER


def _zeek_hook(mechanism: Mechanism) -> str:
    protocol = mechanism.protocol.lower()
    if protocol in {"dns", "doh"}:
        return "dns_message/dns_answer parser hook"
    if protocol in {"http", "binaryhttp"}:
        return "http_message_done parser hook"
    if protocol in {"http/2", "http2"}:
        return "HTTP/2 frame analyzer hook"
    if protocol in {"quic", "http/3"}:
        return "QUIC analyzer frame/transport-parameter hook"
    if protocol in {"tls", "dtls"}:
        return "ssl_extension/record analyzer hook"
    if protocol in {"tcp", "udp", "icmp", "icmpv6", "ipv4", "ipv6"}:
        return f"{protocol} packet/header analyzer hook"
    return f"{mechanism.protocol} protocol analyzer hook"


def _suricata_strategy(detector_kind: StatefulDetectorKind) -> str:
    return {
        StatefulDetectorKind.PARSED_RESERVED_NONZERO: "parser keyword or Lua rule checks parsed reserved bits != 0",
        StatefulDetectorKind.PADDING_ENTROPY: "Lua/dataset rule measures padding entropy and nonzero rate",
        StatefulDetectorKind.OPAQUE_VALUE_BASELINE: "flow state, dataset, or Lua rule baselines opaque value distribution",
        StatefulDetectorKind.RESERVED_CODEPOINT: "parser keyword, dataset, or Lua rule matches reserved codepoint set",
        StatefulDetectorKind.ELEMENT_PRESENCE: "parser keyword or Lua rule records optional/unknown element presence",
        StatefulDetectorKind.TIMING_OR_COUNT_BASELINE: "threshold/detection-filter plus offline inter-arrival or count baseline",
    }[detector_kind]


__all__ = [
    "STATEFUL_DETECTOR_CLAIM_STATUS",
    "StatefulDetectorKind",
    "StatefulDetectorPlan",
    "stateful_detector_plan_for",
    "stateful_detector_plans",
]
