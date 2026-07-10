"""Stateful detector plan classification."""

from pathlib import Path

from celatim.catalog import load_mechanisms
from celatim.detect import (
    STATEFUL_DETECTOR_CLAIM_STATUS,
    StatefulDetectorKind,
    stateful_detector_plan_for,
    stateful_detector_plans,
)
from celatim.model import DetectionAnnotationSource, DetectPredicate, FalsePositive

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def mechs():
    return {mechanism.id: mechanism for mechanism in load_mechanisms(DATA)}


def test_stateful_detector_plans_cover_observable_non_stateless_rows():
    plans = stateful_detector_plans(load_mechanisms(DATA))

    assert len(plans) == 52
    assert {plan.claim_status for plan in plans} == {STATEFUL_DETECTOR_CLAIM_STATUS}
    assert "tcp-reserved-bits" not in {plan.mechanism_id for plan in plans}
    assert "http3-reserved-frame-types" not in {plan.mechanism_id for plan in plans}
    assert "rsa-pss-salt" not in {plan.mechanism_id for plan in plans}


def test_stateful_detector_kind_maps_padding_presence_opaque_and_timing():
    m = mechs()

    padding = stateful_detector_plan_for(m["edns0-padding"])
    presence = stateful_detector_plan_for(m["dns-txt-tunnel"])
    opaque = stateful_detector_plan_for(m["ipv4-id-atomic"])
    timing = stateful_detector_plan_for(m["dns-timing"])

    assert padding is not None
    assert presence is not None
    assert opaque is not None
    assert timing is not None
    assert padding.detector_kind is StatefulDetectorKind.PADDING_ENTROPY
    assert padding.predicate is DetectPredicate.ENTROPY
    assert padding.false_positive_posture is FalsePositive.BENIGN_COMMON
    assert padding.annotation_source is DetectionAnnotationSource.EXPLICIT_CATALOG
    assert presence.detector_kind is StatefulDetectorKind.ELEMENT_PRESENCE
    assert opaque.detector_kind is StatefulDetectorKind.OPAQUE_VALUE_BASELINE
    assert opaque.predicate is DetectPredicate.STATISTICAL
    assert opaque.false_positive_posture is FalsePositive.BENIGN_COMMON
    assert opaque.annotation_source is DetectionAnnotationSource.EXPLICIT_CATALOG
    assert timing.detector_kind is StatefulDetectorKind.TIMING_OR_COUNT_BASELINE


def test_stateful_detector_plan_records_baseline_and_scrub_guidance():
    plan = stateful_detector_plan_for(mechs()["dns-timing"])

    assert plan is not None
    assert plan.baseline_required is True
    assert plan.disposition == "log"
    assert plan.scrub_strategy == "shape_timing"
    assert "dns" in plan.zeek_hook.lower()
    assert "baseline" in plan.suricata_strategy
    assert plan.to_json()["claim_status"] == STATEFUL_DETECTOR_CLAIM_STATUS
    assert plan.to_json()["predicate"] == "timing"
    assert plan.to_json()["false_positive_posture"] == "benign_common"
    assert plan.to_json()["annotation_source"] == "explicit_catalog"
