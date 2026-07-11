"""Threshold-sweep metrics for labeled detector scores."""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass
from itertools import pairwise
from typing import Any

DETECTOR_METRICS_SCHEMA_VERSION = "celatim.detector_metrics.v1"


@dataclass(frozen=True)
class LabeledDetectionScore:
    label: bool
    score: float

    def __post_init__(self) -> None:
        if not math.isfinite(self.score):
            raise ValueError("detector score must be finite")


@dataclass(frozen=True)
class ThresholdMetrics:
    threshold: float
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    true_positive_rate: float
    false_positive_rate: float
    precision: float | None
    recall: float
    tpr_wilson95: tuple[float, float]
    fpr_wilson95: tuple[float, float]
    prevalence_adjusted_precision: dict[str, float | None]

    def to_json(self) -> dict[str, Any]:
        return {
            "threshold": self.threshold,
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "true_negative": self.true_negative,
            "false_negative": self.false_negative,
            "true_positive_rate": self.true_positive_rate,
            "false_positive_rate": self.false_positive_rate,
            "precision": self.precision,
            "recall": self.recall,
            "tpr_wilson95": list(self.tpr_wilson95),
            "fpr_wilson95": list(self.fpr_wilson95),
            "prevalence_adjusted_precision": self.prevalence_adjusted_precision,
        }


@dataclass(frozen=True)
class DetectorMetricReport:
    positive_count: int
    negative_count: int
    roc_auc: float
    average_precision: float
    prevalence_assumptions: tuple[float, ...]
    thresholds: tuple[ThresholdMetrics, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": DETECTOR_METRICS_SCHEMA_VERSION,
            "positive_count": self.positive_count,
            "negative_count": self.negative_count,
            "roc_auc": self.roc_auc,
            "average_precision": self.average_precision,
            "prevalence_assumptions": list(self.prevalence_assumptions),
            "thresholds": [row.to_json() for row in self.thresholds],
        }


def detector_metric_report(
    scores: Iterable[LabeledDetectionScore],
    *,
    prevalence_assumptions: tuple[float, ...] = (0.0001, 0.001, 0.01),
) -> DetectorMetricReport:
    observations = tuple(scores)
    positives = sum(observation.label for observation in observations)
    negatives = len(observations) - positives
    if positives == 0 or negatives == 0:
        raise ValueError("detector evaluation requires positive and negative observations")
    if any(not 0 < prevalence < 1 for prevalence in prevalence_assumptions):
        raise ValueError("prevalence assumptions must be between zero and one")
    unique_scores = sorted({observation.score for observation in observations}, reverse=True)
    thresholds = (math.inf, *unique_scores, -math.inf)
    rows = tuple(
        _threshold_metrics(
            observations,
            threshold,
            prevalence_assumptions=prevalence_assumptions,
        )
        for threshold in thresholds
    )
    roc_points = sorted(
        ((row.false_positive_rate, row.true_positive_rate) for row in rows),
        key=lambda point: (point[0], point[1]),
    )
    precision_rows = [row for row in rows if row.precision is not None]
    precision_rows.sort(key=lambda row: row.recall)
    return DetectorMetricReport(
        positive_count=positives,
        negative_count=negatives,
        roc_auc=_trapezoid(roc_points),
        average_precision=_step_average_precision(precision_rows),
        prevalence_assumptions=prevalence_assumptions,
        thresholds=rows,
    )


def detector_threshold_metrics(
    scores: Iterable[LabeledDetectionScore],
    threshold: float,
    *,
    prevalence_assumptions: tuple[float, ...] = (0.0001, 0.001, 0.01),
) -> ThresholdMetrics:
    """Evaluate one externally selected threshold without recalibrating it."""

    observations = tuple(scores)
    positives = sum(observation.label for observation in observations)
    negatives = len(observations) - positives
    if positives == 0 or negatives == 0:
        raise ValueError("detector evaluation requires positive and negative observations")
    if not math.isfinite(threshold):
        raise ValueError("detector threshold must be finite")
    if any(not 0 < prevalence < 1 for prevalence in prevalence_assumptions):
        raise ValueError("prevalence assumptions must be between zero and one")
    return _threshold_metrics(
        observations,
        threshold,
        prevalence_assumptions=prevalence_assumptions,
    )


def _threshold_metrics(
    scores: tuple[LabeledDetectionScore, ...],
    threshold: float,
    *,
    prevalence_assumptions: tuple[float, ...],
) -> ThresholdMetrics:
    true_positive = sum(item.label and item.score >= threshold for item in scores)
    false_positive = sum(not item.label and item.score >= threshold for item in scores)
    positive_count = sum(item.label for item in scores)
    negative_count = len(scores) - positive_count
    false_negative = positive_count - true_positive
    true_negative = negative_count - false_positive
    tpr = true_positive / positive_count
    fpr = false_positive / negative_count
    predicted_positive = true_positive + false_positive
    precision = true_positive / predicted_positive if predicted_positive else None
    adjusted = {
        f"{prevalence:g}": _prevalence_precision(tpr, fpr, prevalence)
        for prevalence in prevalence_assumptions
    }
    return ThresholdMetrics(
        threshold=threshold,
        true_positive=true_positive,
        false_positive=false_positive,
        true_negative=true_negative,
        false_negative=false_negative,
        true_positive_rate=tpr,
        false_positive_rate=fpr,
        precision=precision,
        recall=tpr,
        tpr_wilson95=_wilson95(true_positive, positive_count),
        fpr_wilson95=_wilson95(false_positive, negative_count),
        prevalence_adjusted_precision=adjusted,
    )


def _prevalence_precision(tpr: float, fpr: float, prevalence: float) -> float | None:
    denominator = tpr * prevalence + fpr * (1 - prevalence)
    return tpr * prevalence / denominator if denominator else None


def _wilson95(successes: int, trials: int) -> tuple[float, float]:
    z = 1.959963984540054
    proportion = successes / trials
    denominator = 1 + z * z / trials
    center = (proportion + z * z / (2 * trials)) / denominator
    margin = (
        z
        * math.sqrt(proportion * (1 - proportion) / trials + z * z / (4 * trials * trials))
        / denominator
    )
    return max(0.0, center - margin), min(1.0, center + margin)


def _trapezoid(points: list[tuple[float, float]]) -> float:
    area = 0.0
    for left, right in pairwise(points):
        area += (right[0] - left[0]) * (left[1] + right[1]) / 2
    return area


def _step_average_precision(rows: list[ThresholdMetrics]) -> float:
    area = 0.0
    previous_recall = 0.0
    for row in rows:
        if row.recall > previous_recall and row.precision is not None:
            area += (row.recall - previous_recall) * row.precision
            previous_recall = row.recall
    return area


__all__ = [
    "DETECTOR_METRICS_SCHEMA_VERSION",
    "DetectorMetricReport",
    "LabeledDetectionScore",
    "ThresholdMetrics",
    "detector_metric_report",
    "detector_threshold_metrics",
]
