"""ROC/PR and prevalence-aware detector metrics."""

import pytest

from celatim.analysis.detector_metrics import (
    LabeledDetectionScore,
    detector_metric_report,
    detector_threshold_metrics,
)


def test_perfect_detector_has_unit_roc_and_average_precision():
    report = detector_metric_report(
        [
            LabeledDetectionScore(True, 0.9),
            LabeledDetectionScore(True, 0.8),
            LabeledDetectionScore(False, 0.2),
            LabeledDetectionScore(False, 0.1),
        ],
        prevalence_assumptions=(0.001,),
    )

    assert report.roc_auc == pytest.approx(1.0)
    assert report.average_precision == pytest.approx(1.0)
    operating_point = next(row for row in report.thresholds if row.threshold == 0.8)
    assert operating_point.true_positive_rate == 1.0
    assert operating_point.false_positive_rate == 0.0
    assert operating_point.prevalence_adjusted_precision["0.001"] == 1.0
    assert operating_point.tpr_wilson95[0] < 1.0


def test_prevalence_adjustment_exposes_low_base_rate_precision():
    report = detector_metric_report(
        [
            LabeledDetectionScore(True, 0.9),
            LabeledDetectionScore(False, 0.8),
            LabeledDetectionScore(False, 0.1),
        ],
        prevalence_assumptions=(0.001,),
    )
    operating_point = next(row for row in report.thresholds if row.threshold == 0.8)

    assert operating_point.true_positive_rate == 1.0
    assert operating_point.false_positive_rate == 0.5
    assert operating_point.precision == 0.5
    assert operating_point.prevalence_adjusted_precision["0.001"] == pytest.approx(
        0.001 / (0.001 + 0.5 * 0.999)
    )


def test_requires_both_classes_and_valid_prevalence():
    with pytest.raises(ValueError, match="positive and negative"):
        detector_metric_report([LabeledDetectionScore(True, 1.0)])
    with pytest.raises(ValueError, match="prevalence"):
        detector_metric_report(
            [LabeledDetectionScore(True, 1.0), LabeledDetectionScore(False, 0.0)],
            prevalence_assumptions=(0.0,),
        )


def test_external_threshold_is_evaluated_without_recalibration():
    scores = [
        LabeledDetectionScore(True, 0.9),
        LabeledDetectionScore(True, 0.4),
        LabeledDetectionScore(False, 0.6),
        LabeledDetectionScore(False, 0.1),
    ]

    row = detector_threshold_metrics(scores, 0.5, prevalence_assumptions=(0.001,))

    assert row.threshold == 0.5
    assert row.true_positive == 1
    assert row.false_positive == 1
    assert row.true_negative == 1
    assert row.false_negative == 1
