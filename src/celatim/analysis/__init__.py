"""Cross-cutting analysis: the reusable telemetry dataset (M6)."""

from __future__ import annotations

from .crosshost_evidence import (
    CLAIM_LEDGER_SCHEMA_VERSION,
    CROSSHOST_PUBLIC_INDEX_SCHEMA_VERSION,
    build_claim_ledger,
    build_crosshost_public_index,
    claim_count,
    load_claim_ledger,
    load_crosshost_public_index,
)
from .dataset import (
    DATASET_SCHEMA_VERSION,
    DatasetRecord,
    build_manifest,
    build_records,
    write_dataset,
)
from .detector_metrics import (
    DETECTOR_METRICS_SCHEMA_VERSION,
    DetectorMetricReport,
    LabeledDetectionScore,
    ThresholdMetrics,
    detector_metric_report,
    detector_threshold_metrics,
)
from .subliminal_controls import (
    SUBLIMINAL_CONTROL_REPORT_SCHEMA_VERSION,
    build_subliminal_control_report,
)

__all__ = [
    "CLAIM_LEDGER_SCHEMA_VERSION",
    "CROSSHOST_PUBLIC_INDEX_SCHEMA_VERSION",
    "DATASET_SCHEMA_VERSION",
    "DETECTOR_METRICS_SCHEMA_VERSION",
    "SUBLIMINAL_CONTROL_REPORT_SCHEMA_VERSION",
    "DatasetRecord",
    "DetectorMetricReport",
    "LabeledDetectionScore",
    "ThresholdMetrics",
    "build_claim_ledger",
    "build_crosshost_public_index",
    "build_manifest",
    "build_records",
    "build_subliminal_control_report",
    "claim_count",
    "detector_metric_report",
    "detector_threshold_metrics",
    "load_claim_ledger",
    "load_crosshost_public_index",
    "write_dataset",
]
