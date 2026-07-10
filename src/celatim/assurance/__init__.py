"""Deployment-readiness assurance: requirements + per-mechanism scorecard."""

from __future__ import annotations

from .requirements import (
    HARD_REQUIREMENTS,
    REQUIREMENTS,
    SOFT_REQUIREMENTS,
    THREAT_MODEL,
    Requirement,
    RequirementKind,
    RequirementStatus,
)
from .scorecard import (
    MechanismScorecard,
    RequirementAssessment,
    ScorecardReport,
    build_scorecard,
    score_mechanism,
)

__all__ = [
    "HARD_REQUIREMENTS",
    "REQUIREMENTS",
    "SOFT_REQUIREMENTS",
    "THREAT_MODEL",
    "MechanismScorecard",
    "Requirement",
    "RequirementAssessment",
    "RequirementKind",
    "RequirementStatus",
    "ScorecardReport",
    "build_scorecard",
    "score_mechanism",
]
