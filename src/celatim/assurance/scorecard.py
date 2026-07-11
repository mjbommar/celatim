"""Evidence-led deployment-readiness scorecard.

Only run-backed mechanism ids from a claim-ledger v2 document earn execution credit.
Adapter capability classifications are deliberately excluded from scoring.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ..analysis.crosshost_evidence import (
    ALL_USABLE_EXACT_RECOVERY_CLAIM,
    CLAIM_LEDGER_SCHEMA_VERSION,
    PACKET_PATH_EXECUTED_CLAIM,
)
from ..model import AnalysisPopulation, CarrierClass, Mechanism
from .requirements import (
    HARD_REQUIREMENTS,
    REQUIREMENTS,
    THREAT_MODEL,
    RequirementStatus,
    blocks_deployability,
)

_S = RequirementStatus


@dataclass(frozen=True)
class RequirementAssessment:
    requirement_id: str
    status: RequirementStatus
    rationale: str

    def to_json(self) -> dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "status": self.status.value,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class MechanismScorecard:
    mechanism_id: str
    carrier_class: str
    assessments: tuple[RequirementAssessment, ...]
    deployable: bool
    blocking_hard: tuple[str, ...]
    hard_passed: int
    hard_partial: int

    def to_json(self) -> dict[str, Any]:
        return {
            "mechanism_id": self.mechanism_id,
            "carrier_class": self.carrier_class,
            "deployable": self.deployable,
            "blocking_hard": list(self.blocking_hard),
            "hard_passed": self.hard_passed,
            "hard_partial": self.hard_partial,
            "assessments": [a.to_json() for a in self.assessments],
        }


def _assess(
    mechanism: Mechanism,
    claim_ledger: Mapping[str, Any] | None,
) -> dict[str, RequirementAssessment]:
    cls = mechanism.carrier_class
    exact_recovery = _claim_mechanism_ids(claim_ledger, ALL_USABLE_EXACT_RECOVERY_CLAIM)
    packet_path = _claim_mechanism_ids(claim_ledger, PACKET_PATH_EXECUTED_CLAIM)

    out: dict[str, RequirementAssessment] = {}

    def put(rid: str, status: RequirementStatus, why: str) -> None:
        out[rid] = RequirementAssessment(rid, status, why)

    put("H1", _S.PASSED, "Runs only in the authorized, isolated testbed per project posture.")

    if mechanism.id in packet_path:
        put(
            "H2",
            _S.PASSED,
            "Claim-ledger v2 records exact recovery across two hosts over AF_PACKET/VXLAN.",
        )
    else:
        put(
            "H2",
            _S.NOT_ASSESSED,
            "No claim-ledger v2 native packet-path execution exists for this mechanism.",
        )

    put(
        "H3",
        _S.NOT_ASSESSED,
        "The current cross-host ledger does not establish acceptance by a stock peer.",
    )

    if cls is CarrierClass.G:
        put(
            "H4",
            _S.NOT_APPLICABLE,
            "Subliminal crypto rides end-to-end inside the cryptographic field.",
        )
    else:
        put(
            "H4", _S.NOT_ASSESSED, "No middlebox matrix (NAT/firewall/proxy/resolver) has been run."
        )

    if mechanism.id in exact_recovery:
        put(
            "H5",
            _S.PARTIAL,
            "Repeated exact recovery exercises framing, but blind resynchronization is unmeasured.",
        )
    else:
        put(
            "H5",
            _S.NOT_ASSESSED,
            "No self-synchronizing framing; receiver cannot find message boundaries blind.",
        )

    if mechanism.id not in exact_recovery:
        put(
            "H6",
            _S.NOT_ASSESSED,
            "No claim-ledger v2 repeated exact-recovery evidence exists.",
        )
    else:
        put(
            "H6",
            _S.PARTIAL,
            "Exact recovery repeated across indexed runs; loss, reorder, and corruption remain untested.",
        )

    put(
        "H7",
        _S.PARTIAL,
        "The package now provides offer-bound TLS 1.3 transfer and encrypted carrier records; "
        "the cross-host ledger predates per-mechanism authenticated-transfer runs.",
    )
    put(
        "H8",
        _S.NOT_ASSESSED,
        "Indistinguishability under an active channel is not measured per technique.",
    )
    put("H9", _S.NOT_ASSESSED, "Fail-safe behaviour and deniability are not addressed.")
    if mechanism.id in packet_path:
        put(
            "H10",
            _S.PARTIAL,
            "Two-host packet execution exists, but it does not jointly exercise all H2-H8 gates.",
        )
    else:
        put("H10", _S.NOT_ASSESSED, "No native packet-path multi-host integration evidence exists.")

    for soft in ("S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9"):
        out.setdefault(soft, RequirementAssessment(soft, _S.NOT_ASSESSED, "Not yet evaluated."))
    out["S6"] = (
        RequirementAssessment(
            "S6", _S.NOT_APPLICABLE, "End-to-end inside the crypto field; no path to traverse."
        )
        if cls is CarrierClass.G
        else out["S6"]
    )
    put(
        "S10",
        _S.PARTIAL,
        "Spec quote and catalog metadata documented; deployment/scrub notes incomplete.",
    )
    return out


def score_mechanism(
    mechanism: Mechanism,
    *,
    claim_ledger: Mapping[str, Any] | None = None,
) -> MechanismScorecard:
    _validate_claim_ledger(claim_ledger)
    assessed = _assess(mechanism, claim_ledger)
    ordered = tuple(assessed[req.id] for req in REQUIREMENTS)

    blocking: list[str] = []
    hard_passed = hard_partial = 0
    for req in HARD_REQUIREMENTS:
        status = assessed[req.id].status
        if not req.applies_to(mechanism.carrier_class):
            continue
        if status is _S.PASSED:
            hard_passed += 1
        elif status is _S.PARTIAL:
            hard_partial += 1
        if blocks_deployability(status):
            blocking.append(req.id)

    return MechanismScorecard(
        mechanism_id=mechanism.id,
        carrier_class=mechanism.carrier_class.value,
        assessments=ordered,
        deployable=not blocking,
        blocking_hard=tuple(blocking),
        hard_passed=hard_passed,
        hard_partial=hard_partial,
    )


@dataclass(frozen=True)
class ScorecardReport:
    threat_model: str
    mechanism_count: int
    deployable_count: int
    hard_pass_counts: dict[str, int]
    status_counts: dict[str, dict[str, int]]
    ranked_requirement_ids: tuple[str, ...]
    evidence_source: str
    closest: tuple[MechanismScorecard, ...]
    cards: tuple[MechanismScorecard, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "threat_model": self.threat_model,
            "mechanism_count": self.mechanism_count,
            "deployable_count": self.deployable_count,
            "hard_pass_counts": self.hard_pass_counts,
            "status_counts": self.status_counts,
            "ranked_requirement_ids": list(self.ranked_requirement_ids),
            "evidence_source": self.evidence_source,
            "closest_to_deployable": [c.mechanism_id for c in self.closest],
            "mechanisms": [c.to_json() for c in self.cards],
        }


def build_scorecard(
    mechanisms: Sequence[Mechanism],
    *,
    shortlist: int = 10,
    claim_ledger: Mapping[str, Any] | None = None,
) -> ScorecardReport:
    _validate_claim_ledger(claim_ledger)
    usable = [
        mechanism
        for mechanism in mechanisms
        if mechanism.is_usable_channel
        and mechanism.analysis_population is AnalysisPopulation.PRIMARY_RFC_CARRIER
    ]
    cards = [score_mechanism(mechanism, claim_ledger=claim_ledger) for mechanism in usable]

    hard_pass_counts = {req.id: 0 for req in HARD_REQUIREMENTS}
    status_counts: dict[str, dict[str, int]] = {
        req.id: {s.value: 0 for s in RequirementStatus} for req in REQUIREMENTS
    }
    for card in cards:
        for assessment in card.assessments:
            status_counts[assessment.requirement_id][assessment.status.value] += 1
    for req in HARD_REQUIREMENTS:
        hard_pass_counts[req.id] = status_counts[req.id][RequirementStatus.PASSED.value]

    ranked_requirement_ids = tuple(
        requirement.id
        for requirement in HARD_REQUIREMENTS
        if _is_discriminating_requirement(cards, requirement.id)
    )
    ranked = sorted(
        cards,
        key=lambda card: _ranking_key(card, ranked_requirement_ids),
        reverse=True,
    )
    return ScorecardReport(
        threat_model=THREAT_MODEL,
        mechanism_count=len(cards),
        deployable_count=sum(1 for c in cards if c.deployable),
        hard_pass_counts=hard_pass_counts,
        status_counts=status_counts,
        ranked_requirement_ids=ranked_requirement_ids,
        evidence_source=(
            CLAIM_LEDGER_SCHEMA_VERSION if claim_ledger is not None else "no_claim_ledger"
        ),
        closest=tuple(ranked[:shortlist]),
        cards=tuple(cards),
    )


_STATUS_GLYPH = {
    RequirementStatus.PASSED.value: "pass",
    RequirementStatus.PARTIAL.value: "part",
    RequirementStatus.FAILED.value: "FAIL",
    RequirementStatus.NOT_ASSESSED.value: "--",
    RequirementStatus.NOT_APPLICABLE.value: "n/a",
}


def scorecard_markdown(report: ScorecardReport) -> str:
    """Render the scorecard as Markdown for the public docs tree."""
    lines: list[str] = [
        "# Technique deployment-readiness scorecard",
        "",
        "<!-- Generated by celatim.assurance.scorecard; do not edit by hand. -->",
        "",
        f"Threat model: **{report.threat_model}** (nation-state-class observer; "
        "indistinguishability and deniability are hard gates).",
        "",
        f"Usable mechanisms: **{report.mechanism_count}** · "
        f"**Deployable today: {report.deployable_count}**.",
        "",
        "A mechanism is *deployable* only when every applicable hard requirement is `passed`. "
        "A carrier round-trip earns `partial` on the framing/parser requirements it touches and "
        "nothing more; requirements with no artifact yet are `not_assessed`, which still blocks.",
        "",
        "## Hard-requirement coverage across all mechanisms",
        "",
        "| Req | Requirement | passed | partial | failed | not-assessed | n/a |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for req in HARD_REQUIREMENTS:
        counts = report.status_counts[req.id]
        lines.append(
            f"| {req.id} | {req.title} | {counts['passed']} | {counts['partial']} | "
            f"{counts['failed']} | {counts['not_assessed']} | {counts['not_applicable']} |"
        )
    lines += [
        "",
        "## Closest to deployable",
        "",
        "Ranking uses only hard requirements with differing execution-evidence status: "
        + (", ".join(report.ranked_requirement_ids) or "none")
        + ". Universal posture and applicability fields do not influence ordering.",
        "",
        "| Mechanism | Class | hard passed | hard partial | blocking hard requirements |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    for card in report.closest:
        lines.append(
            f"| `{card.mechanism_id}` | {card.carrier_class} | {card.hard_passed} | "
            f"{card.hard_partial} | {', '.join(card.blocking_hard)} |"
        )
    lines += [
        "",
        "## Requirement definitions",
        "",
        "| Req | Kind | Pass criterion |",
        "| --- | --- | --- |",
    ]
    for req in REQUIREMENTS:
        lines.append(f"| {req.id} | {req.kind.value} | {req.summary} |")
    lines.append("")
    return "\n".join(lines)


def _validate_claim_ledger(claim_ledger: Mapping[str, Any] | None) -> None:
    if (
        claim_ledger is not None
        and claim_ledger.get("schema_version") != CLAIM_LEDGER_SCHEMA_VERSION
    ):
        raise ValueError("scorecard requires a celatim.claim_ledger.v2 document")


def _claim_mechanism_ids(
    claim_ledger: Mapping[str, Any] | None,
    claim_id: str,
) -> frozenset[str]:
    if claim_ledger is None:
        return frozenset()
    claims = claim_ledger.get("claims")
    if not isinstance(claims, Sequence) or isinstance(claims, str | bytes):
        return frozenset()
    for claim in claims:
        if isinstance(claim, Mapping) and claim.get("id") == claim_id:
            values = claim.get("mechanism_ids")
            if isinstance(values, Sequence) and not isinstance(values, str | bytes):
                return frozenset(value for value in values if isinstance(value, str))
    return frozenset()


def _ranking_key(
    card: MechanismScorecard,
    requirement_ids: Sequence[str],
) -> tuple[int, int, int]:
    statuses = {assessment.requirement_id: assessment.status for assessment in card.assessments}
    passed = sum(statuses[requirement_id] is _S.PASSED for requirement_id in requirement_ids)
    partial = sum(statuses[requirement_id] is _S.PARTIAL for requirement_id in requirement_ids)
    failed = sum(statuses[requirement_id] is _S.FAILED for requirement_id in requirement_ids)
    return passed, partial, -failed


def _is_discriminating_requirement(
    cards: Sequence[MechanismScorecard],
    requirement_id: str,
) -> bool:
    statuses = {
        next(
            assessment.status
            for assessment in card.assessments
            if assessment.requirement_id == requirement_id
        )
        for card in cards
    }
    evidence_statuses = {_S.PASSED, _S.PARTIAL, _S.FAILED}
    return len(statuses) > 1 and bool(statuses & evidence_statuses)


def scorecard_matrix_markdown(report: ScorecardReport) -> str:
    """Render the full per-mechanism status matrix (one row per mechanism)."""
    header = "| Mechanism | Class | " + " | ".join(r.id for r in REQUIREMENTS) + " | deployable |"
    sep = "| --- | --- | " + " | ".join("---" for _ in REQUIREMENTS) + " | --- |"
    lines = [header, sep]
    for card in report.cards:
        status_by_id = {a.requirement_id: a.status.value for a in card.assessments}
        cells = " | ".join(_STATUS_GLYPH[status_by_id[r.id]] for r in REQUIREMENTS)
        lines.append(
            f"| `{card.mechanism_id}` | {card.carrier_class} | {cells} | "
            f"{'yes' if card.deployable else 'no'} |"
        )
    return "\n".join(lines)


__all__ = [
    "MechanismScorecard",
    "RequirementAssessment",
    "ScorecardReport",
    "build_scorecard",
    "score_mechanism",
    "scorecard_markdown",
    "scorecard_matrix_markdown",
]
