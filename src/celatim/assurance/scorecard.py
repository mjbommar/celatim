"""Score each mechanism against the deployment-readiness requirements.

This is deliberately conservative: a requirement is only credited above ``NOT_ASSESSED``
when an artifact in the repository actually demonstrates it. Carrier round-trips (the
"substantiated" tiers) earn ``PARTIAL`` on the framing/parser requirements they touch and
nothing more. Middlebox survival, indistinguishability, deniability, and multi-host
integration have no artifacts yet, so they sit at ``NOT_ASSESSED`` for every mechanism --
which is the honest state, and the reason the deployable count is zero. As real
cross-host/middlebox tests land (see the s0-s7 testbed), their results raise these cells.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from ..adapter import AdapterCapability, adapter_for
from ..model import CarrierClass, Mechanism
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


def _assess(mechanism: Mechanism) -> dict[str, RequirementAssessment]:
    adapter = adapter_for(mechanism)
    caps = adapter.capabilities
    cls = mechanism.carrier_class

    def has(cap: AdapterCapability) -> bool:
        return cap in caps

    out: dict[str, RequirementAssessment] = {}

    def put(rid: str, status: RequirementStatus, why: str) -> None:
        out[rid] = RequirementAssessment(rid, status, why)

    put("H1", _S.PASSED, "Runs only in the authorized, isolated testbed per project posture.")

    if has(AdapterCapability.PACKET_PATH_TEMPLATE):
        put(
            "H2",
            _S.PARTIAL,
            "Raw frames can cross a wire (AF_PACKET), but not yet to a stock peer.",
        )
    else:
        put(
            "H2",
            _S.NOT_ASSESSED,
            "Only an in-process round-trip exists; no cross-host transmission.",
        )

    if has(AdapterCapability.DAEMON_PATH) or has(AdapterCapability.CRYPTO_TRANSCRIPT):
        put(
            "H3",
            _S.PARTIAL,
            "A real daemon/crypto verifier is in the loop; stock-peer survival unconfirmed.",
        )
    else:
        put(
            "H3",
            _S.NOT_ASSESSED,
            "The receiver is our own decoder, not a stock protocol implementation.",
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

    if has(AdapterCapability.PARSER_VALIDATED):
        put(
            "H5",
            _S.PARTIAL,
            "A second parser recovers the field, but framing still needs an out-of-band length.",
        )
    else:
        put(
            "H5",
            _S.NOT_ASSESSED,
            "No self-synchronizing framing; receiver cannot find message boundaries blind.",
        )

    if cls is CarrierClass.F:
        put(
            "H6",
            _S.NOT_ASSESSED,
            "Timing fidelity is probabilistic; no SNR/loss measurement exists.",
        )
    elif has(AdapterCapability.CODEC_SESSION):
        put(
            "H6",
            _S.PARTIAL,
            "Sequencing/ARQ plumbing exists but is unvalidated under injected loss/reorder.",
        )
    else:
        put("H6", _S.NOT_ASSESSED, "No reliability layer demonstrated.")

    put(
        "H7",
        _S.FAILED,
        "Envelope carries an integrity hash only; no AEAD or forward secrecy on the payload.",
    )
    put(
        "H8",
        _S.NOT_ASSESSED,
        "Indistinguishability under an active channel is not measured per technique.",
    )
    put("H9", _S.NOT_ASSESSED, "Fail-safe behaviour and deniability are not addressed.")
    put("H10", _S.NOT_ASSESSED, "No multi-host integration test exercising H2-H8 exists yet.")

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


def score_mechanism(mechanism: Mechanism) -> MechanismScorecard:
    assessed = _assess(mechanism)
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
    closest: tuple[MechanismScorecard, ...]
    cards: tuple[MechanismScorecard, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "threat_model": self.threat_model,
            "mechanism_count": self.mechanism_count,
            "deployable_count": self.deployable_count,
            "hard_pass_counts": self.hard_pass_counts,
            "status_counts": self.status_counts,
            "closest_to_deployable": [c.mechanism_id for c in self.closest],
            "mechanisms": [c.to_json() for c in self.cards],
        }


def build_scorecard(mechanisms: Sequence[Mechanism], *, shortlist: int = 10) -> ScorecardReport:
    usable = [m for m in mechanisms if m.is_usable_channel]
    cards = [score_mechanism(m) for m in usable]

    hard_pass_counts = {req.id: 0 for req in HARD_REQUIREMENTS}
    status_counts: dict[str, dict[str, int]] = {
        req.id: {s.value: 0 for s in RequirementStatus} for req in REQUIREMENTS
    }
    for card in cards:
        for assessment in card.assessments:
            status_counts[assessment.requirement_id][assessment.status.value] += 1
    for req in HARD_REQUIREMENTS:
        hard_pass_counts[req.id] = status_counts[req.id][RequirementStatus.PASSED.value]

    ranked = sorted(
        cards, key=lambda c: (c.hard_passed, c.hard_partial, -len(c.blocking_hard)), reverse=True
    )
    return ScorecardReport(
        threat_model=THREAT_MODEL,
        mechanism_count=len(cards),
        deployable_count=sum(1 for c in cards if c.deployable),
        hard_pass_counts=hard_pass_counts,
        status_counts=status_counts,
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
        "Ranked by hard requirements passed, then partial. Every one still has blocking gates.",
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
