"""Deployment-readiness scorecard: honest-by-construction requirement assessment."""

from __future__ import annotations

from pathlib import Path

from celatim.assurance import (
    HARD_REQUIREMENTS,
    REQUIREMENTS,
    SOFT_REQUIREMENTS,
    RequirementKind,
    RequirementStatus,
    build_scorecard,
    score_mechanism,
)
from celatim.catalog import load_mechanisms
from celatim.cli import session_main
from celatim.model import CarrierClass

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def _usable():
    return [m for m in load_mechanisms(DATA) if m.is_usable_channel]


def test_registry_has_ten_hard_and_ten_soft_with_h8_h9_hard():
    assert len(HARD_REQUIREMENTS) == 10
    assert len(SOFT_REQUIREMENTS) == 10
    assert len(REQUIREMENTS) == 20
    by_id = {r.id: r for r in REQUIREMENTS}
    # Surveilled-user calibration: indistinguishability and deniability are hard gates.
    assert by_id["H8"].kind is RequirementKind.HARD
    assert by_id["H9"].kind is RequirementKind.HARD


def test_h4_not_applicable_to_subliminal_crypto_class():
    by_id = {r.id: r for r in REQUIREMENTS}
    assert not by_id["H4"].applies_to(CarrierClass.G)
    assert by_id["H4"].applies_to(CarrierClass.A)


def test_every_usable_mechanism_scored_against_all_requirements():
    for mech in _usable():
        card = score_mechanism(mech)
        assert len(card.assessments) == len(REQUIREMENTS)
        assert {a.requirement_id for a in card.assessments} == {r.id for r in REQUIREMENTS}


def test_nothing_is_deployable_today_and_the_gap_is_explicit():
    report = build_scorecard(_usable())
    assert report.mechanism_count == 133
    # The honest floor: against the surveilled-user bar, no technique clears every hard gate.
    assert report.deployable_count == 0
    # The cells with no artifacts yet are unmet for *every* mechanism.
    for rid in ("H4", "H8", "H9", "H10"):
        assert report.hard_pass_counts[rid] == 0


def test_authenticated_transfer_layer_replaces_obsolete_hash_only_failure():
    card = score_mechanism(_usable()[0])
    h7 = next(a for a in card.assessments if a.requirement_id == "H7")
    assert h7.status is RequirementStatus.PARTIAL
    assert "TLS 1.3" in h7.rationale


def test_claim_ledger_v2_drives_execution_credit_and_ranking():
    mechanism = _usable()[0]
    ledger = {
        "schema_version": "celatim.claim_ledger.v2",
        "claims": [
            {
                "id": "all_usable_binary_exact_recovery",
                "mechanism_ids": [mechanism.id],
            },
            {
                "id": "crosshost_afpacket_exact_recovery",
                "mechanism_ids": [mechanism.id],
            },
        ],
    }

    card = score_mechanism(mechanism, claim_ledger=ledger)
    statuses = {assessment.requirement_id: assessment.status for assessment in card.assessments}
    assert statuses["H2"] is RequirementStatus.PASSED
    assert statuses["H5"] is RequirementStatus.PARTIAL
    assert statuses["H6"] is RequirementStatus.PARTIAL
    assert statuses["H10"] is RequirementStatus.PARTIAL

    report = build_scorecard(_usable(), claim_ledger=ledger)
    assert report.evidence_source == "celatim.claim_ledger.v2"
    assert set(report.ranked_requirement_ids) == {"H2", "H5", "H6", "H10"}
    assert report.closest[0].mechanism_id == mechanism.id


def test_closest_to_deployable_shortlist_is_ranked_and_nonempty():
    report = build_scorecard(_usable(), shortlist=5)
    assert 1 <= len(report.closest) <= 5
    # Ranked by hard-passed then hard-partial, descending.
    scores = [(c.hard_passed, c.hard_partial) for c in report.closest]
    assert scores == sorted(scores, reverse=True)
    # Even the closest still has blocking hard requirements (nothing is done).
    assert all(c.blocking_hard for c in report.closest)


def test_cli_scorecard_generate_markdown(tmp_path):
    out = tmp_path / "scorecard.md"
    rc = session_main(["scorecard", "generate", "--output", str(out)])
    assert rc == 0
    text = out.read_text()
    assert "Deployable today: 0" in text
    assert "Self-synchronizing framing" in text


def test_cli_scorecard_generate_json(tmp_path):
    import json

    out = tmp_path / "scorecard.json"
    rc = session_main(["scorecard", "generate", "--format", "json", "--output", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text())
    assert doc["deployable_count"] == 0
    assert doc["threat_model"] == "surveilled_user_censorship"
    assert len(doc["mechanisms"]) == doc["mechanism_count"]
