"""Deployment-readiness requirements for covert-channel techniques.

A carrier round-trip proves only that an encoder and decoder agree on a field layout.
Whether a technique *works for a person whose safety depends on it* is a much higher
bar. These requirements encode that bar, calibrated to the **surveilled-user /
censorship** threat model (a nation-state-class observer), in which indistinguishability
(H8) and deniability (H9) are hard gates rather than quality knobs.

Hard requirements gate deployability: a technique that fails any applicable hard
requirement is not deployable, regardless of how clean its carrier round-trip is. Soft
requirements grade quality and robustness. Nothing here is auto-satisfied -- a
requirement is only ``PASSED`` when an artifact demonstrates it (see ``scorecard``).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ..model import CarrierClass

THREAT_MODEL = "surveilled_user_censorship"


class RequirementKind(str, Enum):
    HARD = "hard"  # gating: fail any applicable one and the technique is not deployable
    SOFT = "soft"  # quality / robustness: graded, not gating


class RequirementStatus(str, Enum):
    PASSED = "passed"  # an artifact demonstrates the requirement is met
    PARTIAL = "partial"  # some evidence, but not the full criterion
    FAILED = "failed"  # demonstrated *not* met
    NOT_ASSESSED = "not_assessed"  # no artifact yet -- the honest default, blocks deployability
    NOT_APPLICABLE = "not_applicable"  # does not apply to this technique class


# Statuses that do NOT block a hard-requirement verdict.
_NON_BLOCKING = frozenset({RequirementStatus.PASSED, RequirementStatus.NOT_APPLICABLE})


@dataclass(frozen=True)
class Requirement:
    id: str
    title: str
    kind: RequirementKind
    summary: str  # the objective, testable pass criterion
    # Carrier classes for which this requirement does not apply.
    not_applicable_classes: frozenset[CarrierClass] = frozenset()

    def applies_to(self, carrier_class: CarrierClass) -> bool:
        return carrier_class not in self.not_applicable_classes


HARD_REQUIREMENTS: tuple[Requirement, ...] = (
    Requirement(
        "H1",
        "Authorized context",
        RequirementKind.HARD,
        "Documented authorization for the environment; development confined to an isolated testbed.",
    ),
    Requirement(
        "H2",
        "Real two-party transmission",
        RequirementKind.HARD,
        "Distinct sender and receiver processes on different hosts move the payload over a real "
        "network path with no shared in-process state.",
    ),
    Requirement(
        "H3",
        "Conformant-peer survival",
        RequirementKind.HARD,
        "The covert field is delivered intact when the receiver is a stock, unmodified protocol "
        "implementation -- not our own sniffer or decoder.",
    ),
    Requirement(
        "H4",
        "Middlebox survival",
        RequirementKind.HARD,
        "Payload survives the threat-model middleboxes (NAT, stateful firewall, TLS-terminating "
        "proxy, recursive resolver, normalizer) on the intended path.",
        # Class G (subliminal crypto) rides end-to-end inside the cryptographic field.
        not_applicable_classes=frozenset({CarrierClass.G}),
    ),
    Requirement(
        "H5",
        "Self-synchronizing framing",
        RequirementKind.HARD,
        "Receiver recovers length, order, and boundaries from the stream itself and demuxes from "
        "benign traffic, with zero out-of-band parameters.",
    ),
    Requirement(
        "H6",
        "Reliability under loss",
        RequirementKind.HARD,
        "Byte-exact delivery at a stated loss/reorder/duplication rate via sequencing and ARQ/FEC; "
        "corruption is detected, never silently delivered.",
    ),
    Requirement(
        "H7",
        "Payload security",
        RequirementKind.HARD,
        "Payload is AEAD-encrypted with authenticated framing and forward secrecy; the channel is "
        "assumed fully observed; replay and injection are rejected.",
    ),
    Requirement(
        "H8",
        "Indistinguishability / cover",
        RequirementKind.HARD,
        "A defender's best detector cannot beat a stated TPR at a fixed low FPR against a captured "
        "benign baseline; field values are drawn from the benign distribution.",
    ),
    Requirement(
        "H9",
        "Fail-safe and deniability",
        RequirementKind.HARD,
        "Detection or disruption deanonymizes neither endpoint and reveals no plaintext; abort "
        "leaves no recoverable artifact; the carrier is plausibly deniable.",
    ),
    Requirement(
        "H10",
        "Reproducible assurance",
        RequirementKind.HARD,
        "An automated (or documented-manual for privileged) multi-host integration test exercises "
        "H2-H8 and is wired into the test harness.",
    ),
)

SOFT_REQUIREMENTS: tuple[Requirement, ...] = (
    Requirement(
        "S1",
        "Measured goodput",
        RequirementKind.SOFT,
        "Throughput measured in bits/s under realistic conditions meets a use-case floor.",
    ),
    Requirement(
        "S2",
        "Stack/OS robustness",
        RequirementKind.SOFT,
        "Stable across protocol-stack versions, operating systems, and NIC offloads.",
    ),
    Requirement(
        "S3",
        "Bidirectional + rekey",
        RequirementKind.SOFT,
        "Bidirectional channel with session resumption and rekeying.",
    ),
    Requirement(
        "S4",
        "Rate adaptation",
        RequirementKind.SOFT,
        "Adapts rate/timing to stay under detection thresholds.",
    ),
    Requirement(
        "S5",
        "Carrier agility",
        RequirementKind.SOFT,
        "Rotates to another field or technique when one is scrubbed.",
    ),
    Requirement(
        "S6",
        "NAT traversal",
        RequirementKind.SOFT,
        "Path discovery, NAT traversal, and path-MTU adaptation.",
        frozenset({CarrierClass.G}),
    ),
    Requirement(
        "S7",
        "Key distribution",
        RequirementKind.SOFT,
        "A workable key-distribution and bootstrap story.",
    ),
    Requirement(
        "S8",
        "Operator observability",
        RequirementKind.SOFT,
        "Operator visibility into channel health without leaking to the adversary.",
    ),
    Requirement(
        "S9",
        "Graceful degradation",
        RequirementKind.SOFT,
        "Resumable partial delivery and graceful degradation under stress.",
    ),
    Requirement(
        "S10",
        "Documentation",
        RequirementKind.SOFT,
        "Documented threat model, deployment constraints, and known-scrub list.",
    ),
)

REQUIREMENTS: tuple[Requirement, ...] = HARD_REQUIREMENTS + SOFT_REQUIREMENTS

REQUIREMENTS_BY_ID: dict[str, Requirement] = {req.id: req for req in REQUIREMENTS}


def blocks_deployability(status: RequirementStatus) -> bool:
    """True if a hard requirement in this status prevents deployability."""
    return status not in _NON_BLOCKING


__all__ = [
    "HARD_REQUIREMENTS",
    "REQUIREMENTS",
    "REQUIREMENTS_BY_ID",
    "SOFT_REQUIREMENTS",
    "THREAT_MODEL",
    "Requirement",
    "RequirementKind",
    "RequirementStatus",
    "blocks_deployability",
]
