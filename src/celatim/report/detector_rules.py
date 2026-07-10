"""Generate public-safe detector rule artifacts from catalog locators."""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..detect import (
    STATEFUL_DETECTOR_CLAIM_STATUS,
    StatefulDetectorPlan,
    bpf_filter,
    iptables_u32_rule,
    nftables_rule,
    stateful_detector_plans,
)
from ..model import Detectability, FalsePositive, Mechanism

DETECTOR_RULES_SCHEMA_VERSION = "celatim.detector_rules.v1"
DETECTOR_RULES_MARKDOWN_FILENAME = "detector-rules.md"
NFTABLES_RULES_FILENAME = "detector-rules.nft"
IPTABLES_U32_RULES_FILENAME = "detector-rules.iptables-u32"
BPF_FILTERS_FILENAME = "detector-rules.bpf"
STATEFUL_PLAN_MARKDOWN_FILENAME = "detector-stateful-plan.md"
STATEFUL_ZEEK_FILENAME = "detector-stateful.zeek"
STATEFUL_SURICATA_FILENAME = "detector-stateful.suricata.rules"


@dataclass(frozen=True)
class DetectorRuleArtifact:
    filename: str
    rule_format: str
    title: str
    content: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content.encode()).hexdigest()

    @property
    def size_bytes(self) -> int:
        return len(self.content.encode())

    def to_json(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "rule_format": self.rule_format,
            "title": self.title,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


def detector_rule_artifacts(mechanisms: Iterable[Mechanism]) -> tuple[DetectorRuleArtifact, ...]:
    mechs = tuple(mechanisms)
    rule_mechanisms = _rule_mechanisms(mechs)
    stateful_plans = stateful_detector_plans(mechs)
    return (
        DetectorRuleArtifact(
            filename=DETECTOR_RULES_MARKDOWN_FILENAME,
            rule_format="markdown",
            title="Detector rule appendix",
            content=detector_rules_markdown(mechs),
        ),
        DetectorRuleArtifact(
            filename=NFTABLES_RULES_FILENAME,
            rule_format="nftables",
            title="nftables stateless detector rules",
            content=_rules_file(
                rule_mechanisms,
                rule_format="nftables",
                emitter=nftables_rule,
                scope_note="nftables raw-payload rules; attach to a suitable inet/ip hook.",
            ),
        ),
        DetectorRuleArtifact(
            filename=IPTABLES_U32_RULES_FILENAME,
            rule_format="iptables-u32",
            title="iptables u32 stateless detector match fragments",
            content=_rules_file(
                rule_mechanisms,
                rule_format="iptables-u32",
                emitter=iptables_u32_rule,
                scope_note=(
                    "iptables u32 match fragments; append to a policy chain as "
                    "`iptables -A CHAIN <fragment>`."
                ),
            ),
        ),
        DetectorRuleArtifact(
            filename=BPF_FILTERS_FILENAME,
            rule_format="bpf",
            title="libpcap BPF stateless detector filters",
            content=_rules_file(
                rule_mechanisms,
                rule_format="bpf",
                emitter=bpf_filter,
                scope_note="libpcap/tcpdump filter expressions; execute against traces for FP claims.",
            ),
        ),
        DetectorRuleArtifact(
            filename=STATEFUL_PLAN_MARKDOWN_FILENAME,
            rule_format="stateful-plan",
            title="Stateful detector plan",
            content=stateful_detector_plan_markdown(mechs),
        ),
        DetectorRuleArtifact(
            filename=STATEFUL_ZEEK_FILENAME,
            rule_format="zeek",
            title="Zeek stateful detector plan",
            content=zeek_stateful_detector_script(stateful_plans),
        ),
        DetectorRuleArtifact(
            filename=STATEFUL_SURICATA_FILENAME,
            rule_format="suricata",
            title="Suricata stateful detector templates",
            content=suricata_stateful_detector_rules(stateful_plans),
        ),
    )


def detector_rule_manifest(
    mechanisms: Iterable[Mechanism],
    *,
    output_dir: Path | str | None = None,
) -> dict[str, Any]:
    mechs = tuple(mechanisms)
    artifacts = detector_rule_artifacts(mechs)
    coverage = Counter(mechanism.detectability for mechanism in mechs)
    return {
        "schema_version": DETECTOR_RULES_SCHEMA_VERSION,
        "artifact_count": len(artifacts),
        "rule_mechanism_count": len(_rule_mechanisms(mechs)),
        "stateful_plan_mechanism_count": len(stateful_detector_plans(mechs)),
        "output_dir": None if output_dir is None else str(output_dir),
        "claim_status": "generated_not_executed_no_false_positive_estimate",
        "stateful_claim_status": STATEFUL_DETECTOR_CLAIM_STATUS,
        "coverage": {
            detectability.value: coverage[detectability] for detectability in Detectability
        },
        "artifacts": [artifact.to_json() for artifact in artifacts],
    }


def detector_rules_markdown(mechanisms: Iterable[Mechanism]) -> str:
    mechs = tuple(sorted(mechanisms, key=lambda mechanism: mechanism.id))
    rule_mechanisms = _rule_mechanisms(mechs)
    coverage = Counter(mechanism.detectability for mechanism in mechs)
    rows = [
        "# Detector Rule Appendix",
        "",
        "Generated from `measurement/data/mechanisms.jsonl`. These are public-safe",
        "detector artifacts derived from catalog locators and predicates. They are",
        "not false-positive estimates and are not independent detector execution",
        "unless a separate evidence record reports tool execution over a trace.",
        "",
        "Claim status: `generated_not_executed_no_false_positive_estimate`.",
        "",
        "## Coverage",
        "",
        "| Detectability | Catalog count |",
        "|---|---:|",
    ]
    rows.extend(f"| `{item.value}` | {coverage[item]} |" for item in Detectability)
    rows.extend(
        [
            "",
            "## Stateless Generated Rules",
            "",
            "| Mechanism | Protocol | Predicate | Disposition | nftables | iptables u32 | BPF |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    if not rule_mechanisms:
        rows.append("| -- | -- | -- | -- | -- | -- | -- |")
    else:
        rows.extend(_markdown_rule_row(mechanism) for mechanism in rule_mechanisms)
    rows.append("")
    return "\n".join(rows)


def stateful_detector_plan_markdown(mechanisms: Iterable[Mechanism]) -> str:
    plans = stateful_detector_plans(tuple(mechanisms))
    rows = [
        "# Stateful Detector Plan",
        "",
        "Generated from `measurement/data/mechanisms.jsonl`. These rows need protocol",
        "parsing, flow state, entropy checks, presence checks, timing/count analysis, or",
        "benign-trace baselines. They are generated detector plans, not executed detector",
        "results and not false-positive estimates.",
        "",
        f"Claim status: `{STATEFUL_DETECTOR_CLAIM_STATUS}`.",
        "",
        "| Mechanism | Protocol | Class | Detectability | Detector kind | Predicate | False-positive posture | Annotation source | Disposition | Baseline required | Zeek hook | Suricata strategy | Scrub strategy |",
        "|---|---|---:|---|---|---|---|---|---|---:|---|---|---|",
    ]
    if not plans:
        rows.append("| -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- |")
    else:
        rows.extend(_stateful_plan_row(plan) for plan in plans)
    rows.append("")
    return "\n".join(rows)


def zeek_stateful_detector_script(plans: Iterable[StatefulDetectorPlan]) -> str:
    plan_rows = tuple(plans)
    rows = [
        "# Generated by celatim.report.detector_rules.",
        "# Source: measurement/data/mechanisms.jsonl.",
        f"# Claim status: {STATEFUL_DETECTOR_CLAIM_STATUS}.",
        "# This Zeek policy records a generated detector plan; parser hooks below are",
        "# reviewer-facing scaffolding until executed evidence reports tool output.",
        "",
        "@load base/frameworks/reporter",
        "",
        "module CelatimCovert;",
        "",
        "export {",
        "\ttype DetectorPlan: record {",
        "\t\tprotocol: string;",
        "\t\tcarrier_class: string;",
        "\t\tkind: string;",
        "\t\tpredicate: string;",
        "\t\tfalse_positive_posture: string;",
        "\t\tannotation_source: string;",
        "\t\tdisposition: string;",
        "\t\tbaseline_required: bool;",
        "\t\tscrub_strategy: string;",
        "\t};",
        "",
        "\tconst detector_plan: table[string] of DetectorPlan = {",
    ]
    for plan in plan_rows:
        rows.append(
            "\t\t"
            f'["{_zeek_escape(plan.mechanism_id)}"] = '
            f'[$protocol="{_zeek_escape(plan.protocol)}", '
            f'$carrier_class="{plan.carrier_class.value}", '
            f'$kind="{plan.detector_kind.value}", '
            f'$predicate="{plan.predicate.value}", '
            f'$false_positive_posture="{plan.false_positive_posture.value}", '
            f'$annotation_source="{plan.annotation_source.value}", '
            f'$disposition="{plan.disposition}", '
            f"$baseline_required={'T' if plan.baseline_required else 'F'}, "
            f'$scrub_strategy="{_zeek_escape(plan.scrub_strategy)}"],'
        )
    rows.extend(
        [
            "\t} &redef;",
            "}",
            "",
            "event zeek_init()",
            "\t{",
            '\tReporter::info(fmt("celatim generated stateful detector plans loaded: %d", |detector_plan|));',
            "\t}",
            "",
            "# Hook guidance by mechanism follows. Implement parser-specific extraction",
            "# and baseline storage before enabling alerts from these plans.",
            "",
        ]
    )
    for plan in plan_rows:
        rows.append(
            f"# {plan.mechanism_id}: {plan.zeek_hook}; "
            f"{plan.detector_kind.value}; {plan.disposition} after baseline validation."
        )
    rows.append("")
    return "\n".join(rows)


def suricata_stateful_detector_rules(plans: Iterable[StatefulDetectorPlan]) -> str:
    rows = [
        "# Generated by celatim.report.detector_rules.",
        "# Source: measurement/data/mechanisms.jsonl.",
        f"# Claim status: {STATEFUL_DETECTOR_CLAIM_STATUS}.",
        "# Rules are disabled templates. Add parser keywords, Lua, datasets, or",
        "# threshold/baseline logic before enabling in Suricata.",
        "",
    ]
    for sid_offset, plan in enumerate(plans, start=1):
        action = "alert" if plan.disposition == "alert" else "pass"
        proto = _suricata_proto(plan.protocol)
        sid = 9_300_000 + sid_offset
        rows.extend(
            [
                f"# {plan.mechanism_id}: {plan.suricata_strategy}",
                (
                    f"# {action} {proto} any any -> any any "
                    f'(msg:"CELATIM {plan.mechanism_id} {plan.detector_kind.value}"; '
                    f"metadata: celatim_kind {plan.detector_kind.value}, "
                    f"celatim_predicate {plan.predicate.value}, "
                    f"celatim_false_positive {plan.false_positive_posture.value}, "
                    f"celatim_annotation_source {plan.annotation_source.value}, "
                    f"celatim_claim_status {STATEFUL_DETECTOR_CLAIM_STATUS}; "
                    f"sid:{sid}; rev:1;)"
                ),
                "",
            ]
        )
    if len(rows) == 6:
        rows.append("# No stateful detector plans available.")
        rows.append("")
    return "\n".join(rows)


def write_detector_rule_artifacts(
    mechanisms: Iterable[Mechanism],
    output_dir: Path | str,
) -> tuple[Path, ...]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for artifact in detector_rule_artifacts(mechanisms):
        path = output / artifact.filename
        path.write_text(artifact.content)
        paths.append(path)
    return tuple(paths)


def _rule_mechanisms(mechanisms: Iterable[Mechanism]) -> tuple[Mechanism, ...]:
    rows: list[Mechanism] = []
    for mechanism in sorted(mechanisms, key=lambda item: item.id):
        if mechanism.detectability is not Detectability.STATELESS_FILTER:
            continue
        if _optional_rule(nftables_rule, mechanism) is None:
            continue
        rows.append(mechanism)
    return tuple(rows)


def _markdown_rule_row(mechanism: Mechanism) -> str:
    predicate = mechanism.detect_predicate.value if mechanism.detect_predicate else "none"
    return (
        f"| `{mechanism.id}` | {_md(mechanism.protocol)} | `{predicate}` | "
        f"`{_disposition(mechanism)}` | {_rule_cell(nftables_rule, mechanism)} | "
        f"{_rule_cell(iptables_u32_rule, mechanism)} | {_rule_cell(bpf_filter, mechanism)} |"
    )


def _stateful_plan_row(plan: StatefulDetectorPlan) -> str:
    baseline = "yes" if plan.baseline_required else "no"
    return (
        f"| `{plan.mechanism_id}` | {_md(plan.protocol)} | {plan.carrier_class.value} | "
        f"`{plan.detectability.value}` | `{plan.detector_kind.value}` | "
        f"`{plan.predicate.value}` | `{plan.false_positive_posture.value}` | "
        f"`{plan.annotation_source.value}` | `{plan.disposition}` | {baseline} | "
        f"{_md(plan.zeek_hook)} | "
        f"{_md(plan.suricata_strategy)} | `{plan.scrub_strategy}` |"
    )


def _rule_cell(emitter: Callable[[Mechanism], str], mechanism: Mechanism) -> str:
    rule = _optional_rule(emitter, mechanism)
    if rule is None:
        return "--"
    return f"`{_md(rule)}`"


def _rules_file(
    mechanisms: Iterable[Mechanism],
    *,
    rule_format: str,
    emitter: Callable[[Mechanism], str],
    scope_note: str,
) -> str:
    rows = [
        "# Generated by celatim.report.detector_rules.",
        "# Source: measurement/data/mechanisms.jsonl.",
        "# Scope: supported stateless_filter catalog mechanisms only.",
        "# Claim status: generated_not_executed_no_false_positive_estimate.",
        f"# Format: {rule_format}.",
        f"# {scope_note}",
        "",
    ]
    emitted = 0
    for mechanism in mechanisms:
        rule = _optional_rule(emitter, mechanism)
        if rule is None:
            continue
        rows.extend(
            [
                f"# {mechanism.id}: {_md(mechanism.name)} ({', '.join(mechanism.rfcs)})",
                rule,
                "",
            ]
        )
        emitted += 1
    if emitted == 0:
        rows.append("# No rules available for this format.")
        rows.append("")
    return "\n".join(rows)


def _optional_rule(emitter: Callable[[Mechanism], str], mechanism: Mechanism) -> str | None:
    try:
        return emitter(mechanism)
    except ValueError:
        return None


def _disposition(mechanism: Mechanism) -> str:
    if mechanism.false_positive is None:
        return "log"
    if mechanism.false_positive is FalsePositive.BENIGN_COMMON:
        return "log"
    return "alert"


def _md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _zeek_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _suricata_proto(protocol: str) -> str:
    normalized = protocol.lower()
    if normalized in {"tcp", "http", "http/2", "http2", "tls", "ssh", "bgp"}:
        return "tcp"
    if normalized in {"udp", "dns", "quic", "dtls", "ntp", "dhcp", "coap", "stun"}:
        return "udp"
    if normalized in {"icmp", "icmpv6"}:
        return "icmp"
    return "ip"


__all__ = [
    "BPF_FILTERS_FILENAME",
    "DETECTOR_RULES_MARKDOWN_FILENAME",
    "DETECTOR_RULES_SCHEMA_VERSION",
    "IPTABLES_U32_RULES_FILENAME",
    "NFTABLES_RULES_FILENAME",
    "STATEFUL_PLAN_MARKDOWN_FILENAME",
    "STATEFUL_SURICATA_FILENAME",
    "STATEFUL_ZEEK_FILENAME",
    "DetectorRuleArtifact",
    "detector_rule_artifacts",
    "detector_rule_manifest",
    "detector_rules_markdown",
    "stateful_detector_plan_markdown",
    "suricata_stateful_detector_rules",
    "write_detector_rule_artifacts",
    "zeek_stateful_detector_script",
]
