"""Generate LaTeX scale macros from self-contained survey sources."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from ..analysis.crosshost_evidence import (
    ALL_USABLE_EXACT_RECOVERY_CLAIM,
    ENVELOPE_EXECUTED_CLAIM,
    MESSAGE_CARRIER_EXECUTED_CLAIM,
    PACKET_PATH_EXECUTED_CLAIM,
    claim_count,
    load_claim_ledger,
)
from ..evidence import classify_evidence
from ..model import AnalysisPopulation, CarrierClass, Mechanism

SPEC_ACK_PATTERN = re.compile(r"\bcovert(?:\s+data)?\s+channel\b", re.IGNORECASE)
RFC_CORPUS_COUNT_PATTERN = re.compile(r"~\s*([0-9][0-9,]*)\s+documents")
CITED_RFC_COUNT_PATTERN = re.compile(r"\*\*([0-9][0-9,]*)\s+RFCs\*\*")


@dataclass(frozen=True)
class SurveyScaleMacros:
    catalog_total_count: int
    mechanism_count: int
    usable_mechanism_count: int
    negative_result_count: int
    ordinary_payload_comparison_count: int
    non_ietf_comparison_count: int
    carrier_class_count: int
    spec_acknowledged_rfc_count: int
    spec_acknowledged_rfcs: tuple[str, ...]
    rfc_corpus_swept_count: int
    cited_rfc_count: int
    wiki_page_count: int
    substantiated_count: int
    real_pdu_count: int
    real_daemon_or_crypto_count: int
    timing_scheme_count: int
    codec_roundtrip_count: int
    structural_residual_count: int
    exact_recovery_executed_count: int = 0
    packet_path_executed_count: int = 0
    envelope_executed_count: int = 0
    message_carrier_executed_count: int = 0

    def to_json(self) -> dict[str, object]:
        return {
            "catalog_total_count": self.catalog_total_count,
            "mechanism_count": self.mechanism_count,
            "usable_mechanism_count": self.usable_mechanism_count,
            "negative_result_count": self.negative_result_count,
            "ordinary_payload_comparison_count": self.ordinary_payload_comparison_count,
            "non_ietf_comparison_count": self.non_ietf_comparison_count,
            "carrier_class_count": self.carrier_class_count,
            "spec_acknowledged_rfc_count": self.spec_acknowledged_rfc_count,
            "spec_acknowledged_rfcs": list(self.spec_acknowledged_rfcs),
            "rfc_corpus_swept_count": self.rfc_corpus_swept_count,
            "cited_rfc_count": self.cited_rfc_count,
            "wiki_page_count": self.wiki_page_count,
            "substantiated_count": self.substantiated_count,
            "real_pdu_count": self.real_pdu_count,
            "real_daemon_or_crypto_count": self.real_daemon_or_crypto_count,
            "timing_scheme_count": self.timing_scheme_count,
            "codec_roundtrip_count": self.codec_roundtrip_count,
            "structural_residual_count": self.structural_residual_count,
            "exact_recovery_executed_count": self.exact_recovery_executed_count,
            "packet_path_executed_count": self.packet_path_executed_count,
            "envelope_executed_count": self.envelope_executed_count,
            "message_carrier_executed_count": self.message_carrier_executed_count,
        }


def survey_scale_macros(
    mechanisms: Iterable[Mechanism],
    *,
    rfc_corpus_swept_count: int,
    cited_rfc_count: int,
    wiki_page_count: int,
    claim_ledger: Path | str | dict[str, object] | None = None,
) -> SurveyScaleMacros:
    catalog = tuple(mechanisms)
    mechs = tuple(
        mechanism
        for mechanism in catalog
        if mechanism.analysis_population is AnalysisPopulation.PRIMARY_RFC_CARRIER
    )
    usable = tuple(mechanism for mechanism in mechs if mechanism.is_usable_channel)
    ordinary_payload = tuple(
        mechanism
        for mechanism in catalog
        if mechanism.analysis_population is AnalysisPopulation.COMPARISON_ORDINARY_PAYLOAD
    )
    non_ietf = tuple(
        mechanism
        for mechanism in catalog
        if mechanism.analysis_population is AnalysisPopulation.COMPARISON_NON_IETF
    )
    buckets = [classify_evidence(mechanism).bucket.value for mechanism in usable]
    ledger = claim_ledger if isinstance(claim_ledger, dict) else load_claim_ledger(claim_ledger)
    spec_ack_rfcs = tuple(
        sorted(
            {
                rfc
                for mechanism in mechs
                if SPEC_ACK_PATTERN.search(mechanism.spec_quote)
                for rfc in mechanism.rfcs
            },
            key=_rfc_sort_key,
        )
    )
    return SurveyScaleMacros(
        catalog_total_count=len(catalog),
        mechanism_count=len(mechs),
        usable_mechanism_count=sum(1 for mechanism in mechs if mechanism.is_usable_channel),
        negative_result_count=sum(1 for mechanism in mechs if mechanism.negative_result),
        ordinary_payload_comparison_count=len(ordinary_payload),
        non_ietf_comparison_count=len(non_ietf),
        carrier_class_count=len(CarrierClass),
        spec_acknowledged_rfc_count=len(spec_ack_rfcs),
        spec_acknowledged_rfcs=spec_ack_rfcs,
        rfc_corpus_swept_count=rfc_corpus_swept_count,
        cited_rfc_count=cited_rfc_count,
        wiki_page_count=wiki_page_count,
        substantiated_count=sum(1 for b in buckets if b != "offset_represented_zero_blob"),
        real_pdu_count=buckets.count("real_pdu_packet_path"),
        real_daemon_or_crypto_count=buckets.count("real_daemon_or_crypto_path"),
        timing_scheme_count=buckets.count("timing_scheme"),
        codec_roundtrip_count=buckets.count("codec_roundtrip"),
        structural_residual_count=buckets.count("offset_represented_zero_blob"),
        exact_recovery_executed_count=claim_count(ledger, ALL_USABLE_EXACT_RECOVERY_CLAIM),
        packet_path_executed_count=claim_count(ledger, PACKET_PATH_EXECUTED_CLAIM),
        envelope_executed_count=claim_count(ledger, ENVELOPE_EXECUTED_CLAIM),
        message_carrier_executed_count=claim_count(ledger, MESSAGE_CARRIER_EXECUTED_CLAIM),
    )


def survey_scale_macros_tex(macros: SurveyScaleMacros) -> str:
    """Render paper macros. Keep this generated file free of hand-edited counts."""
    return "\n".join(
        [
            "% Generated by celatim.report.macros; do not edit by hand.",
            "% Regenerate with `make paper-artifacts` from repository root.",
            f"% Spec-acknowledged RFCs: {', '.join(macros.spec_acknowledged_rfcs)}.",
            f"\\newcommand{{\\ncatalogtotal}}{{{_tex_int(macros.catalog_total_count)}\\xspace}}",
            f"\\newcommand{{\\nmech}}{{{_tex_int(macros.mechanism_count)}\\xspace}}",
            f"\\newcommand{{\\nusablemech}}{{{_tex_int(macros.usable_mechanism_count)}\\xspace}}",
            f"\\newcommand{{\\nnegativeresults}}{{{_tex_int(macros.negative_result_count)}\\xspace}}",
            f"\\newcommand{{\\nordinarypayloadcomparisons}}{{{_tex_int(macros.ordinary_payload_comparison_count)}\\xspace}}",
            f"\\newcommand{{\\nnonietfcomparisons}}{{{_tex_int(macros.non_ietf_comparison_count)}\\xspace}}",
            f"\\newcommand{{\\nrfcswept}}{{{_tex_int(macros.rfc_corpus_swept_count)}\\xspace}}",
            f"\\newcommand{{\\nrfcscited}}{{{_tex_int(macros.cited_rfc_count)}\\xspace}}",
            f"\\newcommand{{\\nwikipages}}{{{_tex_int(macros.wiki_page_count)}\\xspace}}",
            f"\\newcommand{{\\nspecack}}{{{_small_word(macros.spec_acknowledged_rfc_count)}\\xspace}}",
            f"\\newcommand{{\\nclasses}}{{{_small_word(macros.carrier_class_count)}\\xspace}}",
            f"\\newcommand{{\\nspecackrfcs}}{{{_tex_rfc_list(macros.spec_acknowledged_rfcs)}\\xspace}}",
            "% Capability-classification counts; these are adapter/evidence-tier classifications.",
            f"\\newcommand{{\\nsubstantiatedcapable}}{{{_tex_int(macros.substantiated_count)}\\xspace}}",
            f"\\newcommand{{\\nrealpducapable}}{{{_tex_int(macros.real_pdu_count)}\\xspace}}",
            f"\\newcommand{{\\nrealdaemoncapable}}{{{_tex_int(macros.real_daemon_or_crypto_count)}\\xspace}}",
            f"\\newcommand{{\\ntimingschemecapable}}{{{_tex_int(macros.timing_scheme_count)}\\xspace}}",
            f"\\newcommand{{\\ncodeconlycapable}}{{{_tex_int(macros.codec_roundtrip_count)}\\xspace}}",
            "% Backward-compatible aliases: capability classifications, not standalone run counts.",
            f"\\newcommand{{\\nsubstantiated}}{{{_tex_int(macros.substantiated_count)}\\xspace}}",
            f"\\newcommand{{\\nrealpdu}}{{{_tex_int(macros.real_pdu_count)}\\xspace}}",
            f"\\newcommand{{\\nrealdaemon}}{{{_tex_int(macros.real_daemon_or_crypto_count)}\\xspace}}",
            f"\\newcommand{{\\ntimingscheme}}{{{_tex_int(macros.timing_scheme_count)}\\xspace}}",
            f"\\newcommand{{\\ncodeconly}}{{{_tex_int(macros.codec_roundtrip_count)}\\xspace}}",
            f"\\newcommand{{\\nstructuralresidual}}{{{_tex_int(macros.structural_residual_count)}\\xspace}}",
            "% Run-backed counts from the claim ledger. Zero means no ledger was supplied.",
            f"\\newcommand{{\\nexactrecoveryexecuted}}{{{_tex_int(macros.exact_recovery_executed_count)}\\xspace}}",
            f"\\newcommand{{\\npacketpathexecuted}}{{{_tex_int(macros.packet_path_executed_count)}\\xspace}}",
            f"\\newcommand{{\\nenvelopeexecuted}}{{{_tex_int(macros.envelope_executed_count)}\\xspace}}",
            f"\\newcommand{{\\nmessagecarrierexecuted}}{{{_tex_int(macros.message_carrier_executed_count)}\\xspace}}",
            "",
        ]
    )


def parse_rfc_corpus_swept_count(path: Path | str) -> int:
    text = Path(path).read_text()
    match = RFC_CORPUS_COUNT_PATTERN.search(text)
    if match is None:
        raise ValueError(f"could not find RFC corpus swept count in {path}")
    return int(match.group(1).replace(",", ""))


def parse_cited_rfc_count(path: Path | str) -> int:
    text = Path(path).read_text()
    match = CITED_RFC_COUNT_PATTERN.search(text)
    if match is None:
        raise ValueError(f"could not find cited RFC count in {path}")
    return int(match.group(1).replace(",", ""))


def count_wiki_pages(path: Path | str) -> int:
    root = Path(path)
    return sum(1 for item in root.glob("*.md") if item.is_file())


def _tex_int(value: int) -> str:
    return f"{value:,}".replace(",", "{,}")


def _small_word(value: int) -> str:
    return {
        0: "zero",
        1: "one",
        2: "two",
        3: "three",
        4: "four",
        5: "five",
        6: "six",
        7: "seven",
        8: "eight",
        9: "nine",
        10: "ten",
    }.get(value, _tex_int(value))


def _tex_rfc_list(rfcs: tuple[str, ...]) -> str:
    if not rfcs:
        return ""
    if len(rfcs) == 1:
        return rfcs[0].replace(" ", "~")
    prefix = ", ".join(rfc.replace(" ", "~") for rfc in rfcs[:-1])
    return f"{prefix}, and {rfcs[-1].replace(' ', '~')}"


def _rfc_sort_key(value: str) -> int:
    match = re.search(r"(\d+)", value)
    if match is None:
        return 0
    return int(match.group(1))


__all__ = [
    "SurveyScaleMacros",
    "count_wiki_pages",
    "parse_cited_rfc_count",
    "parse_rfc_corpus_swept_count",
    "survey_scale_macros",
    "survey_scale_macros_tex",
]
