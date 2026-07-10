"""Reporting: generate the paper's appendix table from the catalog."""

from pathlib import Path

import pytest

from celatim.catalog import load_mechanisms
from celatim.cli import paper_macros_main, paper_tables_main
from celatim.report import (
    count_wiki_pages,
    parse_cited_rfc_count,
    parse_rfc_corpus_swept_count,
    survey_scale_macros,
    survey_scale_macros_tex,
)
from celatim.report.guidance import detector_scrub_guidance_markdown
from celatim.report.tables import mechanisms_to_longtable

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"
GENERATED_TABLE = (
    Path(__file__).resolve().parents[2] / "paper" / "generated" / "field-catalog-longtable.tex"
)
GENERATED_MACROS = (
    Path(__file__).resolve().parents[2] / "paper" / "generated" / "survey-scale-macros.tex"
)
RESEARCH_CATALOG = Path(__file__).resolve().parents[2] / "research" / "rfc-field-catalog.md"
RFC_INDEX = Path(__file__).resolve().parents[2] / "sources" / "rfc" / "INDEX.md"
WIKI_INFOSEC = Path(__file__).resolve().parents[2] / "sources" / "wiki" / "infosec"
CLAIM_LEDGER = Path(__file__).resolve().parents[2] / "docs" / "claim-ledger.json"
PAPER_ARTIFACT_AVAILABLE = all(
    path.exists()
    for path in (
        GENERATED_TABLE,
        GENERATED_MACROS,
        RESEARCH_CATALOG,
        RFC_INDEX,
        WIKI_INFOSEC,
        CLAIM_LEDGER,
    )
)
requires_paper_artifact = pytest.mark.skipif(
    not PAPER_ARTIFACT_AVAILABLE,
    reason="requires the companion RFC survey sources and generated artifacts",
)


def test_longtable_env_and_rows():
    tex = mechanisms_to_longtable(load_mechanisms(DATA))
    assert "\\begin{longtable}" in tex
    assert "\\end{longtable}" in tex
    # a cited RFC and a class tag survive into the rendered table
    assert "RFC 9293" in tex
    assert "RFC" in tex and tex.count("RFC") >= 3


def test_longtable_handles_nonstorage_and_unbounded_rows():
    # Must not raise on timing/subliminal rows (density is width-based only)...
    tex = mechanisms_to_longtable(load_mechanisms(DATA))
    assert "--" in tex  # em dash where density is undefined (F/G rows)
    # ...and unbounded carriers are flagged so a finite figure is not misread.
    assert "9600+" in tex


@requires_paper_artifact
def test_checked_in_appendix_table_matches_catalog():
    assert GENERATED_TABLE.read_text() == mechanisms_to_longtable(load_mechanisms(DATA))


@requires_paper_artifact
def test_survey_scale_macros_are_derived_from_self_contained_sources():
    macros = survey_scale_macros(
        load_mechanisms(DATA),
        rfc_corpus_swept_count=parse_rfc_corpus_swept_count(RESEARCH_CATALOG),
        cited_rfc_count=parse_cited_rfc_count(RFC_INDEX),
        wiki_page_count=count_wiki_pages(WIKI_INFOSEC),
        claim_ledger=CLAIM_LEDGER,
    )
    tex = survey_scale_macros_tex(macros)

    assert macros.mechanism_count == 146
    assert macros.usable_mechanism_count == 142
    assert macros.negative_result_count == 4
    assert macros.spec_acknowledged_rfc_count == 5
    assert macros.spec_acknowledged_rfcs == (
        "RFC 6437",
        "RFC 7685",
        "RFC 7830",
        "RFC 7837",
        "RFC 8017",
    )
    assert "\\newcommand{\\nmech}{146\\xspace}" in tex
    assert "\\newcommand{\\nspecack}{five\\xspace}" in tex

    # Evidence-tier macros are generated from the catalog classification (never hand-edited).
    assert (
        macros.substantiated_count
        == macros.real_pdu_count
        + macros.real_daemon_or_crypto_count
        + macros.timing_scheme_count
        + macros.codec_roundtrip_count
    )
    assert macros.substantiated_count + macros.structural_residual_count == 142
    assert macros.structural_residual_count == 1
    assert macros.exact_recovery_executed_count == 142
    assert macros.packet_path_executed_count == 56
    assert macros.envelope_executed_count == 86
    assert macros.message_carrier_executed_count == 6
    assert "\\newcommand{\\nrealpducapable}{129\\xspace}" in tex
    assert "\\newcommand{\\ncodeconlycapable}{1\\xspace}" in tex
    assert "\\newcommand{\\nexactrecoveryexecuted}{142\\xspace}" in tex
    assert "\\newcommand{\\npacketpathexecuted}{56\\xspace}" in tex
    assert f"\\newcommand{{\\nsubstantiated}}{{{macros.substantiated_count}\\xspace}}" in tex
    assert "\\newcommand{\\nstructuralresidual}{1\\xspace}" in tex


@requires_paper_artifact
def test_checked_in_survey_scale_macros_match_catalog():
    macros = survey_scale_macros(
        load_mechanisms(DATA),
        rfc_corpus_swept_count=parse_rfc_corpus_swept_count(RESEARCH_CATALOG),
        cited_rfc_count=parse_cited_rfc_count(RFC_INDEX),
        wiki_page_count=count_wiki_pages(WIKI_INFOSEC),
        claim_ledger=CLAIM_LEDGER,
    )

    assert GENERATED_MACROS.read_text() == survey_scale_macros_tex(macros)


def test_paper_tables_cli_writes_generated_longtable(tmp_path):
    out = tmp_path / "field-catalog-longtable.tex"

    assert paper_tables_main(["--catalog", str(DATA), "--output", str(out)]) == 0

    assert out.read_text() == mechanisms_to_longtable(load_mechanisms(DATA))


@requires_paper_artifact
def test_paper_macros_cli_writes_generated_macros(tmp_path):
    out = tmp_path / "survey-scale-macros.tex"

    assert (
        paper_macros_main(
            [
                "--catalog",
                str(DATA),
                "--research-catalog",
                str(RESEARCH_CATALOG),
                "--rfc-index",
                str(RFC_INDEX),
                "--wiki-dir",
                str(WIKI_INFOSEC),
                "--claim-ledger",
                str(CLAIM_LEDGER),
                "--output",
                str(out),
            ]
        )
        == 0
    )

    assert out.read_text() == GENERATED_MACROS.read_text()


def test_paper_tables_cli_uses_packaged_catalog_default_outside_measurement_tree(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "field-catalog-longtable.tex"

    assert paper_tables_main(["--output", str(out)]) == 0

    assert out.read_text() == mechanisms_to_longtable(load_mechanisms(DATA))


def test_detector_scrub_guidance_summarizes_public_defensive_posture():
    markdown = detector_scrub_guidance_markdown(load_mechanisms(DATA))

    assert markdown.startswith("# Detector and Scrub Guidance\n")
    assert "| `stateless_filter` |" in markdown
    assert "| `canonicalize_zero` |" in markdown
    assert "## Annotation Coverage" in markdown
    assert "| `explicit_catalog` | 146 |" in markdown
    assert "| `derived_default` | 0 |" in markdown
    assert "`tcp-reserved-bits`" in markdown
    assert "Annotation source" in markdown
    assert "`explicit_catalog`" in markdown
    assert "`derived_default`" in markdown
    assert "`unassessed`" not in markdown
    assert "`sender_bound_no_bits_per_second_claim`" not in markdown
