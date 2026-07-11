"""Render catalog rows into the paper's LaTeX appendix longtable, so the table
and the single-source-of-truth catalog never drift."""

from __future__ import annotations

from collections.abc import Iterable

from ..metrics import density_header, density_wire, raw_bits
from ..model import AnalysisPopulation, CapacityModel, Mechanism

# Short, table-friendly survivability labels (the catalog enum values are verbose).
_SURV_LABEL = {
    "end_to_end": "e2e",
    "nat_rewritten": "NAT",
    "path_dependent": "path",
    "normalized": "norm",
    "integrity_bound": "int-bd",
}

_HEADER = (
    "\\begingroup\n"
    "\\footnotesize\n"
    "\\setlength{\\LTleft}{0pt}\n"
    "\\setlength{\\LTright}{0pt}\n"
    "\\begin{longtable}{@{}>{\\raggedright\\arraybackslash}p{0.40\\textwidth}"
    ">{\\raggedright\\arraybackslash}p{0.15\\textwidth}cclrrr@{}}\n"
    "\\toprule\n"
    "Mechanism & RFC(s) & Class & St. & Surv. & Bits & "
    "Hdr.\\ den. & Wire den. \\\\\n"
    "\\midrule\n"
    "\\endhead\n"
)
# Header-relative density can exceed 1 because covert capacity accumulates across
# repeated carrier units (padding/opaque fields can be far wider than the fixed
# header they are measured against); on-wire density divides by a full PDU and
# stays bounded.
_NOTE = (
    "\\multicolumn{8}{@{}p{\\textwidth}@{}}{\\footnotesize\\textit{Hdr.\\ den.} is "
    "covert bits per header bit and can exceed~1 because capacity accumulates across "
    "repeated carrier units; \\textit{Wire den.}\\ divides by a full on-wire PDU. "
    "Density is defined only for storage classes (A--E); timing/subliminal rows show "
    "``--''. \\textit{St.}: \\textsc{new}/\\textsc{ext}/\\textsc{doc} prior-art status; "
    "\\textit{Surv.}: end-to-end (e2e), NAT-rewritten (NAT), path-dependent (path), "
    "normalized (norm), or integrity-bound (int-bd).} \\\\\n"
)
_FOOTER = "\\bottomrule\n\\end{longtable}\n\\endgroup\n"


def _escape(s: str) -> str:
    for a, b in (("&", "\\&"), ("_", "\\_"), ("#", "\\#"), ("%", "\\%")):
        s = s.replace(a, b)
    return s


def _bits_cell(m: Mechanism) -> str:
    """Trailing ``+`` flags an unbounded carrier so the figure is not read as a
    hard ceiling (the representative value is a floor, not a maximum)."""
    return f"{raw_bits(m)}+" if m.unbounded else str(raw_bits(m))


def _density_header_cell(m: Mechanism) -> str:
    """Header-relative density only for storage rows; timing/subliminal get an em dash."""
    if m.capacity_model is CapacityModel.STORAGE:
        return f"{density_header(m):.3f}"
    return "--"


def _density_wire_cell(m: Mechanism) -> str:
    """On-wire density (bits per full-PDU bit) only for storage rows; else an em dash."""
    if m.capacity_model is CapacityModel.STORAGE:
        return f"{density_wire(m):.4f}"
    return "--"


def _survivability_cell(m: Mechanism) -> str:
    return _SURV_LABEL[m.survivability.value]


def _population_longtable(mechs: Iterable[Mechanism]) -> str:
    rows = [
        f"{_escape(m.name)} & {_escape(', '.join(m.rfcs))} & {m.carrier_class.value} & "
        f"{m.status.value} & {_survivability_cell(m)} & {_bits_cell(m)} & "
        f"{_density_header_cell(m)} & {_density_wire_cell(m)} \\\\"
        for m in mechs
    ]
    return _HEADER + "\n".join(rows) + "\n\\midrule\n" + _NOTE + _FOOTER


def mechanisms_to_longtable(mechs: Iterable[Mechanism]) -> str:
    """Render separate primary, ordinary-payload, and non-IETF tables."""
    catalog = tuple(mechs)
    populations = (
        (AnalysisPopulation.PRIMARY_RFC_CARRIER, "Primary RFC carrier population"),
        (
            AnalysisPopulation.COMPARISON_ORDINARY_PAYLOAD,
            "Ordinary application-payload comparisons",
        ),
        (AnalysisPopulation.COMPARISON_NON_IETF, "Non-IETF comparisons"),
    )
    sections = []
    for population, title in populations:
        rows = tuple(
            mechanism for mechanism in catalog if mechanism.analysis_population is population
        )
        sections.append(f"\\subsubsection*{{{title}}}\n" + _population_longtable(rows))
    return "\n".join(sections)
