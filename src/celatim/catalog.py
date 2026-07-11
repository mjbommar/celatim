"""Load the structured mechanism catalog (the survey's single source of truth)."""

from __future__ import annotations

import json
from pathlib import Path

from .model import (
    AnalysisPopulation,
    CarrierClass,
    DetectPredicate,
    FalsePositive,
    FieldLocator,
    FieldValueMatch,
    Mechanism,
    OnPathVisibility,
    Provenance,
    Reach,
    Status,
    Survivability,
    WireBase,
)


def _int_from_json(value: int | str) -> int:
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def _locator_from_dict(d: dict | None) -> FieldLocator | None:
    if d is None:
        return None
    return FieldLocator(
        base=WireBase(d["base"]),
        bit_offset=int(d["bit_offset"]),
        bit_width=int(d["bit_width"]),
    )


def _value_match_from_dict(d: dict) -> FieldValueMatch:
    return FieldValueMatch(
        value=_int_from_json(d["value"]),
        mask=None if d.get("mask") is None else _int_from_json(d["mask"]),
    )


def _from_dict(d: dict) -> Mechanism:
    carrier_class = CarrierClass(d["carrier_class"])
    survivability = Survivability(d["survivability"])
    if (
        carrier_class
        in {CarrierClass.A, CarrierClass.B, CarrierClass.C, CarrierClass.D, CarrierClass.E}
        and survivability is Survivability.INTEGRITY_BOUND
        and "on_path_visibility" not in d
    ):
        raise ValueError(f"{d['id']}: integrity-bound storage row requires on_path_visibility")
    return Mechanism(
        id=d["id"],
        name=d["name"],
        rfcs=tuple(d["rfcs"]),
        protocol=d["protocol"],
        layer=d["layer"],
        carrier_class=carrier_class,
        status=Status(d["status"]),
        carrier_unit=d["carrier_unit"],
        raw_capacity_bits=int(d["raw_capacity_bits"]),
        header_bits=int(d["header_bits"]),
        wire_bits_typical=int(d["wire_bits_typical"]),
        reach=Reach(d["reach"]),
        survivability=survivability,
        provenance=Provenance(d["provenance"]),
        spec_quote=d["spec_quote"],
        c_capacity_key=d.get("c_capacity_key"),
        c_header_key=d.get("c_header_key"),
        bits_min=d.get("bits_min"),
        bits_max=d.get("bits_max"),
        unbounded=bool(d.get("unbounded", False)),
        locator=_locator_from_dict(d.get("locator")),
        detect_predicate=(
            DetectPredicate(d["detect_predicate"]) if d.get("detect_predicate") else None
        ),
        false_positive=(FalsePositive(d["false_positive"]) if d.get("false_positive") else None),
        on_path_visibility=OnPathVisibility(d.get("on_path_visibility", "cleartext")),
        analysis_population=AnalysisPopulation(d.get("analysis_population", "primary_rfc_carrier")),
        reserved_value_matches=tuple(
            _value_match_from_dict(item) for item in d.get("reserved_value_matches", ())
        ),
        negative_result=bool(d.get("negative_result", False)),
    )


def load_mechanisms(path: Path | str) -> list[Mechanism]:
    """Parse a JSON-lines catalog. Blank lines and ``#`` comments are skipped."""
    mechs: list[Mechanism] = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        mechs.append(_from_dict(json.loads(line)))
    ids = [m.id for m in mechs]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise ValueError(f"duplicate mechanism ids: {dupes}")
    return mechs
