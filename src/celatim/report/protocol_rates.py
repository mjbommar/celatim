"""Cited carrier-unit rates for structural throughput figures."""

from __future__ import annotations

import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..model import Mechanism

PROTOCOL_RATE_CLAIM_STATUS = "structural_upper_bound_not_measured_goodput"


@dataclass(frozen=True)
class ProtocolRate:
    """One traceable carrier-unit rate assumption for a mechanism."""

    id: str
    mechanism_id: str
    protocol: str
    carrier_unit: str
    unit_rate_hz: float
    source_path: str
    source_detail: str
    citation_label: str
    citation_status: str
    claim_status: str
    notes: str = ""

    @classmethod
    def from_mapping(cls, row: Mapping[str, Any]) -> ProtocolRate:
        rate = cls(
            id=str(row["id"]),
            mechanism_id=str(row["mechanism_id"]),
            protocol=str(row["protocol"]),
            carrier_unit=str(row["carrier_unit"]),
            unit_rate_hz=float(row["unit_rate_hz"]),
            source_path=str(row["source_path"]),
            source_detail=str(row["source_detail"]),
            citation_label=str(row["citation_label"]),
            citation_status=str(row["citation_status"]),
            claim_status=str(row["claim_status"]),
            notes=str(row.get("notes", "")),
        )
        rate._validate()
        return rate

    def _validate(self) -> None:
        if not self.id:
            raise ValueError("protocol rate id must be non-empty")
        if not self.mechanism_id:
            raise ValueError(f"{self.id}: mechanism_id must be non-empty")
        if self.unit_rate_hz <= 0:
            raise ValueError(f"{self.id}: unit_rate_hz must be > 0")
        if self.claim_status != PROTOCOL_RATE_CLAIM_STATUS:
            raise ValueError(f"{self.id}: claim_status must be {PROTOCOL_RATE_CLAIM_STATUS!r}")
        for field_name in ("source_path", "source_detail", "citation_label", "citation_status"):
            if not getattr(self, field_name):
                raise ValueError(f"{self.id}: {field_name} must be non-empty")

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "mechanism_id": self.mechanism_id,
            "protocol": self.protocol,
            "carrier_unit": self.carrier_unit,
            "unit_rate_hz": self.unit_rate_hz,
            "source_path": self.source_path,
            "source_detail": self.source_detail,
            "citation_label": self.citation_label,
            "citation_status": self.citation_status,
            "claim_status": self.claim_status,
            "notes": self.notes,
        }


@dataclass(frozen=True)
class ProtocolThroughputEstimate:
    """Structural bits/s upper bound from catalog bits/unit times a cited unit rate."""

    rate: ProtocolRate
    mechanism_id: str
    mechanism_name: str
    carrier_class: str
    raw_capacity_bits: int
    structural_upper_bound_bps: float

    @property
    def claim_status(self) -> str:
        return self.rate.claim_status

    def to_json(self) -> dict[str, Any]:
        return {
            "rate": self.rate.to_json(),
            "mechanism_id": self.mechanism_id,
            "mechanism_name": self.mechanism_name,
            "carrier_class": self.carrier_class,
            "raw_capacity_bits": self.raw_capacity_bits,
            "structural_upper_bound_bps": self.structural_upper_bound_bps,
            "claim_status": self.claim_status,
        }


def load_protocol_rates(path: Path | str) -> tuple[ProtocolRate, ...]:
    """Load a TOML protocol-rate table."""
    document = tomllib.loads(Path(path).read_text())
    rows = tuple(ProtocolRate.from_mapping(row) for row in document.get("rate", ()))
    ids = [row.id for row in rows]
    duplicates = sorted({rate_id for rate_id in ids if ids.count(rate_id) > 1})
    if duplicates:
        raise ValueError(f"duplicate protocol rate ids: {duplicates}")
    return rows


def throughput_estimates(
    mechanisms: Iterable[Mechanism],
    rates: Iterable[ProtocolRate],
) -> tuple[ProtocolThroughputEstimate, ...]:
    """Join mechanisms to protocol-rate rows and compute structural upper bounds."""
    by_id = {mechanism.id: mechanism for mechanism in mechanisms}
    estimates: list[ProtocolThroughputEstimate] = []
    for rate in rates:
        try:
            mechanism = by_id[rate.mechanism_id]
        except KeyError as exc:
            raise ValueError(f"{rate.id}: unknown mechanism_id {rate.mechanism_id!r}") from exc
        if mechanism.carrier_unit != rate.carrier_unit:
            raise ValueError(
                f"{rate.id}: carrier_unit {rate.carrier_unit!r} does not match "
                f"{mechanism.id} catalog unit {mechanism.carrier_unit!r}"
            )
        estimates.append(
            ProtocolThroughputEstimate(
                rate=rate,
                mechanism_id=mechanism.id,
                mechanism_name=mechanism.name,
                carrier_class=mechanism.carrier_class.value,
                raw_capacity_bits=mechanism.raw_capacity_bits,
                structural_upper_bound_bps=mechanism.raw_capacity_bits * rate.unit_rate_hz,
            )
        )
    return tuple(
        sorted(estimates, key=lambda estimate: estimate.structural_upper_bound_bps, reverse=True)
    )


def protocol_rates_markdown(
    mechanisms: Iterable[Mechanism],
    rates: Iterable[ProtocolRate],
) -> str:
    """Render a public-safe rate table with explicit non-goodput claim labels."""
    rows = [
        "# Protocol Rate Assumptions",
        "",
        "Generated from the packaged Celatim protocol-rate catalog. Values are carrier-unit",
        "rates used for structural throughput upper-bound figures; they are not measured",
        "production goodput and must not be cited as evidence-run measured rate output.",
        "",
        "| Mechanism | Protocol | Unit rate | Raw bits/unit | Upper bound | Citation status | Claim status | Source |",
        "|---|---|---:|---:|---:|---|---|---|",
    ]
    for estimate in throughput_estimates(mechanisms, rates):
        rate = estimate.rate
        rows.append(
            f"| `{estimate.mechanism_id}` | {rate.protocol} | "
            f"{rate.unit_rate_hz:g} {rate.carrier_unit}/s | "
            f"{estimate.raw_capacity_bits:g} | "
            f"{estimate.structural_upper_bound_bps:g} bps | "
            f"`{rate.citation_status}` | `{estimate.claim_status}` | "
            f"{_md(rate.source_path)} ({_md(rate.source_detail)}) |"
        )
    rows.append("")
    return "\n".join(rows)


def _md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


__all__ = [
    "PROTOCOL_RATE_CLAIM_STATUS",
    "ProtocolRate",
    "ProtocolThroughputEstimate",
    "load_protocol_rates",
    "protocol_rates_markdown",
    "throughput_estimates",
]
