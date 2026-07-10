"""Versioned, reusable telemetry dataset over every usable mechanism (M6).

For each usable catalog mechanism this builds a real carrier via the adapter, runs the
encode -> on-wire-bytes -> independent re-parse -> decode round-trip, and records the
result with content hashes. ``write_dataset`` lays the corpus out as
``<out>/<run-id>/{manifest.json, evidence/<id>.json, carriers/<id>.bin}`` -- the
provenance-stamped corpus the paper's tier tables and the detector TP/FP base-rate
replay read from. Pure stdlib; no network or extras required.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..adapter import adapter_for
from ..channel.framer import Framer
from ..channel.registry import codec_for
from ..model import Mechanism

DATASET_SCHEMA_VERSION = "celatim.dataset.v1"


@dataclass(frozen=True)
class DatasetRecord:
    mechanism_id: str
    evidence_bucket: str
    carrier_structure: str
    path_kinds: tuple[str, ...]
    transport_kinds: tuple[str, ...]
    supports_carrier_bytes: bool
    payload_sha256: str
    recovered_sha256: str
    matches: bool
    independent_validator_ok: bool | None
    carrier_sha256: str | None
    carrier_size_bytes: int
    unit_count: int

    def to_json(self) -> dict[str, Any]:
        return {
            "mechanism_id": self.mechanism_id,
            "evidence_bucket": self.evidence_bucket,
            "carrier_structure": self.carrier_structure,
            "path_kinds": list(self.path_kinds),
            "transport_kinds": list(self.transport_kinds),
            "supports_carrier_bytes": self.supports_carrier_bytes,
            "payload_sha256": self.payload_sha256,
            "recovered_sha256": self.recovered_sha256,
            "matches": self.matches,
            "independent_validator_ok": self.independent_validator_ok,
            "carrier_sha256": self.carrier_sha256,
            "carrier_size_bytes": self.carrier_size_bytes,
            "unit_count": self.unit_count,
        }


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_records(mechanisms: Sequence[Mechanism], *, payload: bytes) -> list[DatasetRecord]:
    """Round-trip every usable mechanism and capture its dataset record."""
    records: list[DatasetRecord] = []
    for mechanism in mechanisms:
        records.append(_carrier_bytes_for(mechanism, payload)[0])
    return records


def carriers_by_id(mechanisms: Sequence[Mechanism], *, payload: bytes) -> dict[str, bytes]:
    """The on-wire carrier-byte artifact per byte-carrier mechanism (for ``write_dataset``)."""
    out: dict[str, bytes] = {}
    for mechanism in mechanisms:
        record, blob = _carrier_bytes_for(mechanism, payload)
        if record.supports_carrier_bytes:
            out[mechanism.id] = blob
    return out


def _carrier_bytes_for(mechanism: Mechanism, payload: bytes) -> tuple[DatasetRecord, bytes]:
    adapter = adapter_for(mechanism)
    try:
        units = adapter.encode_payload(payload)
    except ModuleNotFoundError:
        framer = Framer[Any](codec_for(mechanism))
        symbols = framer.encode(payload)
        recovered = framer.decode(symbols)
        record = DatasetRecord(
            mechanism_id=mechanism.id,
            evidence_bucket=adapter.evidence.bucket.value,
            carrier_structure=adapter.evidence.carrier_structure.value,
            path_kinds=adapter.path_kinds,
            transport_kinds=adapter.transport_kinds,
            supports_carrier_bytes=False,
            payload_sha256=_sha(payload),
            recovered_sha256=_sha(recovered),
            matches=recovered == payload,
            independent_validator_ok=None,
            carrier_sha256=None,
            carrier_size_bytes=0,
            unit_count=len(symbols),
        )
        return record, b""
    recovered = adapter.decode_units(units)
    has_bytes = adapter.supports_carrier_bytes and any(u.carrier is not None for u in units)
    blob = b"".join(u.carrier for u in units if u.carrier is not None) if has_bytes else b""

    independent_ok: bool | None = None
    if has_bytes:
        # decode_units re-parses each carrier's field (parse_carrier) -> independent path.
        independent_ok = adapter.decode_units(units) == payload

    record = DatasetRecord(
        mechanism_id=mechanism.id,
        evidence_bucket=adapter.evidence.bucket.value,
        carrier_structure=adapter.evidence.carrier_structure.value,
        path_kinds=adapter.path_kinds,
        transport_kinds=adapter.transport_kinds,
        supports_carrier_bytes=has_bytes,
        payload_sha256=_sha(payload),
        recovered_sha256=_sha(recovered),
        matches=recovered == payload,
        independent_validator_ok=independent_ok,
        carrier_sha256=_sha(blob) if has_bytes else None,
        carrier_size_bytes=len(blob),
        unit_count=len(units),
    )
    return record, blob


def build_manifest(
    records: Sequence[DatasetRecord],
    *,
    run_id: str,
    generated_at: str,
    catalog_sha256: str,
    generator_version: str,
) -> dict[str, Any]:
    """Provenance-stamped manifest with tier counts over the dataset records."""
    tier_counts: dict[str, int] = {}
    for record in records:
        tier_counts[record.evidence_bucket] = tier_counts.get(record.evidence_bucket, 0) + 1
    substantiated = sum(1 for r in records if r.evidence_bucket != "offset_represented_zero_blob")
    return {
        "schema_version": DATASET_SCHEMA_VERSION,
        "run_id": run_id,
        "generated_at": generated_at,
        "generator_version": generator_version,
        "catalog_sha256": catalog_sha256,
        "total_usable": len(records),
        "substantiated": substantiated,
        "carrier_bytes_records": sum(1 for r in records if r.supports_carrier_bytes),
        "round_trip_ok": sum(1 for r in records if r.matches),
        "tier_counts": tier_counts,
        "records": [r.to_json() for r in records],
    }


def write_dataset(
    out_dir: Path,
    *,
    run_id: str,
    records: Sequence[DatasetRecord],
    manifest: dict[str, Any],
    carriers: dict[str, bytes] | None = None,
) -> Path:
    """Write the versioned corpus under ``out_dir/run_id`` and return that root."""
    root = out_dir / run_id
    (root / "evidence").mkdir(parents=True, exist_ok=True)
    (root / "carriers").mkdir(parents=True, exist_ok=True)
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    for record in records:
        (root / "evidence" / f"{record.mechanism_id}.json").write_text(
            json.dumps(record.to_json(), indent=2, sort_keys=True) + "\n"
        )
    for mechanism_id, blob in (carriers or {}).items():
        (root / "carriers" / f"{mechanism_id}.bin").write_bytes(blob)
    return root
