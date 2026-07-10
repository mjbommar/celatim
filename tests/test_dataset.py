"""M6 reusable telemetry dataset: versioned per-mechanism corpus + manifest."""

from __future__ import annotations

import json
from pathlib import Path

from celatim.analysis.dataset import (
    DATASET_SCHEMA_VERSION,
    build_manifest,
    build_records,
    carriers_by_id,
    write_dataset,
)
from celatim.catalog import load_mechanisms

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def _usable():
    return [m for m in load_mechanisms(DATA) if m.is_usable_channel]


def test_every_usable_mechanism_has_a_record_that_round_trips():
    records = build_records(_usable(), payload=b"celatim")
    assert len(records) == len(_usable())
    assert all(r.matches for r in records)
    # the carrier-bytes tier carries a real on-wire artifact and an independent re-parse.
    carriers = [r for r in records if r.supports_carrier_bytes]
    assert len(carriers) >= 100
    assert all(r.carrier_sha256 and r.carrier_size_bytes > 0 for r in carriers)
    assert all(r.independent_validator_ok for r in carriers)


def test_manifest_provenance_and_tier_counts():
    records = build_records(_usable(), payload=b"celatim")
    manifest = build_manifest(
        records,
        run_id="run-0001",
        generated_at="2026-06-13T00:00:00Z",
        catalog_sha256="deadbeef",
        generator_version="1.0.0",
    )
    assert manifest["schema_version"] == DATASET_SCHEMA_VERSION
    assert manifest["run_id"] == "run-0001"
    assert manifest["catalog_sha256"] == "deadbeef"
    assert manifest["total_usable"] == len(records)
    assert manifest["substantiated"] == sum(
        1 for r in records if r.evidence_bucket != "offset_represented_zero_blob"
    )
    assert sum(manifest["tier_counts"].values()) == len(records)
    assert manifest["tier_counts"]["real_pdu_packet_path"] >= 100


def test_write_dataset_lays_out_versioned_corpus(tmp_path):
    records = build_records(_usable(), payload=b"celatim")
    manifest = build_manifest(
        records,
        run_id="run-0001",
        generated_at="2026-06-13T00:00:00Z",
        catalog_sha256="deadbeef",
        generator_version="1.0.0",
    )
    carriers = carriers_by_id(_usable(), payload=b"celatim")
    root = write_dataset(
        tmp_path, run_id="run-0001", records=records, manifest=manifest, carriers=carriers
    )
    assert root == tmp_path / "run-0001"
    loaded = json.loads((root / "manifest.json").read_text())
    assert loaded["run_id"] == "run-0001"
    # one evidence file per mechanism; carrier artifacts only for the byte-carrier tier.
    assert len(list((root / "evidence").glob("*.json"))) == len(records)
    sample = next(r for r in records if r.supports_carrier_bytes)
    blob = (root / "carriers" / f"{sample.mechanism_id}.bin").read_bytes()
    import hashlib

    assert hashlib.sha256(blob).hexdigest() == sample.carrier_sha256
