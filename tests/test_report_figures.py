"""Catalog-derived paper figures."""

import json
from pathlib import Path

import pytest

from celatim.catalog import load_mechanisms
from celatim.cli import paper_figures_main, session_main
from celatim.model import CarrierClass
from celatim.report.figures import (
    CAPACITY_BY_CLASS_FILENAME,
    CLASS_LAYER_HEATMAP_FILENAME,
    THROUGHPUT_UPPER_BOUNDS_FILENAME,
    capacity_by_class_data,
    catalog_figure_artifacts,
    class_layer_count_data,
)
from celatim.report.protocol_rates import load_protocol_rates

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"
RATES = Path(__file__).resolve().parents[1] / "data" / "protocol_rates.toml"
PAPER_FIGURES = Path(__file__).resolve().parents[2] / "paper" / "figures"
requires_paper_artifact = pytest.mark.skipif(
    not PAPER_FIGURES.is_dir(),
    reason="requires the companion RFC survey paper artifacts",
)


def test_capacity_by_class_data_separates_capacity_models_without_throughput_claims():
    rows = {row.carrier_class: row for row in capacity_by_class_data(load_mechanisms(DATA))}

    assert rows[CarrierClass.A].mechanism_count == 74
    assert rows[CarrierClass.F].mechanism_count == 3
    assert rows[CarrierClass.G].mechanism_count == 2
    assert rows[CarrierClass.D].unbounded_count >= 1
    assert rows[CarrierClass.G].median_bits == 256.0


def test_class_layer_heatmap_data_uses_known_layer_order():
    layers, matrix = class_layer_count_data(load_mechanisms(DATA))

    assert layers == ("link", "network", "transport", "session", "application", "control", "crypto")
    class_a = dict(matrix)[CarrierClass.A]
    assert sum(class_a) == 74
    assert class_a[layers.index("transport")] > 0


def test_figure_artifacts_are_svg_and_public_safe():
    artifacts = {
        artifact.filename: artifact
        for artifact in catalog_figure_artifacts(load_mechanisms(DATA), load_protocol_rates(RATES))
    }

    assert set(artifacts) == {
        CAPACITY_BY_CLASS_FILENAME,
        CLASS_LAYER_HEATMAP_FILENAME,
        THROUGHPUT_UPPER_BOUNDS_FILENAME,
    }
    for artifact in artifacts.values():
        assert artifact.content.startswith("<svg ")
        assert "Generated from measurement/data/mechanisms.jsonl" in artifact.content
        assert "payload_rate_bps" not in artifact.content
        assert len(artifact.sha256) == 64
    assert "not measured production goodput" in artifacts[THROUGHPUT_UPPER_BOUNDS_FILENAME].content


@requires_paper_artifact
def test_checked_in_paper_figures_match_catalog():
    artifacts = {
        artifact.filename: artifact
        for artifact in catalog_figure_artifacts(load_mechanisms(DATA), load_protocol_rates(RATES))
    }

    for filename, artifact in artifacts.items():
        assert (PAPER_FIGURES / filename).read_text() == artifact.content


@requires_paper_artifact
def test_checked_in_paper_figures_manifest_matches_catalog():
    artifacts = catalog_figure_artifacts(load_mechanisms(DATA), load_protocol_rates(RATES))
    expected = {
        "command": "paper_figures",
        "figure_count": len(artifacts),
        "figures": [artifact.to_json() for artifact in artifacts],
        "output_dir": "../paper/figures",
    }

    assert (PAPER_FIGURES / "figures-manifest.json").read_text() == (
        json.dumps(expected, sort_keys=True) + "\n"
    )


def test_paper_figures_cli_writes_manifest_and_svgs(tmp_path):
    out_dir = tmp_path / "figures"
    manifest = tmp_path / "figures.json"

    assert (
        paper_figures_main(
            ["--catalog", str(DATA), "--output-dir", str(out_dir), "--manifest", str(manifest)]
        )
        == 0
    )

    assert (out_dir / CAPACITY_BY_CLASS_FILENAME).read_text().startswith("<svg ")
    assert (out_dir / CLASS_LAYER_HEATMAP_FILENAME).read_text().startswith("<svg ")
    assert (out_dir / THROUGHPUT_UPPER_BOUNDS_FILENAME).read_text().startswith("<svg ")
    assert '"figure_count": 3' in manifest.read_text()


def test_session_figures_generate_uses_packaged_catalog_default(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    assert (
        session_main(["figures", "generate", "--output-dir", "figures", "--output", "figures.json"])
        == 0
    )

    assert (tmp_path / "figures" / CAPACITY_BY_CLASS_FILENAME).read_text().startswith("<svg ")
    assert (tmp_path / "figures" / CLASS_LAYER_HEATMAP_FILENAME).read_text().startswith("<svg ")
    assert (tmp_path / "figures" / THROUGHPUT_UPPER_BOUNDS_FILENAME).read_text().startswith("<svg ")
    assert '"figure_count": 3' in (tmp_path / "figures.json").read_text()
