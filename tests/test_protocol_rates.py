"""Protocol-rate assumptions for throughput figures."""

from pathlib import Path

import pytest

from celatim.catalog import load_mechanisms
from celatim.cli import session_main
from celatim.report.protocol_rates import (
    PROTOCOL_RATE_CLAIM_STATUS,
    ProtocolRate,
    load_protocol_rates,
    protocol_rates_markdown,
    throughput_estimates,
)

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"
RATES = Path(__file__).resolve().parents[1] / "data" / "protocol_rates.toml"
ROOT = Path(__file__).resolve().parents[2]
PAPER_SOURCES_AVAILABLE = (ROOT / "sources" / "wiki" / "infosec").is_dir()


@pytest.mark.skipif(
    not PAPER_SOURCES_AVAILABLE,
    reason="requires the companion RFC survey source corpus",
)
def test_protocol_rates_load_with_traceable_sources():
    rates = load_protocol_rates(RATES)

    assert len(rates) == 4
    assert {rate.mechanism_id for rate in rates} == {
        "dns-timing",
        "ipv6-flow-label",
        "mqtt-tunnel",
        "ntp-extension-field",
    }
    for rate in rates:
        assert rate.claim_status == PROTOCOL_RATE_CLAIM_STATUS
        assert rate.citation_status == "local_prior_art"
        assert (ROOT / rate.source_path).is_file(), rate.source_path


def test_throughput_estimates_are_structural_upper_bounds_not_goodput():
    estimates = throughput_estimates(load_mechanisms(DATA), load_protocol_rates(RATES))
    by_id = {estimate.mechanism_id: estimate for estimate in estimates}

    assert by_id["ntp-extension-field"].structural_upper_bound_bps == 32000.0
    assert by_id["ipv6-flow-label"].structural_upper_bound_bps == 20000.0
    assert by_id["dns-timing"].claim_status == PROTOCOL_RATE_CLAIM_STATUS
    assert "payload_rate_bps" not in protocol_rates_markdown(
        load_mechanisms(DATA),
        load_protocol_rates(RATES),
    )


def test_protocol_rate_validation_rejects_bad_rows(tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text(
        """
[[rate]]
id = "bad"
mechanism_id = "ipv6-flow-label"
protocol = "IPv6"
carrier_unit = "packet"
unit_rate_hz = 0
source_path = "sources/wiki/infosec/ipv6-extension-headers.md"
source_detail = "bad"
citation_label = "bad"
citation_status = "local_prior_art"
claim_status = "structural_upper_bound_not_measured_goodput"
"""
    )

    with pytest.raises(ValueError, match="unit_rate_hz"):
        load_protocol_rates(bad)


def test_throughput_estimates_reject_unknown_or_unit_mismatch():
    mechanisms = load_mechanisms(DATA)
    unknown = ProtocolRate(
        id="unknown",
        mechanism_id="missing",
        protocol="X",
        carrier_unit="packet",
        unit_rate_hz=1.0,
        source_path="sources/wiki/infosec/ipv6-extension-headers.md",
        source_detail="test",
        citation_label="test",
        citation_status="local_prior_art",
        claim_status=PROTOCOL_RATE_CLAIM_STATUS,
    )
    mismatch = ProtocolRate(
        id="mismatch",
        mechanism_id="ipv6-flow-label",
        protocol="IPv6",
        carrier_unit="query",
        unit_rate_hz=1.0,
        source_path="sources/wiki/infosec/ipv6-extension-headers.md",
        source_detail="test",
        citation_label="test",
        citation_status="local_prior_art",
        claim_status=PROTOCOL_RATE_CLAIM_STATUS,
    )

    with pytest.raises(ValueError, match="unknown mechanism_id"):
        throughput_estimates(mechanisms, (unknown,))
    with pytest.raises(ValueError, match="carrier_unit"):
        throughput_estimates(mechanisms, (mismatch,))


def test_rates_show_cli_uses_packaged_rates_by_default(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    assert session_main(["rates", "show", "--format", "markdown", "--output", "rates.md"]) == 0

    markdown = (tmp_path / "rates.md").read_text()
    assert markdown.startswith("# Protocol Rate Assumptions\n")
    assert "structural_upper_bound_not_measured_goodput" in markdown
    assert "payload_rate_bps" not in markdown
