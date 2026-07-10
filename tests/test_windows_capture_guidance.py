"""Windows pktmon/ETW capture guidance."""

from celatim.report.windows_capture import (
    MICROSOFT_PKTMON_DOCS,
    WINDOWS_CAPTURE_GUIDANCE_CLAIM_STATUS,
    windows_pktmon_guidance_markdown,
)


def test_windows_pktmon_guidance_names_capture_boundary_and_replay_path():
    markdown = windows_pktmon_guidance_markdown()

    assert markdown.startswith("# Windows pktmon / ETW Capture Guidance\n")
    assert WINDOWS_CAPTURE_GUIDANCE_CLAIM_STATUS in markdown
    assert "not a Windows firewall detector" in markdown
    assert "pktmon filter add celatim-tcp -t TCP" in markdown
    assert "pktmon start --capture --comp nics --pkt-size 0" in markdown
    assert "pktmon etl2pcap celatim.etl --out celatim.pcapng" in markdown
    assert "celatim detector replay" in markdown
    assert all(url in markdown for url in MICROSOFT_PKTMON_DOCS)
