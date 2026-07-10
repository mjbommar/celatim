"""Windows pktmon/ETW capture guidance for detector replay artifacts."""

from __future__ import annotations

WINDOWS_CAPTURE_GUIDANCE_CLAIM_STATUS = "capture_guidance_not_header_bit_filter"
WINDOWS_CAPTURE_GUIDANCE_FILENAME = "windows-pktmon-etw-guidance.md"

MICROSOFT_PKTMON_DOCS = (
    "https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon-syntax",
    "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-filter-add",
    "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-start",
    "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-etl2pcap",
)


def windows_pktmon_guidance_markdown() -> str:
    """Render public-safe Windows capture guidance for detector replay workflows."""
    rows = [
        "# Windows pktmon / ETW Capture Guidance",
        "",
        f"Claim status: `{WINDOWS_CAPTURE_GUIDANCE_CLAIM_STATUS}`.",
        "",
        "This guidance is for collecting Windows traces that can later be replayed through",
        "celatim detector artifacts. It is not a Windows firewall detector and it does",
        "not claim arbitrary header-bit matching inside Windows filtering policy.",
        "",
        "## Boundary",
        "",
        "- Use `pktmon`/ETW to collect packet evidence and stack/drop context on Windows.",
        "- Use broad capture filters such as protocol, port, address, EtherType, VLAN, or TCP flags.",
        "- Do not treat Windows Defender Firewall policy as a substitute for nftables,",
        "  iptables `u32`, BPF, Zeek, Suricata, or tshark bit/field checks. The covert",
        "  fields here often require arbitrary parsed-field, byte-mask, entropy, timing,",
        "  or baseline logic.",
        "- Convert ETL to pcapng and run `celatim detector replay`, tshark, Zeek,",
        "  Suricata, or the generated rule artifacts over the exported trace before making",
        "  detector or false-positive claims.",
        "",
        "## Minimal Capture Pattern",
        "",
        "```powershell",
        "pktmon filter remove",
        "pktmon filter add celatim-tcp -t TCP",
        "pktmon start --capture --comp nics --pkt-size 0 --file-name celatim.etl",
        "# reproduce the authorized scenario",
        "pktmon stop",
        "pktmon etl2pcap celatim.etl --out celatim.pcapng",
        "```",
        "",
        "For UDP or DNS-focused traces, replace the TCP filter with a protocol or port",
        "filter such as `pktmon filter add celatim-dns -t UDP -p 53`. Keep the filter",
        "broad enough to preserve the carrier field under study; narrow bit-level checks",
        "belong in the replay/detector stage.",
        "",
        "## Replay and Provenance",
        "",
        "After export, record the pcapng hash, Windows build, pktmon command lines,",
        "filter assumptions, component selection, and whether the trace is a real benign",
        "trace or a local smoke/control fixture. Only real benign or authorized benign",
        "trace replay can support false-positive estimates.",
        "",
        "```bash",
        "celatim detector replay \\",
        "  --pcap celatim.pcapng \\",
        "  --source-kind authorized_benign_trace \\",
        "  --trace-name windows-pktmon-sample \\",
        '  --filtering-assumption "pktmon TCP capture exported to pcapng; bit checks run after export" \\',
        "  --output detector-replay.json",
        "```",
        "",
        "## Source Notes",
        "",
        "- Microsoft documents Packet Monitor as an in-box Windows packet capture, packet",
        "  filtering, counting, and drop-detection tool.",
        "- Microsoft documents `pktmon filter add` filters for MAC, VLAN, EtherType,",
        "  transport protocol, IP address, port, heartbeat, encapsulation, and TCP flags.",
        "- Microsoft documents `pktmon start --capture` and `--pkt-size 0` for full-packet",
        "  logging, and `pktmon etl2pcap` for converting ETL logs to pcapng.",
        "",
        "Sources:",
    ]
    rows.extend(f"- {url}" for url in MICROSOFT_PKTMON_DOCS)
    rows.append("")
    return "\n".join(rows)


__all__ = [
    "MICROSOFT_PKTMON_DOCS",
    "WINDOWS_CAPTURE_GUIDANCE_CLAIM_STATUS",
    "WINDOWS_CAPTURE_GUIDANCE_FILENAME",
    "windows_pktmon_guidance_markdown",
]
