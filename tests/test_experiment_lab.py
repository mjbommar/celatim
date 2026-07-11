"""Regression tests for packet construction used by privileged experiments."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from scapy.layers.inet import IP, TCP, checksum

SCRIPT = Path(__file__).resolve().parents[1] / "experiments" / "lab.py"
SPEC = importlib.util.spec_from_file_location("celatim_experiment_lab", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
LAB = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LAB
SPEC.loader.exec_module(LAB)

sys.modules["lab"] = LAB
FIREWALL_SCRIPT = SCRIPT.with_name("run_firewall.py")
FIREWALL_SPEC = importlib.util.spec_from_file_location(
    "celatim_experiment_firewall", FIREWALL_SCRIPT
)
assert FIREWALL_SPEC is not None and FIREWALL_SPEC.loader is not None
FIREWALL = importlib.util.module_from_spec(FIREWALL_SPEC)
sys.modules[FIREWALL_SPEC.name] = FIREWALL
FIREWALL_SPEC.loader.exec_module(FIREWALL)


def test_clear_checksums_invalidates_parsed_packet_cache() -> None:
    original = bytes(
        IP(src="192.168.9.2", dst="10.10.0.2", id=1)
        / TCP(sport=40000, dport=9999, flags="S", seq=1)
    )
    mutated = bytearray(original)
    mutated[4:6] = (0xBEEF).to_bytes(2, "big")
    parsed = IP(bytes(mutated))
    stale_checksum = parsed.chksum

    LAB._clear_checksums(parsed)
    emitted = bytes(parsed)
    header = bytearray(emitted[:20])
    emitted_checksum = int.from_bytes(header[10:12], "big")
    header[10:12] = b"\x00\x00"

    assert emitted_checksum == checksum(bytes(header))
    assert emitted_checksum != stale_checksum
    assert IP(emitted).id == 0xBEEF


def test_nft_counter_parser_binds_named_accept_and_drop_rules() -> None:
    document = {
        "nftables": [
            {"metainfo": {"json_schema_version": 1}},
            {
                "rule": {
                    "comment": "celatim-allowed",
                    "expr": [{"counter": {"packets": 5, "bytes": 200}}],
                }
            },
            {
                "rule": {
                    "comment": "celatim-denied",
                    "expr": [{"counter": {"packets": 2, "bytes": 80}}],
                }
            },
        ]
    }

    assert FIREWALL._parse_nft_counters(document) == {
        "celatim-allowed": 5,
        "celatim-denied": 2,
    }


def test_firewall_topology_installs_default_drop_and_narrow_accept(monkeypatch) -> None:
    commands: list[str] = []
    monkeypatch.setattr(LAB, "_sh", commands.append)

    LAB.topo_firewall_up()

    assert any("policy drop" in command for command in commands)
    assert any("tcp dport 9999" in command and "celatim-allowed" in command for command in commands)
    assert any("counter drop" in command for command in commands)
