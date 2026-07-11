"""Three-tap IPv4-ID channel run through a real nftables default-drop firewall.

Usage: python run_firewall.py <payload> [--zero]

The forwarding policy admits only the experiment's TCP destination and drops all other
forwarded traffic. A denied ICMP probe and nftables counters prove the firewall hook was
active during each data or field-zero-control run.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import lab

from celatim.catalog import load_mechanisms
from celatim.channel.framer import Framer
from celatim.channel.registry import codec_for

MECH = "ipv4-id-atomic"
LAB_SCRIPT = Path(__file__).with_name("lab.py")
PRIVATE_SENDER_IP = "192.168.9.2"
TAPS = {
    "A_firewall_ingress": ("rtr", "r0", PRIVATE_SENDER_IP),
    "B_firewall_egress": ("rtr", "r1", PRIVATE_SENDER_IP),
    "C_receiver": ("rcv", "vr", PRIVATE_SENDER_IP),
}


def mac(ns: str, dev: str) -> str:
    output = subprocess.check_output(["ip", "-n", ns, "link", "show", dev]).decode()
    return next(line.split()[1] for line in output.splitlines() if "link/ether" in line)


def _paths(tap: str) -> tuple[Path, Path]:
    return Path(f"/tmp/firewall_{tap}"), Path(f"/tmp/firewall_{tap}_status.json")


def _parse_nft_counters(document: dict[str, Any]) -> dict[str, int]:
    counters: dict[str, int] = {}
    for entry in document["nftables"]:
        rule = entry.get("rule")
        if not rule or not rule.get("comment"):
            continue
        counter = next(
            (
                expression["counter"]
                for expression in rule.get("expr", [])
                if "counter" in expression
            ),
            None,
        )
        if counter is not None:
            counters[str(rule["comment"])] = int(counter["packets"])
    return counters


def _nft_counters() -> dict[str, int]:
    return _parse_nft_counters(
        json.loads(
            subprocess.check_output(
                [
                    "ip",
                    "netns",
                    "exec",
                    "rtr",
                    "nft",
                    "-j",
                    "list",
                    "chain",
                    "inet",
                    "celatim_filter",
                    "forward",
                ]
            )
        )
    )


def main() -> None:
    if len(sys.argv) not in {2, 3} or (len(sys.argv) == 3 and sys.argv[2] != "--zero"):
        raise SystemExit("usage: python run_firewall.py <payload> [--zero]")
    payload = sys.argv[1].encode()
    force_zero = len(sys.argv) == 3
    mechanism = next(item for item in load_mechanisms(lab.CATALOG) if item.id == MECH)
    expected_units = len(Framer(codec_for(mechanism)).encode(payload))
    output_paths = {tap: _paths(tap) for tap in TAPS}
    for paths in output_paths.values():
        for path in paths:
            path.unlink(missing_ok=True)

    lab.topo_firewall_up()
    processes: dict[str, subprocess.Popen[bytes]] = {}
    try:
        implementation = subprocess.check_output(
            ["ip", "netns", "exec", "rtr", "nft", "--version"], text=True
        ).strip()
        for tap, (namespace, device, source_ip) in TAPS.items():
            output_path, status_path = output_paths[tap]
            processes[tap] = subprocess.Popen(
                [
                    "ip",
                    "netns",
                    "exec",
                    namespace,
                    "python3",
                    str(LAB_SCRIPT),
                    "capture",
                    MECH,
                    device,
                    str(expected_units),
                    str(output_path),
                    str(status_path),
                    source_ip,
                ]
            )
        time.sleep(2.5)
        command = [
            "ip",
            "netns",
            "exec",
            "snd",
            "python3",
            str(LAB_SCRIPT),
            "inject",
            MECH,
            payload.hex(),
            mac("snd", "vs"),
            mac("rtr", "r0"),
            PRIVATE_SENDER_IP,
            lab.RCV_IP,
        ]
        if force_zero:
            command.append("--zero")
        subprocess.run(command, check=True)
        for process in processes.values():
            process.wait(timeout=15)
        recovered = {
            tap: output_path.read_bytes() for tap, (output_path, _) in output_paths.items()
        }
        statuses = {
            tap: json.loads(status_path.read_text())
            for tap, (_, status_path) in output_paths.items()
        }
        denied_probe = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                "snd",
                "ping",
                "-c",
                "1",
                "-W",
                "1",
                lab.RCV_IP,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        counters = _nft_counters()
    finally:
        lab.topo_down()

    mode = "field_zero_control" if force_zero else "channel_data"
    print(f"MIDDLEBOX implementation={implementation}")
    print(f"THREE-TAP middlebox=linux_nftables mechanism={MECH} mode={mode}")
    valid = True
    for tap in TAPS:
        status = statuses[tap]
        complete = (
            status["captured_units"] == expected_units
            and status["expected_units"] == expected_units
        )
        if force_zero:
            matched = complete and status["nonzero_units"] == 0 and recovered[tap] == b""
            state = "ZERO" if matched else "BROKEN"
        else:
            matched = complete and recovered[tap] == payload
            state = "INTACT" if matched else "BROKEN"
        valid = valid and matched
        print(
            f"  {tap:18} {state} captured={status['captured_units']}/"
            f"{status['expected_units']} nonzero={status['nonzero_units']}/"
            f"{status['captured_units']} recovered={recovered[tap]!r}"
        )
    allowed_packets = counters.get("celatim-allowed", 0)
    denied_packets = counters.get("celatim-denied", 0)
    denied_probe_blocked = denied_probe.returncode != 0
    print(
        f"FIREWALL-CONTROL allowed_packets={allowed_packets} "
        f"denied_packets={denied_packets} "
        f"denied_probe_blocked={str(denied_probe_blocked).lower()}"
    )
    if (
        not valid
        or allowed_packets < expected_units
        or denied_packets < 1
        or not denied_probe_blocked
    ):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
