"""NAT run (E7): send an IP-ID covert channel THROUGH a real Linux MASQUERADE router
and see whether the IP ID survives. Validates the `survivability=nat_rewritten` label.

Usage: python run_nat.py <payload>
"""

from __future__ import annotations

import subprocess
import sys
import time

import lab

from celatim.catalog import load_mechanisms
from celatim.channel.framer import Framer
from celatim.channel.registry import codec_for

OUT = "/tmp/recovered_nat"
MECH = "ipv4-id-atomic"


def mac(ns: str, dev: str) -> str:
    out = subprocess.check_output(["ip", "-n", ns, "link", "show", dev]).decode()
    return next(line.split()[1] for line in out.splitlines() if "link/ether" in line)


def main() -> None:
    payload = sys.argv[1].encode()
    m = next(x for x in load_mechanisms(lab.CATALOG) if x.id == MECH)
    n = len(Framer(codec_for(m)).encode(payload))

    lab.topo_nat_up()
    try:
        cap = subprocess.Popen(
            ["ip", "netns", "exec", "rcv", "python3", "lab.py", "capture", MECH, "vr", str(n), OUT]
        )
        time.sleep(2.5)
        # snd -> router's snd-side MAC; IP src 192.168.9.2, dst 10.10.0.2 (routed + NAT'd)
        subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                "snd",
                "python3",
                "lab.py",
                "inject",
                MECH,
                payload.hex(),
                mac("snd", "vs"),
                mac("rtr", "r0"),
                "192.168.9.2",
                "10.10.0.2",
            ],
            check=True,
        )
        cap.wait(timeout=15)
        recovered = open(OUT, "rb").read()  # noqa: SIM115
    finally:
        lab.topo_down()
        subprocess.run(["ip", "netns", "del", "rtr"], stderr=subprocess.DEVNULL)

    survived = recovered == payload
    print(
        f"RESULT nat=MASQUERADE mechanism={MECH} sent={payload!r} recovered={recovered!r} "
        f"{'IP-ID SURVIVED NAT' if survived else 'IP-ID REWRITTEN BY NAT'}"
    )


if __name__ == "__main__":
    main()
