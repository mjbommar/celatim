"""Survivability run: snd -> [middlebox] -> rcv. The middlebox either forwards
unchanged (`pass`) or scrubs a mechanism's field to zero (`scrub:<mech>`).

Usage: python run_mbox.py <mechanism> <payload> <pass|scrub-mech-id>
Reports DELIVERED (channel survived) or DESTROYED (field scrubbed away).
"""

from __future__ import annotations

import subprocess
import sys
import time

import lab

from celatim.catalog import load_mechanisms
from celatim.channel.framer import Framer
from celatim.channel.registry import codec_for

OUT = "/tmp/recovered_mbox"


def mech(mech_id: str):
    for m in load_mechanisms(lab.CATALOG):
        if m.id == mech_id:
            return m
    raise SystemExit(mech_id)


def mac(ns: str, dev: str) -> str:
    out = subprocess.check_output(["ip", "-n", ns, "link", "show", dev]).decode()
    for line in out.splitlines():
        if "link/ether" in line:
            return line.split()[1]
    raise SystemExit(f"{ns}/{dev}")


def main() -> None:
    mech_id, text, scrub = sys.argv[1], sys.argv[2], sys.argv[3]
    payload = text.encode()
    n = len(Framer(codec_for(mech(mech_id))).encode(payload))

    lab.topo_down()
    lab.topo3_up()
    try:
        cap = subprocess.Popen(
            [
                "ip",
                "netns",
                "exec",
                "rcv",
                "python3",
                "lab.py",
                "capture",
                mech_id,
                "vr",
                str(n),
                OUT,
            ]
        )
        fwd = subprocess.Popen(
            ["ip", "netns", "exec", "mbox", "python3", "lab.py", "forward", "ma", "mb", scrub]
        )
        time.sleep(3.5)  # both sniffer and forwarder must attach first
        subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                "snd",
                "python3",
                "lab.py",
                "inject",
                mech_id,
                payload.hex(),
                mac("snd", "vs"),
                mac("rcv", "vr"),
            ],
            check=True,
        )
        cap.wait(timeout=15)
        fwd.terminate()  # capture has what it needs; stop the forwarder deterministically
        fwd.wait(timeout=5)
        recovered = open(OUT, "rb").read()  # noqa: SIM115
    finally:
        lab.topo_down()

    delivered = recovered == payload
    print(
        f"RESULT middlebox={scrub} mechanism={mech_id} sent={payload!r} "
        f"recovered={recovered!r} {'DELIVERED' if delivered else 'DESTROYED'}"
    )


if __name__ == "__main__":
    main()
