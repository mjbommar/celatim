"""Orchestrate one covert-channel run inside the lab container (run as root, root ns).

Usage: python run.py <mechanism> <payload-string>
Sets up the netns wire, captures in rcv while injecting from snd, decodes, and prints a
PASS/FAIL line plus the recovered payload. Tears the wire down afterwards.
"""

from __future__ import annotations

import subprocess
import sys
import time

import lab

from celatim.catalog import load_mechanisms
from celatim.channel.framer import Framer
from celatim.channel.registry import codec_for

OUT = "/tmp/recovered"


def mech(mech_id: str):
    for m in load_mechanisms(lab.CATALOG):
        if m.id == mech_id:
            return m
    raise SystemExit(f"unknown mechanism {mech_id}")


def mac(ns: str, dev: str) -> str:
    out = subprocess.check_output(["ip", "-n", ns, "link", "show", dev]).decode()
    for line in out.splitlines():
        if "link/ether" in line:
            return line.split()[1]
    raise SystemExit(f"no MAC for {ns}/{dev}")


def main() -> None:
    mech_id, text = sys.argv[1], sys.argv[2]
    payload = text.encode()
    m = mech(mech_id)
    n = len(Framer(codec_for(m)).encode(payload))

    if not lab.calibrate(mech_id):  # pre-flight: inject offset must agree with the detector
        raise SystemExit(f"{mech_id}: harness miscalibrated; aborting before measurement")

    lab.topo_down()  # clean slate
    lab.topo_up()
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
        time.sleep(2.5)  # scapy import + sniff attach is slow; let it bind before traffic
        t0 = time.monotonic()
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
        elapsed = time.monotonic() - t0
        cap.wait(timeout=15)
        with open(OUT, "rb") as fh:
            recovered = fh.read()
    finally:
        lab.topo_down()

    ok = recovered == payload
    cap_bits = codec_for(m).capacity_bits
    goodput = (n * cap_bits) / elapsed if elapsed else 0.0
    print(
        f"RESULT mechanism={mech_id} packets={n} struct_bits/unit={cap_bits} "
        f"covert_bits={n * cap_bits} inject_s={elapsed:.3f} goodput_bps={goodput:.0f} "
        f"sent={payload!r} recovered={recovered!r} {'PASS' if ok else 'FAIL'}"
    )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
