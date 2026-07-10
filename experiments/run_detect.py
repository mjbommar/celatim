"""Detection run (E8): capture covert vs benign traffic to pcap, apply the catalog's
*generated* BPF detector, and count true/false positives.

Usage: python run_detect.py <mechanism> <payload>
"""

from __future__ import annotations

import subprocess
import sys
import time

import lab

from celatim.catalog import load_mechanisms
from celatim.detect import bpf_filter

COVERT = "/tmp/covert.pcap"
BENIGN = "/tmp/benign.pcap"
BASE_FILTER = "ip src 10.10.0.1 and tcp"


def mech(mech_id: str):
    for m in load_mechanisms(lab.CATALOG):
        if m.id == mech_id:
            return m
    raise SystemExit(mech_id)


def mac(ns: str, dev: str) -> str:
    out = subprocess.check_output(["ip", "-n", ns, "link", "show", dev]).decode()
    return next(line.split()[1] for line in out.splitlines() if "link/ether" in line)


def tcpdump_to(path: str) -> subprocess.Popen:
    return subprocess.Popen(
        ["ip", "netns", "exec", "rcv", "tcpdump", "-i", "vr", "-w", path, "-U", BASE_FILTER],
        stderr=subprocess.DEVNULL,
    )


def count(path: str, filt: str) -> int:
    out = subprocess.run(["tcpdump", "-r", path, "-nn", filt], capture_output=True, text=True)
    return sum(1 for line in out.stdout.splitlines() if line.strip())


def main() -> None:
    mech_id, text = sys.argv[1], sys.argv[2]
    m = mech(mech_id)
    detector = bpf_filter(m)
    payload = text.encode()

    lab.topo_down()
    lab.topo_up()
    try:
        s, d = mac("snd", "vs"), mac("rcv", "vr")
        cap = tcpdump_to(COVERT)
        time.sleep(1.5)
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
                s,
                d,
            ],
            check=True,
        )
        time.sleep(0.5)
        cap.terminate()
        cap.wait(timeout=5)

        cap = tcpdump_to(BENIGN)
        time.sleep(1.5)
        subprocess.run(
            ["ip", "netns", "exec", "snd", "python3", "lab.py", "benign", "300", s, d], check=True
        )
        time.sleep(0.5)
        cap.terminate()
        cap.wait(timeout=5)

        c_total, c_hit = count(COVERT, BASE_FILTER), count(COVERT, detector)
        b_total, b_hit = count(BENIGN, BASE_FILTER), count(BENIGN, detector)
    finally:
        lab.topo_down()

    print(f"DETECTOR bpf={detector!r}")
    print(f"COVERT  packets={c_total} flagged={c_hit}  TP_rate={c_hit / max(c_total, 1):.2f}")
    print(f"BENIGN  packets={b_total} flagged={b_hit}  FP_rate={b_hit / max(b_total, 1):.2f}")


if __name__ == "__main__":
    main()
