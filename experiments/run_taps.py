"""Three-tap survivability localization (improves E5/E6).

Captures the covert field at THREE points around the middlebox — its ingress (ma), its
egress (mb), and the receiver (vr) — and reports the recovered payload at each. This
turns "the channel died" into "the field was intact at the middlebox ingress and gone at
its egress", i.e. it localizes exactly where a bit dies (testbed.md 4.2).

Usage: python run_taps.py <mechanism> <payload> <pass|scrub-mech-id>
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import lab

from celatim.catalog import load_mechanisms
from celatim.channel.framer import Framer
from celatim.channel.registry import codec_for

TAPS = {
    "A_mbox_ingress": ("mbox", "ma"),
    "B_mbox_egress": ("mbox", "mb"),
    "C_receiver": ("rcv", "vr"),
}


def mac(ns: str, dev: str) -> str:
    out = subprocess.check_output(["ip", "-n", ns, "link", "show", dev]).decode()
    return next(line.split()[1] for line in out.splitlines() if "link/ether" in line)


def main() -> None:
    mech_id, text, scrub = sys.argv[1], sys.argv[2], sys.argv[3]
    payload = text.encode()
    m = next(x for x in load_mechanisms(lab.CATALOG) if x.id == mech_id)
    n = len(Framer(codec_for(m)).encode(payload))

    lab.topo_down()
    lab.topo3_up()
    procs = {}
    out = {tap: f"/tmp/tap_{tap}" for tap in TAPS}
    status_paths = {tap: f"/tmp/tap_{tap}_status.json" for tap in TAPS}
    for path in (*out.values(), *status_paths.values()):
        Path(path).unlink(missing_ok=True)
    try:
        for tap, (ns, dev) in TAPS.items():
            procs[tap] = subprocess.Popen(
                [
                    "ip",
                    "netns",
                    "exec",
                    ns,
                    "python3",
                    "lab.py",
                    "capture",
                    mech_id,
                    dev,
                    str(n),
                    out[tap],
                    status_paths[tap],
                ]
            )
        fwd = subprocess.Popen(
            ["ip", "netns", "exec", "mbox", "python3", "lab.py", "forward", "ma", "mb", scrub]
        )
        time.sleep(4.0)
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
        for p in procs.values():
            p.wait(timeout=15)
        fwd.terminate()
        fwd.wait(timeout=5)
        recovered = {tap: open(out[tap], "rb").read() for tap in TAPS}  # noqa: SIM115
        status = {tap: json.loads(Path(status_paths[tap]).read_text()) for tap in TAPS}
    finally:
        lab.topo_down()

    print(f"THREE-TAP middlebox={scrub} mechanism={mech_id} sent={payload!r}")
    prev = payload
    for tap in TAPS:
        intact = recovered[tap] == payload
        died = (not intact) and (prev == payload)  # first tap where it breaks
        marker = "  <-- field dies here" if died else ""
        captured = status[tap]["captured_units"]
        expected = status[tap]["expected_units"]
        nonzero = status[tap]["nonzero_units"]
        print(
            f"  {tap:18} {'INTACT' if intact else 'BROKEN'} "
            f"captured={captured}/{expected} nonzero={nonzero}/{captured} "
            f"recovered={recovered[tap]!r}{marker}"
        )
        prev = recovered[tap]


if __name__ == "__main__":
    main()
