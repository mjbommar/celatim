"""Class F timing-channel battery, graded to the test-evidence standard.

A timing channel carries no covert *bit in a field*: the symbol is the inter-departure
gap between otherwise-identical packets. On the real kernel veth wire we send a reference
frame, then one frame per symbol after a symbol-sized gap; the receiver timestamps the
arrivals, quantizes the gaps back to symbols, and decodes.

  COVERT run  : gaps encode the payload -> receiver recovers it.
  BENIGN CTRL : every gap is the symbol-0 gap (constant rate) -> receiver recovers b"".
                This proves the data is in the *timing*, not the (constant) packet bytes.

GRADING:
  Substrate : real Linux kernel veth path (real scheduling + real arrival timestamps).
  Synthesis : Level 2 -- the emitter is synthesized (we choose the gaps), but the transit
              delay and the arrival clock are real; quantum (10 ms) >> veth latency.
Nothing is hidden; the exit code reflects pass/fail.

Usage: python run_timing.py [payload]
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

import lab

from celatim.catalog import load_mechanisms
from celatim.channel.framer import Framer
from celatim.channel.registry import codec_for

OUT = "/tmp/timing_out"


def mac(ns: str, dev: str) -> str:
    out = subprocess.check_output(["ip", "-n", ns, "link", "show", dev]).decode()
    return next(line.split()[1] for line in out.splitlines() if "link/ether" in line)


def run_once(m, payload: bytes, constant: bool, s: str, d: str) -> bytes:
    n = len(Framer(codec_for(m)).encode(payload))
    if n == 0:
        return b""
    env = {**os.environ, "SND_MAC": s}
    recv = subprocess.Popen(
        ["ip", "netns", "exec", "rcv", "python3", "lab.py", "timing-recv", m.id, "vr", str(n), OUT],
        env=env,
    )
    try:
        time.sleep(1.5)  # let the receiver bind its AF_PACKET socket
        args = [
            "ip",
            "netns",
            "exec",
            "snd",
            "python3",
            "lab.py",
            "timing-send",
            m.id,
            payload.hex(),
            s,
            d,
        ]
        if constant:
            args.append("--constant")
        subprocess.run(args, check=True)
        recv.wait(timeout=25)
        with open(OUT, "rb") as fh:
            return fh.read()
    finally:
        if recv.poll() is None:
            recv.kill()
            recv.wait()


def main() -> None:
    payload = (sys.argv[1] if len(sys.argv) > 1 else "tic").encode()
    timing = [m for m in load_mechanisms(lab.CATALOG) if m.carrier_class.value == "F"]

    lab.topo_down()
    lab.topo_up()
    s, d = mac("snd", "vs"), mac("rcv", "vr")
    rows = {}
    try:
        for m in timing:
            try:
                covert = run_once(m, payload, False, s, d)
                control = run_once(m, payload, True, s, d)
                rows[m.id] = (
                    "PASS" if (covert == payload and control == b"") else "FAIL",
                    covert,
                    control,
                )
            except subprocess.CalledProcessError:
                rows[m.id] = ("UNSUPPORTED", b"", b"")
    finally:
        lab.topo_down()

    npass = sum(1 for v, *_ in rows.values() if v == "PASS")
    print(
        f"=== TIMING BATTERY (real kernel veth, Level-2 synthesis): "
        f"{npass}/{len(rows)} passed [covert recovers payload via inter-arrival AND "
        f"constant-rate control recovers nothing] ==="
    )
    for mid, (v, covert, control) in rows.items():
        detail = "" if v == "PASS" else f"  covert={covert!r} control={control!r}"
        print(f"  {v:12} {mid}{detail}")
    sys.exit(0 if npass == len(rows) else 1)


if __name__ == "__main__":
    main()
