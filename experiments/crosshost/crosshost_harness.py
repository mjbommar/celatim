#!/usr/bin/env python3
"""Cross-host covert-channel harness: real s7 -> s6 transmission per mechanism.

For each packet-path mechanism: dry-run to get the frame count + per-mechanism L4 config,
launch the celatim receiver on s6 over the VXLAN overlay, send from s7, verify the
recovered payload byte-for-byte. Emits a JSON + a green/red table.

Run on s7:  python crosshost_harness.py [mech1 mech2 ...]   (default: all afpacket mechs)
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "/nas4/data/celatim/measurement/src")
from celatim.adapter import adapter_for
from celatim.catalog import load_mechanisms
from celatim.testbed.packet_path import default_ipv4_packet_path_config_for

VENV = "/nas4/data/celatim/venv/bin"
CATALOG = "/nas4/data/celatim/measurement/data/mechanisms.jsonl"
NAS = "/nas4/data/celatim"
# overlay
S7_VX, S6_VX = "10.200.0.7", "10.200.0.6"
S7_MAC, S6_MAC = "52:ff:ab:1b:a1:69", "8a:7c:91:39:8e:35"
IFACE = "vxlan0"
PAYLOAD = b"the quick brown fox covertly jumps s7->s6 0123456789"


def afpacket_mechs() -> list[str]:
    ms = [m for m in load_mechanisms(Path(CATALOG)) if m.is_usable_channel]
    return [m.id for m in ms if adapter_for(m).supports_transport("afpacket_ipv4")]


def run(mech: str) -> dict:
    cfg = default_ipv4_packet_path_config_for(mech)
    proto = cfg.protocol.value  # 'tcp' | 'udp'
    dport = str(cfg.dst_port)
    sid = f"xh-{mech}"
    res_path = f"{NAS}/xhres_{mech}.json"
    Path(res_path).unlink(missing_ok=True)

    # 1) frame count via a local dry send
    dry = f"/tmp/dry_{mech}.json"
    subprocess.run(
        [
            f"{VENV}/celatim",
            "send",
            "--mechanism",
            mech,
            "--hex",
            PAYLOAD.hex(),
            "--session-id",
            "dry",
            "--output",
            dry,
        ],
        capture_output=True,
        text=True,
    )
    try:
        nf = json.loads(Path(dry).read_text())["carrier_units"]
    except Exception as e:
        return {"mechanism": mech, "result": "skip", "reason": f"dry-run failed: {e}"}

    common = [
        "--mechanism",
        mech,
        "--session-id",
        sid,
        "--afpacket-protocol",
        proto,
        "--afpacket-src-mac",
        S7_MAC,
        "--afpacket-dst-mac",
        S6_MAC,
        "--afpacket-src-ip",
        S7_VX,
        "--afpacket-dst-ip",
        S6_VX,
        "--afpacket-src-port",
        "40000",
        "--afpacket-dst-port",
        dport,
    ]
    # 2) receiver on s6 (background ssh, blocks until N frames or timeout)
    recv_cmd = (
        f"sudo {VENV}/celatim recv --afpacket-ipv4 "
        + " ".join(common)
        + f" --expected-frames {nf} --afpacket-receiver-interface {IFACE} "
        f"--afpacket-timeout-s 30 --output {res_path}"
    )
    recv = subprocess.Popen(
        ["ssh", "s6", recv_cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    time.sleep(6)  # let the receiver bind

    # 3) send from s7
    send = subprocess.run(
        [
            "sudo",
            f"{VENV}/celatim",
            "send",
            "--afpacket-ipv4",
            *common,
            "--hex",
            PAYLOAD.hex(),
            "--afpacket-sender-interface",
            IFACE,
            "--unit-rate-hz",
            "800",  # pace to avoid burst loss on high-frame-count mechanisms
            "--output",
            f"/tmp/send_{mech}.json",
        ],
        capture_output=True,
        text=True,
    )
    try:
        recv.wait(timeout=40)
    except subprocess.TimeoutExpired:
        recv.kill()

    # 4) verify (read on s6 to dodge NAS sync lag)
    got = subprocess.run(
        ["ssh", "s6", f"cat {res_path} 2>/dev/null || true"],
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not got:
        return {
            "mechanism": mech,
            "result": "fail",
            "reason": "no recv json",
            "frames": nf,
            "send_rc": send.returncode,
        }
    d = json.loads(got)
    ok = bytes.fromhex(d["recovered_hex"]) == PAYLOAD
    return {
        "mechanism": mech,
        "result": "pass" if ok else "fail",
        "frames": nf,
        "proto": proto,
        "dport": dport,
        "recv_sha": d["recovered_sha256"][:12],
    }


def main() -> int:
    mechs = sys.argv[1:] or afpacket_mechs()
    print(f"# cross-host harness: {len(mechs)} mechanisms s7->s6 over {IFACE}\n")
    results = []
    for i, m in enumerate(mechs, 1):
        r = run(m)
        results.append(r)
        flag = {"pass": "PASS", "fail": "FAIL", "skip": "SKIP"}[r["result"]]
        print(f"[{i:2}/{len(mechs)}] {flag:4} {m:26} {r.get('reason', '')}", flush=True)
    Path(f"{NAS}/crosshost_results.json").write_text(json.dumps(results, indent=2))
    npass = sum(1 for r in results if r["result"] == "pass")
    print(
        f"\nGREEN {npass}/{len(results)}  "
        f"(fail {sum(1 for r in results if r['result'] == 'fail')}, "
        f"skip {sum(1 for r in results if r['result'] == 'skip')})"
    )
    return 0 if npass == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
