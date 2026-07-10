#!/usr/bin/env python3
"""Cross-host covert-channel harness: real s7 -> s6 transmission per mechanism.

For each packet-path mechanism: dry-run to get the frame count + per-mechanism L4 config,
launch the celatim receiver on s6 over the VXLAN overlay, send from s7, verify the
recovered payload byte-for-byte. Emits a JSON + a green/red table.

Run on s7:  python crosshost_harness.py [mech1 mech2 ...]   (default: all afpacket mechs)
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
from celatim.adapter import adapter_for  # noqa: E402
from celatim.catalog import load_mechanisms  # noqa: E402
from celatim.testbed.packet_path import default_ipv4_packet_path_config_for  # noqa: E402

CELATIM_BIN = os.environ.get("CELATIM_BIN", str(Path(sys.executable).with_name("celatim")))
CATALOG = PROJECT_ROOT / "data" / "mechanisms.jsonl"
OUTPUT_DIR = Path(os.environ.get("CELATIM_CROSSHOST_OUTPUT_DIR", PROJECT_ROOT / "out/crosshost"))
REMOTE_RESULT_DIR = os.environ.get("CELATIM_REMOTE_RESULT_DIR", "/tmp/celatim-crosshost")
REMOTE_HOST = os.environ.get("CELATIM_REMOTE_HOST", "s6")
# overlay
S7_VX = os.environ.get("CELATIM_SENDER_IP", "10.200.0.7")
S6_VX = os.environ.get("CELATIM_RECEIVER_IP", "10.200.0.6")
S7_MAC = os.environ.get("CELATIM_SENDER_MAC", "52:ff:ab:1b:a1:69")
S6_MAC = os.environ.get("CELATIM_RECEIVER_MAC", "8a:7c:91:39:8e:35")
IFACE = os.environ.get("CELATIM_CROSSHOST_INTERFACE", "vxlan0")
PAYLOAD = b"the quick brown fox covertly jumps s7->s6 0123456789"


def afpacket_mechs() -> list[str]:
    ms = [m for m in load_mechanisms(CATALOG) if m.is_usable_channel]
    return [m.id for m in ms if adapter_for(m).supports_transport("afpacket_ipv4")]


def run(mech: str) -> dict:
    cfg = default_ipv4_packet_path_config_for(mech)
    proto = cfg.protocol.value  # 'tcp' | 'udp'
    dport = str(cfg.dst_port)
    sid = f"xh-{mech}"
    res_path = f"{REMOTE_RESULT_DIR}/xhres_{mech}.json"

    # 1) frame count via a local dry send
    dry = f"/tmp/dry_{mech}.json"
    subprocess.run(
        [
            CELATIM_BIN,
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
        f"mkdir -p {shlex.quote(REMOTE_RESULT_DIR)} && "
        f"sudo {shlex.quote(CELATIM_BIN)} recv --afpacket-ipv4 "
        + " ".join(common)
        + f" --expected-frames {nf} --afpacket-receiver-interface {IFACE} "
        f"--afpacket-timeout-s 30 --output {shlex.quote(res_path)}"
    )
    recv = subprocess.Popen(
        ["ssh", REMOTE_HOST, recv_cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    time.sleep(6)  # let the receiver bind

    # 3) send from s7
    send = subprocess.run(
        [
            "sudo",
            CELATIM_BIN,
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
        ["ssh", REMOTE_HOST, f"cat {shlex.quote(res_path)} 2>/dev/null || true"],
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
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / "crosshost-results.json").write_text(json.dumps(results, indent=2) + "\n")
    npass = sum(1 for r in results if r["result"] == "pass")
    print(
        f"\nGREEN {npass}/{len(results)}  "
        f"(fail {sum(1 for r in results if r['result'] == 'fail')}, "
        f"skip {sum(1 for r in results if r['result'] == 'skip')})"
    )
    return 0 if npass == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
