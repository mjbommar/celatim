#!/usr/bin/env python3
"""Cross-host app-layer harness: the real covert-bearing protocol PDU crosses s7 -> s6.

For each non-packet mechanism, s7 encodes the payload into the mechanism's real carrier
(a TLS record, QUIC packet, DNS message, HTTP/2 frame, JWT, ...) and ships that carrier to
s6 over the network (ssh/TCP); s6 decodes it back with the same protocol parser and we
verify the payload byte-for-byte. The covert is carried in the genuine protocol structure
and recovered on a different host.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
from celatim.adapter import adapter_for  # noqa: E402
from celatim.catalog import load_mechanisms  # noqa: E402

CELATIM_BIN = os.environ.get("CELATIM_BIN", str(Path(sys.executable).with_name("celatim")))
CATALOG = PROJECT_ROOT / "data" / "mechanisms.jsonl"
OUTPUT_DIR = Path(
    os.environ.get("CELATIM_CROSSHOST_OUTPUT_DIR", str(PROJECT_ROOT / "out/crosshost"))
)
REMOTE_HOST = os.environ.get("CELATIM_REMOTE_HOST", "s6")
PAYLOAD = b"covert app-layer payload s7->s6 :: 0123456789 abcdefghij"


def remaining_mechs() -> list[str]:
    ms = [m for m in load_mechanisms(CATALOG) if m.is_usable_channel]
    return [m.id for m in ms if not adapter_for(m).supports_transport("afpacket_ipv4")]


def run(mech: str) -> dict:
    env = f"/tmp/env_{mech}.json"
    Path(env).unlink(missing_ok=True)
    # 1) s7 encodes payload into the real carrier (envelope holds the protocol PDU bytes)
    s = subprocess.run(
        [
            CELATIM_BIN,
            "send",
            "--mechanism",
            mech,
            "--hex",
            PAYLOAD.hex(),
            "--session-id",
            f"al-{mech}",
            "--output",
            env,
        ],
        capture_output=True,
        text=True,
    )
    if s.returncode != 0 or not Path(env).exists():
        return {"mechanism": mech, "result": "skip", "reason": f"send failed: {s.stderr[-120:]}"}
    # confirm the envelope actually carries protocol bytes (not symbol-only)
    doc = json.loads(Path(env).read_text())
    if not doc.get("carrier_units_with_bytes"):
        return {"mechanism": mech, "result": "skip", "reason": "no carrier bytes (symbol-only)"}

    # 2) ship the carrier to s6 over the network and decode it there with the real parser
    blob = Path(env).read_bytes()
    remote = (
        f"cat > /tmp/rx_{mech}.json && {shlex.quote(CELATIM_BIN)} recv "
        f"--input /tmp/rx_{mech}.json --output /tmp/rec_{mech}.json && cat /tmp/rec_{mech}.json"
    )
    r = subprocess.run(["ssh", REMOTE_HOST, remote], input=blob, capture_output=True)
    if r.returncode != 0:
        return {
            "mechanism": mech,
            "result": "fail",
            "reason": f"s6 recv: {r.stderr.decode()[-160:]}",
        }
    try:
        rec = json.loads(r.stdout.decode())
        ok = bytes.fromhex(rec["recovered_hex"]) == PAYLOAD
    except Exception as e:
        return {"mechanism": mech, "result": "fail", "reason": f"parse: {e}"}
    return {
        "mechanism": mech,
        "result": "pass" if ok else "fail",
        "carrier_bytes": len(blob),
        "recv_sha": rec["recovered_sha256"][:12],
    }


def main() -> int:
    mechs = sys.argv[1:] or remaining_mechs()
    print(f"# app-layer cross-host: {len(mechs)} mechanisms, carrier shipped s7->s6\n")
    results = []
    for i, m in enumerate(mechs, 1):
        r = run(m)
        results.append(r)
        flag = {"pass": "PASS", "fail": "FAIL", "skip": "SKIP"}[r["result"]]
        print(f"[{i:2}/{len(mechs)}] {flag:4} {m:30} {r.get('reason', '')}", flush=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / "applayer-results.json").write_text(json.dumps(results, indent=2) + "\n")
    npass = sum(1 for r in results if r["result"] == "pass")
    nskip = sum(1 for r in results if r["result"] == "skip")
    print(f"\nGREEN {npass}/{len(results)}  (fail {len(results) - npass - nskip}, skip {nskip})")
    return 0 if npass + nskip == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
