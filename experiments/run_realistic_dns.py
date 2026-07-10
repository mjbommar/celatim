"""A realistic end-to-end covert channel: real protocol stack, not a crafted packet.

This is the L1 datapoint the reviewer asks for. Nothing here is hand-crafted by us:

  * the carrier is emitted by the **real `dig` client** (ISC BIND's resolver), which puts
    our covert bytes in a real **RFC 7830 EDNS(0) Padding option** (option code 12 — a
    field the spec says the receiver MUST ignore);
  * a **real `dnsmasq` server** receives the query and answers it normally, demonstrating
    the padding rides through a genuine DNS transaction invisibly (the server is none the
    wiser);
  * we recover the covert bytes from the **real query captured on the wire** and decode
    them with the catalog's own codec.

  COVERT  : `dig … +ednsopt=12:<framed payload>` -> we recover the payload from option 12.
  CONTROL : an ordinary `dig … +edns=0` (no padding option) -> nothing to recover.

Substrate: real Linux kernel veth path. Synthesis: **Level 1** for the *send* side — the
carrier is produced by an unmodified real implementation using the field as specified, not
injected by us. (Recovery is still a passive on-wire read, which is exactly how a
cooperating receiver or a censor's DPI would observe it.)

Usage: python run_realistic_dns.py [payload]
"""

from __future__ import annotations

import subprocess
import sys
import time

import lab

from celatim.catalog import load_mechanisms
from celatim.channel.framer import Framer
from celatim.channel.registry import codec_for

PCAP = "/tmp/dns_query.pcap"
PADDING_OPTCODE = 12  # RFC 7830 EDNS(0) Padding


def start_resolver() -> subprocess.Popen:
    """A real dnsmasq, authoritative for covert.test, bound to the receiver address."""
    return subprocess.Popen(
        [
            "ip",
            "netns",
            "exec",
            "rcv",
            "dnsmasq",
            "-d",
            "--conf-file=/dev/null",
            "--no-resolv",
            "--no-hosts",
            "--bind-interfaces",
            f"--listen-address={lab.RCV_IP}",
            "--address=/covert.test/" + lab.RCV_IP,
            "--port=53",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def dig_once(opt_hex: str | None) -> str:
    """Run the real dig client once; return its answer (proves the server replied)."""
    args = [
        "ip",
        "netns",
        "exec",
        "snd",
        "dig",
        f"@{lab.RCV_IP}",
        "-p",
        "53",
        "covert.test",
        "+timeout=2",
        "+tries=1",
        "+short",
    ]
    args += [f"+ednsopt={PADDING_OPTCODE}:{opt_hex}"] if opt_hex else ["+edns=0"]
    return subprocess.run(args, capture_output=True, text=True).stdout.strip()


def padding_from_pcap() -> bytes:
    """Read the EDNS(0) Padding option (code 12) out of the real captured query."""
    from scapy.layers.dns import DNS, DNSRROPT
    from scapy.utils import rdpcap

    for p in rdpcap(PCAP):
        if DNS not in p or p[DNS].qr != 0:
            continue
        ar = p[DNS].ar
        while ar is not None and ar != b"" and not isinstance(ar, int):
            if isinstance(ar, DNSRROPT):
                for tlv in ar.rdata or []:
                    if getattr(tlv, "optcode", None) == PADDING_OPTCODE:
                        return bytes(tlv.optdata)
            ar = ar.payload if hasattr(ar, "payload") and ar.payload else None
    return b""


def run_once(symbol_hex: str | None, n_expected: int) -> tuple[bytes, str]:
    """Capture the real on-wire query for one dig invocation; return (option-12 bytes, answer)."""
    td = subprocess.Popen(
        [
            "ip",
            "netns",
            "exec",
            "rcv",
            "tcpdump",
            "-i",
            "vr",
            "-w",
            PCAP,
            "-c",
            "1",
            f"udp port 53 and src host {lab.SND_IP}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(1.0)
        answer = dig_once(symbol_hex)
        td.wait(timeout=5)
    finally:
        if td.poll() is None:
            td.kill()
            td.wait()
    return padding_from_pcap(), answer


def main() -> None:
    payload = (sys.argv[1] if len(sys.argv) > 1 else "realistic-dns-channel").encode()
    m = next(x for x in load_mechanisms(lab.CATALOG) if x.id == "edns0-padding")
    framer = Framer(codec_for(m))
    symbols = framer.encode(payload)  # each symbol -> one real dig query's padding option

    lab.topo_down()
    lab.topo_up()
    resolver = start_resolver()
    try:
        time.sleep(1.0)  # let dnsmasq bind
        # COVERT: real dig emits each framed symbol as a real EDNS padding option
        recovered_opts, answers = [], []
        for sym in symbols:
            opt, ans = run_once(bytes(sym).hex(), len(symbols))
            recovered_opts.append(opt)
            answers.append(ans)
        recovered = framer.decode(recovered_opts)
        server_answered = all(a == lab.RCV_IP for a in answers)

        # CONTROL: an ordinary EDNS query with no padding option -> nothing to recover
        ctrl_opt, _ = run_once(None, 1)
    finally:
        resolver.terminate()
        resolver.wait()
        lab.topo_down()

    ok = recovered == payload and ctrl_opt == b"" and server_answered
    print("=== REALISTIC DNS CHANNEL (real dig client + real dnsmasq server) ===")
    print("  mechanism      : edns0-padding (RFC 7830 EDNS0 Padding, option 12)")
    print(
        f"  queries (real) : {len(symbols)}  server_answered={server_answered} (covert.test -> {lab.RCV_IP})"
    )
    print(f"  sent           : {payload!r}")
    print(f"  recovered      : {recovered!r}")
    print(f"  control (no pad): option-12 bytes = {ctrl_opt!r} (expected b'')")
    print(
        f"  {'PASS' if ok else 'FAIL'} — covert rides a real DNS transaction; server ignores it; control empty"
    )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
