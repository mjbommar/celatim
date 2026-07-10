#!/usr/bin/env python3
"""Cross-host message-carrier harness: real protocol PDUs cross s7 -> s6, parsed on s6.

Server (s6): listens on TCP, receives a mechanism's real protocol wire PDUs (DNS TXT/NULL
response, SSH_MSG_KEXINIT, CoAP message, WebSocket frame, BGP UPDATE), parses each with the
real protocol library, decodes the covert payload, and replies with the recovered bytes.
Client (s7): encodes a payload into per-symbol PDUs and ships them to the server.

Usage:  python crosshost_msg.py server [port]
        python crosshost_msg.py client <s6-ip> [port] [mech1 mech2 ...]
"""

from __future__ import annotations

import json
import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, "/nas4/data/celatim/measurement/src")
from celatim.catalog import load_mechanisms
from celatim.channel.framer import Framer
from celatim.channel.registry import codec_for
from celatim.testbed.message_carrier import MESSAGE_CARRIER_KINDS

CATALOG = "/nas4/data/celatim/measurement/data/mechanisms.jsonl"
QNAME = "covert.example."
MECHS = {
    "dns-txt-tunnel": "dns_txt_dnspython",
    "dns-null-tunnel": "dns_null_dnspython",
    "ssh-kexinit-cookie": "ssh_kexinit_paramiko",
    "coap-tunnel": "coap_aiocoap",
    "websocket-tunnel": "websocket_websockets",
    "bgp-optional-transitive": "bgp_scapy",
}
_MS = {m.id: m for m in load_mechanisms(Path(CATALOG))}


def _send(sock: socket.socket, obj: dict) -> None:
    blob = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(blob)) + blob)


def _recv(sock: socket.socket) -> dict:
    hdr = b""
    while len(hdr) < 4:
        hdr += sock.recv(4 - len(hdr))
    n = struct.unpack(">I", hdr)[0]
    buf = b""
    while len(buf) < n:
        buf += sock.recv(n - len(buf))
    return json.loads(buf.decode())


def server(port: int) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(8)
    print(f"server listening on {port}", flush=True)
    while True:
        conn, _ = srv.accept()
        try:
            req = _recv(conn)
            mech = req["mechanism"]
            spec = MESSAGE_CARRIER_KINDS[MECHS[mech]]
            wires = [bytes.fromhex(w) for w in req["wires"]]
            symbols = [spec.parse(w) for w in wires]  # real-library parse on s6
            framer = Framer(codec_for(_MS[mech]))
            payload = framer.decode(symbols)
            _send(
                conn,
                {
                    "recovered_hex": payload.hex(),
                    "node": socket.gethostname(),
                    "server_role": spec.server_role,
                },
            )
        except Exception as e:
            _send(conn, {"error": f"{type(e).__name__}: {e}"})
        finally:
            conn.close()


def client(host: str, port: int, mechs: list[str]) -> int:
    payload = b"covert message-carrier PDU s7->s6 :: real protocol bytes 0123456789"
    npass = 0
    print(f"# message-carrier cross-host: {len(mechs)} mechanisms -> {host}:{port}\n")
    for i, mech in enumerate(mechs, 1):
        spec = MESSAGE_CARRIER_KINDS[MECHS[mech]]
        framer = Framer(codec_for(_MS[mech]))
        symbols = framer.encode(payload)
        try:
            wires = [spec.build(sym, QNAME) for sym in symbols]  # real PDUs on s7
            sock = socket.create_connection((host, port), timeout=20)
            _send(sock, {"mechanism": mech, "wires": [w.hex() for w in wires]})
            resp = _recv(sock)
            sock.close()
            ok = resp.get("recovered_hex") and bytes.fromhex(resp["recovered_hex"]) == payload
            flag = "PASS" if ok else "FAIL"
            if ok:
                npass += 1
            extra = resp.get(
                "error", f"on {resp.get('node', '?')} via {resp.get('server_role', '?')}"
            )
            print(f"[{i}/{len(mechs)}] {flag} {mech:24} {extra}", flush=True)
        except Exception as e:
            print(f"[{i}/{len(mechs)}] FAIL {mech:24} client: {type(e).__name__}: {e}", flush=True)
    print(f"\nGREEN {npass}/{len(mechs)}")
    return 0 if npass == len(mechs) else 1


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "server":
        server(int(sys.argv[2]) if len(sys.argv) > 2 else 9911)
    else:
        host = sys.argv[2]
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 9911
        chosen = sys.argv[4:] or list(MECHS)
        sys.exit(client(host, port, chosen))
