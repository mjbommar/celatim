#!/usr/bin/env python3
"""Plain AF_PACKET sniffer on s6 vxlan0: count covert frames 10.200.0.7:40000 -> 10.200.0.6:443."""

import socket
import struct
import sys
import time
from pathlib import Path

DUR = float(sys.argv[1]) if len(sys.argv) > 1 else 15.0
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
s.bind(("vxlan0", 0))
s.settimeout(1.0)
want_src = socket.inet_aton("10.200.0.7")
want_dst = socket.inet_aton("10.200.0.6")
n = 0
end = time.monotonic() + DUR
while time.monotonic() < end:
    try:
        f = s.recv(65535)
    except TimeoutError:
        continue
    if len(f) < 14 + 20 + 20:
        continue
    eth_type = f[12:14]
    if eth_type != b"\x08\x00":
        continue
    ip = f[14:]
    if ip[9] != 6:  # tcp
        continue
    if ip[12:16] != want_src or ip[16:20] != want_dst:
        continue
    ihl = (ip[0] & 0x0F) * 4
    sport, dport = struct.unpack(">HH", ip[ihl : ihl + 4])
    if (sport, dport) == (40000, 443):
        n += 1
Path("/nas4/data/celatim/sniff6_count.txt").write_text(str(n))
print("CAPTURED", n)
