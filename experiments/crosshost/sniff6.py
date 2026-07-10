#!/usr/bin/env python3
"""Count selected IPv4/TCP frames received through an AF_PACKET interface."""

from __future__ import annotations

import argparse
import socket
import struct
import time
from collections.abc import Sequence
from pathlib import Path


def count_frames(
    *,
    duration_s: float,
    interface: str,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
) -> int:
    frame_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    frame_socket.bind((interface, 0))
    frame_socket.settimeout(1.0)
    wanted_source = socket.inet_aton(source_ip)
    wanted_destination = socket.inet_aton(destination_ip)
    count = 0
    end = time.monotonic() + duration_s
    try:
        while time.monotonic() < end:
            try:
                frame = frame_socket.recv(65535)
            except TimeoutError:
                continue
            if len(frame) < 14 + 20 + 20 or frame[12:14] != b"\x08\x00":
                continue
            packet = frame[14:]
            if packet[9] != socket.IPPROTO_TCP:
                continue
            if packet[12:16] != wanted_source or packet[16:20] != wanted_destination:
                continue
            header_length = (packet[0] & 0x0F) * 4
            ports = struct.unpack(">HH", packet[header_length : header_length + 4])
            if ports == (source_port, destination_port):
                count += 1
    finally:
        frame_socket.close()
    return count


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration-s", type=float, default=15.0)
    parser.add_argument("--interface", default="vxlan0")
    parser.add_argument("--source-ip", default="10.200.0.7")
    parser.add_argument("--destination-ip", default="10.200.0.6")
    parser.add_argument("--source-port", type=int, default=40000)
    parser.add_argument("--destination-port", type=int, default=443)
    parser.add_argument("--output", type=Path, default=Path("sniff6-count.txt"))
    args = parser.parse_args(argv)

    count = count_frames(
        duration_s=args.duration_s,
        interface=args.interface,
        source_ip=args.source_ip,
        destination_ip=args.destination_ip,
        source_port=args.source_port,
        destination_port=args.destination_port,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(f"{count}\n")
    print("CAPTURED", count)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
