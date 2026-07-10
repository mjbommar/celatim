"""Offline pcap scrubbers for detector/scrub validation.

The functions in this module are executable countermeasure checks, not live
middlebox claims. They operate on reviewer pcaps and emit provenance so a scrubbed
artifact can be hashed into a private bundle.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCRUB_REPORT_SCHEMA_VERSION = "celatim.scrub_report.v1"
SCRUB_CLAIM_STATUS = "same_code_offline_pcap_scrub_smoke_not_live_middlebox"

_PCAP_GLOBAL = struct.Struct("<IHHIIII")
_PCAP_PACKET = struct.Struct("<IIII")
_PCAP_MAGIC = 0xA1B2C3D4
_PCAP_LINKTYPE_ETHERNET = 1
_ETHERNET_HEADER_BYTES = 14
_ETHERTYPE_IPV4 = 0x0800
_IPPROTO_TCP = 6
_TCP_RESERVED_BYTE_OFFSET = 12
_TCP_CHECKSUM_OFFSET = 16


@dataclass(frozen=True)
class ScrubArtifact:
    path: str
    sha256: str
    size_bytes: int

    @classmethod
    def from_path(cls, path: Path | str) -> ScrubArtifact:
        active = Path(path)
        data = active.read_bytes()
        return cls(
            path=str(active),
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class PcapScrubReport:
    schema_version: str
    ok: bool
    mechanism_id: str
    claim_status: str
    command: tuple[str, ...]
    input: ScrubArtifact
    output: ScrubArtifact
    packet_count: int
    checked_unit_count: int
    scrubbed_unit_count: int
    before_matched_unit_count: int
    after_matched_unit_count: int
    unchanged_unit_count: int
    error: str | None

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "ok": self.ok,
            "mechanism_id": self.mechanism_id,
            "claim_status": self.claim_status,
            "command": list(self.command),
            "input": self.input.to_json(),
            "output": self.output.to_json(),
            "packet_count": self.packet_count,
            "checked_unit_count": self.checked_unit_count,
            "scrubbed_unit_count": self.scrubbed_unit_count,
            "before_matched_unit_count": self.before_matched_unit_count,
            "after_matched_unit_count": self.after_matched_unit_count,
            "unchanged_unit_count": self.unchanged_unit_count,
            "error": self.error,
        }


@dataclass(frozen=True)
class _PcapPacket:
    header: bytes
    frame: bytes


@dataclass(frozen=True)
class _ScrubbedFrame:
    frame: bytes
    checked: bool
    before_matched: bool
    after_matched: bool
    scrubbed: bool


def scrub_pcap(
    mechanism_id: str,
    input_pcap: Path | str,
    output_pcap: Path | str,
    *,
    command: tuple[str, ...] = (),
) -> PcapScrubReport:
    """Scrub one supported mechanism from a pcap and return a report."""

    if mechanism_id != "tcp-reserved-bits":
        raise ValueError(f"{mechanism_id}: no pcap scrubber is available")
    return scrub_tcp_reserved_bits_pcap(input_pcap, output_pcap, command=command)


def scrub_tcp_reserved_bits_pcap(
    input_pcap: Path | str,
    output_pcap: Path | str,
    *,
    command: tuple[str, ...] = (),
) -> PcapScrubReport:
    """Canonicalize TCP reserved bits to zero in a classic Ethernet pcap."""

    input_path = Path(input_pcap)
    output_path = Path(output_pcap)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    error: str | None = None
    try:
        global_header, packets = _read_classic_ethernet_pcap(input_path)
        scrubbed = tuple(_scrub_tcp_reserved_bits_frame(packet.frame) for packet in packets)
        _write_classic_pcap(
            output_path,
            global_header,
            tuple(
                _PcapPacket(header=packet.header, frame=result.frame)
                for packet, result in zip(packets, scrubbed, strict=True)
            ),
        )
    except Exception as exc:
        output_path.write_bytes(b"")
        error = str(exc)
        packets = ()
        scrubbed = ()
    before_matches = sum(1 for result in scrubbed if result.before_matched)
    after_matches = sum(1 for result in scrubbed if result.after_matched)
    checked = sum(1 for result in scrubbed if result.checked)
    scrubbed_count = sum(1 for result in scrubbed if result.scrubbed)
    return PcapScrubReport(
        schema_version=SCRUB_REPORT_SCHEMA_VERSION,
        ok=error is None and after_matches == 0,
        mechanism_id="tcp-reserved-bits",
        claim_status=SCRUB_CLAIM_STATUS,
        command=command,
        input=ScrubArtifact.from_path(input_path),
        output=ScrubArtifact.from_path(output_path),
        packet_count=len(packets),
        checked_unit_count=checked,
        scrubbed_unit_count=scrubbed_count,
        before_matched_unit_count=before_matches,
        after_matched_unit_count=after_matches,
        unchanged_unit_count=max(checked - scrubbed_count, 0),
        error=error,
    )


def _read_classic_ethernet_pcap(path: Path) -> tuple[bytes, tuple[_PcapPacket, ...]]:
    data = path.read_bytes()
    if len(data) < _PCAP_GLOBAL.size:
        raise ValueError("pcap is shorter than the global header")
    global_header = data[: _PCAP_GLOBAL.size]
    magic, _major, _minor, _zone, _sigfigs, _snaplen, linktype = _PCAP_GLOBAL.unpack(global_header)
    if magic != _PCAP_MAGIC:
        raise ValueError("only little-endian classic pcap is supported")
    if linktype != _PCAP_LINKTYPE_ETHERNET:
        raise ValueError("only Ethernet-linktype pcaps are supported")
    offset = _PCAP_GLOBAL.size
    packets: list[_PcapPacket] = []
    while offset + _PCAP_PACKET.size <= len(data):
        header = data[offset : offset + _PCAP_PACKET.size]
        _ts_sec, _ts_usec, incl_len, _orig_len = _PCAP_PACKET.unpack(header)
        offset += _PCAP_PACKET.size
        frame = data[offset : offset + incl_len]
        offset += incl_len
        if len(frame) != incl_len:
            raise ValueError("truncated pcap packet")
        packets.append(_PcapPacket(header=header, frame=frame))
    if offset != len(data):
        raise ValueError("trailing bytes after final pcap packet")
    return global_header, tuple(packets)


def _write_classic_pcap(path: Path, global_header: bytes, packets: tuple[_PcapPacket, ...]) -> None:
    with path.open("wb") as fh:
        fh.write(global_header)
        for packet in packets:
            ts_sec, ts_usec, _incl_len, _orig_len = _PCAP_PACKET.unpack(packet.header)
            frame_len = len(packet.frame)
            fh.write(_PCAP_PACKET.pack(ts_sec, ts_usec, frame_len, frame_len))
            fh.write(packet.frame)


def _scrub_tcp_reserved_bits_frame(frame: bytes) -> _ScrubbedFrame:
    tcp_start, tcp_end, src_ip, dst_ip = _tcp_region(frame)
    if tcp_start is None or tcp_end is None or src_ip is None or dst_ip is None:
        return _ScrubbedFrame(
            frame=frame,
            checked=False,
            before_matched=False,
            after_matched=False,
            scrubbed=False,
        )
    reserved_index = tcp_start + _TCP_RESERVED_BYTE_OFFSET
    before_matched = (frame[reserved_index] & 0x0F) != 0
    if not before_matched:
        return _ScrubbedFrame(
            frame=frame,
            checked=True,
            before_matched=False,
            after_matched=False,
            scrubbed=False,
        )
    mutable = bytearray(frame)
    mutable[reserved_index] &= 0xF0
    _rewrite_tcp_checksum(mutable, tcp_start, tcp_end, src_ip, dst_ip)
    after_matched = (mutable[reserved_index] & 0x0F) != 0
    return _ScrubbedFrame(
        frame=bytes(mutable),
        checked=True,
        before_matched=True,
        after_matched=after_matched,
        scrubbed=not after_matched,
    )


def _tcp_region(frame: bytes) -> tuple[int | None, int | None, bytes | None, bytes | None]:
    if len(frame) < _ETHERNET_HEADER_BYTES + 20:
        return None, None, None, None
    ethertype = int.from_bytes(frame[12:14], "big")
    if ethertype != _ETHERTYPE_IPV4:
        return None, None, None, None
    ip_start = _ETHERNET_HEADER_BYTES
    version_ihl = frame[ip_start]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4 or ihl < 20:
        return None, None, None, None
    ip_end_min = ip_start + ihl
    if len(frame) < ip_end_min:
        return None, None, None, None
    total_length = int.from_bytes(frame[ip_start + 2 : ip_start + 4], "big")
    if total_length < ihl or len(frame) < ip_start + total_length:
        return None, None, None, None
    flags_fragment = int.from_bytes(frame[ip_start + 6 : ip_start + 8], "big")
    if flags_fragment & 0x3FFF:
        return None, None, None, None
    if frame[ip_start + 9] != _IPPROTO_TCP:
        return None, None, None, None
    tcp_start = ip_start + ihl
    tcp_end = ip_start + total_length
    if tcp_end - tcp_start < 20:
        return None, None, None, None
    data_offset = (frame[tcp_start + 12] >> 4) * 4
    if data_offset < 20 or tcp_start + data_offset > tcp_end:
        return None, None, None, None
    return (
        tcp_start,
        tcp_end,
        frame[ip_start + 12 : ip_start + 16],
        frame[ip_start + 16 : ip_start + 20],
    )


def _rewrite_tcp_checksum(
    frame: bytearray,
    tcp_start: int,
    tcp_end: int,
    src_ip: bytes,
    dst_ip: bytes,
) -> None:
    frame[tcp_start + _TCP_CHECKSUM_OFFSET : tcp_start + _TCP_CHECKSUM_OFFSET + 2] = b"\x00\x00"
    segment = bytes(frame[tcp_start:tcp_end])
    pseudo_header = src_ip + dst_ip + bytes([0, _IPPROTO_TCP]) + len(segment).to_bytes(2, "big")
    checksum = _internet_checksum(pseudo_header + segment)
    frame[tcp_start + _TCP_CHECKSUM_OFFSET : tcp_start + _TCP_CHECKSUM_OFFSET + 2] = (
        checksum.to_bytes(2, "big")
    )


def _internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for offset in range(0, len(data), 2):
        total += int.from_bytes(data[offset : offset + 2], "big")
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


__all__ = [
    "SCRUB_CLAIM_STATUS",
    "SCRUB_REPORT_SCHEMA_VERSION",
    "PcapScrubReport",
    "ScrubArtifact",
    "scrub_pcap",
    "scrub_tcp_reserved_bits_pcap",
]
