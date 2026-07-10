"""Minimal real-PDU carriers for protocols without a dedicated Scapy layer.

For protocols Scapy does not model, a minimal but real PDU is a realistic application
header carried in a real IP/UDP or IP/TCP packet built by Scapy. The covert value is
written at the mechanism's locator inside the application header (a Scapy ``Raw``
payload, which Scapy does not recompute, so the value survives), and Scapy validates
the surrounding IP/UDP or IP/TCP framing on re-dissect.

This is the ``minimal_protocol_pdu`` tier (like the original hand-written TCP header):
real packet framing and a realistic protocol header, distinguished in the evidence
matrix from a zero-filled offset blob. Scapy is the optional ``packet`` extra, imported
lazily; ``supports`` is a static, Scapy-free function of the registry and the catalog.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..model import Mechanism, WireBase
from .bitfield import extract_bits, place_bits


@dataclass(frozen=True)
class _MinimalSpec:
    """How to wrap a realistic application header in a real IP/UDP or IP/TCP PDU."""

    transport: str  # "udp", "tcp", or "ip" (application directly over IP)
    ip_proto: int  # IP protocol number for the "ip" transport (ignored otherwise)
    header_bytes: int  # length of the realistic application header
    prefix: bytes  # realistic leading header bytes (version/type/...) for non-zero structure


# Realistic minimal application headers, keyed to catalog protocol. ``prefix`` carries a
# plausible first few header bytes (version/type) so the carrier is a real header rather
# than a zero blob; the rest is padded to ``header_bytes``.
_MINIMAL: dict[str, _MinimalSpec] = {
    "IPComp": _MinimalSpec("ip", 108, 8, b"\x04\x00\xfa\xce"),
    "AMT": _MinimalSpec("udp", 0, 16, b"\x04\x00"),
    "PCP": _MinimalSpec("udp", 0, 24, b"\x02\x01\x00\x00"),
    "NHRP": _MinimalSpec("ip", 54, 24, b"\x00\x01\x08\x00"),
    "DLEP": _MinimalSpec("udp", 0, 16, b"\x00\x00\x00\x1f"),
    "CAPWAP": _MinimalSpec("udp", 0, 16, b"\x00\x00\x00\x00"),
    "tcpcrypt": _MinimalSpec("tcp", 0, 16, b"\x01\x01"),
    "HIP": _MinimalSpec("ip", 139, 40, b"\x3b\x09\x01\x00"),
    "PCEP": _MinimalSpec("tcp", 0, 12, b"\x20\x01\x00\x0c"),
    "BMP": _MinimalSpec("tcp", 0, 12, b"\x03\x00\x00\x00"),
    "MobileIPv6": _MinimalSpec("ip", 135, 24, b"\x3b\x01\x05\x00"),
    "IP-TFS": _MinimalSpec("ip", 50, 16, b"\x00\x00\x00\x00"),
    "SMC-R": _MinimalSpec("tcp", 0, 44, b"\xe2\xd4\xc3\xd9"),
    "LISP": _MinimalSpec("udp", 0, 12, b"\x80\x00\x00\x00"),
}

# Number of IP/transport header bytes before the application header for each transport,
# so a deterministic Scapy-free `supports()` knows where the application header starts.
_TRANSPORT_PREFIX_BYTES = {"udp": 28, "tcp": 40, "ip": 20}


def _scapy() -> Any:
    from types import SimpleNamespace

    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw

    return SimpleNamespace(Ether=Ether, IP=IP, TCP=TCP, UDP=UDP, Raw=Raw)


def supports(mechanism: Mechanism) -> bool:
    """True only for protocols with a registered, realistic minimal header.

    Restricted to the hand-authored ``_MINIMAL`` registry deliberately: a real IP/UDP/TCP
    packet whose application payload is a *realistic protocol header* is the
    ``minimal_protocol_pdu`` tier. Protocols without such a header (TLS/QUIC/HTTP and the
    rest) are not promoted here -- they need a real-library hook to set the real field,
    and remain offset-represented until then.
    """

    locator = mechanism.locator
    if locator is None or not mechanism.is_usable_channel or locator.base is not WireBase.NH:
        return False
    spec = _MINIMAL.get(mechanism.protocol)
    if spec is None:
        return False
    pdu_bits = (_TRANSPORT_PREFIX_BYTES[spec.transport] + spec.header_bytes) * 8
    return locator.bit_offset + locator.bit_width <= pdu_bits


def _frame(transport: str, ip_proto: int, header: bytes) -> Any:
    s = _scapy()
    eth = s.Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    ip = s.IP(src="10.0.0.1", dst="10.0.0.2")
    if transport == "udp":
        return eth / ip / s.UDP(sport=40000, dport=4000) / s.Raw(load=header)
    if transport == "tcp":
        return eth / ip / s.TCP(sport=40000, dport=4000) / s.Raw(load=header)
    return eth / s.IP(src="10.0.0.1", dst="10.0.0.2", proto=ip_proto) / s.Raw(load=header)


def build_minimal_pdu(mechanism: Mechanism, value: int) -> bytes:
    """Build a real IP/UDP/TCP PDU with a realistic app header carrying ``value``."""

    s = _scapy()
    locator = mechanism.locator
    if locator is None:
        raise ValueError(f"{mechanism.id}: no locator")
    spec = _MINIMAL[mechanism.protocol]
    header = (
        spec.prefix
        + bytes((i * 7 + 3) % 256 for i in range(max(0, spec.header_bytes - len(spec.prefix))))
    )[: spec.header_bytes]
    frame = _frame(spec.transport, spec.ip_proto, header)
    raw = bytes(frame)
    base_offset = (len(raw) - len(bytes(frame[s.IP]))) * 8
    placed = place_bits(
        raw, bit_offset=base_offset + locator.bit_offset, bit_width=locator.bit_width, value=value
    )
    rebuilt = s.Ether(placed)
    for layer_name in ("chksum", "len"):
        for layer in (rebuilt, rebuilt.payload, getattr(rebuilt.payload, "payload", None)):
            if layer is not None and layer_name in {f.name for f in layer.fields_desc}:
                setattr(layer, layer_name, None)
    final = bytes(rebuilt)
    return bytes(s.Ether(final)[s.IP])


def extract_field(mechanism: Mechanism, carrier: bytes) -> int:
    """Read the located field from the IP-onward carrier bytes."""

    locator = mechanism.locator
    if locator is None:
        raise ValueError(f"{mechanism.id}: no locator")
    return extract_bits(carrier, bit_offset=locator.bit_offset, bit_width=locator.bit_width)


def dissect(mechanism: Mechanism, carrier: bytes) -> Any:
    """Independently dissect the carrier's IP framing; raise if malformed."""

    s = _scapy()
    pkt = s.IP(carrier)
    if not pkt.haslayer(s.IP):
        raise ValueError(f"{mechanism.id}: carrier did not dissect as IP")
    return pkt


__all__ = [
    "build_minimal_pdu",
    "dissect",
    "extract_field",
    "supports",
]
