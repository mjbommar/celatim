"""Generic Scapy-backed real-PDU scaffold for located packet-class mechanisms.

A located storage mechanism (Class A/C header bit or small field) does not need a
bespoke fixture: given the protocol and the ``FieldLocator``, build a realistic PDU
with Scapy (correct neighboring fields, recomputed checksums), write the covert bits
at the locator with :mod:`celatim.pdu.bitfield`, and hand back the base-layer bytes.
Scapy re-dissects the result as the independent validator. This is what collapses the
plaintext L3/L4 catalog onto one adapter instead of dozens of hand-written templates.

Scapy is the optional ``packet`` extra, so it is imported lazily: this module is safe
to import without it, and :func:`supports` returns ``False`` when it is missing.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

from ..model import Mechanism, WireBase
from .bitfield import extract_bits, place_bits

# Canonical, non-zero baseline header fields so every carrier is a real PDU.
_SRC_IP = "10.0.0.1"
_DST_IP = "10.0.0.2"
_SRC_IP6 = "fd00::1"
_DST_IP6 = "fd00::2"
_SRC_MAC = "02:00:00:00:00:01"
_DST_MAC = "02:00:00:00:00:02"
_SPORT = 40000
_DPORT = 443
_PAYLOAD = b"carrier-payload"
_MLD_IPV6_HEADER_BYTES = 40
_MLD_VALUE_BITS = 40

# Static baseline base-layer header sizes (no options/extension headers). Kept here
# so `supports()` is a deterministic, Scapy-free function of the catalog: the
# generated support matrix must classify the same with or without the packet extra
# installed. Only build/extract/dissect actually need Scapy.
_BASE_HEADER_BYTES: dict[str, int] = {
    "TCP": 20,
    "IPv4": 20,
    "UDP": 8,
    "IPv6": 40,
    "ICMP": 8,
    "ICMPv6": 8,
    "IGMP": 8,
    "AH": 12,
    # App protocols: minimum IP-onward PDU bytes containing the located field. The
    # locator base is `nh`, so the carrier and offset are measured from the IP header.
    "RTP": 40,
    "VXLAN": 36,
    "ISAKMP": 56,
    "BFD": 52,
    "L2TP": 40,
    "GRE": 40,
    "STUN": 48,
    "PIM": 24,
    "Diameter": 60,
    "OSPF": 24,
    "NSH": 36,
    "LDP": 50,
    "MLD": 64,
    "DHCP": 280,
    "SCTP": 32,
    "IKEv2": 56,
    "NVGRE": 28,
}
_PROTO_BASE: dict[str, WireBase] = {
    "TCP": WireBase.TH,
    "IPv4": WireBase.NH,
    "UDP": WireBase.TH,
    "IPv6": WireBase.NH,
    "ICMP": WireBase.TH,
    "ICMPv6": WireBase.TH,
    "IGMP": WireBase.TH,
    "AH": WireBase.TH,
    "RTP": WireBase.NH,
    "VXLAN": WireBase.NH,
    "ISAKMP": WireBase.NH,
    "BFD": WireBase.NH,
    "L2TP": WireBase.NH,
    "GRE": WireBase.NH,
    "STUN": WireBase.NH,
    "PIM": WireBase.NH,
    "Diameter": WireBase.NH,
    "OSPF": WireBase.TH,
    "NSH": WireBase.NH,
    "LDP": WireBase.NH,
    "MLD": WireBase.NH,
    "DHCP": WireBase.NH,
    "SCTP": WireBase.TH,
    "IKEv2": WireBase.NH,
    "NVGRE": WireBase.NH,
}


def _scapy() -> Any:
    """Return the Scapy classes used here, raising a clear error if absent."""

    from scapy.contrib.bfd import BFD
    from scapy.contrib.diameter import DiamG
    from scapy.contrib.igmp import IGMP
    from scapy.contrib.ldp import LDP
    from scapy.contrib.nsh import NSH
    from scapy.contrib.ospf import OSPF_Hdr
    from scapy.contrib.pim import PIMv2Hdr
    from scapy.contrib.stun import STUN
    from scapy.layers.dhcp import BOOTP
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import (
        ICMPv6EchoRequest,
        ICMPv6MLQuery,
        IPv6,
    )
    from scapy.layers.ipsec import AH
    from scapy.layers.isakmp import ISAKMP
    from scapy.layers.l2 import GRE, Ether
    from scapy.layers.l2tp import L2TP
    from scapy.layers.rtp import RTP
    from scapy.layers.sctp import SCTP, SCTPChunkData
    from scapy.layers.vxlan import VXLAN
    from scapy.packet import Raw

    return SimpleNamespace(
        Ether=Ether,
        IP=IP,
        IPv6=IPv6,
        TCP=TCP,
        UDP=UDP,
        ICMP=ICMP,
        ICMPv6=ICMPv6EchoRequest,
        IGMP=IGMP,
        AH=AH,
        RTP=RTP,
        VXLAN=VXLAN,
        ISAKMP=ISAKMP,
        BFD=BFD,
        L2TP=L2TP,
        GRE=GRE,
        STUN=STUN,
        PIM=PIMv2Hdr,
        Diameter=DiamG,
        OSPF=OSPF_Hdr,
        NSH=NSH,
        LDP=LDP,
        MLD=ICMPv6MLQuery,
        BOOTP=BOOTP,
        SCTP=SCTP,
        SCTPChunkData=SCTPChunkData,
        Raw=Raw,
    )


@dataclass(frozen=True)
class _ProtoSpec:
    """How to build/wrap a protocol's baseline frame and find the locator's layer."""

    wire_base: WireBase
    build_frame: Any  # () -> scapy packet (full Ether/.../Raw)
    base_layer: Any  # scapy class for the locator base (e.g. TCP, IP)
    wrap_for_checksum: Any  # (base_pkt) -> full pkt giving the checksum pseudo-header


def _specs() -> dict[str, _ProtoSpec]:
    s = _scapy()

    def _eth() -> Any:
        return s.Ether(src=_SRC_MAC, dst=_DST_MAC)

    def _ip() -> Any:
        return s.IP(src=_SRC_IP, dst=_DST_IP)

    def _ip6() -> Any:
        return s.IPv6(src=_SRC_IP6, dst=_DST_IP6)

    def _tcp() -> Any:
        return s.TCP(sport=_SPORT, dport=_DPORT, flags="PA", seq=0x11223344, ack=0x55667788)

    def _udp() -> Any:
        return s.UDP(sport=_SPORT, dport=_DPORT)

    return {
        "TCP": _ProtoSpec(
            wire_base=WireBase.TH,
            build_frame=lambda: _eth() / _ip() / _tcp() / s.Raw(load=_PAYLOAD),
            base_layer=s.TCP,
            wrap_for_checksum=lambda base: _ip() / base,
        ),
        "IPv4": _ProtoSpec(
            wire_base=WireBase.NH,
            build_frame=lambda: _eth() / _ip() / _udp() / s.Raw(load=_PAYLOAD),
            base_layer=s.IP,
            wrap_for_checksum=lambda base: base,
        ),
        "UDP": _ProtoSpec(
            wire_base=WireBase.TH,
            build_frame=lambda: _eth() / _ip() / _udp() / s.Raw(load=_PAYLOAD),
            base_layer=s.UDP,
            wrap_for_checksum=lambda base: _ip() / base,
        ),
        "IPv6": _ProtoSpec(
            wire_base=WireBase.NH,
            build_frame=lambda: _eth() / _ip6() / _udp() / s.Raw(load=_PAYLOAD),
            base_layer=s.IPv6,
            wrap_for_checksum=lambda base: base,
        ),
        # ICMPv4 checksum covers the ICMP message only (no IP pseudo-header).
        "ICMP": _ProtoSpec(
            wire_base=WireBase.TH,
            build_frame=lambda: _eth() / _ip() / s.ICMP() / s.Raw(load=_PAYLOAD),
            base_layer=s.ICMP,
            wrap_for_checksum=lambda base: base,
        ),
        # ICMPv6 checksum covers an IPv6 pseudo-header, so wrap the base in IPv6.
        "ICMPv6": _ProtoSpec(
            wire_base=WireBase.TH,
            build_frame=lambda: _eth() / _ip6() / s.ICMPv6(),
            base_layer=s.ICMPv6,
            wrap_for_checksum=lambda base: _ip6() / base,
        ),
        # IGMP checksum covers the IGMP message only (like ICMPv4).
        "IGMP": _ProtoSpec(
            wire_base=WireBase.TH,
            build_frame=lambda: _eth() / _ip() / s.IGMP(),
            base_layer=s.IGMP,
            wrap_for_checksum=lambda base: base,
        ),
        # AH has no checksum; the reserved field is covered by the AH ICV computation.
        "AH": _ProtoSpec(
            wire_base=WireBase.TH,
            build_frame=lambda: _eth() / _ip() / s.AH() / s.Raw(load=_PAYLOAD),
            base_layer=s.AH,
            wrap_for_checksum=lambda base: base,
        ),
        # Application protocols: the covert field is `nh`-based (offset from IP), so the
        # carrier is the IP-onward bytes of a real IP/UDP/app or IP/app PDU built by Scapy.
        "RTP": _ip_app_spec(_eth() / _ip() / _udp() / s.RTP(), s.IP),
        "VXLAN": _ip_app_spec(_eth() / _ip() / _udp() / s.VXLAN(), s.IP),
        "ISAKMP": _ip_app_spec(_eth() / _ip() / _udp() / s.ISAKMP(), s.IP),
        "BFD": _ip_app_spec(_eth() / _ip() / _udp() / s.BFD(), s.IP),
        "L2TP": _ip_app_spec(_eth() / _ip() / _udp() / s.L2TP(), s.IP),
        "GRE": _ip_app_spec(_eth() / _ip() / s.GRE() / s.Raw(load=_PAYLOAD), s.IP),
        "STUN": _ip_app_spec(_eth() / _ip() / _udp() / s.STUN(), s.IP),
        "PIM": _ip_app_spec(_eth() / _ip() / s.PIM(), s.IP),
        "Diameter": _ip_app_spec(_eth() / _ip() / _tcp() / s.Diameter(), s.IP),
        # OSPF is `th`-based: the carrier is the OSPF message, whose auth field does not
        # overlap the OSPF checksum, so the covert value survives the rebuild.
        "OSPF": _ProtoSpec(
            wire_base=WireBase.TH,
            build_frame=lambda: _eth() / _ip() / s.OSPF(),
            base_layer=s.OSPF,
            wrap_for_checksum=lambda base: base,
        ),
        "NSH": _ip_app_spec(_eth() / _ip() / _udp() / s.NSH(), s.IP),
        "LDP": _ip_app_spec(_eth() / _ip() / _tcp() / s.LDP(), s.IP),
        "DHCP": _ip_app_spec(_eth() / _ip() / _udp() / s.BOOTP(), s.IP),
        "MLD": _ip_app_spec(_eth() / _ip6() / s.MLD(), s.IPv6),
        "IKEv2": _ip_app_spec(_eth() / _ip() / _udp() / s.ISAKMP(), s.IP),
        "NVGRE": _ip_app_spec(
            _eth() / _ip() / s.GRE(key_present=1, key=0x123456) / s.Raw(load=_PAYLOAD), s.IP
        ),
        # SCTP is `th`-based; the chunk-flags/PPID fields live in a real DATA chunk and
        # do not overlap the SCTP common-header CRC32c, so the covert value survives.
        "SCTP": _ProtoSpec(
            wire_base=WireBase.TH,
            build_frame=lambda: _eth() / _ip() / s.SCTP() / s.SCTPChunkData(data=_PAYLOAD),
            base_layer=s.SCTP,
            wrap_for_checksum=lambda base: base,
        ),
    }


def _ip_app_spec(frame: Any, base_layer: Any) -> _ProtoSpec:
    """An `nh`-based application-protocol spec carried in a real IP/UDP/app PDU.

    ``frame`` is eagerly built here only to capture the lambda; the spec rebuilds a
    fresh frame per call. The carrier is the IP-onward bytes; the IP checksum is the
    only one re-derived for the comparison, so ``wrap_for_checksum`` is a no-op.
    """

    return _ProtoSpec(
        wire_base=WireBase.NH,
        build_frame=lambda: frame.copy(),
        base_layer=base_layer,
        wrap_for_checksum=lambda base: base,
    )


def _spec_and_frame(mechanism: Mechanism) -> tuple[_ProtoSpec, Any]:
    spec = _specs()[mechanism.protocol]
    return spec, spec.build_frame()


def _base_bytes(spec: _ProtoSpec, frame: Any) -> bytes:
    return bytes(frame[spec.base_layer])


def supports(mechanism: Mechanism) -> bool:
    """True if the first scaffold increment can build a real PDU for this row.

    Deterministic and Scapy-free (decided from static baseline header sizes): a known
    L3/L4 protocol, a locator whose base matches the protocol, and a field that fits
    inside the baseline base-layer header. Rows needing options, extension headers,
    specific message types, or payload tunnels are handled by later increments.
    """

    locator = mechanism.locator
    if locator is None or not mechanism.is_usable_channel:
        return False
    header_bytes = _BASE_HEADER_BYTES.get(mechanism.protocol)
    if header_bytes is None or locator.base is not _PROTO_BASE[mechanism.protocol]:
        return False
    return locator.bit_offset + locator.bit_width <= header_bytes * 8


def _iter_layers(pkt: Any) -> Any:
    layer = pkt
    while layer is not None and layer.__class__.__name__ != "NoPayload":
        yield layer
        layer = layer.payload if layer.payload else None


def _clear_checksums(pkt: Any) -> None:
    """Reset auto length/checksum fields to ``None`` so Scapy recomputes them."""

    for layer in _iter_layers(pkt):
        field_names = {f.name for f in layer.fields_desc}
        for name in ("chksum", "cksum", "len", "plen"):
            if name in field_names:
                setattr(layer, name, None)


def build_real_pdu(mechanism: Mechanism, value: int) -> bytes:
    """Build a real PDU carrying ``value`` in the located field; return base-layer bytes."""

    if mechanism.id == "mldv1-reserved":
        return _build_mldv1_reserved_pdu(value)

    s = _scapy()
    locator = mechanism.locator
    if locator is None:
        raise ValueError(f"{mechanism.id}: no locator")
    spec, frame = _spec_and_frame(mechanism)

    raw = bytes(frame)  # canonical, checksums valid
    base_offset = len(raw) - len(_base_bytes(spec, frame))
    placed = place_bits(
        raw,
        bit_offset=base_offset * 8 + locator.bit_offset,
        bit_width=locator.bit_width,
        value=value,
    )
    rebuilt = s.Ether(placed)
    _clear_checksums(rebuilt)
    final = bytes(rebuilt)
    return bytes(s.Ether(final)[spec.base_layer])


def extract_field(mechanism: Mechanism, carrier: bytes) -> int:
    """Read the located field MSB-first from base-layer carrier bytes."""

    if mechanism.id == "mldv1-reserved":
        return _extract_mldv1_reserved(carrier)

    locator = mechanism.locator
    if locator is None:
        raise ValueError(f"{mechanism.id}: no locator")
    return extract_bits(carrier, bit_offset=locator.bit_offset, bit_width=locator.bit_width)


def _build_mldv1_reserved_pdu(value: int) -> bytes:
    """Build a valid MLDv1 query carrying 40 bits outside the checksum field.

    The catalog row's capacity comes from receiver-ignored Code (8 bits), Max Response
    Delay (16 bits for this channel model), and Reserved (16 bits). Those fields are
    not contiguous on the wire because the ICMPv6 checksum sits between Code and MRD,
    so the generic locator writer cannot preserve both payload bits and a valid
    checksum for long payloads.
    """

    if not 0 <= value < (1 << _MLD_VALUE_BITS):
        raise ValueError("mldv1-reserved symbol must fit in 40 bits")
    s = _scapy()
    code = (value >> 32) & 0xFF
    mrd = (value >> 16) & 0xFFFF
    reserved = value & 0xFFFF
    frame = (
        s.Ether(src=_SRC_MAC, dst=_DST_MAC)
        / s.IPv6(src=_SRC_IP6, dst=_DST_IP6)
        / s.MLD(code=code, mrd=mrd, reserved=reserved)
    )
    _clear_checksums(frame)
    return bytes(s.Ether(bytes(frame))[s.IPv6])


def _extract_mldv1_reserved(carrier: bytes) -> int:
    if len(carrier) < _MLD_IPV6_HEADER_BYTES + 8:
        raise ValueError("mldv1-reserved carrier is too short")
    offset = _MLD_IPV6_HEADER_BYTES
    code = carrier[offset + 1]
    mrd = int.from_bytes(carrier[offset + 4 : offset + 6], "big")
    reserved = int.from_bytes(carrier[offset + 6 : offset + 8], "big")
    return (code << 32) | (mrd << 16) | reserved


def extract_field_at(carrier: bytes, bit_offset: int, bit_width: int) -> int:
    """Read an arbitrary field (for wrong-offset mutation checks)."""

    return extract_bits(carrier, bit_offset=bit_offset, bit_width=bit_width)


def dissect(mechanism: Mechanism, carrier: bytes) -> Any:
    """Independently dissect the base-layer carrier with Scapy; raise if malformed."""

    spec, _ = _spec_and_frame(mechanism)
    pkt = spec.base_layer(carrier)
    if not pkt.haslayer(spec.base_layer):
        raise ValueError(f"{mechanism.id}: carrier did not dissect as {spec.base_layer.__name__}")
    return pkt


def checksum_valid(mechanism: Mechanism, carrier: bytes) -> bool:
    """True if the carrier's stored checksums equal a fresh recomputation."""

    spec, _ = _spec_and_frame(mechanism)
    embedded = bytes(spec.wrap_for_checksum(spec.base_layer(carrier)))
    fresh = spec.wrap_for_checksum(spec.base_layer(carrier))
    _clear_checksums(fresh)
    return embedded == bytes(fresh)


__all__ = [
    "build_real_pdu",
    "checksum_valid",
    "dissect",
    "extract_field",
    "extract_field_at",
    "supports",
]
