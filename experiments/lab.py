"""Tier-1 lab roles, run inside the privileged container.

Modes (argv):
  topo-up / topo-down            build / tear down the snd<->rcv netns+veth wire
  inject  <mech> <payload_hex> <dst_ip>    [run via: ip netns exec snd]
  capture <mech> <iface> <n> <out_file>    [run via: ip netns exec rcv]

The covert field is written/read at the position given by the mechanism's
``FieldLocator`` (its third reuse: codec encodes -> we inject -> we read back). Packet
plumbing uses scapy; the bit placement and the codec/framer come from celatim.
"""

from __future__ import annotations

import itertools
import json
import os
import subprocess
import sys
from pathlib import Path

from celatim.catalog import load_mechanisms
from celatim.channel.framer import Framer
from celatim.channel.registry import codec_for
from celatim.model import WireBase
from celatim.pdu import (
    RTCP_APP_DATA_LEN,
    build_app_packet,
    build_connection_preface_ping,
    build_initial_packet,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CATALOG = PROJECT_ROOT / "data" / "mechanisms.jsonl"
SND_IP = "10.10.0.1"
RCV_IP = "10.10.0.2"
SND_IP6 = "fd00::1"
RCV_IP6 = "fd00::2"


def _ip_hdr_bits(ipb: bytes | bytearray) -> int:
    """Bits from the IP header start to the transport header (version-aware)."""
    ver = ipb[0] >> 4
    if ver == 4:
        return (ipb[0] & 0x0F) * 32
    if ver == 6:
        return 320  # fixed 40-byte IPv6 header (no extension headers in our templates)
    raise SystemExit(f"unknown IP version {ver}")


def _sh(cmd: str) -> None:
    subprocess.run(cmd, shell=True, check=True)


def topo_up() -> None:
    _sh("ip netns add snd; ip netns add rcv")
    _sh("ip link add vs type veth peer name vr")
    _sh("ip link set vs netns snd; ip link set vr netns rcv")
    _sh(f"ip -n snd addr add {SND_IP}/24 dev vs; ip -n rcv addr add {RCV_IP}/24 dev vr")
    # large MTU so a single packet can hold a large field (e.g. HTTP/3 ~1200 B) without
    # exceeding the link MTU, which silently drops the frame at AF_PACKET send
    _sh("ip -n snd link set dev vs up mtu 16000; ip -n rcv link set dev vr up mtu 16000")
    _sh("ip -n snd link set lo up; ip -n rcv link set lo up")
    if os.environ.get("KEEP_OFFLOADS"):
        return  # E2 control: leave offloads at their defaults
    for ns, dev in (("snd", "vs"), ("rcv", "vr")):
        _sh(
            f"ip netns exec {ns} ethtool -K {dev} tso off gso off gro off lro off "
            f"tx off rx off 2>/dev/null || true"
        )


def topo_down() -> None:
    for ns in ("snd", "mbox", "rtr", "rcv"):
        _sh(f"ip netns del {ns} 2>/dev/null || true")


def topo3_up() -> None:
    """snd <-> mbox <-> rcv: a bump-in-the-wire middlebox between two veth pairs.

    Create each veth *directly* across the two target namespaces. Moving a veth end by
    name after its peer is already in a non-root netns fails under iproute2 6.15
    ("argument netns is wrong"); cross-netns creation avoids the move entirely."""
    _sh("ip netns add snd; ip netns add mbox; ip netns add rcv")
    _sh("ip -n snd link add vs type veth peer name ma netns mbox")  # snd <-> mbox
    _sh("ip -n mbox link add mb type veth peer name vr netns rcv")  # mbox <-> rcv
    _sh(f"ip -n snd addr add {SND_IP}/24 dev vs; ip -n rcv addr add {RCV_IP}/24 dev vr")
    # NB: always use the explicit `dev` keyword — iproute2 prefix-matches bare names to
    # keywords, e.g. `ma` -> `master`, which breaks `ip link set ma up`.
    for ns, dev in (("snd", "vs"), ("rcv", "vr"), ("mbox", "ma"), ("mbox", "mb")):
        _sh(f"ip -n {ns} link set dev {dev} up")
        _sh(
            f"ip netns exec {ns} ethtool -K {dev} gro off lro off rx off tx off 2>/dev/null || true"
        )
    for ns in ("snd", "rcv", "mbox"):
        _sh(f"ip -n {ns} link set dev lo up")


def _topo_router_up() -> None:
    """Build a routed snd(192.168.9.2) -> rtr -> rcv(10.10.0.2) topology."""
    _sh(
        "ip netns del snd 2>/dev/null||true; ip netns del rtr 2>/dev/null||true; ip netns del rcv 2>/dev/null||true"
    )
    _sh("ip netns add snd; ip netns add rtr; ip netns add rcv")
    _sh("ip -n snd link add vs type veth peer name r0 netns rtr")
    _sh("ip -n rtr link add r1 type veth peer name vr netns rcv")
    _sh("ip -n snd addr add 192.168.9.2/24 dev vs")
    _sh("ip -n rtr addr add 192.168.9.1/24 dev r0; ip -n rtr addr add 10.10.0.1/24 dev r1")
    _sh("ip -n rcv addr add 10.10.0.2/24 dev vr")
    for ns, dev in (("snd", "vs"), ("rtr", "r0"), ("rtr", "r1"), ("rcv", "vr")):
        _sh(f"ip -n {ns} link set dev {dev} up")
        _sh(f"ip netns exec {ns} ethtool -K {dev} gro off lro off rx off tx off 2>/dev/null||true")
    for ns in ("snd", "rtr", "rcv"):
        _sh(f"ip -n {ns} link set dev lo up")
    _sh("ip -n snd route add default via 192.168.9.1")
    _sh("ip -n rcv route add default via 10.10.0.1")
    _sh("ip netns exec rtr sysctl -wq net.ipv4.ip_forward=1")


def topo_nat_up() -> None:
    """Build the routed topology with Linux MASQUERADE on receiver-side egress."""
    _topo_router_up()
    _sh("ip netns exec rtr iptables -t nat -A POSTROUTING -o r1 -j MASQUERADE")


def topo_firewall_up() -> None:
    """Build the routed topology with an nftables default-drop forwarding policy."""
    _topo_router_up()
    _sh("ip netns exec rtr nft add table inet celatim_filter")
    _sh(
        "ip netns exec rtr nft 'add chain inet celatim_filter forward "
        "{ type filter hook forward priority 0; policy drop; }'"
    )
    _sh(
        'ip netns exec rtr nft add rule inet celatim_filter forward iifname "r0" '
        'oifname "r1" ip saddr 192.168.9.2 ip daddr 10.10.0.2 tcp dport 9999 '
        'counter accept comment "celatim-allowed"'
    )
    _sh(
        "ip netns exec rtr nft add rule inet celatim_filter forward "
        'counter drop comment "celatim-denied"'
    )


def _mech(mech_id: str):
    for m in load_mechanisms(CATALOG):
        if m.id == mech_id:
            return m
    raise SystemExit(f"unknown mechanism {mech_id}")


def _abs_bit_offset(loc, ip_hdr_bits: int) -> int:
    """Bit offset of the field from the start of the IP packet (we work on IP-onwards).

    NH-base fields sit at a constant offset in the IP header; TH-base fields start after
    the IP header (``ip_hdr_bits``, via :func:`_ip_hdr_bits`). Computing ``ip_hdr_bits``
    wrong silently places a TH-base field inside the IP header — and a round-trip test
    won't catch it because inject and capture share the offset. The BPF detector does."""
    if loc.base is WireBase.NH:
        return loc.bit_offset
    if loc.base is WireBase.TH:
        return ip_hdr_bits + loc.bit_offset
    raise SystemExit(f"base {loc.base} not handled by this harness")


def _write_bits(buf: bytearray, off: int, width: int, value: int) -> None:
    for i in range(width):
        pos = off + i
        bit = (value >> (width - 1 - i)) & 1
        byte_i, bit_i = divmod(pos, 8)
        mask = 1 << (7 - bit_i)
        buf[byte_i] = (buf[byte_i] | mask) if bit else (buf[byte_i] & ~mask)


def _scrub_field(ipb: bytearray, loc) -> None:
    """Zero one located field using the packet's actual IP-header length."""
    _write_bits(ipb, _abs_bit_offset(loc, _ip_hdr_bits(ipb)), loc.bit_width, 0)


def _read_bits(buf: bytes, off: int, width: int) -> int:
    value = 0
    for i in range(width):
        byte_i, bit_i = divmod(off + i, 8)
        value = (value << 1) | ((buf[byte_i] >> (7 - bit_i)) & 1)
    return value


# Protocols the harness can build a representative IPv4 packet for. The covert field
# is placed by wire offset (locator), so any fixed-layout L3/L4 header works; this set
# grows as templates are added. Encapsulation/app/encrypted carriers need their own.
# Arbitrary-content fields (padding / opaque blob / random cookie / custom bits): the
# field genuinely holds arbitrary bytes, so placing covert bytes in the carrier's L4
# payload is an honest carrier. mech_id -> (transport, dport). Graded L2; cooperating
# where the catalog marks the channel cooperating/integrity-bound.
_PAYLOAD_FIELDS = {
    "ssh-random-padding": ("TCP", 22),
    "ssh-kexinit-cookie": ("TCP", 22),
    "tls-record-padding": ("TCP", 443),
    "tls-heartbeat-padding": ("TCP", 443),
    "tls-legacy-session-id": ("TCP", 443),
    "tls-gmt-unix-time": ("TCP", 443),
    "tcpcrypt-reserved": ("TCP", 443),
    "http2-ping-opaque": ("TCP", 443),
    "http2-padding": ("TCP", 443),
    "diameter-flags-padding": ("TCP", 3868),
    "jwt-private-claims": ("TCP", 80),
    "binary-http-padding": ("TCP", 80),
    "pptp-vendor-name": ("TCP", 1723),
    "openpgp-padding-packet": ("TCP", 443),
    "edhoc-ead-padding": ("UDP", 9528),
    "ogg-opus-comment": ("TCP", 443),
    "tzif-unused": ("TCP", 443),
    "uuidv8-custom": ("TCP", 443),
    "smcr-reserved": ("TCP", 9999),
    "ioam-reserved": ("UDP", 4754),
    "owamp-twamp-padding": ("UDP", 861),
    "edns0-padding": ("UDP", 53),
    "stun-attr-padding": ("UDP", 3478),
    "rtp-rtcp-ext-app": ("UDP", 5004),
    # control-plane reserved fields carried at the start of the protocol PDU (offset-
    # represented L2: covert bits at the reserved position survive the wire; not a live
    # routing session -- that is the L1 step with a real daemon).
    "bmp-reserved": ("TCP", 632),
    "ldp-reserved": ("TCP", 646),
    "pcep-reserved": ("TCP", 4189),
    "bgp-path-attr-flags": ("TCP", 179),
    "bgp-ls-asla-reserved": ("TCP", 179),
    "bgp-opaque-ext-comm": ("TCP", 179),
    "bgp-optional-transitive": ("TCP", 179),
    "ripv1-ignored": ("UDP", 520),
    "bfd-auth-reserved": ("UDP", 3784),
    "sbfd-reserved": ("UDP", 7784),
    "dlep-reserved": ("UDP", 854),
    "capwap-reserved": ("UDP", 5246),
    "pcp-reserved": ("UDP", 5351),
    "amt-reserved": ("UDP", 2268),
    "nhrp-reserved": ("IP", 54),
    "rsvp-reserved": ("IP", 46),
    "pim-sm-reserved": ("IP", 103),
    "mobileip6-reserved": ("IP", 135),
    "ospfv3-trailing-byte": ("IP", 89),
    # ---- batch: encapsulation / application / session / network reserved fields ----
    # All offset-represented over a real carrier (see TEST-EVIDENCE.md group (b)).
    # application / session over TCP
    "http2-reserved-r-bit": ("TCP", 443),
    "http2-unused-flags": ("TCP", 443),
    "http2-priority-deprecated": ("TCP", 443),
    "kerberos-kdcoptions": ("TCP", 88),
    "tls-legacy-record-version": ("TCP", 443),
    "tls-grease": ("TCP", 443),
    "tls-clienthello-padding": ("TCP", 443),
    "dns-dso-zbits": ("TCP", 53),
    "turn-rffu": ("TCP", 3478),
    # session / app / encapsulation over UDP
    "dtls-legacy-version": ("UDP", 443),
    "ikev2-reserved": ("UDP", 500),
    "isakmp-reserved": ("UDP", 500),
    "quic-spin-bit": ("UDP", 443),
    "quic-connection-id": ("UDP", 443),
    "quic-grease-bit": ("UDP", 443),
    "quic-reserved-version": ("UDP", 443),
    "http3-reserved-settings": ("UDP", 443),
    "http3-reserved-error-codes": ("UDP", 443),
    "vxlan-reserved": ("UDP", 4789),
    "geneve-reserved": ("UDP", 6081),
    "lisp-dataplane": ("UDP", 4341),
    "lisp-gpe-bits": ("UDP", 4341),
    "lisp-lcaf-reserved": ("UDP", 4342),
    "rtcp-xr-reserved": ("UDP", 5005),
    "rtp-appbits": ("UDP", 5004),
    "rtp-vp8-rbits": ("UDP", 5004),
    "rtp-vp9-reserved": ("UDP", 5004),
    "rtp-h265-fu-res": ("UDP", 5004),
    "stun-transmit-counter": ("UDP", 3478),
    "dns-caa-flags": ("UDP", 53),
    "lorawan-frame": ("UDP", 1700),
    "nsh-unassigned": ("UDP", 4790),
    # carried directly over IP (proto=port)
    "gre-reserved": ("IP", 47),
    "nvgre-flowid": ("IP", 47),
    "ipcomp-flags": ("IP", 108),
    "iptfs-reserved": ("IP", 50),
    "vrrpv3-rsvd": ("IP", 112),
    "ospf-ri-lsa-padding": ("IP", 89),
    "igmpv3-reserved": ("IP", 2),
    "hip-locator-reserved": ("IP", 139),
    "icmp-extended-echo": ("IP", 1),
    "sctp-idata-reserved": ("IP", 132),
    "sctp-padding": ("IP", 132),
    # carried over IPv6 (nh=port): extension-header / ICMPv6-body reserved fields
    "ipv6-frag-reserved": ("IP6", 44),
    "ipv6-rh0-reserved": ("IP6", 43),
    "ipv6-conex-cdo": ("IP6", 0),
    "srv6-srh": ("IP6", 43),
    "srv6-sid-arg": ("IP6", 43),
    "mldv1-reserved": ("IP6", 58),
    # final batch — L2TP (over UDP / over IP) and the IP-option / TCP-option fields
    "l2tpv2-reserved": ("UDP", 1701),
    "l2tpv3-xbits": ("IP", 115),
    "ipv4-options": ("IP", 4),  # 40-byte options-sized field at the IP-payload position
    "tcp-timestamp-lsb": ("TCP", 80),
}

# L2-only carriers (IS-IS / TRILL / MPLS / PPP / BIER): these ride in an Ethernet frame,
# not over IP, so offset-representing them over IP would misstate the carrier. The covert
# rides in the L2 frame payload (base=ll, offset 0) under the protocol's real ethertype,
# captured at the receiver tap with a field-zero control. mech_id -> ethertype.
_L2_FIELDS = {
    "mpls-exp-tc": 0x8847,  # MPLS unicast
    "mpls-mbz": 0x8848,  # MPLS multicast
    "trill-rbits": 0x22F3,  # TRILL
    "bier-reserved": 0xAB37,  # BIER (RFC 8296)
    "isis-eco": 0x88B5,  # IEEE 802 local experimental EtherType 1 (IS-IS truly uses LLC)
    "isis-reverse-metric": 0x88B6,  # local experimental EtherType 2
    "isis-srv6-sid-flags": 0x8999,  # unassigned, distinct for capture filtering
    "ppp-magic-number": 0x8864,  # PPPoE session (PPP magic number lives in LCP)
}


# Per-mechanism templates (keyed by id) override the per-protocol default. Needed when
# one protocol hosts several mechanisms with different packet shapes (e.g. ICMP type 3
# unused vs type 8 echo payload), and for the payload tunnels whose carrier is the L4 body.
def _template_by_id(mech_id: str, src_ip: str, dst_ip: str):
    from scapy.layers.inet import ICMP, IP, TCP, UDP

    def ip():
        return IP(src=src_ip, dst=dst_ip)

    pad = b"\x00" * 1500

    if mech_id == "http2-ping-opaque":
        return (
            ip()
            / TCP(sport=40000, dport=443, flags="PA", seq=1)
            / build_connection_preface_ping(b"\x00" * 8)
        )
    if mech_id == "quic-connection-id":
        return ip() / UDP(sport=40000, dport=443) / build_initial_packet(b"\x00" * 20)
    if mech_id == "rtp-rtcp-ext-app":
        return ip() / UDP(sport=40000, dport=5004) / build_app_packet(b"\x00" * RTCP_APP_DATA_LEN)
    if mech_id in _PAYLOAD_FIELDS:
        transport, port = _PAYLOAD_FIELDS[mech_id]
        if transport == "TCP":
            return ip() / TCP(sport=40000, dport=port, flags="PA", seq=1) / pad
        if transport == "IP":
            # control-plane protocol carried directly over IP (proto=port); the PDU is
            # represented by the IP payload (offset-represented L2, see TEST-EVIDENCE.md).
            return IP(src=src_ip, dst=dst_ip, proto=port) / pad
        if transport == "IP6":
            from scapy.layers.inet6 import IPv6

            # carried over IPv6 (nh=port): extension-header / ICMPv6-body reserved fields.
            return IPv6(src=SND_IP6, dst=RCV_IP6, nh=port) / pad
        return ip() / UDP(sport=40000, dport=port) / pad
    table = {
        # payload tunnels: covert bytes ride in the L4 application payload
        "http-tunnel": lambda: ip() / TCP(sport=40000, dport=80, flags="PA", seq=1) / pad,
        "websocket-tunnel": lambda: ip() / TCP(sport=40000, dport=80, flags="PA", seq=1) / pad,
        "doh-tunnel": lambda: ip() / TCP(sport=40000, dport=443, flags="PA", seq=1) / pad,
        "mqtt-tunnel": lambda: ip() / TCP(sport=40000, dport=1883, flags="PA", seq=1) / pad,
        "coap-tunnel": lambda: ip() / UDP(sport=40000, dport=5683) / pad,
        "dns-txt-tunnel": lambda: ip() / UDP(sport=40000, dport=53) / pad,
        "dns-null-tunnel": lambda: ip() / UDP(sport=40000, dport=53) / pad,
        "webrtc-datachannel": lambda: ip() / UDP(sport=40000, dport=3478) / pad,
        "icmp-echo-payload": lambda: ip() / ICMP(type=8) / pad,
        # arbitrary-content fields (opaque token/blob/padding) -> bytes in the L4 payload is
        # an honest carrier; cooperating-endpoint channels, graded L2.
        "quic-new-token": lambda: ip() / UDP(sport=40000, dport=443) / pad,
        "quic-path-challenge": lambda: ip() / UDP(sport=40000, dport=443) / pad,
        "quic-stateless-reset": lambda: ip() / UDP(sport=40000, dport=443) / pad,
        "quic-reserved-transport-params": lambda: ip() / UDP(sport=40000, dport=443) / pad,
        "http3-reserved-frame-types": lambda: ip() / UDP(sport=40000, dport=443) / pad,
        "http3-reserved-stream-types": lambda: ip() / UDP(sport=40000, dport=443) / pad,
        "doq-reserved-error": lambda: ip() / UDP(sport=40000, dport=853) / pad,
    }
    builder = table.get(mech_id)
    return builder() if builder else None


def _base_packet(m, src_ip: str, dst_ip: str, seq: int):
    """A representative IPv4/IPv6 packet whose header (or payload) carries ``m``'s field."""
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import ICMPv6DestUnreach, IPv6

    by_id = _template_by_id(m.id, src_ip, dst_ip)
    if by_id is not None:
        return by_id
    p = m.protocol
    if p == "ICMP":
        return IP(src=src_ip, dst=dst_ip) / ICMP(type=3) / (b"\x00" * 8)
    if p in ("IPv4", "TCP"):
        return IP(src=src_ip, dst=dst_ip) / TCP(sport=40000, dport=9999, flags="S", seq=seq)
    if p == "UDP":
        return IP(src=src_ip, dst=dst_ip) / UDP(sport=40000, dport=9999) / (b"\x00" * 16)
    if p == "IPv6":
        return IPv6(src=SND_IP6, dst=RCV_IP6) / TCP(sport=40000, dport=9999, flags="S", seq=seq)
    if p == "ICMPv6":
        return IPv6(src=SND_IP6, dst=RCV_IP6) / ICMPv6DestUnreach() / (b"\x00" * 8)
    if p == "SCTP":
        from scapy.layers.sctp import SCTP, SCTPChunkData

        return (
            IP(src=src_ip, dst=dst_ip)
            / SCTP(sport=40000, dport=40000)
            / SCTPChunkData(data=b"\x00" * 16)
        )
    if p == "VXLAN":
        from scapy.layers.inet import UDP
        from scapy.layers.vxlan import VXLAN

        return (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=40000, dport=4789)
            / VXLAN(vni=1)
            / (b"\x00" * 32)
        )
    if p == "GRE":
        from scapy.layers.l2 import GRE

        return IP(src=src_ip, dst=dst_ip, proto=47) / GRE(proto=0x0800) / (b"\x00" * 20)
    if p == "Geneve":
        from scapy.contrib.geneve import GENEVE
        from scapy.layers.inet import UDP

        return IP(src=src_ip, dst=dst_ip) / UDP(sport=40000, dport=6081) / GENEVE() / (b"\x00" * 16)
    if p == "AH":
        from scapy.layers.ipsec import AH

        return (
            IP(src=src_ip, dst=dst_ip, proto=51)
            / AH(spi=1, seq=1, icv=b"\x00" * 12)
            / (b"\x00" * 8)
        )
    if p == "IGMP":
        from scapy.contrib.igmp import IGMP

        return IP(src=src_ip, dst=dst_ip, ttl=1) / IGMP(type=0x11)
    if p == "RIP":
        from scapy.layers.inet import UDP
        from scapy.layers.rip import RIP, RIPEntry

        return IP(src=src_ip, dst=dst_ip) / UDP(sport=520, dport=520) / RIP() / RIPEntry()
    if p == "OSPF":
        from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello

        return IP(src=src_ip, dst=dst_ip, proto=89) / OSPF_Hdr() / OSPF_Hello()
    if p == "DHCP":
        from scapy.layers.dhcp import BOOTP
        from scapy.layers.inet import UDP

        return IP(src=src_ip, dst=dst_ip) / UDP(sport=68, dport=67) / BOOTP()
    if p == "NTP":
        from scapy.layers.inet import UDP
        from scapy.layers.ntp import NTP

        return IP(src=src_ip, dst=dst_ip) / UDP(sport=123, dport=123) / NTP() / (b"\x00" * 460)
    if p == "ESP":
        from scapy.layers.ipsec import ESP

        return IP(src=src_ip, dst=dst_ip, proto=50) / ESP(spi=1, seq=1) / (b"\x00" * 300)
    raise SystemExit(f"no packet template for protocol {p}")


def _reparse(raw: bytes | bytearray):
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6

    return IPv6(bytes(raw)) if (raw[0] >> 4) == 6 else IP(bytes(raw))


def _clear_checksums(pkt) -> None:
    """Drop every parsed checksum so scapy recomputes it (IPv4/TCP/UDP `chksum`,
    ICMPv6 `cksum`); IPv6 has no header checksum."""
    from scapy.packet import NoPayload

    cur = pkt
    while not isinstance(cur, NoPayload):
        # Use Scapy's field API so a parsed packet's raw_packet_cache is invalidated.
        # Mutating ``fields`` directly leaves stale serialized bytes, which receivers on
        # one L2 segment will capture but a routed Linux path correctly drops.
        for field_name in ("chksum", "cksum"):
            if field_name in cur.fields:
                cur.setfieldval(field_name, None)
        cur = cur.payload


def _inject_l2(m, loc, payload: bytes, src_mac: str, dst_mac: str, force_zero: bool) -> None:
    """L2-only carriers: covert rides in the Ethernet-frame payload (base=ll, offset 0)
    under the protocol's real ethertype. No IP, no checksums."""
    import socket

    et = _L2_FIELDS[m.id]
    eth = (
        bytes.fromhex(dst_mac.replace(":", ""))
        + bytes.fromhex(src_mac.replace(":", ""))
        + et.to_bytes(2, "big")
    )
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind(("vs", 0))
    symbols = Framer(codec_for(m)).encode(payload)
    for symbol in symbols:
        body = bytearray(b"\x00" * 1500)
        sym_int = int.from_bytes(symbol, "big") if isinstance(symbol, bytes) else int(symbol)
        value = 0 if force_zero else sym_int
        _write_bits(body, loc.bit_offset, loc.bit_width, value)
        sock.send(eth + bytes(body))
    sock.close()
    print(f"injected {len(symbols)} L2 frames (force_zero={force_zero})", file=sys.stderr)


def inject(
    mech_id: str,
    payload: bytes,
    src_mac: str,
    dst_mac: str,
    src_ip: str = SND_IP,
    dst_ip: str = RCV_IP,
    force_zero: bool = False,
) -> None:
    # Send at L2 over AF_PACKET: scapy's L3 send() ignores `iface` and cannot resolve
    # the on-link route inside a netns. A raw frame is also a more faithful test.
    import socket

    m = _mech(mech_id)
    loc = m.locator
    if loc is None:
        raise SystemExit(f"{mech_id} has no locator; harness needs one to place the field")
    if mech_id in _L2_FIELDS:
        _inject_l2(m, loc, payload, src_mac, dst_mac, force_zero)
        return
    is_v6 = bytes(_base_packet(m, src_ip, dst_ip, 1000))[0] >> 4 == 6
    ethertype = b"\x86\xdd" if is_v6 else b"\x08\x00"
    eth = (
        bytes.fromhex(dst_mac.replace(":", ""))
        + bytes.fromhex(src_mac.replace(":", ""))
        + ethertype
    )
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind(("vs", 0))
    symbols = Framer(codec_for(m)).encode(payload)
    for i, symbol in enumerate(symbols):
        raw = bytearray(bytes(_base_packet(m, src_ip, dst_ip, 1000 + i)))
        # symbol is int (FixedWidth/SymbolChoice) or bytes (VariableLength); both -> a field int
        sym_int = int.from_bytes(symbol, "big") if isinstance(symbol, bytes) else int(symbol)
        value = 0 if force_zero else sym_int  # benign control sets the field to default 0
        _write_bits(raw, _abs_bit_offset(loc, _ip_hdr_bits(raw)), loc.bit_width, value)
        pkt = _reparse(raw)  # recompute checksums over the modified bytes
        _clear_checksums(pkt)
        sock.send(eth + bytes(pkt))
    sock.close()
    print(f"injected {len(symbols)} frames (force_zero={force_zero})", file=sys.stderr)


def calibrate(mech_id: str) -> bool:
    """Pre-flight guard against offset bugs: build one packet with the field set HIGH
    and one with it ZERO, then check them with the *independently derived* BPF detector.
    HIGH must match and ZERO must not. If our inject offset disagrees with the detector
    offset (e.g. the IHL-in-words bug that put the field in the IP dst address), this
    fails loudly — which a self-consistent round-trip test never would."""
    import subprocess

    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    from celatim.detect import bpf_filter

    m = _mech(mech_id)
    loc = m.locator
    try:
        detector = bpf_filter(m)
    except ValueError:
        print(f"CALIBRATION mechanism={mech_id} skipped (no stateless detector)")
        return True
    matches: dict[str, bool] = {}
    for label, symbol in (("hi", (1 << loc.bit_width) - 1), ("lo", 0)):
        raw = bytearray(
            bytes(Ether() / IP(src=SND_IP, dst=RCV_IP) / TCP(sport=40000, dport=9999, flags="S"))
        )
        # IP starts after the 14-byte Ethernet header
        offset = 14 * 8 + _abs_bit_offset(loc, _ip_hdr_bits(raw[14:]))
        _write_bits(raw, offset, loc.bit_width, symbol)
        ip = IP(bytes(raw[14:]))
        del ip.chksum
        if TCP in ip:
            del ip[TCP].chksum
        path = f"/tmp/cal_{label}.pcap"
        wrpcap(path, [Ether(bytes(raw[:14]) + bytes(ip))])
        out = subprocess.run(
            ["tcpdump", "-r", path, "-nn", detector], capture_output=True, text=True
        )
        matches[label] = bool(out.stdout.strip())
    ok = matches["hi"] and not matches["lo"]
    print(
        f"CALIBRATION mechanism={mech_id} detector={detector!r} "
        f"hi_matches={matches['hi']} lo_matches={matches['lo']} "
        f"{'CALIBRATED' if ok else 'MISCALIBRATED'}"
    )
    return ok


def benign(n: int, src_mac: str, dst_mac: str) -> None:
    """Send n ordinary TCP SYNs (reserved bits = 0) — benign baseline for FP counting."""
    import socket

    from scapy.layers.inet import IP, TCP

    eth = (
        bytes.fromhex(dst_mac.replace(":", ""))
        + bytes.fromhex(src_mac.replace(":", ""))
        + b"\x08\x00"
    )
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind(("vs", 0))
    for i in range(n):
        pkt = IP(src=SND_IP, dst=RCV_IP) / TCP(
            sport=40000 + (i % 2000), dport=80, flags="S", seq=2000 + i
        )
        sock.send(eth + bytes(pkt))
    sock.close()
    print(f"sent {n} benign frames", file=sys.stderr)


# --- Class F timing channel (real inter-arrival, not a field) -----------------------
# The symbol is carried in the gap BEFORE each packet, not in any header bit. A
# reference packet starts the clock; then N symbols -> N more packets. The carrier
# bytes are constant; only the timing varies. Quantum is generous (10 ms) vs. the
# microsecond-scale veth latency, so scheduler jitter cannot cross a symbol boundary.
TIMING_BASE = 0.010  # seconds: the symbol-0 gap
TIMING_QUANTUM = 0.010  # seconds per symbol step


def _timing_frame(mech_id: str, src_mac: str, dst_mac: str) -> bytes:
    from scapy.layers.inet import IP, UDP

    port = {"ntp-timing": 123, "dns-timing": 53, "quic-padding-frame-count": 443}.get(mech_id, 9999)
    pkt = IP(src=SND_IP, dst=RCV_IP) / UDP(sport=40000, dport=port) / (b"\x00" * 8)
    eth = (
        bytes.fromhex(dst_mac.replace(":", ""))
        + bytes.fromhex(src_mac.replace(":", ""))
        + b"\x08\x00"
    )
    return eth + bytes(pkt)


def timing_send(
    mech_id: str, payload: bytes, src_mac: str, dst_mac: str, constant: bool = False
) -> None:
    """Emit one reference frame, then one frame per symbol after a symbol-sized gap.
    constant=True is the benign control: every gap is the symbol-0 gap, so a receiver
    decodes only zeros (no payload) — proving the data is in the timing, not the bytes."""
    import socket
    import time

    m = _mech(mech_id)
    frame = _timing_frame(mech_id, src_mac, dst_mac)
    symbols = Framer(codec_for(m)).encode(payload)  # ints in [0, 2**bits)
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind(("vs", 0))
    sock.send(frame)  # reference (t0)
    for sym in symbols:
        s = 0 if constant else int(sym)
        time.sleep(TIMING_BASE + s * TIMING_QUANTUM)
        sock.send(frame)
    sock.close()
    print(f"timing-sent {len(symbols)} symbols (+1 ref) constant={constant}", file=sys.stderr)


def timing_recv(mech_id: str, iface: str, n: int, out_file: str) -> None:
    """Timestamp n+1 arrivals, quantize the n gaps back to symbols, decode the payload."""
    import socket
    import time

    m = _mech(mech_id)
    codec = codec_for(m)
    hi = (1 << m.raw_capacity_bits) - 1
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((iface, 0))
    sock.settimeout(20)
    stamps: list[float] = []
    src = bytes.fromhex(mac_self_peer_src())  # frames from the sender only
    while len(stamps) < n + 1:
        try:
            data, _ = sock.recvfrom(65535)
        except TimeoutError:
            break
        if len(data) >= 12 and data[6:12] == src and data[12:14] == b"\x08\x00":
            stamps.append(time.monotonic())
    sock.close()
    symbols: list[int] = []
    for a, b in itertools.pairwise(stamps):
        s = round((b - a - TIMING_BASE) / TIMING_QUANTUM)
        symbols.append(max(0, min(hi, s)))
    payload = Framer(codec).decode(symbols)
    with open(out_file, "wb") as fh:
        fh.write(payload)
    print(
        f"timing-recv {len(stamps)} frames -> {len(symbols)} symbols -> {len(payload)} bytes",
        file=sys.stderr,
    )


def mac_self_peer_src() -> str:
    """The sender (vs) MAC, read from inside the rcv netns is not possible; the caller
    passes it via env to keep the receiver self-contained."""
    import os

    return os.environ["SND_MAC"].replace(":", "")


def _capture_l2(m, loc, codec, iface: str, n: int, out_file: str) -> None:
    """Receive L2-only frames at the tap, filtered by the carrier's ethertype, and read
    the covert field from the Ethernet-frame payload (base=ll, offset 0)."""
    from scapy.layers.l2 import Ether
    from scapy.sendrecv import sniff

    from celatim.channel.codec import VariableLengthCodec

    bytes_field = isinstance(codec, VariableLengthCodec)
    et = _L2_FIELDS[m.id]
    symbols: list[int | bytes] = []

    def on_pkt(pkt) -> None:
        body = bytes(pkt)[14:]  # strip the 14-byte Ethernet header -> L2 payload
        val = _read_bits(body, loc.bit_offset, loc.bit_width)
        symbols.append(val.to_bytes(loc.bit_width // 8, "big") if bytes_field else val)

    sniff(
        iface=iface,
        count=n,
        timeout=10,
        prn=on_pkt,
        lfilter=lambda p: Ether in p and p[Ether].type == et,
    )
    payload = Framer(codec).decode(symbols)
    with open(out_file, "wb") as fh:
        fh.write(payload)
    print(f"captured {len(symbols)} L2 frames -> {len(payload)} bytes", file=sys.stderr)


def capture(
    mech_id: str,
    iface: str,
    n: int,
    out_file: str,
    status_file: str | None = None,
    expected_source_ip: str | None = None,
) -> None:
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
    from scapy.sendrecv import sniff

    m = _mech(mech_id)
    loc = m.locator
    codec = codec_for(m)
    if mech_id in _L2_FIELDS:
        _capture_l2(m, loc, codec, iface, n, out_file)
        return
    symbols: list[int | bytes] = []
    source_ip = expected_source_ip or SND_IP

    def is_ours(p) -> bool:
        if IP in p:
            return p[IP].src == source_ip
        if IPv6 in p:
            return p[IPv6].src == SND_IP6
        return False

    from celatim.channel.codec import VariableLengthCodec

    bytes_field = isinstance(codec, VariableLengthCodec)

    def on_pkt(pkt) -> None:
        ipb = bytes(pkt[IPv6]) if IPv6 in pkt else bytes(pkt[IP])
        val = _read_bits(ipb, _abs_bit_offset(loc, _ip_hdr_bits(ipb)), loc.bit_width)
        # reconstruct the codec's symbol type: bytes for VariableLength, int otherwise
        symbols.append(val.to_bytes(loc.bit_width // 8, "big") if bytes_field else val)

    sniff(iface=iface, count=n, timeout=10, prn=on_pkt, lfilter=is_ours)
    decode_error = None
    try:
        payload = Framer(codec).decode(symbols)
    except Exception as exc:
        if status_file is None:
            raise
        payload = b""
        decode_error = f"{type(exc).__name__}: {exc}"
    with open(out_file, "wb") as fh:
        fh.write(payload)
    if status_file is not None:
        nonzero_units = sum(
            (int.from_bytes(symbol, "big") if isinstance(symbol, bytes) else int(symbol)) != 0
            for symbol in symbols
        )
        Path(status_file).write_text(
            json.dumps(
                {
                    "captured_units": len(symbols),
                    "expected_units": n,
                    "nonzero_units": nonzero_units,
                    "recovered_bytes": len(payload),
                    "decode_error": decode_error,
                    "expected_source_ip": source_ip,
                },
                sort_keys=True,
            )
            + "\n"
        )
    print(f"captured {len(symbols)} packets -> {len(payload)} bytes", file=sys.stderr)


def forward(in_if: str, out_if: str, scrub_mech: str) -> None:
    """Bump-in-the-wire forwarder in the mbox ns: copy frames in_if -> out_if, and if
    ``scrub_mech`` names a mechanism, zero that mechanism's field on the way through
    (a real userspace normalizer). ``scrub_mech == 'pass'`` forwards unchanged."""
    import socket

    from scapy.layers.inet import IP, TCP

    loc = None if scrub_mech == "pass" else _mech(scrub_mech).locator
    rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    rx.bind((in_if, 0))
    rx.settimeout(8)
    tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    tx.bind((out_if, 0))
    count = 0
    while True:
        try:
            frame = rx.recv(65535)
        except TimeoutError:
            break
        except OSError:  # interface went down at teardown
            break
        if len(frame) < 34 or frame[12:14] != b"\x08\x00":
            continue
        ipb = bytearray(frame[14:])
        if bytes(ipb[12:16]) != bytes(int(p) for p in SND_IP.split(".")):
            continue  # only forward snd's IPv4 frames
        if loc is not None:
            _scrub_field(ipb, loc)
            ip = IP(bytes(ipb))
            del ip.chksum
            if TCP in ip:
                del ip[TCP].chksum
            ipb = bytearray(bytes(ip))
        tx.send(frame[:14] + bytes(ipb))
        count += 1
    print(f"forwarded {count} frames (scrub={scrub_mech})", file=sys.stderr)


def main() -> None:
    mode = sys.argv[1]
    if mode == "topo-up":
        topo_up()
    elif mode == "topo3-up":
        topo3_up()
    elif mode == "forward":
        forward(sys.argv[2], sys.argv[3], sys.argv[4])
    elif mode == "topo-down":
        topo_down()
    elif mode == "inject":
        rest = sys.argv[4:]
        force_zero = "--zero" in rest
        rest = [a for a in rest if a != "--zero"]
        inject(sys.argv[2], bytes.fromhex(sys.argv[3]), *rest, force_zero=force_zero)
    elif mode == "benign":
        benign(int(sys.argv[2]), sys.argv[3], sys.argv[4])
    elif mode == "calibrate":
        raise SystemExit(0 if calibrate(sys.argv[2]) else 1)
    elif mode == "capture":
        capture(
            sys.argv[2],
            sys.argv[3],
            int(sys.argv[4]),
            sys.argv[5],
            sys.argv[6] if len(sys.argv) > 6 else None,
            sys.argv[7] if len(sys.argv) > 7 else None,
        )
    elif mode == "timing-send":
        rest = sys.argv[4:]
        constant = "--constant" in rest
        rest = [a for a in rest if a != "--constant"]
        timing_send(sys.argv[2], bytes.fromhex(sys.argv[3]), rest[0], rest[1], constant=constant)
    elif mode == "timing-recv":
        timing_recv(sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5])
    else:
        raise SystemExit(f"unknown mode {mode}")


if __name__ == "__main__":
    main()
