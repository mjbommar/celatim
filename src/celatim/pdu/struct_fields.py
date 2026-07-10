"""Real minimal-structure carriers for the remaining application/format protocols.

Each carrier builds a real minimal protocol structure (an HTTP/3 frame, an HTTP/1
request, an MQTT PUBLISH, an SSH binary packet, etc.) with the covert value in its
genuine field -- a varint type/id, a header value, a length-prefixed payload, or a
padding region -- and an independent reader recovers it from the same field. Pure
stdlib (struct/base64), no extras.
"""

from __future__ import annotations

import base64
import struct
from collections.abc import Callable
from dataclasses import dataclass


def _varint(value: int) -> bytes:
    if value < 0x40:
        return bytes([value])
    if value < 0x4000:
        return struct.pack(">H", 0x4000 | value)
    if value < 0x40000000:
        return struct.pack(">I", 0x80000000 | value)
    return struct.pack(">Q", 0xC000000000000000 | value)


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    prefix = data[pos] >> 6
    if prefix == 0:
        return data[pos] & 0x3F, pos + 1
    if prefix == 1:
        return struct.unpack(">H", data[pos : pos + 2])[0] & 0x3FFF, pos + 2
    if prefix == 2:
        return struct.unpack(">I", data[pos : pos + 4])[0] & 0x3FFFFFFF, pos + 4
    return struct.unpack(">Q", data[pos : pos + 8])[0] & 0x3FFFFFFFFFFFFFFF, pos + 8


# --- HTTP/3 (varint frame/stream/setting/error over QUIC) -----------------------------
def _b_h3_frame_type(value: bytes) -> bytes:
    return _varint(0x21) + _varint(len(value)) + value  # reserved frame type + length + payload


def _p_h3_frame_type(c: bytes) -> bytes:
    _t, pos = _read_varint(c, 0)
    length, pos = _read_varint(c, pos)
    return c[pos : pos + length]


def _b_h3_stream_type(value: bytes) -> bytes:
    return _varint(0x21) + value  # reserved unidirectional stream type + stream payload


def _p_h3_stream_type(c: bytes) -> bytes:
    _t, pos = _read_varint(c, 0)
    return c[pos:]


def _b_h3_settings(v: int) -> bytes:
    return bytes([0x04]) + _varint(len(_varint(v) + _varint(0))) + _varint(v) + _varint(0)


def _p_h3_settings(c: bytes) -> int:
    _len, pos = _read_varint(c, 1)
    return _read_varint(c, pos)[0]


def _b_h3_error(v: int) -> bytes:
    return _varint(v)  # application error code varint


def _p_h3_error(c: bytes) -> int:
    return _read_varint(c, 0)[0]


# --- text / payload protocols ---------------------------------------------------------
def _b_http(value: bytes) -> bytes:
    return b"GET / HTTP/1.1\r\nHost: x\r\nX-Covert: " + base64.b64encode(value) + b"\r\n\r\n"


def _p_http(c: bytes) -> bytes:
    for line in c.split(b"\r\n"):
        if line.startswith(b"X-Covert: "):
            return base64.b64decode(line[len(b"X-Covert: ") :])
    return b""


def _b_doh(value: bytes) -> bytes:
    return b"POST /dns-query HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % len(value) + value


def _p_doh(c: bytes) -> bytes:
    return c.split(b"\r\n\r\n", 1)[1]


def _b_mqtt(value: bytes) -> bytes:
    body = struct.pack(">H", 1) + b"t" + value  # topic-len + topic + payload
    return bytes([0x30]) + _varint(len(body)) + body  # PUBLISH


def _p_mqtt(c: bytes) -> bytes:
    rem, pos = _read_varint(c, 1)
    topic_len = struct.unpack(">H", c[pos : pos + 2])[0]
    return c[pos + 2 + topic_len : pos + rem]


def _b_ssh_padding(value: bytes) -> bytes:
    # SSH binary packet: packet_length(4), padding_length(1), payload(0), random padding.
    return struct.pack(">I", 1 + len(value)) + bytes([len(value)]) + value


def _p_ssh_padding(c: bytes) -> bytes:
    pad_len = c[4]
    return c[5 : 5 + pad_len]


def _b_owamp(value: bytes) -> bytes:
    return struct.pack(">I", 0) + struct.pack(">Q", 0) + value  # seq + timestamp + padding


def _p_owamp(c: bytes) -> bytes:
    return c[12:]


def _b_pptp(value: bytes) -> bytes:
    # PPTP control header (length, msg type, magic) + length-counted vendor-name field.
    return struct.pack(">HHI", 156, 1, 0x1A2B3C4D) + struct.pack(">H", len(value)) + value


def _p_pptp(c: bytes) -> bytes:
    length = struct.unpack(">H", c[8:10])[0]
    return c[10 : 10 + length]


def _b_webrtc(value: bytes) -> bytes:
    return bytes([0x03]) + struct.pack(">H", len(value)) + value  # DCEP-ish type + len + payload


def _p_webrtc(c: bytes) -> bytes:
    length = struct.unpack(">H", c[1:3])[0]
    return c[3 : 3 + length]


def _b_edhoc(value: bytes) -> bytes:
    return bytes([0x01]) + struct.pack(">H", len(value)) + value  # EAD label + length + value


def _p_edhoc(c: bytes) -> bytes:
    length = struct.unpack(">H", c[1:3])[0]
    return c[3 : 3 + length]


# --- fixed header-field protocols -----------------------------------------------------
def _b_rtcp_xr(v: int) -> bytes:
    return bytes([207, v & 0xFF]) + struct.pack(">H", 0)  # XR block: BT, reserved byte, length


def _p_rtcp_xr(c: bytes) -> int:
    return c[1]


def _b_turn(v: int) -> bytes:
    val = (v & ((1 << 40) - 1)).to_bytes(5, "big")
    return struct.pack(">HH", 0x8000, len(val)) + val  # STUN attribute: type, length, RFFU value


def _p_turn(c: bytes) -> int:
    return int.from_bytes(c[4:9], "big")


def _b_dns_dso(v: int) -> bytes:
    # DNS header with the DSO message; the 16-bit covert goes in the reserved Z/flags word.
    return struct.pack(">HHHHHH", 0x1234, v & 0xFFFF, 0, 0, 0, 0)


def _p_dns_dso(c: bytes) -> int:
    return struct.unpack(">H", c[2:4])[0]


def _b_lorawan(v: int) -> bytes:
    # LoRaWAN frame: MHDR, DevAddr, then FCtrl/FCnt region carrying the covert value.
    return bytes([0x40]) + struct.pack(">I", 0x11223344) + struct.pack(">Q", v & ((1 << 38) - 1))


def _p_lorawan(c: bytes) -> int:
    return struct.unpack(">Q", c[5:13])[0] & ((1 << 38) - 1)


def _b_icmp_echo(value: bytes) -> bytes:
    return struct.pack(">BBHHH", 8, 0, 0, 0x1234, 1) + value  # ICMP echo header + data payload


def _p_icmp_echo(c: bytes) -> bytes:
    return c[8:]


# --- routing / transport header fields ------------------------------------------------
def _b_bgp_ls_asla(v: int) -> bytes:
    # BGP-LS Application-Specific Link Attributes TLV: type, length, SABML, UDABML, reserved.
    return struct.pack(">HH", 1122, 4) + bytes([0, 0]) + struct.pack(">H", v & 0xFFFF)


def _p_bgp_ls_asla(c: bytes) -> int:
    return struct.unpack(">H", c[6:8])[0]


def _b_bgp_opaque(value: bytes) -> bytes:
    return (
        bytes([0x03, 0x0C]) + value.ljust(6, b"\x00")[:6]
    )  # opaque ext-community: type, subtype, value


def _p_bgp_opaque(c: bytes) -> bytes:
    return c[2:8]


def _b_geneve(v: int) -> bytes:
    # Geneve: ver/optlen, flags+rsvd, protocol, VNI(3), rsvd byte; 14 covert bits across the rsvd fields.
    return bytes([0x00, (v >> 8) & 0x3F, 0x65, 0x58, 0, 0, 0, v & 0xFF])


def _p_geneve(c: bytes) -> int:
    return ((c[1] & 0x3F) << 8) | c[7]


def _b_icmp_ext_echo(v: int) -> bytes:
    return bytes([42, 0, 0, 0]) + struct.pack(">H", v & 0xFFFF) + bytes([0, 0])  # ext echo request


def _p_icmp_ext_echo(c: bytes) -> int:
    return struct.unpack(">H", c[4:6])[0]


def _b_igmpv3(v: int) -> bytes:
    return bytes([0x11, 0, 0, 0, 0, 0, 0, 0]) + (v & 0xFFFFFF).to_bytes(
        3, "big"
    )  # IGMPv3 query + rsvd


def _p_igmpv3(c: bytes) -> int:
    return int.from_bytes(c[8:11], "big")


def _b_kerberos(v: int) -> bytes:
    return struct.pack(">I", v & 0xF)  # KDCOptions 32-bit field, covert in reserved low bits


def _p_kerberos(c: bytes) -> int:
    return struct.unpack(">I", c[0:4])[0] & 0xF


def _b_ospf_ri_padding(value: bytes) -> bytes:
    return (
        struct.pack(">HH", 1, 1) + b"\x00" + value.ljust(3, b"\x00")[:3]
    )  # RI-LSA TLV + 3 pad bytes


def _p_ospf_ri_padding(c: bytes) -> bytes:
    return c[5:8]


def _b_ospfv3_trailing(v: int) -> bytes:
    return (
        bytes([3, 1, 0, 0]) + b"\x00" * 12 + bytes([v & 0xFF])
    )  # OSPFv3 LSA header + trailing byte


def _p_ospfv3_trailing(c: bytes) -> int:
    return c[16]


def _b_rip(v: int) -> bytes:
    data = v.to_bytes(250, "big")
    out = bytearray([2, 1, 0, 0])  # command=response, version=1, must-be-zero
    for i in range(25):
        chunk = data[i * 10 : i * 10 + 10]
        out += struct.pack(">H", 2) + chunk[0:2] + b"\x00\x00\x00\x00" + chunk[2:6] + chunk[6:10]
        out += b"\x00\x00\x00\x01"  # metric
    return bytes(out)


def _p_rip(c: bytes) -> int:
    out = bytearray()
    for i in range(25):
        off = 4 + i * 20
        out += c[off + 2 : off + 4] + c[off + 8 : off + 12] + c[off + 12 : off + 16]
    return int.from_bytes(out, "big")


def _b_rsvp(v: int) -> bytes:
    return bytes([0x10, 1, 0, 0, 64, 0, 0, 12]) + struct.pack(
        ">I", v & 0xFFFFFFFF
    )  # common hdr + rsvd


def _p_rsvp(c: bytes) -> int:
    return struct.unpack(">I", c[8:12])[0]


def _b_sctp_idata(v: int) -> bytes:
    # I-DATA chunk: type, flags, length, TSN, stream, reserved(2), MID.
    return bytes([0x40, 0, 0, 16]) + struct.pack(">IH", 0, 0) + struct.pack(">H", v & 0xFFFF)


def _p_sctp_idata(c: bytes) -> int:
    return struct.unpack(">H", c[10:12])[0]


def _b_sctp_padding(value: bytes) -> bytes:
    return bytes([0x84, 0]) + struct.pack(">H", 4 + len(value)) + value  # PAD chunk + padding


def _p_sctp_padding(c: bytes) -> bytes:
    length = struct.unpack(">H", c[2:4])[0]
    return c[4:length]


def _b_tcp_ts(v: int) -> bytes:
    return bytes([8, 10]) + struct.pack(
        ">II", 0x12345670 | (v & 0xF), 0
    )  # TS option, covert in TSval LSBs


def _p_tcp_ts(c: bytes) -> int:
    return struct.unpack(">I", c[2:6])[0] & 0xF


def _b_vrrp(value: bytes) -> bytes:
    return bytes([0x31, 1, 100, 1, len(value)]) + value  # VRRPv3 header + length-prefixed reserved


def _p_vrrp(c: bytes) -> bytes:
    return c[5 : 5 + c[4]]


@dataclass(frozen=True)
class _Carrier:
    build: Callable[..., bytes]
    parse: Callable[[bytes], object]
    symbol_is_bytes: bool


_CARRIERS: dict[str, _Carrier] = {
    "http3-reserved-frame-types": _Carrier(_b_h3_frame_type, _p_h3_frame_type, True),
    "http3-reserved-stream-types": _Carrier(_b_h3_stream_type, _p_h3_stream_type, True),
    "http3-reserved-settings": _Carrier(_b_h3_settings, _p_h3_settings, False),
    "http3-reserved-error-codes": _Carrier(_b_h3_error, _p_h3_error, False),
    "doq-reserved-error": _Carrier(_b_h3_error, _p_h3_error, False),
    "http-tunnel": _Carrier(_b_http, _p_http, True),
    "doh-tunnel": _Carrier(_b_doh, _p_doh, True),
    "mqtt-tunnel": _Carrier(_b_mqtt, _p_mqtt, True),
    "ssh-random-padding": _Carrier(_b_ssh_padding, _p_ssh_padding, True),
    "owamp-twamp-padding": _Carrier(_b_owamp, _p_owamp, True),
    "pptp-vendor-name": _Carrier(_b_pptp, _p_pptp, True),
    "webrtc-datachannel": _Carrier(_b_webrtc, _p_webrtc, True),
    "edhoc-ead-padding": _Carrier(_b_edhoc, _p_edhoc, True),
    "rtcp-xr-reserved": _Carrier(_b_rtcp_xr, _p_rtcp_xr, False),
    "turn-rffu": _Carrier(_b_turn, _p_turn, False),
    "dns-dso-zbits": _Carrier(_b_dns_dso, _p_dns_dso, False),
    "lorawan-frame": _Carrier(_b_lorawan, _p_lorawan, False),
    "icmp-echo-payload": _Carrier(_b_icmp_echo, _p_icmp_echo, True),
    "bgp-ls-asla-reserved": _Carrier(_b_bgp_ls_asla, _p_bgp_ls_asla, False),
    "bgp-opaque-ext-comm": _Carrier(_b_bgp_opaque, _p_bgp_opaque, True),
    "geneve-reserved": _Carrier(_b_geneve, _p_geneve, False),
    "icmp-extended-echo": _Carrier(_b_icmp_ext_echo, _p_icmp_ext_echo, False),
    "igmpv3-reserved": _Carrier(_b_igmpv3, _p_igmpv3, False),
    "kerberos-kdcoptions": _Carrier(_b_kerberos, _p_kerberos, False),
    "ospf-ri-lsa-padding": _Carrier(_b_ospf_ri_padding, _p_ospf_ri_padding, True),
    "ospfv3-trailing-byte": _Carrier(_b_ospfv3_trailing, _p_ospfv3_trailing, False),
    "ripv1-ignored": _Carrier(_b_rip, _p_rip, False),
    "rsvp-reserved": _Carrier(_b_rsvp, _p_rsvp, False),
    "sctp-idata-reserved": _Carrier(_b_sctp_idata, _p_sctp_idata, False),
    "sctp-padding": _Carrier(_b_sctp_padding, _p_sctp_padding, True),
    "tcp-timestamp-lsb": _Carrier(_b_tcp_ts, _p_tcp_ts, False),
    "vrrpv3-rsvd": _Carrier(_b_vrrp, _p_vrrp, True),
}


def supports(mechanism_id: str) -> bool:
    return mechanism_id in _CARRIERS


def is_bytes_symbol(mechanism_id: str) -> bool:
    return _CARRIERS[mechanism_id].symbol_is_bytes


def build_structure(mechanism_id: str, value: int | bytes) -> bytes:
    return _CARRIERS[mechanism_id].build(value)


def parse_structure(mechanism_id: str, carrier: bytes) -> int | bytes:
    from typing import cast

    return cast("int | bytes", _CARRIERS[mechanism_id].parse(carrier))


__all__ = [
    "build_structure",
    "is_bytes_symbol",
    "parse_structure",
    "supports",
]
