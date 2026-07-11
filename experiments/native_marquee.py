#!/usr/bin/env python3
"""Split-process native-protocol marquee endpoints.

The receiver binds a real TCP or UDP socket and recovers Celatim framing symbols from
nominal protocol messages produced and parsed by the protocol library named in the
result. The sender and receiver commands are designed to run on distinct authorized lab
hosts. Raw payloads and wire messages are never written to the evidence JSON.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import socket
import struct
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from celatim.catalog import load_mechanisms
from celatim.channel.framer import Framer
from celatim.channel.registry import codec_for
from celatim.model import Mechanism
from celatim.pdu.bgp_attr import build_bgp_update, parse_bgp_update
from celatim.pdu.coap_msg import build_coap_message, parse_coap_message
from celatim.pdu.rtcp import build_app_packet, parse_app_packet
from celatim.pdu.ssh_kex import KEXINIT_CARRIER_LEN, build_kexinit, parse_kexinit
from celatim.resources import catalog_path as packaged_catalog_path
from celatim.testbed.quic import DCID_LEN, _aioquic_modules, _self_signed_certificate

SCHEMA_VERSION = "celatim.native_marquee_endpoint.v1"
SUPPORTED_MECHANISMS = (
    "http2-ping-opaque",
    "quic-connection-id",
    "ssh-kexinit-cookie",
    "bgp-optional-transitive",
    "edns0-padding",
    "rtp-rtcp-ext-app",
    "stun-attr-padding",
    "coap-tunnel",
)
TCP_MECHANISMS = {
    "http2-ping-opaque",
    "ssh-kexinit-cookie",
    "bgp-optional-transitive",
}
TRANSPORT_KIND = {
    "http2-ping-opaque": "hyper_h2_tcp",
    "quic-connection-id": "aioquic_initial_udp",
    "ssh-kexinit-cookie": "paramiko_kexinit_tcp",
    "bgp-optional-transitive": "scapy_bgp_tcp",
    "edns0-padding": "dnspython_edns_udp",
    "rtp-rtcp-ext-app": "rtcp_app_udp",
    "stun-attr-padding": "scapy_stun_udp",
    "coap-tunnel": "aiocoap_elective_option_udp",
}
CARRIER_SURFACE = {
    "http2-ping-opaque": "HTTP/2 PING opaque data",
    "quic-connection-id": "QUIC Initial destination connection ID",
    "ssh-kexinit-cookie": "SSH KEXINIT cookie and reserved uint32",
    "bgp-optional-transitive": "BGP unknown optional-transitive attribute type 99",
    "edns0-padding": "EDNS(0) Padding option",
    "rtp-rtcp-ext-app": "RTCP APP application-dependent data",
    "stun-attr-padding": "STUN transaction ID",
    "coap-tunnel": "CoAP experimental elective option 65000",
}
IMPLEMENTATION_SCOPE = {
    "http2-ping-opaque": "hyper-h2 connection state machine over TCP",
    "quic-connection-id": (
        "aioquic connection state over UDP with a controlled pre-connect peer-CID hook"
    ),
    "ssh-kexinit-cookie": "Paramiko Message codec in RFC 4253 TCP packet framing",
    "bgp-optional-transitive": "Scapy BGP codec in a minimal TCP OPEN/KEEPALIVE session",
    "edns0-padding": "dnspython DNS message codec over UDP",
    "rtp-rtcp-ext-app": "Celatim RFC 3550 RTCP APP codec over UDP",
    "stun-attr-padding": "Scapy STUN codec over UDP",
    "coap-tunnel": "aiocoap Message codec over UDP without an aiocoap Context",
}
LIBRARY_DISTRIBUTIONS = {
    "http2-ping-opaque": ("h2",),
    "quic-connection-id": ("aioquic", "cryptography"),
    "ssh-kexinit-cookie": ("paramiko",),
    "bgp-optional-transitive": ("scapy",),
    "edns0-padding": ("dnspython",),
    "rtp-rtcp-ext-app": (),
    "stun-attr-padding": ("scapy",),
    "coap-tunnel": ("aiocoap",),
}
SOCKET_TIMEOUT_S = 15.0


@dataclass(frozen=True)
class ProtocolResult:
    symbols: tuple[bytes, ...]
    carrier_wire_bytes: int
    response_wire_bytes: int
    responses_validated: int
    peer: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _versions(mechanism_id: str) -> dict[str, str | None]:
    values: dict[str, str | None] = {}
    for distribution in LIBRARY_DISTRIBUTIONS[mechanism_id]:
        try:
            values[distribution] = version(distribution)
        except PackageNotFoundError:
            values[distribution] = None
    return values


def _mechanism(mechanism_id: str, catalog: Path | None = None) -> Mechanism:
    if mechanism_id not in SUPPORTED_MECHANISMS:
        raise ValueError(f"unsupported native marquee mechanism: {mechanism_id}")
    if catalog is None:
        with packaged_catalog_path() as path:
            mechanisms = load_mechanisms(path)
    else:
        mechanisms = load_mechanisms(catalog)
    return next(item for item in mechanisms if item.id == mechanism_id)


def encode_payload(mechanism: Mechanism, payload: bytes) -> tuple[bytes, ...]:
    symbols = Framer(codec_for(mechanism)).encode(payload)
    if not all(isinstance(symbol, bytes) for symbol in symbols):
        raise TypeError(f"{mechanism.id}: native marquee requires byte-valued symbols")
    return tuple(symbol for symbol in symbols if isinstance(symbol, bytes))


def decode_payload(mechanism: Mechanism, symbols: Sequence[bytes]) -> bytes:
    return Framer(codec_for(mechanism)).decode(list(symbols))


def _recv_exact(stream: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = stream.recv(remaining)
        if not chunk:
            raise EOFError(f"peer closed with {remaining} bytes still expected")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_line(stream: socket.socket, *, limit: int = 255) -> bytes:
    value = bytearray()
    while len(value) <= limit:
        byte = _recv_exact(stream, 1)
        value.extend(byte)
        if value.endswith(b"\n"):
            return bytes(value)
    raise ValueError("protocol identification line exceeds limit")


def _tcp_listener(bind: str, port: int) -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((bind, port))
    listener.listen(16)
    listener.settimeout(SOCKET_TIMEOUT_S)
    return listener


def _udp_listener(bind: str, port: int) -> socket.socket:
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind((bind, port))
    receiver.settimeout(SOCKET_TIMEOUT_S)
    return receiver


def _connect(host: str, port: int) -> socket.socket:
    stream = socket.create_connection((host, port), timeout=SOCKET_TIMEOUT_S)
    stream.settimeout(SOCKET_TIMEOUT_S)
    return stream


def _h2_connection(client_side: bool) -> Any:
    import h2.config
    import h2.connection

    return h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=client_side, header_encoding=None)
    )


def _receive_h2(listener: socket.socket, expected: int) -> ProtocolResult:
    import h2.events

    stream, address = listener.accept()
    stream.settimeout(SOCKET_TIMEOUT_S)
    connection = _h2_connection(False)
    connection.initiate_connection()
    initial = connection.data_to_send()
    stream.sendall(initial)
    response_bytes = len(initial)
    inbound_bytes = 0
    symbols: list[bytes] = []
    with stream:
        while len(symbols) < expected:
            data = stream.recv(65535)
            if not data:
                break
            inbound_bytes += len(data)
            for event in connection.receive_data(data):
                if isinstance(event, h2.events.PingReceived):
                    symbols.append(bytes(event.ping_data))
            pending = connection.data_to_send()
            if pending:
                stream.sendall(pending)
                response_bytes += len(pending)
    return ProtocolResult(
        symbols=tuple(symbols),
        carrier_wire_bytes=inbound_bytes,
        response_wire_bytes=response_bytes,
        responses_validated=0,
        peer=str(address[0]),
    )


def _send_h2(host: str, port: int, symbols: Sequence[bytes]) -> ProtocolResult:
    import h2.events

    connection = _h2_connection(True)
    response_bytes = 0
    carrier_bytes = 0
    acked = 0
    with _connect(host, port) as stream:
        connection.initiate_connection()
        preface = connection.data_to_send()
        stream.sendall(preface)
        carrier_bytes += len(preface)
        for symbol in symbols:
            connection.ping(symbol)
            outbound = connection.data_to_send()
            stream.sendall(outbound)
            carrier_bytes += len(outbound)
            observed_ack = False
            while not observed_ack:
                inbound = stream.recv(65535)
                if not inbound:
                    raise EOFError("HTTP/2 peer closed before PING ACK")
                response_bytes += len(inbound)
                events = connection.receive_data(inbound)
                observed_ack = any(
                    isinstance(event, h2.events.PingAckReceived)
                    and bytes(event.ping_data) == symbol
                    for event in events
                )
                pending = connection.data_to_send()
                if pending:
                    stream.sendall(pending)
                    carrier_bytes += len(pending)
            acked += 1
        stream.shutdown(socket.SHUT_WR)
    return ProtocolResult((), carrier_bytes, response_bytes, acked, host)


def _receive_quic(receiver: socket.socket, expected: int) -> ProtocolResult:
    modules = _aioquic_modules()
    certificate, private_key = _self_signed_certificate()
    symbols: list[bytes] = []
    inbound_bytes = 0
    response_bytes = 0
    peer = ""
    for _ in range(expected):
        datagram, address = receiver.recvfrom(65535)
        peer = str(address[0])
        inbound_bytes += len(datagram)
        header = modules["pull_quic_header"](
            modules["Buffer"](data=datagram), host_cid_length=DCID_LEN
        )
        dcid = bytes(header.destination_cid)
        configuration = modules["QuicConfiguration"](
            is_client=False,
            alpn_protocols=["h3"],
            connection_id_length=DCID_LEN,
            certificate=certificate,
            private_key=private_key,
        )
        connection = modules["QuicConnection"](
            configuration=configuration,
            original_destination_connection_id=dcid,
        )
        now = time.time()
        connection.receive_datagram(datagram, address, now=now)
        responses = connection.datagrams_to_send(now=now + 0.001)
        if not responses:
            raise ValueError("aioquic server produced no Initial response")
        response = responses[0][0]
        receiver.sendto(response, address)
        response_bytes += len(response)
        symbols.append(dcid)
    return ProtocolResult(tuple(symbols), inbound_bytes, response_bytes, 0, peer)


def _send_quic(host: str, port: int, symbols: Sequence[bytes]) -> ProtocolResult:
    modules = _aioquic_modules()
    transport = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    transport.settimeout(SOCKET_TIMEOUT_S)
    carrier_bytes = 0
    response_bytes = 0
    validated = 0
    with transport:
        for symbol in symbols:
            configuration = modules["QuicConfiguration"](
                is_client=True,
                alpn_protocols=["h3"],
                connection_id_length=DCID_LEN,
                verify_mode=False,
            )
            connection = modules["QuicConnection"](configuration=configuration)
            connection._peer_cid = modules["QuicConnectionId"](cid=symbol, sequence_number=None)
            now = time.time()
            connection.connect((host, port), now=now)
            datagrams = connection.datagrams_to_send(now=now)
            if not datagrams:
                raise ValueError("aioquic client produced no Initial datagram")
            datagram = datagrams[0][0]
            transport.sendto(datagram, (host, port))
            carrier_bytes += len(datagram)
            response, address = transport.recvfrom(65535)
            response_bytes += len(response)
            connection.receive_datagram(response, address, now=time.time())
            validated += 1
    return ProtocolResult((), carrier_bytes, response_bytes, validated, host)


def _ssh_packet(payload: bytes) -> bytes:
    padding_length = 8 - ((4 + 1 + len(payload)) % 8)
    if padding_length < 4:
        padding_length += 8
    body = bytes([padding_length]) + payload + os.urandom(padding_length)
    return struct.pack("!I", len(body)) + body


def _recv_ssh_packet(stream: socket.socket) -> tuple[bytes, int]:
    packet_length = struct.unpack("!I", _recv_exact(stream, 4))[0]
    if not 6 <= packet_length <= 35000:
        raise ValueError(f"invalid SSH packet length: {packet_length}")
    body = _recv_exact(stream, packet_length)
    padding_length = body[0]
    if padding_length < 4 or padding_length >= len(body):
        raise ValueError("invalid SSH padding length")
    return body[1:-padding_length], 4 + packet_length


def _receive_ssh(listener: socket.socket, expected: int) -> ProtocolResult:
    symbols: list[bytes] = []
    inbound_bytes = 0
    response_bytes = 0
    peer = ""
    server_identification = b"SSH-2.0-Celatim_Research_Server\r\n"
    response_message = _ssh_packet(build_kexinit(bytes(KEXINIT_CARRIER_LEN)))
    for _ in range(expected):
        stream, address = listener.accept()
        peer = str(address[0])
        stream.settimeout(SOCKET_TIMEOUT_S)
        with stream:
            identification = _recv_line(stream)
            if not identification.startswith(b"SSH-2.0-"):
                raise ValueError("invalid SSH client identification")
            inbound_bytes += len(identification)
            stream.sendall(server_identification)
            response_bytes += len(server_identification)
            payload, packet_wire_bytes = _recv_ssh_packet(stream)
            inbound_bytes += packet_wire_bytes
            symbols.append(parse_kexinit(payload))
            stream.sendall(response_message)
            response_bytes += len(response_message)
    return ProtocolResult(tuple(symbols), inbound_bytes, response_bytes, 0, peer)


def _send_ssh(host: str, port: int, symbols: Sequence[bytes]) -> ProtocolResult:
    client_identification = b"SSH-2.0-Celatim_Research_Client\r\n"
    carrier_bytes = 0
    response_bytes = 0
    validated = 0
    for symbol in symbols:
        with _connect(host, port) as stream:
            stream.sendall(client_identification)
            carrier_bytes += len(client_identification)
            identification = _recv_line(stream)
            response_bytes += len(identification)
            if not identification.startswith(b"SSH-2.0-"):
                raise ValueError("invalid SSH server identification")
            packet = _ssh_packet(build_kexinit(symbol))
            stream.sendall(packet)
            carrier_bytes += len(packet)
            response, packet_wire_bytes = _recv_ssh_packet(stream)
            parse_kexinit(response)
            response_bytes += packet_wire_bytes
            validated += 1
    return ProtocolResult((), carrier_bytes, response_bytes, validated, host)


def _recv_bgp_message(stream: socket.socket) -> bytes:
    header = _recv_exact(stream, 19)
    if header[:16] != b"\xff" * 16:
        raise ValueError("invalid BGP marker")
    length = int.from_bytes(header[16:18], "big")
    if not 19 <= length <= 4096:
        raise ValueError(f"invalid BGP message length: {length}")
    return header + _recv_exact(stream, length - 19)


def _bgp_open(asn: int, bgp_id: str) -> bytes:
    from scapy.contrib.bgp import BGPHeader, BGPOpen

    return bytes(BGPHeader(type=1) / BGPOpen(my_as=asn, hold_time=90, bgp_id=bgp_id))


def _bgp_keepalive() -> bytes:
    from scapy.contrib.bgp import BGPHeader

    return bytes(BGPHeader(type=4))


def _bgp_type(message: bytes) -> int:
    from scapy.contrib.bgp import BGPHeader

    return int(BGPHeader(message).type)


def _receive_bgp(listener: socket.socket, expected: int) -> ProtocolResult:
    stream, address = listener.accept()
    stream.settimeout(SOCKET_TIMEOUT_S)
    symbols: list[bytes] = []
    inbound_bytes = 0
    response_bytes = 0
    with stream:
        client_open = _recv_bgp_message(stream)
        inbound_bytes += len(client_open)
        if _bgp_type(client_open) != 1:
            raise ValueError("BGP session did not begin with OPEN")
        server_open = _bgp_open(65002, "10.0.0.2")
        keepalive = _bgp_keepalive()
        stream.sendall(server_open + keepalive)
        response_bytes += len(server_open) + len(keepalive)
        client_keepalive = _recv_bgp_message(stream)
        inbound_bytes += len(client_keepalive)
        if _bgp_type(client_keepalive) != 4:
            raise ValueError("BGP peer did not acknowledge OPEN with KEEPALIVE")
        for _ in range(expected):
            update = _recv_bgp_message(stream)
            inbound_bytes += len(update)
            if _bgp_type(update) != 2:
                raise ValueError("expected BGP UPDATE")
            symbols.append(parse_bgp_update(update))
            stream.sendall(keepalive)
            response_bytes += len(keepalive)
    return ProtocolResult(tuple(symbols), inbound_bytes, response_bytes, 0, str(address[0]))


def _send_bgp(host: str, port: int, symbols: Sequence[bytes]) -> ProtocolResult:
    carrier_bytes = 0
    response_bytes = 0
    validated = 0
    with _connect(host, port) as stream:
        client_open = _bgp_open(65001, "10.0.0.1")
        stream.sendall(client_open)
        carrier_bytes += len(client_open)
        server_open = _recv_bgp_message(stream)
        server_keepalive = _recv_bgp_message(stream)
        response_bytes += len(server_open) + len(server_keepalive)
        if _bgp_type(server_open) != 1 or _bgp_type(server_keepalive) != 4:
            raise ValueError("invalid BGP server OPEN sequence")
        keepalive = _bgp_keepalive()
        stream.sendall(keepalive)
        carrier_bytes += len(keepalive)
        for symbol in symbols:
            update = build_bgp_update(symbol)
            stream.sendall(update)
            carrier_bytes += len(update)
            response = _recv_bgp_message(stream)
            response_bytes += len(response)
            if _bgp_type(response) != 4:
                raise ValueError("BGP server did not acknowledge UPDATE")
            validated += 1
    return ProtocolResult((), carrier_bytes, response_bytes, validated, host)


def _receive_edns(receiver: socket.socket, expected: int) -> ProtocolResult:
    import dns.message

    symbols: list[bytes] = []
    inbound_bytes = 0
    response_bytes = 0
    peer = ""
    for _ in range(expected):
        wire, address = receiver.recvfrom(65535)
        peer = str(address[0])
        inbound_bytes += len(wire)
        query = dns.message.from_wire(wire)
        matches = [option for option in query.options if int(option.otype) == 12]
        if len(matches) != 1 or not hasattr(matches[0], "data"):
            raise ValueError("DNS query lacks one EDNS Padding option")
        symbols.append(bytes(matches[0].data))
        response = dns.message.make_response(query).to_wire()
        receiver.sendto(response, address)
        response_bytes += len(response)
    return ProtocolResult(tuple(symbols), inbound_bytes, response_bytes, 0, peer)


def _send_edns(host: str, port: int, symbols: Sequence[bytes]) -> ProtocolResult:
    import dns.edns
    import dns.message

    transport = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    transport.settimeout(SOCKET_TIMEOUT_S)
    carrier_bytes = 0
    response_bytes = 0
    validated = 0
    with transport:
        for index, symbol in enumerate(symbols):
            query = dns.message.make_query("covert.example.", "A")
            query.id = index & 0xFFFF
            query.use_edns(
                edns=0,
                payload=1232,
                options=[dns.edns.GenericOption(dns.edns.OptionType.PADDING, symbol)],
            )
            wire = query.to_wire()
            transport.sendto(wire, (host, port))
            carrier_bytes += len(wire)
            response, _ = transport.recvfrom(65535)
            response_bytes += len(response)
            parsed = dns.message.from_wire(response)
            if parsed.id != query.id or not (parsed.flags & 0x8000):
                raise ValueError("invalid DNS response to EDNS carrier query")
            validated += 1
    return ProtocolResult((), carrier_bytes, response_bytes, validated, host)


def _receive_rtcp(receiver: socket.socket, expected: int) -> ProtocolResult:
    symbols: list[bytes] = []
    inbound_bytes = 0
    response_bytes = 0
    peer = ""
    for _ in range(expected):
        wire, address = receiver.recvfrom(65535)
        peer = str(address[0])
        inbound_bytes += len(wire)
        symbols.append(parse_app_packet(wire).app_data)
        receiver.sendto(wire, address)
        response_bytes += len(wire)
    return ProtocolResult(tuple(symbols), inbound_bytes, response_bytes, 0, peer)


def _send_rtcp(host: str, port: int, symbols: Sequence[bytes]) -> ProtocolResult:
    return _send_echo_udp(
        host, port, symbols, build_app_packet, lambda wire: parse_app_packet(wire).app_data
    )


def _stun_wire(symbol: bytes, *, response: bool = False) -> bytes:
    from scapy.contrib.stun import STUN

    return bytes(
        STUN(
            stun_message_type=0x0101 if response else 0x0001,
            transaction_id=int.from_bytes(symbol, "big"),
        )
    )


def _stun_symbol(wire: bytes) -> bytes:
    from scapy.contrib.stun import STUN

    value = int(STUN(wire).transaction_id)
    return value.to_bytes(12, "big")


def _receive_stun(receiver: socket.socket, expected: int) -> ProtocolResult:
    symbols: list[bytes] = []
    inbound_bytes = 0
    response_bytes = 0
    peer = ""
    for _ in range(expected):
        wire, address = receiver.recvfrom(65535)
        peer = str(address[0])
        inbound_bytes += len(wire)
        symbol = _stun_symbol(wire)
        symbols.append(symbol)
        response = _stun_wire(symbol, response=True)
        receiver.sendto(response, address)
        response_bytes += len(response)
    return ProtocolResult(tuple(symbols), inbound_bytes, response_bytes, 0, peer)


def _send_stun(host: str, port: int, symbols: Sequence[bytes]) -> ProtocolResult:
    return _send_echo_udp(host, port, symbols, _stun_wire, _stun_symbol)


def _coap_response(request_wire: bytes) -> bytes:
    import aiocoap
    from aiocoap.numbers.types import Type

    request = aiocoap.Message.decode(request_wire)
    response = aiocoap.Message(
        code=aiocoap.Code.CHANGED,
        payload=b"",
        mid=request.mid,
        token=request.token,
    )
    response.mtype = Type.ACK
    return bytes(response.encode())


def _receive_coap(receiver: socket.socket, expected: int) -> ProtocolResult:
    symbols: list[bytes] = []
    inbound_bytes = 0
    response_bytes = 0
    peer = ""
    for _ in range(expected):
        wire, address = receiver.recvfrom(65535)
        peer = str(address[0])
        inbound_bytes += len(wire)
        symbols.append(parse_coap_message(wire))
        response = _coap_response(wire)
        receiver.sendto(response, address)
        response_bytes += len(response)
    return ProtocolResult(tuple(symbols), inbound_bytes, response_bytes, 0, peer)


def _send_coap(host: str, port: int, symbols: Sequence[bytes]) -> ProtocolResult:
    import aiocoap

    def validate(wire: bytes) -> bytes:
        response = aiocoap.Message.decode(wire)
        if response.code != aiocoap.Code.CHANGED:
            raise ValueError("CoAP receiver did not return Changed")
        return b""

    return _send_echo_udp(host, port, symbols, build_coap_message, validate, compare=False)


def _send_echo_udp(
    host: str,
    port: int,
    symbols: Sequence[bytes],
    build: Callable[[bytes], bytes],
    parse: Callable[[bytes], bytes],
    *,
    compare: bool = True,
) -> ProtocolResult:
    transport = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    transport.settimeout(SOCKET_TIMEOUT_S)
    carrier_bytes = 0
    response_bytes = 0
    validated = 0
    with transport:
        for symbol in symbols:
            wire = build(symbol)
            transport.sendto(wire, (host, port))
            carrier_bytes += len(wire)
            response, _ = transport.recvfrom(65535)
            response_bytes += len(response)
            parsed = parse(response)
            if compare and parsed != symbol:
                raise ValueError("protocol response did not echo the carrier symbol")
            validated += 1
    return ProtocolResult((), carrier_bytes, response_bytes, validated, host)


RECEIVERS: dict[str, Callable[[socket.socket, int], ProtocolResult]] = {
    "http2-ping-opaque": _receive_h2,
    "quic-connection-id": _receive_quic,
    "ssh-kexinit-cookie": _receive_ssh,
    "bgp-optional-transitive": _receive_bgp,
    "edns0-padding": _receive_edns,
    "rtp-rtcp-ext-app": _receive_rtcp,
    "stun-attr-padding": _receive_stun,
    "coap-tunnel": _receive_coap,
}
SENDERS: dict[str, Callable[[str, int, Sequence[bytes]], ProtocolResult]] = {
    "http2-ping-opaque": _send_h2,
    "quic-connection-id": _send_quic,
    "ssh-kexinit-cookie": _send_ssh,
    "bgp-optional-transitive": _send_bgp,
    "edns0-padding": _send_edns,
    "rtp-rtcp-ext-app": _send_rtcp,
    "stun-attr-padding": _send_stun,
    "coap-tunnel": _send_coap,
}


def _endpoint_metadata(node_label: str) -> dict[str, str]:
    return {
        "node": node_label,
        "runtime_node": platform.node(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
    }


def _write_ready(path: Path | None, sock: socket.socket, mechanism_id: str) -> None:
    if path is None:
        return
    address = sock.getsockname()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": "celatim.native_marquee_ready.v1",
                "mechanism_id": mechanism_id,
                "bind": str(address[0]),
                "port": int(address[1]),
            },
            sort_keys=True,
        )
        + "\n"
    )


def run_receiver(
    *,
    mechanism: Mechanism,
    bind: str,
    port: int,
    expected_symbols: int,
    expected_payload_len: int,
    expected_payload_sha256: str,
    sender_node: str,
    topology_kind: str,
    endpoint_node: str,
    source_revision: str,
    ready_file: Path | None = None,
) -> dict[str, Any]:
    listener = (
        _tcp_listener(bind, port) if mechanism.id in TCP_MECHANISMS else _udp_listener(bind, port)
    )
    with listener:
        _write_ready(ready_file, listener, mechanism.id)
        started = time.monotonic()
        result = RECEIVERS[mechanism.id](listener, expected_symbols)
        elapsed = time.monotonic() - started
    recovered = decode_payload(mechanism, result.symbols)
    recovered_sha256 = _sha256(recovered)
    exact = (
        len(result.symbols) == expected_symbols
        and len(recovered) == expected_payload_len
        and recovered_sha256 == expected_payload_sha256
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "role": "receiver",
        "mechanism_id": mechanism.id,
        "transport_kind": TRANSPORT_KIND[mechanism.id],
        "carrier_surface": CARRIER_SURFACE[mechanism.id],
        "implementation_scope": IMPLEMENTATION_SCOPE[mechanism.id],
        "topology_kind": topology_kind,
        "sender_node": sender_node,
        "receiver": _endpoint_metadata(endpoint_node),
        "source_revision": source_revision,
        "peer_address": result.peer,
        "expected_symbols": expected_symbols,
        "observed_symbols": len(result.symbols),
        "expected_payload_len": expected_payload_len,
        "recovered_payload_len": len(recovered),
        "expected_payload_sha256": expected_payload_sha256,
        "recovered_payload_sha256": recovered_sha256,
        "exact_recovery": exact,
        "carrier_wire_bytes": result.carrier_wire_bytes,
        "response_wire_bytes": result.response_wire_bytes,
        "elapsed_s": elapsed,
        "library_versions": _versions(mechanism.id),
        "ok": exact,
    }


def run_sender(
    *,
    mechanism: Mechanism,
    host: str,
    port: int,
    payload: bytes,
    receiver_node: str,
    topology_kind: str,
    endpoint_node: str,
    source_revision: str,
) -> dict[str, Any]:
    symbols = encode_payload(mechanism, payload)
    started = time.monotonic()
    result = SENDERS[mechanism.id](host, port, symbols)
    elapsed = time.monotonic() - started
    validated = result.responses_validated == len(symbols)
    return {
        "schema_version": SCHEMA_VERSION,
        "role": "sender",
        "mechanism_id": mechanism.id,
        "transport_kind": TRANSPORT_KIND[mechanism.id],
        "carrier_surface": CARRIER_SURFACE[mechanism.id],
        "implementation_scope": IMPLEMENTATION_SCOPE[mechanism.id],
        "topology_kind": topology_kind,
        "sender": _endpoint_metadata(endpoint_node),
        "source_revision": source_revision,
        "receiver_node": receiver_node,
        "peer_address": result.peer,
        "payload_len": len(payload),
        "payload_sha256": _sha256(payload),
        "carrier_units": len(symbols),
        "carrier_wire_bytes": result.carrier_wire_bytes,
        "response_wire_bytes": result.response_wire_bytes,
        "responses_expected": len(symbols),
        "responses_validated": result.responses_validated,
        "response_validation_complete": validated,
        "elapsed_s": elapsed,
        "library_versions": _versions(mechanism.id),
        "ok": validated,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path)
    subparsers = parser.add_subparsers(dest="command", required=True)

    receiver = subparsers.add_parser("receiver")
    receiver.add_argument("--mechanism", choices=SUPPORTED_MECHANISMS, required=True)
    receiver.add_argument("--bind", default="0.0.0.0")
    receiver.add_argument("--port", type=int, default=0)
    receiver.add_argument("--expected-symbols", type=int, required=True)
    receiver.add_argument("--expected-payload-len", type=int, required=True)
    receiver.add_argument("--expected-payload-sha256", required=True)
    receiver.add_argument("--sender-node", required=True)
    receiver.add_argument("--endpoint-node", required=True)
    receiver.add_argument("--source-revision", required=True)
    receiver.add_argument(
        "--topology-kind",
        choices=("loopback_split_process", "cross_host"),
        required=True,
    )
    receiver.add_argument("--ready-file", type=Path)
    receiver.add_argument("--output", type=Path, required=True)

    sender = subparsers.add_parser("sender")
    sender.add_argument("--mechanism", choices=SUPPORTED_MECHANISMS, required=True)
    sender.add_argument("--host", required=True)
    sender.add_argument("--port", type=int, required=True)
    sender.add_argument("--payload-file", type=Path, required=True)
    sender.add_argument("--receiver-node", required=True)
    sender.add_argument("--endpoint-node", required=True)
    sender.add_argument("--source-revision", required=True)
    sender.add_argument(
        "--topology-kind",
        choices=("loopback_split_process", "cross_host"),
        required=True,
    )
    sender.add_argument("--output", type=Path, required=True)
    return parser


def _write_output(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    mechanism = _mechanism(args.mechanism, args.catalog)
    try:
        if args.command == "receiver":
            document = run_receiver(
                mechanism=mechanism,
                bind=args.bind,
                port=args.port,
                expected_symbols=args.expected_symbols,
                expected_payload_len=args.expected_payload_len,
                expected_payload_sha256=args.expected_payload_sha256,
                sender_node=args.sender_node,
                topology_kind=args.topology_kind,
                endpoint_node=args.endpoint_node,
                source_revision=args.source_revision,
                ready_file=args.ready_file,
            )
        else:
            document = run_sender(
                mechanism=mechanism,
                host=args.host,
                port=args.port,
                payload=args.payload_file.read_bytes(),
                receiver_node=args.receiver_node,
                topology_kind=args.topology_kind,
                endpoint_node=args.endpoint_node,
                source_revision=args.source_revision,
            )
    except Exception as exc:
        document = {
            "schema_version": SCHEMA_VERSION,
            "role": args.command,
            "mechanism_id": args.mechanism,
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "endpoint": _endpoint_metadata(args.endpoint_node),
        }
        _write_output(args.output, document)
        print(document["error"], file=sys.stderr)
        return 1
    _write_output(args.output, document)
    return 0 if document["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
