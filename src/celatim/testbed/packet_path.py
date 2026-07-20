"""Mechanism-aware AF_PACKET carrier transport for IPv4 packet paths."""

from __future__ import annotations

import ipaddress
import struct
from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractContextManager, ExitStack
from dataclasses import dataclass, replace
from enum import Enum
from time import monotonic, sleep
from typing import Any

from celatim.envelope import carrier_bytes_for_symbols
from celatim.errors import TransportError
from celatim.pdu import TCP_RESERVED_BITS_WIDTH
from celatim.session import (
    ChannelSession,
    InMemoryTransport,
    MechanismProfile,
    PacingConfig,
    ReceiveResult,
    ReliabilityPolicy,
    SendReceipt,
    Symbol,
)

from .afpacket import (
    ETH_P_ALL,
    AfpacketFrameSocket,
    PacketSocketFactory,
)

ETHERTYPE_IPV4 = 0x0800
IPV4_HEADER_BYTES = 20
TCP_HEADER_BYTES = 20
UDP_HEADER_BYTES = 8
_ETHERNET_HEADER_BYTES = 14
_IPV4_HEADER = struct.Struct("!BBHHHBBH4s4s")
_TCP_HEADER = struct.Struct("!HHIIBBHHH")
_UDP_HEADER = struct.Struct("!HHHH")


class PacketProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"

    @property
    def ip_proto(self) -> int:
        match self:
            case PacketProtocol.TCP:
                return 6
            case PacketProtocol.UDP:
                return 17


@dataclass(frozen=True)
class Ipv4PacketPathConfig:
    sender_interface: str = "vs"
    receiver_interface: str = "vr"
    src_mac: str = "02:00:00:00:00:01"
    dst_mac: str = "02:00:00:00:00:02"
    src_ip: str = "10.10.0.1"
    dst_ip: str = "10.10.0.2"
    src_port: int = 40000
    dst_port: int = 443
    protocol: PacketProtocol = PacketProtocol.TCP
    ttl: int = 64
    tcp_flags: int = 0x18
    tcp_window: int = 8192
    ip_id_base: int = 0x4000
    timeout_s: float | None = 10.0
    expected_frames: int | None = None
    require_expected_frames: bool = True

    def __post_init__(self) -> None:
        _mac_bytes(self.src_mac)
        _mac_bytes(self.dst_mac)
        ipaddress.IPv4Address(self.src_ip)
        ipaddress.IPv4Address(self.dst_ip)
        for field_name in ("src_port", "dst_port"):
            value = getattr(self, field_name)
            if value <= 0 or value > 0xFFFF:
                raise ValueError(f"{field_name} must be in [1, 65535]")
        if self.ttl <= 0 or self.ttl > 0xFF:
            raise ValueError("ttl must be in [1, 255]")
        if self.tcp_flags < 0 or self.tcp_flags > 0xFF:
            raise ValueError("tcp_flags must be in [0, 255]")
        if self.tcp_window < 0 or self.tcp_window > 0xFFFF:
            raise ValueError("tcp_window must be in [0, 65535]")
        if self.ip_id_base < 0 or self.ip_id_base > 0xFFFF:
            raise ValueError("ip_id_base must be in [0, 65535]")
        if self.timeout_s is not None and self.timeout_s <= 0:
            raise ValueError("timeout_s must be > 0")
        if self.expected_frames is not None and self.expected_frames <= 0:
            raise ValueError("expected_frames must be > 0")


class AfpacketCarrierTransport:
    """Send adapter carrier bytes as Ethernet/IPv4/TCP or UDP frames.

    This transport is intentionally limited to parser-visible mechanism adapters. It
    refuses offset-represented rows so live packet-path evidence cannot accidentally
    regress to "write bytes into a zero pad at a nominal offset."
    """

    def __init__(
        self,
        profile: MechanismProfile,
        config: Ipv4PacketPathConfig | None = None,
        *,
        socket_factory: PacketSocketFactory | None = None,
    ) -> None:
        self.profile = profile
        self.config = config or default_ipv4_packet_path_config_for(profile.id)
        self.socket_factory = socket_factory
        self._expected_counts: dict[str, int] = {}
        self._pacing: dict[str, PacingConfig | None] = {}
        self._received_symbols: dict[str, list[Symbol]] = {}

    def send_symbols(
        self,
        session_id: str,
        symbols: list[Symbol],
        pacing: PacingConfig | None = None,
    ) -> None:
        if self.profile.id == "tcp-reserved-bits":
            frames = tuple(
                build_tcp_reserved_bits_frame(
                    self.config, _reserved_bits_symbol(symbol), index=index
                )
                for index, symbol in enumerate(symbols)
            )
        else:
            carriers = carrier_bytes_for_symbols(self.profile, symbols)
            if symbols and not carriers:
                raise TransportError(f"{self.profile.id}: packet path requires carrier bytes")
            frames = tuple(
                build_ipv4_carrier_frame(self.config, carrier, index=index)
                for index, carrier in enumerate(carriers)
            )
        with AfpacketFrameSocket.sender(
            self.config.sender_interface,
            factory=self.socket_factory,
        ) as sender:
            _send_frames_with_pacing(sender, frames, pacing)
        self._expected_counts[session_id] = len(frames)
        self._pacing[session_id] = pacing

    def receive_symbols(self, session_id: str) -> list[Symbol]:
        return self._receive_symbols(session_id, timeout_s=self.config.timeout_s)

    def receive_symbols_with_timeout(
        self,
        session_id: str,
        timeout_s: float | None,
    ) -> list[Symbol]:
        active_timeout_s = self.config.timeout_s if timeout_s is None else timeout_s
        return self._receive_symbols(session_id, timeout_s=active_timeout_s)

    def _receive_symbols(
        self,
        session_id: str,
        *,
        timeout_s: float | None,
    ) -> list[Symbol]:
        if session_id in self._received_symbols:
            return list(self._received_symbols[session_id])
        expected = self._expected_frames(session_id)
        with AfpacketFrameSocket.receiver(
            self.config.receiver_interface,
            protocol=ETH_P_ALL,
            timeout_s=timeout_s,
            factory=self.socket_factory,
        ) as receiver:
            frames = receiver.receive_frames(
                expected,
                predicate=lambda frame: carrier_payload_from_frame(self.config, frame) is not None,
                require_count=self.config.require_expected_frames,
            )
        return self._symbols_from_frames(session_id, frames)

    def receive_symbols_from_receiver(
        self,
        session_id: str,
        receiver: AfpacketFrameSocket,
    ) -> list[Symbol]:
        if session_id in self._received_symbols:
            return list(self._received_symbols[session_id])
        expected = self._expected_frames(session_id)
        frames = receiver.receive_frames(
            expected,
            predicate=lambda frame: carrier_payload_from_frame(self.config, frame) is not None,
            require_count=self.config.require_expected_frames,
        )
        return self._symbols_from_frames(session_id, frames)

    def _symbols_from_frames(self, session_id: str, frames: tuple[bytes, ...]) -> list[Symbol]:
        if self.profile.id == "tcp-reserved-bits":
            try:
                symbols = [tcp_reserved_bits_from_frame(self.config, frame) for frame in frames]
            except Exception as exc:
                raise TransportError(
                    f"{self.profile.id}: invalid packet-path TCP reserved-bit frame: {exc}"
                ) from exc
            if any(symbol is None for symbol in symbols):
                raise TransportError("received non-matching TCP reserved-bit frame after filtering")
            values: list[Symbol] = [int(symbol) for symbol in symbols if symbol is not None]
            self._received_symbols[session_id] = values
            return list(values)
        carriers = [carrier_payload_from_frame(self.config, frame) for frame in frames]
        if any(carrier is None for carrier in carriers):
            raise TransportError("received non-matching AF_PACKET frame after filtering")
        try:
            symbols = [
                self.profile.adapter.parse_carrier(carrier)
                for carrier in carriers
                if carrier is not None
            ]
            self._received_symbols[session_id] = symbols
            return list(symbols)
        except Exception as exc:
            raise TransportError(
                f"{self.profile.id}: invalid packet-path carrier bytes: {exc}"
            ) from exc

    def pacing_for(self, session_id: str) -> PacingConfig | None:
        return self._pacing.get(session_id)

    def expected_frames_for(self, session_id: str) -> int | None:
        return self._expected_counts.get(session_id) or self.config.expected_frames

    def with_expected_frames(self, expected_frames: int) -> AfpacketCarrierTransport:
        return AfpacketCarrierTransport(
            self.profile,
            replace(self.config, expected_frames=expected_frames),
            socket_factory=self.socket_factory,
        )

    def _expected_frames(self, session_id: str) -> int:
        expected = self.expected_frames_for(session_id)
        if expected is None:
            raise TransportError(
                "AF_PACKET receive requires expected frame count from send() or config"
            )
        return expected


@dataclass(frozen=True)
class AfpacketRoundtripResult:
    receipt: SendReceipt
    result: ReceiveResult
    symbols: tuple[Symbol, ...]
    expected_frames: int


def run_afpacket_roundtrip(
    profile: MechanismProfile,
    payload: bytes,
    *,
    session_id: str | None = None,
    config: Ipv4PacketPathConfig | None = None,
    pacing: PacingConfig | None = None,
    reliability: ReliabilityPolicy | None = None,
    socket_factory: PacketSocketFactory | None = None,
    capture: AbstractContextManager[Any] | None = None,
) -> AfpacketRoundtripResult:
    """Run a live packet-path roundtrip with receive/capture armed before send."""
    active_config = config or default_ipv4_packet_path_config_for(profile.id)
    memory_transport = InMemoryTransport()
    receipt = ChannelSession(profile, memory_transport).send_message(
        payload,
        session_id=session_id,
        pacing=pacing,
    )
    symbols = memory_transport.receive_symbols(receipt.session_id)
    receiver_transport = AfpacketCarrierTransport(
        profile,
        replace(active_config, expected_frames=receipt.carrier_units),
        socket_factory=socket_factory,
    )
    sender_transport = AfpacketCarrierTransport(
        profile,
        active_config,
        socket_factory=socket_factory,
    )

    with ExitStack() as stack:
        if capture is not None:
            stack.enter_context(capture)
        receiver_socket = stack.enter_context(
            AfpacketFrameSocket.receiver(
                active_config.receiver_interface,
                protocol=ETH_P_ALL,
                timeout_s=active_config.timeout_s,
                factory=socket_factory,
            )
        )
        receiver_tap = _OpenAfpacketReceiverTap(receiver_transport, receiver_socket)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                ChannelSession(
                    profile,
                    receiver_transport,
                    tap=receiver_tap,
                    reliability=reliability,
                ).receive_message,
                receipt.session_id,
            )
            sender_transport.send_symbols(receipt.session_id, symbols, pacing)
            result = future.result()

    received_symbols = receiver_transport.receive_symbols(receipt.session_id)
    return AfpacketRoundtripResult(
        receipt=receipt,
        result=result,
        symbols=tuple(received_symbols),
        expected_frames=receipt.carrier_units,
    )


class _OpenAfpacketReceiverTap:
    def __init__(
        self,
        transport: AfpacketCarrierTransport,
        receiver: AfpacketFrameSocket,
    ) -> None:
        self._transport = transport
        self._receiver = receiver

    def receive_symbols(self, session_id: str) -> list[Symbol]:
        return self._transport.receive_symbols_from_receiver(session_id, self._receiver)


def _send_frames_with_pacing(
    sender: AfpacketFrameSocket,
    frames: tuple[bytes, ...],
    pacing: PacingConfig | None,
) -> None:
    period = pacing.effective_symbol_period_s if pacing is not None else None
    if pacing is None:
        sender.send_frames(frames)
        return
    if pacing is not None and pacing.base_delay_s > 0:
        sleep(pacing.base_delay_s)
    start = monotonic()
    for index, frame in enumerate(frames):
        if index > 0 and period is not None:
            delay = start + index * period - monotonic()
            if delay > 0:
                sleep(delay)
        sender.send_frame(frame)


def build_ipv4_carrier_frame(
    config: Ipv4PacketPathConfig,
    carrier: bytes,
    *,
    index: int = 0,
) -> bytes:
    src_ip = ipaddress.IPv4Address(config.src_ip).packed
    dst_ip = ipaddress.IPv4Address(config.dst_ip).packed
    ip_id = (config.ip_id_base + index) & 0xFFFF
    match config.protocol:
        case PacketProtocol.TCP:
            l4 = _tcp_segment(config, src_ip, dst_ip, carrier, seq=index + 1)
        case PacketProtocol.UDP:
            l4 = _udp_datagram(config, src_ip, dst_ip, carrier)
    total_len = IPV4_HEADER_BYTES + len(l4)
    header = _IPV4_HEADER.pack(
        0x45,
        0,
        total_len,
        ip_id,
        0x4000,
        config.ttl,
        config.protocol.ip_proto,
        0,
        src_ip,
        dst_ip,
    )
    checksum = _checksum(header)
    ip_header = _IPV4_HEADER.pack(
        0x45,
        0,
        total_len,
        ip_id,
        0x4000,
        config.ttl,
        config.protocol.ip_proto,
        checksum,
        src_ip,
        dst_ip,
    )
    return (
        _mac_bytes(config.dst_mac)
        + _mac_bytes(config.src_mac)
        + ETHERTYPE_IPV4.to_bytes(2, "big")
        + ip_header
        + l4
    )


def build_tcp_reserved_bits_frame(
    config: Ipv4PacketPathConfig,
    reserved_bits: int,
    *,
    index: int = 0,
) -> bytes:
    if config.protocol is not PacketProtocol.TCP:
        raise ValueError("TCP reserved-bit frames require TCP protocol")
    if not 0 <= reserved_bits < (1 << TCP_RESERVED_BITS_WIDTH):
        raise ValueError("reserved_bits must fit in 3 bits")
    src_ip = ipaddress.IPv4Address(config.src_ip).packed
    dst_ip = ipaddress.IPv4Address(config.dst_ip).packed
    ip_id = (config.ip_id_base + index) & 0xFFFF
    l4 = _tcp_segment(
        config,
        src_ip,
        dst_ip,
        b"",
        seq=index + 1,
        reserved_bits=reserved_bits,
    )
    total_len = IPV4_HEADER_BYTES + len(l4)
    header = _IPV4_HEADER.pack(
        0x45,
        0,
        total_len,
        ip_id,
        0x4000,
        config.ttl,
        config.protocol.ip_proto,
        0,
        src_ip,
        dst_ip,
    )
    checksum = _checksum(header)
    ip_header = _IPV4_HEADER.pack(
        0x45,
        0,
        total_len,
        ip_id,
        0x4000,
        config.ttl,
        config.protocol.ip_proto,
        checksum,
        src_ip,
        dst_ip,
    )
    return (
        _mac_bytes(config.dst_mac)
        + _mac_bytes(config.src_mac)
        + ETHERTYPE_IPV4.to_bytes(2, "big")
        + ip_header
        + l4
    )


def tcp_reserved_bits_from_frame(config: Ipv4PacketPathConfig, frame: bytes) -> int | None:
    if config.protocol is not PacketProtocol.TCP:
        return None
    segment = _matching_l4_segment(config, frame)
    if segment is None:
        return None
    if len(segment) < TCP_HEADER_BYTES or _tcp_payload(config, segment) is None:
        return None
    return (segment[12] & 0x0E) >> 1


def carrier_payload_from_frame(config: Ipv4PacketPathConfig, frame: bytes) -> bytes | None:
    l4 = _matching_l4_segment(config, frame)
    if l4 is None:
        return None
    match config.protocol:
        case PacketProtocol.TCP:
            return _tcp_payload(config, l4)
        case PacketProtocol.UDP:
            return _udp_payload(config, l4)


def _matching_l4_segment(config: Ipv4PacketPathConfig, frame: bytes) -> bytes | None:
    try:
        if len(frame) < _ETHERNET_HEADER_BYTES + IPV4_HEADER_BYTES:
            return None
        if frame[:6] != _mac_bytes(config.dst_mac) or frame[6:12] != _mac_bytes(config.src_mac):
            return None
        if frame[12:14] != ETHERTYPE_IPV4.to_bytes(2, "big"):
            return None
        ip_packet = frame[_ETHERNET_HEADER_BYTES:]
        version = ip_packet[0] >> 4
        ihl = (ip_packet[0] & 0x0F) * 4
        if version != 4 or ihl < IPV4_HEADER_BYTES or len(ip_packet) < ihl:
            return None
        total_len = int.from_bytes(ip_packet[2:4], "big")
        if total_len < ihl or len(ip_packet) < total_len:
            return None
        if ip_packet[9] != config.protocol.ip_proto:
            return None
        if ip_packet[12:16] != ipaddress.IPv4Address(config.src_ip).packed:
            return None
        if ip_packet[16:20] != ipaddress.IPv4Address(config.dst_ip).packed:
            return None
        return ip_packet[ihl:total_len]
    except (ipaddress.AddressValueError, ValueError, IndexError):
        return None


def default_ipv4_packet_path_config_for(mechanism_id: str) -> Ipv4PacketPathConfig:
    if mechanism_id == "rtp-rtcp-ext-app":
        return Ipv4PacketPathConfig(protocol=PacketProtocol.UDP, dst_port=5004)
    if mechanism_id == "quic-connection-id":
        return Ipv4PacketPathConfig(protocol=PacketProtocol.UDP, dst_port=443)
    return Ipv4PacketPathConfig(protocol=PacketProtocol.TCP, dst_port=443)


def _tcp_segment(
    config: Ipv4PacketPathConfig,
    src_ip: bytes,
    dst_ip: bytes,
    payload: bytes,
    *,
    seq: int,
    reserved_bits: int = 0,
) -> bytes:
    if not 0 <= reserved_bits < (1 << TCP_RESERVED_BITS_WIDTH):
        raise ValueError("reserved_bits must fit in 3 bits")
    header = _TCP_HEADER.pack(
        config.src_port,
        config.dst_port,
        seq,
        0,
        (5 << 4) | (reserved_bits << 1),
        config.tcp_flags,
        config.tcp_window,
        0,
        0,
    )
    checksum = _transport_checksum(src_ip, dst_ip, PacketProtocol.TCP.ip_proto, header + payload)
    return (
        _TCP_HEADER.pack(
            config.src_port,
            config.dst_port,
            seq,
            0,
            (5 << 4) | (reserved_bits << 1),
            config.tcp_flags,
            config.tcp_window,
            checksum,
            0,
        )
        + payload
    )


def _udp_datagram(
    config: Ipv4PacketPathConfig,
    src_ip: bytes,
    dst_ip: bytes,
    payload: bytes,
) -> bytes:
    length = UDP_HEADER_BYTES + len(payload)
    header = _UDP_HEADER.pack(config.src_port, config.dst_port, length, 0)
    checksum = _transport_checksum(src_ip, dst_ip, PacketProtocol.UDP.ip_proto, header + payload)
    return _UDP_HEADER.pack(config.src_port, config.dst_port, length, checksum) + payload


def _tcp_payload(config: Ipv4PacketPathConfig, segment: bytes) -> bytes | None:
    if len(segment) < TCP_HEADER_BYTES:
        return None
    src_port, dst_port, _seq, _ack, offset_flags, _flags, _window, _checksum, _urgent = (
        _TCP_HEADER.unpack(segment[:TCP_HEADER_BYTES])
    )
    if src_port != config.src_port or dst_port != config.dst_port:
        return None
    data_offset = (offset_flags >> 4) * 4
    if data_offset < TCP_HEADER_BYTES or len(segment) < data_offset:
        return None
    return segment[data_offset:]


def _udp_payload(config: Ipv4PacketPathConfig, datagram: bytes) -> bytes | None:
    if len(datagram) < UDP_HEADER_BYTES:
        return None
    src_port, dst_port, length, _checksum = _UDP_HEADER.unpack(datagram[:UDP_HEADER_BYTES])
    if src_port != config.src_port or dst_port != config.dst_port:
        return None
    if length < UDP_HEADER_BYTES or len(datagram) < length:
        return None
    return datagram[UDP_HEADER_BYTES:length]


def _transport_checksum(src_ip: bytes, dst_ip: bytes, ip_proto: int, payload: bytes) -> int:
    pseudo = src_ip + dst_ip + bytes([0, ip_proto]) + len(payload).to_bytes(2, "big")
    return _checksum(pseudo + payload)


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(int.from_bytes(data[index : index + 2], "big") for index in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _mac_bytes(value: str) -> bytes:
    parts = value.split(":")
    if len(parts) != 6:
        raise ValueError("MAC address must have 6 octets")
    try:
        data = bytes(int(part, 16) for part in parts)
    except ValueError as exc:
        raise ValueError("MAC address must be hex octets") from exc
    if len(data) != 6:
        raise ValueError("MAC address must have 6 octets")
    return data


def _reserved_bits_symbol(symbol: Symbol) -> int:
    if not isinstance(symbol, int):
        raise TransportError("tcp-reserved-bits packet path requires int symbols")
    if not 0 <= symbol < (1 << TCP_RESERVED_BITS_WIDTH):
        raise TransportError("tcp-reserved-bits symbol does not fit in 3 reserved bits")
    return symbol


__all__ = [
    "ETHERTYPE_IPV4",
    "IPV4_HEADER_BYTES",
    "TCP_HEADER_BYTES",
    "UDP_HEADER_BYTES",
    "AfpacketCarrierTransport",
    "AfpacketRoundtripResult",
    "Ipv4PacketPathConfig",
    "PacketProtocol",
    "build_ipv4_carrier_frame",
    "build_tcp_reserved_bits_frame",
    "carrier_payload_from_frame",
    "default_ipv4_packet_path_config_for",
    "run_afpacket_roundtrip",
    "tcp_reserved_bits_from_frame",
]
