"""Mechanism-aware AF_PACKET carrier transport."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType

import pytest

from celatim.errors import TransportError
from celatim.session import ChannelSession, MechanismProfile
from celatim.testbed import (
    ETH_P_ALL,
    ETHERTYPE_IPV4,
    AfpacketCarrierTransport,
    Ipv4PacketPathConfig,
    PacketProtocol,
    build_ipv4_carrier_frame,
    build_tcp_reserved_bits_frame,
    carrier_payload_from_frame,
    run_afpacket_roundtrip,
    tcp_reserved_bits_from_frame,
)

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


@dataclass
class FakePacketSocket:
    recv_queue: list[bytes] = field(default_factory=list)
    bound: tuple[str, int] | None = None
    timeout: float | None = None
    sent: list[bytes] = field(default_factory=list)
    closed: bool = False

    def bind(self, address: tuple[str, int]) -> None:
        self.bound = address

    def settimeout(self, value: float | None) -> None:
        self.timeout = value

    def send(self, data: bytes) -> int:
        self.sent.append(data)
        return len(data)

    def recv(self, bufsize: int) -> bytes:
        if not self.recv_queue:
            raise TimeoutError("timeout")
        return self.recv_queue.pop(0)[:bufsize]

    def close(self) -> None:
        self.closed = True


@dataclass
class QueueSocketFactory:
    sockets: list[FakePacketSocket]
    protocols: list[int] = field(default_factory=list)

    def open(self, protocol: int) -> FakePacketSocket:
        self.protocols.append(protocol)
        if not self.sockets:
            raise AssertionError("no fake sockets left")
        return self.sockets.pop(0)


@dataclass
class SharedFrameQueue:
    frames: list[bytes] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    condition: threading.Condition = field(default_factory=threading.Condition)


class SharedPacketSocket:
    def __init__(self, role: str, shared: SharedFrameQueue) -> None:
        self.role = role
        self.shared = shared
        self.bound: tuple[str, int] | None = None
        self.closed = False

    def bind(self, address: tuple[str, int]) -> None:
        self.bound = address
        self.shared.events.append(f"bind-{self.role}:{address[0]}")

    def settimeout(self, value: float | None) -> None:
        self.shared.events.append(f"timeout-{self.role}:{value}")

    def send(self, data: bytes) -> int:
        with self.shared.condition:
            self.shared.events.append("send")
            self.shared.frames.append(data)
            self.shared.condition.notify_all()
        return len(data)

    def recv(self, bufsize: int) -> bytes:
        with self.shared.condition:
            self.shared.events.append("recv-wait")
            if not self.shared.frames:
                self.shared.condition.wait(timeout=1.0)
            if not self.shared.frames:
                raise TimeoutError("timeout")
            return self.shared.frames.pop(0)[:bufsize]

    def close(self) -> None:
        self.closed = True
        self.shared.events.append(f"close-{self.role}")


@dataclass
class SharedSocketFactory:
    shared: SharedFrameQueue
    protocols: list[int] = field(default_factory=list)

    def open(self, protocol: int) -> SharedPacketSocket:
        self.protocols.append(protocol)
        role = "receiver" if protocol == ETH_P_ALL else "sender"
        self.shared.events.append(f"open-{role}")
        return SharedPacketSocket(role, self.shared)


@dataclass
class FakeCapture:
    events: list[str]

    def __enter__(self) -> FakeCapture:
        self.events.append("capture-enter")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.events.append("capture-exit")


def test_ipv4_tcp_carrier_frame_roundtrips_payload_and_headers():
    config = Ipv4PacketPathConfig(protocol=PacketProtocol.TCP, src_port=40000, dst_port=443)
    carrier = b"HTTP2 carrier bytes"

    frame = build_ipv4_carrier_frame(config, carrier, index=7)

    assert frame[0:6] == bytes.fromhex("02 00 00 00 00 02")
    assert frame[6:12] == bytes.fromhex("02 00 00 00 00 01")
    assert frame[12:14] == ETHERTYPE_IPV4.to_bytes(2, "big")
    assert frame[14] == 0x45
    assert frame[23] == 6
    assert int.from_bytes(frame[18:20], "big") == 0x4007
    assert carrier_payload_from_frame(config, frame) == carrier


def test_ipv4_tcp_reserved_bits_frame_roundtrips_header_symbol():
    config = Ipv4PacketPathConfig(protocol=PacketProtocol.TCP, src_port=40000, dst_port=443)
    wrong_port = Ipv4PacketPathConfig(protocol=PacketProtocol.TCP, src_port=40000, dst_port=8443)

    frame = build_tcp_reserved_bits_frame(config, 0xB, index=3)

    assert frame[23] == 6
    assert frame[14 + 20 + 12] & 0x0F == 0xB
    assert int.from_bytes(frame[18:20], "big") == 0x4003
    assert tcp_reserved_bits_from_frame(config, frame) == 0xB
    assert tcp_reserved_bits_from_frame(wrong_port, frame) is None
    assert carrier_payload_from_frame(config, frame) == b""


def test_ipv4_udp_carrier_frame_roundtrips_payload_and_rejects_wrong_port():
    config = Ipv4PacketPathConfig(protocol=PacketProtocol.UDP, src_port=40000, dst_port=443)
    wrong_port = Ipv4PacketPathConfig(protocol=PacketProtocol.UDP, src_port=40000, dst_port=8443)
    carrier = b"QUIC carrier bytes"

    frame = build_ipv4_carrier_frame(config, carrier)

    assert frame[23] == 17
    assert carrier_payload_from_frame(config, frame) == carrier
    assert carrier_payload_from_frame(wrong_port, frame) is None


def test_afpacket_carrier_transport_roundtrips_real_pdu_payload():
    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    send_socket = FakePacketSocket()
    recv_socket = FakePacketSocket()
    factory = QueueSocketFactory([send_socket, recv_socket])
    transport = AfpacketCarrierTransport(profile, socket_factory=factory)

    receipt = ChannelSession(profile, transport).send_message(b"\x00\xffpacket", session_id="pkt")
    recv_socket.recv_queue = list(send_socket.sent)
    result = ChannelSession(profile, transport).receive_message(receipt)

    assert result.payload == b"\x00\xffpacket"
    assert receipt.carrier_units == len(send_socket.sent)
    assert result.evidence.carrier_units == receipt.carrier_units
    assert transport.expected_frames_for("pkt") == receipt.carrier_units
    assert factory.protocols == [0, ETH_P_ALL]
    assert send_socket.bound == ("vs", 0)
    assert recv_socket.bound == ("vr", 0)
    assert recv_socket.timeout == 10.0
    assert send_socket.closed is True
    assert recv_socket.closed is True


def test_afpacket_carrier_transport_roundtrips_tcp_reserved_header_bits():
    profile = MechanismProfile.from_catalog("tcp-reserved-bits", DATA)
    send_socket = FakePacketSocket()
    recv_socket = FakePacketSocket()
    factory = QueueSocketFactory([send_socket, recv_socket])
    transport = AfpacketCarrierTransport(profile, socket_factory=factory)

    receipt = ChannelSession(profile, transport).send_message(b"\x00\xfftcp", session_id="tcp")
    recv_socket.recv_queue = list(send_socket.sent)
    result = ChannelSession(profile, transport).receive_message(receipt)

    assert result.payload == b"\x00\xfftcp"
    assert receipt.carrier_units == len(send_socket.sent)
    assert {frame[14 + 20 + 12] & 0x0F for frame in send_socket.sent}.issubset(set(range(16)))
    assert factory.protocols == [0, ETH_P_ALL]


def test_run_afpacket_roundtrip_arms_capture_and_receiver_before_send():
    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    shared = SharedFrameQueue()
    factory = SharedSocketFactory(shared)

    live = run_afpacket_roundtrip(
        profile,
        b"\x00\xfflive",
        session_id="live",
        socket_factory=factory,
        capture=FakeCapture(shared.events),
    )

    assert live.result.payload == b"\x00\xfflive"
    assert live.receipt.session_id == "live"
    assert live.expected_frames == live.receipt.carrier_units
    assert len(live.symbols) == live.expected_frames
    assert factory.protocols == [ETH_P_ALL, 0]
    assert shared.events.index("capture-enter") < shared.events.index("open-receiver")
    assert shared.events.index("open-receiver") < shared.events.index("open-sender")
    assert shared.events.index("open-sender") < shared.events.index("send")
    assert shared.events.index("send") < shared.events.index("capture-exit")


def test_afpacket_carrier_transport_supports_separate_receiver_with_expected_count():
    profile = MechanismProfile.from_catalog("quic-connection-id", DATA)
    send_socket = FakePacketSocket()
    sender_factory = QueueSocketFactory([send_socket])
    sender = AfpacketCarrierTransport(profile, socket_factory=sender_factory)
    receipt = ChannelSession(profile, sender).send_message(b"\x00\xffquic", session_id="split")

    recv_socket = FakePacketSocket(recv_queue=list(send_socket.sent))
    receiver = AfpacketCarrierTransport(
        profile,
        Ipv4PacketPathConfig(
            protocol=PacketProtocol.UDP,
            dst_port=443,
            expected_frames=receipt.carrier_units,
        ),
        socket_factory=QueueSocketFactory([recv_socket]),
    )
    result = ChannelSession(profile, receiver).receive_message(receipt.session_id)

    assert result.payload == b"\x00\xffquic"
    assert result.evidence.carrier_units == receipt.carrier_units


def test_afpacket_carrier_transport_filters_unrelated_frames_before_decoding():
    profile = MechanismProfile.from_catalog("rtp-rtcp-ext-app", DATA)
    send_socket = FakePacketSocket()
    recv_socket = FakePacketSocket()
    transport = AfpacketCarrierTransport(
        profile,
        Ipv4PacketPathConfig(protocol=PacketProtocol.UDP, dst_port=5004),
        socket_factory=QueueSocketFactory([send_socket, recv_socket]),
    )

    receipt = ChannelSession(profile, transport).send_message(b"\x00\xffrtcp", session_id="rtcp")
    unrelated = build_ipv4_carrier_frame(
        Ipv4PacketPathConfig(protocol=PacketProtocol.UDP, dst_port=9999),
        b"not this carrier",
    )
    recv_socket.recv_queue = [unrelated, *send_socket.sent]
    result = ChannelSession(profile, transport).receive_message(receipt)

    assert result.payload == b"\x00\xffrtcp"


def test_afpacket_carrier_transport_rejects_symbol_only_mechanism():
    profile = MechanismProfile.from_catalog("bgp-path-attr-flags", DATA)
    transport = AfpacketCarrierTransport(
        profile,
        socket_factory=QueueSocketFactory([FakePacketSocket()]),
    )

    with pytest.raises(TransportError, match="requires carrier bytes"):
        ChannelSession(profile, transport).send_message(b"offset", session_id="bad")


def test_afpacket_carrier_transport_rejects_unparseable_carrier_bytes():
    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    recv_socket = FakePacketSocket(
        recv_queue=[
            build_ipv4_carrier_frame(
                Ipv4PacketPathConfig(protocol=PacketProtocol.TCP, expected_frames=1),
                b"not an HTTP2 PING carrier",
            )
        ]
    )
    transport = AfpacketCarrierTransport(
        profile,
        Ipv4PacketPathConfig(protocol=PacketProtocol.TCP, expected_frames=1),
        socket_factory=QueueSocketFactory([recv_socket]),
    )

    with pytest.raises(TransportError, match="invalid packet-path carrier bytes"):
        ChannelSession(profile, transport).receive_message("bad")


def test_afpacket_carrier_transport_requires_expected_count_for_receive_only():
    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    transport = AfpacketCarrierTransport(
        profile,
        socket_factory=QueueSocketFactory([FakePacketSocket()]),
    )

    with pytest.raises(TransportError, match="expected frame count"):
        ChannelSession(profile, transport).receive_message("missing")


def test_ipv4_packet_path_config_rejects_invalid_values():
    with pytest.raises(ValueError, match="MAC"):
        Ipv4PacketPathConfig(src_mac="bad")
    with pytest.raises(ValueError, match="src_port"):
        Ipv4PacketPathConfig(src_port=0)
    with pytest.raises(ValueError, match="ttl"):
        Ipv4PacketPathConfig(ttl=0)
    with pytest.raises(ValueError, match="expected_frames"):
        Ipv4PacketPathConfig(expected_frames=0)
