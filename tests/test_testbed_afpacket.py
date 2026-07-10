"""AF_PACKET raw-frame helper."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from celatim.errors import TransportError
from celatim.testbed import ETH_P_ALL, AfpacketFrameSocket, AfpacketSocketConfig


@dataclass
class FakePacketSocket:
    recv_queue: list[bytes] = field(default_factory=list)
    bind_error: BaseException | None = None
    short_send: bool = False
    bound: tuple[str, int] | None = None
    timeout: float | None = None
    sent: list[bytes] = field(default_factory=list)
    closed: bool = False

    def bind(self, address: tuple[str, int]) -> None:
        if self.bind_error is not None:
            raise self.bind_error
        self.bound = address

    def settimeout(self, value: float | None) -> None:
        self.timeout = value

    def send(self, data: bytes) -> int:
        self.sent.append(data)
        return len(data) - 1 if self.short_send else len(data)

    def recv(self, bufsize: int) -> bytes:
        if not self.recv_queue:
            raise TimeoutError("timeout")
        frame = self.recv_queue.pop(0)
        return frame[:bufsize]

    def close(self) -> None:
        self.closed = True


@dataclass
class FakePacketSocketFactory:
    socket: FakePacketSocket
    protocols: list[int] = field(default_factory=list)

    def open(self, protocol: int) -> FakePacketSocket:
        self.protocols.append(protocol)
        return self.socket


def _frame(tag: bytes = b"A") -> bytes:
    return b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x00\x11\x22\x33\x44\x55" + b"\x08\x00" + tag


def test_afpacket_sender_binds_and_sends_full_frame():
    fake = FakePacketSocket()
    factory = FakePacketSocketFactory(fake)

    with AfpacketFrameSocket.sender("vs", factory=factory) as sender:
        sender.send_frame(_frame(b"payload"))

    assert factory.protocols == [0]
    assert fake.bound == ("vs", 0)
    assert fake.timeout is None
    assert fake.sent == [_frame(b"payload")]
    assert fake.closed is True


def test_afpacket_receiver_binds_protocol_timeout_and_filters_frames():
    accepted = _frame(b"accepted")
    fake = FakePacketSocket(recv_queue=[_frame(b"drop"), accepted, _frame(b"also")])
    factory = FakePacketSocketFactory(fake)

    with AfpacketFrameSocket.receiver("vr", timeout_s=2.5, factory=factory) as receiver:
        frames = receiver.receive_frames(
            1,
            predicate=lambda frame: frame.endswith(b"accepted"),
            require_count=True,
        )

    assert factory.protocols == [ETH_P_ALL]
    assert fake.bound == ("vr", 0)
    assert fake.timeout == 2.5
    assert frames == (accepted,)
    assert fake.closed is True


def test_afpacket_receive_frame_reports_timeout():
    fake = FakePacketSocket()
    receiver = AfpacketFrameSocket.receiver("vr", factory=FakePacketSocketFactory(fake))
    receiver.open()

    with pytest.raises(TransportError, match="timed out"):
        receiver.receive_frame()


def test_afpacket_receive_frames_can_require_exact_count():
    fake = FakePacketSocket(recv_queue=[_frame(b"one")])
    receiver = AfpacketFrameSocket.receiver("vr", factory=FakePacketSocketFactory(fake))
    receiver.open()

    with pytest.raises(TransportError, match="expected 2"):
        receiver.receive_frames(2, require_count=True)


def test_afpacket_send_requires_open_socket_and_ethernet_header():
    sender = AfpacketFrameSocket.sender("vs", factory=FakePacketSocketFactory(FakePacketSocket()))

    with pytest.raises(TransportError, match="not open"):
        sender.send_frame(_frame())

    sender.open()
    with pytest.raises(TransportError, match="Ethernet header"):
        sender.send_frame(b"short")


def test_afpacket_send_detects_short_write():
    fake = FakePacketSocket(short_send=True)
    sender = AfpacketFrameSocket.sender("vs", factory=FakePacketSocketFactory(fake))
    sender.open()

    with pytest.raises(TransportError, match="short AF_PACKET send"):
        sender.send_frame(_frame())


def test_afpacket_open_closes_socket_after_bind_failure():
    fake = FakePacketSocket(bind_error=OSError("bind failed"))
    sender = AfpacketFrameSocket.sender("vs", factory=FakePacketSocketFactory(fake))

    with pytest.raises(OSError, match="bind failed"):
        sender.open()

    assert fake.closed is True


def test_afpacket_rejects_invalid_config():
    with pytest.raises(ValueError, match="interface"):
        AfpacketSocketConfig(interface="")
    with pytest.raises(ValueError, match="protocol"):
        AfpacketSocketConfig(interface="vs", protocol=0x10000)
    with pytest.raises(ValueError, match="timeout_s"):
        AfpacketSocketConfig(interface="vs", timeout_s=0)
    with pytest.raises(ValueError, match="max_frame_bytes"):
        AfpacketSocketConfig(interface="vs", max_frame_bytes=13)
