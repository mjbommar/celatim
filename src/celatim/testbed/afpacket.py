"""AF_PACKET raw-frame helpers for live packet-path scenarios."""

from __future__ import annotations

import socket as _socket
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import Protocol, Self, cast

from celatim.errors import TransportError

ETH_P_ALL = 0x0003
MIN_ETHERNET_FRAME_BYTES = 14

type FramePredicate = Callable[[bytes], bool]


class PacketSocket(Protocol):
    def bind(self, address: tuple[str, int]) -> None: ...

    def settimeout(self, value: float | None) -> None: ...

    def send(self, data: bytes) -> int: ...

    def recv(self, bufsize: int) -> bytes: ...

    def close(self) -> None: ...


class PacketSocketFactory(Protocol):
    def open(self, protocol: int) -> PacketSocket: ...


class StdlibPacketSocketFactory:
    """Open Linux AF_PACKET sockets through the standard library."""

    def open(self, protocol: int) -> PacketSocket:
        family = getattr(_socket, "AF_PACKET", None)
        if family is None:
            raise TransportError("AF_PACKET sockets are not available on this platform")
        sock = _socket.socket(family, _socket.SOCK_RAW, _socket.htons(protocol))
        # Enlarge the receive buffer so long covert bursts are not dropped before the
        # per-frame Python decode can drain them (high-frame-count 1-bit mechanisms).
        with suppress(OSError):
            sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_RCVBUF, 32 * 1024 * 1024)
        return cast(PacketSocket, sock)


@dataclass(frozen=True)
class AfpacketSocketConfig:
    interface: str
    protocol: int = 0
    timeout_s: float | None = None
    max_frame_bytes: int = 65535

    def __post_init__(self) -> None:
        if not self.interface:
            raise ValueError("interface must be non-empty")
        if self.protocol < 0 or self.protocol > 0xFFFF:
            raise ValueError("protocol must be in [0, 65535]")
        if self.timeout_s is not None and self.timeout_s <= 0:
            raise ValueError("timeout_s must be > 0")
        if self.max_frame_bytes < MIN_ETHERNET_FRAME_BYTES:
            raise ValueError(f"max_frame_bytes must be >= {MIN_ETHERNET_FRAME_BYTES}")


class AfpacketFrameSocket:
    """Context manager for sending and receiving raw Ethernet frames."""

    def __init__(
        self,
        config: AfpacketSocketConfig,
        factory: PacketSocketFactory | None = None,
    ) -> None:
        self.config = config
        self.factory = factory or StdlibPacketSocketFactory()
        self._socket: PacketSocket | None = None

    @classmethod
    def sender(
        cls,
        interface: str,
        *,
        factory: PacketSocketFactory | None = None,
    ) -> AfpacketFrameSocket:
        return cls(AfpacketSocketConfig(interface=interface, protocol=0), factory)

    @classmethod
    def receiver(
        cls,
        interface: str,
        *,
        protocol: int = ETH_P_ALL,
        timeout_s: float | None = 10.0,
        max_frame_bytes: int = 65535,
        factory: PacketSocketFactory | None = None,
    ) -> AfpacketFrameSocket:
        return cls(
            AfpacketSocketConfig(
                interface=interface,
                protocol=protocol,
                timeout_s=timeout_s,
                max_frame_bytes=max_frame_bytes,
            ),
            factory,
        )

    def __enter__(self) -> Self:
        self.open()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def open(self) -> None:
        if self._socket is not None:
            raise TransportError("AF_PACKET socket already open")
        sock = self.factory.open(self.config.protocol)
        try:
            sock.bind((self.config.interface, 0))
            if self.config.timeout_s is not None:
                sock.settimeout(self.config.timeout_s)
        except Exception:
            sock.close()
            raise
        self._socket = sock

    def close(self) -> None:
        sock = self._socket
        self._socket = None
        if sock is not None:
            sock.close()

    def send_frame(self, frame: bytes) -> None:
        if len(frame) < MIN_ETHERNET_FRAME_BYTES:
            raise TransportError("AF_PACKET frame must include an Ethernet header")
        sock = self._open_socket()
        sent = sock.send(frame)
        if sent != len(frame):
            raise TransportError(f"short AF_PACKET send: sent {sent} of {len(frame)} bytes")

    def send_frames(self, frames: tuple[bytes, ...]) -> None:
        if any(len(frame) < MIN_ETHERNET_FRAME_BYTES for frame in frames):
            raise TransportError("AF_PACKET frame must include an Ethernet header")
        sock = self._open_socket()
        batch_sender = getattr(sock, "send_frames", None)
        if callable(batch_sender):
            sent = batch_sender(frames)
            if sent != len(frames):
                raise TransportError(
                    f"short AF_PACKET batch send: sent {sent} of {len(frames)} frames"
                )
            return
        for frame in frames:
            self.send_frame(frame)

    def receive_frame(self) -> bytes:
        try:
            return self._open_socket().recv(self.config.max_frame_bytes)
        except TimeoutError as exc:
            raise TransportError("timed out waiting for AF_PACKET frame") from exc

    def receive_frames(
        self,
        count: int,
        *,
        predicate: FramePredicate | None = None,
        require_count: bool = False,
    ) -> tuple[bytes, ...]:
        if count <= 0:
            raise ValueError("count must be > 0")
        frames: list[bytes] = []
        sock = self._open_socket()
        batch_receiver = getattr(sock, "receive_frames", None)
        if callable(batch_receiver):
            batch = batch_receiver(count, self.config.max_frame_bytes)
            frames = [frame for frame in batch if predicate is None or predicate(frame)][:count]
            if require_count and len(frames) != count:
                raise TransportError(f"captured {len(frames)} AF_PACKET frames, expected {count}")
            return tuple(frames)
        while len(frames) < count:
            try:
                frame = sock.recv(self.config.max_frame_bytes)
            except TimeoutError:
                break
            if predicate is None or predicate(frame):
                frames.append(frame)
        if require_count and len(frames) != count:
            raise TransportError(f"captured {len(frames)} AF_PACKET frames, expected {count}")
        return tuple(frames)

    def _open_socket(self) -> PacketSocket:
        if self._socket is None:
            raise TransportError("AF_PACKET socket is not open")
        return self._socket


__all__ = [
    "ETH_P_ALL",
    "MIN_ETHERNET_FRAME_BYTES",
    "AfpacketFrameSocket",
    "AfpacketSocketConfig",
    "FramePredicate",
    "PacketSocket",
    "PacketSocketFactory",
    "StdlibPacketSocketFactory",
]
