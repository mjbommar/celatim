"""Authenticated bounded IPC for privilege-separated packet providers."""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import logging
import os
import platform
import re
import shlex
import socket
import struct
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from time import monotonic, sleep
from typing import Any, Self
from uuid import UUID, uuid4

from celatim.errors import TransportError

from .errors import TransferErrorCode, TransferFailure, transfer_failure

PACKET_SERVICE_SCHEMA_VERSION = "celatim.packet_service.v1"
MAX_PACKET_SERVICE_PAYLOAD = 4 * 1024 * 1024
MAX_PACKET_SERVICE_MESSAGE = 6 * 1024 * 1024
_LENGTH = struct.Struct("!I")
_PEER_CREDENTIALS = struct.Struct("3i")
_BATCH_REQUEST = struct.Struct("!II")
_FILTERED_BATCH_REQUEST = struct.Struct("!BII6s6s4s4sBHH")
_BATCH_FRAME = struct.Struct("!I")
_SAFE_NAME = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_LOGGER = logging.getLogger(__name__)


class PacketOperation(str, Enum):
    SEND = "send"
    SEND_BATCH = "send_batch"
    RECEIVE = "receive"
    PREFLIGHT = "preflight"


@dataclass(frozen=True)
class PacketServiceRequest:
    request_id: str
    operation: PacketOperation
    provider: str
    interface: str
    payload: bytes = b""

    def __post_init__(self) -> None:
        _validate_uuid(self.request_id)
        if not _SAFE_NAME.fullmatch(self.provider):
            raise ValueError("packet provider name is invalid")
        if not _SAFE_NAME.fullmatch(self.interface):
            raise ValueError("packet interface name is invalid")
        if len(self.payload) > MAX_PACKET_SERVICE_PAYLOAD:
            raise ValueError("packet service payload exceeds the size limit")

    @classmethod
    def create(
        cls,
        operation: PacketOperation,
        provider: str,
        interface: str,
        payload: bytes = b"",
    ) -> Self:
        return cls(str(uuid4()), operation, provider, interface, payload)

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": PACKET_SERVICE_SCHEMA_VERSION,
            "message_type": "request",
            "request_id": self.request_id,
            "operation": self.operation.value,
            "provider": self.provider,
            "interface": self.interface,
            "payload": base64.b64encode(self.payload).decode(),
        }

    @classmethod
    def from_json(cls, document: dict[str, Any]) -> Self:
        if (
            document.get("schema_version") != PACKET_SERVICE_SCHEMA_VERSION
            or document.get("message_type") != "request"
        ):
            raise ValueError("unsupported packet service request")
        try:
            payload_raw = document["payload"]
            if not isinstance(payload_raw, str) or len(payload_raw) > 5_592_408:
                raise ValueError("packet service payload encoding is invalid")
            payload = base64.b64decode(payload_raw, validate=True)
            return cls(
                request_id=str(document["request_id"]),
                operation=PacketOperation(str(document["operation"])),
                provider=str(document["provider"]),
                interface=str(document["interface"]),
                payload=payload,
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise ValueError(f"invalid packet service request: {exc}") from exc


@dataclass(frozen=True)
class PacketServiceResponse:
    request_id: str
    ok: bool
    payload: bytes = b""
    error_code: str | None = None
    detail: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": PACKET_SERVICE_SCHEMA_VERSION,
            "message_type": "response",
            "request_id": self.request_id,
            "ok": self.ok,
            "payload": base64.b64encode(self.payload).decode(),
            "error_code": self.error_code,
            "detail": self.detail,
        }

    @classmethod
    def from_json(cls, document: dict[str, Any]) -> Self:
        if (
            document.get("schema_version") != PACKET_SERVICE_SCHEMA_VERSION
            or document.get("message_type") != "response"
        ):
            raise ValueError("unsupported packet service response")
        payload_raw = document.get("payload")
        if not isinstance(payload_raw, str) or len(payload_raw) > 5_592_408:
            raise ValueError("packet service response payload is invalid")
        return cls(
            request_id=str(document.get("request_id")),
            ok=document.get("ok") is True,
            payload=base64.b64decode(payload_raw, validate=True),
            error_code=(
                str(document["error_code"]) if document.get("error_code") is not None else None
            ),
            detail=str(document["detail"]) if document.get("detail") is not None else None,
        )


type PacketHandler = Callable[[PacketServiceRequest], Awaitable[bytes]]


@dataclass(frozen=True)
class PacketCaptureFilter:
    """Exact IPv4 flow authorized for one bounded packet capture request."""

    src_mac: str
    dst_mac: str
    src_ip: str
    dst_ip: str
    ip_protocol: int
    src_port: int
    dst_port: int

    def __post_init__(self) -> None:
        _mac_bytes(self.src_mac)
        _mac_bytes(self.dst_mac)
        ipaddress.IPv4Address(self.src_ip)
        ipaddress.IPv4Address(self.dst_ip)
        if self.ip_protocol not in {6, 17}:
            raise ValueError("packet capture protocol must be TCP or UDP")
        if not 0 < self.src_port <= 0xFFFF or not 0 < self.dst_port <= 0xFFFF:
            raise ValueError("packet capture ports must be in [1, 65535]")

    def matches(self, frame: bytes) -> bool:
        """Return whether an Ethernet frame belongs to the authorized flow."""

        if len(frame) < 14 + 20 + 4:
            return False
        if frame[:6] != _mac_bytes(self.dst_mac):
            return False
        if frame[6:12] != _mac_bytes(self.src_mac) or frame[12:14] != b"\x08\x00":
            return False
        packet = frame[14:]
        ihl = (packet[0] & 0x0F) * 4
        if packet[0] >> 4 != 4 or ihl < 20 or len(packet) < ihl + 4:
            return False
        total_length = int.from_bytes(packet[2:4], "big")
        if total_length < ihl + 4 or len(packet) < total_length:
            return False
        if packet[9] != self.ip_protocol:
            return False
        if packet[12:16] != ipaddress.IPv4Address(self.src_ip).packed:
            return False
        if packet[16:20] != ipaddress.IPv4Address(self.dst_ip).packed:
            return False
        segment = packet[ihl:total_length]
        return (
            int.from_bytes(segment[:2], "big") == self.src_port
            and int.from_bytes(segment[2:4], "big") == self.dst_port
        )

    def _wire_values(self) -> tuple[bytes, bytes, bytes, bytes, int, int, int]:
        return (
            _mac_bytes(self.src_mac),
            _mac_bytes(self.dst_mac),
            ipaddress.IPv4Address(self.src_ip).packed,
            ipaddress.IPv4Address(self.dst_ip).packed,
            self.ip_protocol,
            self.src_port,
            self.dst_port,
        )

    @classmethod
    def _from_wire(
        cls,
        src_mac: bytes,
        dst_mac: bytes,
        src_ip: bytes,
        dst_ip: bytes,
        ip_protocol: int,
        src_port: int,
        dst_port: int,
    ) -> Self:
        return cls(
            src_mac=src_mac.hex(":"),
            dst_mac=dst_mac.hex(":"),
            src_ip=str(ipaddress.IPv4Address(src_ip)),
            dst_ip=str(ipaddress.IPv4Address(dst_ip)),
            ip_protocol=ip_protocol,
            src_port=src_port,
            dst_port=dst_port,
        )


class PacketService:
    """One-request-per-connection Unix service with peer and allowlist checks."""

    def __init__(
        self,
        socket_path: Path | str,
        handler: PacketHandler,
        *,
        allowed_uids: set[int] | None = None,
        allowed_providers: set[str] | None = None,
        allowed_interfaces: set[str] | None = None,
        max_concurrent: int = 16,
        timeout_s: float = 10.0,
    ) -> None:
        if max_concurrent <= 0 or timeout_s <= 0:
            raise ValueError("packet service limits must be > 0")
        self.socket_path = Path(socket_path)
        self.handler = handler
        self.allowed_uids = allowed_uids if allowed_uids is not None else {os.getuid()}
        self.allowed_providers = allowed_providers or set()
        self.allowed_interfaces = allowed_interfaces or set()
        self.timeout_s = timeout_s
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        if not hasattr(socket, "SO_PEERCRED"):
            raise transfer_failure(
                TransferErrorCode.PROVIDER_UNAVAILABLE,
                "packet service peer credentials are not supported on this platform",
            )
        self.socket_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.socket_path.exists() or self.socket_path.is_symlink():
            if not self.socket_path.is_socket():
                raise transfer_failure(
                    TransferErrorCode.STORAGE_FAILED,
                    "packet service socket path is occupied by a non-socket",
                )
            self.socket_path.unlink()
        self._server = await asyncio.start_unix_server(
            self._handle_connection,
            path=self.socket_path,
        )
        self.socket_path.chmod(0o660)

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        self.socket_path.unlink(missing_ok=True)

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        await self.close()

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        async with self._semaphore:
            request_id = str(uuid4())
            try:
                peer_uid = _peer_uid(writer)
                if peer_uid not in self.allowed_uids:
                    raise transfer_failure(
                        TransferErrorCode.PRIVILEGE_REQUIRED,
                        "packet service rejected the local peer identity",
                    )
                async with asyncio.timeout(self.timeout_s):
                    document = await _read_document(reader)
                    request = PacketServiceRequest.from_json(document)
                    request_id = request.request_id
                    self._check_policy(request)
                    payload = await self.handler(request)
                response = PacketServiceResponse(request_id, True, payload)
            except Exception as exc:
                if not isinstance(exc, TransferFailure):
                    _LOGGER.exception(
                        "packet service request failed with %s",
                        type(exc).__name__,
                    )
                code = getattr(exc, "code", TransferErrorCode.INTERNAL_ERROR)
                detail = getattr(exc, "detail", "packet service request failed")
                response = PacketServiceResponse(
                    request_id,
                    False,
                    error_code=code.value,
                    detail=str(detail),
                )
            with suppress(ConnectionError, OSError):
                await _write_document(writer, response.to_json())
            writer.close()
            with suppress(ConnectionError, OSError):
                await writer.wait_closed()

    def _check_policy(self, request: PacketServiceRequest) -> None:
        if request.provider not in self.allowed_providers:
            raise transfer_failure(
                TransferErrorCode.POLICY_BLOCKED,
                "packet provider is not allowed by the service",
            )
        if request.interface not in self.allowed_interfaces:
            raise transfer_failure(
                TransferErrorCode.POLICY_BLOCKED,
                "packet interface is not allowed by the service",
            )


class PacketServiceClient:
    def __init__(self, socket_path: Path | str, *, timeout_s: float = 10.0) -> None:
        self.socket_path = Path(socket_path)
        self.timeout_s = timeout_s

    async def request(self, request: PacketServiceRequest) -> PacketServiceResponse:
        try:
            async with asyncio.timeout(self.timeout_s):
                reader, writer = await asyncio.open_unix_connection(self.socket_path)
                try:
                    await _write_document(writer, request.to_json())
                    response = PacketServiceResponse.from_json(await _read_document(reader))
                finally:
                    writer.close()
                    await writer.wait_closed()
        except TimeoutError as exc:
            raise transfer_failure(
                TransferErrorCode.TIMEOUT,
                "packet service request timed out",
                retryable=True,
            ) from exc
        except OSError as exc:
            raise transfer_failure(
                TransferErrorCode.PRIVILEGE_REQUIRED,
                f"could not connect to the packet service: {exc}",
            ) from exc
        if response.request_id != request.request_id:
            raise transfer_failure(
                TransferErrorCode.COMPATIBILITY_FAILED,
                "packet service response id does not match the request",
            )
        return response


class BlockingPacketServiceClient:
    """Synchronous client for existing transport protocols and worker threads."""

    def __init__(self, socket_path: Path | str, *, timeout_s: float = 10.0) -> None:
        self.socket_path = Path(socket_path)
        self.timeout_s = timeout_s

    def request(self, request: PacketServiceRequest) -> PacketServiceResponse:
        encoded = json.dumps(request.to_json(), sort_keys=True, separators=(",", ":")).encode()
        if len(encoded) > MAX_PACKET_SERVICE_MESSAGE:
            raise TransportError("packet service request exceeds the size limit")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(self.timeout_s)
                client.connect(str(self.socket_path))
                client.sendall(_LENGTH.pack(len(encoded)) + encoded)
                length = _LENGTH.unpack(_recv_exact(client, _LENGTH.size))[0]
                if length > MAX_PACKET_SERVICE_MESSAGE:
                    raise TransportError("packet service response exceeds the size limit")
                document = json.loads(_recv_exact(client, length))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise TransportError(f"packet service request failed: {exc}") from exc
        if not isinstance(document, dict):
            raise TransportError("packet service response must be an object")
        try:
            response = PacketServiceResponse.from_json(document)
        except ValueError as exc:
            raise TransportError(f"packet service response is invalid: {exc}") from exc
        if response.request_id != request.request_id:
            raise TransportError("packet service response id does not match the request")
        if not response.ok:
            raise TransportError(
                f"packet service rejected request [{response.error_code}]: {response.detail}"
            )
        return response


class PacketServicePacketSocket:
    """PacketSocket-compatible proxy used by existing AF_PACKET transports."""

    def __init__(
        self,
        client: BlockingPacketServiceClient,
        provider: str,
        protocol: int,
        capture_filter: PacketCaptureFilter | None = None,
    ) -> None:
        self.client = client
        self.provider = provider
        self.protocol = protocol
        self.capture_filter = capture_filter
        self.interface: str | None = None
        self.timeout_s: float | None = None
        self.closed = False

    def bind(self, address: tuple[str, int]) -> None:
        if self.closed:
            raise TransportError("packet service socket is closed")
        self.interface = address[0]

    def settimeout(self, value: float | None) -> None:
        self.timeout_s = value

    def send(self, data: bytes) -> int:
        interface = self._interface()
        response = self.client.request(
            PacketServiceRequest.create(PacketOperation.SEND, self.provider, interface, data)
        )
        if len(response.payload) == 8:
            return int.from_bytes(response.payload, "big")
        return len(data)

    def send_frames(self, frames: tuple[bytes, ...]) -> int:
        if not frames:
            return 0
        payload = _encode_frame_batch(list(frames))
        if len(payload) > MAX_PACKET_SERVICE_PAYLOAD:
            raise TransportError("packet service frame batch exceeds the size limit")
        response = self.client.request(
            PacketServiceRequest.create(
                PacketOperation.SEND_BATCH,
                self.provider,
                self._interface(),
                payload,
            )
        )
        if len(response.payload) != 8:
            raise TransportError("packet service returned an invalid batch send count")
        return int.from_bytes(response.payload, "big")

    def recv(self, bufsize: int) -> bytes:
        interface = self._interface()
        response = self.client.request(
            PacketServiceRequest.create(PacketOperation.RECEIVE, self.provider, interface)
        )
        return response.payload[:bufsize]

    def receive_frames(self, count: int, max_frame_bytes: int) -> tuple[bytes, ...]:
        interface = self._interface()
        if self.capture_filter is None:
            request_payload = _BATCH_REQUEST.pack(count, max_frame_bytes)
        else:
            request_payload = _FILTERED_BATCH_REQUEST.pack(
                1,
                count,
                max_frame_bytes,
                *self.capture_filter._wire_values(),
            )
        response = self.client.request(
            PacketServiceRequest.create(
                PacketOperation.RECEIVE,
                self.provider,
                interface,
                request_payload,
            )
        )
        return _decode_frame_batch(response.payload, max_frame_bytes)

    def close(self) -> None:
        self.closed = True

    def _interface(self) -> str:
        if self.closed:
            raise TransportError("packet service socket is closed")
        if self.interface is None:
            raise TransportError("packet service socket is not bound")
        return self.interface


class PacketServiceSocketFactory:
    """PacketSocketFactory that delegates raw I/O to the local packet service."""

    def __init__(
        self,
        socket_path: Path | str,
        *,
        provider: str = "afpacket-carrier",
        timeout_s: float = 10.0,
        capture_filter: PacketCaptureFilter | None = None,
    ) -> None:
        self.client = BlockingPacketServiceClient(socket_path, timeout_s=timeout_s)
        self.provider = provider
        self.capture_filter = capture_filter

    def open(self, protocol: int) -> PacketServicePacketSocket:
        return PacketServicePacketSocket(
            self.client,
            self.provider,
            protocol,
            self.capture_filter,
        )


async def raw_packet_handler(
    request: PacketServiceRequest,
    *,
    timeout_s: float = 1.0,
    batch_frame_rate_hz: float = 2_000.0,
) -> bytes:
    """Execute one allowlisted AF_PACKET action without file or key access."""

    if batch_frame_rate_hz <= 0:
        raise transfer_failure(
            TransferErrorCode.INPUT_INVALID,
            "packet-service batch frame rate must be > 0",
        )
    return await asyncio.to_thread(
        _raw_packet_action,
        request,
        timeout_s,
        1.0 / batch_frame_rate_hz,
    )


def packet_service_preflight(
    socket_path: Path | str,
    *,
    providers: set[str],
    interfaces: set[str],
    allowed_uids: set[int],
) -> dict[str, Any]:
    path = Path(socket_path)
    return {
        "schema_version": "celatim.packet_service_preflight.v1",
        "platform": platform.system().lower(),
        "so_peercred_available": hasattr(socket, "SO_PEERCRED"),
        "af_packet_available": hasattr(socket, "AF_PACKET"),
        "socket_path": str(path),
        "socket_parent_exists": path.parent.is_dir(),
        "socket_parent_writable": os.access(path.parent, os.W_OK)
        if path.parent.exists()
        else False,
        "allowed_uids": sorted(allowed_uids),
        "allowed_providers": sorted(providers),
        "allowed_interfaces": sorted(interfaces),
        "ready": (
            hasattr(socket, "SO_PEERCRED")
            and hasattr(socket, "AF_PACKET")
            and bool(providers)
            and bool(interfaces)
            and bool(allowed_uids)
        ),
    }


def packet_service_systemd_unit(
    *,
    executable: Path | str,
    user: str,
    socket_path: Path | str,
    providers: set[str],
    interfaces: set[str],
    allowed_uids: set[int],
) -> str:
    """Generate a capability-bounded systemd service without installing it."""

    if not user or any(char.isspace() for char in user):
        raise ValueError("systemd service user is invalid")
    argv = [
        str(executable),
        "transfer",
        "packet-service",
        "serve",
        "--socket",
        str(socket_path),
    ]
    for provider in sorted(providers):
        argv.extend(("--allow-provider", provider))
    for interface in sorted(interfaces):
        argv.extend(("--allow-interface", interface))
    for uid in sorted(allowed_uids):
        argv.extend(("--allow-uid", str(uid)))
    writable_parent = Path(socket_path).parent
    return "\n".join(
        (
            "[Unit]",
            "Description=Celatim privilege-separated packet service",
            "After=network.target",
            "",
            "[Service]",
            "Type=simple",
            f"User={user}",
            f"ExecStart={shlex.join(argv)}",
            "AmbientCapabilities=CAP_NET_RAW",
            "CapabilityBoundingSet=CAP_NET_RAW",
            "NoNewPrivileges=yes",
            "PrivateTmp=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            f"ReadWritePaths={writable_parent}",
            "RestrictAddressFamilies=AF_UNIX AF_PACKET",
            "LockPersonality=yes",
            "MemoryDenyWriteExecute=yes",
            "RestrictSUIDSGID=yes",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        )
    )


async def _write_document(writer: asyncio.StreamWriter, document: dict[str, Any]) -> None:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > MAX_PACKET_SERVICE_MESSAGE:
        raise ValueError("packet service message exceeds the size limit")
    writer.write(_LENGTH.pack(len(encoded)))
    writer.write(encoded)
    await writer.drain()


async def _read_document(reader: asyncio.StreamReader) -> dict[str, Any]:
    header = await reader.readexactly(_LENGTH.size)
    (length,) = _LENGTH.unpack(header)
    if length > MAX_PACKET_SERVICE_MESSAGE:
        raise ValueError("packet service message exceeds the size limit")
    document = json.loads(await reader.readexactly(length))
    if not isinstance(document, dict):
        raise ValueError("packet service message must be an object")
    return document


def _peer_uid(writer: asyncio.StreamWriter) -> int:
    transport_socket = writer.get_extra_info("socket")
    if transport_socket is None:
        raise ValueError("packet service connection has no socket")
    credentials = transport_socket.getsockopt(
        socket.SOL_SOCKET,
        socket.SO_PEERCRED,
        _PEER_CREDENTIALS.size,
    )
    _, uid, _ = _PEER_CREDENTIALS.unpack(credentials)
    return uid


def _raw_packet_action(
    request: PacketServiceRequest,
    timeout_s: float,
    batch_frame_interval_s: float,
) -> bytes:
    if not hasattr(socket, "AF_PACKET"):
        raise transfer_failure(
            TransferErrorCode.PROVIDER_UNAVAILABLE,
            "AF_PACKET is not supported on this platform",
        )
    try:
        packet_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        try:
            packet_socket.bind((request.interface, 0))
            packet_socket.settimeout(timeout_s)
            if request.operation is PacketOperation.PREFLIGHT:
                return b"ready"
            if request.operation is PacketOperation.SEND:
                if len(request.payload) < 14:
                    raise transfer_failure(
                        TransferErrorCode.INPUT_INVALID,
                        "raw Ethernet frame must contain at least 14 bytes",
                    )
                sent = packet_socket.send(request.payload)
                return sent.to_bytes(8, "big")
            if request.operation is PacketOperation.SEND_BATCH:
                frames = _decode_frame_batch(request.payload, 65535)
                if not frames:
                    raise transfer_failure(
                        TransferErrorCode.INPUT_INVALID,
                        "raw Ethernet frame batch must not be empty",
                    )
                started = monotonic()
                for index, frame in enumerate(frames):
                    if index:
                        delay = started + index * batch_frame_interval_s - monotonic()
                        if delay > 0:
                            sleep(delay)
                    sent = packet_socket.send(frame)
                    if sent != len(frame):
                        raise transfer_failure(
                            TransferErrorCode.NETWORK_FAILED,
                            "raw Ethernet frame batch had a short send",
                            retryable=True,
                        )
                return len(frames).to_bytes(8, "big")
            batch_request = _decode_batch_request(request.payload)
            if batch_request is not None:
                count, max_frame_bytes, capture_filter = batch_request
                if count <= 0 or count > 1_000_000:
                    raise transfer_failure(
                        TransferErrorCode.INPUT_INVALID,
                        "packet batch count is outside the service limit",
                    )
                if max_frame_bytes < 14 or max_frame_bytes > 65535:
                    raise transfer_failure(
                        TransferErrorCode.INPUT_INVALID,
                        "packet batch frame size is outside the service limit",
                    )
                frames: list[bytes] = []
                encoded_bytes = 0
                deadline = monotonic() + timeout_s
                while len(frames) < count:
                    remaining = deadline - monotonic()
                    if remaining <= 0:
                        break
                    packet_socket.settimeout(remaining)
                    try:
                        frame = packet_socket.recv(max_frame_bytes)
                    except TimeoutError:
                        break
                    if capture_filter is not None and not capture_filter.matches(frame):
                        continue
                    next_size = _BATCH_FRAME.size + len(frame)
                    if encoded_bytes + next_size > MAX_PACKET_SERVICE_PAYLOAD:
                        break
                    frames.append(frame)
                    encoded_bytes += next_size
                return _encode_frame_batch(frames)
            if request.payload:
                raise transfer_failure(
                    TransferErrorCode.INPUT_INVALID,
                    "packet receive request payload is invalid",
                )
            return packet_socket.recv(MAX_PACKET_SERVICE_PAYLOAD)
        finally:
            packet_socket.close()
    except PermissionError as exc:
        raise transfer_failure(
            TransferErrorCode.PRIVILEGE_REQUIRED,
            "packet service lacks CAP_NET_RAW",
        ) from exc
    except OSError as exc:
        raise transfer_failure(
            TransferErrorCode.NETWORK_FAILED,
            f"AF_PACKET operation failed: {exc}",
            retryable=True,
        ) from exc


def _validate_uuid(value: str) -> None:
    if str(UUID(value)) != value:
        raise ValueError("request_id must use canonical UUID text")


def _recv_exact(client: socket.socket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        chunk = client.recv(length - len(output))
        if not chunk:
            raise OSError("packet service connection closed early")
        output.extend(chunk)
    return bytes(output)


def _encode_frame_batch(frames: list[bytes]) -> bytes:
    return b"".join(_BATCH_FRAME.pack(len(frame)) + frame for frame in frames)


def _decode_batch_request(
    payload: bytes,
) -> tuple[int, int, PacketCaptureFilter | None] | None:
    if len(payload) == _BATCH_REQUEST.size:
        count, max_frame_bytes = _BATCH_REQUEST.unpack(payload)
        return count, max_frame_bytes, None
    if len(payload) != _FILTERED_BATCH_REQUEST.size:
        return None
    version, count, max_frame_bytes, *filter_values = _FILTERED_BATCH_REQUEST.unpack(payload)
    if version != 1:
        return None
    return count, max_frame_bytes, PacketCaptureFilter._from_wire(*filter_values)


def _mac_bytes(value: str) -> bytes:
    try:
        parsed = bytes.fromhex(value.replace(":", ""))
    except ValueError as exc:
        raise ValueError("invalid packet capture MAC address") from exc
    if len(parsed) != 6:
        raise ValueError("invalid packet capture MAC address")
    return parsed


def _decode_frame_batch(payload: bytes, max_frame_bytes: int) -> tuple[bytes, ...]:
    frames: list[bytes] = []
    offset = 0
    while offset < len(payload):
        if len(payload) - offset < _BATCH_FRAME.size:
            raise TransportError("packet service batch has a truncated frame header")
        (length,) = _BATCH_FRAME.unpack(payload[offset : offset + _BATCH_FRAME.size])
        offset += _BATCH_FRAME.size
        if length < 14 or length > max_frame_bytes or len(payload) - offset < length:
            raise TransportError("packet service batch has an invalid frame length")
        frames.append(payload[offset : offset + length])
        offset += length
    return tuple(frames)


__all__ = [
    "MAX_PACKET_SERVICE_MESSAGE",
    "MAX_PACKET_SERVICE_PAYLOAD",
    "PACKET_SERVICE_SCHEMA_VERSION",
    "BlockingPacketServiceClient",
    "PacketCaptureFilter",
    "PacketOperation",
    "PacketService",
    "PacketServiceClient",
    "PacketServicePacketSocket",
    "PacketServiceRequest",
    "PacketServiceResponse",
    "PacketServiceSocketFactory",
    "packet_service_preflight",
    "packet_service_systemd_unit",
    "raw_packet_handler",
]
