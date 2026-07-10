"""Encrypted mechanism-carrier provider with TLS control and acknowledgements."""

from __future__ import annotations

import asyncio
import hashlib
import json
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from celatim.errors import TransportError
from celatim.session import ChannelSession, InMemoryTransport, MechanismProfile
from celatim.testbed.packet_path import (
    AfpacketCarrierTransport,
    Ipv4PacketPathConfig,
    PacketProtocol,
)

from .direct import (
    _advance_sender,
    _apply_receiver_state,
    _emit,
    _handshake,
    _mark_sender_interrupted,
    _open_tls,
    _raise_remote_error,
    _send_manifest,
    _sender_record,
    _validate_complete,
    _verify_peer,
)
from .errors import TransferErrorCode, TransferFailure, transfer_failure
from .models import (
    ProviderDirectionality,
    ProviderEvidenceLevel,
    ProviderManifest,
    TransferEventKind,
    TransferOffer,
    TransferReceipt,
    TransferStateRecord,
    TransferStatus,
)
from .packet_service import PacketCaptureFilter, PacketServiceSocketFactory
from .providers import ProviderPreflight, ProviderSendRequest, basic_preflight
from .source import StableSourceFile
from .state import TransferStateStore
from .wire import TRANSFER_PROTOCOL_VERSION, read_control, write_control

PACKET_SERVICE_CARRIER_POLICY = "afpacket-carrier"
MAX_CARRIER_CHUNK_SIZE = 64 * 1024


def carrier_provider_name(mechanism_id: str) -> str:
    return f"afpacket.{mechanism_id}"


@dataclass(frozen=True)
class CarrierEndpointConfig:
    mechanism_id: str
    packet_service_socket: Path
    packet_path: Ipv4PacketPathConfig
    priority: int = 50

    @property
    def provider_name(self) -> str:
        return carrier_provider_name(self.mechanism_id)

    def profile(self) -> MechanismProfile:
        return MechanismProfile.from_catalog(self.mechanism_id)

    def socket_factory(self) -> PacketServiceSocketFactory:
        path = self.packet_path
        return PacketServiceSocketFactory(
            self.packet_service_socket,
            provider=PACKET_SERVICE_CARRIER_POLICY,
            timeout_s=(path.timeout_s or 10.0) + 5.0,
            capture_filter=PacketCaptureFilter(
                src_mac=path.src_mac,
                dst_mac=path.dst_mac,
                src_ip=path.src_ip,
                dst_ip=path.dst_ip,
                ip_protocol=path.protocol.ip_proto,
                src_port=path.src_port,
                dst_port=path.dst_port,
            ),
        )

    def to_json(self) -> dict[str, object]:
        path = self.packet_path
        return {
            "schema_version": "celatim.carrier_endpoint.v1",
            "mechanism_id": self.mechanism_id,
            "packet_service_socket": str(self.packet_service_socket),
            "priority": self.priority,
            "packet_path": {
                "sender_interface": path.sender_interface,
                "receiver_interface": path.receiver_interface,
                "src_mac": path.src_mac,
                "dst_mac": path.dst_mac,
                "src_ip": path.src_ip,
                "dst_ip": path.dst_ip,
                "src_port": path.src_port,
                "dst_port": path.dst_port,
                "protocol": path.protocol.value,
                "ttl": path.ttl,
                "tcp_flags": path.tcp_flags,
                "tcp_window": path.tcp_window,
                "ip_id_base": path.ip_id_base,
                "timeout_s": path.timeout_s,
            },
        }

    @classmethod
    def from_json(cls, document: dict[str, object]) -> CarrierEndpointConfig:
        if document.get("schema_version") != "celatim.carrier_endpoint.v1":
            raise ValueError("unsupported carrier endpoint schema")
        packet_path = document.get("packet_path")
        if not isinstance(packet_path, dict):
            raise ValueError("carrier endpoint packet_path must be an object")
        packet_path = cast(dict[str, object], packet_path)
        return cls(
            mechanism_id=_text(document, "mechanism_id"),
            packet_service_socket=Path(_text(document, "packet_service_socket")),
            priority=_integer(document, "priority"),
            packet_path=Ipv4PacketPathConfig(
                sender_interface=_text(packet_path, "sender_interface"),
                receiver_interface=_text(packet_path, "receiver_interface"),
                src_mac=_text(packet_path, "src_mac"),
                dst_mac=_text(packet_path, "dst_mac"),
                src_ip=_text(packet_path, "src_ip"),
                dst_ip=_text(packet_path, "dst_ip"),
                src_port=_integer(packet_path, "src_port"),
                dst_port=_integer(packet_path, "dst_port"),
                protocol=PacketProtocol(_text(packet_path, "protocol")),
                ttl=_integer(packet_path, "ttl"),
                tcp_flags=_integer(packet_path, "tcp_flags"),
                tcp_window=_integer(packet_path, "tcp_window"),
                ip_id_base=_integer(packet_path, "ip_id_base"),
                timeout_s=_optional_float(packet_path, "timeout_s"),
            ),
        )

    @classmethod
    def load(cls, path: Path | str) -> CarrierEndpointConfig:
        document = json.loads(Path(path).read_text())
        if not isinstance(document, dict):
            raise ValueError("carrier endpoint file must contain an object")
        return cls.from_json(document)


class AfpacketCarrierProvider:
    """Send encrypted chunks through a selected adapter's AF_PACKET carrier path."""

    def __init__(self, config: CarrierEndpointConfig) -> None:
        self.config = config
        self.profile = config.profile()

    @property
    def manifest(self) -> ProviderManifest:
        return ProviderManifest(
            name=self.config.provider_name,
            version="1",
            priority=self.config.priority,
            directionality=ProviderDirectionality.DUPLEX,
            feedback=True,
            max_record_size=MAX_CARRIER_CHUNK_SIZE,
            evidence_level=ProviderEvidenceLevel.SYNTHETIC_OUTER_FRAME,
            extras=("transfer",),
            privileges=("packet-service:CAP_NET_RAW",),
            platforms=("linux",),
        )

    def preflight(self, source: Path, offer: TransferOffer) -> ProviderPreflight:
        result = basic_preflight(self.manifest, source, offer)
        if not result.eligible:
            return result
        if not self.config.packet_service_socket.is_socket():
            failure = transfer_failure(
                TransferErrorCode.PRIVILEGE_REQUIRED,
                "configured packet service socket is not available",
            )
            return ProviderPreflight(
                self.manifest.name,
                False,
                result.checks,
                failure,
            )
        try:
            probe = InMemoryTransport()
            receipt = ChannelSession(self.profile, probe).send_message(
                b"\x00",
                session_id="celatim-provider-preflight",
            )
            symbol = probe.receive_symbols(receipt.session_id)[0]
            self.profile.adapter.build_carrier(symbol)
        except ImportError as exc:
            dependency = exc.name or "an optional adapter dependency"
            failure = transfer_failure(
                TransferErrorCode.PROVIDER_UNAVAILABLE,
                f"mechanism adapter dependency is not installed: {dependency}",
            )
            return ProviderPreflight(
                self.manifest.name,
                False,
                result.checks,
                failure,
            )
        except Exception as exc:
            failure = transfer_failure(
                TransferErrorCode.PROVIDER_INCOMPATIBLE,
                f"mechanism adapter preflight failed: {type(exc).__name__}",
            )
            return ProviderPreflight(
                self.manifest.name,
                False,
                result.checks,
                failure,
            )
        return ProviderPreflight(
            self.manifest.name,
            True,
            (*result.checks, "packet_service_available", "mechanism_profile_loaded"),
        )

    async def send(self, request: ProviderSendRequest) -> TransferReceipt:
        if request.chunk_size > MAX_CARRIER_CHUNK_SIZE:
            raise transfer_failure(
                TransferErrorCode.POLICY_BLOCKED,
                f"carrier provider chunk_size must be <= {MAX_CARRIER_CHUNK_SIZE}",
            )
        started_at = datetime.now(UTC)
        source = await asyncio.to_thread(StableSourceFile.open, request.source)
        try:
            return await self._send_source(request, source, started_at)
        finally:
            await asyncio.to_thread(source.close)

    async def _send_source(
        self,
        request: ProviderSendRequest,
        source: StableSourceFile,
        started_at: datetime,
    ) -> TransferReceipt:
        store = TransferStateStore(request.home)
        manifest = await asyncio.to_thread(
            source.create_manifest,
            offer_id=request.offer.offer_id,
            provider=self.manifest.name,
            chunk_size=request.chunk_size,
            transfer_id=request.transfer_id,
        )
        provider_state = _carrier_sender_state(store, manifest.transfer_id)
        record = _sender_record(
            store,
            manifest,
            request.source,
            request.offer,
            provider_state=provider_state,
        )
        manifest = record.manifest
        try:
            if record.status is TransferStatus.CREATED:
                record = await _advance_sender(
                    store,
                    record,
                    TransferStatus.PREFLIGHTING,
                    TransferStatus.NEGOTIATING,
                )
            await _emit(request, record, TransferEventKind.STATE, "connecting to TLS control path")
            reader, writer = await _open_tls(request.offer, request.timeout_s)
            try:
                _verify_peer(writer, request.offer)
                record = await _advance_sender(store, record, TransferStatus.HANDSHAKING)
                await _handshake(reader, writer, request.offer, manifest)
                record = await _advance_sender(store, record, TransferStatus.TRANSFERRING)
                ready = await _send_manifest(
                    reader,
                    writer,
                    manifest,
                    provider_state=provider_state,
                )
                record = await _apply_receiver_state(store, record, ready)
                await self._send_missing_chunks(
                    request,
                    source,
                    reader,
                    writer,
                    store,
                    record,
                )
                record = store.read_state(manifest.transfer_id, "sender")
                await write_control(
                    writer,
                    {
                        "protocol": TRANSFER_PROTOCOL_VERSION,
                        "type": "finish",
                        "transfer_id": manifest.transfer_id,
                        "file_sha256": manifest.file_sha256,
                    },
                )
                complete = await asyncio.wait_for(read_control(reader), request.timeout_s)
                _validate_complete(complete, manifest)
                record = await _advance_sender(
                    store,
                    record,
                    TransferStatus.VERIFYING,
                    TransferStatus.FINALIZING,
                    TransferStatus.COMPLETED,
                )
            finally:
                writer.close()
                with suppress(ConnectionError, OSError):
                    await writer.wait_closed()
        except asyncio.CancelledError as exc:
            await _mark_sender_interrupted(
                store,
                record,
                TransferErrorCode.CANCELLED,
                cancelled=True,
            )
            raise transfer_failure(
                TransferErrorCode.CANCELLED,
                "carrier transfer was cancelled",
                retryable=True,
                resumable=True,
            ) from exc
        except TransportError as exc:
            failure = transfer_failure(
                TransferErrorCode.NETWORK_FAILED,
                "mechanism carrier packet I/O failed",
                retryable=True,
                resumable=True,
            )
            await _mark_sender_interrupted(
                store,
                record,
                failure.code,
                resumable=failure.resumable,
            )
            raise failure from exc
        except ImportError as exc:
            failure = transfer_failure(
                TransferErrorCode.PROVIDER_UNAVAILABLE,
                f"mechanism adapter dependency is not installed: {exc.name or 'unknown'}",
            )
            await _mark_sender_interrupted(store, record, failure.code)
            raise failure from exc
        except TransferFailure as exc:
            await _mark_sender_interrupted(store, record, exc.code, resumable=exc.resumable)
            raise
        except Exception as exc:
            await _mark_sender_interrupted(store, record, TransferErrorCode.INTERNAL_ERROR)
            raise transfer_failure(
                TransferErrorCode.INTERNAL_ERROR,
                "mechanism carrier provider encountered an unexpected internal error",
            ) from exc
        receipt = TransferReceipt(
            transfer_id=manifest.transfer_id,
            role="sender",
            status=TransferStatus.COMPLETED,
            provider=self.manifest.name,
            trust_mode=request.offer.trust_mode,
            authenticated=True,
            verified=True,
            acknowledged=True,
            file_name=manifest.file_name,
            file_size=manifest.file_size,
            file_sha256=manifest.file_sha256,
            started_at=started_at,
            completed_at=datetime.now(UTC),
        )
        await _emit(
            request,
            record,
            TransferEventKind.COMPLETED,
            "receiver verified the encrypted mechanism-carrier transfer",
            bytes_transferred=manifest.file_size,
        )
        return receipt

    async def _send_missing_chunks(
        self,
        request: ProviderSendRequest,
        source: StableSourceFile,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        store: TransferStateStore,
        record: TransferStateRecord,
    ) -> None:
        fernet = _fernet(record.provider_state)
        manifest = record.manifest
        acknowledged = set(record.acknowledged_chunks)
        transferred = sum(
            min(manifest.chunk_size, manifest.file_size - index * manifest.chunk_size)
            for index in acknowledged
        )
        transport = AfpacketCarrierTransport(
            self.profile,
            self.config.packet_path,
            socket_factory=self.config.socket_factory(),
        )
        for index in range(manifest.chunk_count):
            if index in acknowledged:
                continue
            data = await asyncio.to_thread(source.read_chunk, manifest, index)
            digest = hashlib.sha256(data).digest()
            encrypted = fernet.encrypt(data)
            session_id = f"{manifest.transfer_id}:{index}"
            memory = InMemoryTransport()
            send_receipt = ChannelSession(self.profile, memory).send_message(
                encrypted,
                session_id=session_id,
            )
            symbols = memory.receive_symbols(session_id)
            await write_control(
                writer,
                {
                    "protocol": TRANSFER_PROTOCOL_VERSION,
                    "type": "carrier_chunk",
                    "transfer_id": manifest.transfer_id,
                    "chunk_index": index,
                    "chunk_sha256": digest.hex(),
                    "session_id": session_id,
                    "expected_frames": send_receipt.carrier_units,
                },
            )
            carrier_ready = await asyncio.wait_for(read_control(reader), request.timeout_s)
            _raise_remote_error(carrier_ready)
            if (
                carrier_ready.get("type") != "carrier_ready"
                or carrier_ready.get("chunk_index") != index
            ):
                raise transfer_failure(
                    TransferErrorCode.COMPATIBILITY_FAILED,
                    "receiver did not arm the mechanism carrier path",
                )
            await asyncio.to_thread(transport.send_symbols, session_id, symbols)
            response = await asyncio.wait_for(read_control(reader), request.timeout_s)
            _raise_remote_error(response)
            if (
                response.get("type") != "ack"
                or response.get("chunk_index") != index
                or response.get("chunk_sha256") != digest.hex()
            ):
                raise transfer_failure(
                    TransferErrorCode.INTEGRITY_FAILED,
                    "receiver returned an invalid carrier chunk acknowledgement",
                )
            acknowledged.add(index)
            record = replace(
                record,
                acknowledged_chunks=tuple(sorted(acknowledged)),
                updated_at=datetime.now(UTC),
            )
            await asyncio.to_thread(store.write_state, record)
            transferred += len(data)
            await _emit(
                request,
                record,
                TransferEventKind.PROGRESS,
                "receiver durably acknowledged a mechanism-carrier chunk",
                bytes_transferred=transferred,
                chunk_index=index,
            )


def _carrier_sender_state(store: TransferStateStore, transfer_id: str) -> dict[str, str]:
    try:
        existing = store.read_state(transfer_id, "sender")
    except TransferFailure as exc:
        if exc.code is not TransferErrorCode.INPUT_INVALID:
            raise
    else:
        key = existing.provider_state.get("fernet_key")
        if not isinstance(key, str):
            raise transfer_failure(
                TransferErrorCode.CRYPTO_FAILED,
                "carrier resume state does not contain its encryption key",
            )
        _fernet(existing.provider_state)
        return {"fernet_key": key}
    try:
        from cryptography.fernet import Fernet
    except ImportError as exc:
        raise transfer_failure(
            TransferErrorCode.CRYPTO_UNAVAILABLE,
            "carrier encryption requires the celatim transfer extra",
        ) from exc
    except (KeyError, ValueError) as exc:
        raise transfer_failure(
            TransferErrorCode.CRYPTO_FAILED,
            "carrier encryption state is invalid",
        ) from exc
    return {"fernet_key": Fernet.generate_key().decode()}


def _fernet(provider_state: dict[str, object]):
    try:
        from cryptography.fernet import Fernet

        key = provider_state["fernet_key"]
        if not isinstance(key, str):
            raise ValueError("fernet key is not text")
        return Fernet(key.encode())
    except ImportError as exc:
        raise transfer_failure(
            TransferErrorCode.CRYPTO_UNAVAILABLE,
            "carrier encryption requires the celatim transfer extra",
        ) from exc


def _text(document: dict[str, object], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ValueError(f"carrier endpoint {key} must be non-empty text")
    return value


def _integer(document: dict[str, object], key: str) -> int:
    value = document.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"carrier endpoint {key} must be an integer")
    return value


def _optional_float(document: dict[str, object], key: str) -> float | None:
    value = document.get(key)
    if value is None:
        return None
    if not isinstance(value, int | float) or isinstance(value, bool):
        raise ValueError(f"carrier endpoint {key} must be numeric or null")
    return float(value)


__all__ = [
    "MAX_CARRIER_CHUNK_SIZE",
    "PACKET_SERVICE_CARRIER_POLICY",
    "AfpacketCarrierProvider",
    "CarrierEndpointConfig",
    "carrier_provider_name",
]
