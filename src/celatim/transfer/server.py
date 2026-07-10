"""Persistent TLS transfer receiver and offer lifecycle."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from collections.abc import AsyncIterator
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

from celatim.errors import TransportError
from celatim.session import ChannelSession
from celatim.testbed.packet_path import AfpacketCarrierTransport

from .carrier import CarrierEndpointConfig, _fernet
from .direct import DIRECT_TLS_PROVIDER
from .errors import TransferErrorCode, TransferFailure, transfer_failure
from .models import (
    TransferManifest,
    TransferOffer,
    TransferReceipt,
    TransferStateRecord,
    TransferStatus,
    TransferTrustMode,
)
from .security import ensure_tls_identity, server_ssl_context
from .state import TransferStateStore, transition_state
from .storage import ReceiverFile
from .wire import TRANSFER_PROTOCOL_VERSION, read_chunk, read_control, write_control

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class TransferServerAddress:
    host: str
    port: int


class TransferServer:
    """A bounded persistent receiver for offer-bound TLS file transfers."""

    def __init__(
        self,
        output_dir: Path | str,
        *,
        home: Path | str | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
        advertise_host: str | None = None,
        max_file_size: int = 1024 * 1024 * 1024,
        max_concurrent: int = 4,
        timeout_s: float = 60.0,
        collision: str = "fail",
        carrier_receivers: tuple[CarrierEndpointConfig, ...] = (),
    ) -> None:
        if not 1 <= max_concurrent <= 128:
            raise ValueError("max_concurrent must be between 1 and 128")
        if timeout_s <= 0:
            raise ValueError("timeout_s must be > 0")
        self.output_dir = Path(output_dir)
        self.store = TransferStateStore(home)
        self.host = host
        self.requested_port = port
        self.advertise_host = advertise_host
        self.max_file_size = max_file_size
        self.timeout_s = timeout_s
        self.collision = collision
        self.carrier_receivers = {config.provider_name: config for config in carrier_receivers}
        if len(self.carrier_receivers) != len(carrier_receivers):
            raise ValueError("carrier receiver provider names must be unique")
        self._server: asyncio.Server | None = None
        self._offers: dict[str, TransferOffer] = {}
        self._results: asyncio.Queue[TransferReceipt] = asyncio.Queue()
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._offer_lock = asyncio.Lock()
        self._active_receivers: dict[int, ReceiverFile] = {}

    @property
    def address(self) -> TransferServerAddress:
        if self._server is None or not self._server.sockets:
            raise RuntimeError("transfer server is not running")
        socket_name = self._server.sockets[0].getsockname()
        return TransferServerAddress(str(socket_name[0]), int(socket_name[1]))

    async def start(self) -> None:
        if self._server is not None:
            return
        self.store.initialize()
        self.output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        identity = await asyncio.to_thread(ensure_tls_identity, self.store.identities_dir)
        self._load_offers()
        self._server = await asyncio.start_server(
            self._handle_connection,
            self.host,
            self.requested_port,
            ssl=server_ssl_context(identity),
        )

    async def close(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        await self.close()

    async def create_offer(
        self,
        *,
        expires_in_s: int = 900,
        receiver_label: str | None = None,
    ) -> TransferOffer:
        if self._server is None:
            raise RuntimeError("start the transfer server before creating an offer")
        identity = await asyncio.to_thread(ensure_tls_identity, self.store.identities_dir)
        offer = TransferOffer.create(
            host=self.advertise_host or self.address.host,
            port=self.address.port,
            tls_cert_sha256=identity.certificate_sha256,
            providers=(DIRECT_TLS_PROVIDER, *sorted(self.carrier_receivers)),
            max_file_size=self.max_file_size,
            expires_in_s=expires_in_s,
            receiver_label=receiver_label,
        )
        self._offers[offer.offer_id] = offer
        await asyncio.to_thread(self.store.write_offer, offer.to_json())
        return offer

    async def receive(self, *, timeout_s: float | None = None) -> TransferReceipt:
        if timeout_s is None:
            return await self._results.get()
        try:
            return await asyncio.wait_for(self._results.get(), timeout_s)
        except TimeoutError as exc:
            raise transfer_failure(
                TransferErrorCode.TIMEOUT,
                "timed out waiting for a completed transfer",
                retryable=True,
            ) from exc

    async def completed_transfers(self) -> AsyncIterator[TransferReceipt]:
        while True:
            yield await self._results.get()

    def _load_offers(self) -> None:
        self.store.initialize()
        for path in sorted(self.store.offers_dir.glob("*.json")):
            try:
                raw = json.loads(path.read_text())
                if isinstance(raw, dict):
                    offer = TransferOffer.parse(raw)
                    self._offers[offer.offer_id] = offer
            except OSError, ValueError, TransferFailure, json.JSONDecodeError:
                continue

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        async with self._semaphore:
            try:
                async with asyncio.timeout(self.timeout_s):
                    await self._process_connection(reader, writer)
            except TransferFailure as exc:
                await self._mark_active_failure(writer, exc)
                await _send_error(writer, exc)
            except TimeoutError:
                failure = transfer_failure(
                    TransferErrorCode.TIMEOUT,
                    "receiver timed out waiting for transfer data",
                    retryable=True,
                    resumable=True,
                )
                await self._mark_active_failure(writer, failure)
                await _send_error(writer, failure)
            except Exception as exc:
                _LOGGER.exception(
                    "receiver transfer failed with %s",
                    type(exc).__name__,
                )
                failure = transfer_failure(
                    TransferErrorCode.INTERNAL_ERROR,
                    "receiver encountered an internal transfer error",
                )
                await self._mark_active_failure(writer, failure)
                await _send_error(writer, failure)
            finally:
                self._active_receivers.pop(id(writer), None)
                writer.close()
                with suppress(ConnectionError, OSError):
                    await writer.wait_closed()

    async def _process_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        hello = await read_control(reader)
        offer, transfer_id = self._validate_hello(hello)
        existing = _optional_receiver_state(self.store, transfer_id)
        if existing is None:
            offer.require_active()
        elif existing.manifest.offer_id != offer.offer_id:
            raise transfer_failure(
                TransferErrorCode.OFFER_REPLAYED,
                "transfer id is already bound to another offer",
            )
        await write_control(
            writer,
            {
                "protocol": TRANSFER_PROTOCOL_VERSION,
                "type": "hello_ok",
                "transfer_id": transfer_id,
                "trust_mode": offer.trust_mode.value,
            },
        )
        manifest_message = await read_control(reader)
        manifest = _manifest_from_message(manifest_message)
        provider_state = _provider_state_from_message(manifest_message)
        if manifest.transfer_id != transfer_id or manifest.offer_id != offer.offer_id:
            raise transfer_failure(
                TransferErrorCode.INTEGRITY_FAILED,
                "manifest does not match the authenticated transfer handshake",
            )
        if (
            manifest.provider != DIRECT_TLS_PROVIDER
            and manifest.provider not in self.carrier_receivers
        ):
            raise transfer_failure(
                TransferErrorCode.PROVIDER_INCOMPATIBLE,
                "manifest provider does not match the active listener",
            )
        if manifest.provider == DIRECT_TLS_PROVIDER and provider_state:
            raise transfer_failure(
                TransferErrorCode.COMPATIBILITY_FAILED,
                "direct TLS provider sent unexpected provider state",
            )
        if manifest.provider in self.carrier_receivers:
            _fernet(provider_state)
        if manifest.file_size > offer.max_file_size:
            raise transfer_failure(
                TransferErrorCode.POLICY_BLOCKED,
                "file exceeds the receiver offer limit",
            )
        async with self._offer_lock:
            accepted = _accepted_transfer_id(self.store, offer.offer_id)
            if accepted is not None and accepted != transfer_id:
                raise transfer_failure(
                    TransferErrorCode.OFFER_REPLAYED,
                    "offer was already accepted for another transfer",
                )
            receiver_file = await asyncio.to_thread(
                self._receiver_file,
                existing,
                manifest,
                offer,
                provider_state,
            )
            self._active_receivers[id(writer)] = receiver_file
        await write_control(
            writer,
            {
                "protocol": TRANSFER_PROTOCOL_VERSION,
                "type": "ready",
                "transfer_id": transfer_id,
                "acknowledged_chunks": list(receiver_file.record.acknowledged_chunks),
            },
        )
        if manifest.provider == DIRECT_TLS_PROVIDER:
            await _receive_direct_chunks(reader, writer, receiver_file)
        else:
            await self._receive_carrier_chunks(
                reader,
                writer,
                receiver_file,
                self.carrier_receivers[manifest.provider],
            )
        finish = await read_control(reader)
        if (
            finish.get("protocol") != TRANSFER_PROTOCOL_VERSION
            or finish.get("type") != "finish"
            or finish.get("transfer_id") != transfer_id
            or finish.get("file_sha256") != manifest.file_sha256
        ):
            raise transfer_failure(
                TransferErrorCode.COMPATIBILITY_FAILED,
                "sender returned an invalid finish record",
            )
        destination = await asyncio.to_thread(receiver_file.finalize)
        receipt = TransferReceipt(
            transfer_id=transfer_id,
            role="receiver",
            status=TransferStatus.COMPLETED,
            provider=manifest.provider,
            trust_mode=TransferTrustMode.OFFER_BOUND,
            authenticated=True,
            verified=True,
            acknowledged=True,
            file_name=manifest.file_name,
            file_size=manifest.file_size,
            file_sha256=manifest.file_sha256,
            started_at=receiver_file.record.created_at,
            completed_at=datetime.now(UTC),
            path=str(destination),
        )
        await write_control(
            writer,
            {
                "protocol": TRANSFER_PROTOCOL_VERSION,
                "type": "complete",
                "transfer_id": transfer_id,
                "file_sha256": manifest.file_sha256,
                "file_size": manifest.file_size,
                "verified": True,
                "acknowledged": True,
            },
        )
        await self._results.put(receipt)

    async def _mark_active_failure(
        self,
        writer: asyncio.StreamWriter,
        failure: TransferFailure,
    ) -> None:
        receiver_file = self._active_receivers.get(id(writer))
        if receiver_file is not None:
            await asyncio.to_thread(
                _mark_receiver_interrupted,
                receiver_file,
                failure.code,
                failure.resumable,
            )

    def _validate_hello(self, hello: dict[str, Any]) -> tuple[TransferOffer, str]:
        if hello.get("protocol") != TRANSFER_PROTOCOL_VERSION or hello.get("type") != "hello":
            raise transfer_failure(
                TransferErrorCode.COMPATIBILITY_FAILED,
                "sender used an unsupported transfer protocol",
            )
        offer_id = hello.get("offer_id")
        transfer_id = hello.get("transfer_id")
        token = hello.get("access_token")
        if not all(isinstance(value, str) for value in (offer_id, transfer_id, token)):
            raise transfer_failure(
                TransferErrorCode.OFFER_INVALID,
                "transfer handshake is missing offer credentials",
            )
        try:
            offer = self._offers[str(offer_id)]
        except KeyError as exc:
            raise transfer_failure(
                TransferErrorCode.OFFER_INVALID,
                "receiver does not recognize the transfer offer",
            ) from exc
        if not hmac.compare_digest(offer.access_token, str(token)):
            raise transfer_failure(
                TransferErrorCode.TRUST_FAILED,
                "transfer offer access token is invalid",
            )
        return offer, str(transfer_id)

    def _receiver_file(
        self,
        existing: TransferStateRecord | None,
        manifest: TransferManifest,
        offer: TransferOffer,
        provider_state: dict[str, Any],
    ) -> ReceiverFile:
        if existing is None:
            return ReceiverFile.create(
                self.store,
                manifest,
                offer.to_json(),
                self.output_dir,
                collision=self.collision,
                provider_state=provider_state,
            )
        if (
            existing.manifest != manifest
            or existing.offer != offer.to_json()
            or existing.provider_state != provider_state
        ):
            raise transfer_failure(
                TransferErrorCode.INTEGRITY_FAILED,
                "resume manifest or offer differs from durable receiver state",
            )
        receiver_file = ReceiverFile(self.store, existing)
        if receiver_file.record.status is TransferStatus.TRANSFERRING:
            receiver_file.record = transition_state(receiver_file.record, TransferStatus.PAUSED)
        if receiver_file.record.status in {
            TransferStatus.PAUSED,
            TransferStatus.CANCELLED,
            TransferStatus.FAILED,
        }:
            receiver_file.record = transition_state(
                receiver_file.record,
                TransferStatus.HANDSHAKING,
            )
            receiver_file.record = transition_state(
                receiver_file.record,
                TransferStatus.TRANSFERRING,
            )
            self.store.write_state(receiver_file.record)
        return receiver_file

    async def _receive_carrier_chunks(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        receiver_file: ReceiverFile,
        config: CarrierEndpointConfig,
    ) -> None:
        manifest = receiver_file.record.manifest
        fernet = _fernet(receiver_file.record.provider_state)
        profile = config.profile()
        missing_count = manifest.chunk_count - len(receiver_file.record.acknowledged_chunks)
        for _ in range(missing_count):
            chunk_message = await read_control(reader)
            index, digest, session_id, expected_frames = _carrier_chunk_fields(
                chunk_message,
                manifest,
            )
            transport = AfpacketCarrierTransport(
                profile,
                replace(config.packet_path, expected_frames=expected_frames),
                socket_factory=config.socket_factory(),
            )
            receive_task = asyncio.create_task(
                asyncio.to_thread(
                    ChannelSession(profile, transport).receive_message,
                    session_id,
                )
            )
            await asyncio.sleep(0.02)
            await write_control(
                writer,
                {
                    "protocol": TRANSFER_PROTOCOL_VERSION,
                    "type": "carrier_ready",
                    "transfer_id": manifest.transfer_id,
                    "chunk_index": index,
                },
            )
            try:
                result = await receive_task
            except TransportError as exc:
                raise transfer_failure(
                    TransferErrorCode.NETWORK_FAILED,
                    "mechanism carrier packet receive failed",
                    retryable=True,
                    resumable=True,
                ) from exc
            try:
                data = fernet.decrypt(result.payload)
            except Exception as exc:
                raise transfer_failure(
                    TransferErrorCode.CRYPTO_FAILED,
                    "mechanism-carrier chunk authentication failed",
                ) from exc
            await asyncio.to_thread(receiver_file.write_chunk, index, data, digest)
            await write_control(
                writer,
                {
                    "protocol": TRANSFER_PROTOCOL_VERSION,
                    "type": "ack",
                    "transfer_id": manifest.transfer_id,
                    "chunk_index": index,
                    "chunk_sha256": hashlib.sha256(data).hexdigest(),
                    "durable": True,
                    "carrier_units": result.evidence.carrier_units,
                },
            )


async def _receive_direct_chunks(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    receiver_file: ReceiverFile,
) -> None:
    manifest = receiver_file.record.manifest
    missing_count = manifest.chunk_count - len(receiver_file.record.acknowledged_chunks)
    for _ in range(missing_count):
        index, digest, data = await read_chunk(reader)
        await asyncio.to_thread(receiver_file.write_chunk, index, data, digest)
        await write_control(
            writer,
            {
                "protocol": TRANSFER_PROTOCOL_VERSION,
                "type": "ack",
                "transfer_id": manifest.transfer_id,
                "chunk_index": index,
                "chunk_sha256": hashlib.sha256(data).hexdigest(),
                "durable": True,
            },
        )


def _provider_state_from_message(message: dict[str, Any]) -> dict[str, Any]:
    raw = message.get("provider_state", {})
    if not isinstance(raw, dict) or len(raw) > 16:
        raise transfer_failure(
            TransferErrorCode.COMPATIBILITY_FAILED,
            "sender provider state is invalid",
        )
    return dict(raw)


def _carrier_chunk_fields(
    message: dict[str, Any],
    manifest: TransferManifest,
) -> tuple[int, bytes, str, int]:
    if (
        message.get("protocol") != TRANSFER_PROTOCOL_VERSION
        or message.get("type") != "carrier_chunk"
        or message.get("transfer_id") != manifest.transfer_id
    ):
        raise transfer_failure(
            TransferErrorCode.COMPATIBILITY_FAILED,
            "sender returned an invalid mechanism-carrier chunk record",
        )
    index = message.get("chunk_index")
    expected_frames = message.get("expected_frames")
    session_id = message.get("session_id")
    digest_text = message.get("chunk_sha256")
    if (
        not isinstance(index, int)
        or isinstance(index, bool)
        or not 0 <= index < manifest.chunk_count
        or not isinstance(expected_frames, int)
        or isinstance(expected_frames, bool)
        or expected_frames <= 0
        or expected_frames > 10_000_000
        or not isinstance(session_id, str)
        or len(session_id) > 128
        or not isinstance(digest_text, str)
        or len(digest_text) != 64
    ):
        raise transfer_failure(
            TransferErrorCode.COMPATIBILITY_FAILED,
            "mechanism-carrier chunk metadata is out of bounds",
        )
    try:
        digest = bytes.fromhex(digest_text)
    except ValueError as exc:
        raise transfer_failure(
            TransferErrorCode.COMPATIBILITY_FAILED,
            "mechanism-carrier chunk digest is invalid",
        ) from exc
    return index, digest, session_id, expected_frames


def _manifest_from_message(message: dict[str, Any]) -> TransferManifest:
    if message.get("protocol") != TRANSFER_PROTOCOL_VERSION or message.get("type") != "manifest":
        raise transfer_failure(
            TransferErrorCode.COMPATIBILITY_FAILED,
            "sender did not provide a transfer manifest",
        )
    raw = message.get("manifest")
    if not isinstance(raw, dict):
        raise transfer_failure(
            TransferErrorCode.COMPATIBILITY_FAILED,
            "sender manifest is not an object",
        )
    try:
        return TransferManifest.from_json(raw)
    except (TypeError, ValueError) as exc:
        raise transfer_failure(
            TransferErrorCode.COMPATIBILITY_FAILED,
            f"sender manifest is invalid: {exc}",
        ) from exc


def _optional_receiver_state(
    store: TransferStateStore, transfer_id: str
) -> TransferStateRecord | None:
    try:
        return store.read_state(transfer_id, "receiver")
    except TransferFailure as exc:
        if exc.code is TransferErrorCode.INPUT_INVALID:
            return None
        raise


def _accepted_transfer_id(store: TransferStateStore, offer_id: str) -> str | None:
    for record in store.list_states(role="receiver"):
        if record.manifest.offer_id == offer_id:
            return record.transfer_id
    return None


def _mark_receiver_interrupted(
    receiver_file: ReceiverFile,
    code: TransferErrorCode,
    resumable: bool,
) -> None:
    try:
        current = receiver_file.store.read_state(
            receiver_file.record.transfer_id,
            "receiver",
        )
        if current.status in {
            TransferStatus.COMPLETED,
            TransferStatus.CANCELLED,
            TransferStatus.EXPIRED,
            TransferStatus.QUARANTINED,
        }:
            return
        if resumable and current.status is TransferStatus.TRANSFERRING:
            current = transition_state(current, TransferStatus.PAUSED)
        else:
            current = transition_state(
                current,
                TransferStatus.FAILED,
                error_code=code,
            )
        receiver_file.store.write_state(current)
        receiver_file.record = current
    except TransferFailure, ValueError:
        return


async def _send_error(writer: asyncio.StreamWriter, failure: TransferFailure) -> None:
    if writer.is_closing():
        return
    try:
        await write_control(
            writer,
            {
                "protocol": TRANSFER_PROTOCOL_VERSION,
                "type": "error",
                "code": failure.code.value,
                "detail": _remote_safe_detail(failure.code),
                "retryable": failure.retryable,
                "resumable": failure.resumable,
            },
        )
    except ConnectionError, OSError, TransferFailure:
        return


def _remote_safe_detail(code: TransferErrorCode) -> str:
    details = {
        TransferErrorCode.INPUT_INVALID: "receiver rejected the transfer input",
        TransferErrorCode.OFFER_INVALID: "receiver rejected the transfer offer",
        TransferErrorCode.OFFER_EXPIRED: "receiver offer has expired",
        TransferErrorCode.OFFER_REPLAYED: "receiver offer was already used",
        TransferErrorCode.TRUST_FAILED: "receiver rejected the transfer credentials",
        TransferErrorCode.POLICY_BLOCKED: "receiver policy blocked the transfer",
        TransferErrorCode.CRYPTO_UNAVAILABLE: "receiver cryptography is unavailable",
        TransferErrorCode.CRYPTO_FAILED: "receiver cryptographic validation failed",
        TransferErrorCode.PROVIDER_UNAVAILABLE: "receiver provider is unavailable",
        TransferErrorCode.PROVIDER_INCOMPATIBLE: "receiver provider is incompatible",
        TransferErrorCode.PRIVILEGE_REQUIRED: "receiver provider lacks required privileges",
        TransferErrorCode.NETWORK_FAILED: "receiver network operation failed",
        TransferErrorCode.TIMEOUT: "receiver transfer operation timed out",
        TransferErrorCode.INTEGRITY_FAILED: "receiver integrity validation failed",
        TransferErrorCode.STORAGE_FAILED: "receiver could not persist the transfer",
        TransferErrorCode.COMPATIBILITY_FAILED: "receiver protocol is incompatible",
        TransferErrorCode.CANCELLED: "receiver transfer was cancelled",
        TransferErrorCode.INTERNAL_ERROR: "receiver encountered an internal transfer error",
    }
    return details[code]


__all__ = ["TransferServer", "TransferServerAddress"]
