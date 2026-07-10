"""Direct TLS provider with durable chunk acknowledgements and resume."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ssl
from contextlib import suppress
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .errors import TransferErrorCode, TransferFailure, transfer_failure
from .models import (
    TRANSFER_EVENT_SCHEMA_VERSION,
    ProviderDirectionality,
    ProviderEvidenceLevel,
    ProviderManifest,
    TransferEvent,
    TransferEventKind,
    TransferManifest,
    TransferOffer,
    TransferReceipt,
    TransferStateRecord,
    TransferStatus,
)
from .providers import ProviderPreflight, ProviderSendRequest, basic_preflight
from .security import client_ssl_context, peer_certificate_sha256
from .source import StableSourceFile
from .state import TransferStateStore, transition_state
from .wire import TRANSFER_PROTOCOL_VERSION, read_control, write_chunk, write_control

DIRECT_TLS_PROVIDER = "tcp-tls"


class DirectTlsProvider:
    """TLS 1.3 direct provider used as the first secure product control path."""

    @property
    def manifest(self) -> ProviderManifest:
        return ProviderManifest(
            name=DIRECT_TLS_PROVIDER,
            version="1",
            priority=100,
            directionality=ProviderDirectionality.DUPLEX,
            feedback=True,
            max_record_size=4 * 1024 * 1024,
            evidence_level=ProviderEvidenceLevel.DIRECT_TLS_CONTROL,
            extras=("transfer",),
        )

    def preflight(self, source: Path, offer: TransferOffer) -> ProviderPreflight:
        return basic_preflight(self.manifest, source, offer)

    async def send(self, request: ProviderSendRequest) -> TransferReceipt:
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
        record = _sender_record(store, manifest, request.source, request.offer)
        manifest = record.manifest
        try:
            if record.status is TransferStatus.CREATED:
                record = await _advance_sender(
                    store,
                    record,
                    TransferStatus.PREFLIGHTING,
                    TransferStatus.NEGOTIATING,
                )
            await _emit(request, record, TransferEventKind.STATE, "connecting to receiver")
            reader, writer = await _open_tls(request.offer, request.timeout_s)
            try:
                _verify_peer(writer, request.offer)
                record = await _advance_sender(
                    store,
                    record,
                    TransferStatus.HANDSHAKING,
                )
                await _emit(request, record, TransferEventKind.STATE, "TLS peer pin verified")
                await _handshake(reader, writer, request.offer, manifest)
                record = await _advance_sender(
                    store,
                    record,
                    TransferStatus.TRANSFERRING,
                )
                ready = await _send_manifest(reader, writer, manifest)
                record = await _apply_receiver_state(store, record, ready)
                await _send_missing_chunks(request, source, reader, writer, store, record)
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
                "transfer was cancelled",
                retryable=True,
                resumable=True,
            ) from exc
        except TransferFailure as exc:
            await _mark_sender_interrupted(store, record, exc.code, resumable=exc.resumable)
            raise
        except Exception as exc:
            await _mark_sender_interrupted(store, record, TransferErrorCode.INTERNAL_ERROR)
            raise transfer_failure(
                TransferErrorCode.INTERNAL_ERROR,
                "direct TLS provider encountered an unexpected internal error",
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
            "receiver durably acknowledged and verified the file",
            bytes_transferred=manifest.file_size,
        )
        return receipt


async def _open_tls(
    offer: TransferOffer,
    timeout_s: float,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    try:
        async with asyncio.timeout(timeout_s):
            return await asyncio.open_connection(
                offer.host,
                offer.port,
                ssl=client_ssl_context(),
                server_hostname=offer.host,
            )
    except TimeoutError as exc:
        raise transfer_failure(
            TransferErrorCode.TIMEOUT,
            "timed out connecting to the receiver",
            retryable=True,
            resumable=True,
        ) from exc
    except (OSError, ssl.SSLError) as exc:
        raise transfer_failure(
            TransferErrorCode.NETWORK_FAILED,
            f"could not establish the TLS transfer connection: {exc}",
            retryable=True,
            resumable=True,
        ) from exc


def _verify_peer(writer: asyncio.StreamWriter, offer: TransferOffer) -> None:
    ssl_object = writer.get_extra_info("ssl_object")
    if not isinstance(ssl_object, ssl.SSLObject | ssl.SSLSocket):
        raise transfer_failure(
            TransferErrorCode.CRYPTO_FAILED,
            "transfer provider did not establish TLS",
        )
    actual = peer_certificate_sha256(ssl_object)
    if not hmac.compare_digest(actual, offer.tls_cert_sha256):
        raise transfer_failure(
            TransferErrorCode.TRUST_FAILED,
            "receiver TLS certificate does not match the transfer offer",
        )


async def _handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    offer: TransferOffer,
    manifest: TransferManifest,
) -> None:
    await write_control(
        writer,
        {
            "protocol": TRANSFER_PROTOCOL_VERSION,
            "type": "hello",
            "offer_id": offer.offer_id,
            "access_token": offer.access_token,
            "transfer_id": manifest.transfer_id,
        },
    )
    response = await read_control(reader)
    _raise_remote_error(response)
    if response.get("type") != "hello_ok" or response.get("transfer_id") != manifest.transfer_id:
        raise transfer_failure(
            TransferErrorCode.COMPATIBILITY_FAILED,
            "receiver returned an invalid handshake response",
        )


async def _send_manifest(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    manifest: TransferManifest,
    *,
    provider_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    await write_control(
        writer,
        {
            "protocol": TRANSFER_PROTOCOL_VERSION,
            "type": "manifest",
            "manifest": manifest.to_json(),
            "provider_state": dict(provider_state or {}),
        },
    )
    response = await read_control(reader)
    _raise_remote_error(response)
    if response.get("type") != "ready" or response.get("transfer_id") != manifest.transfer_id:
        raise transfer_failure(
            TransferErrorCode.COMPATIBILITY_FAILED,
            "receiver returned an invalid manifest response",
        )
    return response


async def _apply_receiver_state(
    store: TransferStateStore,
    record: TransferStateRecord,
    ready: dict[str, Any],
) -> TransferStateRecord:
    raw = ready.get("acknowledged_chunks")
    if not isinstance(raw, list) or not all(
        isinstance(item, int) and not isinstance(item, bool) for item in raw
    ):
        raise transfer_failure(
            TransferErrorCode.COMPATIBILITY_FAILED,
            "receiver acknowledgement state is invalid",
        )
    acknowledged = tuple(sorted(set(raw)))
    if any(index < 0 or index >= record.manifest.chunk_count for index in acknowledged):
        raise transfer_failure(
            TransferErrorCode.COMPATIBILITY_FAILED,
            "receiver acknowledged a chunk outside the manifest",
        )
    updated = replace(
        record,
        acknowledged_chunks=acknowledged,
        updated_at=datetime.now(UTC),
    )
    await asyncio.to_thread(store.write_state, updated)
    return updated


async def _send_missing_chunks(
    request: ProviderSendRequest,
    source: StableSourceFile,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    store: TransferStateStore,
    record: TransferStateRecord,
) -> None:
    manifest = record.manifest
    acknowledged = set(record.acknowledged_chunks)
    transferred = sum(_chunk_length(manifest, index) for index in acknowledged)
    for index in range(manifest.chunk_count):
        if index in acknowledged:
            continue
        data = await asyncio.to_thread(source.read_chunk, manifest, index)
        digest = hashlib.sha256(data).digest()
        await write_chunk(writer, index, digest, data)
        response = await asyncio.wait_for(read_control(reader), request.timeout_s)
        _raise_remote_error(response)
        if response.get("type") != "ack" or response.get("chunk_index") != index:
            raise transfer_failure(
                TransferErrorCode.COMPATIBILITY_FAILED,
                "receiver returned an invalid chunk acknowledgement",
            )
        if response.get("chunk_sha256") != digest.hex():
            raise transfer_failure(
                TransferErrorCode.INTEGRITY_FAILED,
                "receiver acknowledged a different chunk digest",
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
            "receiver durably acknowledged a chunk",
            bytes_transferred=transferred,
            chunk_index=index,
        )


def _sender_record(
    store: TransferStateStore,
    manifest: TransferManifest,
    source: Path,
    offer: TransferOffer,
    *,
    provider_state: dict[str, Any] | None = None,
) -> TransferStateRecord:
    active_provider_state = dict(provider_state or {})
    try:
        existing = store.read_state(manifest.transfer_id, "sender")
    except TransferFailure as exc:
        if exc.code is not TransferErrorCode.INPUT_INVALID:
            raise
    else:
        normalized = replace(manifest, created_at=existing.manifest.created_at)
        if (
            existing.manifest != normalized
            or existing.offer != offer.to_json()
            or existing.provider_state != active_provider_state
        ):
            raise transfer_failure(
                TransferErrorCode.INTEGRITY_FAILED,
                "source file or offer changed since the transfer began",
            )
        return _prepare_resumed_sender(store, existing)
    now = datetime.now(UTC)
    record = TransferStateRecord(
        transfer_id=manifest.transfer_id,
        role="sender",
        status=TransferStatus.CREATED,
        manifest=manifest,
        acknowledged_chunks=(),
        source_path=str(source.resolve()),
        spool_path=None,
        destination_path=None,
        offer=offer.to_json(),
        created_at=now,
        updated_at=now,
        provider_state=active_provider_state,
    )
    store.write_state(record)
    return record


def _prepare_resumed_sender(
    store: TransferStateStore,
    record: TransferStateRecord,
) -> TransferStateRecord:
    if record.status is TransferStatus.COMPLETED:
        raise transfer_failure(
            TransferErrorCode.OFFER_REPLAYED,
            "the requested transfer is already complete",
        )
    if record.status is TransferStatus.TRANSFERRING:
        record = transition_state(record, TransferStatus.PAUSED)
        store.write_state(record)
    if record.status not in {
        TransferStatus.PAUSED,
        TransferStatus.CANCELLED,
        TransferStatus.FAILED,
        TransferStatus.NEGOTIATING,
    }:
        raise transfer_failure(
            TransferErrorCode.INTERNAL_ERROR,
            f"sender state {record.status.value} cannot be resumed",
        )
    return record


async def _advance_sender(
    store: TransferStateStore,
    record: TransferStateRecord,
    *targets: TransferStatus,
) -> TransferStateRecord:
    for target in targets:
        if record.status is target:
            continue
        if record.status is TransferStatus.TRANSFERRING and target is TransferStatus.PREFLIGHTING:
            continue
        record = transition_state(record, target)
        await asyncio.to_thread(store.write_state, record)
    return record


async def _mark_sender_interrupted(
    store: TransferStateStore,
    record: TransferStateRecord,
    code: TransferErrorCode,
    *,
    resumable: bool = False,
    cancelled: bool = False,
) -> None:
    try:
        current = store.read_state(record.transfer_id, "sender")
        if current.status is TransferStatus.COMPLETED:
            return
        if cancelled and TransferStatus.CANCELLED in _next_states(current.status):
            current = transition_state(current, TransferStatus.CANCELLED)
        elif resumable and TransferStatus.PAUSED in _next_states(current.status):
            current = transition_state(current, TransferStatus.PAUSED)
        elif TransferStatus.FAILED in _next_states(current.status):
            current = transition_state(current, TransferStatus.FAILED, error_code=code)
        else:
            return
        await asyncio.to_thread(store.write_state, current)
    except TransferFailure, ValueError:
        return


def _next_states(status: TransferStatus) -> set[TransferStatus]:
    if status is TransferStatus.CREATED:
        return {TransferStatus.PREFLIGHTING, TransferStatus.CANCELLED, TransferStatus.EXPIRED}
    if status in {
        TransferStatus.PREFLIGHTING,
        TransferStatus.NEGOTIATING,
        TransferStatus.HANDSHAKING,
    }:
        return {TransferStatus.FAILED, TransferStatus.CANCELLED}
    if status is TransferStatus.TRANSFERRING:
        return {TransferStatus.PAUSED, TransferStatus.FAILED, TransferStatus.CANCELLED}
    return set()


def _chunk_length(manifest: TransferManifest, index: int) -> int:
    return min(manifest.chunk_size, manifest.file_size - index * manifest.chunk_size)


async def _emit(
    request: ProviderSendRequest,
    record: TransferStateRecord,
    kind: TransferEventKind,
    message: str,
    *,
    bytes_transferred: int = 0,
    chunk_index: int | None = None,
) -> None:
    await request.emit(
        TransferEvent(
            schema_version=TRANSFER_EVENT_SCHEMA_VERSION,
            sequence=0,
            transfer_id=record.transfer_id,
            kind=kind,
            status=record.status,
            timestamp=datetime.now(UTC),
            provider=record.manifest.provider,
            bytes_transferred=bytes_transferred,
            total_bytes=record.manifest.file_size,
            chunk_index=chunk_index,
            message=message,
        )
    )


def _validate_complete(response: dict[str, Any], manifest: TransferManifest) -> None:
    _raise_remote_error(response)
    if (
        response.get("type") != "complete"
        or response.get("transfer_id") != manifest.transfer_id
        or response.get("file_sha256") != manifest.file_sha256
        or response.get("file_size") != manifest.file_size
        or response.get("verified") is not True
        or response.get("acknowledged") is not True
    ):
        raise transfer_failure(
            TransferErrorCode.INTEGRITY_FAILED,
            "receiver final acknowledgement does not match the transfer manifest",
        )


def _raise_remote_error(response: dict[str, Any]) -> None:
    if response.get("type") != "error":
        return
    raw_code = response.get("code")
    try:
        code = TransferErrorCode(str(raw_code))
    except ValueError:
        code = TransferErrorCode.INTERNAL_ERROR
    detail = response.get("detail")
    raise transfer_failure(
        code,
        str(detail) if isinstance(detail, str) else "receiver rejected the transfer",
        retryable=bool(response.get("retryable", False)),
        resumable=bool(response.get("resumable", False)),
    )


__all__ = ["DIRECT_TLS_PROVIDER", "DirectTlsProvider"]
