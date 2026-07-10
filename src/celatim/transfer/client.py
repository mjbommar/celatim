"""Typed async client and operation lifecycle for file transfer."""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import AsyncIterable
from contextlib import suppress
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Self
from uuid import uuid4

from .direct import DirectTlsProvider
from .errors import TransferErrorCode, TransferFailure, transfer_failure
from .models import (
    DEFAULT_CHUNK_SIZE,
    MAX_CHUNK_SIZE,
    MIN_CHUNK_SIZE,
    TRANSFER_EVENT_SCHEMA_VERSION,
    TransferEvent,
    TransferEventKind,
    TransferOffer,
    TransferReceipt,
    TransferStateRecord,
    TransferStatus,
)
from .providers import ProviderRegistry, ProviderSendRequest, TransferProvider
from .state import TransferStateStore, default_transfer_home
from .storage import sanitize_file_name

_LOGGER = logging.getLogger(__name__)


class TransferOperation:
    """One running transfer with ordered events, cancellation, and a typed result."""

    def __init__(
        self,
        transfer_id: str,
        provider: TransferProvider,
        request: ProviderSendRequest,
        *,
        max_retries: int,
        retry_backoff_s: float,
        cleanup_on_success: Path | None = None,
    ) -> None:
        self.transfer_id = transfer_id
        self.provider = provider
        self._queue: asyncio.Queue[TransferEvent | None] = asyncio.Queue(maxsize=256)
        self._sequence = 0
        self._terminal_emitted = False
        self._max_retries = max_retries
        self._retry_backoff_s = retry_backoff_s
        self._request = replace(request, emit=self._emit)
        self._cleanup_on_success = cleanup_on_success
        self._task = asyncio.create_task(self._run())

    async def _emit(self, event: TransferEvent) -> None:
        if event.kind in {TransferEventKind.COMPLETED, TransferEventKind.FAILED}:
            self._terminal_emitted = True
        ordered = replace(event, sequence=self._sequence)
        self._sequence += 1
        self._enqueue(ordered)

    async def _run(self) -> TransferReceipt:
        try:
            for attempt in range(self._max_retries + 1):
                try:
                    receipt = await self.provider.send(self._request)
                    if not self._terminal_emitted:
                        await self._emit(
                            TransferEvent(
                                schema_version=TRANSFER_EVENT_SCHEMA_VERSION,
                                sequence=0,
                                transfer_id=self.transfer_id,
                                kind=TransferEventKind.COMPLETED,
                                status=TransferStatus.COMPLETED,
                                timestamp=datetime.now(UTC),
                                provider=self.provider.manifest.name,
                                bytes_transferred=receipt.file_size,
                                total_bytes=receipt.file_size,
                                message="provider completed an authenticated transfer",
                            )
                        )
                    await self._cleanup_completed_source()
                    return receipt
                except TransferFailure as exc:
                    if (
                        exc.retryable
                        and exc.resumable
                        and exc.code is not TransferErrorCode.CANCELLED
                        and attempt < self._max_retries
                    ):
                        await self._emit(
                            TransferEvent(
                                schema_version=TRANSFER_EVENT_SCHEMA_VERSION,
                                sequence=0,
                                transfer_id=self.transfer_id,
                                kind=TransferEventKind.RETRY,
                                status=TransferStatus.PAUSED,
                                timestamp=datetime.now(UTC),
                                provider=self.provider.manifest.name,
                                retry_count=attempt + 1,
                                message="retrying the same provider and authenticated manifest",
                                error_code=exc.code,
                            )
                        )
                        if self._retry_backoff_s:
                            await asyncio.sleep(self._retry_backoff_s)
                        continue
                    await self._emit(
                        TransferEvent(
                            schema_version=TRANSFER_EVENT_SCHEMA_VERSION,
                            sequence=0,
                            transfer_id=self.transfer_id,
                            kind=TransferEventKind.FAILED,
                            status=(
                                TransferStatus.CANCELLED
                                if exc.code is TransferErrorCode.CANCELLED
                                else TransferStatus.FAILED
                            ),
                            timestamp=datetime.now(UTC),
                            provider=self.provider.manifest.name,
                            message=exc.detail,
                            error_code=exc.code,
                        )
                    )
                    raise
            raise AssertionError("retry loop exhausted without a result or failure")
        except Exception as exc:
            if isinstance(exc, TransferFailure):
                raise
            _LOGGER.exception(
                "transfer provider %s failed with %s",
                self.provider.manifest.name,
                type(exc).__name__,
            )
            failure = transfer_failure(
                TransferErrorCode.INTERNAL_ERROR,
                "transfer provider raised an unexpected internal error",
            )
            await self._emit(
                TransferEvent(
                    schema_version=TRANSFER_EVENT_SCHEMA_VERSION,
                    sequence=0,
                    transfer_id=self.transfer_id,
                    kind=TransferEventKind.FAILED,
                    status=TransferStatus.FAILED,
                    timestamp=datetime.now(UTC),
                    provider=self.provider.manifest.name,
                    message=failure.detail,
                    error_code=failure.code,
                )
            )
            raise failure from exc
        finally:
            self._enqueue(None)

    def _enqueue(self, item: TransferEvent | None) -> None:
        """Keep event memory bounded without making transfer progress consumer-dependent."""

        try:
            self._queue.put_nowait(item)
        except asyncio.QueueFull:
            self._queue.get_nowait()
            self._queue.put_nowait(item)

    async def events(self):
        """Yield ordered events until the transfer reaches a terminal state."""

        while True:
            event = await self._queue.get()
            if event is None:
                return
            yield event

    async def result(self) -> TransferReceipt:
        return await self._task

    async def cancel(self) -> None:
        self._task.cancel()
        try:
            await self._task
        except TransferFailure as exc:
            if exc.code is not TransferErrorCode.CANCELLED:
                raise

    @property
    def done(self) -> bool:
        return self._task.done()

    async def _cleanup_completed_source(self) -> None:
        path = self._cleanup_on_success
        if path is None:
            return
        try:
            await asyncio.to_thread(path.unlink, missing_ok=True)
            await asyncio.to_thread(path.parent.rmdir)
        except OSError as exc:
            _LOGGER.warning(
                "completed stream source cleanup failed with %s",
                type(exc).__name__,
            )


class TransferClient:
    """High-level typed client shared by the CLI and embedding applications."""

    def __init__(
        self,
        *,
        home: Path | str | None = None,
        registry: ProviderRegistry | None = None,
        timeout_s: float = 60.0,
        max_retries: int = 2,
        retry_backoff_s: float = 0.25,
    ) -> None:
        if timeout_s <= 0 or retry_backoff_s < 0 or max_retries < 0:
            raise ValueError("timeout_s must be > 0 and retry controls must be >= 0")
        self.home = Path(home) if home is not None else default_transfer_home()
        if registry is None:
            registry = ProviderRegistry((DirectTlsProvider(),))
            registry.discover()
        self.registry = registry
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self.retry_backoff_s = retry_backoff_s
        self._closed = False

    @classmethod
    def open_default(
        cls,
        *,
        home: Path | str | None = None,
        registry: ProviderRegistry | None = None,
        timeout_s: float = 60.0,
        max_retries: int = 2,
        retry_backoff_s: float = 0.25,
    ) -> Self:
        return cls(
            home=home,
            registry=registry,
            timeout_s=timeout_s,
            max_retries=max_retries,
            retry_backoff_s=retry_backoff_s,
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self._closed = True

    async def send_file(
        self,
        path: Path | str,
        offer: TransferOffer | str | bytes | dict[str, object],
        *,
        provider: str | None = None,
        allow_fallback: bool = False,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        transfer_id: str | None = None,
        allow_expired_resume: bool = False,
        _cleanup_on_success: Path | None = None,
    ) -> TransferOperation:
        if self._closed:
            raise RuntimeError("transfer client is closed")
        if (
            not isinstance(chunk_size, int)
            or isinstance(chunk_size, bool)
            or not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE
        ):
            raise transfer_failure(
                TransferErrorCode.INPUT_INVALID,
                f"chunk_size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE}",
            )
        parsed_offer = offer if isinstance(offer, TransferOffer) else TransferOffer.parse(offer)
        if not allow_expired_resume:
            parsed_offer.require_active()
        source = Path(path)
        selected, _ = self.registry.select(
            source,
            parsed_offer,
            requested=provider,
            allow_fallback=allow_fallback,
        )
        if chunk_size > selected.manifest.max_record_size:
            raise transfer_failure(
                TransferErrorCode.POLICY_BLOCKED,
                f"chunk_size exceeds provider {selected.manifest.name!r} record limit",
            )
        active_id = transfer_id or str(uuid4())

        async def placeholder_emit(event: TransferEvent) -> None:
            del event

        request = ProviderSendRequest(
            source=source,
            offer=parsed_offer,
            transfer_id=active_id,
            home=self.home,
            chunk_size=chunk_size,
            timeout_s=self.timeout_s,
            emit=placeholder_emit,
        )
        return TransferOperation(
            active_id,
            selected,
            request,
            max_retries=self.max_retries,
            retry_backoff_s=self.retry_backoff_s,
            cleanup_on_success=_cleanup_on_success,
        )

    async def send_stream(
        self,
        chunks: AsyncIterable[bytes],
        offer: TransferOffer | str | bytes | dict[str, object],
        *,
        file_name: str,
        provider: str | None = None,
        allow_fallback: bool = False,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> TransferOperation:
        """Spool a bounded async byte stream privately, then transfer it by name."""

        if self._closed:
            raise RuntimeError("transfer client is closed")
        parsed_offer = offer if isinstance(offer, TransferOffer) else TransferOffer.parse(offer)
        parsed_offer.require_active()
        safe_name = sanitize_file_name(file_name)
        transfer_id = str(uuid4())
        spool_dir = self.home / "outgoing" / transfer_id
        spool_path = spool_dir / safe_name
        try:
            await asyncio.to_thread(spool_dir.mkdir, mode=0o700, parents=True)
            await asyncio.to_thread(spool_dir.chmod, 0o700)
            descriptor = await asyncio.to_thread(
                os.open,
                spool_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            total = 0
            try:
                async for chunk in chunks:
                    if not isinstance(chunk, bytes):
                        raise transfer_failure(
                            TransferErrorCode.INPUT_INVALID,
                            "stream chunks must be bytes",
                        )
                    total += len(chunk)
                    if total > parsed_offer.max_file_size:
                        raise transfer_failure(
                            TransferErrorCode.POLICY_BLOCKED,
                            "stream exceeds the receiver's maximum file size",
                        )
                    await asyncio.to_thread(_write_all, descriptor, chunk)
                await asyncio.to_thread(os.fsync, descriptor)
            finally:
                await asyncio.to_thread(os.close, descriptor)
            operation = await self.send_file(
                spool_path,
                parsed_offer,
                provider=provider,
                allow_fallback=allow_fallback,
                chunk_size=chunk_size,
                transfer_id=transfer_id,
                _cleanup_on_success=spool_path,
            )
        except Exception:
            await asyncio.to_thread(spool_path.unlink, missing_ok=True)
            with suppress(OSError):
                await asyncio.to_thread(spool_dir.rmdir)
            raise
        return operation

    async def send_bytes(
        self,
        data: bytes,
        offer: TransferOffer | str | bytes | dict[str, object],
        *,
        file_name: str,
        provider: str | None = None,
        allow_fallback: bool = False,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> TransferOperation:
        """Send an in-memory byte string through the streaming source API."""

        async def chunks() -> AsyncIterable[bytes]:
            yield data

        return await self.send_stream(
            chunks(),
            offer,
            file_name=file_name,
            provider=provider,
            allow_fallback=allow_fallback,
            chunk_size=chunk_size,
        )

    async def resume(self, transfer_id: str) -> TransferOperation:
        store = TransferStateStore(self.home)
        record = await asyncio.to_thread(store.read_state, transfer_id, "sender")
        if record.source_path is None:
            raise transfer_failure(
                TransferErrorCode.STORAGE_FAILED,
                "sender transfer state does not include a source path",
            )
        offer = TransferOffer.parse(record.offer)
        return await self.send_file(
            Path(record.source_path),
            offer,
            provider=record.manifest.provider,
            chunk_size=record.manifest.chunk_size,
            transfer_id=transfer_id,
            allow_expired_resume=True,
        )

    async def status(self) -> tuple[TransferStateRecord, ...]:
        store = TransferStateStore(self.home)
        return await asyncio.to_thread(store.list_states, role="sender")


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write while spooling transfer stream")
        view = view[written:]


__all__ = ["TransferClient", "TransferOperation"]
