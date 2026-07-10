"""Stable, bounded reads from one opened regular source file."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Self
from uuid import uuid4

from .errors import TransferErrorCode, transfer_failure

if TYPE_CHECKING:
    from .models import TransferManifest


@dataclass
class StableSourceFile:
    """An open source descriptor whose identity is checked around every read."""

    path: Path
    _descriptor: int
    _identity: tuple[int, int, int, int, int]
    _closed: bool = False

    @classmethod
    def open(cls, path: Path | str) -> Self:
        source_path = Path(path)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(source_path, flags)
        except OSError as exc:
            raise transfer_failure(
                TransferErrorCode.INPUT_INVALID,
                f"could not open a regular non-symlink source file: {exc}",
            ) from exc
        try:
            source_stat = os.fstat(descriptor)
            if not stat.S_ISREG(source_stat.st_mode):
                raise transfer_failure(
                    TransferErrorCode.INPUT_INVALID,
                    "source must be a regular, non-symlink file",
                )
            return cls(source_path, descriptor, _file_identity(source_stat))
        except Exception:
            os.close(descriptor)
            raise

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        os.close(self._descriptor)
        self._closed = True

    def create_manifest(
        self,
        *,
        offer_id: str,
        provider: str,
        chunk_size: int,
        transfer_id: str | None = None,
    ) -> TransferManifest:
        from .models import MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, TransferManifest

        if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
            raise transfer_failure(
                TransferErrorCode.INPUT_INVALID,
                f"chunk_size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE}",
            )
        self._verify_identity()
        digest = hashlib.sha256()
        offset = 0
        while chunk := os.pread(self._descriptor, 1024 * 1024, offset):
            digest.update(chunk)
            offset += len(chunk)
        self._verify_identity()
        return TransferManifest(
            transfer_id=transfer_id or str(uuid4()),
            offer_id=offer_id,
            file_name=self.path.name,
            file_size=self._identity[2],
            file_sha256=digest.hexdigest(),
            chunk_size=chunk_size,
            chunk_count=(self._identity[2] + chunk_size - 1) // chunk_size,
            provider=provider,
            created_at=datetime.now(UTC),
        )

    def read_chunk(self, manifest: TransferManifest, index: int) -> bytes:
        if not 0 <= index < manifest.chunk_count:
            raise transfer_failure(
                TransferErrorCode.INPUT_INVALID,
                "source chunk index is outside the manifest",
            )
        self._verify_identity()
        length = min(
            manifest.chunk_size,
            manifest.file_size - index * manifest.chunk_size,
        )
        try:
            data = os.pread(self._descriptor, length, index * manifest.chunk_size)
        except OSError as exc:
            raise transfer_failure(
                TransferErrorCode.STORAGE_FAILED,
                f"could not read the source file: {exc}",
                retryable=True,
                resumable=True,
            ) from exc
        self._verify_identity()
        if len(data) != length:
            raise transfer_failure(
                TransferErrorCode.INTEGRITY_FAILED,
                "source file changed while the transfer was running",
            )
        return data

    def _verify_identity(self) -> None:
        if self._closed:
            raise transfer_failure(
                TransferErrorCode.INTERNAL_ERROR,
                "source descriptor was closed before transfer completion",
            )
        try:
            current = _file_identity(os.fstat(self._descriptor))
        except OSError as exc:
            raise transfer_failure(
                TransferErrorCode.STORAGE_FAILED,
                f"could not inspect the source file: {exc}",
                retryable=True,
                resumable=True,
            ) from exc
        if current != self._identity:
            raise transfer_failure(
                TransferErrorCode.INTEGRITY_FAILED,
                "source file identity or contents changed after manifest creation",
            )


def _file_identity(source_stat: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        source_stat.st_dev,
        source_stat.st_ino,
        source_stat.st_size,
        source_stat.st_mtime_ns,
        source_stat.st_ctime_ns,
    )


__all__ = ["StableSourceFile"]
