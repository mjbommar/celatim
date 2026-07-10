"""Safe receiver file naming, durable chunks, and atomic final placement."""

from __future__ import annotations

import hashlib
import os
import re
import unicodedata
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from .errors import TransferErrorCode, transfer_failure
from .models import TransferManifest, TransferStateRecord, TransferStatus
from .state import TransferStateStore, transition_state

_WINDOWS_DEVICE_NAMES = {
    "aux",
    "clock$",
    "con",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}


def sanitize_file_name(value: str) -> str:
    """Return a safe basename or fail without silently changing sender intent."""

    normalized = unicodedata.normalize("NFC", value)
    if not normalized or normalized in {".", ".."}:
        raise transfer_failure(TransferErrorCode.INPUT_INVALID, "file name is empty or reserved")
    if Path(normalized).name != normalized or "/" in normalized or "\\" in normalized:
        raise transfer_failure(
            TransferErrorCode.INPUT_INVALID,
            "file name must not contain a path",
        )
    if "\x00" in normalized or any(
        unicodedata.category(char).startswith("C") for char in normalized
    ):
        raise transfer_failure(
            TransferErrorCode.INPUT_INVALID,
            "file name contains a control character",
        )
    if len(normalized.encode()) > 255:
        raise transfer_failure(
            TransferErrorCode.INPUT_INVALID,
            "file name exceeds 255 encoded bytes",
        )
    stem = normalized.rstrip(" .").split(".", 1)[0].casefold()
    if stem in _WINDOWS_DEVICE_NAMES:
        raise transfer_failure(
            TransferErrorCode.INPUT_INVALID,
            "file name is a reserved device name",
        )
    return normalized


def choose_destination(output_dir: Path, file_name: str, *, collision: str = "fail") -> Path:
    """Choose a destination without following sender-controlled path components."""

    if collision not in {"fail", "rename"}:
        raise ValueError("collision policy must be fail or rename")
    safe_name = sanitize_file_name(file_name)
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if output_dir.is_symlink() or not output_dir.is_dir():
        raise transfer_failure(
            TransferErrorCode.STORAGE_FAILED,
            "output directory must be a real directory, not a symlink",
        )
    candidate = output_dir / safe_name
    if not candidate.exists() and not candidate.is_symlink():
        return candidate
    if collision == "fail":
        raise transfer_failure(
            TransferErrorCode.STORAGE_FAILED,
            "destination file already exists",
        )
    stem, suffix = _split_name(safe_name)
    for index in range(1, 10_000):
        candidate = output_dir / f"{stem} ({index}){suffix}"
        if not candidate.exists() and not candidate.is_symlink():
            return candidate
    raise transfer_failure(
        TransferErrorCode.STORAGE_FAILED,
        "could not choose an unused destination name",
    )


class ReceiverFile:
    """A destination-local spool that acknowledges only durable verified chunks."""

    def __init__(self, store: TransferStateStore, record: TransferStateRecord) -> None:
        if record.role != "receiver" or record.spool_path is None:
            raise ValueError("receiver state must include a spool path")
        self.store = store
        self.record = record
        self.spool_path = Path(record.spool_path)

    @classmethod
    def create(
        cls,
        store: TransferStateStore,
        manifest: TransferManifest,
        offer: dict[str, object],
        output_dir: Path,
        *,
        collision: str = "fail",
        provider_state: dict[str, object] | None = None,
    ) -> ReceiverFile:
        destination = choose_destination(output_dir, manifest.file_name, collision=collision)
        spool = output_dir / f".celatim-{manifest.transfer_id}.part"
        try:
            descriptor = os.open(spool, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        except FileExistsError as exc:
            raise transfer_failure(
                TransferErrorCode.STORAGE_FAILED,
                "a partial file already exists without matching transfer state",
            ) from exc
        except OSError as exc:
            raise transfer_failure(
                TransferErrorCode.STORAGE_FAILED,
                f"could not create receiver spool: {exc}",
            ) from exc
        os.close(descriptor)
        now = datetime.now(UTC)
        record = TransferStateRecord(
            transfer_id=manifest.transfer_id,
            role="receiver",
            status=TransferStatus.CREATED,
            manifest=manifest,
            acknowledged_chunks=(),
            source_path=None,
            spool_path=str(spool),
            destination_path=str(destination),
            offer=dict(offer),
            created_at=now,
            updated_at=now,
            provider_state=dict(provider_state or {}),
        )
        for status in (
            TransferStatus.PREFLIGHTING,
            TransferStatus.NEGOTIATING,
            TransferStatus.HANDSHAKING,
            TransferStatus.TRANSFERRING,
        ):
            record = transition_state(record, status)
        store.write_state(record)
        return cls(store, record)

    @classmethod
    def resume(cls, store: TransferStateStore, transfer_id: str) -> ReceiverFile:
        return cls(store, store.read_state(transfer_id, "receiver"))

    def write_chunk(self, index: int, data: bytes, expected_sha256: bytes) -> None:
        manifest = self.record.manifest
        if not 0 <= index < manifest.chunk_count:
            raise transfer_failure(
                TransferErrorCode.INTEGRITY_FAILED,
                "chunk index is outside the transfer manifest",
            )
        expected_length = min(
            manifest.chunk_size,
            manifest.file_size - index * manifest.chunk_size,
        )
        if len(data) != expected_length:
            raise transfer_failure(
                TransferErrorCode.INTEGRITY_FAILED,
                "chunk length does not match the transfer manifest",
            )
        actual_digest = hashlib.sha256(data).digest()
        if not expected_sha256 or not _constant_time_equal(actual_digest, expected_sha256):
            raise transfer_failure(
                TransferErrorCode.INTEGRITY_FAILED,
                "chunk digest does not match its authenticated record",
            )
        if index in self.record.acknowledged_chunks:
            if self._read_chunk(index, expected_length) != data:
                raise transfer_failure(
                    TransferErrorCode.INTEGRITY_FAILED,
                    "duplicate chunk differs from durable receiver state",
                )
            return
        try:
            with self.spool_path.open("r+b", buffering=0) as output:
                output.seek(index * manifest.chunk_size)
                output.write(data)
                os.fsync(output.fileno())
        except OSError as exc:
            raise transfer_failure(
                TransferErrorCode.STORAGE_FAILED,
                f"could not persist receiver chunk: {exc}",
                retryable=True,
                resumable=True,
            ) from exc
        acknowledged = tuple(sorted((*self.record.acknowledged_chunks, index)))
        self.record = replace(
            self.record,
            acknowledged_chunks=acknowledged,
            updated_at=datetime.now(UTC),
        )
        self.store.write_state(self.record)

    def finalize(self) -> Path:
        manifest = self.record.manifest
        if len(self.record.acknowledged_chunks) != manifest.chunk_count:
            raise transfer_failure(
                TransferErrorCode.INTEGRITY_FAILED,
                "receiver cannot finalize before every chunk is acknowledged",
                retryable=True,
                resumable=True,
            )
        self.record = transition_state(self.record, TransferStatus.VERIFYING)
        self.store.write_state(self.record)
        try:
            with self.spool_path.open("r+b", buffering=0) as spool:
                spool.truncate(manifest.file_size)
                os.fsync(spool.fileno())
            if self.spool_path.stat().st_size != manifest.file_size:
                raise OSError("spool size does not match the manifest")
            digest = _hash_path(self.spool_path)
        except OSError as exc:
            raise transfer_failure(
                TransferErrorCode.STORAGE_FAILED,
                f"could not verify receiver spool: {exc}",
                retryable=True,
                resumable=True,
            ) from exc
        if digest != manifest.file_sha256:
            self.record = transition_state(
                self.record,
                TransferStatus.QUARANTINED,
                error_code=TransferErrorCode.INTEGRITY_FAILED,
            )
            self.store.write_state(self.record)
            raise transfer_failure(
                TransferErrorCode.INTEGRITY_FAILED,
                "received file digest does not match the authenticated manifest",
            )
        self.record = transition_state(self.record, TransferStatus.FINALIZING)
        self.store.write_state(self.record)
        destination = Path(self.record.destination_path or "")
        try:
            os.link(self.spool_path, destination)
            _sync_directory(destination.parent)
            self.spool_path.unlink()
            _sync_directory(destination.parent)
        except FileExistsError as exc:
            raise transfer_failure(
                TransferErrorCode.STORAGE_FAILED,
                "destination appeared while finalizing; partial file was retained",
            ) from exc
        except OSError as exc:
            raise transfer_failure(
                TransferErrorCode.STORAGE_FAILED,
                f"could not atomically place received file: {exc}",
            ) from exc
        self.record = transition_state(self.record, TransferStatus.COMPLETED)
        self.store.write_state(self.record)
        return destination

    def _read_chunk(self, index: int, length: int) -> bytes:
        try:
            with self.spool_path.open("rb") as source:
                source.seek(index * self.record.manifest.chunk_size)
                return source.read(length)
        except OSError as exc:
            raise transfer_failure(
                TransferErrorCode.STORAGE_FAILED,
                f"could not validate duplicate chunk: {exc}",
            ) from exc


def _hash_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _constant_time_equal(left: bytes, right: bytes) -> bool:
    import hmac

    return hmac.compare_digest(left, right)


def _split_name(name: str) -> tuple[str, str]:
    match = re.match(r"^(.*?)(\.[^.]+)?$", name)
    if match is None:
        return name, ""
    return match.group(1), match.group(2) or ""


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = ["ReceiverFile", "choose_destination", "sanitize_file_name"]
