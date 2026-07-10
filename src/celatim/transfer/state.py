"""Transfer state transitions and crash-safe local persistence."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .errors import TransferErrorCode, transfer_failure
from .models import TransferStateRecord, TransferStatus

_ALLOWED_TRANSITIONS: dict[TransferStatus, frozenset[TransferStatus]] = {
    TransferStatus.CREATED: frozenset(
        {TransferStatus.PREFLIGHTING, TransferStatus.CANCELLED, TransferStatus.EXPIRED}
    ),
    TransferStatus.PREFLIGHTING: frozenset(
        {TransferStatus.NEGOTIATING, TransferStatus.FAILED, TransferStatus.CANCELLED}
    ),
    TransferStatus.NEGOTIATING: frozenset(
        {TransferStatus.HANDSHAKING, TransferStatus.FAILED, TransferStatus.CANCELLED}
    ),
    TransferStatus.HANDSHAKING: frozenset(
        {TransferStatus.TRANSFERRING, TransferStatus.FAILED, TransferStatus.CANCELLED}
    ),
    TransferStatus.TRANSFERRING: frozenset(
        {
            TransferStatus.PAUSED,
            TransferStatus.VERIFYING,
            TransferStatus.FAILED,
            TransferStatus.CANCELLED,
        }
    ),
    TransferStatus.PAUSED: frozenset(
        {TransferStatus.HANDSHAKING, TransferStatus.FAILED, TransferStatus.CANCELLED}
    ),
    TransferStatus.VERIFYING: frozenset(
        {TransferStatus.FINALIZING, TransferStatus.QUARANTINED, TransferStatus.FAILED}
    ),
    TransferStatus.FINALIZING: frozenset(
        {TransferStatus.COMPLETED, TransferStatus.QUARANTINED, TransferStatus.FAILED}
    ),
    TransferStatus.COMPLETED: frozenset(),
    TransferStatus.CANCELLED: frozenset({TransferStatus.HANDSHAKING}),
    TransferStatus.EXPIRED: frozenset(),
    TransferStatus.FAILED: frozenset({TransferStatus.HANDSHAKING}),
    TransferStatus.QUARANTINED: frozenset(),
}


def transition_state(
    record: TransferStateRecord,
    target: TransferStatus,
    *,
    error_code: TransferErrorCode | None = None,
) -> TransferStateRecord:
    """Return a new record after enforcing the transfer state machine."""

    if target not in _ALLOWED_TRANSITIONS[record.status]:
        raise transfer_failure(
            TransferErrorCode.INTERNAL_ERROR,
            f"invalid transfer state transition {record.status.value} -> {target.value}",
        )
    if target in {TransferStatus.FAILED, TransferStatus.QUARANTINED} and error_code is None:
        raise ValueError("failed and quarantined states require an error code")
    if target not in {TransferStatus.FAILED, TransferStatus.QUARANTINED}:
        error_code = None
    return replace(
        record,
        status=target,
        error_code=error_code,
        updated_at=datetime.now(UTC),
    )


def default_transfer_home() -> Path:
    """Return the XDG-compatible Celatim product-state directory."""

    if configured := os.environ.get("CELATIM_HOME"):
        return Path(configured).expanduser()
    if xdg_data := os.environ.get("XDG_DATA_HOME"):
        return Path(xdg_data).expanduser() / "celatim"
    return Path.home() / ".local" / "share" / "celatim"


class TransferStateStore:
    """Owner-only, atomic persistence for transfer records and private spool files."""

    def __init__(self, home: Path | str | None = None) -> None:
        self.home = Path(home) if home is not None else default_transfer_home()
        self.transfers_dir = self.home / "transfers"
        self.offers_dir = self.home / "offers"
        self.spool_dir = self.home / "spool"
        self.identities_dir = self.home / "identities"
        self.lock_path = self.home / ".transfer.lock"

    def initialize(self) -> None:
        for path in (
            self.home,
            self.transfers_dir,
            self.offers_dir,
            self.spool_dir,
            self.identities_dir,
        ):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                path.chmod(0o700)
            except OSError as exc:
                raise transfer_failure(
                    TransferErrorCode.STORAGE_FAILED,
                    f"could not secure transfer state directory: {exc}",
                ) from exc

    def state_path(self, transfer_id: str, role: str) -> Path:
        _validate_component(transfer_id)
        if role not in {"sender", "receiver"}:
            raise ValueError("role must be sender or receiver")
        return self.transfers_dir / f"{transfer_id}.{role}.json"

    def write_state(self, record: TransferStateRecord) -> Path:
        self.initialize()
        path = self.state_path(record.transfer_id, record.role)
        with self.lock():
            atomic_write_json(path, record.to_json())
        return path

    def read_state(self, transfer_id: str, role: str) -> TransferStateRecord:
        path = self.state_path(transfer_id, role)
        try:
            raw = json.loads(path.read_text())
        except FileNotFoundError as exc:
            raise transfer_failure(
                TransferErrorCode.INPUT_INVALID,
                "no local state exists for the requested transfer",
            ) from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise transfer_failure(
                TransferErrorCode.STORAGE_FAILED,
                f"could not read transfer state: {exc}",
            ) from exc
        if not isinstance(raw, dict):
            raise transfer_failure(
                TransferErrorCode.STORAGE_FAILED,
                "transfer state document is not an object",
            )
        try:
            return TransferStateRecord.from_json(raw)
        except (TypeError, ValueError) as exc:
            raise transfer_failure(
                TransferErrorCode.STORAGE_FAILED,
                f"transfer state is invalid: {exc}",
            ) from exc

    def list_states(self, *, role: str | None = None) -> tuple[TransferStateRecord, ...]:
        self.initialize()
        states: list[TransferStateRecord] = []
        suffix = f".{role}.json" if role is not None else ".json"
        for path in sorted(self.transfers_dir.glob(f"*{suffix}")):
            try:
                raw = json.loads(path.read_text())
                if isinstance(raw, dict):
                    states.append(TransferStateRecord.from_json(raw))
            except OSError, ValueError, TypeError, json.JSONDecodeError:
                continue
        return tuple(states)

    def offer_path(self, offer_id: str) -> Path:
        _validate_component(offer_id)
        return self.offers_dir / f"{offer_id}.json"

    def write_offer(self, offer: dict[str, Any]) -> Path:
        self.initialize()
        offer_id = offer.get("offer_id")
        if not isinstance(offer_id, str):
            raise ValueError("offer must contain an offer_id")
        path = self.offer_path(offer_id)
        with self.lock():
            atomic_write_json(path, offer)
        return path

    @contextmanager
    def lock(self) -> Iterator[None]:
        self.initialize()
        descriptor = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            _flock(descriptor, exclusive=True)
            yield
        finally:
            _flock(descriptor, exclusive=False)
            os.close(descriptor)


def atomic_write_json(path: Path, document: dict[str, Any]) -> None:
    """Write owner-only JSON using fsync and same-directory atomic replacement."""

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    encoded = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _sync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _flock(descriptor: int, *, exclusive: bool) -> None:
    """Use advisory process locking where the platform provides fcntl."""

    try:
        import fcntl
    except ImportError:  # pragma: no cover - Windows uses the single-process fallback.
        return
    operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_UN
    fcntl.flock(descriptor, operation)


def _validate_component(value: str) -> None:
    if not value or value in {".", ".."} or "/" in value or "\\" in value or "\x00" in value:
        raise ValueError("unsafe state path component")


__all__ = [
    "TransferStateStore",
    "atomic_write_json",
    "default_transfer_home",
    "transition_state",
]
