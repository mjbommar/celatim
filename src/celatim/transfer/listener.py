"""Safe local lifecycle state for a foreground transfer-listener process."""

from __future__ import annotations

import json
import os
import signal
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .errors import TransferErrorCode, transfer_failure
from .state import TransferStateStore, atomic_write_json

LISTENER_STATUS_SCHEMA_VERSION = "celatim.transfer_listener_status.v1"


@dataclass(frozen=True)
class ListenerStatus:
    pid: int
    process_start: str | None
    host: str
    port: int
    output_dir: str
    started_at: str
    active: bool

    def to_json(self, *, redact_private: bool = False) -> dict[str, Any]:
        return {
            "schema_version": LISTENER_STATUS_SCHEMA_VERSION,
            "pid": self.pid,
            "process_start": self.process_start,
            "host": self.host,
            "port": self.port,
            "output_dir": None if redact_private else self.output_dir,
            "started_at": self.started_at,
            "active": self.active,
        }


def listener_state_path(store: TransferStateStore) -> Path:
    return store.home / "service" / "listener.json"


def write_listener_status(
    store: TransferStateStore,
    *,
    host: str,
    port: int,
    output_dir: Path,
) -> ListenerStatus:
    status = ListenerStatus(
        pid=os.getpid(),
        process_start=_process_start(os.getpid()),
        host=host,
        port=port,
        output_dir=str(output_dir.resolve()),
        started_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        active=True,
    )
    atomic_write_json(listener_state_path(store), status.to_json())
    return status


def load_listener_status(store: TransferStateStore) -> ListenerStatus | None:
    path = listener_state_path(store)
    try:
        document = json.loads(path.read_text())
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise transfer_failure(
            TransferErrorCode.STORAGE_FAILED,
            f"could not read listener state: {exc}",
        ) from exc
    if not isinstance(document, dict) or document.get("schema_version") != (
        LISTENER_STATUS_SCHEMA_VERSION
    ):
        raise transfer_failure(
            TransferErrorCode.STORAGE_FAILED,
            "listener state has an unsupported schema",
        )
    try:
        pid = int(document["pid"])
        process_start_raw = document.get("process_start")
        status = ListenerStatus(
            pid=pid,
            process_start=str(process_start_raw) if process_start_raw is not None else None,
            host=str(document["host"]),
            port=int(document["port"]),
            output_dir=str(document["output_dir"]),
            started_at=str(document["started_at"]),
            active=_process_matches(pid, process_start_raw),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise transfer_failure(
            TransferErrorCode.STORAGE_FAILED,
            f"listener state is invalid: {exc}",
        ) from exc
    return status


def clear_listener_status(store: TransferStateStore, *, pid: int | None = None) -> None:
    path = listener_state_path(store)
    if pid is not None:
        current = load_listener_status(store)
        if current is not None and current.pid != pid:
            return
    path.unlink(missing_ok=True)


def stop_listener(store: TransferStateStore) -> ListenerStatus:
    status = load_listener_status(store)
    if status is None:
        raise transfer_failure(
            TransferErrorCode.INPUT_INVALID,
            "no CLI transfer listener is registered",
        )
    if not status.active:
        clear_listener_status(store)
        raise transfer_failure(
            TransferErrorCode.INPUT_INVALID,
            "registered transfer listener is no longer running",
        )
    if not _command_is_listener(status.pid):
        raise transfer_failure(
            TransferErrorCode.POLICY_BLOCKED,
            "registered process does not match a Celatim transfer listener",
        )
    try:
        os.kill(status.pid, signal.SIGTERM)
    except OSError as exc:
        raise transfer_failure(
            TransferErrorCode.INTERNAL_ERROR,
            f"could not stop the transfer listener: {exc}",
        ) from exc
    clear_listener_status(store, pid=status.pid)
    return status


def _process_matches(pid: int, expected_start: object) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    actual_start = _process_start(pid)
    return expected_start is None or actual_start == str(expected_start)


def _process_start(pid: int) -> str | None:
    try:
        fields = (Path("/proc") / str(pid) / "stat").read_text().split()
        return fields[21]
    except OSError, IndexError:
        return None


def _command_is_listener(pid: int) -> bool:
    try:
        parts = (Path("/proc") / str(pid) / "cmdline").read_bytes().split(b"\0")
    except OSError:
        return True
    return b"transfer" in parts and b"listen" in parts


__all__ = [
    "LISTENER_STATUS_SCHEMA_VERSION",
    "ListenerStatus",
    "clear_listener_status",
    "listener_state_path",
    "load_listener_status",
    "stop_listener",
    "write_listener_status",
]
