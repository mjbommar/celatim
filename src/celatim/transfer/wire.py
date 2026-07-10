"""Bounded binary framing for the TLS transfer protocol."""

from __future__ import annotations

import asyncio
import json
from enum import IntEnum
from struct import Struct
from typing import Any

from .errors import TransferErrorCode, transfer_failure

TRANSFER_PROTOCOL_VERSION = "celatim.transfer_protocol.v1"
MAX_CONTROL_BYTES = 64 * 1024
MAX_DATA_BYTES = 4 * 1024 * 1024 + 40
_FRAME_HEADER = Struct("!BI")
_CHUNK_HEADER = Struct("!Q32s")


class FrameKind(IntEnum):
    CONTROL = 1
    DATA = 2


async def write_control(writer: asyncio.StreamWriter, document: dict[str, Any]) -> None:
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    if len(payload) > MAX_CONTROL_BYTES:
        raise transfer_failure(
            TransferErrorCode.COMPATIBILITY_FAILED,
            "transfer control record exceeds the size limit",
        )
    await _write_frame(writer, FrameKind.CONTROL, payload)


async def read_control(reader: asyncio.StreamReader) -> dict[str, Any]:
    kind, payload = await _read_frame(reader)
    if kind is not FrameKind.CONTROL:
        raise transfer_failure(
            TransferErrorCode.COMPATIBILITY_FAILED,
            "expected a transfer control record",
        )
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise transfer_failure(
            TransferErrorCode.COMPATIBILITY_FAILED,
            "transfer control record is not valid JSON",
        ) from exc
    if not isinstance(document, dict):
        raise transfer_failure(
            TransferErrorCode.COMPATIBILITY_FAILED,
            "transfer control record must be an object",
        )
    return document


async def write_chunk(
    writer: asyncio.StreamWriter,
    index: int,
    digest: bytes,
    data: bytes,
) -> None:
    if len(digest) != 32:
        raise ValueError("chunk digest must contain 32 bytes")
    payload = _CHUNK_HEADER.pack(index, digest) + data
    if len(payload) > MAX_DATA_BYTES:
        raise transfer_failure(
            TransferErrorCode.COMPATIBILITY_FAILED,
            "transfer chunk exceeds the size limit",
        )
    await _write_frame(writer, FrameKind.DATA, payload)


async def read_chunk(reader: asyncio.StreamReader) -> tuple[int, bytes, bytes]:
    kind, payload = await _read_frame(reader)
    if kind is not FrameKind.DATA or len(payload) < _CHUNK_HEADER.size:
        raise transfer_failure(
            TransferErrorCode.COMPATIBILITY_FAILED,
            "expected a valid transfer chunk record",
        )
    index, digest = _CHUNK_HEADER.unpack(payload[: _CHUNK_HEADER.size])
    return index, digest, payload[_CHUNK_HEADER.size :]


async def _write_frame(
    writer: asyncio.StreamWriter,
    kind: FrameKind,
    payload: bytes,
) -> None:
    writer.write(_FRAME_HEADER.pack(kind, len(payload)))
    writer.write(payload)
    await writer.drain()


async def _read_frame(reader: asyncio.StreamReader) -> tuple[FrameKind, bytes]:
    try:
        header = await reader.readexactly(_FRAME_HEADER.size)
        raw_kind, length = _FRAME_HEADER.unpack(header)
        kind = FrameKind(raw_kind)
        maximum = MAX_CONTROL_BYTES if kind is FrameKind.CONTROL else MAX_DATA_BYTES
        if length > maximum:
            raise transfer_failure(
                TransferErrorCode.COMPATIBILITY_FAILED,
                "incoming transfer record exceeds the size limit",
            )
        return kind, await reader.readexactly(length)
    except asyncio.IncompleteReadError as exc:
        raise transfer_failure(
            TransferErrorCode.NETWORK_FAILED,
            "transfer connection closed before a complete record arrived",
            retryable=True,
            resumable=True,
        ) from exc
    except ValueError as exc:
        raise transfer_failure(
            TransferErrorCode.COMPATIBILITY_FAILED,
            "incoming transfer record has an unknown frame kind",
        ) from exc


__all__ = [
    "MAX_CONTROL_BYTES",
    "MAX_DATA_BYTES",
    "TRANSFER_PROTOCOL_VERSION",
    "FrameKind",
    "read_chunk",
    "read_control",
    "write_chunk",
    "write_control",
]
