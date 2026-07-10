"""Versioned domain models for secure file transfer."""

from __future__ import annotations

import base64
import json
import math
import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Self, cast
from uuid import UUID, uuid4

from .errors import TransferErrorCode, TransferFailure, transfer_failure

TRANSFER_OFFER_SCHEMA_VERSION = "celatim.transfer_offer.v1"
TRANSFER_MANIFEST_SCHEMA_VERSION = "celatim.transfer_manifest.v1"
TRANSFER_STATE_SCHEMA_VERSION = "celatim.transfer_state.v1"
TRANSFER_RECEIPT_SCHEMA_VERSION = "celatim.transfer_receipt.v1"
TRANSFER_EVENT_SCHEMA_VERSION = "celatim.transfer_event.v1"
PROVIDER_MANIFEST_SCHEMA_VERSION = "celatim.provider_manifest.v1"
TRANSFER_URI_PREFIX = "celatim://v1/"
DEFAULT_CHUNK_SIZE = 256 * 1024
MIN_CHUNK_SIZE = 4 * 1024
MAX_CHUNK_SIZE = 4 * 1024 * 1024
MAX_OFFER_BYTES = 16 * 1024
MAX_FILE_SIZE = 1 << 40
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
PROVIDER_NAME_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?")


class TransferStatus(str, Enum):
    """Persisted transfer lifecycle states."""

    CREATED = "created"
    PREFLIGHTING = "preflighting"
    NEGOTIATING = "negotiating"
    HANDSHAKING = "handshaking"
    TRANSFERRING = "transferring"
    PAUSED = "paused"
    VERIFYING = "verifying"
    FINALIZING = "finalizing"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    FAILED = "failed"
    QUARANTINED = "quarantined"


class TransferEventKind(str, Enum):
    """Stable event categories for terminal and application progress."""

    STATE = "state"
    PROGRESS = "progress"
    RETRY = "retry"
    WARNING = "warning"
    COMPLETED = "completed"
    FAILED = "failed"


class TransferTrustMode(str, Enum):
    """What the active transfer authenticated."""

    OFFER_BOUND = "offer_bound"
    VERIFIED_CONTACT = "verified_contact"


class ProviderDirectionality(str, Enum):
    DUPLEX = "duplex"
    SEND_ONLY = "send_only"
    RECEIVE_ONLY = "receive_only"


class ProviderEvidenceLevel(str, Enum):
    DIRECT_TLS_CONTROL = "direct_tls_control"
    SYNTHETIC_OUTER_FRAME = "synthetic_outer_frame"
    REAL_PDU = "real_pdu"
    PRODUCTION_DAEMON = "production_daemon"
    NATIVE_STACK = "native_stack"


@dataclass(frozen=True)
class ProviderManifest:
    """Machine-readable transfer-provider capabilities and requirements."""

    name: str
    version: str
    priority: int
    directionality: ProviderDirectionality
    feedback: bool
    max_record_size: int
    evidence_level: ProviderEvidenceLevel
    extras: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()
    privileges: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not PROVIDER_NAME_PATTERN.fullmatch(self.name):
            raise ValueError(f"invalid provider name: {self.name!r}")
        if not self.version or len(self.version) > 64:
            raise ValueError("provider version must contain 1-64 characters")
        if self.priority < 0:
            raise ValueError("provider priority must be >= 0")
        if self.max_record_size < MIN_CHUNK_SIZE:
            raise ValueError(f"provider max_record_size must be >= {MIN_CHUNK_SIZE}")

    @property
    def resumable(self) -> bool:
        return self.directionality is ProviderDirectionality.DUPLEX and self.feedback

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": PROVIDER_MANIFEST_SCHEMA_VERSION,
            "name": self.name,
            "version": self.version,
            "priority": self.priority,
            "directionality": self.directionality.value,
            "feedback": self.feedback,
            "resumable": self.resumable,
            "max_record_size": self.max_record_size,
            "evidence_level": self.evidence_level.value,
            "extras": list(self.extras),
            "tools": list(self.tools),
            "privileges": list(self.privileges),
            "platforms": list(self.platforms),
        }


@dataclass(frozen=True)
class TransferOffer:
    """Short-lived receiver capability shared with one sender."""

    offer_id: str
    host: str
    port: int
    expires_at: datetime
    tls_cert_sha256: str
    access_token: str
    providers: tuple[str, ...]
    max_file_size: int
    trust_mode: TransferTrustMode = TransferTrustMode.OFFER_BOUND
    receiver_label: str | None = None

    def __post_init__(self) -> None:
        _validate_uuid(self.offer_id, "offer_id")
        if not self.host or len(self.host) > 253 or any(char.isspace() for char in self.host):
            raise ValueError("offer host must contain 1-253 non-whitespace characters")
        if not 1 <= self.port <= 65535:
            raise ValueError("offer port must be between 1 and 65535")
        if self.expires_at.tzinfo is None:
            raise ValueError("offer expiry must be timezone-aware")
        if not SHA256_PATTERN.fullmatch(self.tls_cert_sha256):
            raise ValueError("offer TLS certificate fingerprint must be lowercase SHA-256")
        _validate_token(self.access_token)
        if not self.providers or len(self.providers) > 32:
            raise ValueError("offer must name between 1 and 32 providers")
        for provider in self.providers:
            if not PROVIDER_NAME_PATTERN.fullmatch(provider):
                raise ValueError(f"invalid offer provider: {provider!r}")
        if not 0 < self.max_file_size <= MAX_FILE_SIZE:
            raise ValueError(f"offer max_file_size must be between 1 and {MAX_FILE_SIZE}")
        if self.receiver_label is not None and not 0 < len(self.receiver_label) <= 128:
            raise ValueError("receiver_label must contain 1-128 characters")

    @classmethod
    def create(
        cls,
        *,
        host: str,
        port: int,
        tls_cert_sha256: str,
        providers: tuple[str, ...],
        max_file_size: int,
        expires_in_s: int = 900,
        receiver_label: str | None = None,
    ) -> Self:
        if not 1 <= expires_in_s <= 86400:
            raise ValueError("expires_in_s must be between 1 and 86400")
        return cls(
            offer_id=str(uuid4()),
            host=host,
            port=port,
            expires_at=datetime.now(UTC) + timedelta(seconds=expires_in_s),
            tls_cert_sha256=tls_cert_sha256,
            access_token=secrets.token_urlsafe(32),
            providers=providers,
            max_file_size=max_file_size,
            receiver_label=receiver_label,
        )

    @property
    def expired(self) -> bool:
        return datetime.now(UTC) >= self.expires_at

    def require_active(self) -> None:
        if self.expired:
            raise transfer_failure(
                TransferErrorCode.OFFER_EXPIRED,
                "the transfer offer has expired",
            )

    def to_json(self, *, redact_secret: bool = False) -> dict[str, Any]:
        return {
            "schema_version": TRANSFER_OFFER_SCHEMA_VERSION,
            "offer_id": self.offer_id,
            "host": self.host,
            "port": self.port,
            "expires_at": _format_datetime(self.expires_at),
            "tls_cert_sha256": self.tls_cert_sha256,
            "access_token": "[redacted]" if redact_secret else self.access_token,
            "providers": list(self.providers),
            "max_file_size": self.max_file_size,
            "trust_mode": self.trust_mode.value,
            "receiver_label": self.receiver_label,
        }

    def to_uri(self) -> str:
        raw = json.dumps(self.to_json(), sort_keys=True, separators=(",", ":")).encode()
        encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        return TRANSFER_URI_PREFIX + encoded

    @classmethod
    def parse(cls, value: str | bytes | dict[str, Any]) -> Self:
        try:
            document = _offer_document(value)
            _require_schema(document, TRANSFER_OFFER_SCHEMA_VERSION)
            return cls(
                offer_id=_require_str(document, "offer_id", maximum=64),
                host=_require_str(document, "host", maximum=253),
                port=_require_int(document, "port"),
                expires_at=_parse_datetime(_require_str(document, "expires_at", maximum=64)),
                tls_cert_sha256=_require_str(document, "tls_cert_sha256", maximum=64),
                access_token=_require_str(document, "access_token", maximum=128),
                providers=tuple(_require_str_list(document, "providers", maximum=32)),
                max_file_size=_require_int(document, "max_file_size"),
                trust_mode=TransferTrustMode(_require_str(document, "trust_mode", maximum=32)),
                receiver_label=_optional_str(document, "receiver_label", maximum=128),
            )
        except TransferFailure:
            raise
        except Exception as exc:
            raise transfer_failure(
                TransferErrorCode.OFFER_INVALID,
                f"could not parse transfer offer: {exc}",
            ) from exc


@dataclass(frozen=True)
class TransferManifest:
    """Immutable file commitment used by transfer and resume."""

    transfer_id: str
    offer_id: str
    file_name: str
    file_size: int
    file_sha256: str
    chunk_size: int
    chunk_count: int
    provider: str
    created_at: datetime

    def __post_init__(self) -> None:
        _validate_uuid(self.transfer_id, "transfer_id")
        _validate_uuid(self.offer_id, "offer_id")
        if not self.file_name or len(self.file_name.encode()) > 255:
            raise ValueError("file_name must contain 1-255 encoded bytes")
        if not 0 <= self.file_size <= MAX_FILE_SIZE:
            raise ValueError(f"file_size must be between 0 and {MAX_FILE_SIZE}")
        if not SHA256_PATTERN.fullmatch(self.file_sha256):
            raise ValueError("file_sha256 must be lowercase SHA-256")
        if not MIN_CHUNK_SIZE <= self.chunk_size <= MAX_CHUNK_SIZE:
            raise ValueError(f"chunk_size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE}")
        expected_chunks = math.ceil(self.file_size / self.chunk_size) if self.file_size else 0
        if self.chunk_count != expected_chunks:
            raise ValueError("chunk_count does not match file_size and chunk_size")
        if not PROVIDER_NAME_PATTERN.fullmatch(self.provider):
            raise ValueError(f"invalid manifest provider: {self.provider!r}")
        if self.created_at.tzinfo is None:
            raise ValueError("manifest creation time must be timezone-aware")

    @classmethod
    def from_path(
        cls,
        path: Path,
        *,
        offer_id: str,
        provider: str,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        transfer_id: str | None = None,
    ) -> Self:
        from .source import StableSourceFile

        with StableSourceFile.open(path) as source:
            return cast(
                Self,
                source.create_manifest(
                    transfer_id=transfer_id,
                    offer_id=offer_id,
                    provider=provider,
                    chunk_size=chunk_size,
                ),
            )

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": TRANSFER_MANIFEST_SCHEMA_VERSION,
            "transfer_id": self.transfer_id,
            "offer_id": self.offer_id,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "file_sha256": self.file_sha256,
            "chunk_size": self.chunk_size,
            "chunk_count": self.chunk_count,
            "provider": self.provider,
            "created_at": _format_datetime(self.created_at),
        }

    @classmethod
    def from_json(cls, document: dict[str, Any]) -> Self:
        _require_schema(document, TRANSFER_MANIFEST_SCHEMA_VERSION)
        return cls(
            transfer_id=_require_str(document, "transfer_id", maximum=64),
            offer_id=_require_str(document, "offer_id", maximum=64),
            file_name=_require_str(document, "file_name", maximum=255),
            file_size=_require_int(document, "file_size"),
            file_sha256=_require_str(document, "file_sha256", maximum=64),
            chunk_size=_require_int(document, "chunk_size"),
            chunk_count=_require_int(document, "chunk_count"),
            provider=_require_str(document, "provider", maximum=64),
            created_at=_parse_datetime(_require_str(document, "created_at", maximum=64)),
        )


@dataclass(frozen=True)
class TransferEvent:
    schema_version: str
    sequence: int
    transfer_id: str
    kind: TransferEventKind
    status: TransferStatus
    timestamp: datetime
    provider: str | None = None
    bytes_transferred: int = 0
    total_bytes: int | None = None
    chunk_index: int | None = None
    retry_count: int = 0
    message: str | None = None
    error_code: TransferErrorCode | None = None

    def __post_init__(self) -> None:
        if self.schema_version != TRANSFER_EVENT_SCHEMA_VERSION:
            raise ValueError("unsupported transfer event schema")
        if self.sequence < 0 or self.bytes_transferred < 0 or self.retry_count < 0:
            raise ValueError("event counters must be >= 0")
        if self.total_bytes is not None and self.total_bytes < 0:
            raise ValueError("event total_bytes must be >= 0")

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "transfer_id": self.transfer_id,
            "kind": self.kind.value,
            "status": self.status.value,
            "timestamp": _format_datetime(self.timestamp),
            "provider": self.provider,
            "bytes_transferred": self.bytes_transferred,
            "total_bytes": self.total_bytes,
            "chunk_index": self.chunk_index,
            "retry_count": self.retry_count,
            "message": self.message,
            "error_code": None if self.error_code is None else self.error_code.value,
        }


@dataclass(frozen=True)
class TransferReceipt:
    transfer_id: str
    role: str
    status: TransferStatus
    provider: str
    trust_mode: TransferTrustMode
    authenticated: bool
    verified: bool
    acknowledged: bool
    file_name: str
    file_size: int
    file_sha256: str
    started_at: datetime
    completed_at: datetime
    path: str | None = None

    def to_json(self, *, include_path: bool = True) -> dict[str, Any]:
        return {
            "schema_version": TRANSFER_RECEIPT_SCHEMA_VERSION,
            "transfer_id": self.transfer_id,
            "role": self.role,
            "status": self.status.value,
            "provider": self.provider,
            "trust_mode": self.trust_mode.value,
            "authenticated": self.authenticated,
            "verified": self.verified,
            "acknowledged": self.acknowledged,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "file_sha256": self.file_sha256,
            "started_at": _format_datetime(self.started_at),
            "completed_at": _format_datetime(self.completed_at),
            "path": self.path if include_path else None,
        }


@dataclass(frozen=True)
class TransferStateRecord:
    transfer_id: str
    role: str
    status: TransferStatus
    manifest: TransferManifest
    acknowledged_chunks: tuple[int, ...]
    source_path: str | None
    spool_path: str | None
    destination_path: str | None
    offer: dict[str, Any]
    created_at: datetime
    updated_at: datetime
    provider_state: dict[str, Any] = field(default_factory=dict)
    error_code: TransferErrorCode | None = None

    def __post_init__(self) -> None:
        if self.transfer_id != self.manifest.transfer_id:
            raise ValueError("state transfer_id does not match manifest")
        if self.role not in {"sender", "receiver"}:
            raise ValueError("state role must be sender or receiver")
        if tuple(sorted(set(self.acknowledged_chunks))) != self.acknowledged_chunks:
            raise ValueError("acknowledged_chunks must be sorted and unique")
        if any(
            index < 0 or index >= self.manifest.chunk_count for index in self.acknowledged_chunks
        ):
            raise ValueError("acknowledged chunk is outside the manifest")

    def to_json(self, *, redact_private: bool = False) -> dict[str, Any]:
        offer = dict(self.offer)
        if redact_private and "access_token" in offer:
            offer["access_token"] = "[redacted]"
        return {
            "schema_version": TRANSFER_STATE_SCHEMA_VERSION,
            "transfer_id": self.transfer_id,
            "role": self.role,
            "status": self.status.value,
            "manifest": self.manifest.to_json(),
            "acknowledged_chunks": list(self.acknowledged_chunks),
            "source_path": None if redact_private else self.source_path,
            "spool_path": None if redact_private else self.spool_path,
            "destination_path": None if redact_private else self.destination_path,
            "offer": offer,
            "provider_state": (
                dict.fromkeys(self.provider_state, "[redacted]")
                if redact_private
                else dict(self.provider_state)
            ),
            "created_at": _format_datetime(self.created_at),
            "updated_at": _format_datetime(self.updated_at),
            "error_code": None if self.error_code is None else self.error_code.value,
        }

    @classmethod
    def from_json(cls, document: dict[str, Any]) -> Self:
        _require_schema(document, TRANSFER_STATE_SCHEMA_VERSION)
        manifest_raw = document.get("manifest")
        offer_raw = document.get("offer")
        provider_state_raw = document.get("provider_state", {})
        chunks_raw = document.get("acknowledged_chunks")
        if not isinstance(manifest_raw, dict) or not isinstance(offer_raw, dict):
            raise ValueError("state manifest and offer must be objects")
        if not isinstance(provider_state_raw, dict):
            raise ValueError("state provider_state must be an object")
        if not isinstance(chunks_raw, list) or not all(
            isinstance(item, int) and not isinstance(item, bool) for item in chunks_raw
        ):
            raise ValueError("state acknowledged_chunks must be an integer array")
        error_raw = document.get("error_code")
        return cls(
            transfer_id=_require_str(document, "transfer_id", maximum=64),
            role=_require_str(document, "role", maximum=16),
            status=TransferStatus(_require_str(document, "status", maximum=32)),
            manifest=TransferManifest.from_json(manifest_raw),
            acknowledged_chunks=tuple(chunks_raw),
            source_path=_optional_str(document, "source_path", maximum=4096),
            spool_path=_optional_str(document, "spool_path", maximum=4096),
            destination_path=_optional_str(document, "destination_path", maximum=4096),
            offer=dict(offer_raw),
            created_at=_parse_datetime(_require_str(document, "created_at", maximum=64)),
            updated_at=_parse_datetime(_require_str(document, "updated_at", maximum=64)),
            provider_state=dict(provider_state_raw),
            error_code=None if error_raw is None else TransferErrorCode(str(error_raw)),
        )


def _offer_document(value: str | bytes | dict[str, Any]) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    raw = value.encode() if isinstance(value, str) else value
    if len(raw) > MAX_OFFER_BYTES * 2:
        raise ValueError("offer encoding exceeds the size limit")
    if raw.startswith(TRANSFER_URI_PREFIX.encode()):
        encoded = raw[len(TRANSFER_URI_PREFIX) :]
        padding = b"=" * (-len(encoded) % 4)
        raw = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
    if len(raw) > MAX_OFFER_BYTES:
        raise ValueError("decoded offer exceeds the size limit")
    document = json.loads(raw)
    if not isinstance(document, dict):
        raise ValueError("offer must be a JSON object")
    return document


def _validate_uuid(value: str, field_name: str) -> None:
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a UUID") from exc
    if str(parsed) != value:
        raise ValueError(f"{field_name} must use canonical UUID text")


def _validate_token(value: str) -> None:
    if not 32 <= len(value) <= 128 or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("offer access token is invalid")


def _format_datetime(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(UTC)


def _require_schema(document: dict[str, Any], expected: str) -> None:
    if document.get("schema_version") != expected:
        raise ValueError(f"unsupported schema version; expected {expected}")


def _require_str(document: dict[str, Any], key: str, *, maximum: int) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{key} must contain 1-{maximum} characters")
    return value


def _optional_str(document: dict[str, Any], key: str, *, maximum: int) -> str | None:
    value = document.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{key} must be null or contain 1-{maximum} characters")
    return value


def _require_int(document: dict[str, Any], key: str) -> int:
    value = document.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{key} must be an integer")
    return value


def _require_str_list(document: dict[str, Any], key: str, *, maximum: int) -> list[str]:
    value = document.get(key)
    if not isinstance(value, list) or not 1 <= len(value) <= maximum:
        raise ValueError(f"{key} must contain 1-{maximum} strings")
    if not all(isinstance(item, str) for item in value):
        raise ValueError(f"{key} must contain only strings")
    return value


__all__ = [
    "DEFAULT_CHUNK_SIZE",
    "MAX_CHUNK_SIZE",
    "MAX_FILE_SIZE",
    "MIN_CHUNK_SIZE",
    "PROVIDER_MANIFEST_SCHEMA_VERSION",
    "TRANSFER_EVENT_SCHEMA_VERSION",
    "TRANSFER_MANIFEST_SCHEMA_VERSION",
    "TRANSFER_OFFER_SCHEMA_VERSION",
    "TRANSFER_RECEIPT_SCHEMA_VERSION",
    "TRANSFER_STATE_SCHEMA_VERSION",
    "TRANSFER_URI_PREFIX",
    "ProviderDirectionality",
    "ProviderEvidenceLevel",
    "ProviderManifest",
    "TransferEvent",
    "TransferEventKind",
    "TransferManifest",
    "TransferOffer",
    "TransferReceipt",
    "TransferStateRecord",
    "TransferStatus",
    "TransferTrustMode",
]
