"""Typed file-transfer failures and stable operator guidance."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from celatim.errors import CelatimError

TRANSFER_ERROR_SCHEMA_VERSION = "celatim.transfer_error.v1"


class TransferErrorCode(str, Enum):
    """Stable failure families exposed by the transfer CLI and SDK."""

    INPUT_INVALID = "input_invalid"
    OFFER_INVALID = "offer_invalid"
    OFFER_EXPIRED = "offer_expired"
    OFFER_REPLAYED = "offer_replayed"
    TRUST_FAILED = "trust_failed"
    POLICY_BLOCKED = "policy_blocked"
    CRYPTO_UNAVAILABLE = "crypto_unavailable"
    CRYPTO_FAILED = "crypto_failed"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    PROVIDER_INCOMPATIBLE = "provider_incompatible"
    PRIVILEGE_REQUIRED = "privilege_required"
    NETWORK_FAILED = "network_failed"
    TIMEOUT = "timeout"
    INTEGRITY_FAILED = "integrity_failed"
    STORAGE_FAILED = "storage_failed"
    COMPATIBILITY_FAILED = "compatibility_failed"
    CANCELLED = "cancelled"
    INTERNAL_ERROR = "internal_error"


_DEFAULT_ACTIONS: dict[TransferErrorCode, str] = {
    TransferErrorCode.INPUT_INVALID: "check the file path and command arguments",
    TransferErrorCode.OFFER_INVALID: "request a new transfer offer from the receiver",
    TransferErrorCode.OFFER_EXPIRED: "request a new transfer offer from the receiver",
    TransferErrorCode.OFFER_REPLAYED: "resume the existing transfer or request a new offer",
    TransferErrorCode.TRUST_FAILED: "verify the offer through the intended out-of-band channel",
    TransferErrorCode.POLICY_BLOCKED: "review the local and receiver transfer policies",
    TransferErrorCode.CRYPTO_UNAVAILABLE: "install the celatim transfer extra",
    TransferErrorCode.CRYPTO_FAILED: "discard the offer and retry with a new receiver offer",
    TransferErrorCode.PROVIDER_UNAVAILABLE: "install or enable a compatible transfer provider",
    TransferErrorCode.PROVIDER_INCOMPATIBLE: "request an offer with a mutually supported provider",
    TransferErrorCode.PRIVILEGE_REQUIRED: "configure the packet service or select another provider",
    TransferErrorCode.NETWORK_FAILED: "check reachability and retry or resume the transfer",
    TransferErrorCode.TIMEOUT: "check receiver status and retry or resume the transfer",
    TransferErrorCode.INTEGRITY_FAILED: "discard partial output and retry with a new offer",
    TransferErrorCode.STORAGE_FAILED: "check destination space and permissions before resuming",
    TransferErrorCode.COMPATIBILITY_FAILED: "upgrade both peers to compatible Celatim versions",
    TransferErrorCode.CANCELLED: "resume the transfer when ready",
    TransferErrorCode.INTERNAL_ERROR: "collect redacted diagnostics and report the failure",
}


@dataclass
class TransferFailure(CelatimError):
    """A safe, structured transfer failure suitable for public API handling."""

    code: TransferErrorCode
    detail: str
    retryable: bool = False
    resumable: bool = False
    next_action: str | None = None

    def __str__(self) -> str:
        return f"{self.code.value}: {self.detail}"

    def to_json(self) -> dict[str, str | bool]:
        return {
            "schema_version": TRANSFER_ERROR_SCHEMA_VERSION,
            "code": self.code.value,
            "detail": self.detail,
            "retryable": self.retryable,
            "resumable": self.resumable,
            "next_action": self.next_action or _DEFAULT_ACTIONS[self.code],
        }


def transfer_failure(
    code: TransferErrorCode,
    detail: str,
    *,
    retryable: bool = False,
    resumable: bool = False,
    next_action: str | None = None,
) -> TransferFailure:
    """Build a typed failure while keeping default guidance in one place."""

    return TransferFailure(
        code=code,
        detail=detail,
        retryable=retryable,
        resumable=resumable,
        next_action=next_action,
    )


__all__ = [
    "TRANSFER_ERROR_SCHEMA_VERSION",
    "TransferErrorCode",
    "TransferFailure",
    "transfer_failure",
]
