"""Reusable conformance checks for built-in and entry-point transfer providers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from .models import DEFAULT_CHUNK_SIZE, TransferEvent, TransferOffer, TransferStatus
from .providers import ProviderSendRequest, TransferProvider

PROVIDER_CONFORMANCE_SCHEMA_VERSION = "celatim.provider_conformance.v1"


@dataclass(frozen=True)
class ProviderConformanceResult:
    provider: str
    checks: tuple[str, ...]
    event_count: int
    ok: bool

    def to_json(self) -> dict[str, object]:
        return {
            "schema_version": PROVIDER_CONFORMANCE_SCHEMA_VERSION,
            "provider": self.provider,
            "checks": list(self.checks),
            "event_count": self.event_count,
            "ok": self.ok,
        }


async def run_provider_conformance(
    provider: TransferProvider,
    *,
    source: Path,
    offer: TransferOffer,
    home: Path,
    timeout_s: float = 10.0,
) -> ProviderConformanceResult:
    """Exercise only the public provider contract and return stable check names."""

    checks: list[str] = []
    events: list[TransferEvent] = []
    manifest = provider.manifest
    if manifest.name not in offer.providers:
        raise AssertionError("fixture offer must include the provider under test")
    checks.append("manifest_offered")
    if not manifest.resumable:
        raise AssertionError("product provider must expose duplex feedback and resume")
    checks.append("duplex_feedback")
    preflight = provider.preflight(source, offer)
    if not preflight.eligible:
        raise AssertionError(f"provider preflight failed: {preflight.failure}")
    checks.append("preflight_eligible")

    async def emit(event: TransferEvent) -> None:
        events.append(event)

    receipt = await provider.send(
        ProviderSendRequest(
            source=source,
            offer=offer,
            transfer_id=str(uuid4()),
            home=home,
            chunk_size=DEFAULT_CHUNK_SIZE,
            timeout_s=timeout_s,
            emit=emit,
        )
    )
    if receipt.status is not TransferStatus.COMPLETED:
        raise AssertionError("provider receipt is not complete")
    checks.append("completed_receipt")
    if not receipt.authenticated or not receipt.verified or not receipt.acknowledged:
        raise AssertionError(
            "provider receipt lacks authentication, verification, or acknowledgement"
        )
    checks.append("verified_acknowledgement")
    if receipt.provider != manifest.name:
        raise AssertionError("provider receipt names a different provider")
    checks.append("provider_identity")
    return ProviderConformanceResult(
        provider=manifest.name,
        checks=tuple(checks),
        event_count=len(events),
        ok=True,
    )


__all__ = [
    "PROVIDER_CONFORMANCE_SCHEMA_VERSION",
    "ProviderConformanceResult",
    "run_provider_conformance",
]
