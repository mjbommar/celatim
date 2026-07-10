"""External transfer provider implemented only against Celatim's public contract."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from celatim.transfer import (
    ProviderDirectionality,
    ProviderEvidenceLevel,
    ProviderManifest,
    ProviderPreflight,
    ProviderSendRequest,
    TransferManifest,
    TransferOffer,
    TransferReceipt,
    TransferStatus,
    basic_preflight,
)


class FixtureProvider:
    @property
    def manifest(self) -> ProviderManifest:
        return ProviderManifest(
            name="fixture-entry",
            version="1",
            priority=1,
            directionality=ProviderDirectionality.DUPLEX,
            feedback=True,
            max_record_size=262144,
            evidence_level=ProviderEvidenceLevel.DIRECT_TLS_CONTROL,
        )

    def preflight(self, source: Path, offer: TransferOffer) -> ProviderPreflight:
        return basic_preflight(self.manifest, source, offer)

    async def send(self, request: ProviderSendRequest) -> TransferReceipt:
        started = datetime.now(UTC)
        manifest = TransferManifest.from_path(
            request.source,
            offer_id=request.offer.offer_id,
            provider=self.manifest.name,
            transfer_id=request.transfer_id,
            chunk_size=request.chunk_size,
        )
        return TransferReceipt(
            transfer_id=request.transfer_id,
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
            started_at=started,
            completed_at=datetime.now(UTC),
        )


__all__ = ["FixtureProvider"]
