"""Versioned file-transfer contracts, provider selection, and local state."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest

from celatim.inspection import get_schema_text, list_schemas
from celatim.transfer import (
    DEFAULT_CHUNK_SIZE,
    PROVIDER_MANIFEST_SCHEMA_VERSION,
    TRANSFER_EVENT_SCHEMA_VERSION,
    TRANSFER_MANIFEST_SCHEMA_VERSION,
    TRANSFER_OFFER_SCHEMA_VERSION,
    ProviderDirectionality,
    ProviderEvidenceLevel,
    ProviderManifest,
    ProviderPreflight,
    ProviderRegistry,
    ProviderSendRequest,
    TransferClient,
    TransferErrorCode,
    TransferEvent,
    TransferEventKind,
    TransferFailure,
    TransferManifest,
    TransferOffer,
    TransferProvider,
    TransferReceipt,
    TransferStateRecord,
    TransferStateStore,
    TransferStatus,
    basic_preflight,
    transition_state,
)

PROJECT = Path(__file__).resolve().parents[1]
TRANSFER_SCHEMAS = {
    "carrier-endpoint-v1": "celatim.carrier_endpoint.v1",
    "packet-service-v1": "celatim.packet_service.v1",
    "packet-service-preflight-v1": "celatim.packet_service_preflight.v1",
    "provider-conformance-v1": "celatim.provider_conformance.v1",
    "provider-inventory-v1": "celatim.provider_inventory.v1",
    "provider-manifest-v1": PROVIDER_MANIFEST_SCHEMA_VERSION,
    "transfer-error-v1": "celatim.transfer_error.v1",
    "transfer-event-v1": TRANSFER_EVENT_SCHEMA_VERSION,
    "transfer-manifest-v1": TRANSFER_MANIFEST_SCHEMA_VERSION,
    "transfer-listener-status-v1": "celatim.transfer_listener_status.v1",
    "transfer-listener-stop-v1": "celatim.transfer_listener_stop.v1",
    "transfer-offer-v1": TRANSFER_OFFER_SCHEMA_VERSION,
    "transfer-receipt-v1": "celatim.transfer_receipt.v1",
    "transfer-state-v1": "celatim.transfer_state.v1",
    "transfer-status-v1": "celatim.transfer_status.v1",
}


class FixtureProvider:
    def __init__(self, name: str = "fixture", priority: int = 10) -> None:
        self._manifest = ProviderManifest(
            name=name,
            version="1",
            priority=priority,
            directionality=ProviderDirectionality.DUPLEX,
            feedback=True,
            max_record_size=DEFAULT_CHUNK_SIZE,
            evidence_level=ProviderEvidenceLevel.DIRECT_TLS_CONTROL,
        )

    @property
    def manifest(self) -> ProviderManifest:
        return self._manifest

    def preflight(self, source: Path, offer: TransferOffer) -> ProviderPreflight:
        return basic_preflight(self.manifest, source, offer)

    async def send(self, request: ProviderSendRequest) -> TransferReceipt:
        raise NotImplementedError


def _offer(*, providers: tuple[str, ...] = ("fixture",)) -> TransferOffer:
    return TransferOffer.create(
        host="127.0.0.1",
        port=8443,
        tls_cert_sha256="a" * 64,
        providers=providers,
        max_file_size=1024 * 1024,
    )


def _record(tmp_path: Path) -> TransferStateRecord:
    source = tmp_path / "source.bin"
    source.write_bytes(b"contract fixture")
    offer = _offer()
    manifest = TransferManifest.from_path(
        source,
        offer_id=offer.offer_id,
        provider="fixture",
    )
    now = datetime.now(UTC)
    return TransferStateRecord(
        transfer_id=manifest.transfer_id,
        role="sender",
        status=TransferStatus.CREATED,
        manifest=manifest,
        acknowledged_chunks=(),
        source_path=str(source),
        spool_path=None,
        destination_path=None,
        offer=offer.to_json(),
        created_at=now,
        updated_at=now,
    )


def test_transfer_offer_roundtrips_uri_and_redacts_secret():
    offer = _offer(providers=("fixture", "second"))

    parsed = TransferOffer.parse(offer.to_uri())

    assert parsed == offer
    assert parsed.to_json(redact_secret=True)["access_token"] == "[redacted]"
    assert offer.access_token not in json.dumps(parsed.to_json(redact_secret=True))


def test_transfer_offer_rejects_expired_and_modified_documents():
    offer = _offer()
    expired = replace(offer, expires_at=datetime.now(UTC) - timedelta(seconds=1))

    with pytest.raises(TransferFailure) as expired_error:
        expired.require_active()
    assert expired_error.value.code is TransferErrorCode.OFFER_EXPIRED

    document = offer.to_json()
    document["schema_version"] = "celatim.transfer_offer.v999"
    with pytest.raises(TransferFailure) as invalid_error:
        TransferOffer.parse(document)
    assert invalid_error.value.code is TransferErrorCode.OFFER_INVALID


def test_transfer_manifest_streams_binary_file_and_checks_chunk_count(tmp_path):
    source = tmp_path / "binary.dat"
    payload = b"\x00\xff" * (DEFAULT_CHUNK_SIZE // 2 + 3)
    source.write_bytes(payload)
    offer = _offer()

    manifest = TransferManifest.from_path(
        source,
        offer_id=offer.offer_id,
        provider="fixture",
    )

    assert manifest.file_size == len(payload)
    assert manifest.file_sha256 == hashlib.sha256(payload).hexdigest()
    assert manifest.chunk_count == 2
    assert TransferManifest.from_json(manifest.to_json()) == manifest


def test_transfer_state_machine_enforces_transitions_and_error_codes(tmp_path):
    record = _record(tmp_path)
    record = transition_state(record, TransferStatus.PREFLIGHTING)
    record = transition_state(record, TransferStatus.NEGOTIATING)
    record = transition_state(record, TransferStatus.HANDSHAKING)
    record = transition_state(record, TransferStatus.TRANSFERRING)
    record = transition_state(record, TransferStatus.VERIFYING)
    record = transition_state(record, TransferStatus.FINALIZING)
    record = transition_state(record, TransferStatus.COMPLETED)

    assert record.status is TransferStatus.COMPLETED
    with pytest.raises(TransferFailure, match="invalid transfer state transition"):
        transition_state(record, TransferStatus.TRANSFERRING)

    failed = transition_state(_record(tmp_path), TransferStatus.PREFLIGHTING)
    with pytest.raises(ValueError, match="require an error code"):
        transition_state(failed, TransferStatus.FAILED)


def test_transfer_state_store_is_atomic_owner_only_and_roundtrips(tmp_path):
    store = TransferStateStore(tmp_path / "home")
    record = _record(tmp_path)

    state_path = store.write_state(record)
    recovered = store.read_state(record.transfer_id, "sender")

    assert recovered == record
    assert store.list_states(role="sender") == (record,)
    if os.name == "posix":
        assert state_path.stat().st_mode & 0o777 == 0o600
        assert store.home.stat().st_mode & 0o777 == 0o700
    assert not list(state_path.parent.glob(f".{state_path.name}.*"))
    redacted = recovered.to_json(redact_private=True)
    assert redacted["source_path"] is None
    assert redacted["spool_path"] is None
    assert redacted["destination_path"] is None
    assert redacted["offer"]["access_token"] == "[redacted]"
    assert recovered.offer["access_token"] not in json.dumps(redacted)


def test_transfer_event_and_failure_outputs_are_stable():
    transfer_id = str(uuid4())
    event = TransferEvent(
        schema_version=TRANSFER_EVENT_SCHEMA_VERSION,
        sequence=3,
        transfer_id=transfer_id,
        kind=TransferEventKind.PROGRESS,
        status=TransferStatus.TRANSFERRING,
        timestamp=datetime.now(UTC),
        provider="fixture",
        bytes_transferred=1024,
        total_bytes=4096,
        chunk_index=0,
    )
    failure = TransferFailure(
        TransferErrorCode.NETWORK_FAILED,
        "receiver connection failed",
        retryable=True,
        resumable=True,
    )

    assert event.to_json()["sequence"] == 3
    assert event.to_json()["error_code"] is None
    assert failure.to_json() == {
        "schema_version": "celatim.transfer_error.v1",
        "code": "network_failed",
        "detail": "receiver connection failed",
        "retryable": True,
        "resumable": True,
        "next_action": "check reachability and retry or resume the transfer",
    }


def test_provider_registry_selects_highest_priority_eligible_provider(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"provider selection")
    lower = FixtureProvider("lower", priority=10)
    higher = FixtureProvider("higher", priority=20)
    registry = ProviderRegistry((lower, higher))
    offer = _offer(providers=("lower", "higher"))

    provider, preflight = registry.select(source, offer)

    assert isinstance(provider, TransferProvider)
    assert provider.manifest.name == "higher"
    assert preflight.eligible
    assert registry.manifests() == (higher.manifest, lower.manifest)


def test_provider_registry_rejects_missing_requested_provider_without_fallback(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"provider selection")
    registry = ProviderRegistry((FixtureProvider("available"),))
    offer = _offer(providers=("missing", "available"))

    with pytest.raises(TransferFailure) as error:
        registry.select(source, offer, requested="missing")

    assert error.value.code is TransferErrorCode.PROVIDER_UNAVAILABLE


def test_provider_registry_uses_explicit_fallback_only_when_allowed(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"provider selection")
    available = FixtureProvider("available")
    registry = ProviderRegistry((available,))
    offer = _offer(providers=("available",))

    provider, preflight = registry.select(
        source,
        offer,
        requested="missing",
        allow_fallback=True,
    )

    assert provider is available
    assert preflight.eligible


def test_transfer_schemas_are_packaged_and_match_source_files():
    listed = {summary.name for summary in list_schemas()}

    for name, schema_version in TRANSFER_SCHEMAS.items():
        source = PROJECT / "schemas" / f"{name}.schema.json"
        packaged = get_schema_text(name)
        document = cast(dict[str, object], json.loads(packaged))
        assert name in listed
        assert packaged == source.read_text()
        assert document["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        properties = cast(dict[str, dict[str, object]], document["properties"])
        assert properties["schema_version"]["const"] == schema_version


def test_transfer_operation_retries_same_provider_with_bounded_policy(tmp_path):
    class RetryProvider(FixtureProvider):
        def __init__(self) -> None:
            super().__init__("retry-provider")
            self.calls = 0

        async def send(self, request: ProviderSendRequest) -> TransferReceipt:
            self.calls += 1
            if self.calls == 1:
                raise TransferFailure(
                    TransferErrorCode.NETWORK_FAILED,
                    "fixture interruption",
                    retryable=True,
                    resumable=True,
                )
            manifest = TransferManifest.from_path(
                request.source,
                offer_id=request.offer.offer_id,
                provider=self.manifest.name,
                transfer_id=request.transfer_id,
                chunk_size=request.chunk_size,
            )
            now = datetime.now(UTC)
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
                started_at=now,
                completed_at=now,
            )

    async def run() -> None:
        source = tmp_path / "source.bin"
        source.write_bytes(b"retry")
        provider = RetryProvider()
        offer = _offer(providers=(provider.manifest.name,))
        client = TransferClient(
            home=tmp_path / "home",
            registry=ProviderRegistry((provider,)),
            max_retries=1,
            retry_backoff_s=0,
        )
        operation = await client.send_file(source, offer)
        receipt = await operation.result()
        events = [event async for event in operation.events()]

        assert receipt.verified
        assert provider.calls == 2
        assert [event.kind for event in events] == [
            TransferEventKind.RETRY,
            TransferEventKind.COMPLETED,
        ]
        assert events[0].retry_count == 1

    asyncio.run(run())
