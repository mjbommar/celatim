"""Typed transfer-provider discovery, preflight, and deterministic selection."""

from __future__ import annotations

import inspect
import platform
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from importlib.metadata import EntryPoint, entry_points
from pathlib import Path
from typing import Protocol, runtime_checkable

from .errors import TransferErrorCode, TransferFailure, transfer_failure
from .models import ProviderManifest, TransferEvent, TransferOffer, TransferReceipt
from .storage import sanitize_file_name

PROVIDER_ENTRY_POINT_GROUP = "celatim.providers"
type EventSink = Callable[[TransferEvent], Awaitable[None]]


@dataclass(frozen=True)
class ProviderPreflight:
    provider: str
    eligible: bool
    checks: tuple[str, ...]
    failure: TransferFailure | None = None


@dataclass(frozen=True)
class ProviderSendRequest:
    source: Path
    offer: TransferOffer
    transfer_id: str
    home: Path
    chunk_size: int
    timeout_s: float
    emit: EventSink


@runtime_checkable
class TransferProvider(Protocol):
    """Stable provider contract used by the SDK and external entry points."""

    @property
    def manifest(self) -> ProviderManifest: ...

    def preflight(self, source: Path, offer: TransferOffer) -> ProviderPreflight: ...

    async def send(self, request: ProviderSendRequest) -> TransferReceipt: ...


class ProviderRegistry:
    """Lazy provider registry with isolated entry-point failures."""

    def __init__(self, providers: Iterable[TransferProvider] = ()) -> None:
        self._providers: dict[str, TransferProvider] = {}
        self._failures: dict[str, TransferFailure] = {}
        for provider in providers:
            self.register(provider)

    @property
    def failures(self) -> dict[str, TransferFailure]:
        return dict(self._failures)

    def register(self, provider: TransferProvider) -> None:
        _validate_provider(provider)
        name = provider.manifest.name
        if name in self._providers:
            raise transfer_failure(
                TransferErrorCode.PROVIDER_INCOMPATIBLE,
                f"duplicate transfer provider: {name}",
            )
        self._providers[name] = provider

    def discover(self) -> None:
        for entry_point in entry_points(group=PROVIDER_ENTRY_POINT_GROUP):
            self._load_entry_point(entry_point)

    def _load_entry_point(self, entry_point: EntryPoint) -> None:
        if entry_point.name in self._providers:
            self._failures[entry_point.name] = transfer_failure(
                TransferErrorCode.PROVIDER_INCOMPATIBLE,
                f"duplicate transfer provider entry point: {entry_point.name}",
            )
            return
        try:
            loaded = entry_point.load()
            provider = loaded() if inspect.isclass(loaded) else loaded
            _validate_provider(provider)
            if provider.manifest.name != entry_point.name:
                raise ValueError("entry-point name does not match provider manifest")
            self.register(provider)
        except Exception as exc:
            self._failures[entry_point.name] = transfer_failure(
                TransferErrorCode.PROVIDER_UNAVAILABLE,
                f"provider {entry_point.name!r} could not be loaded: {exc}",
            )

    def get(self, name: str) -> TransferProvider:
        try:
            return self._providers[name]
        except KeyError as exc:
            failure = self._failures.get(name)
            if failure is not None:
                raise failure from exc
            raise transfer_failure(
                TransferErrorCode.PROVIDER_UNAVAILABLE,
                f"transfer provider is not installed: {name}",
            ) from exc

    def manifests(self) -> tuple[ProviderManifest, ...]:
        return tuple(
            sorted(
                (provider.manifest for provider in self._providers.values()),
                key=lambda item: (-item.priority, item.name),
            )
        )

    def select(
        self,
        source: Path,
        offer: TransferOffer,
        *,
        requested: str | None = None,
        allow_fallback: bool = False,
    ) -> tuple[TransferProvider, ProviderPreflight]:
        if requested is not None and allow_fallback:
            offered = (requested, *(name for name in offer.providers if name != requested))
        elif requested is not None:
            offered = (requested,)
        else:
            offered = offer.providers
        failures: list[TransferFailure] = []
        eligible: list[tuple[ProviderManifest, TransferProvider, ProviderPreflight]] = []
        for name in offered:
            if name not in offer.providers:
                failures.append(
                    transfer_failure(
                        TransferErrorCode.PROVIDER_INCOMPATIBLE,
                        f"receiver did not offer provider {name}",
                    )
                )
                continue
            try:
                provider = self.get(name)
                preflight = provider.preflight(source, offer)
            except TransferFailure as exc:
                failures.append(exc)
                continue
            if preflight.eligible:
                eligible.append((provider.manifest, provider, preflight))
            elif preflight.failure is not None:
                failures.append(preflight.failure)
            if requested is not None and not allow_fallback:
                break
        if eligible:
            _, provider, preflight = sorted(
                eligible,
                key=lambda item: (-item[0].priority, item[0].name),
            )[0]
            return provider, preflight
        if failures:
            raise failures[0]
        raise transfer_failure(
            TransferErrorCode.PROVIDER_INCOMPATIBLE,
            "no mutually supported transfer provider passed preflight",
        )


def basic_preflight(
    manifest: ProviderManifest,
    source: Path,
    offer: TransferOffer,
) -> ProviderPreflight:
    """Run provider-independent, non-destructive transfer checks."""

    checks: list[str] = []
    if not source.is_file() or source.is_symlink():
        failure = transfer_failure(
            TransferErrorCode.INPUT_INVALID,
            "source must be a regular, non-symlink file",
        )
        return ProviderPreflight(manifest.name, False, tuple(checks), failure)
    checks.append("regular_file")
    try:
        sanitize_file_name(source.name)
    except TransferFailure as exc:
        return ProviderPreflight(manifest.name, False, tuple(checks), exc)
    checks.append("safe_file_name")
    size = source.stat().st_size
    if size > offer.max_file_size:
        failure = transfer_failure(
            TransferErrorCode.POLICY_BLOCKED,
            "source exceeds the receiver's maximum file size",
        )
        return ProviderPreflight(manifest.name, False, tuple(checks), failure)
    checks.append("size_allowed")
    if manifest.name not in offer.providers:
        failure = transfer_failure(
            TransferErrorCode.PROVIDER_INCOMPATIBLE,
            "provider is not present in the receiver offer",
        )
        return ProviderPreflight(manifest.name, False, tuple(checks), failure)
    checks.append("offered")
    if manifest.platforms and platform.system().lower() not in manifest.platforms:
        failure = transfer_failure(
            TransferErrorCode.PROVIDER_UNAVAILABLE,
            "provider does not support this platform",
        )
        return ProviderPreflight(manifest.name, False, tuple(checks), failure)
    checks.append("platform_supported")
    return ProviderPreflight(manifest.name, True, tuple(checks))


def _validate_provider(provider: object) -> None:
    if not isinstance(provider, TransferProvider):
        raise TypeError("provider does not implement the TransferProvider protocol")
    manifest = provider.manifest
    if not manifest.feedback or not manifest.resumable:
        raise ValueError("product transfer providers must expose a duplex feedback path")


__all__ = [
    "PROVIDER_ENTRY_POINT_GROUP",
    "EventSink",
    "ProviderPreflight",
    "ProviderRegistry",
    "ProviderSendRequest",
    "TransferProvider",
    "basic_preflight",
]
