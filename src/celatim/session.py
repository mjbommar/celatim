"""Library-facing send/receive session API.

The current production experiments are still script-oriented. This module is the first
stable endpoint shape that real transports can implement: encode a payload into carrier
symbols, send them through a transport, receive symbols from a tap, decode the payload,
and return structured evidence metadata.
"""

from __future__ import annotations

import hashlib
import platform as platform_module
from dataclasses import dataclass, replace
from math import ceil, log10, sqrt
from pathlib import Path
from struct import Struct
from time import monotonic, sleep
from typing import Any, Protocol, cast, runtime_checkable
from uuid import uuid4

from .adapter import AdapterCapability, AdapterStatus, MechanismAdapter, adapter_for
from .catalog import load_mechanisms
from .channel.framer import MAX_PAYLOAD_BYTES, Framer
from .channel.registry import codec_for
from .errors import (
    ConfigurationError,
    DecodeError,
    EncodeError,
    ReceiveTimeoutError,
    TransportError,
    UnsupportedMechanismError,
)
from .evidence import (
    CarrierStructure,
    ControlStrength,
    EvidenceBucket,
    EvidenceProfile,
    IndependentValidator,
    ThroughputStatus,
)
from .model import Mechanism
from .resources import catalog_path as packaged_catalog_path

type Symbol = int | bytes

ENDPOINT_TOPOLOGY_KINDS = (
    "same_process",
    "same_host_artifact",
    "same_kernel_netns",
    "cross_stack_vm",
    "cross_host",
    "unknown",
)
# Topology kinds for which the receiver runs on a separate OS instance from the
# sender, so independent_receiver_os may be True.
_INDEPENDENT_RECEIVER_TOPOLOGY_KINDS = ("cross_stack_vm", "cross_host")
_SESSION_FRAME_MAGIC = b"RFTC"
_SESSION_FRAME_VERSION = 1
_SESSION_FRAME_KIND_DATA = 1
_SESSION_FRAME_FLAG_END = 0x01
_SESSION_CHUNK_HEADER = Struct("!4sBB16sIIQ32sI32s")
_SESSION_CHUNK_FLAGS_BYTES = 1
_DEFAULT_CHUNK_PAYLOAD_BYTES = 32768
_MAX_CHUNK_PAYLOAD_BYTES = (
    MAX_PAYLOAD_BYTES - _SESSION_CHUNK_HEADER.size - _SESSION_CHUNK_FLAGS_BYTES
)


@dataclass(frozen=True)
class SessionFramingConfig:
    """Caller-visible session framing controls above the field-level framer."""

    chunk_payload_bytes: int = _DEFAULT_CHUNK_PAYLOAD_BYTES
    force_chunked: bool = False

    def __post_init__(self) -> None:
        if self.chunk_payload_bytes <= 0:
            raise ConfigurationError("chunk_payload_bytes must be > 0")
        if self.chunk_payload_bytes > _MAX_CHUNK_PAYLOAD_BYTES:
            raise ConfigurationError(f"chunk_payload_bytes must be <= {_MAX_CHUNK_PAYLOAD_BYTES}")


@dataclass(frozen=True)
class ReliabilityPolicy:
    """Receive-side reliability controls for a session."""

    max_receive_attempts: int = 1
    retry_backoff_s: float = 0.0
    suppress_duplicate_chunks: bool = True
    max_retransmissions: int = 0

    def __post_init__(self) -> None:
        if self.max_receive_attempts <= 0:
            raise ConfigurationError("max_receive_attempts must be > 0")
        if self.retry_backoff_s < 0:
            raise ConfigurationError("retry_backoff_s must be >= 0")
        if self.max_retransmissions < 0:
            raise ConfigurationError("max_retransmissions must be >= 0")


@dataclass(frozen=True)
class ReliabilityStats:
    """Observed receive/reassembly reliability metadata."""

    policy: ReliabilityPolicy
    receive_attempts: int
    retry_count: int
    retransmit_requests: int = 0
    duplicate_chunks: int = 0
    loss_detected: bool = False
    timed_out: bool = False
    expected_chunks: int | None = None
    recovered_chunks: int = 0
    last_error: str | None = None


@dataclass(frozen=True)
class PacingConfig:
    """Caller-selected pacing controls for storage and timing-channel transports."""

    unit_rate_hz: float | None = None
    symbol_period_s: float | None = None
    base_delay_s: float = 0.0
    timing_quantum_s: float | None = None
    decode_tolerance_s: float | None = None
    timeout_s: float | None = None
    adaptive: bool = False
    jitter_sample_window: int = 0

    def __post_init__(self) -> None:
        if self.unit_rate_hz is not None and self.symbol_period_s is not None:
            raise ConfigurationError("set unit_rate_hz or symbol_period_s, not both")
        for field_name in (
            "unit_rate_hz",
            "symbol_period_s",
            "timing_quantum_s",
            "decode_tolerance_s",
            "timeout_s",
        ):
            value = getattr(self, field_name)
            if value is not None and value <= 0:
                raise ConfigurationError(f"{field_name} must be > 0")
        if self.base_delay_s < 0:
            raise ConfigurationError("base_delay_s must be >= 0")
        if self.jitter_sample_window < 0:
            raise ConfigurationError("jitter_sample_window must be >= 0")

    @property
    def effective_symbol_period_s(self) -> float | None:
        if self.symbol_period_s is not None:
            return self.symbol_period_s
        if self.unit_rate_hz is not None:
            return 1.0 / self.unit_rate_hz
        return None

    def scheduled_duration_s(self, symbol_count: int) -> float | None:
        if symbol_count < 0:
            raise ConfigurationError("symbol_count must be >= 0")
        period = self.effective_symbol_period_s
        if period is None:
            return self.base_delay_s or None
        return self.base_delay_s + max(0, symbol_count - 1) * period


@dataclass(frozen=True)
class TimingSample:
    """One carrier-unit timestamp captured by a timing-aware transport."""

    index: int
    scheduled_offset_s: float
    observed_offset_s: float
    error_s: float


@dataclass(frozen=True)
class TimingTrace:
    """Observed timing evidence for a send path."""

    samples: tuple[TimingSample, ...]
    scheduled_duration_s: float | None
    observed_duration_s: float | None
    mean_abs_error_s: float | None
    max_abs_error_s: float | None
    inter_arrival_s: tuple[float, ...]
    inter_arrival_error_s: tuple[float, ...]

    @classmethod
    def from_offsets(
        cls,
        scheduled_offsets_s: tuple[float, ...],
        observed_offsets_s: tuple[float, ...],
    ) -> TimingTrace:
        if len(scheduled_offsets_s) != len(observed_offsets_s):
            raise ConfigurationError("scheduled and observed timing offsets must have same length")
        samples = tuple(
            TimingSample(
                index=index,
                scheduled_offset_s=scheduled,
                observed_offset_s=observed,
                error_s=observed - scheduled,
            )
            for index, (scheduled, observed) in enumerate(
                zip(scheduled_offsets_s, observed_offsets_s, strict=True)
            )
        )
        abs_errors = [abs(sample.error_s) for sample in samples]
        inter_arrival_s = tuple(
            observed_offsets_s[index] - observed_offsets_s[index - 1]
            for index in range(1, len(observed_offsets_s))
        )
        inter_arrival_error_s = tuple(
            inter_arrival - (scheduled_offsets_s[index] - scheduled_offsets_s[index - 1])
            for index, inter_arrival in enumerate(inter_arrival_s, start=1)
        )
        return cls(
            samples=samples,
            scheduled_duration_s=scheduled_offsets_s[-1] if scheduled_offsets_s else None,
            observed_duration_s=observed_offsets_s[-1] if observed_offsets_s else None,
            mean_abs_error_s=sum(abs_errors) / len(abs_errors) if abs_errors else None,
            max_abs_error_s=max(abs_errors) if abs_errors else None,
            inter_arrival_s=inter_arrival_s,
            inter_arrival_error_s=inter_arrival_error_s,
        )


@dataclass(frozen=True)
class TimingProfile:
    """Derived timing-rate and jitter metadata for timing-aware evidence."""

    sample_count: int
    nominal_symbol_period_s: float | None
    timing_quantum_s: float | None
    decode_tolerance_s: float | None
    tolerance_source: str | None
    error_basis: str | None
    jitter_sample_count: int
    jitter_mean_abs_s: float | None
    jitter_p50_abs_s: float | None
    jitter_p95_abs_s: float | None
    jitter_max_abs_s: float | None
    jitter_stddev_s: float | None
    snr_db: float | None
    symbol_error_count: int | None
    symbol_error_rate: float | None
    scheduled_unit_rate_hz: float | None
    observed_unit_rate_hz: float | None
    effective_goodput_bps: float | None
    rate_status: str

    @classmethod
    def from_trace(
        cls,
        trace: TimingTrace,
        pacing: PacingConfig | None,
        *,
        payload_len: int,
    ) -> TimingProfile:
        period = pacing.effective_symbol_period_s if pacing is not None else None
        quantum = pacing.timing_quantum_s if pacing is not None else None
        tolerance, tolerance_source = _timing_tolerance(pacing)
        errors, error_basis = _timing_error_series(trace)
        abs_errors = tuple(abs(value) for value in errors)
        stddev = _stddev(errors)
        observed_unit_rate = _observed_unit_rate(trace)
        return cls(
            sample_count=len(trace.samples),
            nominal_symbol_period_s=period,
            timing_quantum_s=quantum,
            decode_tolerance_s=tolerance,
            tolerance_source=tolerance_source,
            error_basis=error_basis,
            jitter_sample_count=len(errors),
            jitter_mean_abs_s=sum(abs_errors) / len(abs_errors) if abs_errors else None,
            jitter_p50_abs_s=_percentile(abs_errors, 0.50),
            jitter_p95_abs_s=_percentile(abs_errors, 0.95),
            jitter_max_abs_s=max(abs_errors) if abs_errors else None,
            jitter_stddev_s=stddev,
            snr_db=_snr_db(quantum, stddev),
            symbol_error_count=(
                sum(1 for value in abs_errors if tolerance is not None and value > tolerance)
                if tolerance is not None
                else None
            ),
            symbol_error_rate=(
                sum(1 for value in abs_errors if tolerance is not None and value > tolerance)
                / len(abs_errors)
                if tolerance is not None and abs_errors
                else None
            ),
            scheduled_unit_rate_hz=(1.0 / period if period else None),
            observed_unit_rate_hz=observed_unit_rate,
            effective_goodput_bps=(
                payload_len * 8.0 / trace.observed_duration_s
                if trace.observed_duration_s and trace.observed_duration_s > 0
                else None
            ),
            rate_status=_timing_rate_status(trace, pacing),
        )


@dataclass(frozen=True)
class ThroughputProfile:
    """Derived storage-rate metadata with explicit claim boundaries."""

    payload_len: int
    recovered_len: int
    carrier_units: int
    scheduled_unit_rate_hz: float | None
    measurement_window_s: float | None
    observed_unit_rate_hz: float | None
    payload_rate_bps: float | None
    throughput_status: ThroughputStatus
    rate_basis: str
    claim_status: str

    @classmethod
    def from_observation(
        cls,
        *,
        throughput_status: ThroughputStatus,
        payload_len: int,
        recovered_len: int,
        carrier_units: int,
        elapsed_s: float,
        pacing: PacingConfig | None,
        ok: bool,
    ) -> ThroughputProfile | None:
        scheduled_unit_rate_hz = _scheduled_unit_rate_hz(pacing)
        if throughput_status is ThroughputStatus.SENDER_BOUND:
            return cls(
                payload_len=payload_len,
                recovered_len=recovered_len,
                carrier_units=carrier_units,
                scheduled_unit_rate_hz=scheduled_unit_rate_hz,
                measurement_window_s=None,
                observed_unit_rate_hz=None,
                payload_rate_bps=None,
                throughput_status=throughput_status,
                rate_basis="sender_bound_no_production_window",
                claim_status="sender_bound_no_bits_per_second_claim",
            )
        if throughput_status is ThroughputStatus.PRODUCTION_PATH_MEASURED:
            measurement_window_s = elapsed_s if elapsed_s > 0 else None
            observed_unit_rate_hz = (
                carrier_units / measurement_window_s
                if measurement_window_s is not None and carrier_units > 0
                else None
            )
            payload_rate_bps = (
                recovered_len * 8.0 / measurement_window_s
                if measurement_window_s is not None and ok and recovered_len > 0
                else None
            )
            return cls(
                payload_len=payload_len,
                recovered_len=recovered_len,
                carrier_units=carrier_units,
                scheduled_unit_rate_hz=scheduled_unit_rate_hz,
                measurement_window_s=measurement_window_s,
                observed_unit_rate_hz=observed_unit_rate_hz,
                payload_rate_bps=payload_rate_bps,
                throughput_status=throughput_status,
                rate_basis="production_path_elapsed_s",
                claim_status="production_path_measured",
            )
        return None


@dataclass(frozen=True)
class EndpointOsInfo:
    """OS/runtime identity for one sender, receiver, or tap endpoint."""

    role: str
    system: str
    release: str
    version: str
    machine: str
    platform: str
    node: str
    namespace: str | None = None
    interface: str | None = None
    source: str = "local_platform"

    def to_json(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "system": self.system,
            "release": self.release,
            "version": self.version,
            "machine": self.machine,
            "platform": self.platform,
            "node": self.node,
            "namespace": self.namespace,
            "interface": self.interface,
            "source": self.source,
        }


@dataclass(frozen=True)
class EndpointOsMetadata:
    """Endpoint OS metadata needed to separate netns and cross-stack claims."""

    topology_kind: str
    independent_receiver_os: bool
    sender: EndpointOsInfo
    receiver: EndpointOsInfo
    tap: EndpointOsInfo | None = None
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.topology_kind not in ENDPOINT_TOPOLOGY_KINDS:
            raise ConfigurationError(
                f"topology_kind must be one of {', '.join(ENDPOINT_TOPOLOGY_KINDS)}"
            )
        if (
            self.topology_kind not in _INDEPENDENT_RECEIVER_TOPOLOGY_KINDS
            and self.independent_receiver_os
        ):
            raise ConfigurationError(
                "independent_receiver_os requires topology_kind in "
                f"{{{', '.join(_INDEPENDENT_RECEIVER_TOPOLOGY_KINDS)}}}"
            )

    def to_json(self) -> dict[str, Any]:
        return {
            "topology_kind": self.topology_kind,
            "independent_receiver_os": self.independent_receiver_os,
            "sender": self.sender.to_json(),
            "receiver": self.receiver.to_json(),
            "tap": None if self.tap is None else self.tap.to_json(),
            "notes": list(self.notes),
        }


def local_endpoint_os(
    topology_kind: str = "same_process",
    *,
    sender_namespace: str | None = None,
    sender_interface: str | None = None,
    receiver_namespace: str | None = None,
    receiver_interface: str | None = None,
    tap_namespace: str | None = None,
    tap_interface: str | None = None,
    include_tap: bool = False,
    notes: tuple[str, ...] = (),
) -> EndpointOsMetadata:
    """Build same-host endpoint metadata from Python's platform module."""

    return EndpointOsMetadata(
        topology_kind=topology_kind,
        independent_receiver_os=False,
        sender=_local_endpoint(
            "sender",
            namespace=sender_namespace,
            interface=sender_interface,
        ),
        receiver=_local_endpoint(
            "receiver",
            namespace=receiver_namespace,
            interface=receiver_interface,
        ),
        tap=(
            _local_endpoint("tap", namespace=tap_namespace, interface=tap_interface)
            if include_tap
            else None
        ),
        notes=notes,
    )


def cross_host_endpoint_os(
    *,
    sender_node: str,
    sender_ip: str | None = None,
    sender_mac: str | None = None,
    sender_interface: str | None = None,
    receiver_node: str | None = None,
    receiver_ip: str | None = None,
    receiver_mac: str | None = None,
    receiver_interface: str | None = None,
    notes: tuple[str, ...] = (),
) -> EndpointOsMetadata:
    """Build two-host endpoint metadata for a cross-host run.

    The receiver endpoint is sampled from the local platform module (this process runs
    on the receiver host). The sender (remote peer) identity is supplied by the caller,
    since the receiver cannot introspect the remote sender's platform module. Only the
    fields the caller actually knows are populated; unknown remote platform fields are
    left as empty strings rather than copied from the local receiver.
    """

    receiver = replace(
        _local_endpoint(
            "receiver",
            interface=receiver_interface,
        ),
        node=receiver_node if receiver_node is not None else platform_module.node(),
        interface=receiver_interface or _join_ip_mac(receiver_ip, receiver_mac),
        source="local_platform",
    )
    sender = EndpointOsInfo(
        role="sender",
        system="",
        release="",
        version="",
        machine="",
        platform="",
        node=sender_node,
        namespace=None,
        interface=sender_interface or _join_ip_mac(sender_ip, sender_mac),
        source="remote_peer_reported",
    )
    return EndpointOsMetadata(
        topology_kind="cross_host",
        independent_receiver_os=True,
        sender=sender,
        receiver=receiver,
        tap=None,
        notes=notes,
    )


def _join_ip_mac(ip: str | None, mac: str | None) -> str | None:
    parts = [part for part in (ip, mac) if part]
    return " ".join(parts) if parts else None


def _local_endpoint(
    role: str,
    *,
    namespace: str | None = None,
    interface: str | None = None,
) -> EndpointOsInfo:
    return EndpointOsInfo(
        role=role,
        system=platform_module.system(),
        release=platform_module.release(),
        version=platform_module.version(),
        machine=platform_module.machine(),
        platform=platform_module.platform(),
        node=platform_module.node(),
        namespace=namespace,
        interface=interface,
    )


class Transport(Protocol):
    """Sends encoded carrier symbols for one session."""

    def send_symbols(
        self,
        session_id: str,
        symbols: list[Symbol],
        pacing: PacingConfig | None = None,
    ) -> None: ...


class RetransmitCapableTransport(Transport, Protocol):
    """Transport that can replay previously sent symbols for one session."""

    def retransmit_symbols(self, session_id: str) -> None: ...


class Tap(Protocol):
    """Reads encoded carrier symbols for one session."""

    def receive_symbols(self, session_id: str) -> list[Symbol]: ...


class TimeoutAwareTap(Tap, Protocol):
    """Tap that accepts a caller-visible receive timeout."""

    def receive_symbols_with_timeout(
        self,
        session_id: str,
        timeout_s: float | None,
    ) -> list[Symbol]: ...


@dataclass(frozen=True)
class MechanismProfile:
    mechanism: Mechanism
    adapter: MechanismAdapter

    @property
    def id(self) -> str:
        return self.mechanism.id

    @property
    def evidence(self) -> EvidenceProfile:
        return self.adapter.evidence

    @classmethod
    def from_catalog(
        cls,
        mechanism_id: str,
        catalog_path: Path | str | None = None,
    ) -> MechanismProfile:
        with packaged_catalog_path(catalog_path) as catalog:
            for mechanism in load_mechanisms(catalog):
                if mechanism.id == mechanism_id:
                    return cls(mechanism, adapter_for(mechanism))
        raise UnsupportedMechanismError(f"unknown mechanism: {mechanism_id}")


@dataclass(frozen=True)
class SendReceipt:
    session_id: str
    mechanism_id: str
    payload_len: int
    carrier_units: int
    evidence_bucket: EvidenceBucket
    adapter_status: AdapterStatus
    adapter_capabilities: frozenset[AdapterCapability]
    pacing: PacingConfig | None = None
    scheduled_duration_s: float | None = None
    session_framing: str = "raw"
    chunk_count: int = 1
    integrity_sha256: str | None = None


@dataclass(frozen=True)
class EvidenceRecord:
    mechanism_id: str
    session_id: str
    adapter_status: AdapterStatus
    adapter_capabilities: frozenset[AdapterCapability]
    evidence_bucket: EvidenceBucket
    carrier_structure: CarrierStructure
    control_strength: ControlStrength
    independent_validator: IndependentValidator
    throughput_status: ThroughputStatus
    endpoint_os: EndpointOsMetadata
    payload_len: int
    recovered_len: int
    carrier_units: int
    elapsed_s: float
    pacing: PacingConfig | None
    scheduled_duration_s: float | None
    timing_trace: TimingTrace | None
    timing_profile: TimingProfile | None
    throughput_profile: ThroughputProfile | None
    session_framing: str
    chunk_count: int
    integrity_sha256: str | None
    reliability: ReliabilityStats
    ok: bool
    error: str | None = None


@dataclass(frozen=True)
class ReceiveResult:
    session_id: str
    payload: bytes
    evidence: EvidenceRecord


@runtime_checkable
class Sender(Protocol):
    """Endpoint object that can send one caller payload."""

    def send_message(
        self,
        payload: bytes,
        session_id: str | None = None,
        pacing: PacingConfig | None = None,
    ) -> SendReceipt: ...


@runtime_checkable
class Receiver(Protocol):
    """Endpoint object that can receive and decode one caller payload."""

    def receive_message(self, receipt_or_session_id: SendReceipt | str) -> ReceiveResult: ...


@dataclass(frozen=True)
class _EncodedSessionPayload:
    symbols: list[Symbol]
    framing: str
    chunk_count: int
    integrity_sha256: str


@dataclass(frozen=True)
class _DecodedSessionPayload:
    payload: bytes
    framing: str
    chunk_count: int
    integrity_sha256: str
    reliability: ReliabilityStats


@dataclass(frozen=True)
class _ChunkHeader:
    session_tag: bytes
    chunk_index: int
    total_chunks: int
    total_len: int
    payload_sha256: bytes
    chunk_len: int
    chunk_sha256: bytes
    flags: int


@dataclass(frozen=True)
class _ChunkDecodeResult:
    payload: bytes
    total_chunks: int
    duplicate_chunks: int
    recovered_chunks: int


class InMemoryTransport:
    """Deterministic transport/tap for API tests and adapter development."""

    def __init__(self) -> None:
        self._sessions: dict[str, list[Symbol]] = {}
        self._original_sessions: dict[str, list[Symbol]] = {}
        self._pacing: dict[str, PacingConfig | None] = {}

    def send_symbols(
        self,
        session_id: str,
        symbols: list[Symbol],
        pacing: PacingConfig | None = None,
    ) -> None:
        copied = list(symbols)
        self._sessions[session_id] = copied
        self._original_sessions[session_id] = list(copied)
        self._pacing[session_id] = pacing

    def retransmit_symbols(self, session_id: str) -> None:
        try:
            symbols = self._original_sessions[session_id]
        except KeyError as exc:
            raise TransportError(f"no symbols for session: {session_id}") from exc
        self._sessions.setdefault(session_id, []).extend(symbols)

    def receive_symbols(self, session_id: str) -> list[Symbol]:
        try:
            return list(self._sessions[session_id])
        except KeyError as exc:
            raise TransportError(f"no symbols for session: {session_id}") from exc

    def receive_symbols_with_timeout(
        self,
        session_id: str,
        timeout_s: float | None,
    ) -> list[Symbol]:
        if timeout_s is None:
            return self.receive_symbols(session_id)
        deadline = monotonic() + timeout_s
        while True:
            try:
                return self.receive_symbols(session_id)
            except TransportError as exc:
                if monotonic() >= deadline:
                    raise ReceiveTimeoutError(
                        f"timed out waiting for symbols for session: {session_id}"
                    ) from exc
                sleep(min(0.01, max(0.0, deadline - monotonic())))

    def pacing_for(self, session_id: str) -> PacingConfig | None:
        return self._pacing.get(session_id)


class ChannelSession:
    """Encode/send and receive/decode messages for one mechanism profile."""

    def __init__(
        self,
        profile: MechanismProfile,
        transport: Transport,
        tap: Tap | None = None,
        pacing: PacingConfig | None = None,
        framing: SessionFramingConfig | None = None,
        reliability: ReliabilityPolicy | None = None,
        endpoint_os: EndpointOsMetadata | None = None,
    ) -> None:
        self.profile = profile
        self._transport = transport
        self._pacing = pacing
        self._framing = framing or SessionFramingConfig()
        self._reliability = reliability or ReliabilityPolicy()
        if tap is None:
            if not callable(getattr(transport, "receive_symbols", None)):
                raise TransportError("tap is required when transport cannot receive symbols")
            self._tap = cast(Tap, transport)
        else:
            self._tap = tap
        self._framer = Framer[Any](cast(Any, codec_for(profile.mechanism)))
        self._endpoint_os = endpoint_os or local_endpoint_os()

    def send_message(
        self,
        payload: bytes,
        session_id: str | None = None,
        pacing: PacingConfig | None = None,
    ) -> SendReceipt:
        sid = session_id or uuid4().hex
        try:
            encoded = self._encode_payload(payload, sid)
        except Exception as exc:
            raise EncodeError(f"{sid}: encode failed: {exc}") from exc
        active_pacing = pacing or self._pacing
        self._transport.send_symbols(sid, encoded.symbols, active_pacing)
        return SendReceipt(
            session_id=sid,
            mechanism_id=self.profile.id,
            payload_len=len(payload),
            carrier_units=len(encoded.symbols),
            evidence_bucket=self.profile.evidence.bucket,
            adapter_status=self.profile.adapter.status,
            adapter_capabilities=self.profile.adapter.capabilities,
            pacing=active_pacing,
            scheduled_duration_s=(
                active_pacing.scheduled_duration_s(len(encoded.symbols)) if active_pacing else None
            ),
            session_framing=encoded.framing,
            chunk_count=encoded.chunk_count,
            integrity_sha256=encoded.integrity_sha256,
        )

    def receive_message(self, receipt_or_session_id: SendReceipt | str) -> ReceiveResult:
        session_id = (
            receipt_or_session_id.session_id
            if isinstance(receipt_or_session_id, SendReceipt)
            else receipt_or_session_id
        )
        pacing = (
            receipt_or_session_id.pacing
            if isinstance(receipt_or_session_id, SendReceipt)
            else self._pacing
        )
        if pacing is None:
            pacing_for = getattr(self._tap, "pacing_for", None)
            if callable(pacing_for):
                pacing = pacing_for(session_id)
        start = monotonic()
        symbols: list[Symbol] = []
        last_error: BaseException | None = None
        loss_detected = False
        timed_out = False
        retransmit_requests = 0
        timeout_s = pacing.timeout_s if pacing is not None else None
        for attempt in range(1, self._reliability.max_receive_attempts + 1):
            try:
                symbols = _receive_symbols_from_tap(self._tap, session_id, timeout_s)
            except ReceiveTimeoutError as exc:
                last_error = exc
                loss_detected = True
                timed_out = True
            except TransportError as exc:
                last_error = exc
                loss_detected = True
            except Exception as exc:
                last_error = TransportError(f"{session_id}: receive failed: {exc}")
                loss_detected = True
            else:
                try:
                    decoded = self._decode_payload(symbols, session_id)
                except Exception as exc:
                    last_error = exc
                    loss_detected = loss_detected or _is_loss_error(exc)
                else:
                    decoded = replace(
                        decoded,
                        reliability=replace(
                            decoded.reliability,
                            receive_attempts=attempt,
                            retry_count=attempt - 1,
                            retransmit_requests=retransmit_requests,
                            loss_detected=decoded.reliability.loss_detected or loss_detected,
                            timed_out=decoded.reliability.timed_out or timed_out,
                            last_error=_format_error(last_error) if last_error else None,
                        ),
                    )
                    break
            if attempt < self._reliability.max_receive_attempts:
                if (
                    last_error is not None
                    and _is_loss_error(last_error)
                    and retransmit_requests < self._reliability.max_retransmissions
                    and _request_retransmission(self._transport, session_id)
                ):
                    retransmit_requests += 1
                if self._reliability.retry_backoff_s:
                    sleep(self._reliability.retry_backoff_s)
        else:
            if isinstance(last_error, TransportError):
                raise last_error
            raise DecodeError(f"{session_id}: decode failed: {last_error}") from last_error
        elapsed = monotonic() - start
        timing_trace = _timing_trace_for(self._tap, session_id)
        evidence = self._record(
            session_id,
            payload_len=len(decoded.payload),
            recovered_len=len(decoded.payload),
            carrier_units=len(symbols),
            elapsed_s=elapsed,
            pacing=pacing,
            timing_trace=timing_trace,
            session_framing=decoded.framing,
            chunk_count=decoded.chunk_count,
            integrity_sha256=decoded.integrity_sha256,
            reliability=decoded.reliability,
            ok=True,
        )
        return ReceiveResult(session_id=session_id, payload=decoded.payload, evidence=evidence)

    def run_roundtrip(
        self,
        payload: bytes,
        session_id: str | None = None,
        pacing: PacingConfig | None = None,
    ) -> ReceiveResult:
        receipt = self.send_message(payload, session_id=session_id, pacing=pacing)
        return self.receive_message(receipt)

    def failure_result(
        self,
        session_id: str,
        error: BaseException,
        *,
        expected_payload_len: int,
        recovered_len: int = 0,
        carrier_units: int = 0,
        elapsed_s: float = 0.0,
        pacing: PacingConfig | None = None,
        timing_trace: TimingTrace | None = None,
        session_framing: str = "unknown",
        chunk_count: int = 0,
        integrity_sha256: str | None = None,
        reliability: ReliabilityStats | None = None,
    ) -> ReceiveResult:
        """Return a failed receive result with an EvidenceRecord instead of raising."""
        return ReceiveResult(
            session_id=session_id,
            payload=b"",
            evidence=self._record(
                session_id,
                payload_len=expected_payload_len,
                recovered_len=recovered_len,
                carrier_units=carrier_units,
                elapsed_s=elapsed_s,
                pacing=pacing,
                timing_trace=timing_trace,
                session_framing=session_framing,
                chunk_count=chunk_count,
                integrity_sha256=integrity_sha256,
                reliability=reliability or _failure_reliability_stats(self._reliability, error),
                ok=False,
                error=_format_error(error),
            ),
        )

    def _record(
        self,
        session_id: str,
        payload_len: int,
        recovered_len: int,
        carrier_units: int,
        elapsed_s: float,
        pacing: PacingConfig | None,
        timing_trace: TimingTrace | None = None,
        session_framing: str = "raw",
        chunk_count: int = 1,
        integrity_sha256: str | None = None,
        reliability: ReliabilityStats | None = None,
        *,
        ok: bool,
        error: str | None = None,
    ) -> EvidenceRecord:
        evidence = self.profile.evidence
        return EvidenceRecord(
            mechanism_id=self.profile.id,
            session_id=session_id,
            adapter_status=self.profile.adapter.status,
            adapter_capabilities=self.profile.adapter.capabilities,
            evidence_bucket=evidence.bucket,
            carrier_structure=evidence.carrier_structure,
            control_strength=evidence.control_strength,
            independent_validator=evidence.independent_validator,
            throughput_status=evidence.throughput_status,
            endpoint_os=self._endpoint_os,
            payload_len=payload_len,
            recovered_len=recovered_len,
            carrier_units=carrier_units,
            elapsed_s=elapsed_s,
            pacing=pacing,
            scheduled_duration_s=pacing.scheduled_duration_s(carrier_units) if pacing else None,
            timing_trace=timing_trace,
            timing_profile=(
                TimingProfile.from_trace(timing_trace, pacing, payload_len=payload_len)
                if timing_trace is not None
                else None
            ),
            throughput_profile=ThroughputProfile.from_observation(
                throughput_status=evidence.throughput_status,
                payload_len=payload_len,
                recovered_len=recovered_len,
                carrier_units=carrier_units,
                elapsed_s=elapsed_s,
                pacing=pacing,
                ok=ok,
            ),
            session_framing=session_framing,
            chunk_count=chunk_count,
            integrity_sha256=integrity_sha256,
            reliability=reliability or _default_reliability_stats(self._reliability, chunk_count),
            ok=ok,
            error=error,
        )

    def _encode_payload(self, payload: bytes, session_id: str) -> _EncodedSessionPayload:
        payload_sha256 = hashlib.sha256(payload).hexdigest()
        if not self._framing.force_chunked and len(payload) <= MAX_PAYLOAD_BYTES:
            return _EncodedSessionPayload(
                symbols=cast(list[Symbol], self._framer.encode(payload)),
                framing="raw",
                chunk_count=1,
                integrity_sha256=payload_sha256,
            )
        frames = _build_chunk_frames(payload, session_id, self._framing.chunk_payload_bytes)
        symbols: list[Symbol] = []
        for frame in frames:
            symbols.extend(cast(list[Symbol], self._framer.encode(frame)))
        return _EncodedSessionPayload(
            symbols=symbols,
            framing="chunked",
            chunk_count=len(frames),
            integrity_sha256=payload_sha256,
        )

    def _decode_payload(self, symbols: list[Symbol], session_id: str) -> _DecodedSessionPayload:
        first_frame, _used = self._framer.decode_one(cast(list[Any], symbols))
        if not _is_chunk_frame(first_frame):
            payload = self._framer.decode(cast(list[Any], symbols))
            return _DecodedSessionPayload(
                payload=payload,
                framing="raw",
                chunk_count=1,
                integrity_sha256=hashlib.sha256(payload).hexdigest(),
                reliability=_default_reliability_stats(self._reliability, 1),
            )
        chunked = _decode_chunked_payload(
            symbols,
            session_id,
            self._framer,
            self._reliability,
        )
        return _DecodedSessionPayload(
            payload=chunked.payload,
            framing="chunked",
            chunk_count=chunked.total_chunks,
            integrity_sha256=hashlib.sha256(chunked.payload).hexdigest(),
            reliability=ReliabilityStats(
                policy=self._reliability,
                receive_attempts=1,
                retry_count=0,
                retransmit_requests=0,
                duplicate_chunks=chunked.duplicate_chunks,
                expected_chunks=chunked.total_chunks,
                recovered_chunks=chunked.recovered_chunks,
            ),
        )


def _build_chunk_frames(
    payload: bytes, session_id: str, chunk_payload_bytes: int
) -> tuple[bytes, ...]:
    if chunk_payload_bytes > _MAX_CHUNK_PAYLOAD_BYTES:
        raise ConfigurationError(f"chunk_payload_bytes must be <= {_MAX_CHUNK_PAYLOAD_BYTES}")
    payload_sha256 = hashlib.sha256(payload).digest()
    session_tag = _session_tag(session_id)
    total_chunks = max(1, ceil(len(payload) / chunk_payload_bytes))
    frames: list[bytes] = []
    for index in range(total_chunks):
        chunk = payload[index * chunk_payload_bytes : (index + 1) * chunk_payload_bytes]
        flags = _SESSION_FRAME_FLAG_END if index == total_chunks - 1 else 0
        header = _SESSION_CHUNK_HEADER.pack(
            _SESSION_FRAME_MAGIC,
            _SESSION_FRAME_VERSION,
            _SESSION_FRAME_KIND_DATA,
            session_tag,
            index,
            total_chunks,
            len(payload),
            payload_sha256,
            len(chunk),
            hashlib.sha256(chunk).digest(),
        )
        frames.append(header + bytes([flags]) + chunk)
    return tuple(frames)


def _decode_chunked_payload(
    symbols: list[Symbol],
    session_id: str,
    framer: Framer[Any],
    reliability: ReliabilityPolicy,
) -> _ChunkDecodeResult:
    offset = 0
    expected_session_tag = _session_tag(session_id)
    expected_total_chunks: int | None = None
    expected_total_len: int | None = None
    expected_payload_sha256: bytes | None = None
    chunks: dict[int, bytes] = {}
    duplicate_chunks = 0
    saw_end = False
    while offset < len(symbols):
        frame, consumed = framer.decode_one(cast(list[Any], symbols), offset)
        offset += consumed
        header, chunk = _parse_chunk_frame(frame)
        if header.session_tag != expected_session_tag:
            raise ValueError("chunk session tag mismatch")
        if expected_total_chunks is None:
            expected_total_chunks = header.total_chunks
            expected_total_len = header.total_len
            expected_payload_sha256 = header.payload_sha256
        elif (
            header.total_chunks != expected_total_chunks
            or header.total_len != expected_total_len
            or header.payload_sha256 != expected_payload_sha256
        ):
            raise ValueError("inconsistent chunk metadata")
        if header.chunk_index in chunks:
            if not reliability.suppress_duplicate_chunks or chunks[header.chunk_index] != chunk:
                raise ValueError(f"conflicting duplicate chunk index {header.chunk_index}")
            duplicate_chunks += 1
            continue
        chunks[header.chunk_index] = chunk
        is_end = bool(header.flags & _SESSION_FRAME_FLAG_END)
        if is_end:
            saw_end = True
        if is_end != (header.chunk_index == header.total_chunks - 1):
            raise ValueError("end flag does not match final chunk index")
    if (
        expected_total_chunks is None
        or expected_total_len is None
        or expected_payload_sha256 is None
    ):
        raise ValueError("missing chunked session frames")
    if not saw_end:
        raise ValueError("missing end chunk")
    missing = sorted(set(range(expected_total_chunks)) - set(chunks))
    if missing:
        raise ValueError(f"missing chunk indexes: {missing}")
    payload = b"".join(chunks[index] for index in range(expected_total_chunks))
    if len(payload) != expected_total_len:
        raise ValueError("reassembled payload length mismatch")
    if hashlib.sha256(payload).digest() != expected_payload_sha256:
        raise ValueError("reassembled payload checksum mismatch")
    return _ChunkDecodeResult(
        payload=payload,
        total_chunks=expected_total_chunks,
        duplicate_chunks=duplicate_chunks,
        recovered_chunks=len(chunks),
    )


def _parse_chunk_frame(frame: bytes) -> tuple[_ChunkHeader, bytes]:
    minimum_len = _SESSION_CHUNK_HEADER.size + 1
    if len(frame) < minimum_len:
        raise ValueError("chunk frame too short")
    unpacked = _SESSION_CHUNK_HEADER.unpack(frame[: _SESSION_CHUNK_HEADER.size])
    (
        magic,
        version,
        kind,
        session_tag,
        chunk_index,
        total_chunks,
        total_len,
        payload_sha256,
        chunk_len,
        chunk_sha256,
    ) = unpacked
    flags = frame[_SESSION_CHUNK_HEADER.size]
    chunk = frame[minimum_len:]
    if magic != _SESSION_FRAME_MAGIC:
        raise ValueError("invalid chunk magic")
    if version != _SESSION_FRAME_VERSION:
        raise ValueError("unsupported chunk version")
    if kind != _SESSION_FRAME_KIND_DATA:
        raise ValueError("unsupported chunk frame kind")
    if flags & ~_SESSION_FRAME_FLAG_END:
        raise ValueError("unknown chunk frame flags")
    if total_chunks <= 0:
        raise ValueError("total_chunks must be > 0")
    if chunk_index >= total_chunks:
        raise ValueError("chunk_index out of range")
    if chunk_len != len(chunk):
        raise ValueError("chunk length mismatch")
    if hashlib.sha256(chunk).digest() != chunk_sha256:
        raise ValueError("chunk checksum mismatch")
    return (
        _ChunkHeader(
            session_tag=session_tag,
            chunk_index=chunk_index,
            total_chunks=total_chunks,
            total_len=total_len,
            payload_sha256=payload_sha256,
            chunk_len=chunk_len,
            chunk_sha256=chunk_sha256,
            flags=flags,
        ),
        chunk,
    )


def _is_chunk_frame(frame: bytes) -> bool:
    return len(frame) >= len(_SESSION_FRAME_MAGIC) and frame.startswith(_SESSION_FRAME_MAGIC)


def _session_tag(session_id: str) -> bytes:
    return hashlib.sha256(session_id.encode()).digest()[:16]


def _default_reliability_stats(
    policy: ReliabilityPolicy,
    expected_chunks: int | None,
) -> ReliabilityStats:
    return ReliabilityStats(
        policy=policy,
        receive_attempts=1,
        retry_count=0,
        expected_chunks=expected_chunks,
        recovered_chunks=expected_chunks or 0,
    )


def _failure_reliability_stats(
    policy: ReliabilityPolicy,
    error: BaseException,
) -> ReliabilityStats:
    return ReliabilityStats(
        policy=policy,
        receive_attempts=1,
        retry_count=0,
        retransmit_requests=0,
        loss_detected=_is_loss_error(error),
        timed_out=isinstance(error, ReceiveTimeoutError),
        last_error=_format_error(error),
    )


def _request_retransmission(transport: Transport, session_id: str) -> bool:
    retransmit = getattr(transport, "retransmit_symbols", None)
    if not callable(retransmit):
        return False
    try:
        retransmit(session_id)
    except Exception as exc:
        raise TransportError(f"{session_id}: retransmit failed: {exc}") from exc
    return True


def _is_loss_error(error: BaseException) -> bool:
    if isinstance(error, ReceiveTimeoutError):
        return True
    message = str(error).lower()
    return any(
        marker in message
        for marker in (
            "missing",
            "truncated",
            "not enough symbols",
            "no symbols",
            "no file transport record",
            "timed out",
        )
    )


def _receive_symbols_from_tap(
    tap: Tap,
    session_id: str,
    timeout_s: float | None,
) -> list[Symbol]:
    receive_with_timeout = getattr(tap, "receive_symbols_with_timeout", None)
    if callable(receive_with_timeout):
        try:
            return list(receive_with_timeout(session_id, timeout_s))
        except TransportError:
            raise
        except Exception as exc:
            raise TransportError(f"{session_id}: timed receive failed: {exc}") from exc
    return tap.receive_symbols(session_id)


def _timing_trace_for(tap: Tap, session_id: str) -> TimingTrace | None:
    trace_for = getattr(tap, "timing_trace_for", None)
    if not callable(trace_for):
        return None
    try:
        trace = trace_for(session_id)
    except Exception as exc:
        raise TransportError(f"{session_id}: timing trace failed: {exc}") from exc
    if trace is not None and not isinstance(trace, TimingTrace):
        raise TransportError(f"{session_id}: timing trace must be TimingTrace or None")
    return trace


def _timing_tolerance(pacing: PacingConfig | None) -> tuple[float | None, str | None]:
    if pacing is None:
        return None, None
    if pacing.decode_tolerance_s is not None:
        return pacing.decode_tolerance_s, "decode_tolerance_s"
    if pacing.timing_quantum_s is not None:
        return pacing.timing_quantum_s / 2.0, "timing_quantum_s_half"
    return None, None


def _timing_error_series(trace: TimingTrace) -> tuple[tuple[float, ...], str | None]:
    if trace.inter_arrival_error_s:
        return trace.inter_arrival_error_s, "inter_arrival_error_s"
    if trace.samples:
        return tuple(sample.error_s for sample in trace.samples), "offset_error_s"
    return (), None


def _scheduled_unit_rate_hz(pacing: PacingConfig | None) -> float | None:
    period = pacing.effective_symbol_period_s if pacing is not None else None
    if period is None:
        return None
    return 1.0 / period


def _percentile(values: tuple[float, ...], percentile: float) -> float | None:
    if not values:
        return None
    if percentile < 0 or percentile > 1:
        raise ConfigurationError("percentile must be in [0, 1]")
    sorted_values = sorted(values)
    index = ceil(percentile * len(sorted_values)) - 1
    return sorted_values[max(0, min(index, len(sorted_values) - 1))]


def _stddev(values: tuple[float, ...]) -> float | None:
    if not values:
        return None
    mean = sum(values) / len(values)
    return sqrt(sum((value - mean) ** 2 for value in values) / len(values))


def _snr_db(quantum: float | None, jitter_stddev_s: float | None) -> float | None:
    if quantum is None or jitter_stddev_s is None or jitter_stddev_s <= 0:
        return None
    return 20.0 * log10(quantum / jitter_stddev_s)


def _observed_unit_rate(trace: TimingTrace) -> float | None:
    if not trace.inter_arrival_s:
        return None
    duration = sum(trace.inter_arrival_s)
    if duration <= 0:
        return None
    return len(trace.inter_arrival_s) / duration


def _timing_rate_status(trace: TimingTrace, pacing: PacingConfig | None) -> str:
    if pacing is None:
        return "observed_local_transport"
    if pacing.timing_quantum_s is not None:
        return "local_scheme_demonstration_not_capacity"
    if trace.inter_arrival_s:
        return "local_pacing_observed_not_medium_capacity"
    return "local_single_symbol_no_rate_claim"


def _format_error(error: BaseException) -> str:
    return f"{type(error).__name__}: {error}"


__all__ = [
    "ENDPOINT_TOPOLOGY_KINDS",
    "ChannelSession",
    "DecodeError",
    "EncodeError",
    "EndpointOsInfo",
    "EndpointOsMetadata",
    "EvidenceRecord",
    "InMemoryTransport",
    "MechanismProfile",
    "PacingConfig",
    "ReceiveResult",
    "Receiver",
    "ReliabilityPolicy",
    "ReliabilityStats",
    "RetransmitCapableTransport",
    "SendReceipt",
    "Sender",
    "SessionFramingConfig",
    "Symbol",
    "Tap",
    "ThroughputProfile",
    "TimeoutAwareTap",
    "TimingProfile",
    "TimingSample",
    "TimingTrace",
    "Transport",
    "TransportError",
    "UnsupportedMechanismError",
    "cross_host_endpoint_os",
    "local_endpoint_os",
]
