"""DNS EDNS(0) padding daemon-path helpers."""

from __future__ import annotations

import hashlib
import importlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from time import monotonic, sleep
from typing import Any, cast

from celatim.errors import TransportError
from celatim.session import (
    ChannelSession,
    EndpointOsMetadata,
    EvidenceRecord,
    InMemoryTransport,
    MechanismProfile,
    PacingConfig,
    ReceiveResult,
    ReliabilityPolicy,
    ReliabilityStats,
    SendReceipt,
    Symbol,
    ThroughputProfile,
    local_endpoint_os,
)

from .commands import CommandRunner, SubprocessCommandRunner
from .daemon import (
    CommandReadinessProbe,
    DigQueryConfig,
    DnsmasqResolverConfig,
    ManagedDaemon,
    ManagedDaemonConfig,
)
from .tcpdump import ProcessRunner, TcpdumpCapture, TcpdumpCaptureConfig

EDNS_PADDING_OPTCODE = 12
type EdnsPaddingPcapDecoder = Callable[[Path, int], tuple[bytes, ...]]
type Sleeper = Callable[[float], None]


@dataclass(frozen=True)
class DnsEdnsPaddingPathConfig:
    sender_namespace: str = "snd"
    resolver_namespace: str = "rcv"
    sender_address: str = "10.10.0.1"
    resolver_address: str = "10.10.0.2"
    query_name: str = "covert.test"
    answer_address: str = "10.10.0.2"
    port: int = 53
    padding_optcode: int = EDNS_PADDING_OPTCODE
    timeout_s: float = 2.0
    tries: int = 1
    capture_interface: str = "vr"
    capture_pcap: Path | None = None
    capture_filter: tuple[str, ...] = ()
    capture_snaplen: int = 65535
    capture_require_output: bool = True
    capture_start_delay_s: float = 1.0
    ready_timeout_s: float = 5.0
    ready_interval_s: float = 0.1
    stop_timeout_s: float = 2.0
    require_answer: bool = True

    def __post_init__(self) -> None:
        for field_name in (
            "sender_namespace",
            "resolver_namespace",
            "sender_address",
            "resolver_address",
            "query_name",
            "answer_address",
            "capture_interface",
        ):
            if not getattr(self, field_name):
                raise ValueError(f"{field_name} must be non-empty")
        if self.port <= 0:
            raise ValueError("port must be > 0")
        if self.padding_optcode <= 0:
            raise ValueError("padding_optcode must be > 0")
        if self.timeout_s <= 0:
            raise ValueError("timeout_s must be > 0")
        if self.tries <= 0:
            raise ValueError("tries must be > 0")
        if self.capture_snaplen <= 0:
            raise ValueError("capture_snaplen must be > 0")
        if self.capture_start_delay_s < 0:
            raise ValueError("capture_start_delay_s must be >= 0")
        if self.ready_timeout_s <= 0:
            raise ValueError("ready_timeout_s must be > 0")
        if self.ready_interval_s < 0:
            raise ValueError("ready_interval_s must be >= 0")
        if self.stop_timeout_s <= 0:
            raise ValueError("stop_timeout_s must be > 0")

    @property
    def dnsmasq(self) -> DnsmasqResolverConfig:
        return DnsmasqResolverConfig(
            namespace=self.resolver_namespace,
            listen_address=self.resolver_address,
            answer_name=self.query_name,
            answer_address=self.answer_address,
            port=self.port,
        )

    @property
    def dig(self) -> DigQueryConfig:
        return DigQueryConfig(
            namespace=self.sender_namespace,
            server_address=self.resolver_address,
            query_name=self.query_name,
            port=self.port,
            timeout_s=self.timeout_s,
            tries=self.tries,
            padding_optcode=self.padding_optcode,
        )

    def capture(self, *, packet_count: int, output: Path) -> TcpdumpCaptureConfig:
        return TcpdumpCaptureConfig(
            namespace=self.resolver_namespace,
            interface=self.capture_interface,
            output=output,
            packet_count=packet_count,
            filter_expr=self.capture_filter or self.default_capture_filter,
            snaplen=self.capture_snaplen,
            require_output=self.capture_require_output,
        )

    @property
    def default_capture_filter(self) -> tuple[str, ...]:
        return (
            "src",
            "host",
            self.sender_address,
            "and",
            "(",
            "udp",
            "dst",
            "port",
            str(self.port),
            "or",
            "(",
            "tcp",
            "dst",
            "port",
            str(self.port),
            "and",
            "tcp[tcpflags]",
            "&",
            "tcp-push",
            "!=",
            "0",
            ")",
            ")",
        )


@dataclass(frozen=True)
class DnsToolVersionRecord:
    tool: str
    argv: tuple[str, ...]
    returncode: int | None
    stdout_sha256: str | None
    stderr_sha256: str | None
    stdout_excerpt: str | None
    stderr_excerpt: str | None
    error: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "argv": list(self.argv),
            "returncode": self.returncode,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "stdout_excerpt": self.stdout_excerpt,
            "stderr_excerpt": self.stderr_excerpt,
            "error": self.error,
        }


@dataclass(frozen=True)
class DnsEdnsPaddingRoundtripResult:
    receipt: SendReceipt
    result: ReceiveResult
    symbols: tuple[Symbol, ...]
    capture_pcap: Path
    answers: tuple[str, ...]
    daemon_readiness: dict[str, Any] | None
    tool_versions: tuple[DnsToolVersionRecord, ...]


@dataclass(frozen=True)
class DnsEdnsPaddingSendResult:
    receipt: SendReceipt
    symbols: tuple[Symbol, ...]
    answers: tuple[str, ...]
    tool_versions: tuple[DnsToolVersionRecord, ...]


@dataclass(frozen=True)
class DnsEdnsPaddingReceiveResult:
    result: ReceiveResult
    symbols: tuple[Symbol, ...]
    capture_pcap: Path
    daemon_readiness: dict[str, Any] | None
    tool_versions: tuple[DnsToolVersionRecord, ...]


def run_dns_edns0_padding_roundtrip(
    profile: MechanismProfile,
    payload: bytes,
    *,
    session_id: str | None = None,
    config: DnsEdnsPaddingPathConfig | None = None,
    pacing: PacingConfig | None = None,
    reliability: ReliabilityPolicy | None = None,
    command_runner: CommandRunner | None = None,
    process_runner: ProcessRunner | None = None,
    pcap_decoder: EdnsPaddingPcapDecoder | None = None,
    sleeper: Sleeper = sleep,
) -> DnsEdnsPaddingRoundtripResult:
    """Run a real ``dig`` -> ``dnsmasq`` EDNS(0) padding roundtrip.

    The sender bytes are produced by the unmodified ``dig`` client through the EDNS
    option interface. Recovery is from the captured DNS query pcap.
    """

    if profile.id != "edns0-padding":
        raise TransportError("dns_edns0_padding transport only supports edns0-padding")
    active_config = config or DnsEdnsPaddingPathConfig()
    capture_pcap = active_config.capture_pcap or Path(f"{session_id or 'edns0-padding'}.pcap")
    runner = command_runner or SubprocessCommandRunner()
    decoder = pcap_decoder or edns_padding_options_from_pcap
    active_reliability = reliability or ReliabilityPolicy()
    endpoint_os = _dns_endpoint_os(active_config)
    tool_versions = _dns_tool_versions(active_config, runner)

    memory_transport = InMemoryTransport()
    receipt = ChannelSession(profile, memory_transport, endpoint_os=endpoint_os).send_message(
        payload,
        session_id=session_id,
        pacing=pacing,
    )
    symbols = memory_transport.receive_symbols(receipt.session_id)
    query_symbols = tuple(_bytes_symbol(symbol) for symbol in symbols) if payload else ()
    packet_count = len(query_symbols) if query_symbols else 1

    daemon = ManagedDaemon(
        ManagedDaemonConfig(
            argv=active_config.dnsmasq.argv,
            name="dnsmasq",
            ready_timeout_s=active_config.ready_timeout_s,
            ready_interval_s=active_config.ready_interval_s,
            stop_timeout_s=active_config.stop_timeout_s,
        ),
        runner=process_runner,
        readiness_probe=CommandReadinessProbe(
            active_config.dig.argv(None),
            runner=runner,
            name="dig",
        ),
    )
    capture_timeout = _capture_wait_timeout(active_config, pacing, packet_count)
    start = monotonic()
    with daemon:
        capture = TcpdumpCapture(
            active_config.capture(packet_count=packet_count, output=capture_pcap),
            process_runner,
        )
        with capture:
            if active_config.capture_start_delay_s:
                sleeper(active_config.capture_start_delay_s)
            answers = _run_dig_queries(
                active_config,
                query_symbols,
                runner=runner,
                pacing=pacing,
                sleeper=sleeper,
            )
            capture.wait(timeout=capture_timeout)

    captured_symbols = decoder(capture_pcap, active_config.padding_optcode)
    if len(captured_symbols) != len(query_symbols):
        raise TransportError(
            f"expected {len(query_symbols)} EDNS padding option(s), "
            f"captured {len(captured_symbols)}"
        )
    if active_config.require_answer:
        _validate_answers(active_config, answers)

    if not query_symbols:
        result = _empty_receive_result(
            profile,
            receipt.session_id,
            elapsed_s=monotonic() - start,
            pacing=pacing,
            reliability=active_reliability,
            endpoint_os=endpoint_os,
        )
        recovered_symbols: tuple[Symbol, ...] = ()
    else:
        receiver_transport = InMemoryTransport()
        receiver_transport.send_symbols(receipt.session_id, list(captured_symbols), pacing)
        result = ChannelSession(
            profile,
            receiver_transport,
            reliability=active_reliability,
            endpoint_os=endpoint_os,
        ).receive_message(receipt)
        recovered_symbols = tuple(captured_symbols)

    return DnsEdnsPaddingRoundtripResult(
        receipt=receipt,
        result=result,
        symbols=recovered_symbols,
        capture_pcap=capture_pcap,
        answers=answers,
        daemon_readiness=(
            daemon.readiness_result.to_json() if daemon.readiness_result is not None else None
        ),
        tool_versions=tool_versions,
    )


def send_dns_edns0_padding(
    profile: MechanismProfile,
    payload: bytes,
    *,
    session_id: str | None = None,
    config: DnsEdnsPaddingPathConfig | None = None,
    pacing: PacingConfig | None = None,
    command_runner: CommandRunner | None = None,
    sleeper: Sleeper = sleep,
) -> DnsEdnsPaddingSendResult:
    """Send EDNS(0) padding symbols with ``dig`` to a separately managed resolver."""

    if profile.id != "edns0-padding":
        raise TransportError("dns_edns0_padding transport only supports edns0-padding")
    active_config = config or DnsEdnsPaddingPathConfig()
    runner = command_runner or SubprocessCommandRunner()
    tool_versions = _dns_tool_versions(active_config, runner)

    memory_transport = InMemoryTransport()
    receipt = ChannelSession(
        profile,
        memory_transport,
        endpoint_os=_dns_endpoint_os(active_config),
    ).send_message(payload, session_id=session_id, pacing=pacing)
    symbols = tuple(memory_transport.receive_symbols(receipt.session_id))
    query_symbols = tuple(_bytes_symbol(symbol) for symbol in symbols)
    if not query_symbols:
        raise TransportError("split dns_edns0_padding send requires a non-empty payload")

    answers = _run_dig_queries(
        active_config,
        query_symbols,
        runner=runner,
        pacing=pacing,
        sleeper=sleeper,
    )
    if active_config.require_answer:
        _validate_answers(active_config, answers)
    return DnsEdnsPaddingSendResult(
        receipt=receipt,
        symbols=symbols,
        answers=answers,
        tool_versions=tool_versions,
    )


def receive_dns_edns0_padding(
    profile: MechanismProfile,
    session_id: str,
    *,
    expected_queries: int,
    config: DnsEdnsPaddingPathConfig | None = None,
    pacing: PacingConfig | None = None,
    reliability: ReliabilityPolicy | None = None,
    command_runner: CommandRunner | None = None,
    process_runner: ProcessRunner | None = None,
    pcap_decoder: EdnsPaddingPcapDecoder | None = None,
    sleeper: Sleeper = sleep,
) -> DnsEdnsPaddingReceiveResult:
    """Receive EDNS(0) padding symbols from a live ``dnsmasq``/tcpdump path."""

    if profile.id != "edns0-padding":
        raise TransportError("dns_edns0_padding transport only supports edns0-padding")
    if expected_queries <= 0:
        raise TransportError("dns_edns0_padding receive requires expected_queries > 0")
    active_config = config or DnsEdnsPaddingPathConfig()
    capture_pcap = active_config.capture_pcap or Path(f"{session_id}.pcap")
    runner = command_runner or SubprocessCommandRunner()
    decoder = pcap_decoder or edns_padding_options_from_pcap
    active_reliability = reliability or ReliabilityPolicy()
    endpoint_os = _dns_endpoint_os(active_config)
    tool_versions = _dns_tool_versions(active_config, runner)

    daemon = ManagedDaemon(
        ManagedDaemonConfig(
            argv=active_config.dnsmasq.argv,
            name="dnsmasq",
            ready_timeout_s=active_config.ready_timeout_s,
            ready_interval_s=active_config.ready_interval_s,
            stop_timeout_s=active_config.stop_timeout_s,
        ),
        runner=process_runner,
        readiness_probe=CommandReadinessProbe(
            active_config.dig.argv(None),
            runner=runner,
            name="dig",
        ),
    )
    capture_timeout = _capture_wait_timeout(active_config, pacing, expected_queries)
    with daemon:
        capture = TcpdumpCapture(
            active_config.capture(packet_count=expected_queries, output=capture_pcap),
            process_runner,
        )
        with capture:
            if active_config.capture_start_delay_s:
                sleeper(active_config.capture_start_delay_s)
            capture.wait(timeout=capture_timeout)

    captured_symbols = decoder(capture_pcap, active_config.padding_optcode)
    if len(captured_symbols) != expected_queries:
        raise TransportError(
            f"expected {expected_queries} EDNS padding option(s), captured {len(captured_symbols)}"
        )
    receiver_transport = InMemoryTransport()
    receiver_transport.send_symbols(session_id, list(captured_symbols), pacing)
    result = ChannelSession(
        profile,
        receiver_transport,
        reliability=active_reliability,
        endpoint_os=endpoint_os,
    ).receive_message(session_id)
    return DnsEdnsPaddingReceiveResult(
        result=result,
        symbols=tuple(captured_symbols),
        capture_pcap=capture_pcap,
        daemon_readiness=(
            daemon.readiness_result.to_json() if daemon.readiness_result is not None else None
        ),
        tool_versions=tool_versions,
    )


def edns_padding_options_from_pcap(
    path: Path, padding_optcode: int = EDNS_PADDING_OPTCODE
) -> tuple[bytes, ...]:
    """Extract EDNS(0) Padding option bytes from DNS query packets in ``path``."""

    try:
        scapy_all = cast(Any, importlib.import_module("scapy.all"))
    except ImportError as exc:
        raise TransportError("the packet extra is required to parse EDNS padding pcaps") from exc

    dns_cls = scapy_all.DNS
    opt_cls = scapy_all.DNSRROPT
    rdpcap = scapy_all.rdpcap
    options: list[bytes] = []
    for packet in rdpcap(str(path)):
        if dns_cls not in packet or packet[dns_cls].qr != 0:
            continue
        additional = packet[dns_cls].ar
        records: list[Any] = []
        if isinstance(additional, list):
            records.extend(additional)
        else:
            while additional is not None and additional != b"" and not isinstance(additional, int):
                records.append(additional)
                additional = additional.payload if getattr(additional, "payload", None) else None
        for additional in records:
            if isinstance(additional, opt_cls):
                for tlv in additional.rdata or []:
                    if getattr(tlv, "optcode", None) == padding_optcode:
                        options.append(bytes(tlv.optdata))
    return tuple(options)


def _run_dig_queries(
    config: DnsEdnsPaddingPathConfig,
    symbols: tuple[bytes, ...],
    *,
    runner: CommandRunner,
    pacing: PacingConfig | None,
    sleeper: Sleeper,
) -> tuple[str, ...]:
    scheduled_offsets = _scheduled_offsets(pacing, len(symbols) if symbols else 1)
    start = monotonic()
    answers: list[str] = []
    query_values: tuple[bytes | None, ...] = symbols or (None,)
    for symbol, scheduled_offset in zip(query_values, scheduled_offsets, strict=True):
        delay = start + scheduled_offset - monotonic()
        if delay > 0:
            sleeper(delay)
        result = runner.run(
            config.dig.argv(None if symbol is None else symbol.hex()),
            check=True,
        )
        answers.append(result.stdout.strip())
    return tuple(answers)


def _dns_endpoint_os(config: DnsEdnsPaddingPathConfig) -> EndpointOsMetadata:
    return local_endpoint_os(
        "same_kernel_netns",
        sender_namespace=config.sender_namespace,
        receiver_namespace=config.resolver_namespace,
        tap_namespace=config.resolver_namespace,
        tap_interface=config.capture_interface,
        include_tap=True,
        notes=(
            "real dig client and dnsmasq resolver run in Linux network namespaces on the same kernel",
        ),
    )


def _scheduled_offsets(pacing: PacingConfig | None, count: int) -> tuple[float, ...]:
    if count <= 0:
        return ()
    if pacing is None:
        return tuple(0.0 for _ in range(count))
    period = pacing.effective_symbol_period_s or 0.0
    return tuple(pacing.base_delay_s + index * period for index in range(count))


def _capture_wait_timeout(
    config: DnsEdnsPaddingPathConfig,
    pacing: PacingConfig | None,
    expected_queries: int,
) -> float:
    scheduled = pacing.scheduled_duration_s(expected_queries) if pacing is not None else None
    return (
        (scheduled or 0.0)
        + config.capture_start_delay_s
        + max(config.timeout_s, 1.0) * max(1, expected_queries)
        + config.ready_timeout_s
    )


def _bytes_symbol(symbol: Symbol) -> bytes:
    if not isinstance(symbol, bytes):
        raise TransportError("edns0-padding symbols must be bytes")
    return symbol


def _validate_answers(config: DnsEdnsPaddingPathConfig, answers: tuple[str, ...]) -> None:
    for answer in answers:
        lines = {line.strip() for line in answer.splitlines() if line.strip()}
        if config.answer_address not in lines:
            raise TransportError(
                f"dig answer did not contain expected address {config.answer_address}"
            )


def _dns_tool_versions(
    config: DnsEdnsPaddingPathConfig,
    runner: CommandRunner,
) -> tuple[DnsToolVersionRecord, ...]:
    return (
        _tool_version_record(
            "dnsmasq",
            (config.dnsmasq.dnsmasq_binary, "--version"),
            runner,
        ),
        _tool_version_record(
            "dig",
            (config.dig.dig_binary, "-v"),
            runner,
        ),
    )


def _tool_version_record(
    tool: str,
    argv: tuple[str, ...],
    runner: CommandRunner,
) -> DnsToolVersionRecord:
    try:
        result = runner.run(argv, check=False)
    except Exception as exc:
        return DnsToolVersionRecord(
            tool=tool,
            argv=argv,
            returncode=None,
            stdout_sha256=None,
            stderr_sha256=None,
            stdout_excerpt=None,
            stderr_excerpt=None,
            error=f"{type(exc).__name__}: {exc}",
        )
    return DnsToolVersionRecord(
        tool=tool,
        argv=tuple(result.argv),
        returncode=result.returncode,
        stdout_sha256=hashlib.sha256(result.stdout.encode()).hexdigest(),
        stderr_sha256=hashlib.sha256(result.stderr.encode()).hexdigest(),
        stdout_excerpt=_excerpt(result.stdout),
        stderr_excerpt=_excerpt(result.stderr),
    )


def _excerpt(value: str, limit: int = 500) -> str | None:
    value = value.strip()
    if not value:
        return None
    if len(value) <= limit:
        return value
    return value[:limit] + "..."


def _empty_receive_result(
    profile: MechanismProfile,
    session_id: str,
    *,
    elapsed_s: float,
    pacing: PacingConfig | None,
    reliability: ReliabilityPolicy,
    endpoint_os: EndpointOsMetadata,
) -> ReceiveResult:
    evidence_profile = profile.evidence
    return ReceiveResult(
        session_id=session_id,
        payload=b"",
        evidence=EvidenceRecord(
            mechanism_id=profile.id,
            session_id=session_id,
            adapter_status=profile.adapter.status,
            adapter_capabilities=profile.adapter.capabilities,
            evidence_bucket=evidence_profile.bucket,
            carrier_structure=evidence_profile.carrier_structure,
            control_strength=evidence_profile.control_strength,
            independent_validator=evidence_profile.independent_validator,
            throughput_status=evidence_profile.throughput_status,
            endpoint_os=endpoint_os,
            payload_len=0,
            recovered_len=0,
            carrier_units=0,
            elapsed_s=elapsed_s,
            pacing=pacing,
            scheduled_duration_s=pacing.scheduled_duration_s(0) if pacing else None,
            timing_trace=None,
            timing_profile=None,
            throughput_profile=ThroughputProfile.from_observation(
                throughput_status=evidence_profile.throughput_status,
                payload_len=0,
                recovered_len=0,
                carrier_units=0,
                elapsed_s=elapsed_s,
                pacing=pacing,
                ok=True,
            ),
            session_framing="raw",
            chunk_count=0,
            integrity_sha256=None,
            reliability=ReliabilityStats(
                policy=reliability,
                receive_attempts=1,
                retry_count=0,
            ),
            ok=True,
        ),
    )


__all__ = [
    "EDNS_PADDING_OPTCODE",
    "DnsEdnsPaddingPathConfig",
    "DnsEdnsPaddingReceiveResult",
    "DnsEdnsPaddingRoundtripResult",
    "DnsEdnsPaddingSendResult",
    "DnsToolVersionRecord",
    "EdnsPaddingPcapDecoder",
    "edns_padding_options_from_pcap",
    "receive_dns_edns0_padding",
    "run_dns_edns0_padding_roundtrip",
    "send_dns_edns0_padding",
]
