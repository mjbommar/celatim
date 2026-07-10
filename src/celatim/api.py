"""Convenience endpoint helpers for communication-library callers."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from celatim.detect import PcapScrubReport, scrub_pcap
from celatim.doctor import DoctorResult, run_doctor
from celatim.envelope import build_send_envelope, parse_envelope_symbols
from celatim.errors import ConfigurationError, ControlFailureError, TransportError
from celatim.pcap_decode import PcapDecodeReport, decode_pcap
from celatim.resources import scenario_dir_path as packaged_scenario_dir_path
from celatim.scenario import (
    EvidenceRunResult,
    ScenarioConfig,
    TransportConfig,
    load_scenario_by_id,
    run_evidence,
)
from celatim.session import (
    ChannelSession,
    EvidenceRecord,
    MechanismProfile,
    PacingConfig,
    ReceiveResult,
    ReliabilityPolicy,
    SendReceipt,
    SessionFramingConfig,
    Symbol,
    ThroughputProfile,
    TimingProfile,
    TimingSample,
    TimingTrace,
)
from celatim.testbed import CommandResult, CommandRunner, NetnsPair, NetnsPairConfig
from celatim.timing_sweep import (
    ObservedTimingCaseInput,
    TimingSweepReport,
    run_observed_timing_sweep,
    run_timing_sweep,
)
from celatim.transports import FileTransport, PcapTransport, TimedMemoryTransport

from .transports import InMemoryTransport


@dataclass(frozen=True)
class PayloadSource:
    """Reusable payload source for endpoint helpers and caller configuration."""

    kind: str
    value: str | int | Path
    encoding: str = "utf-8"

    @classmethod
    def text(cls, message: str, *, encoding: str = "utf-8") -> PayloadSource:
        """Build a text payload source."""

        return cls("text", message, encoding=encoding)

    @classmethod
    def hex(cls, hex_payload: str) -> PayloadSource:
        """Build a hex-encoded payload source."""

        return cls("hex", hex_payload)

    @classmethod
    def file(cls, path: Path | str) -> PayloadSource:
        """Build a binary-file payload source."""

        return cls("file", Path(path))

    @classmethod
    def random(cls, length: int) -> PayloadSource:
        """Build a cryptographically random payload source."""

        return cls("random", length)

    def read_bytes(self) -> bytes:
        """Resolve this source into payload bytes."""

        if self.kind == "text":
            return payload_from_text(str(self.value), encoding=self.encoding)
        if self.kind == "hex":
            return payload_from_hex(str(self.value))
        if self.kind == "file":
            if isinstance(self.value, int):
                raise ConfigurationError("file payload source requires a path")
            return payload_from_file(Path(self.value))
        if self.kind == "random":
            if isinstance(self.value, Path):
                raise ConfigurationError("random payload source requires a byte length")
            return random_payload(int(self.value))
        raise ConfigurationError(f"unknown payload source kind: {self.kind}")

    def to_json(self) -> dict[str, Any]:
        value: str | int = str(self.value) if isinstance(self.value, Path) else self.value
        return {
            "kind": self.kind,
            "value": value,
            "encoding": self.encoding if self.kind == "text" else None,
        }


NETNS_LAB_SCHEMA_VERSION = "celatim.netns_lab.v1"


@dataclass(frozen=True)
class LabCommandPlan:
    """One command in a reusable lab topology action."""

    argv: tuple[str, ...]
    check: bool

    def to_json(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "check": self.check,
        }


@dataclass(frozen=True)
class LabTopologyResult:
    """Result or dry-run plan for a lab topology lifecycle command."""

    action: str
    topology: NetnsPairConfig
    commands: tuple[LabCommandPlan, ...]
    executed: bool
    command_results: tuple[CommandResult, ...] = ()
    schema_version: str = NETNS_LAB_SCHEMA_VERSION

    @property
    def command(self) -> str:
        return f"lab {self.action}"

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "command": self.command,
            "action": self.action,
            "executed": self.executed,
            "topology": netns_lab_config_to_json(self.topology),
            "commands": [command.to_json() for command in self.commands],
            "command_results": [_command_result_to_json(result) for result in self.command_results],
        }


@dataclass(frozen=True)
class EndpointSendResult:
    """Result of encoding and sending one caller payload."""

    profile: MechanismProfile
    receipt: SendReceipt
    envelope: dict[str, Any]
    transport: Any
    transport_kind: str
    transport_record: Path | None = None

    @property
    def session_id(self) -> str:
        return self.receipt.session_id

    @property
    def mechanism_id(self) -> str:
        return self.receipt.mechanism_id

    def to_json(self) -> dict[str, Any]:
        return {
            "command": "send_payload",
            "session_id": self.session_id,
            "mechanism_id": self.mechanism_id,
            "payload_len": self.receipt.payload_len,
            "payload_sha256": self.envelope.get("payload_sha256"),
            "carrier_units": self.receipt.carrier_units,
            "carrier_units_with_bytes": self.envelope.get("carrier_units_with_bytes", 0),
            "carrier_unit_sha256": list(self.envelope.get("carrier_unit_sha256", [])),
            "transport": self.transport_kind,
            "transport_record": _path_to_json(self.transport_record),
            "receipt": _send_receipt_to_json(self.receipt),
            "envelope": dict(self.envelope),
        }


@dataclass(frozen=True)
class EndpointReceiveResult:
    """Result of receiving and decoding one endpoint payload."""

    result: ReceiveResult
    transport_kind: str
    carrier_input_used: bool | None = None
    parser_validated: bool | None = None
    carrier_units_with_bytes: int = 0
    carrier_unit_sha256: tuple[str, ...] = ()
    transport_record: Path | None = None
    expected_payload: bytes | None = None

    @property
    def session_id(self) -> str:
        return self.result.session_id

    @property
    def payload(self) -> bytes:
        return self.result.payload

    def to_json(self) -> dict[str, Any]:
        document = {
            "command": "receive_payload",
            "session_id": self.session_id,
            "mechanism_id": self.result.evidence.mechanism_id,
            "payload_len": len(self.payload),
            "recovered_hex": self.payload.hex(),
            "recovered_sha256": hashlib.sha256(self.payload).hexdigest(),
            "transport": self.transport_kind,
            "transport_record": _path_to_json(self.transport_record),
            "carrier_input_used": self.carrier_input_used,
            "parser_validated": self.parser_validated,
            "carrier_units_with_bytes": self.carrier_units_with_bytes,
            "carrier_unit_sha256": list(self.carrier_unit_sha256),
            "ok": self.result.evidence.ok,
            "evidence": _evidence_to_json(self.result.evidence),
        }
        document.update(_expected_payload_to_json(self.expected_payload, self.payload))
        return document


@dataclass(frozen=True)
class EndpointRoundtripResult:
    """Combined send/receive helper result for local endpoint checks."""

    sent: EndpointSendResult
    received: EndpointReceiveResult

    @property
    def payload(self) -> bytes:
        return self.received.payload

    @property
    def ok(self) -> bool:
        return self.received.result.evidence.ok

    @property
    def matches_sent_payload(self) -> bool:
        expected = self.sent.envelope.get("payload_sha256")
        return expected == hashlib.sha256(self.payload).hexdigest()

    @property
    def expected_matches(self) -> bool | None:
        expected = self.received.expected_payload
        return None if expected is None else self.payload == expected

    def to_json(self) -> dict[str, Any]:
        document = {
            "command": "roundtrip_payload",
            "session_id": self.sent.session_id,
            "mechanism_id": self.sent.mechanism_id,
            "payload_len": self.sent.receipt.payload_len,
            "recovered_len": len(self.payload),
            "recovered_hex": self.payload.hex(),
            "recovered_sha256": hashlib.sha256(self.payload).hexdigest(),
            "transport": self.sent.transport_kind,
            "transport_record": _path_to_json(self.sent.transport_record),
            "matches_sent_payload": self.matches_sent_payload,
            "ok": self.ok and self.matches_sent_payload,
            "sent": self.sent.to_json(),
            "received": self.received.to_json(),
        }
        document.update(_expected_payload_to_json(self.received.expected_payload, self.payload))
        return document


def payload_from_text(message: str, *, encoding: str = "utf-8") -> bytes:
    """Encode a caller text payload for endpoint helper APIs."""

    return message.encode(encoding)


def payload_from_hex(hex_payload: str) -> bytes:
    """Decode a hex payload string for endpoint helper APIs."""

    return bytes.fromhex(hex_payload)


def payload_from_file(path: Path | str) -> bytes:
    """Read a binary payload file for endpoint helper APIs."""

    return Path(path).read_bytes()


def random_payload(length: int) -> bytes:
    """Generate cryptographically strong random payload bytes."""

    if length <= 0:
        raise ConfigurationError("random payload length must be > 0")
    return secrets.token_bytes(length)


def manage_netns_lab(
    action: str,
    config: NetnsPairConfig | None = None,
    *,
    dry_run: bool = False,
    runner: CommandRunner | None = None,
) -> LabTopologyResult:
    """Create, tear down, or plan the Linux netns/veth lab topology.

    ``dry_run=True`` returns the exact command plan without changing host network
    state, which is useful for rootless installed-package checks.
    """

    if action not in {"up", "down"}:
        raise ConfigurationError("netns lab action must be 'up' or 'down'")
    active_config = config or NetnsPairConfig()
    pair = NetnsPair(active_config, runner=runner)
    command_plans = _netns_lab_command_plans(action, pair)
    if dry_run:
        return LabTopologyResult(
            action=action,
            topology=active_config,
            commands=command_plans,
            executed=False,
        )
    results = tuple(pair.runner.run(command.argv, check=command.check) for command in command_plans)
    return LabTopologyResult(
        action=action,
        topology=active_config,
        commands=command_plans,
        executed=True,
        command_results=results,
    )


def netns_lab_config_to_json(config: NetnsPairConfig) -> dict[str, Any]:
    """Serialize a netns/veth lab topology configuration."""

    return {
        "sender_ns": config.sender_ns,
        "receiver_ns": config.receiver_ns,
        "sender_iface": config.sender_iface,
        "receiver_iface": config.receiver_iface,
        "sender_ipv4_cidr": config.sender_ipv4_cidr,
        "receiver_ipv4_cidr": config.receiver_ipv4_cidr,
        "mtu": config.mtu,
        "ip_binary": config.ip_binary,
        "ethtool_binary": config.ethtool_binary,
        "disable_offloads": config.disable_offloads,
        "cleanup_existing": config.cleanup_existing,
    }


def send_payload(
    mechanism: str | MechanismProfile,
    payload: bytes | bytearray | memoryview | PayloadSource,
    *,
    catalog_path: Path | str | None = None,
    session_id: str | None = None,
    transport: Any | None = None,
    transport_dir: Path | str | None = None,
    pcap_dir: Path | str | None = None,
    timed_transport: bool = False,
    transport_kind: str | None = None,
    pacing: PacingConfig | None = None,
    framing: SessionFramingConfig | None = None,
    reliability: ReliabilityPolicy | None = None,
) -> EndpointSendResult:
    """Encode caller bytes, send them through a local transport, and return an envelope."""

    profile = _profile(mechanism, catalog_path)
    payload_bytes = _payload_bytes(payload)
    active_transport, transport_kind = _transport_for_send(
        profile,
        transport=transport,
        transport_dir=transport_dir,
        pcap_dir=pcap_dir,
        timed_transport=timed_transport,
        transport_kind=transport_kind,
    )
    session = ChannelSession(
        profile,
        active_transport,
        pacing=pacing,
        framing=framing,
        reliability=reliability,
    )
    receipt = session.send_message(payload_bytes, session_id=session_id, pacing=pacing)
    symbols = _receive_symbols(active_transport, receipt.session_id)
    envelope = build_send_envelope(receipt, payload_bytes, symbols, profile)
    transport_record = _transport_record(active_transport, receipt.session_id)
    envelope["transport"] = transport_kind
    if transport_record is not None:
        envelope["transport_record"] = str(transport_record)
    return EndpointSendResult(
        profile=profile,
        receipt=receipt,
        envelope=envelope,
        transport=active_transport,
        transport_kind=transport_kind,
        transport_record=transport_record,
    )


def receive_payload(
    sent: EndpointSendResult | dict[str, Any] | None = None,
    *,
    mechanism: str | MechanismProfile | None = None,
    catalog_path: Path | str | None = None,
    session_id: str | None = None,
    transport: Any | None = None,
    transport_dir: Path | str | None = None,
    pcap_dir: Path | str | None = None,
    transport_kind: str | None = None,
    reliability: ReliabilityPolicy | None = None,
    expected_payload: bytes | bytearray | memoryview | PayloadSource | None = None,
) -> EndpointReceiveResult:
    """Receive and decode bytes from an envelope, transport artifact, or send result."""

    expected_payload_bytes = _optional_payload_bytes(expected_payload)
    if isinstance(sent, EndpointSendResult):
        if transport is None and transport_dir is None and pcap_dir is None:
            result = ChannelSession(
                sent.profile,
                sent.transport,
                reliability=reliability,
            ).receive_message(sent.session_id)
            envelope_symbols = parse_envelope_symbols(sent.envelope, sent.profile)
            return _with_expected_payload(
                EndpointReceiveResult(
                    result=result,
                    transport_kind=sent.transport_kind,
                    carrier_input_used=envelope_symbols.carrier_input_used,
                    parser_validated=envelope_symbols.parser_validated,
                    carrier_units_with_bytes=envelope_symbols.carrier_units_with_bytes,
                    carrier_unit_sha256=envelope_symbols.carrier_unit_sha256,
                    transport_record=sent.transport_record,
                ),
                expected_payload_bytes,
            )
        if mechanism is None:
            mechanism = sent.profile
        if session_id is None:
            session_id = sent.session_id
        profile = _profile(mechanism, catalog_path)
        active_transport, transport_kind = _transport_for_receive(
            profile,
            transport=transport,
            transport_dir=transport_dir,
            pcap_dir=pcap_dir,
            transport_kind=transport_kind,
        )
        result = ChannelSession(
            profile,
            active_transport,
            reliability=reliability,
        ).receive_message(session_id)
        envelope_symbols = parse_envelope_symbols(sent.envelope, profile)
        return _with_expected_payload(
            EndpointReceiveResult(
                result=result,
                transport_kind=transport_kind,
                carrier_input_used=envelope_symbols.carrier_input_used,
                parser_validated=envelope_symbols.parser_validated,
                carrier_units_with_bytes=envelope_symbols.carrier_units_with_bytes,
                carrier_unit_sha256=envelope_symbols.carrier_unit_sha256,
                transport_record=_transport_record(active_transport, result.session_id),
            ),
            expected_payload_bytes,
        )
    if isinstance(sent, dict):
        return _with_expected_payload(
            _receive_from_envelope(
                sent,
                mechanism=mechanism,
                catalog_path=catalog_path,
                reliability=reliability,
            ),
            expected_payload_bytes,
        )

    if mechanism is None or session_id is None:
        raise ConfigurationError(
            "receive_payload requires mechanism and session_id without envelope"
        )
    profile = _profile(mechanism, catalog_path)
    active_transport, transport_kind = _transport_for_receive(
        profile,
        transport=transport,
        transport_dir=transport_dir,
        pcap_dir=pcap_dir,
        transport_kind=transport_kind,
    )
    result = ChannelSession(
        profile,
        active_transport,
        reliability=reliability,
    ).receive_message(session_id)
    return _with_expected_payload(
        EndpointReceiveResult(
            result=result,
            transport_kind=transport_kind,
            transport_record=_transport_record(active_transport, result.session_id),
        ),
        expected_payload_bytes,
    )


def roundtrip_payload(
    mechanism: str | MechanismProfile,
    payload: bytes | bytearray | memoryview | PayloadSource,
    *,
    catalog_path: Path | str | None = None,
    session_id: str | None = None,
    transport: Any | None = None,
    transport_dir: Path | str | None = None,
    pcap_dir: Path | str | None = None,
    timed_transport: bool = False,
    transport_kind: str | None = None,
    pacing: PacingConfig | None = None,
    framing: SessionFramingConfig | None = None,
    reliability: ReliabilityPolicy | None = None,
    expected_payload: bytes | bytearray | memoryview | PayloadSource | None = None,
) -> EndpointRoundtripResult:
    """Send and receive one payload through the selected local transport."""

    sent = send_payload(
        mechanism,
        payload,
        catalog_path=catalog_path,
        session_id=session_id,
        transport=transport,
        transport_dir=transport_dir,
        pcap_dir=pcap_dir,
        timed_transport=timed_transport,
        transport_kind=transport_kind,
        pacing=pacing,
        framing=framing,
        reliability=reliability,
    )
    received = receive_payload(
        sent,
        reliability=reliability,
        expected_payload=expected_payload,
    )
    return EndpointRoundtripResult(sent=sent, received=received)


def send_scenario_payload(
    scenario: ScenarioConfig | str,
    *,
    scenario_id: str | None = None,
    scenario_dir: Path | str | None = None,
    payload: bytes | bytearray | memoryview | PayloadSource | None = None,
    catalog_path: Path | str | None = None,
    session_id: str | None = None,
    transport: TransportConfig | None = None,
    transport_dir: Path | str | None = None,
    pcap_dir: Path | str | None = None,
    timed_transport: bool = False,
    pacing: PacingConfig | None = None,
    framing: SessionFramingConfig | None = None,
    reliability: ReliabilityPolicy | None = None,
) -> EndpointSendResult:
    """Load a scenario, send its payload through a local endpoint transport."""

    config = _endpoint_config(
        scenario,
        scenario_id=scenario_id,
        scenario_dir=scenario_dir,
        payload=payload,
        transport=transport,
        transport_dir=transport_dir,
        pcap_dir=pcap_dir,
        timed_transport=timed_transport,
        pacing=pacing,
        reliability=reliability,
    )
    return send_payload(
        config.mechanism_id,
        config.payload,
        catalog_path=catalog_path,
        session_id=session_id or config.scenario_id,
        pacing=config.pacing,
        framing=framing,
        reliability=config.reliability,
        **_endpoint_transport_kwargs(config.transport),
    )


def receive_scenario_payload(
    scenario: ScenarioConfig | str,
    sent: EndpointSendResult | dict[str, Any] | None = None,
    *,
    scenario_id: str | None = None,
    scenario_dir: Path | str | None = None,
    catalog_path: Path | str | None = None,
    session_id: str | None = None,
    transport: TransportConfig | None = None,
    transport_dir: Path | str | None = None,
    pcap_dir: Path | str | None = None,
    reliability: ReliabilityPolicy | None = None,
    expected_payload: bytes | bytearray | memoryview | PayloadSource | None = None,
) -> EndpointReceiveResult:
    """Load a scenario and receive a payload from an envelope or scenario transport."""

    config = _endpoint_config(
        scenario,
        scenario_id=scenario_id,
        scenario_dir=scenario_dir,
        payload=None,
        transport=transport,
        transport_dir=transport_dir,
        pcap_dir=pcap_dir,
        timed_transport=False,
        pacing=None,
        reliability=reliability,
    )
    if sent is not None:
        return receive_payload(
            sent,
            mechanism=config.mechanism_id,
            catalog_path=catalog_path,
            reliability=config.reliability,
            expected_payload=expected_payload,
        )
    if config.transport.kind in {"memory", "timed_memory"}:
        raise ConfigurationError(
            "receive_scenario_payload without a send result requires file or pcap transport"
        )
    return receive_payload(
        None,
        mechanism=config.mechanism_id,
        catalog_path=catalog_path,
        session_id=session_id or config.scenario_id,
        reliability=config.reliability,
        expected_payload=expected_payload,
        **_endpoint_transport_kwargs(config.transport),
    )


def roundtrip_scenario_payload(
    scenario: ScenarioConfig | str,
    *,
    scenario_id: str | None = None,
    scenario_dir: Path | str | None = None,
    payload: bytes | bytearray | memoryview | PayloadSource | None = None,
    catalog_path: Path | str | None = None,
    session_id: str | None = None,
    transport: TransportConfig | None = None,
    transport_dir: Path | str | None = None,
    pcap_dir: Path | str | None = None,
    timed_transport: bool = False,
    pacing: PacingConfig | None = None,
    framing: SessionFramingConfig | None = None,
    reliability: ReliabilityPolicy | None = None,
    expected_payload: bytes | bytearray | memoryview | PayloadSource | None = None,
) -> EndpointRoundtripResult:
    """Load a scenario and run an endpoint send/receive roundtrip."""

    config = _endpoint_config(
        scenario,
        scenario_id=scenario_id,
        scenario_dir=scenario_dir,
        payload=payload,
        transport=transport,
        transport_dir=transport_dir,
        pcap_dir=pcap_dir,
        timed_transport=timed_transport,
        pacing=pacing,
        reliability=reliability,
    )
    return roundtrip_payload(
        config.mechanism_id,
        config.payload,
        catalog_path=catalog_path,
        session_id=session_id or config.scenario_id,
        pacing=config.pacing,
        framing=framing,
        reliability=config.reliability,
        expected_payload=expected_payload,
        **_endpoint_transport_kwargs(config.transport),
    )


def decode_pcap_payload(
    mechanism: str | MechanismProfile,
    pcap: Path | str,
    *,
    expected_payload: bytes | bytearray | memoryview | PayloadSource | None = None,
    catalog_path: Path | str | None = None,
    session_id: str | None = None,
    reliability: ReliabilityPolicy | None = None,
    tshark_path: str = "tshark",
) -> PcapDecodeReport:
    """Decode a parser-visible pcap artifact into a schema-backed payload report."""

    return decode_pcap(
        _profile(mechanism, catalog_path),
        pcap,
        expected_payload=_optional_payload_bytes(expected_payload),
        session_id=session_id,
        reliability=reliability,
        tshark_path=tshark_path,
    )


def scrub_pcap_payload(
    mechanism: str,
    input_pcap: Path | str,
    output_pcap: Path | str,
    *,
    command: tuple[str, ...] = (),
) -> PcapScrubReport:
    """Scrub a supported mechanism from a pcap and return a schema-backed report."""

    return scrub_pcap(mechanism, input_pcap, output_pcap, command=command)


def run_timing_sweep_payload(
    mechanism: str | MechanismProfile,
    payload: bytes | bytearray | memoryview | PayloadSource,
    *,
    quanta_s: tuple[float, ...] | list[float],
    base_pacing: PacingConfig,
    catalog_path: Path | str | None = None,
    baseline_payload: bytes | bytearray | memoryview | PayloadSource | None = None,
    run_id: str | None = None,
    clock: Any | None = None,
    sleeper: Any | None = None,
) -> TimingSweepReport:
    """Run a local timed-memory baseline and quantum sweep for a timing mechanism."""

    return run_timing_sweep(
        _profile(mechanism, catalog_path),
        _payload_bytes(payload),
        quanta_s=quanta_s,
        base_pacing=base_pacing,
        baseline_payload=_optional_payload_bytes(baseline_payload),
        run_id=run_id,
        clock=clock,
        sleeper=sleeper,
    )


def run_observed_timing_sweep_payload(
    mechanism: str | MechanismProfile,
    payload: bytes | bytearray | memoryview | PayloadSource,
    *,
    baseline: ObservedTimingCaseInput,
    trials: tuple[ObservedTimingCaseInput, ...] | list[ObservedTimingCaseInput],
    base_pacing: PacingConfig,
    catalog_path: Path | str | None = None,
    baseline_payload: bytes | bytearray | memoryview | PayloadSource | None = None,
    run_id: str | None = None,
    path_kind: str = "observed_trace",
    path_metadata: dict[str, Any] | None = None,
) -> TimingSweepReport:
    """Build a timing sweep report from observed tap offsets and recovered bytes."""

    return run_observed_timing_sweep(
        _profile(mechanism, catalog_path),
        _payload_bytes(payload),
        baseline=baseline,
        trials=trials,
        base_pacing=base_pacing,
        baseline_payload=_optional_payload_bytes(baseline_payload),
        run_id=run_id,
        path_kind=path_kind,
        path_metadata=path_metadata,
    )


def check_installation(
    *,
    catalog_path: Path | str | None = None,
    scenario_dir: Path | str | None = None,
    artifact_dir: Path | str | None = None,
    optional_tools: tuple[str, ...] | None = None,
    required_tools: tuple[str, ...] = (),
    optional_extras: tuple[str, ...] = (),
    required_extras: tuple[str, ...] = (),
    testbed_profiles: tuple[str, ...] = (),
) -> DoctorResult:
    """Run the packaged resource and environment preflight checks."""

    doctor_kwargs: dict[str, Any] = {}
    if optional_tools is not None:
        doctor_kwargs["optional_tools"] = optional_tools
    return run_doctor(
        catalog=_optional_path(catalog_path),
        scenario_dir=_optional_path(scenario_dir),
        artifact_dir=_optional_path(artifact_dir),
        required_tools=required_tools,
        optional_extras=optional_extras,
        required_extras=required_extras,
        testbed_profiles=testbed_profiles,
        **doctor_kwargs,
    )


def run_evidence_payload(
    scenario: ScenarioConfig | str | None = None,
    *,
    scenario_id: str | None = None,
    scenario_dir: Path | str | None = None,
    mechanism: str | None = None,
    payload: bytes | bytearray | memoryview | PayloadSource | None = None,
    control_payload: bytes | bytearray | memoryview | PayloadSource | None = None,
    control_kind: str | None = None,
    catalog_path: Path | str | None = None,
    command: tuple[str, ...] = (),
    artifact_dir: Path | str | None = None,
    log_dir: Path | str | None = None,
    run_id: str | None = None,
    transport: TransportConfig | None = None,
    transport_dir: Path | str | None = None,
    pcap_dir: Path | str | None = None,
    timed_transport: bool = False,
    pacing: PacingConfig | None = None,
    reliability: ReliabilityPolicy | None = None,
) -> EvidenceRunResult:
    """Run covert/control evidence from a scenario id, config, or ad hoc inputs."""

    config = _evidence_config(
        scenario,
        scenario_id=scenario_id,
        scenario_dir=scenario_dir,
        mechanism=mechanism,
        payload=payload,
        control_payload=control_payload,
        control_kind=control_kind,
        artifact_dir=artifact_dir,
        log_dir=log_dir,
        run_id=run_id,
        transport=transport,
        transport_dir=transport_dir,
        pcap_dir=pcap_dir,
        timed_transport=timed_transport,
        pacing=pacing,
        reliability=reliability,
    )
    return run_evidence(config, catalog_path=catalog_path, command=command)


def _receive_from_envelope(
    envelope: dict[str, Any],
    *,
    mechanism: str | MechanismProfile | None,
    catalog_path: Path | str | None,
    reliability: ReliabilityPolicy | None,
) -> EndpointReceiveResult:
    profile = _profile(mechanism or str(envelope["mechanism_id"]), catalog_path)
    envelope_symbols = parse_envelope_symbols(envelope, profile)
    transport = InMemoryTransport()
    active_session_id = str(envelope["session_id"])
    pacing = _pacing_from_mapping(envelope.get("pacing"))
    transport.send_symbols(active_session_id, envelope_symbols.symbols, pacing)
    result = ChannelSession(profile, transport, reliability=reliability).receive_message(
        active_session_id
    )
    return EndpointReceiveResult(
        result=result,
        transport_kind="envelope",
        carrier_input_used=envelope_symbols.carrier_input_used,
        parser_validated=envelope_symbols.parser_validated,
        carrier_units_with_bytes=envelope_symbols.carrier_units_with_bytes,
        carrier_unit_sha256=envelope_symbols.carrier_unit_sha256,
    )


def _profile(
    mechanism: str | MechanismProfile,
    catalog_path: Path | str | None,
) -> MechanismProfile:
    if isinstance(mechanism, MechanismProfile):
        return mechanism
    return MechanismProfile.from_catalog(mechanism, catalog_path)


def _payload_bytes(payload: bytes | bytearray | memoryview | PayloadSource) -> bytes:
    if isinstance(payload, PayloadSource):
        return payload.read_bytes()
    return bytes(payload)


def _optional_payload_bytes(
    payload: bytes | bytearray | memoryview | PayloadSource | None,
) -> bytes | None:
    return None if payload is None else _payload_bytes(payload)


def _evidence_config(
    scenario: ScenarioConfig | str | None,
    *,
    scenario_id: str | None,
    scenario_dir: Path | str | None,
    mechanism: str | None,
    payload: bytes | bytearray | memoryview | PayloadSource | None,
    control_payload: bytes | bytearray | memoryview | PayloadSource | None,
    control_kind: str | None,
    artifact_dir: Path | str | None,
    log_dir: Path | str | None,
    run_id: str | None,
    transport: TransportConfig | None,
    transport_dir: Path | str | None,
    pcap_dir: Path | str | None,
    timed_transport: bool,
    pacing: PacingConfig | None,
    reliability: ReliabilityPolicy | None,
) -> ScenarioConfig:
    base = (
        None
        if scenario is None and mechanism is not None
        else _evidence_base_scenario(scenario, scenario_id=scenario_id, scenario_dir=scenario_dir)
    )
    if base is None:
        if scenario_id is None:
            raise ConfigurationError("run_evidence_payload requires scenario_id without scenario")
        if mechanism is None:
            raise ConfigurationError("run_evidence_payload requires mechanism without scenario")
        if payload is None:
            raise ConfigurationError("run_evidence_payload requires payload without scenario")
        return ScenarioConfig(
            scenario_id=scenario_id,
            mechanism_id=mechanism,
            payload=_payload_bytes(payload),
            control_payload=_optional_payload_bytes(control_payload) or b"",
            control_kind=control_kind or _control_kind_for_source(control_payload),
            artifact_dir=_optional_str_path(artifact_dir),
            log_dir=_optional_str_path(log_dir),
            run_id=run_id,
            pacing=pacing,
            reliability=reliability,
            transport=_evidence_transport_config(
                transport=transport,
                transport_dir=transport_dir,
                pcap_dir=pcap_dir,
                timed_transport=timed_transport,
                default=None,
            ),
        )
    if mechanism is not None and mechanism != base.mechanism_id:
        raise ConfigurationError(
            f"mechanism {mechanism!r} does not match scenario mechanism {base.mechanism_id!r}"
        )
    return replace(
        base,
        payload=_payload_bytes(payload) if payload is not None else base.payload,
        control_payload=_optional_payload_bytes(control_payload)
        if control_payload is not None
        else base.control_payload,
        control_kind=control_kind
        or (
            _control_kind_for_source(control_payload, default=base.control_kind)
            if control_payload is not None
            else base.control_kind
        ),
        artifact_dir=_optional_str_path(artifact_dir)
        if artifact_dir is not None
        else base.artifact_dir,
        log_dir=_optional_str_path(log_dir) if log_dir is not None else base.log_dir,
        run_id=run_id if run_id is not None else base.run_id,
        pacing=pacing or base.pacing,
        reliability=reliability or base.reliability,
        transport=_evidence_transport_config(
            transport=transport,
            transport_dir=transport_dir,
            pcap_dir=pcap_dir,
            timed_transport=timed_transport,
            default=base.transport,
        ),
    )


def _endpoint_config(
    scenario: ScenarioConfig | str,
    *,
    scenario_id: str | None,
    scenario_dir: Path | str | None,
    payload: bytes | bytearray | memoryview | PayloadSource | None,
    transport: TransportConfig | None,
    transport_dir: Path | str | None,
    pcap_dir: Path | str | None,
    timed_transport: bool,
    pacing: PacingConfig | None,
    reliability: ReliabilityPolicy | None,
) -> ScenarioConfig:
    base = _evidence_base_scenario(
        scenario,
        scenario_id=scenario_id,
        scenario_dir=scenario_dir,
    )
    if base is None:
        raise ConfigurationError("scenario endpoint helpers require a scenario")
    return replace(
        base,
        payload=_payload_bytes(payload) if payload is not None else base.payload,
        pacing=pacing or base.pacing,
        reliability=reliability or base.reliability,
        transport=_evidence_transport_config(
            transport=transport,
            transport_dir=transport_dir,
            pcap_dir=pcap_dir,
            timed_transport=timed_transport,
            default=base.transport,
        ),
    )


def _evidence_base_scenario(
    scenario: ScenarioConfig | str | None,
    *,
    scenario_id: str | None,
    scenario_dir: Path | str | None,
) -> ScenarioConfig | None:
    if isinstance(scenario, ScenarioConfig):
        if scenario_id is not None and scenario_id != scenario.scenario_id:
            raise ConfigurationError(
                f"scenario_id {scenario_id!r} does not match scenario {scenario.scenario_id!r}"
            )
        return scenario
    if isinstance(scenario, str) and scenario_id is not None and scenario_id != scenario:
        raise ConfigurationError(
            f"scenario_id {scenario_id!r} does not match scenario {scenario!r}"
        )
    active_scenario_id = scenario if scenario is not None else scenario_id
    if active_scenario_id is None:
        return None
    with packaged_scenario_dir_path(_optional_path(scenario_dir)) as directory:
        return load_scenario_by_id(directory, active_scenario_id)


def _evidence_transport_config(
    *,
    transport: TransportConfig | None,
    transport_dir: Path | str | None,
    pcap_dir: Path | str | None,
    timed_transport: bool,
    default: TransportConfig | None,
) -> TransportConfig:
    _reject_multiple_transports(transport, transport_dir, pcap_dir, timed_transport)
    if transport is not None:
        return transport
    if transport_dir is not None:
        return TransportConfig("file", str(transport_dir))
    if pcap_dir is not None:
        return TransportConfig("pcap", str(pcap_dir))
    if timed_transport:
        return TransportConfig("timed_memory")
    if default is not None:
        return default
    return TransportConfig()


def _endpoint_transport_kwargs(transport: TransportConfig) -> dict[str, Any]:
    if transport.kind == "memory":
        return {}
    if transport.kind == "timed_memory":
        return {"timed_transport": True}
    if transport.kind == "file":
        if transport.root is None:
            raise ConfigurationError("file scenario transport requires a root directory")
        return {"transport_dir": Path(transport.root)}
    if transport.kind == "pcap":
        if transport.root is None:
            raise ConfigurationError("pcap scenario transport requires a root directory")
        return {"pcap_dir": Path(transport.root)}
    raise ConfigurationError(
        f"scenario endpoint helpers do not support transport {transport.kind!r}; "
        "use run_evidence_payload or the transport-specific APIs"
    )


def _control_kind_for_source(
    source: bytes | bytearray | memoryview | PayloadSource | None,
    *,
    default: str = "empty_payload",
) -> str:
    if source is None:
        return default
    if isinstance(source, PayloadSource):
        if source.kind == "text":
            return "control_message"
        if source.kind == "hex":
            return "control_hex"
        if source.kind == "file":
            return "control_file"
        if source.kind == "random":
            return "control_random_bytes"
    return "control_message"


def _optional_str_path(path: Path | str | None) -> str | None:
    return None if path is None else str(path)


def _optional_path(path: Path | str | None) -> Path | None:
    return None if path is None else Path(path)


def _with_expected_payload(
    result: EndpointReceiveResult,
    expected_payload: bytes | None,
) -> EndpointReceiveResult:
    if expected_payload is None:
        return result
    if result.payload != expected_payload:
        raise ControlFailureError(
            "expected payload mismatch: "
            f"expected_len={len(expected_payload)} "
            f"expected_sha256={hashlib.sha256(expected_payload).hexdigest()} "
            f"actual_len={len(result.payload)} "
            f"actual_sha256={hashlib.sha256(result.payload).hexdigest()}"
        )
    return replace(result, expected_payload=expected_payload)


def _transport_for_send(
    profile: MechanismProfile,
    *,
    transport: Any | None,
    transport_dir: Path | str | None,
    pcap_dir: Path | str | None,
    timed_transport: bool,
    transport_kind: str | None,
) -> tuple[Any, str]:
    _reject_multiple_transports(transport, transport_dir, pcap_dir, timed_transport)
    if transport is not None:
        return transport, transport_kind or "custom"
    if transport_dir is not None:
        return FileTransport(profile, Path(transport_dir)), "file"
    if pcap_dir is not None:
        return PcapTransport(profile, Path(pcap_dir)), "pcap"
    if timed_transport:
        return TimedMemoryTransport(), "timed_memory"
    return InMemoryTransport(), "memory"


def _transport_for_receive(
    profile: MechanismProfile,
    *,
    transport: Any | None,
    transport_dir: Path | str | None,
    pcap_dir: Path | str | None,
    transport_kind: str | None,
) -> tuple[Any, str]:
    _reject_multiple_transports(transport, transport_dir, pcap_dir, False)
    if transport is not None:
        return transport, transport_kind or "custom"
    if transport_dir is not None:
        return FileTransport(profile, Path(transport_dir)), "file"
    if pcap_dir is not None:
        return PcapTransport(profile, Path(pcap_dir)), "pcap"
    return InMemoryTransport(), "memory"


def _reject_multiple_transports(*values: object) -> None:
    if sum(value is not None and value is not False for value in values) > 1:
        raise ConfigurationError("select only one transport source")


def _receive_symbols(transport: Any, session_id: str) -> list[Symbol]:
    receiver = getattr(transport, "receive_symbols", None)
    if not callable(receiver):
        raise TransportError("transport must support receive_symbols to build a send envelope")
    return list(receiver(session_id))


def _transport_record(transport: Any, session_id: str) -> Path | None:
    path_for = getattr(transport, "path_for", None)
    if not callable(path_for):
        return None
    return Path(path_for(session_id))


def _pacing_from_mapping(raw: Any) -> PacingConfig | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ConfigurationError("envelope pacing must be an object or null")
    return PacingConfig(
        unit_rate_hz=_optional_float(raw.get("unit_rate_hz")),
        base_delay_s=float(raw.get("base_delay_s", 0.0)),
        timing_quantum_s=_optional_float(raw.get("timing_quantum_s")),
        decode_tolerance_s=_optional_float(raw.get("decode_tolerance_s")),
    )


def _optional_float(value: Any) -> float | None:
    return None if value is None else float(value)


def _path_to_json(path: Path | None) -> str | None:
    return None if path is None else str(path)


def _expected_payload_to_json(
    expected_payload: bytes | None,
    recovered_payload: bytes,
) -> dict[str, Any]:
    if expected_payload is None:
        return {}
    return {
        "expected_payload_len": len(expected_payload),
        "expected_payload_sha256": hashlib.sha256(expected_payload).hexdigest(),
        "expected_matches": recovered_payload == expected_payload,
    }


def _send_receipt_to_json(receipt: SendReceipt) -> dict[str, Any]:
    return {
        "session_id": receipt.session_id,
        "mechanism_id": receipt.mechanism_id,
        "payload_len": receipt.payload_len,
        "carrier_units": receipt.carrier_units,
        "evidence_bucket": receipt.evidence_bucket.value,
        "adapter_status": receipt.adapter_status.value,
        "adapter_capabilities": sorted(
            capability.value for capability in receipt.adapter_capabilities
        ),
        "pacing": _pacing_to_json(receipt.pacing),
        "scheduled_duration_s": receipt.scheduled_duration_s,
        "session_framing": receipt.session_framing,
        "chunk_count": receipt.chunk_count,
        "integrity_sha256": receipt.integrity_sha256,
    }


def _evidence_to_json(evidence: EvidenceRecord) -> dict[str, Any]:
    return {
        "mechanism_id": evidence.mechanism_id,
        "session_id": evidence.session_id,
        "adapter_status": evidence.adapter_status.value,
        "adapter_capabilities": sorted(
            capability.value for capability in evidence.adapter_capabilities
        ),
        "evidence_bucket": evidence.evidence_bucket.value,
        "carrier_structure": evidence.carrier_structure.value,
        "control_strength": evidence.control_strength.value,
        "independent_validator": evidence.independent_validator.value,
        "throughput_status": evidence.throughput_status.value,
        "endpoint_os": evidence.endpoint_os.to_json(),
        "payload_len": evidence.payload_len,
        "recovered_len": evidence.recovered_len,
        "carrier_units": evidence.carrier_units,
        "elapsed_s": evidence.elapsed_s,
        "pacing": _pacing_to_json(evidence.pacing),
        "scheduled_duration_s": evidence.scheduled_duration_s,
        "timing_trace": _timing_trace_to_json(evidence.timing_trace),
        "timing_profile": _timing_profile_to_json(evidence.timing_profile),
        "throughput_profile": _throughput_profile_to_json(evidence.throughput_profile),
        "session_framing": evidence.session_framing,
        "chunk_count": evidence.chunk_count,
        "integrity_sha256": evidence.integrity_sha256,
        "reliability": _reliability_to_json(evidence.reliability),
        "ok": evidence.ok,
        "error": evidence.error,
    }


def _pacing_to_json(pacing: PacingConfig | None) -> dict[str, Any] | None:
    return None if pacing is None else asdict(pacing)


def _reliability_to_json(reliability: Any) -> dict[str, Any]:
    return {
        "policy": asdict(reliability.policy),
        "receive_attempts": reliability.receive_attempts,
        "retry_count": reliability.retry_count,
        "retransmit_requests": reliability.retransmit_requests,
        "duplicate_chunks": reliability.duplicate_chunks,
        "loss_detected": reliability.loss_detected,
        "timed_out": reliability.timed_out,
        "expected_chunks": reliability.expected_chunks,
        "recovered_chunks": reliability.recovered_chunks,
        "last_error": reliability.last_error,
    }


def _timing_trace_to_json(trace: TimingTrace | None) -> dict[str, Any] | None:
    if trace is None:
        return None
    return {
        "sample_count": len(trace.samples),
        "scheduled_duration_s": trace.scheduled_duration_s,
        "observed_duration_s": trace.observed_duration_s,
        "mean_abs_error_s": trace.mean_abs_error_s,
        "max_abs_error_s": trace.max_abs_error_s,
        "inter_arrival_s": list(trace.inter_arrival_s),
        "inter_arrival_error_s": list(trace.inter_arrival_error_s),
        "samples": [_timing_sample_to_json(sample) for sample in trace.samples],
    }


def _timing_profile_to_json(profile: TimingProfile | None) -> dict[str, Any] | None:
    if profile is None:
        return None
    return {
        "sample_count": profile.sample_count,
        "nominal_symbol_period_s": profile.nominal_symbol_period_s,
        "timing_quantum_s": profile.timing_quantum_s,
        "decode_tolerance_s": profile.decode_tolerance_s,
        "tolerance_source": profile.tolerance_source,
        "error_basis": profile.error_basis,
        "jitter_sample_count": profile.jitter_sample_count,
        "jitter_mean_abs_s": profile.jitter_mean_abs_s,
        "jitter_p50_abs_s": profile.jitter_p50_abs_s,
        "jitter_p95_abs_s": profile.jitter_p95_abs_s,
        "jitter_max_abs_s": profile.jitter_max_abs_s,
        "jitter_stddev_s": profile.jitter_stddev_s,
        "snr_db": profile.snr_db,
        "symbol_error_count": profile.symbol_error_count,
        "symbol_error_rate": profile.symbol_error_rate,
        "scheduled_unit_rate_hz": profile.scheduled_unit_rate_hz,
        "observed_unit_rate_hz": profile.observed_unit_rate_hz,
        "effective_goodput_bps": profile.effective_goodput_bps,
        "rate_status": profile.rate_status,
    }


def _throughput_profile_to_json(profile: ThroughputProfile | None) -> dict[str, Any] | None:
    if profile is None:
        return None
    return {
        "payload_len": profile.payload_len,
        "recovered_len": profile.recovered_len,
        "carrier_units": profile.carrier_units,
        "scheduled_unit_rate_hz": profile.scheduled_unit_rate_hz,
        "measurement_window_s": profile.measurement_window_s,
        "observed_unit_rate_hz": profile.observed_unit_rate_hz,
        "payload_rate_bps": profile.payload_rate_bps,
        "throughput_status": profile.throughput_status.value,
        "rate_basis": profile.rate_basis,
        "claim_status": profile.claim_status,
    }


def _timing_sample_to_json(sample: TimingSample) -> dict[str, Any]:
    return {
        "index": sample.index,
        "scheduled_offset_s": sample.scheduled_offset_s,
        "observed_offset_s": sample.observed_offset_s,
        "error_s": sample.error_s,
    }


def _netns_lab_command_plans(
    action: str,
    pair: NetnsPair,
) -> tuple[LabCommandPlan, ...]:
    if action == "up":
        commands = (tuple(pair.down_commands()) if pair.config.cleanup_existing else ()) + tuple(
            pair.up_commands()
        )
    elif action == "down":
        commands = tuple(pair.down_commands())
    else:
        raise ConfigurationError("netns lab action must be 'up' or 'down'")
    return tuple(LabCommandPlan(argv=tuple(argv), check=check) for argv, check in commands)


def _command_result_to_json(result: CommandResult) -> dict[str, Any]:
    return {
        "argv": list(result.argv),
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


__all__ = [
    "NETNS_LAB_SCHEMA_VERSION",
    "EndpointReceiveResult",
    "EndpointRoundtripResult",
    "EndpointSendResult",
    "LabCommandPlan",
    "LabTopologyResult",
    "PayloadSource",
    "check_installation",
    "decode_pcap_payload",
    "manage_netns_lab",
    "netns_lab_config_to_json",
    "receive_payload",
    "receive_scenario_payload",
    "roundtrip_payload",
    "roundtrip_scenario_payload",
    "run_evidence_payload",
    "run_observed_timing_sweep_payload",
    "run_timing_sweep_payload",
    "scrub_pcap_payload",
    "send_payload",
    "send_scenario_payload",
]
