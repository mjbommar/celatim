"""Endpoint command implementations for the unified Celatim CLI."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

from .api import (
    EndpointReceiveResult,
    payload_from_file,
    payload_from_hex,
    payload_from_text,
    random_payload,
    receive_payload,
    roundtrip_payload,
    send_payload,
)
from .crypto_transcript import (
    ECDSA_NONCE_TRANSPORT_KIND,
    RSA_PSS_SALT_TRANSPORT_KIND,
    EcdsaNonceTranscriptConfig,
    EcdsaNonceTranscriptReplayTransport,
    EcdsaNonceTranscriptTransport,
    RsaPssSaltTranscriptConfig,
    RsaPssSaltTranscriptReplayTransport,
    RsaPssSaltTranscriptTransport,
)
from .discovery import get_scenario
from .envelope import build_send_envelope, parse_envelope_symbols
from .errors import ControlFailureError
from .scenario import ScenarioConfig, TransportConfig, load_scenario
from .session import (
    ChannelSession,
    InMemoryTransport,
    MechanismProfile,
    PacingConfig,
    ReliabilityPolicy,
)
from .testbed import (
    AfpacketCarrierTransport,
    AfpacketRoundtripResult,
    AioquicConnectionIdPathConfig,
    AioquicConnectionIdRoundtripResult,
    AioquicH3SettingsPathConfig,
    AioquicH3SettingsRoundtripResult,
    DnsEdnsPaddingPathConfig,
    DnsEdnsPaddingReceiveResult,
    DnsEdnsPaddingRoundtripResult,
    DnsEdnsPaddingSendResult,
    HyperH2PingPathConfig,
    HyperH2PingRoundtripResult,
    Ipv4PacketPathConfig,
    PacketProtocol,
    TcpdumpCapture,
    TcpdumpCaptureConfig,
    receive_dns_edns0_padding,
    run_afpacket_roundtrip,
    run_aioquic_connection_id_roundtrip,
    run_aioquic_h3_settings_roundtrip,
    run_dns_edns0_padding_roundtrip,
    run_hyper_h2_ping_roundtrip,
    send_dns_edns0_padding,
)

_MISSING = object()


def evidence_config_from_args(args: argparse.Namespace) -> ScenarioConfig:
    """Resolve an evidence configuration from explicit or scenario-backed CLI args."""

    scenario = None
    if args.scenario is not None or (args.scenario_id is not None and args.mechanism is None):
        scenario = _scenario_from_args(args)
    if scenario is None:
        if args.scenario_id is None:
            raise ValueError("evidence run requires --scenario-id or --scenario")
        if args.mechanism is None:
            raise ValueError("evidence run requires --mechanism without a scenario")
        return ScenarioConfig(
            scenario_id=args.scenario_id,
            mechanism_id=args.mechanism,
            payload=_payload_from_args(args),
            control_payload=_control_payload_from_args(args),
            control_kind=_control_kind_from_args(args),
            pacing=_pacing_from_args(args),
            reliability=_reliability_from_args(args),
            artifact_dir=str(args.artifact_dir) if args.artifact_dir is not None else None,
            log_dir=str(args.log_dir) if args.log_dir is not None else None,
            run_id=args.run_id,
            transport=_transport_config_from_args(args, mechanism=args.mechanism),
        )

    _mechanism_from_args(args, scenario)
    return replace(
        scenario,
        payload=_payload_from_args(args, default=scenario.payload),
        control_payload=_control_payload_from_args(args, default=scenario.control_payload),
        control_kind=_control_kind_from_args(args, default=scenario.control_kind),
        pacing=_pacing_from_args(args) or scenario.pacing,
        reliability=_reliability_from_args(args) or scenario.reliability,
        artifact_dir=str(args.artifact_dir)
        if args.artifact_dir is not None
        else scenario.artifact_dir,
        log_dir=str(args.log_dir) if args.log_dir is not None else scenario.log_dir,
        run_id=args.run_id if args.run_id is not None else scenario.run_id,
        transport=_transport_config_from_args(
            args, default=scenario.transport, mechanism=scenario.mechanism_id
        ),
    )


def _control_payload_from_args(args: argparse.Namespace, default: bytes = b"") -> bytes:
    if args.control_message is not None:
        return payload_from_text(args.control_message)
    if args.control_hex is not None:
        return payload_from_hex(args.control_hex)
    if args.control_file is not None:
        return payload_from_file(args.control_file)
    if args.control_random_bytes is not None:
        return random_payload(args.control_random_bytes)
    return default


def _control_kind_from_args(args: argparse.Namespace, default: str = "empty_payload") -> str:
    if args.control_message is not None:
        return "control_message"
    if args.control_hex is not None:
        return "control_hex"
    if args.control_file is not None:
        return "control_file"
    if args.control_random_bytes is not None:
        return "control_random_bytes"
    return default


def _send_main(args: argparse.Namespace) -> int:
    scenario = _endpoint_scenario_from_args(args)
    mechanism = _mechanism_from_args(args, scenario)
    payload = _payload_from_args(args, default=None if scenario is None else scenario.payload)
    transport = _transport_config_from_args(
        args,
        default=None if scenario is None else scenario.transport,
        mechanism=mechanism,
    )
    if transport.kind == "afpacket_ipv4":
        return _afpacket_send_main(
            args,
            scenario=scenario,
            mechanism=mechanism,
            payload=payload,
            transport=transport,
            pacing=_pacing_from_args(args) or (None if scenario is None else scenario.pacing),
        )
    if transport.kind == "dns_edns0_padding":
        return _dns_edns0_send_main(
            args,
            scenario=scenario,
            mechanism=mechanism,
            payload=payload,
            transport=transport,
            pacing=_pacing_from_args(args) or (None if scenario is None else scenario.pacing),
        )
    transport_kwargs = _endpoint_transport_kwargs(
        transport,
        command="send",
        mechanism=mechanism,
        catalog=args.catalog,
        scenario_id=_transport_scenario_id(args, scenario, mechanism),
    )
    sent = send_payload(
        mechanism,
        payload,
        catalog_path=args.catalog,
        session_id=_session_id_from_args(args, scenario),
        pacing=_pacing_from_args(args) or (None if scenario is None else scenario.pacing),
        **transport_kwargs,
    )
    document = dict(sent.envelope)
    if scenario is not None:
        document["scenario_id"] = scenario.scenario_id
    return _write_json(document, args.output)


def _recv_main(args: argparse.Namespace) -> int:
    scenario = _endpoint_scenario_from_args(args)
    if args.input is not None and _has_transport_override(args):
        raise ValueError("set --input or one transport source, not both")
    if args.timed_transport:
        raise ValueError("recv does not support --timed-transport")

    reliability = _reliability_from_args(args) or (
        None if scenario is None else scenario.reliability
    )
    if args.input is not None:
        envelope = _read_json_mapping(args.input)
        received = receive_payload(
            envelope,
            catalog_path=args.catalog,
            reliability=reliability,
        )
        document = _recv_document(received.to_json())
        _apply_expected_payload(document, received.payload, _expected_payload_from_args(args))
        return _write_json(document, args.output)

    mechanism = _mechanism_from_args(args, scenario)
    transport = _transport_config_from_args(
        args,
        default=None if scenario is None else scenario.transport,
        mechanism=mechanism,
    )
    if transport.kind == "memory":
        raise ValueError("recv requires --input or a non-memory transport source")
    if transport.kind == "afpacket_ipv4":
        return _afpacket_recv_main(
            args,
            scenario=scenario,
            mechanism=mechanism,
            transport=transport,
            reliability=reliability,
        )
    if transport.kind == "dns_edns0_padding":
        return _dns_edns0_recv_main(
            args,
            scenario=scenario,
            mechanism=mechanism,
            transport=transport,
            pacing=None if scenario is None else scenario.pacing,
            reliability=reliability,
        )

    session_id = _session_id_from_args(args, scenario)
    if session_id is None:
        raise ValueError("transport receive requires --mechanism and --session-id")
    transport_kwargs = _endpoint_transport_kwargs(
        transport,
        command="recv",
        mechanism=mechanism,
        catalog=args.catalog,
        scenario_id=_transport_scenario_id(args, scenario, mechanism),
    )
    received = receive_payload(
        None,
        mechanism=mechanism,
        catalog_path=args.catalog,
        session_id=session_id,
        reliability=reliability,
        **transport_kwargs,
    )
    document = _recv_document(received.to_json())
    if transport.kind == "file" and received.transport_record is not None:
        document.update(
            _file_transport_record_metadata(
                received.transport_record,
                mechanism,
                args.catalog,
            )
        )
    if scenario is not None:
        document["scenario_id"] = scenario.scenario_id
    _apply_expected_payload(document, received.payload, _expected_payload_from_args(args))
    return _write_json(document, args.output)


def _afpacket_send_main(
    args: argparse.Namespace,
    *,
    scenario: ScenarioConfig | None,
    mechanism: str,
    payload: bytes,
    transport: TransportConfig,
    pacing: PacingConfig | None,
) -> int:
    profile = MechanismProfile.from_catalog(mechanism, args.catalog)
    memory_transport = InMemoryTransport()
    receipt = ChannelSession(profile, memory_transport).send_message(
        payload,
        session_id=_session_id_from_args(args, scenario),
        pacing=pacing,
    )
    symbols = memory_transport.receive_symbols(receipt.session_id)
    packet_config = _packet_path_config_from_transport(transport)
    packet_transport = AfpacketCarrierTransport(profile, packet_config)
    packet_transport.send_symbols(receipt.session_id, symbols, pacing)
    document = build_send_envelope(receipt, payload, symbols, profile)
    document["transport"] = "afpacket_ipv4"
    document["expected_frames"] = receipt.carrier_units
    document["packet_path"] = _packet_path_config_to_json(packet_config)
    if scenario is not None:
        document["scenario_id"] = scenario.scenario_id
    return _write_json(document, args.output)


def _afpacket_recv_main(
    args: argparse.Namespace,
    *,
    scenario: ScenarioConfig | None,
    mechanism: str,
    transport: TransportConfig,
    reliability: ReliabilityPolicy | None,
) -> int:
    session_id = _session_id_from_args(args, scenario)
    if session_id is None:
        raise ValueError("recv --afpacket requires --mechanism and --session-id or --scenario-id")
    expected_frames = args.expected_frames or transport.expected_frames
    if expected_frames is None:
        raise ValueError("recv for afpacket_ipv4 requires --expected-frames")
    profile = MechanismProfile.from_catalog(mechanism, args.catalog)
    packet_config = replace(
        _packet_path_config_from_transport(transport),
        expected_frames=expected_frames,
    )
    packet_transport = AfpacketCarrierTransport(profile, packet_config)
    received = receive_payload(
        None,
        mechanism=profile,
        session_id=session_id,
        reliability=reliability,
        transport=packet_transport,
        transport_kind="afpacket_ipv4",
    )
    document = _recv_document(received.to_json())
    document["transport"] = "afpacket_ipv4"
    document["expected_frames"] = expected_frames
    document["packet_path"] = _packet_path_config_to_json(packet_config)
    if scenario is not None:
        document["scenario_id"] = scenario.scenario_id
    _apply_expected_payload(document, received.payload, _expected_payload_from_args(args))
    return _write_json(document, args.output)


def _dns_edns0_send_main(
    args: argparse.Namespace,
    *,
    scenario: ScenarioConfig | None,
    mechanism: str,
    payload: bytes,
    transport: TransportConfig,
    pacing: PacingConfig | None,
) -> int:
    profile = MechanismProfile.from_catalog(mechanism, args.catalog)
    live = send_dns_edns0_padding(
        profile,
        payload,
        session_id=_session_id_from_args(args, scenario),
        config=_dns_edns0_config_from_transport(transport, None),
        pacing=pacing,
    )
    document = _dns_edns0_send_document(
        live,
        profile=profile,
        payload=payload,
        transport=transport,
    )
    if scenario is not None:
        document["scenario_id"] = scenario.scenario_id
    return _write_json(document, args.output)


def _dns_edns0_recv_main(
    args: argparse.Namespace,
    *,
    scenario: ScenarioConfig | None,
    mechanism: str,
    transport: TransportConfig,
    pacing: PacingConfig | None,
    reliability: ReliabilityPolicy | None,
) -> int:
    session_id = _session_id_from_args(args, scenario)
    if session_id is None:
        raise ValueError(
            "recv dns_edns0_padding requires --mechanism and --session-id or --scenario-id"
        )
    expected_frames = args.expected_frames
    if expected_frames is None:
        raise ValueError("recv for dns_edns0_padding requires --expected-frames")
    scenario_id = _transport_scenario_id(args, scenario, mechanism)
    capture_path = _endpoint_capture_path(transport, scenario_id, explicit=args.capture_pcap)
    if capture_path is None:
        raise ValueError("recv for dns_edns0_padding requires --capture-pcap")
    profile = MechanismProfile.from_catalog(mechanism, args.catalog)
    live = receive_dns_edns0_padding(
        profile,
        session_id,
        expected_queries=expected_frames,
        config=_dns_edns0_config_from_transport(transport, capture_path),
        pacing=pacing,
        reliability=reliability,
    )
    document = _dns_edns0_recv_document(
        live,
        expected_frames=expected_frames,
        transport=transport,
    )
    if scenario is not None:
        document["scenario_id"] = scenario.scenario_id
    _apply_expected_payload(document, live.result.payload, _expected_payload_from_args(args))
    return _write_json(document, args.output)


def _roundtrip_main(args: argparse.Namespace) -> int:
    scenario = _endpoint_scenario_from_args(args)
    mechanism = _mechanism_from_args(args, scenario)
    payload = _payload_from_args(args, default=None if scenario is None else scenario.payload)
    transport = _transport_config_from_args(
        args,
        default=None if scenario is None else scenario.transport,
        mechanism=mechanism,
    )
    pacing = _pacing_from_args(args) or (None if scenario is None else scenario.pacing)
    reliability = _reliability_from_args(args) or (
        None if scenario is None else scenario.reliability
    )
    if transport.kind == "afpacket_ipv4":
        return _afpacket_roundtrip_main(
            args,
            scenario=scenario,
            mechanism=mechanism,
            payload=payload,
            transport=transport,
            pacing=pacing,
            reliability=reliability,
        )
    if transport.kind == "dns_edns0_padding":
        return _dns_edns0_roundtrip_main(
            args,
            scenario=scenario,
            mechanism=mechanism,
            payload=payload,
            transport=transport,
            pacing=pacing,
            reliability=reliability,
        )
    if transport.kind == "http2_hyper_h2":
        return _http2_hyper_h2_roundtrip_main(
            args,
            scenario=scenario,
            mechanism=mechanism,
            payload=payload,
            transport=transport,
            pacing=pacing,
            reliability=reliability,
        )
    if transport.kind == "http3_aioquic_reserved_settings":
        return _http3_aioquic_settings_roundtrip_main(
            args,
            scenario=scenario,
            mechanism=mechanism,
            payload=payload,
            transport=transport,
            pacing=pacing,
            reliability=reliability,
        )
    if transport.kind == "quic_aioquic_connection_id":
        return _quic_aioquic_roundtrip_main(
            args,
            scenario=scenario,
            mechanism=mechanism,
            payload=payload,
            transport=transport,
            pacing=pacing,
            reliability=reliability,
        )
    transport_kwargs = _endpoint_transport_kwargs(
        transport,
        command="roundtrip",
        mechanism=mechanism,
        catalog=args.catalog,
        scenario_id=_transport_scenario_id(args, scenario, mechanism),
    )
    result = roundtrip_payload(
        mechanism,
        payload,
        catalog_path=args.catalog,
        session_id=_session_id_from_args(args, scenario),
        pacing=pacing,
        reliability=reliability,
        **transport_kwargs,
    )
    received_json = result.received.to_json()
    document: dict[str, Any] = {
        "command": "roundtrip",
        "session_id": result.sent.session_id,
        "mechanism_id": result.sent.mechanism_id,
        "payload_len": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "recovered_hex": result.payload.hex(),
        "recovered_sha256": hashlib.sha256(result.payload).hexdigest(),
        "matches": result.matches_sent_payload,
        "evidence": received_json["evidence"],
    }
    if result.sent.transport_kind != "memory":
        document["transport"] = result.sent.transport_kind
    if result.sent.transport_record is not None:
        document["transport_record"] = str(result.sent.transport_record)
    if scenario is not None:
        document["scenario_id"] = scenario.scenario_id
    _apply_expected_payload(document, result.payload, _expected_payload_from_args(args))
    return _write_json(document, args.output)


def _afpacket_roundtrip_main(
    args: argparse.Namespace,
    *,
    scenario: ScenarioConfig | None,
    mechanism: str,
    payload: bytes,
    transport: TransportConfig,
    pacing: PacingConfig | None,
    reliability: ReliabilityPolicy | None,
) -> int:
    profile = MechanismProfile.from_catalog(mechanism, args.catalog)
    scenario_id = _transport_scenario_id(args, scenario, mechanism)
    capture_path = _endpoint_capture_path(
        transport,
        scenario_id,
        explicit=args.capture_pcap,
    )
    live = run_afpacket_roundtrip(
        profile,
        payload,
        session_id=_session_id_from_args(args, scenario),
        config=_packet_path_config_from_transport(transport),
        pacing=pacing,
        reliability=reliability,
        capture=_capture_from_transport(transport, capture_path),
    )
    document = _afpacket_roundtrip_document(
        live,
        payload=payload,
        transport=transport,
        capture_path=capture_path,
    )
    if scenario is not None:
        document["scenario_id"] = scenario.scenario_id
    _apply_expected_payload(document, live.result.payload, _expected_payload_from_args(args))
    return _write_json(document, args.output)


def _dns_edns0_roundtrip_main(
    args: argparse.Namespace,
    *,
    scenario: ScenarioConfig | None,
    mechanism: str,
    payload: bytes,
    transport: TransportConfig,
    pacing: PacingConfig | None,
    reliability: ReliabilityPolicy | None,
) -> int:
    profile = MechanismProfile.from_catalog(mechanism, args.catalog)
    scenario_id = _transport_scenario_id(args, scenario, mechanism)
    capture_path = _endpoint_capture_path(
        transport,
        scenario_id,
        explicit=args.capture_pcap,
    )
    if capture_path is None:
        raise ValueError("dns_edns0_padding endpoint roundtrip requires --capture-pcap")
    live = run_dns_edns0_padding_roundtrip(
        profile,
        payload,
        session_id=_session_id_from_args(args, scenario),
        config=_dns_edns0_config_from_transport(transport, capture_path),
        pacing=pacing,
        reliability=reliability,
    )
    document = _dns_edns0_roundtrip_document(live, payload=payload, transport=transport)
    if scenario is not None:
        document["scenario_id"] = scenario.scenario_id
    _apply_expected_payload(document, live.result.payload, _expected_payload_from_args(args))
    return _write_json(document, args.output)


def _http2_hyper_h2_roundtrip_main(
    args: argparse.Namespace,
    *,
    scenario: ScenarioConfig | None,
    mechanism: str,
    payload: bytes,
    transport: TransportConfig,
    pacing: PacingConfig | None,
    reliability: ReliabilityPolicy | None,
) -> int:
    profile = MechanismProfile.from_catalog(mechanism, args.catalog)
    scenario_id = _transport_scenario_id(args, scenario, mechanism)
    live = run_hyper_h2_ping_roundtrip(
        profile,
        payload,
        session_id=_session_id_from_args(args, scenario),
        config=_http2_hyper_h2_config_from_transport(transport, scenario_id),
        pacing=pacing,
        reliability=reliability,
    )
    document = _http2_hyper_h2_roundtrip_document(live, payload=payload)
    if scenario is not None:
        document["scenario_id"] = scenario.scenario_id
    _apply_expected_payload(document, live.result.payload, _expected_payload_from_args(args))
    return _write_json(document, args.output)


def _quic_aioquic_roundtrip_main(
    args: argparse.Namespace,
    *,
    scenario: ScenarioConfig | None,
    mechanism: str,
    payload: bytes,
    transport: TransportConfig,
    pacing: PacingConfig | None,
    reliability: ReliabilityPolicy | None,
) -> int:
    profile = MechanismProfile.from_catalog(mechanism, args.catalog)
    scenario_id = _transport_scenario_id(args, scenario, mechanism)
    live = run_aioquic_connection_id_roundtrip(
        profile,
        payload,
        session_id=_session_id_from_args(args, scenario),
        config=_quic_aioquic_config_from_transport(transport, scenario_id),
        pacing=pacing,
        reliability=reliability,
    )
    document = _quic_aioquic_roundtrip_document(live, payload=payload)
    if scenario is not None:
        document["scenario_id"] = scenario.scenario_id
    _apply_expected_payload(document, live.result.payload, _expected_payload_from_args(args))
    return _write_json(document, args.output)


def _http3_aioquic_settings_roundtrip_main(
    args: argparse.Namespace,
    *,
    scenario: ScenarioConfig | None,
    mechanism: str,
    payload: bytes,
    transport: TransportConfig,
    pacing: PacingConfig | None,
    reliability: ReliabilityPolicy | None,
) -> int:
    profile = MechanismProfile.from_catalog(mechanism, args.catalog)
    scenario_id = _transport_scenario_id(args, scenario, mechanism)
    live = run_aioquic_h3_settings_roundtrip(
        profile,
        payload,
        session_id=_session_id_from_args(args, scenario),
        config=_http3_aioquic_settings_config_from_transport(transport, scenario_id),
        pacing=pacing,
        reliability=reliability,
    )
    document = _http3_aioquic_settings_roundtrip_document(live, payload=payload)
    if scenario is not None:
        document["scenario_id"] = scenario.scenario_id
    _apply_expected_payload(document, live.result.payload, _expected_payload_from_args(args))
    return _write_json(document, args.output)


def _recv_document(received_json: dict[str, Any]) -> dict[str, Any]:
    document = dict(received_json)
    document["command"] = "recv"
    document.pop("ok", None)
    if document.get("transport") == "envelope":
        document.pop("transport", None)
        document.pop("transport_record", None)
    return document


def _file_transport_record_metadata(
    record_path: Path,
    mechanism_id: str,
    catalog: Path | None,
) -> dict[str, Any]:
    record = _read_json_mapping(record_path)
    profile = MechanismProfile.from_catalog(mechanism_id, catalog)
    envelope_symbols = parse_envelope_symbols(record, profile)
    return {
        "carrier_input_used": envelope_symbols.carrier_input_used,
        "parser_validated": envelope_symbols.parser_validated,
        "carrier_units_with_bytes": envelope_symbols.carrier_units_with_bytes,
        "carrier_unit_sha256": list(envelope_symbols.carrier_unit_sha256),
    }


def _scenario_from_args(args: argparse.Namespace) -> ScenarioConfig | None:
    if getattr(args, "scenario", None) is not None:
        return load_scenario(args.scenario)
    scenario_id = getattr(args, "scenario_id", None)
    if scenario_id is None:
        return None
    return get_scenario(scenario_id, scenario_dir=getattr(args, "scenario_dir", None))


def _endpoint_scenario_from_args(args: argparse.Namespace) -> ScenarioConfig | None:
    return _scenario_from_args(args)


def _mechanism_from_args(args: argparse.Namespace, scenario: ScenarioConfig | None) -> str:
    mechanism = getattr(args, "mechanism", None)
    if scenario is None:
        if mechanism is None:
            raise ValueError("command requires --mechanism or --scenario/--scenario-id")
        return str(mechanism)
    if mechanism is not None and mechanism != scenario.mechanism_id:
        raise ValueError(
            f"--mechanism {mechanism!r} does not match scenario mechanism {scenario.mechanism_id!r}"
        )
    return scenario.mechanism_id


def _session_id_from_args(args: argparse.Namespace, scenario: ScenarioConfig | None) -> str | None:
    if getattr(args, "session_id", None) is not None:
        return str(args.session_id)
    if scenario is not None:
        return scenario.scenario_id
    return None


def _endpoint_transport_kwargs(
    transport: TransportConfig,
    *,
    command: str,
    mechanism: str,
    catalog: Path | None,
    scenario_id: str,
) -> dict[str, Any]:
    if transport.kind == "memory":
        return {}
    if transport.kind == "file":
        if transport.root is None:
            raise ValueError("file transport requires a root directory")
        return {"transport_dir": Path(transport.root)}
    if transport.kind == "pcap":
        if transport.root is None:
            raise ValueError("pcap transport requires a root directory")
        return {"pcap_dir": Path(transport.root)}
    if transport.kind == "timed_memory":
        if command == "recv":
            raise ValueError("recv does not support timed_memory scenario transport")
        return {"timed_transport": True}
    if transport.kind in {ECDSA_NONCE_TRANSPORT_KIND, RSA_PSS_SALT_TRANSPORT_KIND}:
        transcript_path = _endpoint_transcript_path(transport, scenario_id)
        profile = MechanismProfile.from_catalog(mechanism, catalog)
        if command == "recv":
            return {
                "transport": _crypto_replay_transport(profile, transport.kind, transcript_path),
                "transport_kind": transport.kind,
            }
        return {
            "transport": _crypto_write_transport(profile, transport, transcript_path),
            "transport_kind": transport.kind,
        }
    raise ValueError(
        f"{command} supports scenario transports memory, file, pcap, timed_memory, "
        f"{ECDSA_NONCE_TRANSPORT_KIND}, and {RSA_PSS_SALT_TRANSPORT_KIND}; "
        f"use scenario run or evidence run for transport {transport.kind!r}"
    )


def _afpacket_roundtrip_document(
    live: AfpacketRoundtripResult,
    *,
    payload: bytes,
    transport: TransportConfig,
    capture_path: Path | None,
) -> dict[str, Any]:
    received_json = EndpointReceiveResult(
        result=live.result,
        transport_kind="afpacket_ipv4",
    ).to_json()
    document: dict[str, Any] = {
        "command": "roundtrip",
        "session_id": live.receipt.session_id,
        "mechanism_id": live.receipt.mechanism_id,
        "payload_len": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "recovered_hex": live.result.payload.hex(),
        "recovered_sha256": hashlib.sha256(live.result.payload).hexdigest(),
        "matches": live.result.payload == payload,
        "transport": "afpacket_ipv4",
        "expected_frames": live.expected_frames,
        "packet_path": _packet_path_config_to_json(_packet_path_config_from_transport(transport)),
        "evidence": received_json["evidence"],
    }
    if capture_path is not None:
        document["transport_record"] = str(capture_path)
        if capture_path.is_file():
            raw = capture_path.read_bytes()
            document["transport_artifact"] = {
                "kind": "transport_capture",
                "path": str(capture_path),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": len(raw),
            }
    return document


def _dns_edns0_roundtrip_document(
    live: DnsEdnsPaddingRoundtripResult,
    *,
    payload: bytes,
    transport: TransportConfig,
) -> dict[str, Any]:
    received_json = EndpointReceiveResult(
        result=live.result,
        transport_kind="dns_edns0_padding",
        transport_record=live.capture_pcap,
    ).to_json()
    document: dict[str, Any] = {
        "command": "roundtrip",
        "session_id": live.receipt.session_id,
        "mechanism_id": live.receipt.mechanism_id,
        "payload_len": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "recovered_hex": live.result.payload.hex(),
        "recovered_sha256": hashlib.sha256(live.result.payload).hexdigest(),
        "matches": live.result.payload == payload,
        "transport": "dns_edns0_padding",
        "transport_record": str(live.capture_pcap),
        "dns_path": _dns_edns0_config_to_json(
            _dns_edns0_config_from_transport(transport, live.capture_pcap)
        ),
        "transport_metadata": _dns_edns0_transport_metadata(transport, live),
        "evidence": received_json["evidence"],
    }
    if live.capture_pcap.is_file():
        raw = live.capture_pcap.read_bytes()
        document["transport_artifact"] = {
            "kind": "transport_capture",
            "path": str(live.capture_pcap),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
        }
    return document


def _http2_hyper_h2_roundtrip_document(
    live: HyperH2PingRoundtripResult,
    *,
    payload: bytes,
) -> dict[str, Any]:
    received_json = EndpointReceiveResult(
        result=live.result,
        transport_kind="http2_hyper_h2",
        transport_record=live.transcript_json,
    ).to_json()
    document: dict[str, Any] = {
        "command": "roundtrip",
        "session_id": live.receipt.session_id,
        "mechanism_id": live.receipt.mechanism_id,
        "payload_len": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "recovered_hex": live.result.payload.hex(),
        "recovered_sha256": hashlib.sha256(live.result.payload).hexdigest(),
        "matches": live.result.payload == payload,
        "transport": "http2_hyper_h2",
        "expected_frames": live.receipt.carrier_units,
        "transport_metadata": live.transport_metadata,
        "evidence": received_json["evidence"],
    }
    if live.transcript_json is not None:
        document["transport_record"] = str(live.transcript_json)
        if live.transcript_json.is_file():
            raw = live.transcript_json.read_bytes()
            document["transport_artifact"] = {
                "kind": "http2_hyper_h2_transcript",
                "path": str(live.transcript_json),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": len(raw),
            }
    return document


def _quic_aioquic_roundtrip_document(
    live: AioquicConnectionIdRoundtripResult,
    *,
    payload: bytes,
) -> dict[str, Any]:
    received_json = EndpointReceiveResult(
        result=live.result,
        transport_kind="quic_aioquic_connection_id",
        transport_record=live.transcript_json,
    ).to_json()
    document: dict[str, Any] = {
        "command": "roundtrip",
        "session_id": live.receipt.session_id,
        "mechanism_id": live.receipt.mechanism_id,
        "payload_len": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "recovered_hex": live.result.payload.hex(),
        "recovered_sha256": hashlib.sha256(live.result.payload).hexdigest(),
        "matches": live.result.payload == payload,
        "transport": "quic_aioquic_connection_id",
        "expected_frames": live.receipt.carrier_units,
        "transport_metadata": live.transport_metadata,
        "evidence": received_json["evidence"],
    }
    if live.transcript_json is not None:
        document["transport_record"] = str(live.transcript_json)
        if live.transcript_json.is_file():
            raw = live.transcript_json.read_bytes()
            document["transport_artifact"] = {
                "kind": "quic_aioquic_transcript",
                "path": str(live.transcript_json),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": len(raw),
            }
    return document


def _http3_aioquic_settings_roundtrip_document(
    live: AioquicH3SettingsRoundtripResult,
    *,
    payload: bytes,
) -> dict[str, Any]:
    received_json = EndpointReceiveResult(
        result=live.result,
        transport_kind="http3_aioquic_reserved_settings",
        transport_record=live.transcript_json,
    ).to_json()
    document: dict[str, Any] = {
        "command": "roundtrip",
        "session_id": live.receipt.session_id,
        "mechanism_id": live.receipt.mechanism_id,
        "payload_len": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "recovered_hex": live.result.payload.hex(),
        "recovered_sha256": hashlib.sha256(live.result.payload).hexdigest(),
        "matches": live.result.payload == payload,
        "transport": "http3_aioquic_reserved_settings",
        "expected_frames": live.receipt.carrier_units,
        "transport_metadata": live.transport_metadata,
        "evidence": received_json["evidence"],
    }
    if live.transcript_json is not None:
        document["transport_record"] = str(live.transcript_json)
        if live.transcript_json.is_file():
            raw = live.transcript_json.read_bytes()
            document["transport_artifact"] = {
                "kind": "http3_aioquic_settings_transcript",
                "path": str(live.transcript_json),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": len(raw),
            }
    return document


def _dns_edns0_send_document(
    live: DnsEdnsPaddingSendResult,
    *,
    profile: MechanismProfile,
    payload: bytes,
    transport: TransportConfig,
) -> dict[str, Any]:
    document = build_send_envelope(live.receipt, payload, list(live.symbols), profile)
    document["transport"] = "dns_edns0_padding"
    document["expected_frames"] = live.receipt.carrier_units
    document["dns_path"] = _dns_edns0_config_to_json(
        _dns_edns0_config_from_transport(transport, None)
    )
    document["transport_metadata"] = _dns_edns0_send_metadata(transport, live)
    return document


def _dns_edns0_recv_document(
    live: DnsEdnsPaddingReceiveResult,
    *,
    expected_frames: int,
    transport: TransportConfig,
) -> dict[str, Any]:
    received_json = EndpointReceiveResult(
        result=live.result,
        transport_kind="dns_edns0_padding",
        transport_record=live.capture_pcap,
    ).to_json()
    document = _recv_document(received_json)
    document["transport"] = "dns_edns0_padding"
    document["expected_frames"] = expected_frames
    document["dns_path"] = _dns_edns0_config_to_json(
        _dns_edns0_config_from_transport(transport, live.capture_pcap)
    )
    document["transport_metadata"] = _dns_edns0_receive_metadata(transport, live)
    if live.capture_pcap.is_file():
        raw = live.capture_pcap.read_bytes()
        document["transport_artifact"] = {
            "kind": "transport_capture",
            "path": str(live.capture_pcap),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
        }
    return document


def _packet_path_config_from_transport(transport: TransportConfig) -> Ipv4PacketPathConfig:
    return Ipv4PacketPathConfig(
        sender_interface=transport.sender_interface,
        receiver_interface=transport.receiver_interface,
        src_mac=transport.src_mac,
        dst_mac=transport.dst_mac,
        src_ip=transport.src_ip,
        dst_ip=transport.dst_ip,
        src_port=transport.src_port,
        dst_port=transport.dst_port,
        protocol=PacketProtocol(transport.protocol),
        timeout_s=transport.timeout_s,
        expected_frames=transport.expected_frames,
        require_expected_frames=transport.require_expected_frames,
    )


def _packet_path_config_to_json(config: Ipv4PacketPathConfig) -> dict[str, Any]:
    return {
        "sender_interface": config.sender_interface,
        "receiver_interface": config.receiver_interface,
        "src_mac": config.src_mac,
        "dst_mac": config.dst_mac,
        "src_ip": config.src_ip,
        "dst_ip": config.dst_ip,
        "src_port": config.src_port,
        "dst_port": config.dst_port,
        "protocol": config.protocol.value,
        "timeout_s": config.timeout_s,
        "expected_frames": config.expected_frames,
        "require_expected_frames": config.require_expected_frames,
    }


def _capture_from_transport(
    transport: TransportConfig,
    capture_path: Path | None,
) -> TcpdumpCapture | None:
    if capture_path is None:
        return None
    return TcpdumpCapture(
        TcpdumpCaptureConfig(
            namespace=transport.capture_namespace,
            interface=transport.capture_interface or transport.receiver_interface,
            output=capture_path,
            packet_count=transport.expected_frames,
            filter_expr=transport.capture_filter,
            snaplen=transport.capture_snaplen,
            require_output=transport.capture_require_output,
        )
    )


def _endpoint_capture_path(
    transport: TransportConfig,
    scenario_id: str,
    *,
    explicit: Path | None,
) -> Path | None:
    if explicit is not None:
        return explicit
    raw = transport.capture_pcap
    if raw is None:
        return None
    safe_scenario = _safe_artifact_name(scenario_id)
    if "{" in raw or "}" in raw:
        try:
            return Path(raw.format(scenario_id=safe_scenario, case="endpoint"))
        except (KeyError, ValueError) as exc:
            raise ValueError(f"invalid capture_pcap template: {raw}") from exc
    path = Path(raw)
    if path.suffix:
        return path.with_name(f"{path.stem}-endpoint{path.suffix}")
    return path / f"{safe_scenario}-endpoint.pcap"


def _dns_edns0_config_from_transport(
    transport: TransportConfig,
    capture_path: str | Path | None,
) -> DnsEdnsPaddingPathConfig:
    return DnsEdnsPaddingPathConfig(
        sender_namespace=transport.dns_sender_namespace,
        resolver_namespace=transport.dns_resolver_namespace,
        sender_address=transport.src_ip,
        resolver_address=transport.dst_ip,
        query_name=transport.dns_query_name,
        answer_address=transport.dns_answer_address or transport.dst_ip,
        port=transport.dst_port,
        padding_optcode=transport.dns_padding_optcode,
        timeout_s=transport.timeout_s or 2.0,
        tries=transport.dns_tries,
        capture_interface=transport.capture_interface or transport.receiver_interface,
        capture_pcap=None if capture_path is None else Path(capture_path),
        capture_filter=transport.capture_filter,
        capture_snaplen=transport.capture_snaplen,
        capture_require_output=transport.capture_require_output,
        capture_start_delay_s=transport.dns_capture_start_delay_s,
        require_answer=transport.dns_require_answer,
    )


def _dns_edns0_config_to_json(config: DnsEdnsPaddingPathConfig) -> dict[str, Any]:
    return {
        "sender_namespace": config.sender_namespace,
        "resolver_namespace": config.resolver_namespace,
        "sender_address": config.sender_address,
        "resolver_address": config.resolver_address,
        "query_name": config.query_name,
        "answer_address": config.answer_address,
        "port": config.port,
        "padding_optcode": config.padding_optcode,
        "timeout_s": config.timeout_s,
        "tries": config.tries,
        "capture_interface": config.capture_interface,
        "capture_pcap": str(config.capture_pcap) if config.capture_pcap is not None else None,
        "capture_filter": list(config.capture_filter),
        "capture_snaplen": config.capture_snaplen,
        "capture_require_output": config.capture_require_output,
        "capture_start_delay_s": config.capture_start_delay_s,
        "require_answer": config.require_answer,
    }


def _http2_hyper_h2_config_from_transport(
    transport: TransportConfig,
    scenario_id: str,
) -> HyperH2PingPathConfig:
    return HyperH2PingPathConfig(
        transcript_json=_endpoint_http2_transcript_path(transport, scenario_id),
        validate_ack=transport.http2_validate_ack,
    )


def _quic_aioquic_config_from_transport(
    transport: TransportConfig,
    scenario_id: str,
) -> AioquicConnectionIdPathConfig:
    return AioquicConnectionIdPathConfig(
        transcript_json=_endpoint_quic_transcript_path(transport, scenario_id),
        validate_server_response=transport.quic_validate_server_response,
    )


def _http3_aioquic_settings_config_from_transport(
    transport: TransportConfig,
    scenario_id: str,
) -> AioquicH3SettingsPathConfig:
    return AioquicH3SettingsPathConfig(
        transcript_json=_endpoint_http3_transcript_path(transport, scenario_id),
        validate_receiver_settings=transport.http3_validate_receiver_settings,
    )


def _dns_edns0_transport_metadata(
    transport: TransportConfig,
    live: DnsEdnsPaddingRoundtripResult,
) -> dict[str, Any]:
    return {
        "schema_version": "celatim.transport_metadata.dns_edns0_padding.v1",
        "query_name": transport.dns_query_name,
        "resolver_address": transport.dst_ip,
        "port": transport.dst_port,
        "padding_optcode": transport.dns_padding_optcode,
        "answer_count": len(live.answers),
        "answers": list(live.answers),
        "daemon_readiness": live.daemon_readiness,
        "tool_versions": [record.to_json() for record in live.tool_versions],
    }


def _dns_edns0_send_metadata(
    transport: TransportConfig,
    live: DnsEdnsPaddingSendResult,
) -> dict[str, Any]:
    return {
        "schema_version": "celatim.transport_metadata.dns_edns0_padding.v1",
        "query_name": transport.dns_query_name,
        "resolver_address": transport.dst_ip,
        "port": transport.dst_port,
        "padding_optcode": transport.dns_padding_optcode,
        "answer_count": len(live.answers),
        "answers": list(live.answers),
        "daemon_readiness": None,
        "tool_versions": [record.to_json() for record in live.tool_versions],
    }


def _dns_edns0_receive_metadata(
    transport: TransportConfig,
    live: DnsEdnsPaddingReceiveResult,
) -> dict[str, Any]:
    return {
        "schema_version": "celatim.transport_metadata.dns_edns0_padding.v1",
        "query_name": transport.dns_query_name,
        "resolver_address": transport.dst_ip,
        "port": transport.dst_port,
        "padding_optcode": transport.dns_padding_optcode,
        "answer_count": 0,
        "answers": [],
        "daemon_readiness": live.daemon_readiness,
        "tool_versions": [record.to_json() for record in live.tool_versions],
    }


def _crypto_write_transport(
    profile: MechanismProfile,
    transport: TransportConfig,
    transcript_path: Path,
) -> EcdsaNonceTranscriptTransport | RsaPssSaltTranscriptTransport:
    if transport.kind == ECDSA_NONCE_TRANSPORT_KIND:
        return EcdsaNonceTranscriptTransport(
            profile,
            EcdsaNonceTranscriptConfig(
                transcript_path=transcript_path,
                curve=transport.crypto_curve,
                hash_name=transport.crypto_hash_name,
                nonce_payload_bits=transport.crypto_nonce_payload_bits,
                honest_random_control_signatures=(
                    transport.crypto_honest_random_control_signatures
                ),
                message_prefix=transport.crypto_message_prefix,
            ),
        )
    if transport.kind == RSA_PSS_SALT_TRANSPORT_KIND:
        return RsaPssSaltTranscriptTransport(
            profile,
            RsaPssSaltTranscriptConfig(
                transcript_path=transcript_path,
                key_bits=transport.crypto_key_bits,
                public_exponent=transport.crypto_public_exponent,
                hash_name=transport.crypto_hash_name,
                mgf_hash_name=transport.crypto_mgf_hash_name,
                salt_payload_bits=transport.crypto_salt_payload_bits,
                honest_random_control_signatures=(
                    transport.crypto_honest_random_control_signatures
                ),
                message_prefix=transport.crypto_message_prefix,
            ),
        )
    raise ValueError(f"unsupported crypto transcript transport: {transport.kind}")


def _crypto_replay_transport(
    profile: MechanismProfile,
    transport_kind: str,
    transcript_path: Path,
) -> EcdsaNonceTranscriptReplayTransport | RsaPssSaltTranscriptReplayTransport:
    if transport_kind == ECDSA_NONCE_TRANSPORT_KIND:
        return EcdsaNonceTranscriptReplayTransport(profile, transcript_path)
    if transport_kind == RSA_PSS_SALT_TRANSPORT_KIND:
        return RsaPssSaltTranscriptReplayTransport(profile, transcript_path)
    raise ValueError(f"unsupported crypto transcript transport: {transport_kind}")


def _endpoint_transcript_path(transport: TransportConfig, scenario_id: str) -> Path:
    raw = transport.crypto_transcript_json
    if raw is None:
        raise ValueError(f"{transport.kind} endpoint transport requires --transcript-json")
    safe_scenario = _safe_artifact_name(scenario_id)
    if "{" in raw or "}" in raw:
        try:
            return Path(raw.format(scenario_id=safe_scenario, case="endpoint"))
        except (KeyError, ValueError) as exc:
            raise ValueError(f"invalid transcript-json template: {raw}") from exc
    path = Path(raw)
    if path.suffix:
        return path.with_name(f"{path.stem}-endpoint{path.suffix}")
    return path / f"{safe_scenario}-endpoint.json"


def _endpoint_http2_transcript_path(
    transport: TransportConfig,
    scenario_id: str,
) -> Path | None:
    raw = transport.http2_transcript_json
    if raw is None:
        return None
    safe_scenario = _safe_artifact_name(scenario_id)
    if "{" in raw or "}" in raw:
        try:
            return Path(raw.format(scenario_id=safe_scenario, case="endpoint"))
        except (KeyError, ValueError) as exc:
            raise ValueError(f"invalid transcript-json template: {raw}") from exc
    path = Path(raw)
    if path.suffix:
        return path.with_name(f"{path.stem}-endpoint{path.suffix}")
    return path / f"{safe_scenario}-endpoint.json"


def _endpoint_http3_transcript_path(
    transport: TransportConfig,
    scenario_id: str,
) -> Path | None:
    raw = transport.http3_transcript_json
    if raw is None:
        return None
    safe_scenario = _safe_artifact_name(scenario_id)
    if "{" in raw or "}" in raw:
        try:
            return Path(raw.format(scenario_id=safe_scenario, case="endpoint"))
        except (KeyError, ValueError) as exc:
            raise ValueError(f"invalid transcript-json template: {raw}") from exc
    path = Path(raw)
    if path.suffix:
        return path.with_name(f"{path.stem}-endpoint{path.suffix}")
    return path / f"{safe_scenario}-endpoint.json"


def _endpoint_quic_transcript_path(
    transport: TransportConfig,
    scenario_id: str,
) -> Path | None:
    raw = transport.quic_transcript_json
    if raw is None:
        return None
    safe_scenario = _safe_artifact_name(scenario_id)
    if "{" in raw or "}" in raw:
        try:
            return Path(raw.format(scenario_id=safe_scenario, case="endpoint"))
        except (KeyError, ValueError) as exc:
            raise ValueError(f"invalid transcript-json template: {raw}") from exc
    path = Path(raw)
    if path.suffix:
        return path.with_name(f"{path.stem}-endpoint{path.suffix}")
    return path / f"{safe_scenario}-endpoint.json"


def _safe_artifact_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "artifact"


def _transport_scenario_id(
    args: argparse.Namespace,
    scenario: ScenarioConfig | None,
    mechanism: str,
) -> str:
    if scenario is not None:
        return scenario.scenario_id
    if getattr(args, "session_id", None) is not None:
        return str(args.session_id)
    return mechanism


def _payload_from_args(args: argparse.Namespace, default: object = _MISSING) -> bytes:
    if args.message is not None:
        return payload_from_text(args.message)
    if args.hex_payload is not None:
        return payload_from_hex(args.hex_payload)
    if args.file is not None:
        return payload_from_file(args.file)
    if default is not _MISSING:
        if not isinstance(default, bytes):
            raise TypeError("payload default must be bytes")
        return default
    raise ValueError("payload required: set --message, --hex, --file, or select a scenario")


def _expected_payload_from_args(args: argparse.Namespace) -> bytes | None:
    if args.expect_message is not None:
        return payload_from_text(args.expect_message)
    if args.expect_hex is not None:
        return payload_from_hex(args.expect_hex)
    if args.expect_file is not None:
        return payload_from_file(args.expect_file)
    return None


def _apply_expected_payload(
    document: dict[str, Any],
    recovered: bytes,
    expected: bytes | None,
) -> None:
    if expected is None:
        return
    expected_sha256 = hashlib.sha256(expected).hexdigest()
    recovered_sha256 = hashlib.sha256(recovered).hexdigest()
    matches = recovered == expected
    document["expected_payload_len"] = len(expected)
    document["expected_payload_sha256"] = expected_sha256
    document["expected_matches"] = matches
    if not matches:
        raise ControlFailureError(
            "expected payload mismatch: "
            f"expected_len={len(expected)} expected_sha256={expected_sha256} "
            f"recovered_len={len(recovered)} recovered_sha256={recovered_sha256}"
        )


def _pacing_from_args(args: argparse.Namespace) -> PacingConfig | None:
    has_pacing = any(
        value is not None
        for value in (
            args.unit_rate_hz,
            args.symbol_period_s,
            args.timing_quantum_s,
            args.decode_tolerance_s,
            args.timeout_s,
        )
    )
    has_pacing = (
        has_pacing or args.base_delay_s != 0.0 or args.adaptive or args.jitter_sample_window != 0
    )
    if not has_pacing:
        return None
    return PacingConfig(
        unit_rate_hz=args.unit_rate_hz,
        symbol_period_s=args.symbol_period_s,
        base_delay_s=args.base_delay_s,
        timing_quantum_s=args.timing_quantum_s,
        decode_tolerance_s=args.decode_tolerance_s,
        timeout_s=args.timeout_s,
        adaptive=args.adaptive,
        jitter_sample_window=args.jitter_sample_window,
    )


def _reliability_from_args(args: argparse.Namespace) -> ReliabilityPolicy | None:
    if (
        args.max_receive_attempts is None
        and args.retry_backoff_s is None
        and args.max_retransmissions is None
        and not args.no_duplicate_suppression
    ):
        return None
    return ReliabilityPolicy(
        max_receive_attempts=args.max_receive_attempts
        if args.max_receive_attempts is not None
        else 1,
        retry_backoff_s=args.retry_backoff_s if args.retry_backoff_s is not None else 0.0,
        suppress_duplicate_chunks=not args.no_duplicate_suppression,
        max_retransmissions=args.max_retransmissions if args.max_retransmissions is not None else 0,
    )


def _transport_config_from_args(
    args: argparse.Namespace,
    default: TransportConfig | None = None,
    mechanism: str | None = None,
) -> TransportConfig:
    if args.afpacket_ipv4:
        return TransportConfig(
            "afpacket_ipv4",
            sender_interface=args.afpacket_sender_interface,
            receiver_interface=args.afpacket_receiver_interface,
            src_mac=args.afpacket_src_mac,
            dst_mac=args.afpacket_dst_mac,
            src_ip=args.afpacket_src_ip,
            dst_ip=args.afpacket_dst_ip,
            src_port=args.afpacket_src_port,
            dst_port=args.afpacket_dst_port,
            protocol=args.afpacket_protocol,
            timeout_s=args.afpacket_timeout_s,
            expected_frames=args.expected_frames,
            require_expected_frames=not args.allow_partial_afpacket,
            capture_pcap=None
            if args.afpacket_capture_pcap is None
            else str(args.afpacket_capture_pcap),
            capture_namespace=args.afpacket_capture_namespace,
            capture_interface=args.afpacket_capture_interface,
            capture_filter=tuple(args.afpacket_capture_filter),
            capture_snaplen=args.afpacket_capture_snaplen,
            capture_require_output=not args.allow_missing_afpacket_capture,
        )
    if args.timed_transport:
        return TransportConfig("timed_memory")
    if args.pcap_dir is not None:
        return TransportConfig("pcap", str(args.pcap_dir))
    if args.transport_dir is not None:
        return TransportConfig("file", str(args.transport_dir))
    if args.transcript_json is not None:
        if default is not None and default.kind == "http2_hyper_h2":
            return replace(default, http2_transcript_json=args.transcript_json)
        if default is not None and default.kind == "http3_aioquic_reserved_settings":
            return replace(default, http3_transcript_json=args.transcript_json)
        if default is not None and default.kind == "quic_aioquic_connection_id":
            return replace(default, quic_transcript_json=args.transcript_json)
        kind = _crypto_transport_kind(default, mechanism)
        if default is None:
            return TransportConfig(kind, crypto_transcript_json=args.transcript_json)
        return replace(default, kind=kind, crypto_transcript_json=args.transcript_json)
    if default is not None:
        return default
    return TransportConfig()


def _crypto_transport_kind(default: TransportConfig | None, mechanism: str | None) -> str:
    if default is not None and default.kind in {
        ECDSA_NONCE_TRANSPORT_KIND,
        RSA_PSS_SALT_TRANSPORT_KIND,
    }:
        return default.kind
    if mechanism == "ecdsa-nonce":
        return ECDSA_NONCE_TRANSPORT_KIND
    if mechanism == "rsa-pss-salt":
        return RSA_PSS_SALT_TRANSPORT_KIND
    raise ValueError("--transcript-json requires an ecdsa-nonce or rsa-pss-salt mechanism")


def _has_transport_override(args: argparse.Namespace) -> bool:
    return (
        args.transport_dir is not None
        or args.pcap_dir is not None
        or args.timed_transport
        or args.transcript_json is not None
        or args.afpacket_ipv4
    )


def _read_json_mapping(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text())
    except OSError as exc:
        raise SystemExit(f"{path}: could not read JSON: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"{path}: invalid JSON at line {exc.lineno} column {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(document, dict):
        raise SystemExit(f"{path}: expected a JSON object")
    return document


def _write_json(document: dict[str, Any], output: Path | None) -> int:
    text = json.dumps(document, sort_keys=True) + "\n"
    return _write_text(text, output)


def _write_text(text: str, output: Path | None) -> int:
    if output is None:
        sys.stdout.write(text)
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text)
    return 0


send_main = _send_main
recv_main = _recv_main
roundtrip_main = _roundtrip_main

__all__ = ["evidence_config_from_args", "recv_main", "roundtrip_main", "send_main"]
