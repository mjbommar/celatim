"""hyper-h2 HTTP/2 PING opaque-data path helpers."""

from __future__ import annotations

import hashlib
import importlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from time import monotonic
from typing import Any, cast

from celatim.errors import TransportError
from celatim.pdu.http2 import PING_OPAQUE_LEN
from celatim.session import (
    ChannelSession,
    MechanismProfile,
    PacingConfig,
    ReceiveResult,
    ReliabilityPolicy,
    SendReceipt,
    Symbol,
    local_endpoint_os,
)

HTTP2_HYPER_H2_TRANSPORT_KIND = "http2_hyper_h2"
HTTP2_HYPER_H2_TRANSCRIPT_SCHEMA_VERSION = "celatim.http2_hyper_h2_transcript.v1"
HTTP2_HYPER_H2_TRANSPORT_METADATA_SCHEMA_VERSION = "celatim.transport_metadata.http2_hyper_h2.v1"
HTTP2_HYPER_H2_CLAIM_STATUS = "local_hyper_h2_client_server_ping_path"

type H2ConnectionFactory = Callable[[bool], Any]


@dataclass(frozen=True)
class HyperH2PingPathConfig:
    transcript_json: Path | None = None
    validate_ack: bool = True


@dataclass(frozen=True)
class HyperH2PingRoundtripResult:
    receipt: SendReceipt
    result: ReceiveResult
    symbols: tuple[Symbol, ...]
    transcript_json: Path | None
    transport_metadata: dict[str, Any]


class HyperH2PingTransport:
    """Send PING opaque bytes through a client/server ``hyper-h2`` exchange."""

    def __init__(
        self,
        profile: MechanismProfile,
        config: HyperH2PingPathConfig | None = None,
        *,
        connection_factory: H2ConnectionFactory | None = None,
    ) -> None:
        if profile.id != "http2-ping-opaque":
            raise TransportError("http2_hyper_h2 transport only supports http2-ping-opaque")
        self.profile = profile
        self.config = config or HyperH2PingPathConfig()
        self._connection_factory = connection_factory
        self._sessions: dict[str, list[Symbol]] = {}
        self._pacing: dict[str, PacingConfig | None] = {}
        self._metadata: dict[str, dict[str, Any]] = {}

    def send_symbols(
        self,
        session_id: str,
        symbols: list[Symbol],
        pacing: PacingConfig | None = None,
    ) -> None:
        opaque_symbols = tuple(_opaque_symbol(symbol) for symbol in symbols)
        transcript = _run_hyper_h2_exchange(
            opaque_symbols,
            validate_ack=self.config.validate_ack,
            connection_factory=self._connection_factory,
        )
        transcript = {
            **transcript,
            "session_id": session_id,
            "mechanism_id": self.profile.id,
            "transport_kind": HTTP2_HYPER_H2_TRANSPORT_KIND,
        }
        ping_data = cast(list[bytes], transcript.pop("ping_data"))
        self._sessions[session_id] = list(ping_data)
        self._pacing[session_id] = pacing
        self._metadata[session_id] = _metadata_from_transcript(transcript, self.config)
        if self.config.transcript_json is not None:
            _write_transcript(self.config.transcript_json, transcript)

    def receive_symbols(self, session_id: str) -> list[Symbol]:
        try:
            return list(self._sessions[session_id])
        except KeyError as exc:
            raise TransportError(f"no hyper-h2 PING symbols for session: {session_id}") from exc

    def pacing_for(self, session_id: str) -> PacingConfig | None:
        return self._pacing.get(session_id)

    def metadata_for(self, session_id: str) -> dict[str, Any]:
        try:
            return dict(self._metadata[session_id])
        except KeyError as exc:
            raise TransportError(f"no hyper-h2 metadata for session: {session_id}") from exc


def run_hyper_h2_ping_roundtrip(
    profile: MechanismProfile,
    payload: bytes,
    *,
    session_id: str | None = None,
    config: HyperH2PingPathConfig | None = None,
    pacing: PacingConfig | None = None,
    reliability: ReliabilityPolicy | None = None,
    connection_factory: H2ConnectionFactory | None = None,
) -> HyperH2PingRoundtripResult:
    """Run a local real-library HTTP/2 PING exchange using ``hyper-h2``."""

    active_config = config or HyperH2PingPathConfig()
    endpoint_os = local_endpoint_os(
        "same_process",
        notes=(
            "client and receiver are independent hyper-h2 H2Connection instances in one Python process",
        ),
    )
    transport = HyperH2PingTransport(
        profile,
        active_config,
        connection_factory=connection_factory,
    )
    session = ChannelSession(
        profile,
        transport,
        reliability=reliability,
        endpoint_os=endpoint_os,
    )
    start = monotonic()
    receipt = session.send_message(payload, session_id=session_id, pacing=pacing)
    result = session.receive_message(receipt)
    metadata = transport.metadata_for(receipt.session_id)
    metadata["elapsed_exchange_s"] = monotonic() - start
    return HyperH2PingRoundtripResult(
        receipt=receipt,
        result=result,
        symbols=tuple(transport.receive_symbols(receipt.session_id)),
        transcript_json=active_config.transcript_json,
        transport_metadata=metadata,
    )


def _run_hyper_h2_exchange(
    symbols: tuple[bytes, ...],
    *,
    validate_ack: bool,
    connection_factory: H2ConnectionFactory | None,
) -> dict[str, Any]:
    factory = connection_factory or _default_h2_connection
    client = factory(True)
    server = factory(False)

    server.initiate_connection()
    server_settings = server.data_to_send()
    client.initiate_connection()
    client_preface = client.data_to_send()
    server_preface_events = server.receive_data(client_preface)
    server_settings_ack = server.data_to_send()
    client_settings_events = client.receive_data(server_settings + server_settings_ack)
    client_settings_ack = client.data_to_send()
    server_settings_events = server.receive_data(client_settings_ack) if client_settings_ack else []

    ping_data: list[bytes] = []
    ack_data: list[bytes] = []
    ping_frames: list[dict[str, Any]] = []
    for index, opaque in enumerate(symbols):
        client.ping(opaque)
        client_to_server = client.data_to_send()
        server_ping_events = server.receive_data(client_to_server)
        received = _ping_data_from_events(server_ping_events, "PingReceived")
        if received != [opaque]:
            raise TransportError(
                f"hyper-h2 server did not observe expected PING opaque data at index {index}"
            )
        server_to_client = server.data_to_send()
        client_ping_ack_events = client.receive_data(server_to_client)
        received_ack = _ping_data_from_events(client_ping_ack_events, "PingAckReceived")
        if validate_ack and received_ack != [opaque]:
            raise TransportError(
                f"hyper-h2 client did not observe expected PING ACK opaque data at index {index}"
            )
        ping_data.extend(received)
        ack_data.extend(received_ack)
        ping_frames.append(
            {
                "index": index,
                "opaque_hex": opaque.hex(),
                "client_to_server_len": len(client_to_server),
                "client_to_server_sha256": _sha256_hex(client_to_server),
                "server_to_client_len": len(server_to_client),
                "server_to_client_sha256": _sha256_hex(server_to_client),
                "server_event_types": _event_type_names(server_ping_events),
                "client_ack_event_types": _event_type_names(client_ping_ack_events),
            }
        )

    return {
        "schema_version": HTTP2_HYPER_H2_TRANSCRIPT_SCHEMA_VERSION,
        "implementation": "hyper-h2",
        "h2_version": _h2_version(),
        "claim_status": HTTP2_HYPER_H2_CLAIM_STATUS,
        "validate_ack": validate_ack,
        "client_preface_len": len(client_preface),
        "client_preface_sha256": _sha256_hex(client_preface),
        "server_settings_len": len(server_settings),
        "server_settings_sha256": _sha256_hex(server_settings),
        "server_settings_ack_len": len(server_settings_ack),
        "server_settings_ack_sha256": _sha256_hex(server_settings_ack),
        "client_settings_ack_len": len(client_settings_ack),
        "client_settings_ack_sha256": _sha256_hex(client_settings_ack),
        "server_preface_event_types": _event_type_names(server_preface_events),
        "client_settings_event_types": _event_type_names(client_settings_events),
        "server_settings_event_types": _event_type_names(server_settings_events),
        "ping_count": len(ping_data),
        "ping_ack_count": len(ack_data),
        "ping_data_hex": [value.hex() for value in ping_data],
        "ping_ack_data_hex": [value.hex() for value in ack_data],
        "ping_frames": ping_frames,
        "ping_data": ping_data,
    }


def _default_h2_connection(client_side: bool) -> Any:
    try:
        connection_module = importlib.import_module("h2.connection")
        config_module = importlib.import_module("h2.config")
    except ImportError as exc:
        raise TransportError(
            "http2_hyper_h2 transport requires the h2 package; install celatim[daemon]"
        ) from exc
    return connection_module.H2Connection(
        config=config_module.H2Configuration(client_side=client_side, header_encoding=None)
    )


def _opaque_symbol(symbol: Symbol) -> bytes:
    if not isinstance(symbol, bytes):
        raise TransportError("http2_hyper_h2 symbols must be bytes")
    if len(symbol) != PING_OPAQUE_LEN:
        raise TransportError(f"http2_hyper_h2 PING opaque symbols must be {PING_OPAQUE_LEN} bytes")
    return symbol


def _ping_data_from_events(events: Any, event_type_name: str) -> list[bytes]:
    values: list[bytes] = []
    for event in events:
        if type(event).__name__ == event_type_name and hasattr(event, "ping_data"):
            values.append(bytes(event.ping_data))
    return values


def _event_type_names(events: Any) -> list[str]:
    return [type(event).__name__ for event in events]


def _metadata_from_transcript(
    transcript: dict[str, Any],
    config: HyperH2PingPathConfig,
) -> dict[str, Any]:
    return {
        "schema_version": HTTP2_HYPER_H2_TRANSPORT_METADATA_SCHEMA_VERSION,
        "implementation": transcript["implementation"],
        "h2_version": transcript["h2_version"],
        "claim_status": transcript["claim_status"],
        "validate_ack": transcript["validate_ack"],
        "ping_count": transcript["ping_count"],
        "ping_ack_count": transcript["ping_ack_count"],
        "transcript_schema_version": transcript["schema_version"],
        "transcript_json": None if config.transcript_json is None else str(config.transcript_json),
    }


def _write_transcript(path: Path, transcript: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(transcript, indent=2, sort_keys=True) + "\n")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _h2_version() -> str | None:
    try:
        return version("h2")
    except PackageNotFoundError:
        return None
