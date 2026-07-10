"""aioquic QUIC connection-ID path helpers."""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from time import monotonic, time
from typing import Any

from celatim.errors import TransportError
from celatim.pdu import DCID_LEN
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

QUIC_AIOQUIC_TRANSPORT_KIND = "quic_aioquic_connection_id"
QUIC_AIOQUIC_TRANSCRIPT_SCHEMA_VERSION = "celatim.quic_aioquic_transcript.v1"
QUIC_AIOQUIC_TRANSPORT_METADATA_SCHEMA_VERSION = (
    "celatim.transport_metadata.quic_aioquic_connection_id.v1"
)
QUIC_AIOQUIC_CLAIM_STATUS = "local_aioquic_client_server_initial_dcid_controlled_hook"

type AioquicExchangeRunner = Callable[[tuple[bytes, ...], bool], dict[str, Any]]


@dataclass(frozen=True)
class AioquicConnectionIdPathConfig:
    transcript_json: Path | None = None
    validate_server_response: bool = True


@dataclass(frozen=True)
class AioquicConnectionIdRoundtripResult:
    receipt: SendReceipt
    result: ReceiveResult
    symbols: tuple[Symbol, ...]
    transcript_json: Path | None
    transport_metadata: dict[str, Any]


class AioquicConnectionIdTransport:
    """Send QUIC DCID carrier symbols through aioquic Initial datagrams."""

    def __init__(
        self,
        profile: MechanismProfile,
        config: AioquicConnectionIdPathConfig | None = None,
        *,
        exchange_runner: AioquicExchangeRunner | None = None,
    ) -> None:
        if profile.id != "quic-connection-id":
            raise TransportError(
                "quic_aioquic_connection_id transport only supports quic-connection-id"
            )
        self.profile = profile
        self.config = config or AioquicConnectionIdPathConfig()
        self._exchange_runner = exchange_runner or _run_aioquic_exchange
        self._sessions: dict[str, list[Symbol]] = {}
        self._pacing: dict[str, PacingConfig | None] = {}
        self._metadata: dict[str, dict[str, Any]] = {}

    def send_symbols(
        self,
        session_id: str,
        symbols: list[Symbol],
        pacing: PacingConfig | None = None,
    ) -> None:
        dcid_symbols = tuple(_dcid_symbol(symbol) for symbol in symbols)
        transcript = self._exchange_runner(
            dcid_symbols,
            self.config.validate_server_response,
        )
        observed = [bytes.fromhex(value) for value in transcript["observed_dcid_hex"]]
        if tuple(observed) != dcid_symbols:
            raise TransportError("aioquic observed DCID symbols differ from sent symbols")
        transcript = {
            **transcript,
            "session_id": session_id,
            "mechanism_id": self.profile.id,
            "transport_kind": QUIC_AIOQUIC_TRANSPORT_KIND,
        }
        self._sessions[session_id] = list(observed)
        self._pacing[session_id] = pacing
        self._metadata[session_id] = _metadata_from_transcript(transcript, self.config)
        if self.config.transcript_json is not None:
            _write_transcript(self.config.transcript_json, transcript)

    def receive_symbols(self, session_id: str) -> list[Symbol]:
        try:
            return list(self._sessions[session_id])
        except KeyError as exc:
            raise TransportError(f"no aioquic DCID symbols for session: {session_id}") from exc

    def pacing_for(self, session_id: str) -> PacingConfig | None:
        return self._pacing.get(session_id)

    def metadata_for(self, session_id: str) -> dict[str, Any]:
        try:
            return dict(self._metadata[session_id])
        except KeyError as exc:
            raise TransportError(f"no aioquic metadata for session: {session_id}") from exc


def run_aioquic_connection_id_roundtrip(
    profile: MechanismProfile,
    payload: bytes,
    *,
    session_id: str | None = None,
    config: AioquicConnectionIdPathConfig | None = None,
    pacing: PacingConfig | None = None,
    reliability: ReliabilityPolicy | None = None,
    exchange_runner: AioquicExchangeRunner | None = None,
) -> AioquicConnectionIdRoundtripResult:
    """Run a local aioquic QUIC Initial exchange using caller-controlled DCIDs."""

    active_config = config or AioquicConnectionIdPathConfig()
    endpoint_os = local_endpoint_os(
        "same_process",
        notes=(
            "client and receiver are independent aioquic QuicConnection instances in one Python process",
            "client peer CID is set through a controlled pre-connect library hook before aioquic serializes the Initial datagram",
        ),
    )
    transport = AioquicConnectionIdTransport(
        profile,
        active_config,
        exchange_runner=exchange_runner,
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
    return AioquicConnectionIdRoundtripResult(
        receipt=receipt,
        result=result,
        symbols=tuple(transport.receive_symbols(receipt.session_id)),
        transcript_json=active_config.transcript_json,
        transport_metadata=metadata,
    )


def _run_aioquic_exchange(
    symbols: tuple[bytes, ...],
    validate_server_response: bool,
) -> dict[str, Any]:
    modules = _aioquic_modules()
    cert, key = _self_signed_certificate()
    observed_dcid: list[bytes] = []
    packets: list[dict[str, Any]] = []
    for index, dcid in enumerate(symbols):
        client_config = modules["QuicConfiguration"](
            is_client=True,
            alpn_protocols=["h3"],
            connection_id_length=DCID_LEN,
            verify_mode=False,
        )
        client = modules["QuicConnection"](configuration=client_config)
        client._peer_cid = modules["QuicConnectionId"](cid=dcid, sequence_number=None)
        now = time()
        client.connect(("127.0.0.1", 4433), now=now)
        client_datagrams = client.datagrams_to_send(now=now)
        if not client_datagrams:
            raise TransportError("aioquic client produced no Initial datagram")
        datagram = client_datagrams[0][0]
        header = modules["pull_quic_header"](
            modules["Buffer"](data=datagram),
            host_cid_length=DCID_LEN,
        )
        observed = bytes(header.destination_cid)
        if observed != dcid:
            raise TransportError(f"aioquic Initial DCID mismatch at index {index}")

        server_config = modules["QuicConfiguration"](
            is_client=False,
            alpn_protocols=["h3"],
            connection_id_length=DCID_LEN,
            certificate=cert,
            private_key=key,
        )
        server = modules["QuicConnection"](
            configuration=server_config,
            original_destination_connection_id=observed,
        )
        server.receive_datagram(datagram, ("127.0.0.1", 5555), now=now)
        server_datagrams = server.datagrams_to_send(now=now + 0.001)
        if validate_server_response and not server_datagrams:
            raise TransportError(f"aioquic server produced no response at index {index}")
        if bytes(server.original_destination_connection_id) != dcid:
            raise TransportError(f"aioquic server original DCID mismatch at index {index}")
        observed_dcid.append(observed)
        packets.append(
            {
                "index": index,
                "dcid_hex": observed.hex(),
                "client_initial_len": len(datagram),
                "client_initial_sha256": _sha256_hex(datagram),
                "client_scid_hex": bytes(header.source_cid).hex(),
                "server_response_count": len(server_datagrams),
                "server_response_lengths": [len(item[0]) for item in server_datagrams],
                "server_response_sha256": [_sha256_hex(item[0]) for item in server_datagrams],
            }
        )

    return {
        "schema_version": QUIC_AIOQUIC_TRANSCRIPT_SCHEMA_VERSION,
        "implementation": "aioquic",
        "aioquic_version": _aioquic_version(),
        "claim_status": QUIC_AIOQUIC_CLAIM_STATUS,
        "controlled_hook": "client._peer_cid set before QuicConnection.connect",
        "validate_server_response": validate_server_response,
        "symbol_count": len(observed_dcid),
        "observed_dcid_hex": [value.hex() for value in observed_dcid],
        "packets": packets,
    }


def _aioquic_modules() -> dict[str, Any]:
    try:
        buffer_module = importlib.import_module("aioquic.buffer")
        connection_module = importlib.import_module("aioquic.quic.connection")
        config_module = importlib.import_module("aioquic.quic.configuration")
        packet_module = importlib.import_module("aioquic.quic.packet")
    except ImportError as exc:
        raise TransportError(
            "quic_aioquic_connection_id transport requires aioquic; install celatim[daemon]"
        ) from exc
    return {
        "Buffer": buffer_module.Buffer,
        "QuicConnection": connection_module.QuicConnection,
        "QuicConnectionId": connection_module.QuicConnectionId,
        "QuicConfiguration": config_module.QuicConfiguration,
        "pull_quic_header": packet_module.pull_quic_header,
    }


def _self_signed_certificate() -> tuple[Any, Any]:
    try:
        x509 = importlib.import_module("cryptography.x509")
        oid = importlib.import_module("cryptography.x509.oid")
        hashes = importlib.import_module("cryptography.hazmat.primitives.hashes")
        rsa = importlib.import_module("cryptography.hazmat.primitives.asymmetric.rsa")
    except ImportError as exc:
        raise TransportError("aioquic server path requires cryptography") from exc
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.UTC)
    subject = issuer = x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _dcid_symbol(symbol: Symbol) -> bytes:
    if not isinstance(symbol, bytes):
        raise TransportError("quic_aioquic_connection_id symbols must be bytes")
    if len(symbol) != DCID_LEN:
        raise TransportError(f"quic_aioquic_connection_id DCID symbols must be {DCID_LEN} bytes")
    return symbol


def _metadata_from_transcript(
    transcript: dict[str, Any],
    config: AioquicConnectionIdPathConfig,
) -> dict[str, Any]:
    return {
        "schema_version": QUIC_AIOQUIC_TRANSPORT_METADATA_SCHEMA_VERSION,
        "implementation": transcript["implementation"],
        "aioquic_version": transcript["aioquic_version"],
        "claim_status": transcript["claim_status"],
        "controlled_hook": transcript["controlled_hook"],
        "validate_server_response": transcript["validate_server_response"],
        "symbol_count": transcript["symbol_count"],
        "transcript_schema_version": transcript["schema_version"],
        "transcript_json": None if config.transcript_json is None else str(config.transcript_json),
    }


def _write_transcript(path: Path, transcript: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(transcript, indent=2, sort_keys=True) + "\n")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _aioquic_version() -> str | None:
    try:
        return version("aioquic")
    except PackageNotFoundError:
        return None
