"""aioquic HTTP/3 reserved SETTINGS path helpers."""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from time import monotonic
from typing import Any

from celatim.errors import TransportError
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

HTTP3_AIOQUIC_SETTINGS_TRANSPORT_KIND = "http3_aioquic_reserved_settings"
HTTP3_AIOQUIC_SETTINGS_TRANSCRIPT_SCHEMA_VERSION = "celatim.http3_aioquic_settings_transcript.v1"
HTTP3_AIOQUIC_SETTINGS_TRANSPORT_METADATA_SCHEMA_VERSION = (
    "celatim.transport_metadata.http3_aioquic_reserved_settings.v1"
)
HTTP3_AIOQUIC_SETTINGS_CLAIM_STATUS = "local_aioquic_h3_settings_reserved_value_controlled_hook"
HTTP3_RESERVED_SETTINGS_ID = 0x21
HTTP3_SETTINGS_VALUE_MAX = (1 << 62) - 1

type H3SettingsExchangeRunner = Callable[[tuple[int, ...], bool], dict[str, Any]]


@dataclass(frozen=True)
class AioquicH3SettingsPathConfig:
    transcript_json: Path | None = None
    validate_receiver_settings: bool = True


@dataclass(frozen=True)
class AioquicH3SettingsRoundtripResult:
    receipt: SendReceipt
    result: ReceiveResult
    symbols: tuple[Symbol, ...]
    transcript_json: Path | None
    transport_metadata: dict[str, Any]


class AioquicH3SettingsTransport:
    """Send HTTP/3 reserved SETTINGS values through aioquic H3 control streams."""

    def __init__(
        self,
        profile: MechanismProfile,
        config: AioquicH3SettingsPathConfig | None = None,
        *,
        exchange_runner: H3SettingsExchangeRunner | None = None,
    ) -> None:
        if profile.id != "http3-reserved-settings":
            raise TransportError(
                "http3_aioquic_reserved_settings transport only supports http3-reserved-settings"
            )
        self.profile = profile
        self.config = config or AioquicH3SettingsPathConfig()
        self._exchange_runner = exchange_runner or _run_h3_settings_exchange
        self._sessions: dict[str, list[Symbol]] = {}
        self._pacing: dict[str, PacingConfig | None] = {}
        self._metadata: dict[str, dict[str, Any]] = {}

    def send_symbols(
        self,
        session_id: str,
        symbols: list[Symbol],
        pacing: PacingConfig | None = None,
    ) -> None:
        setting_symbols = tuple(_settings_symbol(symbol) for symbol in symbols)
        transcript = self._exchange_runner(
            setting_symbols,
            self.config.validate_receiver_settings,
        )
        observed = [int(value) for value in transcript["observed_setting_values"]]
        if tuple(observed) != setting_symbols:
            raise TransportError("aioquic observed HTTP/3 SETTINGS values differ from sent symbols")
        transcript = {
            **transcript,
            "session_id": session_id,
            "mechanism_id": self.profile.id,
            "transport_kind": HTTP3_AIOQUIC_SETTINGS_TRANSPORT_KIND,
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
            raise TransportError(
                f"no aioquic H3 SETTINGS symbols for session: {session_id}"
            ) from exc

    def pacing_for(self, session_id: str) -> PacingConfig | None:
        return self._pacing.get(session_id)

    def metadata_for(self, session_id: str) -> dict[str, Any]:
        try:
            return dict(self._metadata[session_id])
        except KeyError as exc:
            raise TransportError(f"no aioquic H3 metadata for session: {session_id}") from exc


def run_aioquic_h3_settings_roundtrip(
    profile: MechanismProfile,
    payload: bytes,
    *,
    session_id: str | None = None,
    config: AioquicH3SettingsPathConfig | None = None,
    pacing: PacingConfig | None = None,
    reliability: ReliabilityPolicy | None = None,
    exchange_runner: H3SettingsExchangeRunner | None = None,
) -> AioquicH3SettingsRoundtripResult:
    """Run a local aioquic HTTP/3 SETTINGS exchange using caller-controlled values."""

    active_config = config or AioquicH3SettingsPathConfig()
    endpoint_os = local_endpoint_os(
        "same_process",
        notes=(
            "client and receiver are independent aioquic H3Connection instances in one Python process",
            "client reserved SETTINGS value is set through a controlled local-settings hook before aioquic serializes the H3 control stream",
        ),
    )
    transport = AioquicH3SettingsTransport(
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
    return AioquicH3SettingsRoundtripResult(
        receipt=receipt,
        result=result,
        symbols=tuple(transport.receive_symbols(receipt.session_id)),
        transcript_json=active_config.transcript_json,
        transport_metadata=metadata,
    )


def _run_h3_settings_exchange(
    symbols: tuple[int, ...],
    validate_receiver_settings: bool,
) -> dict[str, Any]:
    modules = _aioquic_h3_modules()
    cert, key = _self_signed_certificate()
    observed_values: list[int] = []
    records: list[dict[str, Any]] = []
    for index, value in enumerate(symbols):
        client_config = modules["QuicConfiguration"](is_client=True, alpn_protocols=["h3"])
        client_quic = modules["QuicConnection"](configuration=client_config)
        client_h3 = _H3ConnectionWithReservedSetting(
            client_quic,
            reserved_setting_value=value,
            h3_connection_cls=modules["H3Connection"],
            setting_cls=modules["Setting"],
        )
        control_stream_id = client_h3.local_control_stream_id
        control_stream = client_quic._streams[control_stream_id]
        control_stream_bytes = bytes(control_stream.sender._buffer)

        server_config = modules["QuicConfiguration"](
            is_client=False,
            alpn_protocols=["h3"],
            certificate=cert,
            private_key=key,
        )
        server_quic = modules["QuicConnection"](
            configuration=server_config,
            original_destination_connection_id=b"rfch3cid",
        )
        server_h3 = modules["H3Connection"](server_quic)
        server_h3.handle_event(
            modules["StreamDataReceived"](
                data=control_stream_bytes,
                end_stream=False,
                stream_id=control_stream_id,
            )
        )
        received_settings = dict(server_h3.received_settings)
        observed = int(received_settings.get(HTTP3_RESERVED_SETTINGS_ID, -1))
        if validate_receiver_settings and observed != value:
            raise TransportError(f"aioquic H3 SETTINGS value mismatch at index {index}")
        observed_values.append(observed)
        records.append(
            {
                "index": index,
                "reserved_setting_id": HTTP3_RESERVED_SETTINGS_ID,
                "sent_setting_value": value,
                "observed_setting_value": observed,
                "control_stream_id": control_stream_id,
                "control_stream_len": len(control_stream_bytes),
                "control_stream_sha256": _sha256_hex(control_stream_bytes),
                "receiver_settings": {
                    str(setting): setting_value
                    for setting, setting_value in sorted(received_settings.items())
                },
            }
        )

    return {
        "schema_version": HTTP3_AIOQUIC_SETTINGS_TRANSCRIPT_SCHEMA_VERSION,
        "implementation": "aioquic.h3",
        "aioquic_version": _aioquic_version(),
        "claim_status": HTTP3_AIOQUIC_SETTINGS_CLAIM_STATUS,
        "controlled_hook": "H3Connection._get_local_settings reserved DUMMY value override",
        "validate_receiver_settings": validate_receiver_settings,
        "reserved_setting_id": HTTP3_RESERVED_SETTINGS_ID,
        "symbol_count": len(observed_values),
        "observed_setting_values": observed_values,
        "settings": records,
    }


class _H3ConnectionWithReservedSetting:
    def __init__(
        self,
        quic: Any,
        *,
        reserved_setting_value: int,
        h3_connection_cls: type[Any],
        setting_cls: Any,
    ) -> None:
        self._reserved_setting_value = reserved_setting_value
        self._setting_cls = setting_cls

        class CustomH3Connection(h3_connection_cls):
            def _get_local_settings(inner_self) -> dict[int, int]:
                settings = super()._get_local_settings()
                settings[setting_cls.DUMMY] = reserved_setting_value
                return settings

        self._connection = CustomH3Connection(quic)

    @property
    def local_control_stream_id(self) -> int:
        return int(self._connection._local_control_stream_id)


def _aioquic_h3_modules() -> dict[str, Any]:
    try:
        h3_module = importlib.import_module("aioquic.h3.connection")
        config_module = importlib.import_module("aioquic.quic.configuration")
        connection_module = importlib.import_module("aioquic.quic.connection")
        events_module = importlib.import_module("aioquic.quic.events")
    except ImportError as exc:
        raise TransportError(
            "http3_aioquic_reserved_settings transport requires aioquic; install celatim[daemon]"
        ) from exc
    return {
        "H3Connection": h3_module.H3Connection,
        "Setting": h3_module.Setting,
        "QuicConfiguration": config_module.QuicConfiguration,
        "QuicConnection": connection_module.QuicConnection,
        "StreamDataReceived": events_module.StreamDataReceived,
    }


def _self_signed_certificate() -> tuple[Any, Any]:
    try:
        x509 = importlib.import_module("cryptography.x509")
        oid = importlib.import_module("cryptography.x509.oid")
        hashes = importlib.import_module("cryptography.hazmat.primitives.hashes")
        rsa = importlib.import_module("cryptography.hazmat.primitives.asymmetric.rsa")
    except ImportError as exc:
        raise TransportError("aioquic HTTP/3 server path requires cryptography") from exc
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


def _settings_symbol(symbol: Symbol) -> int:
    if not isinstance(symbol, int):
        raise TransportError("http3_aioquic_reserved_settings symbols must be integers")
    if not 0 <= symbol <= HTTP3_SETTINGS_VALUE_MAX:
        raise TransportError("HTTP/3 SETTINGS symbols must fit in 62 bits")
    return symbol


def _metadata_from_transcript(
    transcript: dict[str, Any],
    config: AioquicH3SettingsPathConfig,
) -> dict[str, Any]:
    return {
        "schema_version": HTTP3_AIOQUIC_SETTINGS_TRANSPORT_METADATA_SCHEMA_VERSION,
        "implementation": transcript["implementation"],
        "aioquic_version": transcript["aioquic_version"],
        "claim_status": transcript["claim_status"],
        "controlled_hook": transcript["controlled_hook"],
        "validate_receiver_settings": transcript["validate_receiver_settings"],
        "reserved_setting_id": transcript["reserved_setting_id"],
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
