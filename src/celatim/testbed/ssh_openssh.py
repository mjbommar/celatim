"""Paramiko client to production OpenSSH SSH_MSG_KEXINIT path."""

from __future__ import annotations

import hashlib
import importlib
import json
import socket
from collections.abc import Callable
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from time import monotonic
from typing import Any, cast

from celatim.errors import TransportError
from celatim.pdu.ssh_kex import KEXINIT_CARRIER_LEN, SSH_MSG_KEXINIT
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

SSH_KEXINIT_OPENSSH_TRANSPORT_KIND = "ssh_kexinit_openssh"
SSH_KEXINIT_OPENSSH_TRANSCRIPT_SCHEMA_VERSION = "celatim.ssh_kexinit_openssh_transcript.v1"
SSH_KEXINIT_OPENSSH_TRANSPORT_METADATA_SCHEMA_VERSION = (
    "celatim.transport_metadata.ssh_kexinit_openssh.v1"
)
SSH_KEXINIT_OPENSSH_CLAIM_STATUS = "paramiko_client_openssh_daemon_completed_key_exchange"

type KexConnector = Callable[[bytes, "OpenSshKexinitPathConfig"], dict[str, Any]]


@dataclass(frozen=True)
class OpenSshKexinitPathConfig:
    host: str = "127.0.0.1"
    port: int = 22
    timeout_s: float = 10.0
    transcript_json: Path | None = None

    def __post_init__(self) -> None:
        if not self.host:
            raise ValueError("host must be non-empty")
        if self.port <= 0:
            raise ValueError("port must be > 0")
        if self.timeout_s <= 0:
            raise ValueError("timeout_s must be > 0")


@dataclass(frozen=True)
class OpenSshKexinitRoundtripResult:
    receipt: SendReceipt
    result: ReceiveResult
    symbols: tuple[Symbol, ...]
    transcript_json: Path | None
    transport_metadata: dict[str, Any]


class OpenSshKexinitTransport:
    """Complete a production OpenSSH key exchange for every KEXINIT cookie symbol."""

    def __init__(
        self,
        profile: MechanismProfile,
        config: OpenSshKexinitPathConfig | None = None,
        *,
        connector: KexConnector | None = None,
    ) -> None:
        if profile.id != "ssh-kexinit-cookie":
            raise TransportError("ssh_kexinit_openssh transport only supports ssh-kexinit-cookie")
        self.profile = profile
        self.config = config or OpenSshKexinitPathConfig()
        self._connector = connector or _complete_openssh_key_exchange
        self._sessions: dict[str, list[Symbol]] = {}
        self._pacing: dict[str, PacingConfig | None] = {}
        self._metadata: dict[str, dict[str, Any]] = {}

    def send_symbols(
        self,
        session_id: str,
        symbols: list[Symbol],
        pacing: PacingConfig | None = None,
    ) -> None:
        cookies = tuple(_cookie_symbol(symbol) for symbol in symbols)
        handshakes = [self._connector(cookie, self.config) for cookie in cookies]
        recovered = [bytes.fromhex(item["sent_cookie_hex"]) for item in handshakes]
        transcript = {
            "schema_version": SSH_KEXINIT_OPENSSH_TRANSCRIPT_SCHEMA_VERSION,
            "session_id": session_id,
            "mechanism_id": self.profile.id,
            "transport_kind": SSH_KEXINIT_OPENSSH_TRANSPORT_KIND,
            "claim_status": SSH_KEXINIT_OPENSSH_CLAIM_STATUS,
            "client_implementation": "paramiko",
            "paramiko_version": _paramiko_version(),
            "server_host": self.config.host,
            "server_port": self.config.port,
            "handshake_count": len(handshakes),
            "all_key_exchanges_completed": all(
                item["key_exchange_completed"] for item in handshakes
            ),
            "all_reserved_words_zero": all(
                item["reserved_uint32_hex"] == "00000000" for item in handshakes
            ),
            "handshakes": handshakes,
        }
        self._sessions[session_id] = list(recovered)
        self._pacing[session_id] = pacing
        self._metadata[session_id] = _metadata_from_transcript(transcript, self.config)
        if self.config.transcript_json is not None:
            _write_transcript(self.config.transcript_json, transcript)

    def receive_symbols(self, session_id: str) -> list[Symbol]:
        try:
            return list(self._sessions[session_id])
        except KeyError as exc:
            raise TransportError(f"no OpenSSH KEXINIT symbols for session: {session_id}") from exc

    def pacing_for(self, session_id: str) -> PacingConfig | None:
        return self._pacing.get(session_id)

    def metadata_for(self, session_id: str) -> dict[str, Any]:
        try:
            return dict(self._metadata[session_id])
        except KeyError as exc:
            raise TransportError(f"no OpenSSH KEXINIT metadata for session: {session_id}") from exc


def run_openssh_kexinit_roundtrip(
    profile: MechanismProfile,
    payload: bytes,
    *,
    session_id: str | None = None,
    config: OpenSshKexinitPathConfig | None = None,
    pacing: PacingConfig | None = None,
    reliability: ReliabilityPolicy | None = None,
    connector: KexConnector | None = None,
) -> OpenSshKexinitRoundtripResult:
    """Send a framed payload through Paramiko KEXINIT cookies to an OpenSSH daemon."""

    active_config = config or OpenSshKexinitPathConfig()
    endpoint_os = local_endpoint_os(
        "unknown",
        notes=(
            f"Paramiko client connects to an OpenSSH daemon at "
            f"{active_config.host}:{active_config.port}",
        ),
    )
    transport = OpenSshKexinitTransport(profile, active_config, connector=connector)
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
    return OpenSshKexinitRoundtripResult(
        receipt=receipt,
        result=result,
        symbols=tuple(transport.receive_symbols(receipt.session_id)),
        transcript_json=active_config.transcript_json,
        transport_metadata=metadata,
    )


def _complete_openssh_key_exchange(
    cookie: bytes,
    config: OpenSshKexinitPathConfig,
) -> dict[str, Any]:
    try:
        message_module = importlib.import_module("paramiko.message")
        transport_module = importlib.import_module("paramiko.transport")
    except ImportError as exc:
        raise TransportError(
            "ssh_kexinit_openssh transport requires paramiko; install celatim[ssh]"
        ) from exc

    message_class = message_module.Message
    base_transport = transport_module.Transport

    class CookieTransport(base_transport):  # type: ignore[misc, valid-type]
        def __init__(self, sock: socket.socket) -> None:
            self.carrier_wire: bytes | None = None
            super().__init__(sock)

        def _send_message(self, data: Any) -> Any:
            wire = bytes(data.asbytes())
            if (
                self.carrier_wire is None
                and not self.server_mode
                and wire[:1] == bytes([SSH_MSG_KEXINIT])
            ):
                wire = wire[:1] + cookie + wire[1 + KEXINIT_CARRIER_LEN :]
                self.local_kex_init = self._latest_kex_init = wire
                self.carrier_wire = wire
                data = message_class(wire)
            return super()._send_message(data)

    started = monotonic()
    sock = socket.create_connection((config.host, config.port), timeout=config.timeout_s)
    transport = CookieTransport(sock)
    try:
        transport.start_client(timeout=config.timeout_s)
        wire = transport.carrier_wire
        if wire is None:
            raise TransportError("Paramiko did not emit SSH_MSG_KEXINIT")
        if wire[-4:] != bytes(4):
            raise TransportError("SSH_MSG_KEXINIT reserved uint32 was not zero")
        host_key = transport.get_remote_server_key()
        if not transport.is_active():
            raise TransportError("OpenSSH transport was inactive after key exchange")
        return {
            "sent_cookie_hex": wire[1 : 1 + KEXINIT_CARRIER_LEN].hex(),
            "reserved_uint32_hex": wire[-4:].hex(),
            "kexinit_payload_len": len(wire),
            "kexinit_payload_sha256": hashlib.sha256(wire).hexdigest(),
            "key_exchange_completed": True,
            "remote_version": transport.remote_version,
            "host_key_type": host_key.get_name(),
            "host_key_sha256": hashlib.sha256(host_key.asbytes()).hexdigest(),
            "local_cipher": transport.local_cipher,
            "remote_cipher": transport.remote_cipher,
            "elapsed_s": monotonic() - started,
        }
    finally:
        transport.close()


def _cookie_symbol(symbol: Symbol) -> bytes:
    if not isinstance(symbol, bytes):
        raise TransportError("ssh_kexinit_openssh symbols must be bytes")
    if len(symbol) != KEXINIT_CARRIER_LEN:
        raise TransportError(
            f"ssh_kexinit_openssh cookie symbols must be {KEXINIT_CARRIER_LEN} bytes"
        )
    return symbol


def _metadata_from_transcript(
    transcript: dict[str, Any],
    config: OpenSshKexinitPathConfig,
) -> dict[str, Any]:
    handshakes = cast(list[dict[str, Any]], transcript["handshakes"])
    return {
        "schema_version": SSH_KEXINIT_OPENSSH_TRANSPORT_METADATA_SCHEMA_VERSION,
        "claim_status": transcript["claim_status"],
        "client_implementation": transcript["client_implementation"],
        "paramiko_version": transcript["paramiko_version"],
        "server_host": transcript["server_host"],
        "server_port": transcript["server_port"],
        "server_versions": sorted({item["remote_version"] for item in handshakes}),
        "handshake_count": transcript["handshake_count"],
        "all_key_exchanges_completed": transcript["all_key_exchanges_completed"],
        "all_reserved_words_zero": transcript["all_reserved_words_zero"],
        "transcript_schema_version": transcript["schema_version"],
        "transcript_json": None if config.transcript_json is None else str(config.transcript_json),
    }


def _write_transcript(path: Path, transcript: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(transcript, indent=2, sort_keys=True) + "\n")


def _paramiko_version() -> str | None:
    try:
        return version("paramiko")
    except PackageNotFoundError:
        return None


__all__ = [
    "SSH_KEXINIT_OPENSSH_CLAIM_STATUS",
    "SSH_KEXINIT_OPENSSH_TRANSCRIPT_SCHEMA_VERSION",
    "SSH_KEXINIT_OPENSSH_TRANSPORT_KIND",
    "SSH_KEXINIT_OPENSSH_TRANSPORT_METADATA_SCHEMA_VERSION",
    "OpenSshKexinitPathConfig",
    "OpenSshKexinitRoundtripResult",
    "OpenSshKexinitTransport",
    "run_openssh_kexinit_roundtrip",
]
