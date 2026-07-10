"""Reusable transport and tap implementations."""

from __future__ import annotations

import json
import re
import struct
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from time import monotonic, sleep, time
from typing import Any

from .envelope import carrier_bytes_for_symbols, parse_envelope_symbols, sha256_hex, symbols_to_json
from .errors import ConfigurationError, ReceiveTimeoutError, TransportError
from .session import MechanismProfile, PacingConfig, Symbol, TimingTrace
from .testbed.packet_path import (
    build_ipv4_carrier_frame,
    build_tcp_reserved_bits_frame,
    carrier_payload_from_frame,
    default_ipv4_packet_path_config_for,
    tcp_reserved_bits_from_frame,
)

FILE_TRANSPORT_SCHEMA = "celatim.file_transport.v1"
PCAP_TRANSPORT_LINKTYPE_ETHERNET = 1
PCAP_TRANSPORT_LINKTYPE_USER0 = 147
_PCAP_GLOBAL = struct.Struct("<IHHIIII")
_PCAP_PACKET = struct.Struct("<IIII")
_PCAP_MAGIC = 0xA1B2C3D4
_PCAP_VERSION_MAJOR = 2
_PCAP_VERSION_MINOR = 4
_PCAP_SNAPLEN = 65535

type Clock = Callable[[], float]
type Sleeper = Callable[[float], None]


class FileTransport:
    """Persist carrier symbols to one JSON file per session.

    This is a real transport/tap implementation for local and multi-process tests. It
    is not a network path, but it exercises the same ``Transport``/``Tap`` protocol as
    future pcap, AF_PACKET, daemon, and VM transports. Real-PDU adapters write
    parser-visible carrier bytes and hashes into the record; reads validate those
    bytes before returning symbols to the session decoder.
    """

    def __init__(self, profile: MechanismProfile, root: Path | str) -> None:
        self.profile = profile
        self.root = Path(root)

    def send_symbols(
        self,
        session_id: str,
        symbols: list[Symbol],
        pacing: PacingConfig | None = None,
    ) -> None:
        path = self.path_for(session_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self._record(session_id, symbols, pacing), sort_keys=True) + "\n"
        )

    def receive_symbols(self, session_id: str) -> list[Symbol]:
        path = self.path_for(session_id)
        try:
            record = json.loads(path.read_text())
        except FileNotFoundError as exc:
            raise TransportError(f"no file transport record for session: {session_id}") from exc
        except json.JSONDecodeError as exc:
            raise TransportError(f"{path}: invalid file transport JSON: {exc}") from exc
        self._validate_record(record, session_id, path)
        try:
            return parse_envelope_symbols(record, self.profile).symbols
        except Exception as exc:
            raise TransportError(f"{path}: invalid carrier record: {exc}") from exc

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
                if "no file transport record" not in str(exc):
                    raise
                if monotonic() >= deadline:
                    raise ReceiveTimeoutError(
                        f"timed out waiting for file transport record: {session_id}"
                    ) from exc
                sleep(min(0.01, max(0.0, deadline - monotonic())))

    def pacing_for(self, session_id: str) -> PacingConfig | None:
        path = self.path_for(session_id)
        try:
            record = json.loads(path.read_text())
        except FileNotFoundError:
            return None
        return _pacing_from_json(record.get("pacing"))

    def path_for(self, session_id: str) -> Path:
        return self.root / f"{_safe_name(session_id)}.json"

    def _record(
        self,
        session_id: str,
        symbols: list[Symbol],
        pacing: PacingConfig | None,
    ) -> dict[str, Any]:
        symbol_encoding, encoded_symbols = symbols_to_json(symbols)
        carriers = carrier_bytes_for_symbols(self.profile, symbols)
        return {
            "schema_version": FILE_TRANSPORT_SCHEMA,
            "session_id": session_id,
            "mechanism_id": self.profile.id,
            "pacing": None if pacing is None else asdict(pacing),
            "symbol_encoding": symbol_encoding,
            "symbols": encoded_symbols,
            "carrier_encoding": "hex" if carriers else None,
            "carriers": [carrier.hex() for carrier in carriers],
            "carrier_units_with_bytes": len(carriers),
            "carrier_unit_sha256": [sha256_hex(carrier) for carrier in carriers],
        }

    def _validate_record(self, record: Any, session_id: str, path: Path) -> None:
        if not isinstance(record, dict):
            raise TransportError(f"{path}: file transport record must be an object")
        if record.get("schema_version") != FILE_TRANSPORT_SCHEMA:
            raise TransportError(f"{path}: unsupported file transport schema")
        if record.get("session_id") != session_id:
            raise TransportError(f"{path}: session id mismatch")
        if record.get("mechanism_id") != self.profile.id:
            raise TransportError(f"{path}: mechanism id mismatch")


class PcapTransport:
    """Persist parser-visible carrier bytes to a classic pcap file per session.

    This transport is an artifact/tap bridge, not a live NIC path. It requires a
    mechanism adapter that can build and parse real carrier bytes. New captures are
    standard Ethernet/IPv4 frames so external tools such as tcpdump can inspect them;
    legacy USER0 fixture captures are still readable for compatibility.
    """

    def __init__(self, profile: MechanismProfile, root: Path | str) -> None:
        self.profile = profile
        self.root = Path(root)
        self._pacing: dict[str, PacingConfig | None] = {}

    def send_symbols(
        self,
        session_id: str,
        symbols: list[Symbol],
        pacing: PacingConfig | None = None,
    ) -> None:
        records = _pcap_records_for_symbols(self.profile, symbols)
        if symbols and not records:
            raise TransportError(f"{self.profile.id}: pcap transport requires carrier bytes")
        path = self.path_for(session_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        _write_pcap(path, records, pacing, linktype=PCAP_TRANSPORT_LINKTYPE_ETHERNET)
        self._pacing[session_id] = pacing

    def receive_symbols(self, session_id: str) -> list[Symbol]:
        path = self.path_for(session_id)
        try:
            return list(extract_pcap_carriers(self.profile, path).symbols)
        except Exception as exc:
            raise TransportError(f"{path}: invalid pcap carrier bytes: {exc}") from exc

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
                if "no pcap transport record" not in str(exc):
                    raise
                if monotonic() >= deadline:
                    raise ReceiveTimeoutError(
                        f"timed out waiting for pcap transport record: {session_id}"
                    ) from exc
                sleep(min(0.01, max(0.0, deadline - monotonic())))

    def pacing_for(self, session_id: str) -> PacingConfig | None:
        return self._pacing.get(session_id)

    def path_for(self, session_id: str) -> Path:
        return self.root / f"{_safe_name(session_id)}.pcap"


class TimedMemoryTransport:
    """In-process transport that applies pacing and records observed send timestamps.

    This is intentionally local and dependency-free. It gives endpoint tests and
    scenario smoke runs a real timing boundary: caller-selected base delay and symbol
    period are applied through a sleeper, each carrier unit gets an observed timestamp,
    and the receiver exposes a ``TimingTrace`` in its evidence record.
    """

    def __init__(
        self,
        *,
        clock: Clock | None = None,
        sleeper: Sleeper | None = None,
        default_pacing: PacingConfig | None = None,
    ) -> None:
        self._clock = monotonic if clock is None else clock
        self._sleeper = sleep if sleeper is None else sleeper
        self._default_pacing = default_pacing
        self._sessions: dict[str, list[Symbol]] = {}
        self._pacing: dict[str, PacingConfig | None] = {}
        self._timing_traces: dict[str, TimingTrace] = {}

    def send_symbols(
        self,
        session_id: str,
        symbols: list[Symbol],
        pacing: PacingConfig | None = None,
    ) -> None:
        active_pacing = pacing or self._default_pacing
        scheduled_offsets = _scheduled_offsets(active_pacing, len(symbols))
        start = self._clock()
        observed_offsets: list[float] = []
        transmitted: list[Symbol] = []
        for symbol, scheduled_offset in zip(symbols, scheduled_offsets, strict=True):
            delay = start + scheduled_offset - self._clock()
            if delay > 0:
                self._sleeper(delay)
            transmitted.append(symbol)
            observed_offsets.append(self._clock() - start)
        self._sessions[session_id] = transmitted
        self._pacing[session_id] = active_pacing
        self._timing_traces[session_id] = TimingTrace.from_offsets(
            scheduled_offsets,
            tuple(observed_offsets),
        )

    def receive_symbols(self, session_id: str) -> list[Symbol]:
        try:
            return list(self._sessions[session_id])
        except KeyError as exc:
            raise TransportError(f"no timed memory symbols for session: {session_id}") from exc

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
                        f"timed out waiting for timed memory symbols: {session_id}"
                    ) from exc
                sleep(min(0.01, max(0.0, deadline - monotonic())))

    def pacing_for(self, session_id: str) -> PacingConfig | None:
        return self._pacing.get(session_id)

    def timing_trace_for(self, session_id: str) -> TimingTrace | None:
        return self._timing_traces.get(session_id)


@dataclass(frozen=True)
class PcapCarrierExtraction:
    """Carrier bytes and decoded symbols extracted from one classic pcap."""

    path: Path
    linktype: int
    packet_count: int
    carrier_bytes: tuple[bytes, ...]
    symbols: tuple[Symbol, ...]


def extract_pcap_carriers(profile: MechanismProfile, path: Path | str) -> PcapCarrierExtraction:
    """Extract parser-validated carrier symbols from a classic pcap artifact."""

    pcap_path = Path(path)
    pcap = _read_pcap(pcap_path)
    carriers = tuple(_carrier_bytes_from_pcap_records(profile, pcap))
    symbols = tuple(profile.adapter.parse_carrier(carrier) for carrier in carriers)
    return PcapCarrierExtraction(
        path=pcap_path,
        linktype=pcap.linktype,
        packet_count=len(pcap.records),
        carrier_bytes=carriers,
        symbols=symbols,
    )


def _pacing_from_json(value: Any) -> PacingConfig | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ConfigurationError("pacing must be an object or null")
    return PacingConfig(
        unit_rate_hz=value.get("unit_rate_hz"),
        symbol_period_s=value.get("symbol_period_s"),
        base_delay_s=value.get("base_delay_s", 0.0),
        timing_quantum_s=value.get("timing_quantum_s"),
        decode_tolerance_s=value.get("decode_tolerance_s"),
        timeout_s=value.get("timeout_s"),
        adaptive=value.get("adaptive", False),
        jitter_sample_window=value.get("jitter_sample_window", 0),
    )


def _scheduled_offsets(pacing: PacingConfig | None, symbol_count: int) -> tuple[float, ...]:
    if symbol_count < 0:
        raise ConfigurationError("symbol_count must be >= 0")
    if symbol_count == 0:
        return ()
    if pacing is None:
        return tuple(0.0 for _ in range(symbol_count))
    period = pacing.effective_symbol_period_s or 0.0
    return tuple(pacing.base_delay_s + index * period for index in range(symbol_count))


def _pcap_records_for_symbols(profile: MechanismProfile, symbols: list[Symbol]) -> list[bytes]:
    config = default_ipv4_packet_path_config_for(profile.id)
    if profile.id == "tcp-reserved-bits":
        records: list[bytes] = []
        for index, symbol in enumerate(symbols):
            if not isinstance(symbol, int):
                raise TransportError("tcp-reserved-bits pcap transport requires int symbols")
            records.append(build_tcp_reserved_bits_frame(config, symbol, index=index))
        return records
    carriers = carrier_bytes_for_symbols(profile, symbols)
    return [
        build_ipv4_carrier_frame(config, carrier, index=index)
        for index, carrier in enumerate(carriers)
    ]


class _PcapRecords:
    def __init__(self, linktype: int, records: list[bytes]) -> None:
        self.linktype = linktype
        self.records = records


def _carrier_bytes_from_pcap_records(
    profile: MechanismProfile,
    pcap: _PcapRecords,
) -> list[bytes]:
    if pcap.linktype == PCAP_TRANSPORT_LINKTYPE_USER0:
        return pcap.records
    if pcap.linktype != PCAP_TRANSPORT_LINKTYPE_ETHERNET:
        raise TransportError(f"{profile.id}: unsupported pcap linktype")
    config = default_ipv4_packet_path_config_for(profile.id)
    if profile.id == "tcp-reserved-bits":
        carriers: list[bytes] = []
        for frame in pcap.records:
            reserved = tcp_reserved_bits_from_frame(config, frame)
            if reserved is None:
                raise TransportError("pcap record is not a matching TCP reserved-bit frame")
            carriers.append(profile.adapter.build_carrier(reserved) or b"")
        return carriers
    carriers = []
    for frame in pcap.records:
        carrier = carrier_payload_from_frame(config, frame)
        if carrier is None:
            raise TransportError("pcap record is not a matching IPv4 carrier frame")
        carriers.append(carrier)
    return carriers


def _write_pcap(
    path: Path,
    records: list[bytes],
    pacing: PacingConfig | None,
    *,
    linktype: int,
) -> None:
    base = time()
    scheduled_offsets = _scheduled_offsets(pacing, len(records))
    with path.open("wb") as fh:
        fh.write(
            _PCAP_GLOBAL.pack(
                _PCAP_MAGIC,
                _PCAP_VERSION_MAJOR,
                _PCAP_VERSION_MINOR,
                0,
                0,
                _PCAP_SNAPLEN,
                linktype,
            )
        )
        for record, offset in zip(records, scheduled_offsets, strict=True):
            if len(record) > _PCAP_SNAPLEN:
                raise TransportError(f"{path}: pcap record exceeds snaplen")
            timestamp = base + offset
            ts_sec = int(timestamp)
            ts_usec = int((timestamp - ts_sec) * 1_000_000)
            fh.write(_PCAP_PACKET.pack(ts_sec, ts_usec, len(record), len(record)))
            fh.write(record)


def _read_pcap(path: Path) -> _PcapRecords:
    try:
        data = path.read_bytes()
    except FileNotFoundError as exc:
        raise TransportError(f"no pcap transport record for session: {path.stem}") from exc
    if len(data) < _PCAP_GLOBAL.size:
        raise TransportError(f"{path}: truncated pcap global header")
    magic, major, minor, _zone, _sigfigs, snaplen, linktype = _PCAP_GLOBAL.unpack(
        data[: _PCAP_GLOBAL.size]
    )
    if magic != _PCAP_MAGIC:
        raise TransportError(f"{path}: unsupported pcap byte order or magic")
    if (major, minor) != (_PCAP_VERSION_MAJOR, _PCAP_VERSION_MINOR):
        raise TransportError(f"{path}: unsupported pcap version")
    if linktype not in {PCAP_TRANSPORT_LINKTYPE_ETHERNET, PCAP_TRANSPORT_LINKTYPE_USER0}:
        raise TransportError(f"{path}: unsupported pcap linktype")
    offset = _PCAP_GLOBAL.size
    records: list[bytes] = []
    while offset < len(data):
        if len(data) - offset < _PCAP_PACKET.size:
            raise TransportError(f"{path}: truncated pcap packet header")
        _ts_sec, _ts_usec, incl_len, orig_len = _PCAP_PACKET.unpack(
            data[offset : offset + _PCAP_PACKET.size]
        )
        offset += _PCAP_PACKET.size
        if incl_len != orig_len:
            raise TransportError(f"{path}: truncated captured packet")
        if incl_len > snaplen:
            raise TransportError(f"{path}: packet length exceeds snaplen")
        if len(data) - offset < incl_len:
            raise TransportError(f"{path}: truncated pcap packet data")
        records.append(data[offset : offset + incl_len])
        offset += incl_len
    return _PcapRecords(linktype, records)


def _safe_name(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return safe or "session"


# Public transport surface. These are imported after the local implementations to
# keep the core transport module acyclic while presenting one coherent namespace.
from .crypto_transcript import (  # noqa: E402
    EcdsaNonceTranscriptReplayTransport,
    EcdsaNonceTranscriptTransport,
    RsaPssSaltTranscriptReplayTransport,
    RsaPssSaltTranscriptTransport,
)
from .session import InMemoryTransport  # noqa: E402
from .testbed import (  # noqa: E402
    AfpacketCarrierTransport,
    AfpacketRoundtripResult,
    AioquicConnectionIdPathConfig,
    AioquicConnectionIdRoundtripResult,
    AioquicConnectionIdTransport,
    AioquicH3SettingsPathConfig,
    AioquicH3SettingsRoundtripResult,
    AioquicH3SettingsTransport,
    DnsEdnsPaddingPathConfig,
    DnsEdnsPaddingReceiveResult,
    DnsEdnsPaddingRoundtripResult,
    DnsEdnsPaddingSendResult,
    DnsToolVersionRecord,
    HyperH2PingPathConfig,
    HyperH2PingRoundtripResult,
    HyperH2PingTransport,
    Ipv4PacketPathConfig,
    NetnsPair,
    NetnsPairConfig,
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

PacketPath = Ipv4PacketPathConfig
PcapTap = TcpdumpCaptureConfig


__all__ = [
    "FILE_TRANSPORT_SCHEMA",
    "PCAP_TRANSPORT_LINKTYPE_ETHERNET",
    "PCAP_TRANSPORT_LINKTYPE_USER0",
    "AfpacketCarrierTransport",
    "AfpacketRoundtripResult",
    "AioquicConnectionIdPathConfig",
    "AioquicConnectionIdRoundtripResult",
    "AioquicConnectionIdTransport",
    "AioquicH3SettingsPathConfig",
    "AioquicH3SettingsRoundtripResult",
    "AioquicH3SettingsTransport",
    "DnsEdnsPaddingPathConfig",
    "DnsEdnsPaddingReceiveResult",
    "DnsEdnsPaddingRoundtripResult",
    "DnsEdnsPaddingSendResult",
    "DnsToolVersionRecord",
    "EcdsaNonceTranscriptReplayTransport",
    "EcdsaNonceTranscriptTransport",
    "FileTransport",
    "HyperH2PingPathConfig",
    "HyperH2PingRoundtripResult",
    "HyperH2PingTransport",
    "InMemoryTransport",
    "Ipv4PacketPathConfig",
    "NetnsPair",
    "NetnsPairConfig",
    "PacketPath",
    "PacketProtocol",
    "PcapCarrierExtraction",
    "PcapTap",
    "PcapTransport",
    "RsaPssSaltTranscriptReplayTransport",
    "RsaPssSaltTranscriptTransport",
    "TcpdumpCapture",
    "TcpdumpCaptureConfig",
    "TimedMemoryTransport",
    "extract_pcap_carriers",
    "receive_dns_edns0_padding",
    "run_afpacket_roundtrip",
    "run_aioquic_connection_id_roundtrip",
    "run_aioquic_h3_settings_roundtrip",
    "run_dns_edns0_padding_roundtrip",
    "run_hyper_h2_ping_roundtrip",
    "send_dns_edns0_padding",
]
