"""Independent observer checks for parser-visible carrier fixtures.

These checks are intentionally separate from the generic field codec/framer path. They
act as small, mechanism-specific structure oracles over the carrier bytes emitted in an
evidence run: the target field must be at the expected protocol offset, surrounding
bytes must contain real non-zero structure, and the extracted field must match the
symbol that the session decoder consumed.
"""

from __future__ import annotations

import hashlib
import shutil
import struct
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .adapter import CarrierUnit
from .evidence import IndependentValidator
from .pdu.http2 import (
    EMPTY_SETTINGS_FRAME,
    FRAME_HEADER_LEN,
    FRAME_TYPE_PING,
    HTTP2_PREFACE,
    PING_OPAQUE_LEN,
    ping_opaque_offset,
)
from .pdu.quic import DCID_LEN, LONG_INITIAL_1BYTE_PN, QUIC_V1, dcid_offset
from .pdu.rtcp import (
    DEFAULT_APP_NAME,
    DEFAULT_SSRC,
    RTCP_APP_DATA_LEN,
    RTCP_APP_HEADER_LEN,
    RTCP_APP_PACKET_TYPE,
    RTCP_VERSION,
    app_data_offset,
)
from .pdu.tcp import (
    TCP_HEADER_BYTES,
    TCP_RESERVED_BITS_WIDTH,
    parse_tcp_header,
    tcp_reserved_bits_offset,
)


@dataclass(frozen=True)
class ObserverValidationRecord:
    """Aggregate result from one independent observer over one evidence case."""

    name: str
    validator: IndependentValidator
    ok: bool
    checked_units: int
    failed_units: int
    field_offset: int | None
    field_len: int | None
    extracted_field_sha256: tuple[str, ...]
    nonzero_surrounding_bytes_min: int | None
    error: str | None = None

    def to_json(self) -> dict[str, object]:
        return {
            "name": self.name,
            "validator": self.validator.value,
            "ok": self.ok,
            "checked_units": self.checked_units,
            "failed_units": self.failed_units,
            "field_offset": self.field_offset,
            "field_len": self.field_len,
            "extracted_field_sha256": list(self.extracted_field_sha256),
            "nonzero_surrounding_bytes_min": self.nonzero_surrounding_bytes_min,
            "error": self.error,
        }


@dataclass(frozen=True)
class ParserProvenanceRecord:
    """External parser/dissector provenance for one evidence case."""

    name: str
    parser_family: str
    implementation: str
    implementation_kind: str
    executed: bool
    result: str
    field_paths: tuple[str, ...]
    decode_as: tuple[str, ...]
    display_filter: str | None
    checked_units: int
    parsed_units: int
    failed_units: int
    command: tuple[str, ...]
    returncode: int | None
    stdout_sha256: str | None
    stderr_sha256: str | None
    stderr_excerpt: str | None
    notes: str

    def to_json(self) -> dict[str, object]:
        return {
            "name": self.name,
            "parser_family": self.parser_family,
            "implementation": self.implementation,
            "implementation_kind": self.implementation_kind,
            "executed": self.executed,
            "result": self.result,
            "field_paths": list(self.field_paths),
            "decode_as": list(self.decode_as),
            "display_filter": self.display_filter,
            "checked_units": self.checked_units,
            "parsed_units": self.parsed_units,
            "failed_units": self.failed_units,
            "command": list(self.command),
            "returncode": self.returncode,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "stderr_excerpt": self.stderr_excerpt,
            "notes": self.notes,
        }


@dataclass(frozen=True)
class ObserverMutationControlRecord:
    """Aggregate result from observer negative controls over one evidence case.

    ``ok`` means the mutation failed validation for every tested carrier unit, which
    is the desired discriminating-control outcome.
    """

    name: str
    control_type: str
    expected_failure: str
    ok: bool
    tested_units: int
    expected_failure_units: int
    unexpected_pass_units: int
    setup_failed_units: int
    error_samples: tuple[str, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "name": self.name,
            "control_type": self.control_type,
            "expected_failure": self.expected_failure,
            "ok": self.ok,
            "tested_units": self.tested_units,
            "expected_failure_units": self.expected_failure_units,
            "unexpected_pass_units": self.unexpected_pass_units,
            "setup_failed_units": self.setup_failed_units,
            "error_samples": list(self.error_samples),
        }


@dataclass(frozen=True)
class _ObservedField:
    field: bytes
    offset: int
    field_len: int
    nonzero_surrounding_bytes: int


type _CarrierObserver = Callable[[bytes], _ObservedField]
type _CarrierMutation = Callable[[_CarrierObserver, CarrierUnit], bytes]


@dataclass(frozen=True)
class _TsharkSpec:
    display_filter: str | None
    field_paths: tuple[str, ...]
    decode_as: tuple[str, ...] = ()


def observer_validations_for(
    mechanism_id: str,
    units: list[CarrierUnit],
) -> tuple[ObserverValidationRecord, ...]:
    """Return independent observer summaries for supported mechanism carrier units."""
    observer = _OBSERVERS.get(mechanism_id)
    if observer is None:
        return ()

    checked = 0
    failed = 0
    first_error: str | None = None
    field_offset: int | None = None
    field_len: int | None = None
    extracted_hashes: list[str] = []
    nonzero_min: int | None = None
    for unit in units:
        if unit.carrier is None:
            failed += 1
            first_error = first_error or f"unit {unit.index}: missing carrier bytes"
            continue
        checked += 1
        try:
            observed = observer(unit.carrier)
            if observed.field != _symbol_field_bytes(unit.symbol, observed.field_len):
                raise ValueError("observed field does not match decoded symbol")
        except Exception as exc:
            failed += 1
            first_error = first_error or f"unit {unit.index}: {exc}"
            continue
        field_offset = observed.offset if field_offset is None else field_offset
        field_len = observed.field_len if field_len is None else field_len
        extracted_hashes.append(hashlib.sha256(observed.field).hexdigest())
        nonzero_min = (
            observed.nonzero_surrounding_bytes
            if nonzero_min is None
            else min(nonzero_min, observed.nonzero_surrounding_bytes)
        )

    if checked == 0 and failed == 0:
        first_error = "no carrier units to observe"

    return (
        ObserverValidationRecord(
            name=f"{mechanism_id}-carrier-structure-oracle",
            validator=IndependentValidator.SECOND_PARSER,
            ok=checked > 0 and failed == 0,
            checked_units=checked,
            failed_units=failed,
            field_offset=field_offset,
            field_len=field_len,
            extracted_field_sha256=tuple(extracted_hashes),
            nonzero_surrounding_bytes_min=nonzero_min,
            error=first_error,
        ),
    )


def observer_mutation_controls_for(
    mechanism_id: str,
    units: list[CarrierUnit],
) -> tuple[ObserverMutationControlRecord, ...]:
    """Return observer-backed mutation controls for supported carrier fixtures."""
    observer = _OBSERVERS.get(mechanism_id)
    if observer is None:
        return ()
    return (
        _run_mutation_control(
            mechanism_id,
            "wrong_nominal_offset",
            "mutated carrier writes the symbol at carrier byte zero instead of the parsed field",
            observer,
            units,
            _mutate_wrong_nominal_offset,
        ),
        _run_mutation_control(
            mechanism_id,
            "zero_surrounding_bytes",
            "mutated carrier preserves the parsed field but removes non-zero protocol structure",
            observer,
            units,
            _mutate_zero_surrounding_bytes,
        ),
    )


def parser_provenance_for(
    mechanism_id: str,
    pcap_path: Path | str | None,
    *,
    tshark_path: str = "tshark",
) -> tuple[ParserProvenanceRecord, ...]:
    """Return optional tshark/Wireshark dissector provenance for a pcap artifact."""

    if pcap_path is None:
        return ()
    spec = _TSHARK_SPECS.get(mechanism_id)
    if spec is None:
        return ()
    return (_tshark_parser_record(mechanism_id, Path(pcap_path), spec, tshark_path),)


def _observe_http2_ping(carrier: bytes) -> _ObservedField:
    offset = ping_opaque_offset()
    field_len = PING_OPAQUE_LEN
    if not carrier.startswith(HTTP2_PREFACE):
        raise ValueError("missing HTTP/2 connection preface")
    settings_start = len(HTTP2_PREFACE)
    settings_end = settings_start + len(EMPTY_SETTINGS_FRAME)
    if carrier[settings_start:settings_end] != EMPTY_SETTINGS_FRAME:
        raise ValueError("missing empty HTTP/2 SETTINGS frame before PING")
    ping_start = settings_end
    ping_header = carrier[ping_start : ping_start + FRAME_HEADER_LEN]
    expected_ping_header = (
        field_len.to_bytes(3, "big") + bytes([FRAME_TYPE_PING, 0]) + (0).to_bytes(4, "big")
    )
    if ping_header != expected_ping_header:
        raise ValueError("PING frame header does not match fixture oracle")
    return _field_at(carrier, offset, field_len)


def _observe_quic_dcid(carrier: bytes) -> _ObservedField:
    offset = dcid_offset()
    field_len = DCID_LEN
    if len(carrier) < offset + field_len:
        raise ValueError("truncated QUIC DCID carrier")
    if carrier[0] != LONG_INITIAL_1BYTE_PN:
        raise ValueError("unexpected QUIC long-header first byte")
    if int.from_bytes(carrier[1:5], "big") != QUIC_V1:
        raise ValueError("unexpected QUIC version")
    if carrier[5] != field_len:
        raise ValueError("unexpected QUIC DCID length")
    scid_len_offset = offset + field_len
    if len(carrier) <= scid_len_offset or carrier[scid_len_offset] == 0:
        raise ValueError("missing non-empty QUIC SCID")
    return _field_at(carrier, offset, field_len)


def _observe_rtcp_app(carrier: bytes) -> _ObservedField:
    offset = app_data_offset()
    field_len = RTCP_APP_DATA_LEN
    if len(carrier) < offset + field_len:
        raise ValueError("truncated RTCP APP carrier")
    first = carrier[0]
    if first >> 6 != RTCP_VERSION or first & 0x20:
        raise ValueError("unexpected RTCP APP version or padding bit")
    if carrier[1] != RTCP_APP_PACKET_TYPE:
        raise ValueError("unexpected RTCP APP packet type")
    expected_len = (int.from_bytes(carrier[2:4], "big") + 1) * 4
    if expected_len != len(carrier):
        raise ValueError("RTCP APP length does not match carrier size")
    if int.from_bytes(carrier[4:8], "big") != DEFAULT_SSRC:
        raise ValueError("unexpected RTCP APP SSRC")
    if carrier[8:12] != DEFAULT_APP_NAME:
        raise ValueError("unexpected RTCP APP name")
    if offset != RTCP_APP_HEADER_LEN:
        raise ValueError("RTCP APP oracle offset mismatch")
    return _field_at(carrier, offset, field_len)


def _observe_tcp_reserved_bits(carrier: bytes) -> _ObservedField:
    offset = tcp_reserved_bits_offset()
    header = parse_tcp_header(carrier)
    if len(carrier) < TCP_HEADER_BYTES:
        raise ValueError("truncated TCP reserved-bit carrier")
    if header.src_port == 0 or header.dst_port == 0:
        raise ValueError("TCP ports must be non-zero")
    if header.seq == 0 or header.ack == 0 or header.window == 0:
        raise ValueError("TCP surrounding header fields must be non-zero")
    if header.flags == 0:
        raise ValueError("TCP control flags must be non-zero")
    observed = _field_at(carrier, offset, 1)
    return _ObservedField(
        field=bytes([(observed.field[0] & 0x0E) >> 1]),
        offset=offset,
        field_len=1,
        nonzero_surrounding_bytes=observed.nonzero_surrounding_bytes,
    )


def _field_at(carrier: bytes, offset: int, field_len: int) -> _ObservedField:
    end = offset + field_len
    if len(carrier) < end:
        raise ValueError("carrier truncated before observed field")
    surrounding = carrier[:offset] + carrier[end:]
    nonzero = sum(1 for byte in surrounding if byte != 0)
    if nonzero == 0:
        raise ValueError("carrier has no non-zero surrounding bytes")
    return _ObservedField(
        field=carrier[offset:end],
        offset=offset,
        field_len=field_len,
        nonzero_surrounding_bytes=nonzero,
    )


def _run_mutation_control(
    mechanism_id: str,
    control_type: str,
    expected_failure: str,
    observer: _CarrierObserver,
    units: list[CarrierUnit],
    mutate: _CarrierMutation,
) -> ObserverMutationControlRecord:
    tested = 0
    expected_failures = 0
    unexpected_passes = 0
    setup_failures = 0
    error_samples: list[str] = []
    for unit in units:
        try:
            mutated = mutate(observer, unit)
        except Exception as exc:
            setup_failures += 1
            _append_sample(error_samples, f"unit {unit.index}: setup failed: {exc}")
            continue
        tested += 1
        try:
            _validate_observed_unit(observer, unit, mutated)
        except Exception as exc:
            expected_failures += 1
            _append_sample(error_samples, f"unit {unit.index}: {exc}")
        else:
            unexpected_passes += 1
            _append_sample(error_samples, f"unit {unit.index}: mutation unexpectedly passed")
    return ObserverMutationControlRecord(
        name=f"{mechanism_id}-{control_type}-mutation-control",
        control_type=control_type,
        expected_failure=expected_failure,
        ok=tested > 0 and setup_failures == 0 and unexpected_passes == 0,
        tested_units=tested,
        expected_failure_units=expected_failures,
        unexpected_pass_units=unexpected_passes,
        setup_failed_units=setup_failures,
        error_samples=tuple(error_samples),
    )


def _mutate_wrong_nominal_offset(observer: _CarrierObserver, unit: CarrierUnit) -> bytes:
    if unit.carrier is None:
        raise ValueError("missing carrier bytes")
    observed = observer(unit.carrier)
    symbol = _symbol_field_bytes(unit.symbol, observed.field_len)
    mutated = bytearray(unit.carrier)
    mutated[observed.offset : observed.offset + observed.field_len] = b"\x00" * observed.field_len
    write_len = min(len(symbol), len(mutated))
    mutated[:write_len] = symbol[:write_len]
    return bytes(mutated)


def _mutate_zero_surrounding_bytes(observer: _CarrierObserver, unit: CarrierUnit) -> bytes:
    if unit.carrier is None:
        raise ValueError("missing carrier bytes")
    observed = observer(unit.carrier)
    symbol = _symbol_field_bytes(unit.symbol, observed.field_len)
    mutated = bytearray(len(unit.carrier))
    mutated[observed.offset : observed.offset + observed.field_len] = symbol[: observed.field_len]
    return bytes(mutated)


def _validate_observed_unit(
    observer: _CarrierObserver,
    unit: CarrierUnit,
    carrier: bytes,
) -> None:
    observed = observer(carrier)
    if observed.field != _symbol_field_bytes(unit.symbol, observed.field_len):
        raise ValueError("observed field does not match decoded symbol")


def _symbol_field_bytes(symbol: object, field_len: int) -> bytes:
    if isinstance(symbol, bytes):
        return symbol[:field_len]
    if isinstance(symbol, int):
        if field_len <= 0:
            raise ValueError("field_len must be > 0 for int-valued symbol")
        if not 0 <= symbol < (1 << (field_len * 8)):
            raise ValueError("int-valued symbol does not fit observed field")
        if field_len == 1 and symbol < (1 << TCP_RESERVED_BITS_WIDTH):
            return bytes([symbol])
        return symbol.to_bytes(field_len, "big")
    raise ValueError("observer expects an int or bytes-valued symbol")


def _append_sample(samples: list[str], value: str) -> None:
    if len(samples) < 3:
        samples.append(value)


_PCAP_GLOBAL = struct.Struct("<IHHIIII")
_PCAP_PACKET = struct.Struct("<IIII")
_PCAP_MAGIC = 0xA1B2C3D4


def _tshark_parser_record(
    mechanism_id: str,
    pcap_path: Path,
    spec: _TsharkSpec,
    tshark_path: str,
) -> ParserProvenanceRecord:
    checked_units = _classic_pcap_record_count(pcap_path)
    command = _tshark_command(tshark_path, pcap_path, spec)
    if shutil.which(tshark_path) is None:
        return ParserProvenanceRecord(
            name=f"{mechanism_id}-tshark-dissector",
            parser_family="packet_dissector",
            implementation="tshark/Wireshark display-field export",
            implementation_kind="independent_tool_output",
            executed=False,
            result="tool_missing",
            field_paths=spec.field_paths,
            decode_as=spec.decode_as,
            display_filter=spec.display_filter,
            checked_units=checked_units,
            parsed_units=0,
            failed_units=checked_units,
            command=command,
            returncode=None,
            stdout_sha256=None,
            stderr_sha256=None,
            stderr_excerpt=f"{tshark_path}: not found",
            notes="tshark was unavailable; dissector field export was not executed",
        )
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    stdout = completed.stdout
    stderr = completed.stderr
    parsed_units = _tshark_parsed_unit_count(stdout)
    failed = completed.returncode != 0
    return ParserProvenanceRecord(
        name=f"{mechanism_id}-tshark-dissector",
        parser_family="packet_dissector",
        implementation="tshark/Wireshark display-field export",
        implementation_kind="independent_tool_output",
        executed=not failed,
        result=_tshark_result(completed.returncode, parsed_units),
        field_paths=spec.field_paths,
        decode_as=spec.decode_as,
        display_filter=spec.display_filter,
        checked_units=checked_units,
        parsed_units=parsed_units,
        failed_units=checked_units if failed else max(checked_units - parsed_units, 0),
        command=command,
        returncode=completed.returncode,
        stdout_sha256=hashlib.sha256(stdout.encode()).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr.encode()).hexdigest(),
        stderr_excerpt=_excerpt(stderr),
        notes=(
            "independent tshark/Wireshark dissector field export over this pcap; "
            "field values are represented by stdout hash, not embedded verbatim"
        ),
    )


def _tshark_command(tshark_path: str, pcap_path: Path, spec: _TsharkSpec) -> tuple[str, ...]:
    command: list[str] = [tshark_path, "-r", str(pcap_path)]
    for decode in spec.decode_as:
        command.extend(("-d", decode))
    if spec.display_filter:
        command.extend(("-Y", spec.display_filter))
    command.extend(("-T", "fields", "-E", "separator=\t", "-e", "frame.number"))
    for field in spec.field_paths:
        command.extend(("-e", field))
    return tuple(command)


def _tshark_parsed_unit_count(stdout: str) -> int:
    count = 0
    for line in stdout.splitlines():
        columns = line.split("\t")
        if len(columns) > 1 and any(column.strip() for column in columns[1:]):
            count += 1
    return count


def _tshark_result(returncode: int, parsed_units: int) -> str:
    if returncode != 0:
        return "tool_failed"
    if parsed_units:
        return "parsed"
    return "not_parsed"


def _classic_pcap_record_count(path: Path) -> int:
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return 0
    if len(data) < _PCAP_GLOBAL.size:
        return 0
    magic, _major, _minor, _zone, _sigfigs, _snaplen, _linktype = _PCAP_GLOBAL.unpack(
        data[: _PCAP_GLOBAL.size]
    )
    if magic != _PCAP_MAGIC:
        return 0
    offset = _PCAP_GLOBAL.size
    count = 0
    while offset + _PCAP_PACKET.size <= len(data):
        _ts_sec, _ts_usec, incl_len, _orig_len = _PCAP_PACKET.unpack(
            data[offset : offset + _PCAP_PACKET.size]
        )
        offset += _PCAP_PACKET.size + incl_len
        if offset <= len(data):
            count += 1
    return count


def _excerpt(value: str, limit: int = 500) -> str | None:
    if not value:
        return None
    value = value.strip()
    if len(value) <= limit:
        return value
    return value[:limit] + "..."


_OBSERVERS: dict[str, _CarrierObserver] = {
    "http2-ping-opaque": _observe_http2_ping,
    "quic-connection-id": _observe_quic_dcid,
    "rtp-rtcp-ext-app": _observe_rtcp_app,
    "tcp-reserved-bits": _observe_tcp_reserved_bits,
}


_TSHARK_SPECS: dict[str, _TsharkSpec] = {
    "edns0-padding": _TsharkSpec(
        display_filter="dns",
        field_paths=("dns.opt.code", "dns.opt.data"),
    ),
    "http2-ping-opaque": _TsharkSpec(
        display_filter="http2",
        field_paths=("http2.type", "http2.ping.opaque_data"),
        decode_as=("tcp.port==443,http2",),
    ),
    "quic-connection-id": _TsharkSpec(
        display_filter="quic",
        field_paths=("quic.dcid",),
        decode_as=("udp.port==443,quic",),
    ),
    "rtp-rtcp-ext-app": _TsharkSpec(
        display_filter="rtcp",
        field_paths=("rtcp.app.name", "rtcp.app.data"),
        decode_as=("udp.port==5004,rtcp",),
    ),
    "tcp-reserved-bits": _TsharkSpec(
        display_filter="tcp",
        field_paths=("tcp.flags.res",),
    ),
}


__all__ = [
    "ObserverMutationControlRecord",
    "ObserverValidationRecord",
    "ParserProvenanceRecord",
    "observer_mutation_controls_for",
    "observer_validations_for",
    "parser_provenance_for",
]
