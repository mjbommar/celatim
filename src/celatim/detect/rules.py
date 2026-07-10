"""Emit stateless packet-filter rules for located, fixed-value mechanisms, and
bucket the whole catalog by where (if anywhere) it is observable.

Scope discipline (mirrors report/tables.py): an emitter only produces a rule for
a mechanism whose ``detectability`` is ``STATELESS_FILTER`` — located, cleartext,
and matchable with a fixed offset+mask. Everything else is returned by
``coverage()`` in its own bucket *with the reason it is not on-wire matchable*, so
the output never claims coverage it does not have. nftables raw-payload offsets
(``@base,offset,len``) are the locator verbatim; iptables u32 and BPF derive from
the same numbers.
"""

from __future__ import annotations

import hashlib
import shutil
import struct
import subprocess
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from ..adapter import CarrierUnit
from ..model import Detectability, DetectPredicate, FalsePositive, FieldLocator, Mechanism, WireBase

# Disposition follows the benign base rate: only never/rare-benign signals alert.
_DISPOSITION = {
    FalsePositive.BENIGN_NEVER: "alert",
    FalsePositive.BENIGN_RARE: "alert",
    FalsePositive.BENIGN_COMMON: "log",
    None: "log",
}

# BPF protocol accessor (header-relative indexing) by protocol name, else by base.
_BPF_BY_PROTO = {"ipv4": "ip", "ip": "ip", "ipv6": "ip6", "tcp": "tcp", "udp": "udp"}
_BPF_BY_BASE = {WireBase.NH: "ip", WireBase.TH: "tcp", WireBase.LL: "ether"}
_NFT_L4 = {"tcp": "tcp", "udp": "udp"}
_IPTABLES_U32_L4_PROTO = {"tcp": 6, "udp": 17}


class DetectorImplementationKind(str, Enum):
    SAME_CODE = "same_code"
    GENERATED_KERNEL_RULE = "generated_kernel_rule"
    INDEPENDENT_TOOL_OUTPUT = "independent_tool_output"


@dataclass(frozen=True)
class DetectorProvenanceRecord:
    """Reviewer-facing detector provenance for one evidence case.

    ``executed`` is intentionally separate from ``rule``. Generated packet-filter
    rules are useful artifacts, but they are not independent detector output until
    run against a trace.
    """

    name: str
    detector_family: str
    implementation: str
    implementation_kind: DetectorImplementationKind
    executed: bool
    result: str
    detectability: Detectability
    predicate: DetectPredicate | None
    disposition: str
    rule_format: str | None
    rule: str | None
    checked_units: int
    matched_units: int
    failed_units: int
    detected: bool | None
    benign_basis: str
    false_positive_estimate: bool
    command: tuple[str, ...]
    returncode: int | None
    stdout_sha256: str | None
    stderr_sha256: str | None
    stderr_excerpt: str | None
    notes: str

    def to_json(self) -> dict[str, object]:
        return {
            "name": self.name,
            "detector_family": self.detector_family,
            "implementation": self.implementation,
            "implementation_kind": self.implementation_kind.value,
            "executed": self.executed,
            "result": self.result,
            "detectability": self.detectability.value,
            "predicate": None if self.predicate is None else self.predicate.value,
            "disposition": self.disposition,
            "rule_format": self.rule_format,
            "rule": self.rule,
            "checked_units": self.checked_units,
            "matched_units": self.matched_units,
            "failed_units": self.failed_units,
            "detected": self.detected,
            "benign_basis": self.benign_basis,
            "false_positive_estimate": self.false_positive_estimate,
            "command": list(self.command),
            "returncode": self.returncode,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "stderr_excerpt": self.stderr_excerpt,
            "notes": self.notes,
        }


def _require_stateless(m: Mechanism) -> None:
    if m.detectability is not Detectability.STATELESS_FILTER:
        raise ValueError(
            f"{m.id}: not stateless-filterable ({m.detectability.value}); "
            f"see coverage() for the tier it needs"
        )
    if m.detect_predicate is DetectPredicate.NONZERO:
        return
    if m.detect_predicate is DetectPredicate.RESERVED_VALUE and m.reserved_value_matches:
        return
    raise ValueError(
        f"{m.id}: emitter supports NONZERO or RESERVED_VALUE with concrete "
        f"reserved_value_matches, got {m.detect_predicate}"
    )


def _has_supported_stateless_predicate(m: Mechanism) -> bool:
    if m.detectability is not Detectability.STATELESS_FILTER:
        return False
    if m.detect_predicate is DetectPredicate.NONZERO:
        return True
    return m.detect_predicate is DetectPredicate.RESERVED_VALUE and bool(m.reserved_value_matches)


def disposition(m: Mechanism) -> str:
    """'alert' for never/rare-benign signals, 'log' for benign-common (GREASE,
    padding, spin-bit randomization) — the 'worth further research' dial."""
    return _DISPOSITION[m.false_positive]


def nftables_rule(m: Mechanism) -> str:
    """An nftables rule line. The raw-payload expression is the locator verbatim."""
    _require_stateless(m)
    loc = m.locator
    assert loc is not None  # guaranteed by STATELESS_FILTER
    l4 = _NFT_L4.get(m.protocol.lower())
    guard = f"meta l4proto {l4} " if l4 else ""
    verb = (
        'log prefix "covert-chan "'
        if disposition(m) == "log"
        else 'log prefix "covert-chan " counter'
    )
    predicate = _nftables_predicate(m, loc)
    return f"{guard}{predicate} {verb}  # {m.id}: {disposition(m)} ({', '.join(m.rfcs)})"


def _nftables_predicate(m: Mechanism, loc: FieldLocator) -> str:
    field = f"@{loc.base.value},{loc.bit_offset},{loc.bit_width}"
    if m.detect_predicate is DetectPredicate.NONZERO:
        return f"{field} != 0"
    if m.detect_predicate is DetectPredicate.RESERVED_VALUE:
        terms = []
        for match in m.reserved_value_matches:
            if match.mask is None:
                terms.append(f"{field} == {_hex(match.value, loc.bit_width)}")
            else:
                terms.append(
                    f"({field} & {_hex(match.mask, loc.bit_width)} "
                    f"== {_hex(match.value, loc.bit_width)})"
                )
        return " or ".join(terms)
    raise ValueError(f"{m.id}: unsupported nftables predicate {m.detect_predicate}")


def _hex(value: int, width_bits: int | None = None) -> str:
    digits = 1 if width_bits is None else max(1, (width_bits + 3) // 4)
    return f"0x{value:0{digits}x}"


def _require_nonzero_stateless(m: Mechanism, emitter: str) -> None:
    _require_stateless(m)
    if m.detect_predicate is not DetectPredicate.NONZERO:
        raise ValueError(f"{m.id}: {emitter} emitter currently supports NONZERO only")


def _optional_rule(fn: Callable[[Mechanism], str], mechanism: Mechanism) -> str | None:
    try:
        return fn(mechanism)
    except ValueError:
        return None


def bpf_filter(m: Mechanism) -> str:
    """A libpcap/tcpdump filter expression. Single-byte fields only (BPF indexes
    bytes); wider fields are emitted by nftables instead."""
    _require_nonzero_stateless(m, "BPF")
    loc = m.locator
    assert loc is not None
    if not loc.spans_single_byte:
        raise ValueError(f"{m.id}: BPF emitter handles single-byte fields; use nftables")
    accessor = _BPF_BY_PROTO.get(m.protocol.lower()) or _BPF_BY_BASE[loc.base]
    return f"{accessor}[{loc.byte_offset}] & 0x{loc.byte_mask:02x} != 0"


def iptables_u32_rule(m: Mechanism) -> str:
    """An iptables u32 match fragment for IPv4 stateless NONZERO locators.

    ``u32`` reads four-byte words, so single-byte locators need a byte-lane
    shift before masking. Transport-header locators also need the IPv4 IHL jump
    idiom (``0>>22&0x3C@...``) and guards for protocol plus non-fragmented
    packets.
    """
    _require_nonzero_stateless(m, "iptables u32")
    loc = m.locator
    assert loc is not None
    if not loc.spans_single_byte:
        raise ValueError(f"{m.id}: iptables u32 emitter handles single-byte fields; use nftables")
    if loc.base is WireBase.LL:
        raise ValueError(f"{m.id}: iptables u32 starts at the IPv4 header, not link layer")
    predicate = f"{_iptables_u32_byte_expr(loc)}=0x1:0x{loc.byte_mask:02X}"
    if loc.base is WireBase.TH:
        protocol_number = _IPTABLES_U32_L4_PROTO.get(m.protocol.lower())
        if protocol_number is None:
            raise ValueError(f"{m.id}: no iptables u32 transport guard for {m.protocol}")
        predicate = f"6&0xFF={protocol_number} && 4&0x3FFF=0 && {predicate}"
    return f'-m u32 --u32 "{predicate}"'


def _iptables_u32_byte_expr(loc: FieldLocator) -> str:
    mask = f"0x{loc.byte_mask:02X}"
    if loc.base is WireBase.NH:
        return f"{loc.byte_offset}>>24&{mask}"
    if loc.base is WireBase.TH:
        return f"0>>22&0x3C@{loc.byte_offset}>>24&{mask}"
    raise ValueError("iptables u32 cannot address link-layer locators")


def emittable(mechs: list[Mechanism]) -> list[Mechanism]:
    """Mechanisms a stateless packet filter can match (located + fixed-value)."""
    return [m for m in mechs if m.detectability is Detectability.STATELESS_FILTER]


def coverage(mechs: list[Mechanism]) -> dict[Detectability, list[Mechanism]]:
    """Bucket every mechanism by where it is observable — the honest coverage
    map. The non-STATELESS buckets are exactly what a packet filter cannot see."""
    out: dict[Detectability, list[Mechanism]] = defaultdict(list)
    for m in mechs:
        out[m.detectability].append(m)
    return dict(out)


def detector_provenance_for(
    mechanism: Mechanism,
    units: list[CarrierUnit],
    *,
    pcap_path: Path | str | None = None,
    tcpdump_path: str = "tcpdump",
) -> tuple[DetectorProvenanceRecord, ...]:
    """Describe detector coverage and provenance for a case's carrier units.

    The current checked-in evaluator is deliberately narrow: it evaluates located
    NONZERO stateless fields against carrier bytes anchored at the locator base.
    Other mechanisms still get an explicit classification record so evidence JSON
    names why no packet-filter detector result is being claimed.
    """

    if mechanism.detectability is not Detectability.STATELESS_FILTER:
        return (_classification_record(mechanism),)
    if not _has_supported_stateless_predicate(mechanism):
        return (
            _classification_record(
                mechanism,
                result="stateless_filter_no_concrete_match",
                notes=(
                    "classified as stateless_filter, but the current detector "
                    "generator has no concrete match values for this predicate"
                ),
            ),
        )

    records = [_stateless_same_code_record(mechanism, units)]
    records.extend(_generated_rule_records(mechanism))
    if (
        pcap_path is not None
        and mechanism.locator is not None
        and mechanism.locator.spans_single_byte
        and _optional_rule(bpf_filter, mechanism) is not None
    ):
        records.append(
            tcpdump_bpf_provenance_record(
                mechanism,
                pcap_path,
                tcpdump_path=tcpdump_path,
                benign_basis="scenario_control_fixture_not_fp_estimate",
                false_positive_estimate=False,
                implementation="tcpdump/libpcap BPF execution over scenario pcap",
                notes=(
                    "independent tcpdump/libpcap execution over this scenario pcap; "
                    "not a benign-trace replay"
                ),
            )
        )
    return tuple(records)


def _classification_record(
    mechanism: Mechanism,
    *,
    result: str = "not_stateless_filterable",
    notes: str = "classified only; packet-filter detector not generated for this detectability tier",
) -> DetectorProvenanceRecord:
    return DetectorProvenanceRecord(
        name=f"{mechanism.id}-detectability-classification",
        detector_family="catalog_detectability",
        implementation="celatim.model.Mechanism.detectability",
        implementation_kind=DetectorImplementationKind.SAME_CODE,
        executed=True,
        result=result,
        detectability=mechanism.detectability,
        predicate=mechanism.detect_predicate,
        disposition=disposition(mechanism),
        rule_format=None,
        rule=None,
        checked_units=0,
        matched_units=0,
        failed_units=0,
        detected=None,
        benign_basis="scenario_control_fixture_not_fp_estimate",
        false_positive_estimate=False,
        command=(),
        returncode=None,
        stdout_sha256=None,
        stderr_sha256=None,
        stderr_excerpt=None,
        notes=notes,
    )


def _stateless_same_code_record(
    mechanism: Mechanism,
    units: list[CarrierUnit],
) -> DetectorProvenanceRecord:
    _require_stateless(mechanism)
    predicate = mechanism.detect_predicate
    assert predicate is not None
    checked = 0
    matched = 0
    failed = 0
    for unit in units:
        if unit.carrier is None:
            failed += 1
            continue
        checked += 1
        try:
            if _located_field_matches(mechanism, unit.carrier):
                matched += 1
        except ValueError:
            failed += 1
    detected = matched > 0 if checked else None
    result = "matched" if detected else "not_matched"
    if failed:
        result = "partial_failure" if checked else "failed"
    return DetectorProvenanceRecord(
        name=f"{mechanism.id}-same-code-stateless-{predicate.value}",
        detector_family="stateless_filter",
        implementation="celatim.detect.rules.located_field_matches",
        implementation_kind=DetectorImplementationKind.SAME_CODE,
        executed=True,
        result=result,
        detectability=mechanism.detectability,
        predicate=mechanism.detect_predicate,
        disposition=disposition(mechanism),
        rule_format=None,
        rule=None,
        checked_units=checked,
        matched_units=matched,
        failed_units=failed,
        detected=detected,
        benign_basis="scenario_control_fixture_not_fp_estimate",
        false_positive_estimate=False,
        command=(),
        returncode=None,
        stdout_sha256=None,
        stderr_sha256=None,
        stderr_excerpt=None,
        notes=(
            "carrier-byte evaluator anchored at the catalog locator base; "
            "not an independent trace replay"
        ),
    )


def _generated_rule_records(mechanism: Mechanism) -> tuple[DetectorProvenanceRecord, ...]:
    records: list[DetectorProvenanceRecord] = []
    for rule_format, emitter, implementation, suffix, notes in (
        (
            "nftables",
            nftables_rule,
            "nftables raw-payload expression generated by celatim.detect.rules",
            "nftables-rule",
            "generated filter provenance only; no kernel or benign-trace execution in this evidence run",
        ),
        (
            "iptables-u32",
            iptables_u32_rule,
            "iptables u32 expression generated by celatim.detect.rules",
            "iptables-u32-rule",
            "generated filter provenance only; no iptables/kernel or benign-trace execution in this evidence run",
        ),
        (
            "bpf",
            bpf_filter,
            "libpcap/tcpdump filter generated by celatim.detect.rules",
            "bpf-filter",
            "generated filter provenance only; no tcpdump or benign-trace execution in this evidence run",
        ),
    ):
        rule = _optional_rule(emitter, mechanism)
        if rule is None:
            continue
        records.append(
            DetectorProvenanceRecord(
                name=f"{mechanism.id}-{suffix}",
                detector_family="stateless_filter",
                implementation=implementation,
                implementation_kind=DetectorImplementationKind.GENERATED_KERNEL_RULE,
                executed=False,
                result="generated_not_executed",
                detectability=mechanism.detectability,
                predicate=mechanism.detect_predicate,
                disposition=disposition(mechanism),
                rule_format=rule_format,
                rule=rule,
                checked_units=0,
                matched_units=0,
                failed_units=0,
                detected=None,
                benign_basis="scenario_control_fixture_not_fp_estimate",
                false_positive_estimate=False,
                command=(),
                returncode=None,
                stdout_sha256=None,
                stderr_sha256=None,
                stderr_excerpt=None,
                notes=notes,
            )
        )
    return tuple(records)


def tcpdump_bpf_provenance_record(
    mechanism: Mechanism,
    pcap_path: Path | str,
    *,
    tcpdump_path: str = "tcpdump",
    benign_basis: str,
    false_positive_estimate: bool,
    implementation: str,
    notes: str,
    name: str | None = None,
) -> DetectorProvenanceRecord:
    """Run a generated libpcap BPF filter with tcpdump and return provenance.

    This is the independent-tool execution path used both by scenario evidence
    and by benign-trace detector replay reports. Callers must provide the benign
    basis explicitly so scenario controls cannot be mistaken for FP estimates.
    """

    rule = bpf_filter(mechanism)
    pcap = Path(pcap_path)
    command = (tcpdump_path, "-tt", "-n", "-r", str(pcap), rule)
    resolved = shutil.which(tcpdump_path)
    checked_units = classic_pcap_record_count(pcap)
    record_name = name or f"{mechanism.id}-tcpdump-bpf"
    if resolved is None:
        return DetectorProvenanceRecord(
            name=record_name,
            detector_family="stateless_filter",
            implementation=implementation,
            implementation_kind=DetectorImplementationKind.INDEPENDENT_TOOL_OUTPUT,
            executed=False,
            result="tool_missing",
            detectability=mechanism.detectability,
            predicate=mechanism.detect_predicate,
            disposition=disposition(mechanism),
            rule_format="bpf",
            rule=rule,
            checked_units=checked_units,
            matched_units=0,
            failed_units=checked_units,
            detected=None,
            benign_basis=benign_basis,
            false_positive_estimate=False,
            command=command,
            returncode=None,
            stdout_sha256=None,
            stderr_sha256=None,
            stderr_excerpt=f"{tcpdump_path}: not found",
            notes=f"tcpdump was unavailable; {notes}",
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
    matched_units = _tcpdump_packet_line_count(stdout)
    command_failed = completed.returncode != 0
    return DetectorProvenanceRecord(
        name=record_name,
        detector_family="stateless_filter",
        implementation=implementation,
        implementation_kind=DetectorImplementationKind.INDEPENDENT_TOOL_OUTPUT,
        executed=not command_failed,
        result=_tcpdump_result(completed.returncode, matched_units),
        detectability=mechanism.detectability,
        predicate=mechanism.detect_predicate,
        disposition=disposition(mechanism),
        rule_format="bpf",
        rule=rule,
        checked_units=checked_units,
        matched_units=matched_units,
        failed_units=checked_units if command_failed else 0,
        detected=matched_units > 0 if not command_failed else None,
        benign_basis=benign_basis,
        false_positive_estimate=false_positive_estimate and not command_failed,
        command=command,
        returncode=completed.returncode,
        stdout_sha256=hashlib.sha256(stdout.encode()).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr.encode()).hexdigest(),
        stderr_excerpt=_excerpt(stderr),
        notes=notes,
    )


def _located_field_matches(mechanism: Mechanism, carrier: bytes) -> bool:
    value = _located_field_value(mechanism, carrier)
    if mechanism.detect_predicate is DetectPredicate.NONZERO:
        return value != 0
    if mechanism.detect_predicate is DetectPredicate.RESERVED_VALUE:
        return any(match.matches(value) for match in mechanism.reserved_value_matches)
    raise ValueError(
        f"{mechanism.id}: unsupported same-code predicate {mechanism.detect_predicate}"
    )


def _located_field_value(mechanism: Mechanism, carrier: bytes) -> int:
    loc = mechanism.locator
    if loc is None:
        raise ValueError(f"{mechanism.id}: no field locator")
    needed_bits = loc.bit_offset + loc.bit_width
    if len(carrier) * 8 < needed_bits:
        raise ValueError(f"{mechanism.id}: carrier shorter than located field")
    value = 0
    for offset in range(loc.bit_width):
        bit_index = loc.bit_offset + offset
        byte = carrier[bit_index // 8]
        bit = (byte >> (7 - (bit_index % 8))) & 1
        value = (value << 1) | bit
    return value


_PCAP_GLOBAL = struct.Struct("<IHHIIII")
_PCAP_PACKET = struct.Struct("<IIII")
_PCAP_MAGIC = 0xA1B2C3D4


def classic_pcap_record_count(path: Path) -> int:
    data = path.read_bytes()
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


def _tcpdump_packet_line_count(stdout: str) -> int:
    return sum(1 for line in stdout.splitlines() if line.strip())


def _tcpdump_result(returncode: int, matched_units: int) -> str:
    if returncode != 0:
        return "tool_failed"
    if matched_units:
        return "matched"
    return "not_matched"


def _excerpt(value: str, limit: int = 240) -> str | None:
    text = " ".join(value.split())
    if not text:
        return None
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."
