"""Decode parser-visible carrier pcaps into payload evidence."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from .observer import ParserProvenanceRecord, parser_provenance_for
from .session import (
    ChannelSession,
    EvidenceRecord,
    InMemoryTransport,
    MechanismProfile,
    ReliabilityPolicy,
    ThroughputProfile,
    TimingProfile,
    TimingSample,
    TimingTrace,
    local_endpoint_os,
)
from .transports import PcapCarrierExtraction, extract_pcap_carriers

PCAP_DECODE_SCHEMA_VERSION = "celatim.pcap_decode.v1"
PCAP_DECODE_CLAIM_STATUS = "same_code_pcap_decode_not_independent_trace_validation"


@dataclass(frozen=True)
class PcapDecodeArtifact:
    """Hashable pcap artifact metadata for a decode report."""

    path: str
    sha256: str
    size_bytes: int
    packet_count: int
    linktype: int

    def to_json(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "packet_count": self.packet_count,
            "linktype": self.linktype,
        }


@dataclass(frozen=True)
class PcapDecodeReport:
    """Machine-readable pcap carrier decode evidence."""

    mechanism_id: str
    session_id: str
    pcap: PcapDecodeArtifact
    carrier_units: int
    carrier_unit_sha256: tuple[str, ...]
    recovered_payload: bytes
    evidence: EvidenceRecord
    parser_provenance: tuple[ParserProvenanceRecord, ...] = ()
    expected_payload: bytes | None = None
    claim_status: str = PCAP_DECODE_CLAIM_STATUS

    @property
    def matches_expected(self) -> bool | None:
        if self.expected_payload is None:
            return None
        return self.recovered_payload == self.expected_payload

    @property
    def ok(self) -> bool:
        return self.evidence.ok and self.matches_expected is not False

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": PCAP_DECODE_SCHEMA_VERSION,
            "mechanism_id": self.mechanism_id,
            "session_id": self.session_id,
            "claim_status": self.claim_status,
            "pcap": self.pcap.to_json(),
            "carrier_units": self.carrier_units,
            "carrier_units_with_bytes": len(self.carrier_unit_sha256),
            "carrier_unit_sha256": list(self.carrier_unit_sha256),
            "parser_validated": True,
            "parser_provenance_count": len(self.parser_provenance),
            "parser_provenance_executed_count": sum(
                1 for record in self.parser_provenance if record.executed
            ),
            "parser_provenance": [record.to_json() for record in self.parser_provenance],
            "payload_len": len(self.recovered_payload),
            "recovered_hex": self.recovered_payload.hex(),
            "recovered_sha256": hashlib.sha256(self.recovered_payload).hexdigest(),
            "expected_sha256": (
                None
                if self.expected_payload is None
                else hashlib.sha256(self.expected_payload).hexdigest()
            ),
            "matches_expected": self.matches_expected,
            "ok": self.ok,
            "evidence": _evidence_to_json(self.evidence),
        }


def decode_pcap(
    profile: MechanismProfile,
    pcap: Path | str,
    *,
    expected_payload: bytes | None = None,
    session_id: str | None = None,
    reliability: ReliabilityPolicy | None = None,
    tshark_path: str = "tshark",
) -> PcapDecodeReport:
    """Decode one pcap/tap artifact using the mechanism's registered carrier parser."""

    extraction = extract_pcap_carriers(profile, pcap)
    active_session_id = session_id or uuid4().hex
    transport = InMemoryTransport()
    transport.send_symbols(active_session_id, list(extraction.symbols))
    result = ChannelSession(
        profile,
        transport,
        reliability=reliability,
        endpoint_os=local_endpoint_os(
            "same_host_artifact",
            include_tap=True,
            notes=(
                "standalone pcap decode from a local artifact",
                "same-code mechanism parser, not an independent trace validator",
            ),
        ),
    ).receive_message(active_session_id)
    return PcapDecodeReport(
        mechanism_id=profile.id,
        session_id=active_session_id,
        pcap=_pcap_artifact(extraction),
        carrier_units=len(extraction.symbols),
        carrier_unit_sha256=tuple(
            hashlib.sha256(carrier).hexdigest() for carrier in extraction.carrier_bytes
        ),
        recovered_payload=result.payload,
        parser_provenance=parser_provenance_for(
            profile.id, extraction.path, tshark_path=tshark_path
        ),
        expected_payload=expected_payload,
        evidence=result.evidence,
    )


def _pcap_artifact(extraction: PcapCarrierExtraction) -> PcapDecodeArtifact:
    data = extraction.path.read_bytes()
    return PcapDecodeArtifact(
        path=str(extraction.path),
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        packet_count=extraction.packet_count,
        linktype=extraction.linktype,
    )


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
        "pacing": None if evidence.pacing is None else asdict(evidence.pacing),
        "scheduled_duration_s": evidence.scheduled_duration_s,
        "timing_trace": _timing_trace_to_json(evidence.timing_trace),
        "timing_profile": _timing_profile_to_json(evidence.timing_profile),
        "throughput_profile": _throughput_profile_to_json(evidence.throughput_profile),
        "session_framing": evidence.session_framing,
        "chunk_count": evidence.chunk_count,
        "integrity_sha256": evidence.integrity_sha256,
        "reliability": {
            "receive_attempts": evidence.reliability.receive_attempts,
            "retry_count": evidence.reliability.retry_count,
            "retransmit_requests": evidence.reliability.retransmit_requests,
            "duplicate_chunks": evidence.reliability.duplicate_chunks,
            "loss_detected": evidence.reliability.loss_detected,
            "timed_out": evidence.reliability.timed_out,
            "expected_chunks": evidence.reliability.expected_chunks,
            "recovered_chunks": evidence.reliability.recovered_chunks,
            "last_error": evidence.reliability.last_error,
            "policy": {
                "max_receive_attempts": evidence.reliability.policy.max_receive_attempts,
                "retry_backoff_s": evidence.reliability.policy.retry_backoff_s,
                "suppress_duplicate_chunks": evidence.reliability.policy.suppress_duplicate_chunks,
                "max_retransmissions": evidence.reliability.policy.max_retransmissions,
            },
        },
        "ok": evidence.ok,
        "error": evidence.error,
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


__all__ = [
    "PCAP_DECODE_CLAIM_STATUS",
    "PCAP_DECODE_SCHEMA_VERSION",
    "PcapDecodeArtifact",
    "PcapDecodeReport",
    "decode_pcap",
]
