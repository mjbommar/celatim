"""Evidence classification for the current executable artifact.

This module is intentionally conservative. It records what the current runs prove,
not what a future adapter should prove. In particular, payload-field rows that are
currently carried as a nominal offset into a zero-filled payload are kept separate
from real-PDU and real-daemon evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .model import CarrierClass, Detectability, Mechanism


class EvidenceBucket(str, Enum):
    CODEC_ROUNDTRIP = "codec_roundtrip"
    OFFSET_REPRESENTED_ZERO_BLOB = "offset_represented_zero_blob"
    REAL_PDU_PACKET_PATH = "real_pdu_packet_path"
    REAL_DAEMON_OR_CRYPTO_PATH = "real_daemon_or_crypto_path"
    TIMING_SCHEME = "timing_scheme"
    NEGATIVE_RESULT = "negative_result"


class CarrierStructure(str, Enum):
    REAL_PROTOCOL_PDU = "real_protocol_pdu"
    MINIMAL_PROTOCOL_PDU = "minimal_protocol_pdu"
    ZERO_PAD_NOMINAL_OFFSET = "zero_pad_nominal_offset"
    TIMING_ONLY = "timing_only"
    CRYPTO_TRANSCRIPT = "crypto_transcript"
    NEGATIVE_CONTROL = "negative_control"
    NONE = "none"


class ControlStrength(str, Enum):
    VACUOUS_ZERO_CARRIER = "vacuous_zero_carrier"
    ZERO_TARGET_FIELD_ONLY = "zero_target_field_only"
    NONZERO_SURROUNDING_BYTES = "nonzero_surrounding_bytes"
    INDEPENDENT_PARSER_CHECKED = "independent_parser_checked"
    REAL_BENIGN_TRACE = "real_benign_trace"
    DAEMON_CONTROL = "daemon_control"
    HONEST_RANDOM_CONTROL = "honest_random_control"
    CONSTANT_RATE_CONTROL = "constant_rate_control"
    NEGATIVE_CRYPTO_CONTROL = "negative_crypto_control"
    NONE = "none"


class IndependentValidator(str, Enum):
    NONE = "none"
    BPF_CALIBRATION = "bpf_calibration"
    SECOND_PARSER = "second_parser"
    TSHARK_OR_WIRESHARK = "tshark_or_wireshark"
    DAEMON_ACCEPTED = "daemon_accepted"
    REAL_CRYPTO_VERIFY = "real_crypto_verify"
    PUBLIC_TRACE_REPLAY = "public_trace_replay"


class ThroughputStatus(str, Enum):
    NOT_APPLICABLE = "not_applicable"
    NOT_REPORTED = "not_reported"
    SCHEME_ONLY = "scheme_only"
    SENDER_BOUND = "sender_bound"
    PRODUCTION_PATH_MEASURED = "production_path_measured"


class UpgradePriority(str, Enum):
    MARQUEE = "marquee"
    HIGH = "high"
    NORMAL = "normal"


@dataclass(frozen=True)
class EvidenceProfile:
    mechanism_id: str
    bucket: EvidenceBucket
    carrier_structure: CarrierStructure
    control_strength: ControlStrength
    independent_validator: IndependentValidator
    throughput_status: ThroughputStatus
    upgrade_priority: UpgradePriority
    notes: str


# Current lab.py payload/template rows that put the covert field at a nominal offset
# inside a zero-filled payload. These are useful internal consistency tests, but they
# are not real protocol-PDU evidence until replaced by surrounding PDU structure and
# an independent parser/daemon check.
ZERO_PAD_OFFSET_REPRESENTED_IDS = frozenset(
    {
        "bgp-path-attr-flags",
        "ioam-reserved",
    }
)


# Rows that currently have a stronger, non-zero-blob path.
REAL_DAEMON_PATH_IDS = frozenset(
    {
        "edns0-padding",
        "dns-txt-tunnel",
        "dns-null-tunnel",
        "ssh-kexinit-cookie",
        "coap-tunnel",
        "websocket-tunnel",
    }
)
REAL_PDU_FIXTURE_IDS = frozenset({"http2-ping-opaque", "quic-connection-id", "rtp-rtcp-ext-app"})
MINIMAL_PACKET_TEMPLATE_IDS = frozenset({"tcp-reserved-bits"})
REAL_CRYPTO_PATH_IDS = frozenset({"ecdsa-nonce", "rsa-pss-salt"})
TIMING_SCHEME_IDS = frozenset({"dns-timing", "ntp-timing", "quic-padding-frame-count"})


MARQUEE_SUBSET_IDS = frozenset(
    {
        "tcp-reserved-bits",
        "edns0-padding",
        "http2-ping-opaque",
        "quic-connection-id",
        "tls-record-padding",
        "bgp-path-attr-flags",
        "vxlan-reserved",
        "rtp-rtcp-ext-app",
        "ntp-timing",
        "rsa-pss-salt",
    }
)


def classify_evidence(mechanism: Mechanism) -> EvidenceProfile:
    """Classify the strongest current evidence for one mechanism.

    The order matters: real daemon/crypto and timing evidence override the old
    zero-pad battery classification for mechanisms that have a stronger dedicated
    runner.
    """
    if mechanism.negative_result:
        return EvidenceProfile(
            mechanism.id,
            EvidenceBucket.NEGATIVE_RESULT,
            CarrierStructure.NEGATIVE_CONTROL,
            ControlStrength.NEGATIVE_CRYPTO_CONTROL,
            IndependentValidator.REAL_CRYPTO_VERIFY,
            ThroughputStatus.NOT_APPLICABLE,
            _priority(mechanism),
            "negative-result contrast; not counted as a usable channel",
        )

    if mechanism.id in REAL_DAEMON_PATH_IDS:
        return EvidenceProfile(
            mechanism.id,
            EvidenceBucket.REAL_DAEMON_OR_CRYPTO_PATH,
            CarrierStructure.REAL_PROTOCOL_PDU,
            ControlStrength.DAEMON_CONTROL,
            IndependentValidator.DAEMON_ACCEPTED,
            ThroughputStatus.NOT_REPORTED,
            _priority(mechanism),
            "real client/server transaction; pcap receiver; no-padding control",
        )

    if mechanism.id in REAL_CRYPTO_PATH_IDS or mechanism.carrier_class is CarrierClass.G:
        return EvidenceProfile(
            mechanism.id,
            EvidenceBucket.REAL_DAEMON_OR_CRYPTO_PATH,
            CarrierStructure.CRYPTO_TRANSCRIPT,
            ControlStrength.HONEST_RANDOM_CONTROL,
            IndependentValidator.REAL_CRYPTO_VERIFY,
            ThroughputStatus.NOT_APPLICABLE,
            _priority(mechanism),
            "real signing/verification transcript; honest-random control",
        )

    if mechanism.id in TIMING_SCHEME_IDS or mechanism.carrier_class is CarrierClass.F:
        return EvidenceProfile(
            mechanism.id,
            EvidenceBucket.TIMING_SCHEME,
            CarrierStructure.TIMING_ONLY,
            ControlStrength.CONSTANT_RATE_CONTROL,
            IndependentValidator.NONE,
            ThroughputStatus.SCHEME_ONLY,
            _priority(mechanism),
            "scheme round-trips; needs jitter/SNR sweep before rate claim",
        )

    if mechanism.id in REAL_PDU_FIXTURE_IDS:
        return EvidenceProfile(
            mechanism.id,
            EvidenceBucket.REAL_PDU_PACKET_PATH,
            CarrierStructure.REAL_PROTOCOL_PDU,
            ControlStrength.NONZERO_SURROUNDING_BYTES,
            IndependentValidator.SECOND_PARSER,
            ThroughputStatus.SENDER_BOUND,
            _priority(mechanism),
            "real protocol PDU fixture; parser validates field placement",
        )

    if mechanism.id in MINIMAL_PACKET_TEMPLATE_IDS:
        return EvidenceProfile(
            mechanism.id,
            EvidenceBucket.REAL_PDU_PACKET_PATH,
            CarrierStructure.MINIMAL_PROTOCOL_PDU,
            ControlStrength.INDEPENDENT_PARSER_CHECKED,
            IndependentValidator.SECOND_PARSER,
            ThroughputStatus.SENDER_BOUND,
            _priority(mechanism),
            "minimal packet header fixture; parser validates field placement and surrounding structure",
        )

    if mechanism.id in ZERO_PAD_OFFSET_REPRESENTED_IDS:
        return EvidenceProfile(
            mechanism.id,
            EvidenceBucket.OFFSET_REPRESENTED_ZERO_BLOB,
            CarrierStructure.ZERO_PAD_NOMINAL_OFFSET,
            ControlStrength.VACUOUS_ZERO_CARRIER,
            IndependentValidator.NONE,
            ThroughputStatus.SENDER_BOUND,
            _priority(mechanism),
            "nominal field offset inside zero-filled payload; needs real PDU fixture",
        )

    if mechanism.locator is not None:
        validator = (
            IndependentValidator.BPF_CALIBRATION
            if mechanism.detectability is Detectability.STATELESS_FILTER
            else IndependentValidator.NONE
        )
        return EvidenceProfile(
            mechanism.id,
            EvidenceBucket.REAL_PDU_PACKET_PATH,
            CarrierStructure.MINIMAL_PROTOCOL_PDU,
            ControlStrength.ZERO_TARGET_FIELD_ONLY,
            validator,
            ThroughputStatus.SENDER_BOUND,
            _priority(mechanism),
            "minimal packet template over netns/veth; throughput currently sender-bound",
        )

    return EvidenceProfile(
        mechanism.id,
        EvidenceBucket.CODEC_ROUNDTRIP,
        CarrierStructure.NONE,
        ControlStrength.NONE,
        IndependentValidator.NONE,
        ThroughputStatus.NOT_REPORTED,
        _priority(mechanism),
        "codec/framer round-trip only; no current packet-path evidence",
    )


def _priority(mechanism: Mechanism) -> UpgradePriority:
    if mechanism.id in MARQUEE_SUBSET_IDS:
        return UpgradePriority.MARQUEE
    if mechanism.id in ZERO_PAD_OFFSET_REPRESENTED_IDS:
        return UpgradePriority.HIGH
    return UpgradePriority.NORMAL


def evidence_profiles(mechanisms: list[Mechanism]) -> list[EvidenceProfile]:
    return [classify_evidence(m) for m in mechanisms]


def bucket_counts(profiles: list[EvidenceProfile]) -> dict[EvidenceBucket, int]:
    return {bucket: sum(p.bucket is bucket for p in profiles) for bucket in EvidenceBucket}
