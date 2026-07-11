"""Mechanism adapter registry.

Codecs answer "how many bits fit in this field?" Adapters answer the next question:
what executable path currently exists for this mechanism? For the upgraded real-PDU
fixtures, the adapter can build and parse carrier bytes. For the rest of the catalog,
the adapter still records conservative status and capability metadata so generated
tables do not treat every codec as the same evidence class.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, cast

from .channel.codec import VariableLengthCodec
from .channel.framer import Framer
from .channel.registry import codec_for
from .evidence import CarrierStructure, EvidenceBucket, EvidenceProfile, classify_evidence
from .model import CapacityModel, Mechanism
from .pdu import (
    DCID_LEN,
    RTCP_APP_DATA_LEN,
    TCP_RESERVED_BITS_WIDTH,
    build_app_packet,
    build_connection_preface_ping,
    build_initial_packet,
    build_tcp_reserved_bits_segment,
    format_carriers,
    http2_fields,
    minimal_pdu,
    parse_app_packet,
    parse_frames,
    parse_long_header,
    parse_tcp_reserved_bits,
    quic_fields,
    scapy_field,
    scapy_pdu,
    struct_fields,
    tls_fields,
)

type Symbol = int | bytes
type CarrierBuilder = Callable[[Symbol], bytes]
type CarrierParser = Callable[[bytes], Symbol]


class AdapterStatus(str, Enum):
    CODEC_ONLY = "codec_only"
    MINIMAL_PACKET_TEMPLATE = "minimal_packet_template"
    OFFSET_REPRESENTED_ZERO_BLOB = "offset_represented_zero_blob"
    REAL_PDU_FIXTURE = "real_pdu_fixture"
    REAL_DAEMON_PATH = "real_daemon_path"
    REAL_CRYPTO_PATH = "real_crypto_path"
    TIMING_SCHEME = "timing_scheme"
    NEGATIVE_RESULT = "negative_result"


class AdapterCapability(str, Enum):
    CODEC_SESSION = "codec_session"
    JSON_ENVELOPE = "json_envelope"
    PACKET_PATH_TEMPLATE = "packet_path_template"
    REAL_PDU_FIXTURE = "real_pdu_fixture"
    PARSER_VALIDATED = "parser_validated"
    DAEMON_PATH = "daemon_path"
    CRYPTO_TRANSCRIPT = "crypto_transcript"
    TIMING = "timing"
    OFFSET_REPRESENTED = "offset_represented"
    NEGATIVE_RESULT = "negative_result"


class AdapterPathKind(str, Enum):
    MEMORY = "memory"
    FILE_RECORD = "file_record"
    TIMED_MEMORY = "timed_memory"
    PCAP_ARTIFACT = "pcap_artifact"
    AFPACKET_IPV4 = "afpacket_ipv4"
    HTTP2_HYPER_H2 = "http2_hyper_h2"
    HTTP3_AIOQUIC_RESERVED_SETTINGS = "http3_aioquic_reserved_settings"
    QUIC_AIOQUIC_CONNECTION_ID = "quic_aioquic_connection_id"
    SCAPY_PACKET = "scapy_packet"
    DNS_EDNS0_PADDING_DAEMON = "dns_edns0_padding_daemon"
    DNS_TXT_DNSPYTHON = "dns_txt_dnspython"
    DNS_NULL_DNSPYTHON = "dns_null_dnspython"
    SSH_KEXINIT_PARAMIKO = "ssh_kexinit_paramiko"
    SSH_KEXINIT_OPENSSH = "ssh_kexinit_openssh"
    COAP_AIOCOAP = "coap_aiocoap"
    WEBSOCKET_WEBSOCKETS = "websocket_websockets"
    BGP_SCAPY = "bgp_scapy"
    CRYPTO_ECDSA_NONCE = "crypto_ecdsa_nonce"
    CRYPTO_RSA_PSS_SALT = "crypto_rsa_pss_salt"


@dataclass(frozen=True)
class AdapterPath:
    """One executable path currently registered for a mechanism adapter."""

    kind: AdapterPathKind
    transport_kind: str
    evidence_tier: str
    claim_status: str
    privilege: str = "none"
    required_binaries: tuple[str, ...] = ()
    required_extras: tuple[str, ...] = ()
    scenario_id: str | None = None
    records_artifact: bool = False
    notes: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "transport_kind": self.transport_kind,
            "evidence_tier": self.evidence_tier,
            "claim_status": self.claim_status,
            "privilege": self.privilege,
            "required_binaries": list(self.required_binaries),
            "required_extras": list(self.required_extras),
            "scenario_id": self.scenario_id,
            "records_artifact": self.records_artifact,
            "notes": self.notes,
        }


@dataclass(frozen=True)
class CarrierUnit:
    index: int
    symbol: Symbol
    carrier: bytes | None = None

    @property
    def has_carrier_bytes(self) -> bool:
        return self.carrier is not None


@dataclass(frozen=True)
class MechanismAdapter:
    mechanism: Mechanism
    evidence: EvidenceProfile
    status: AdapterStatus
    capabilities: frozenset[AdapterCapability]
    required_privilege: str = "none"
    required_binaries: tuple[str, ...] = ()
    required_extras: tuple[str, ...] = ()
    paths: tuple[AdapterPath, ...] = ()
    _carrier_builder: CarrierBuilder | None = field(default=None, repr=False, compare=False)
    _carrier_parser: CarrierParser | None = field(default=None, repr=False, compare=False)

    @property
    def mechanism_id(self) -> str:
        return self.mechanism.id

    @property
    def supports_carrier_bytes(self) -> bool:
        return self._carrier_builder is not None and self._carrier_parser is not None

    @property
    def path_kinds(self) -> tuple[str, ...]:
        return tuple(path.kind.value for path in self.paths)

    @property
    def transport_kinds(self) -> tuple[str, ...]:
        return tuple(sorted({path.transport_kind for path in self.paths}))

    def supports_transport(self, transport_kind: str) -> bool:
        return any(path.transport_kind == transport_kind for path in self.paths)

    def path_for_transport(self, transport_kind: str) -> AdapterPath | None:
        for path in self.paths:
            if path.transport_kind == transport_kind:
                return path
        return None

    def encode_payload(self, payload: bytes) -> list[CarrierUnit]:
        """Encode a caller payload into carrier units for this adapter."""
        framer = Framer[Any](cast(Any, codec_for(self.mechanism)))
        symbols = cast(list[Symbol], framer.encode(payload))
        return [
            CarrierUnit(index, symbol, self.build_carrier(symbol))
            for index, symbol in enumerate(symbols)
        ]

    def decode_units(self, units: list[CarrierUnit]) -> bytes:
        """Decode a payload from symbols or parser-validated carrier bytes."""
        framer = Framer[Any](cast(Any, codec_for(self.mechanism)))
        symbols = [
            self.parse_carrier(unit.carrier) if unit.carrier is not None else unit.symbol
            for unit in units
        ]
        return framer.decode(cast(list[Any], symbols))

    def build_carrier(self, symbol: Symbol) -> bytes | None:
        if self._carrier_builder is None:
            return None
        return self._carrier_builder(symbol)

    def parse_carrier(self, carrier: bytes | None) -> Symbol:
        if carrier is None:
            raise ValueError(f"{self.mechanism_id}: no carrier bytes to parse")
        if self._carrier_parser is None:
            raise ValueError(f"{self.mechanism_id}: no carrier parser registered")
        return self._carrier_parser(carrier)


def adapter_for(mechanism: Mechanism) -> MechanismAdapter:
    evidence = classify_evidence(mechanism)
    if mechanism.id in _REAL_PDU_FIXTURES:
        builder, parser = _REAL_PDU_FIXTURES[mechanism.id]
        paths = _paths_for(mechanism, evidence, register_packet_artifact_paths=True)
        return MechanismAdapter(
            mechanism=mechanism,
            evidence=evidence,
            status=AdapterStatus.REAL_PDU_FIXTURE,
            capabilities=frozenset(
                {
                    AdapterCapability.CODEC_SESSION,
                    AdapterCapability.JSON_ENVELOPE,
                    AdapterCapability.PACKET_PATH_TEMPLATE,
                    AdapterCapability.REAL_PDU_FIXTURE,
                    AdapterCapability.PARSER_VALIDATED,
                }
            ),
            required_privilege="none",
            required_binaries=_required_binaries_for_paths(paths),
            required_extras=_required_extras_for_paths(paths),
            paths=paths,
            _carrier_builder=builder,
            _carrier_parser=parser,
        )
    if mechanism.id in _MINIMAL_PACKET_TEMPLATES:
        builder, parser = _MINIMAL_PACKET_TEMPLATES[mechanism.id]
        paths = _paths_for(mechanism, evidence, register_packet_artifact_paths=True)
        return MechanismAdapter(
            mechanism=mechanism,
            evidence=evidence,
            status=AdapterStatus.MINIMAL_PACKET_TEMPLATE,
            capabilities=frozenset(
                {
                    AdapterCapability.CODEC_SESSION,
                    AdapterCapability.JSON_ENVELOPE,
                    AdapterCapability.PACKET_PATH_TEMPLATE,
                    AdapterCapability.PARSER_VALIDATED,
                }
            ),
            required_privilege="none",
            required_binaries=_required_binaries_for_paths(paths),
            required_extras=_required_extras_for_paths(paths),
            paths=paths,
            _carrier_builder=builder,
            _carrier_parser=parser,
        )

    if mechanism.id == "tls-record-padding":
        builder, parser = _tls_field_carrier(mechanism)
        paths = _paths_for(mechanism, evidence, register_packet_artifact_paths=False)
        return MechanismAdapter(
            mechanism=mechanism,
            evidence=evidence,
            status=AdapterStatus.CODEC_ONLY,
            capabilities=frozenset(
                {
                    AdapterCapability.CODEC_SESSION,
                    AdapterCapability.JSON_ENVELOPE,
                    AdapterCapability.PARSER_VALIDATED,
                }
            ),
            required_privilege="none",
            required_binaries=_required_binaries_for_paths(paths),
            required_extras=_required_extras_for_paths(paths),
            paths=paths,
            _carrier_builder=builder,
            _carrier_parser=parser,
        )

    if (
        format_carriers.supports(mechanism.id)
        or http2_fields.supports(mechanism.id)
        or quic_fields.supports(mechanism.id)
        or tls_fields.supports(mechanism.id)
        or struct_fields.supports(mechanism.id)
    ):
        if http2_fields.supports(mechanism.id):
            builder, parser = _http2_field_carrier(mechanism)
        elif quic_fields.supports(mechanism.id):
            builder, parser = _quic_field_carrier(mechanism)
        elif tls_fields.supports(mechanism.id):
            builder, parser = _tls_field_carrier(mechanism)
        elif struct_fields.supports(mechanism.id):
            builder, parser = _struct_field_carrier(mechanism)
        else:
            builder, parser = _format_carrier(mechanism)
        paths = _paths_for(mechanism, evidence, register_packet_artifact_paths=False)
        return MechanismAdapter(
            mechanism=mechanism,
            evidence=evidence,
            status=AdapterStatus.REAL_PDU_FIXTURE,
            capabilities=frozenset(
                {
                    AdapterCapability.CODEC_SESSION,
                    AdapterCapability.JSON_ENVELOPE,
                    AdapterCapability.REAL_PDU_FIXTURE,
                    AdapterCapability.PARSER_VALIDATED,
                }
            ),
            required_privilege="none",
            required_binaries=_required_binaries_for_paths(paths),
            required_extras=_required_extras_for_paths(paths),
            paths=paths,
            _carrier_builder=builder,
            _carrier_parser=parser,
        )

    if (
        scapy_field.supports(mechanism.id)
        or scapy_pdu.supports(mechanism)
        or minimal_pdu.supports(mechanism)
    ):
        if scapy_field.supports(mechanism.id):
            builder, parser = _scapy_field_carrier(mechanism)
        elif scapy_pdu.supports(mechanism):
            builder, parser = _scapy_carrier(mechanism)
        else:
            builder, parser = _minimal_carrier(mechanism)
        paths = _paths_for(mechanism, evidence, register_packet_artifact_paths=True)
        return MechanismAdapter(
            mechanism=mechanism,
            evidence=evidence,
            status=AdapterStatus.MINIMAL_PACKET_TEMPLATE,
            capabilities=frozenset(
                {
                    AdapterCapability.CODEC_SESSION,
                    AdapterCapability.JSON_ENVELOPE,
                    AdapterCapability.PACKET_PATH_TEMPLATE,
                    AdapterCapability.PARSER_VALIDATED,
                }
            ),
            required_privilege="none",
            required_binaries=_required_binaries_for_paths(paths),
            required_extras=_required_extras_for_paths(paths),
            paths=paths,
            _carrier_builder=builder,
            _carrier_parser=parser,
        )

    status = _status_for(evidence)
    paths = _paths_for(mechanism, evidence, register_packet_artifact_paths=False)
    return MechanismAdapter(
        mechanism=mechanism,
        evidence=evidence,
        status=status,
        capabilities=_capabilities_for(evidence),
        required_privilege=_required_privilege_for(evidence),
        required_binaries=_required_binaries_for_paths(paths),
        required_extras=_required_extras_for_paths(paths),
        paths=paths,
    )


def adapters_for(mechanisms: list[Mechanism]) -> dict[str, MechanismAdapter]:
    return {mechanism.id: adapter_for(mechanism) for mechanism in mechanisms}


def _status_for(evidence: EvidenceProfile) -> AdapterStatus:
    if evidence.bucket is EvidenceBucket.NEGATIVE_RESULT:
        return AdapterStatus.NEGATIVE_RESULT
    if evidence.bucket is EvidenceBucket.OFFSET_REPRESENTED_ZERO_BLOB:
        return AdapterStatus.OFFSET_REPRESENTED_ZERO_BLOB
    if evidence.bucket is EvidenceBucket.TIMING_SCHEME:
        return AdapterStatus.TIMING_SCHEME
    if evidence.bucket is EvidenceBucket.REAL_DAEMON_OR_CRYPTO_PATH:
        if evidence.carrier_structure is CarrierStructure.CRYPTO_TRANSCRIPT:
            return AdapterStatus.REAL_CRYPTO_PATH
        return AdapterStatus.REAL_DAEMON_PATH
    if evidence.bucket is EvidenceBucket.REAL_PDU_PACKET_PATH:
        return AdapterStatus.MINIMAL_PACKET_TEMPLATE
    return AdapterStatus.CODEC_ONLY


def _capabilities_for(evidence: EvidenceProfile) -> frozenset[AdapterCapability]:
    capabilities = {AdapterCapability.CODEC_SESSION, AdapterCapability.JSON_ENVELOPE}
    match _status_for(evidence):
        case AdapterStatus.NEGATIVE_RESULT:
            capabilities = {AdapterCapability.NEGATIVE_RESULT}
        case AdapterStatus.OFFSET_REPRESENTED_ZERO_BLOB:
            capabilities.add(AdapterCapability.OFFSET_REPRESENTED)
        case AdapterStatus.TIMING_SCHEME:
            capabilities.add(AdapterCapability.TIMING)
        case AdapterStatus.REAL_DAEMON_PATH:
            capabilities.add(AdapterCapability.DAEMON_PATH)
        case AdapterStatus.REAL_CRYPTO_PATH:
            capabilities.add(AdapterCapability.CRYPTO_TRANSCRIPT)
        case AdapterStatus.MINIMAL_PACKET_TEMPLATE:
            capabilities.add(AdapterCapability.PACKET_PATH_TEMPLATE)
        case AdapterStatus.CODEC_ONLY | AdapterStatus.REAL_PDU_FIXTURE:
            pass
    return frozenset(capabilities)


def _required_privilege_for(evidence: EvidenceProfile) -> str:
    match _status_for(evidence):
        case AdapterStatus.MINIMAL_PACKET_TEMPLATE | AdapterStatus.OFFSET_REPRESENTED_ZERO_BLOB:
            return "root_for_packet_path"
        case AdapterStatus.REAL_DAEMON_PATH:
            return "daemon_scenario"
        case _:
            return "none"


def _paths_for(
    mechanism: Mechanism,
    evidence: EvidenceProfile,
    *,
    register_packet_artifact_paths: bool,
) -> tuple[AdapterPath, ...]:
    if evidence.bucket is EvidenceBucket.NEGATIVE_RESULT or not mechanism.is_usable_channel:
        return ()

    paths = [
        AdapterPath(
            kind=AdapterPathKind.MEMORY,
            transport_kind="memory",
            evidence_tier="in_memory_regression",
            claim_status="local_codec_session_not_network_evidence",
            notes="single-process codec/session regression path",
        ),
        AdapterPath(
            kind=AdapterPathKind.FILE_RECORD,
            transport_kind="file",
            evidence_tier="in_memory_regression",
            claim_status="local_file_transport_record_not_network_evidence",
            records_artifact=True,
            notes="JSON carrier-symbol record for local or multi-process tests",
        ),
        AdapterPath(
            kind=AdapterPathKind.TIMED_MEMORY,
            transport_kind="timed_memory",
            evidence_tier=(
                "timing_path"
                if mechanism.capacity_model is CapacityModel.TIMING
                else "in_memory_regression"
            ),
            claim_status="local_timed_memory_scheme_demonstration_not_capacity",
            notes="local paced transport with timestamp/error evidence",
        ),
    ]

    if register_packet_artifact_paths:
        paths.extend(
            [
                AdapterPath(
                    kind=AdapterPathKind.PCAP_ARTIFACT,
                    transport_kind="pcap",
                    evidence_tier="real_pdu_packet_path",
                    claim_status="parser_visible_pcap_artifact_not_live_tap",
                    records_artifact=True,
                    scenario_id=_pcap_scenario_id(mechanism.id),
                    notes="classic pcap artifact with parser-visible carrier bytes",
                ),
                AdapterPath(
                    kind=AdapterPathKind.AFPACKET_IPV4,
                    transport_kind="afpacket_ipv4",
                    evidence_tier="real_pdu_packet_path",
                    claim_status="live_linux_afpacket_path_requires_prepared_netns",
                    privilege="root",
                    required_binaries=("ip", "tcpdump"),
                    records_artifact=True,
                    scenario_id=(
                        "tcp-reserved-bits-afpacket-netns"
                        if mechanism.id == "tcp-reserved-bits"
                        else None
                    ),
                    notes="live Linux AF_PACKET over an IPv4 packet path",
                ),
            ]
        )

    if (
        scapy_pdu.supports(mechanism)
        or scapy_field.supports(mechanism.id)
        or minimal_pdu.supports(mechanism)
    ):
        by_field = scapy_field.supports(mechanism.id)
        paths.append(
            AdapterPath(
                kind=AdapterPathKind.SCAPY_PACKET,
                transport_kind="scapy_packet",
                evidence_tier="real_pdu_packet_path",
                claim_status="scapy_built_real_pdu_independent_dissect_not_live_tap",
                required_extras=("packet",),
                records_artifact=True,
                notes=(
                    "generic Scapy-built real PDU with the covert value in the named "
                    "protocol field; Scapy dissect independently validates"
                    if by_field
                    else "generic Scapy-built real PDU with covert bits at the locator; "
                    "Scapy dissect independently validates field placement"
                ),
            )
        )
    if mechanism.id == "dns-txt-tunnel":
        paths.append(
            AdapterPath(
                kind=AdapterPathKind.DNS_TXT_DNSPYTHON,
                transport_kind="dns_txt_dnspython",
                evidence_tier="real_daemon_path",
                claim_status="local_dnspython_client_server_txt_message_path",
                required_extras=("dns",),
                records_artifact=True,
                notes=(
                    "paired dnspython client/server TXT message exchange; covert bytes "
                    "in a conforming TXT record, dnspython re-parse validates"
                ),
            )
        )
    if mechanism.id == "dns-null-tunnel":
        paths.append(
            AdapterPath(
                kind=AdapterPathKind.DNS_NULL_DNSPYTHON,
                transport_kind="dns_null_dnspython",
                evidence_tier="real_daemon_path",
                claim_status="local_dnspython_client_server_null_message_path",
                required_extras=("dns",),
                records_artifact=True,
                notes=(
                    "paired dnspython client/server NULL message exchange; covert bytes "
                    "in a conforming NULL record (RDATA is anything at all), dnspython "
                    "re-parse validates"
                ),
            )
        )
    if mechanism.id == "ssh-kexinit-cookie":
        paths.append(
            AdapterPath(
                kind=AdapterPathKind.SSH_KEXINIT_PARAMIKO,
                transport_kind="ssh_kexinit_paramiko",
                evidence_tier="real_pdu_packet_path",
                claim_status="local_paramiko_client_server_kexinit_message_path",
                required_extras=("ssh",),
                records_artifact=True,
                notes=(
                    "in-process paramiko SSH_MSG_KEXINIT build/parse; bytes occupy only "
                    "the 16-byte random cookie and the reserved uint32 remains zero"
                ),
            )
        )
        paths.append(
            AdapterPath(
                kind=AdapterPathKind.SSH_KEXINIT_OPENSSH,
                transport_kind="ssh_kexinit_openssh",
                evidence_tier="real_daemon_path",
                claim_status="paramiko_client_openssh_daemon_completed_key_exchange",
                required_binaries=("sshd",),
                required_extras=("ssh",),
                scenario_id="ssh-kexinit-openssh-real-daemon",
                records_artifact=True,
                notes=(
                    "Paramiko client substitutes the 16-byte KEXINIT cookie, preserves "
                    "the reserved uint32 as zero, and completes key exchange with a "
                    "production OpenSSH daemon"
                ),
            )
        )
    if mechanism.id == "coap-tunnel":
        paths.append(
            AdapterPath(
                kind=AdapterPathKind.COAP_AIOCOAP,
                transport_kind="coap_aiocoap",
                evidence_tier="real_daemon_path",
                claim_status="local_aiocoap_client_server_elective_option_path",
                required_extras=("iot",),
                records_artifact=True,
                notes=(
                    "paired aiocoap client/server CoAP message exchange; covert bytes in "
                    "an unknown elective option, aiocoap Message codec validates"
                ),
            )
        )
    if mechanism.id == "bgp-optional-transitive":
        paths.append(
            AdapterPath(
                kind=AdapterPathKind.BGP_SCAPY,
                transport_kind="bgp_scapy",
                evidence_tier="real_pdu_packet_path",
                claim_status="local_scapy_speaker_peer_optional_transitive_attr_path",
                required_extras=("packet",),
                records_artifact=True,
                notes=(
                    "paired scapy BGP speaker/peer UPDATE exchange; covert bytes in an "
                    "unknown optional-transitive path attribute (passed on unchanged per "
                    "RFC 4271), scapy BGP codec validates"
                ),
            )
        )
    if mechanism.id == "websocket-tunnel":
        paths.append(
            AdapterPath(
                kind=AdapterPathKind.WEBSOCKET_WEBSOCKETS,
                transport_kind="websocket_websockets",
                evidence_tier="real_daemon_path",
                claim_status="local_websockets_client_server_frame_path",
                required_extras=("realtime",),
                records_artifact=True,
                notes=(
                    "paired websockets client/server frame exchange; covert bytes in the "
                    "conforming binary-frame payload, websockets codec validates"
                ),
            )
        )
    if mechanism.id == "edns0-padding":
        paths.append(
            AdapterPath(
                kind=AdapterPathKind.DNS_EDNS0_PADDING_DAEMON,
                transport_kind="dns_edns0_padding",
                evidence_tier="real_daemon_path",
                claim_status="dig_dnsmasq_daemon_path_requires_prepared_netns",
                privilege="cap_net_admin",
                required_binaries=("dig", "dnsmasq", "ip", "tcpdump"),
                required_extras=("packet",),
                scenario_id="edns0-padding-dnsmasq-dig-real-daemon",
                records_artifact=True,
                notes="real dig client, dnsmasq resolver, netns, and tcpdump capture",
            )
        )
    if mechanism.id == "http2-ping-opaque":
        paths.append(
            AdapterPath(
                kind=AdapterPathKind.HTTP2_HYPER_H2,
                transport_kind="http2_hyper_h2",
                evidence_tier="real_daemon_path",
                claim_status="local_hyper_h2_client_server_ping_path",
                required_extras=("daemon",),
                scenario_id="http2-ping-opaque-hyper-h2",
                records_artifact=True,
                notes="real hyper-h2 client/server state machines exchange HTTP/2 SETTINGS and PING/ACK frames",
            )
        )
    if mechanism.id == "http3-reserved-settings":
        paths.append(
            AdapterPath(
                kind=AdapterPathKind.HTTP3_AIOQUIC_RESERVED_SETTINGS,
                transport_kind="http3_aioquic_reserved_settings",
                evidence_tier="real_daemon_path",
                claim_status="local_aioquic_h3_settings_reserved_value_controlled_hook",
                required_extras=("daemon",),
                scenario_id="http3-reserved-settings-aioquic",
                records_artifact=True,
                notes=(
                    "real aioquic HTTP/3 client/server SETTINGS processing with a "
                    "controlled reserved-setting value hook"
                ),
            )
        )
    if mechanism.id == "quic-connection-id":
        paths.append(
            AdapterPath(
                kind=AdapterPathKind.QUIC_AIOQUIC_CONNECTION_ID,
                transport_kind="quic_aioquic_connection_id",
                evidence_tier="real_daemon_path",
                claim_status="local_aioquic_client_server_initial_dcid_controlled_hook",
                required_extras=("daemon",),
                scenario_id="quic-connection-id-aioquic",
                records_artifact=True,
                notes=(
                    "real aioquic client/server QUIC Initial processing with a controlled "
                    "pre-connect client DCID hook"
                ),
            )
        )
    if mechanism.id == "ecdsa-nonce":
        paths.append(
            AdapterPath(
                kind=AdapterPathKind.CRYPTO_ECDSA_NONCE,
                transport_kind="crypto_ecdsa_nonce",
                evidence_tier="real_crypto_path",
                claim_status="local_real_ecdsa_sign_verify_transcript",
                required_extras=("crypto",),
                scenario_id="ecdsa-nonce-local-crypto-transcript",
                records_artifact=True,
                notes="real ECDSA signing/verification transcript with honest-random control",
            )
        )
    if mechanism.id == "rsa-pss-salt":
        paths.append(
            AdapterPath(
                kind=AdapterPathKind.CRYPTO_RSA_PSS_SALT,
                transport_kind="crypto_rsa_pss_salt",
                evidence_tier="real_crypto_path",
                claim_status="local_real_rsa_pss_sign_verify_transcript",
                required_extras=("crypto",),
                scenario_id="rsa-pss-salt-local-crypto-transcript",
                records_artifact=True,
                notes="real RSA-PSS signing/verification transcript with honest-random control",
            )
        )
    return tuple(paths)


def _pcap_scenario_id(mechanism_id: str) -> str | None:
    if mechanism_id in _DEFAULT_PCAP_SCENARIOS:
        return _DEFAULT_PCAP_SCENARIOS[mechanism_id]
    return None


def _required_binaries_for_paths(paths: tuple[AdapterPath, ...]) -> tuple[str, ...]:
    return tuple(sorted({binary for path in paths for binary in path.required_binaries}))


def _required_extras_for_paths(paths: tuple[AdapterPath, ...]) -> tuple[str, ...]:
    return tuple(sorted({extra for path in paths for extra in path.required_extras}))


def _struct_field_carrier(mechanism: Mechanism) -> tuple[CarrierBuilder, CarrierParser]:
    """Real minimal-structure carrier (covert value in the genuine protocol field)."""

    def build(symbol: Symbol) -> bytes:
        return struct_fields.build_structure(mechanism.id, symbol)

    def parse(carrier: bytes) -> Symbol:
        return struct_fields.parse_structure(mechanism.id, carrier)

    return build, parse


def _tls_field_carrier(mechanism: Mechanism) -> tuple[CarrierBuilder, CarrierParser]:
    """Serialized TLS structure fixture with the symbol in its protocol element."""

    def build(symbol: Symbol) -> bytes:
        return tls_fields.build_record(mechanism.id, symbol)

    def parse(carrier: bytes) -> Symbol:
        return tls_fields.parse_record(mechanism.id, carrier)

    return build, parse


def _quic_field_carrier(mechanism: Mechanism) -> tuple[CarrierBuilder, CarrierParser]:
    """Real QUIC wire-structure carrier (the covert value goes in the genuine QUIC field)."""

    def build(symbol: Symbol) -> bytes:
        return quic_fields.build_packet(mechanism.id, symbol)

    def parse(carrier: bytes) -> Symbol:
        return quic_fields.parse_packet(mechanism.id, carrier)

    return build, parse


def _http2_field_carrier(mechanism: Mechanism) -> tuple[CarrierBuilder, CarrierParser]:
    """Real HTTP/2 frame carrier (hyperframe sets the real padding/priority/flags field)."""

    def build(symbol: Symbol) -> bytes:
        return http2_fields.build_frame(mechanism.id, symbol)

    def parse(carrier: bytes) -> Symbol:
        return http2_fields.parse_frame(mechanism.id, carrier)

    return build, parse


def _format_carrier(mechanism: Mechanism) -> tuple[CarrierBuilder, CarrierParser]:
    """Real file/token-format carrier (JWT/UUIDv8/OpenPGP/TZif/Opus/Binary HTTP)."""

    def build(symbol: Symbol) -> bytes:
        return format_carriers.build_format(mechanism.id, symbol)

    def parse(carrier: bytes) -> Symbol:
        return format_carriers.parse_format(mechanism.id, carrier)

    return build, parse


def _minimal_carrier(mechanism: Mechanism) -> tuple[CarrierBuilder, CarrierParser]:
    """Minimal real-PDU carrier for a protocol without a dedicated Scapy layer."""

    symbol_is_bytes = isinstance(codec_for(mechanism), VariableLengthCodec)
    field_bytes = (mechanism.locator.bit_width // 8) if mechanism.locator is not None else 0

    def build(symbol: Symbol) -> bytes:
        value = symbol if isinstance(symbol, int) else int.from_bytes(bytes(symbol), "big")
        return minimal_pdu.build_minimal_pdu(mechanism, value)

    def parse(carrier: bytes) -> Symbol:
        value = minimal_pdu.extract_field(mechanism, carrier)
        return value.to_bytes(field_bytes, "big") if symbol_is_bytes else value

    return build, parse


def _scapy_field_carrier(mechanism: Mechanism) -> tuple[CarrierBuilder, CarrierParser]:
    """Named-field Scapy carrier: set/read the covert value in the real protocol field."""

    def build(symbol: Symbol) -> bytes:
        if not isinstance(symbol, int):
            raise TypeError(f"{mechanism.id}: expected int-valued carrier symbol")
        return scapy_field.build_field_pdu(mechanism.id, symbol)

    def parse(carrier: bytes) -> Symbol:
        return scapy_field.extract_field_value(mechanism.id, carrier)

    return build, parse


def _scapy_carrier(mechanism: Mechanism) -> tuple[CarrierBuilder, CarrierParser]:
    """Generic Scapy-backed carrier for a located header-field mechanism.

    Builds a real PDU with the covert symbol at the locator and recovers it via an
    independent Scapy dissect. Handles both int symbols (fixed-width fields) and
    byte-string symbols (variable-length fields) by mapping bytes to/from the field's
    big-endian integer value. Scapy is imported lazily inside ``scapy_pdu``, so these
    closures only require the ``packet`` extra when actually exercised.
    """

    width = mechanism.locator.bit_width if mechanism.locator is not None else 0
    symbol_is_bytes = isinstance(codec_for(mechanism), VariableLengthCodec)
    field_bytes = width // 8

    def build(symbol: Symbol) -> bytes:
        if isinstance(symbol, int):
            value = symbol
        elif isinstance(symbol, bytes):
            value = int.from_bytes(symbol, "big")
        else:
            raise TypeError(f"{mechanism.id}: expected int or bytes carrier symbol")
        return scapy_pdu.build_real_pdu(mechanism, value)

    def parse(carrier: bytes) -> Symbol:
        value = scapy_pdu.extract_field(mechanism, carrier)
        if symbol_is_bytes:
            return value.to_bytes(field_bytes, "big")
        return value

    return build, parse


def _bytes_symbol(symbol: Symbol, expected_len: int, mechanism_id: str) -> bytes:
    if not isinstance(symbol, bytes):
        raise TypeError(f"{mechanism_id}: expected bytes-valued carrier symbol")
    if len(symbol) != expected_len:
        raise ValueError(f"{mechanism_id}: expected {expected_len} carrier bytes")
    return symbol


_DNS_CAA_QNAME = "covert.example."


def _build_dns_caa(symbol: Symbol) -> bytes:
    if not isinstance(symbol, int):
        raise TypeError("dns-caa-flags: expected int-valued carrier symbol")
    from .pdu.dns_txt import build_caa_flags_response

    return build_caa_flags_response(_DNS_CAA_QNAME, symbol)


def _parse_dns_caa(carrier: bytes) -> Symbol:
    from .pdu.dns_txt import parse_caa_flags

    return parse_caa_flags(carrier)


def _build_http2_ping(symbol: Symbol) -> bytes:
    return build_connection_preface_ping(_bytes_symbol(symbol, 8, "http2-ping-opaque"))


def _parse_http2_ping(carrier: bytes) -> Symbol:
    pings = [frame for frame in parse_frames(carrier) if frame.is_ping]
    if not pings:
        raise ValueError("http2-ping-opaque: no PING frame found")
    return pings[-1].payload


def _build_quic_initial(symbol: Symbol) -> bytes:
    return build_initial_packet(_bytes_symbol(symbol, DCID_LEN, "quic-connection-id"))


def _parse_quic_initial(carrier: bytes) -> Symbol:
    return parse_long_header(carrier).dcid


def _build_rtcp_app(symbol: Symbol) -> bytes:
    return build_app_packet(_bytes_symbol(symbol, RTCP_APP_DATA_LEN, "rtp-rtcp-ext-app"))


def _parse_rtcp_app(carrier: bytes) -> Symbol:
    return parse_app_packet(carrier).app_data


def _build_tcp_reserved_bits(symbol: Symbol) -> bytes:
    if not isinstance(symbol, int):
        raise TypeError("tcp-reserved-bits: expected int-valued carrier symbol")
    if not 0 <= symbol < (1 << TCP_RESERVED_BITS_WIDTH):
        raise ValueError("tcp-reserved-bits: symbol does not fit in 3 reserved bits")
    return build_tcp_reserved_bits_segment(symbol)


def _parse_tcp_reserved_bits(carrier: bytes) -> Symbol:
    return parse_tcp_reserved_bits(carrier)


_REAL_PDU_FIXTURES: dict[str, tuple[CarrierBuilder, CarrierParser]] = {
    "http2-ping-opaque": (_build_http2_ping, _parse_http2_ping),
    "quic-connection-id": (_build_quic_initial, _parse_quic_initial),
    "rtp-rtcp-ext-app": (_build_rtcp_app, _parse_rtcp_app),
    "dns-caa-flags": (_build_dns_caa, _parse_dns_caa),
}

_MINIMAL_PACKET_TEMPLATES: dict[str, tuple[CarrierBuilder, CarrierParser]] = {
    "tcp-reserved-bits": (_build_tcp_reserved_bits, _parse_tcp_reserved_bits),
}


_DEFAULT_PCAP_SCENARIOS = {
    "http2-ping-opaque": "http2-ping-opaque-real-pdu-smoke",
    "quic-connection-id": "quic-connection-id-real-pdu-smoke",
    "rtp-rtcp-ext-app": "rtp-rtcp-ext-app-real-pdu-smoke",
    "tcp-reserved-bits": "tcp-reserved-bits-real-pdu-smoke",
}


__all__ = [
    "AdapterCapability",
    "AdapterPath",
    "AdapterPathKind",
    "AdapterStatus",
    "CarrierUnit",
    "MechanismAdapter",
    "adapter_for",
    "adapters_for",
]
