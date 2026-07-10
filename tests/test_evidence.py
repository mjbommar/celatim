"""Evidence classification: current claims are conservative and auditable."""

import json
from pathlib import Path

import pytest

from celatim.adapter import AdapterPathKind, adapter_for
from celatim.catalog import load_mechanisms
from celatim.cli import support_matrix_main
from celatim.evidence import (
    CarrierStructure,
    ControlStrength,
    EvidenceBucket,
    IndependentValidator,
    ThroughputStatus,
    UpgradePriority,
    bucket_counts,
    classify_evidence,
)
from celatim.report import support_matrix_markdown, support_matrix_report

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"
ROOT = Path(__file__).resolve().parents[2]
SUPPORT_MATRIX = ROOT / "docs" / "evidence-support-matrix.md"
requires_paper_artifact = pytest.mark.skipif(
    not SUPPORT_MATRIX.is_file(),
    reason="requires the companion RFC survey repository",
)


def mechs_by_id():
    return {m.id: m for m in load_mechanisms(DATA)}


def test_zero_pad_payload_rows_are_not_counted_as_real_pdu_evidence():
    # bgp-path-attr-flags is deliberately retained as the single zero-blob exemplar so the
    # evidence framework keeps a live contrast case for the paper's tiering (every other
    # usable mechanism now has a real-structure carrier).
    mechs = mechs_by_id()
    profile = classify_evidence(mechs["bgp-path-attr-flags"])
    assert profile.bucket is EvidenceBucket.OFFSET_REPRESENTED_ZERO_BLOB
    assert profile.carrier_structure is CarrierStructure.ZERO_PAD_NOMINAL_OFFSET
    assert profile.control_strength is ControlStrength.VACUOUS_ZERO_CARRIER
    assert profile.independent_validator is IndependentValidator.NONE
    assert profile.upgrade_priority is UpgradePriority.MARQUEE


def test_marquee_fixtures_have_been_upgraded_to_real_pdu_evidence():
    mechs = mechs_by_id()
    for mid in ("http2-ping-opaque", "quic-connection-id", "rtp-rtcp-ext-app"):
        profile = classify_evidence(mechs[mid])
        assert profile.bucket is EvidenceBucket.REAL_PDU_PACKET_PATH
        assert profile.carrier_structure is CarrierStructure.REAL_PROTOCOL_PDU
        assert profile.control_strength is ControlStrength.NONZERO_SURROUNDING_BYTES
        assert profile.independent_validator is IndependentValidator.SECOND_PARSER
        assert profile.upgrade_priority is UpgradePriority.MARQUEE


def test_real_dns_and_crypto_paths_are_separated_from_zero_blob_rows():
    mechs = mechs_by_id()

    dns = classify_evidence(mechs["edns0-padding"])
    assert dns.bucket is EvidenceBucket.REAL_DAEMON_OR_CRYPTO_PATH
    assert dns.carrier_structure is CarrierStructure.REAL_PROTOCOL_PDU
    assert dns.control_strength is ControlStrength.DAEMON_CONTROL
    assert dns.independent_validator is IndependentValidator.DAEMON_ACCEPTED

    salt = classify_evidence(mechs["rsa-pss-salt"])
    assert salt.bucket is EvidenceBucket.REAL_DAEMON_OR_CRYPTO_PATH
    assert salt.carrier_structure is CarrierStructure.CRYPTO_TRANSCRIPT
    assert salt.control_strength is ControlStrength.HONEST_RANDOM_CONTROL
    assert salt.throughput_status is ThroughputStatus.NOT_APPLICABLE


def test_minimal_packet_and_timing_evidence_are_labeled_precisely():
    mechs = mechs_by_id()

    tcp = classify_evidence(mechs["tcp-reserved-bits"])
    assert tcp.bucket is EvidenceBucket.REAL_PDU_PACKET_PATH
    assert tcp.carrier_structure is CarrierStructure.MINIMAL_PROTOCOL_PDU
    assert tcp.control_strength is ControlStrength.INDEPENDENT_PARSER_CHECKED
    assert tcp.independent_validator is IndependentValidator.SECOND_PARSER
    assert tcp.throughput_status is ThroughputStatus.SENDER_BOUND

    timing = classify_evidence(mechs["ntp-timing"])
    assert timing.bucket is EvidenceBucket.TIMING_SCHEME
    assert timing.carrier_structure is CarrierStructure.TIMING_ONLY
    assert timing.control_strength is ControlStrength.CONSTANT_RATE_CONTROL
    assert timing.throughput_status is ThroughputStatus.SCHEME_ONLY


def test_negative_results_and_summary_counts_are_explicit():
    mechs = mechs_by_id()
    neg = classify_evidence(mechs["quic-hdr-protected-neg"])
    assert neg.bucket is EvidenceBucket.NEGATIVE_RESULT
    assert neg.carrier_structure is CarrierStructure.NEGATIVE_CONTROL

    counts = bucket_counts([classify_evidence(m) for m in mechs.values()])
    assert counts[EvidenceBucket.OFFSET_REPRESENTED_ZERO_BLOB] > 0
    assert counts[EvidenceBucket.REAL_DAEMON_OR_CRYPTO_PATH] >= 3
    assert counts[EvidenceBucket.TIMING_SCHEME] >= 3
    assert counts[EvidenceBucket.NEGATIVE_RESULT] == 4


def test_support_matrix_markdown_contains_marquee_and_full_tables():
    text = support_matrix_markdown(load_mechanisms(DATA))
    assert "# Evidence Support Matrix" in text
    assert "| Adapter path | Count |" in text
    assert "## Marquee Upgrade Subset" in text
    assert "`real_pdu_fixture`" in text
    assert "`parser_validated`" in text
    assert "`pcap_artifact`" in text
    assert "`dns_edns0_padding_daemon`" in text
    assert "`offset_represented_zero_blob`" in text
    assert "`zero_pad_nominal_offset`" in text
    assert "`bgp-path-attr-flags`" in text
    assert "`edns0-padding`" in text


def test_adapter_paths_are_registered_by_executable_transport():
    mechs = mechs_by_id()
    http2 = adapter_for(mechs["http2-ping-opaque"])
    edns = adapter_for(mechs["edns0-padding"])
    ecdsa = adapter_for(mechs["ecdsa-nonce"])
    offset = adapter_for(mechs["bgp-path-attr-flags"])

    assert http2.supports_transport("pcap")
    assert http2.supports_transport("afpacket_ipv4")
    http2_paths = {path.kind: path for path in http2.paths}
    assert http2_paths[AdapterPathKind.PCAP_ARTIFACT].scenario_id == (
        "http2-ping-opaque-real-pdu-smoke"
    )
    assert http2_paths[AdapterPathKind.AFPACKET_IPV4].required_binaries == ("ip", "tcpdump")
    assert http2.path_for_transport("pcap") is http2_paths[AdapterPathKind.PCAP_ARTIFACT]

    dns_path = edns.path_for_transport("dns_edns0_padding")
    assert dns_path is not None
    assert dns_path.kind is AdapterPathKind.DNS_EDNS0_PADDING_DAEMON
    assert dns_path.privilege == "cap_net_admin"
    assert dns_path.required_binaries == ("dig", "dnsmasq", "ip", "tcpdump")
    assert dns_path.required_extras == ("packet",)

    crypto_path = ecdsa.path_for_transport("crypto_ecdsa_nonce")
    assert crypto_path is not None
    assert crypto_path.kind is AdapterPathKind.CRYPTO_ECDSA_NONCE
    assert crypto_path.required_extras == ("crypto",)

    assert offset.supports_transport("file")
    assert not offset.supports_transport("pcap")


def test_support_matrix_report_is_machine_readable():
    report = support_matrix_report(load_mechanisms(DATA)).to_json()

    assert report["schema_version"] == "celatim.support_matrix.v1"
    assert report["mechanism_count"] == len(report["rows"])
    assert report["marquee_count"] > 0
    assert report["evidence_bucket_counts"]["real_pdu_packet_path"] > 0
    assert report["adapter_path_kind_counts"]["pcap_artifact"] >= 4
    assert report["adapter_path_kind_counts"]["http2_hyper_h2"] == 1
    assert report["adapter_path_kind_counts"]["http3_aioquic_reserved_settings"] == 1
    assert report["adapter_path_kind_counts"]["quic_aioquic_connection_id"] == 1
    assert report["adapter_path_kind_counts"]["dns_edns0_padding_daemon"] == 1
    rows = {row["mechanism_id"]: row for row in report["rows"]}
    assert rows["http2-ping-opaque"]["adapter_status"] == "real_pdu_fixture"
    assert rows["http2-ping-opaque"]["adapter_capabilities"] == sorted(
        rows["http2-ping-opaque"]["adapter_capabilities"]
    )
    assert [path["kind"] for path in rows["http2-ping-opaque"]["adapter_paths"]] == [
        "memory",
        "file_record",
        "timed_memory",
        "pcap_artifact",
        "afpacket_ipv4",
        "http2_hyper_h2",
    ]
    assert rows["http2-ping-opaque"]["required_extras"] == ["daemon"]
    assert [path["kind"] for path in rows["http3-reserved-settings"]["adapter_paths"]] == [
        "memory",
        "file_record",
        "timed_memory",
        "http3_aioquic_reserved_settings",
    ]
    assert rows["http3-reserved-settings"]["required_extras"] == ["daemon"]
    assert [path["kind"] for path in rows["quic-connection-id"]["adapter_paths"]] == [
        "memory",
        "file_record",
        "timed_memory",
        "pcap_artifact",
        "afpacket_ipv4",
        "quic_aioquic_connection_id",
    ]
    assert rows["quic-connection-id"]["required_extras"] == ["daemon"]
    assert rows["edns0-padding"]["adapter_paths"][-1]["transport_kind"] == "dns_edns0_padding"
    assert rows["edns0-padding"]["required_extras"] == ["packet"]
    assert rows["bgp-path-attr-flags"]["carrier_structure"] == "zero_pad_nominal_offset"
    assert [path["transport_kind"] for path in rows["bgp-path-attr-flags"]["adapter_paths"]] == [
        "memory",
        "file",
        "timed_memory",
    ]


@requires_paper_artifact
def test_support_matrix_doc_is_generated_from_current_catalog():
    assert SUPPORT_MATRIX.read_text() == support_matrix_markdown(load_mechanisms(DATA))


def test_support_matrix_cli_writes_generated_markdown(tmp_path):
    out = tmp_path / "matrix.md"
    assert support_matrix_main(["--catalog", str(DATA), "--output", str(out)]) == 0
    assert out.read_text() == support_matrix_markdown(load_mechanisms(DATA))


def test_support_matrix_cli_writes_generated_json(tmp_path):
    out = tmp_path / "matrix.json"
    assert (
        support_matrix_main(["--catalog", str(DATA), "--format", "json", "--output", str(out)]) == 0
    )
    assert json.loads(out.read_text()) == support_matrix_report(load_mechanisms(DATA)).to_json()


def test_support_matrix_cli_uses_packaged_catalog_default_outside_measurement_tree(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "matrix.md"

    assert support_matrix_main(["--output", str(out)]) == 0

    assert out.read_text() == support_matrix_markdown(load_mechanisms(DATA))
