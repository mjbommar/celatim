"""Detection: field locators, the derived detectability tier, and stateless
rule emission with an honest coverage split."""

import json
import shutil
import struct
from pathlib import Path

import pytest

from celatim.adapter import adapter_for
from celatim.catalog import load_mechanisms
from celatim.detect import (
    DetectorReplayBackend,
    TraceSourceKind,
    bpf_filter,
    coverage,
    default_replay_mechanisms,
    detector_provenance_for,
    emittable,
    iptables_u32_rule,
    load_trace_manifest,
    nftables_rule,
    replay_detector_corpus,
    replay_detectors_on_pcap,
    scrub_tcp_reserved_bits_pcap,
)
from celatim.model import (
    Detectability,
    FieldLocator,
    WireBase,
)
from celatim.testbed import (
    build_tcp_reserved_bits_frame,
    default_ipv4_packet_path_config_for,
    tcp_reserved_bits_from_frame,
)

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def mechs():
    return {m.id: m for m in load_mechanisms(DATA)}


# --- locator wire-offset arithmetic -----------------------------------------


def test_locator_byte_math():
    # RFC 9768 leaves three Reserved bits at TH bit offset 100.
    loc = FieldLocator(base=WireBase.TH, bit_offset=100, bit_width=3)
    assert loc.byte_offset == 12
    assert loc.spans_single_byte
    assert loc.byte_mask == 0x0E


def test_locator_high_nibble_mask():
    # A field in the high nibble (offset 96, width 4) masks 0xf0.
    loc = FieldLocator(base=WireBase.TH, bit_offset=96, bit_width=4)
    assert loc.byte_mask == 0xF0


# --- detectability tier ------------------------------------------------------


def test_detectability_spread_across_catalog():
    m = mechs()
    assert m["tcp-reserved-bits"].detectability is Detectability.STATELESS_FILTER
    assert m["ipv4-id-atomic"].detectability is Detectability.STATISTICAL  # arbitrary value
    assert m["http3-reserved-frame-types"].detectability is Detectability.ENDPOINT_ONLY  # AEAD
    assert m["ah-reserved"].detectability is Detectability.STATEFUL_DPI  # visible, authenticated
    assert m["http2-ping-opaque"].detectability is Detectability.VISIBILITY_DEPENDENT  # h2c vs TLS
    assert m["quic-padding-frame-count"].detectability is Detectability.STATISTICAL  # timing
    assert m["rsa-pss-salt"].detectability is Detectability.UNDETECTABLE_ONWIRE  # subliminal


# --- rule emission -----------------------------------------------------------


def test_bpf_for_tcp_reserved():
    m = mechs()["tcp-reserved-bits"]
    assert bpf_filter(m) == "tcp[12] & 0x0e != 0"


def test_nftables_for_tcp_reserved():
    m = mechs()["tcp-reserved-bits"]
    rule = nftables_rule(m)
    assert "@th,100,3 != 0" in rule
    assert "meta l4proto tcp" in rule
    assert "RFC 9768" in rule
    assert "RFC 9293" in rule  # provenance carried into the comment


def test_reserved_value_match_parses_for_quic_reserved_version():
    m = mechs()["quic-reserved-version"]
    assert m.locator is not None
    assert m.locator.bit_width == 32
    assert m.raw_capacity_bits == 28
    assert len(m.reserved_value_matches) == 1
    match = m.reserved_value_matches[0]
    assert match.mask == 0x0F0F0F0F
    assert match.value == 0x0A0A0A0A
    assert match.matches(0xFAFAFAFA)
    assert not match.matches(0x00000001)


def test_nftables_for_quic_reserved_version_uses_masked_value_set():
    m = mechs()["quic-reserved-version"]
    rule = nftables_rule(m)

    assert "(@nh,224,32 & 0x0f0f0f0f == 0x0a0a0a0a)" in rule
    assert "RFC 9000" in rule


def test_iptables_u32_for_tcp_reserved():
    m = mechs()["tcp-reserved-bits"]
    assert (
        iptables_u32_rule(m)
        == '-m u32 --u32 "6&0xFF=6 && 4&0x3FFF=0 && 0>>22&0x3C@12>>24&0x0E=0x1:0x0E"'
    )


def test_emitter_refuses_non_stateless():
    # IP ID is located but arbitrary-valued -> not stateless-alertable.
    m = mechs()["ipv4-id-atomic"]
    with pytest.raises(ValueError):
        bpf_filter(m)
    with pytest.raises(ValueError):
        iptables_u32_rule(m)
    with pytest.raises(ValueError):
        nftables_rule(m)


def test_coverage_buckets_and_emittable_set():
    ms = load_mechanisms(DATA)
    cov = coverage(ms)
    # Every mechanism lands in exactly one bucket.
    assert sum(len(v) for v in cov.values()) == len(ms)
    assert len(emittable(ms)) == 70
    assert {"tcp-reserved-bits", "ipv4-reserved-flag", "sctp-chunk-flags"} <= {
        m.id for m in emittable(ms)
    }
    assert [m.id for m in default_replay_mechanisms(ms)] == [
        "tcp-reserved-bits",
        "ipv4-reserved-flag",
    ]
    assert [
        m.id
        for m in default_replay_mechanisms(
            ms,
            backend=DetectorReplayBackend.TSHARK_DISPLAY_FILTER,
        )
    ] == ["tcp-reserved-bits"]
    assert [
        m.id
        for m in default_replay_mechanisms(
            ms,
            backend=DetectorReplayBackend.SURICATA_RULE,
        )
    ] == ["tcp-reserved-bits"]


def test_detector_provenance_names_same_code_and_generated_rule_paths():
    m = mechs()["tcp-reserved-bits"]
    units = adapter_for(m).encode_payload(b"\x00\xffdetector")

    records = detector_provenance_for(m, units)

    assert [record.name for record in records] == [
        "tcp-reserved-bits-same-code-stateless-nonzero",
        "tcp-reserved-bits-nftables-rule",
        "tcp-reserved-bits-iptables-u32-rule",
        "tcp-reserved-bits-bpf-filter",
    ]
    same_code = records[0]
    assert same_code.implementation_kind.value == "same_code"
    assert same_code.executed is True
    assert same_code.detectability is Detectability.STATELESS_FILTER
    assert same_code.predicate is not None
    assert same_code.predicate.value == "nonzero"
    assert same_code.checked_units == len(units)
    assert same_code.matched_units > 0
    assert same_code.detected is True
    assert same_code.false_positive_estimate is False
    assert same_code.benign_basis == "scenario_control_fixture_not_fp_estimate"
    assert same_code.command == ()
    assert same_code.returncode is None

    nft, iptables, bpf = records[1:]
    assert {record.implementation_kind.value for record in (nft, iptables, bpf)} == {
        "generated_kernel_rule"
    }
    assert {record.executed for record in (nft, iptables, bpf)} == {False}
    assert nft.rule_format == "nftables"
    assert "@th,100,3 != 0" in str(nft.rule)
    assert iptables.rule_format == "iptables-u32"
    assert iptables.rule == (
        '-m u32 --u32 "6&0xFF=6 && 4&0x3FFF=0 && 0>>22&0x3C@12>>24&0x0E=0x1:0x0E"'
    )
    assert bpf.rule_format == "bpf"
    assert bpf.rule == "tcp[12] & 0x0e != 0"
    assert all(record.command == () for record in (nft, iptables, bpf))


def test_detector_provenance_classifies_non_stateless_paths_without_fp_claim():
    m = mechs()["http2-ping-opaque"]
    units = adapter_for(m).encode_payload(b"\x00\xffdetector")

    records = detector_provenance_for(m, units)

    assert len(records) == 1
    record = records[0]
    assert record.name == "http2-ping-opaque-detectability-classification"
    assert record.implementation_kind.value == "same_code"
    assert record.executed is True
    assert record.result == "not_stateless_filterable"
    assert record.detected is None
    assert record.checked_units == 0
    assert record.false_positive_estimate is False
    assert record.command == ()


def test_detector_replay_missing_tool_does_not_claim_false_positive_estimate(tmp_path):
    m = mechs()["tcp-reserved-bits"]
    pcap = tmp_path / "clean.pcap"
    _write_test_ethernet_pcap(
        pcap,
        [build_tcp_reserved_bits_frame(default_ipv4_packet_path_config_for(m.id), 0, index=0)],
    )

    report = replay_detectors_on_pcap(
        [m],
        pcap,
        source_kind=TraceSourceKind.LOCAL_GENERATED_CONTROL,
        trace_name="unit-test-clean-control",
        filtering_assumptions=("generated clean fixture, not an FP estimate",),
        tcpdump_path="tcpdump-definitely-not-installed",
        command=("unit-test",),
    )
    doc = report.to_json()

    assert doc["schema_version"] == "celatim.detector_replay.v1"
    assert doc["ok"] is False
    assert doc["trace"]["source_kind"] == "local_generated_control"
    assert doc["trace"]["packet_count"] == 1
    assert doc["checked_unit_count"] == 0
    assert doc["matched_unit_count"] == 0
    assert doc["aggregate_matched_rate"] is None
    assert doc["false_positive_estimate"] is False
    assert doc["false_positive_claim_status"] == "not_false_positive_estimate"
    assert doc["false_positive_claim_blockers"] == [
        "not_false_positive_source",
        "detector_execution_incomplete",
    ]
    assert doc["aggregate_false_positive_rate"] is None
    result = doc["mechanisms"][0]
    assert result["ok"] is False
    assert result["false_positive_estimate"] is False
    assert result["false_positive_rate"] is None
    provenance = result["detector_provenance"]
    assert provenance["implementation_kind"] == "independent_tool_output"
    assert provenance["result"] == "tool_missing"
    assert provenance["benign_basis"] == "local_generated_control"
    assert provenance["false_positive_estimate"] is False


def test_detector_replay_tshark_backend_missing_tool_does_not_claim_fp(tmp_path):
    m = mechs()["tcp-reserved-bits"]
    pcap = tmp_path / "clean.pcap"
    _write_test_ethernet_pcap(
        pcap,
        [build_tcp_reserved_bits_frame(default_ipv4_packet_path_config_for(m.id), 0, index=0)],
    )

    report = replay_detectors_on_pcap(
        [m],
        pcap,
        source_kind=TraceSourceKind.PUBLIC_BENIGN_TRACE,
        backend=DetectorReplayBackend.TSHARK_DISPLAY_FILTER,
        tshark_path="tshark-definitely-not-installed",
        command=("unit-test",),
    )
    doc = report.to_json()

    assert doc["ok"] is False
    assert doc["checked_unit_count"] == 0
    assert doc["matched_unit_count"] == 0
    assert doc["false_positive_estimate"] is False
    assert doc["false_positive_claim_status"] == "not_false_positive_estimate"
    assert doc["false_positive_claim_blockers"] == [
        "missing_trace_name",
        "missing_trace_license",
        "missing_filtering_assumptions",
        "missing_public_trace_origin",
        "detector_execution_incomplete",
    ]
    result = doc["mechanisms"][0]
    assert result["ok"] is False
    assert result["false_positive_estimate"] is False
    provenance = result["detector_provenance"]
    assert provenance["implementation_kind"] == "independent_tool_output"
    assert provenance["detector_family"] == "display_filter"
    assert provenance["rule_format"] == "tshark-display-filter"
    assert provenance["rule"] == "tcp.flags.res != 0"
    assert provenance["result"] == "tool_missing"
    assert provenance["false_positive_estimate"] is False
    assert provenance["command"][:4] == [
        "tshark-definitely-not-installed",
        "-r",
        str(pcap),
        "-Y",
    ]


def test_detector_replay_suricata_backend_missing_tool_does_not_claim_fp(tmp_path):
    m = mechs()["tcp-reserved-bits"]
    pcap = tmp_path / "clean.pcap"
    _write_test_ethernet_pcap(
        pcap,
        [build_tcp_reserved_bits_frame(default_ipv4_packet_path_config_for(m.id), 0, index=0)],
    )

    report = replay_detectors_on_pcap(
        [m],
        pcap,
        source_kind=TraceSourceKind.PUBLIC_BENIGN_TRACE,
        backend=DetectorReplayBackend.SURICATA_RULE,
        suricata_path="suricata-definitely-not-installed",
        command=("unit-test",),
    )
    doc = report.to_json()

    assert doc["ok"] is False
    assert doc["checked_unit_count"] == 0
    assert doc["matched_unit_count"] == 0
    assert doc["false_positive_estimate"] is False
    assert doc["false_positive_claim_status"] == "not_false_positive_estimate"
    assert doc["false_positive_claim_blockers"] == [
        "missing_trace_name",
        "missing_trace_license",
        "missing_filtering_assumptions",
        "missing_public_trace_origin",
        "detector_execution_incomplete",
    ]
    result = doc["mechanisms"][0]
    assert result["ok"] is False
    assert result["false_positive_estimate"] is False
    provenance = result["detector_provenance"]
    assert provenance["implementation_kind"] == "independent_tool_output"
    assert provenance["detector_family"] == "ids_rule"
    assert provenance["rule_format"] == "suricata"
    assert "tcp.hdr" in provenance["rule"]
    assert "byte_test:1,&,0x0e,12" in provenance["rule"]
    assert provenance["result"] == "tool_missing"
    assert provenance["false_positive_estimate"] is False
    assert provenance["command"][:3] == [
        "suricata-definitely-not-installed",
        "-r",
        str(pcap),
    ]


def test_detector_replay_suricata_backend_parses_eve_alerts(tmp_path):
    m = mechs()["tcp-reserved-bits"]
    pcap = tmp_path / "mixed-public.pcap"
    fake_suricata = _write_fake_suricata(tmp_path / "suricata", alert_count=1)
    _write_test_ethernet_pcap(
        pcap,
        [
            build_tcp_reserved_bits_frame(default_ipv4_packet_path_config_for(m.id), 0x05, index=0),
            build_tcp_reserved_bits_frame(default_ipv4_packet_path_config_for(m.id), 0, index=1),
        ],
    )

    report = replay_detectors_on_pcap(
        [m],
        pcap,
        source_kind=TraceSourceKind.PUBLIC_BENIGN_TRACE,
        trace_name="unit-test-public-suricata",
        origin_url="https://example.invalid/public-trace",
        license="unit-test fixture",
        filtering_assumptions=("fixture contains only TCP packets in scope for the filter",),
        backend=DetectorReplayBackend.SURICATA_RULE,
        suricata_path=str(fake_suricata),
        command=("unit-test",),
    )
    doc = report.to_json()

    assert doc["ok"] is True
    assert doc["executed_count"] == 1
    assert doc["checked_unit_count"] == 2
    assert doc["matched_unit_count"] == 1
    assert doc["aggregate_matched_rate"] == 0.5
    assert doc["false_positive_estimate"] is True
    assert doc["false_positive_claim_status"] == "false_positive_estimate_ready"
    assert doc["false_positive_claim_blockers"] == []
    assert doc["aggregate_false_positive_rate"] == 0.5
    result = doc["mechanisms"][0]
    assert result["ok"] is True
    assert result["matched_rate"] == 0.5
    assert result["false_positive_rate"] == 0.5
    provenance = result["detector_provenance"]
    assert provenance["result"] == "matched"
    assert provenance["rule_format"] == "suricata"
    assert provenance["returncode"] == 0
    assert provenance["command"][0] == str(fake_suricata)


def test_detector_replay_executed_public_source_requires_trace_provenance_for_fp(tmp_path):
    m = mechs()["tcp-reserved-bits"]
    pcap = tmp_path / "clean-public-without-provenance.pcap"
    fake_suricata = _write_fake_suricata(tmp_path / "suricata", alert_count=0)
    _write_test_ethernet_pcap(
        pcap,
        [
            build_tcp_reserved_bits_frame(default_ipv4_packet_path_config_for(m.id), 0, index=0),
            build_tcp_reserved_bits_frame(default_ipv4_packet_path_config_for(m.id), 0, index=1),
        ],
    )

    report = replay_detectors_on_pcap(
        [m],
        pcap,
        source_kind=TraceSourceKind.PUBLIC_BENIGN_TRACE,
        backend=DetectorReplayBackend.SURICATA_RULE,
        suricata_path=str(fake_suricata),
        command=("unit-test",),
    )
    doc = report.to_json()

    assert doc["ok"] is True
    assert doc["executed_count"] == 1
    assert doc["checked_unit_count"] == 2
    assert doc["matched_unit_count"] == 0
    assert doc["aggregate_matched_rate"] == 0.0
    assert doc["trace"]["trace_name"] is None
    assert doc["trace"]["license"] is None
    assert doc["trace"]["filtering_assumptions"] == []
    assert doc["false_positive_estimate"] is False
    assert doc["false_positive_claim_status"] == "not_false_positive_estimate"
    assert doc["false_positive_claim_blockers"] == [
        "missing_trace_name",
        "missing_trace_license",
        "missing_filtering_assumptions",
        "missing_public_trace_origin",
    ]
    assert doc["aggregate_false_positive_rate"] is None
    result = doc["mechanisms"][0]
    assert result["ok"] is True
    assert result["matched_rate"] == 0.0
    assert result["false_positive_estimate"] is False
    assert result["false_positive_rate"] is None
    assert result["detector_provenance"]["false_positive_estimate"] is False


def test_tcp_reserved_bits_pcap_scrubber_zeroes_reserved_bits(tmp_path):
    config = default_ipv4_packet_path_config_for("tcp-reserved-bits")
    pcap = tmp_path / "dirty.pcap"
    scrubbed = tmp_path / "scrubbed.pcap"
    _write_test_ethernet_pcap(
        pcap,
        [
            build_tcp_reserved_bits_frame(config, 0x05, index=0),
            build_tcp_reserved_bits_frame(config, 0, index=1),
        ],
    )

    report = scrub_tcp_reserved_bits_pcap(pcap, scrubbed, command=("unit-test", "scrub"))
    doc = report.to_json()

    assert doc["schema_version"] == "celatim.scrub_report.v1"
    assert doc["ok"] is True
    assert doc["mechanism_id"] == "tcp-reserved-bits"
    assert doc["claim_status"] == "same_code_offline_pcap_scrub_smoke_not_live_middlebox"
    assert doc["packet_count"] == 2
    assert doc["checked_unit_count"] == 2
    assert doc["before_matched_unit_count"] == 1
    assert doc["scrubbed_unit_count"] == 1
    assert doc["after_matched_unit_count"] == 0
    assert doc["unchanged_unit_count"] == 1
    frames = _read_test_ethernet_pcap(scrubbed)
    assert [tcp_reserved_bits_from_frame(config, frame) for frame in frames] == [0, 0]


def test_detector_replay_public_benign_trace_can_record_zero_fp_when_tcpdump_available(
    tmp_path,
):
    if shutil.which("tcpdump") is None:
        pytest.skip("tcpdump is not installed")
    m = mechs()["tcp-reserved-bits"]
    pcap = tmp_path / "clean-public-trace.pcap"
    _write_test_ethernet_pcap(
        pcap,
        [
            build_tcp_reserved_bits_frame(default_ipv4_packet_path_config_for(m.id), 0, index=0),
            build_tcp_reserved_bits_frame(default_ipv4_packet_path_config_for(m.id), 0, index=1),
        ],
    )

    report = replay_detectors_on_pcap(
        [m],
        pcap,
        source_kind=TraceSourceKind.PUBLIC_BENIGN_TRACE,
        trace_name="unit-test-clean-public-trace",
        origin_url="https://example.invalid/public-trace",
        license="unit-test fixture",
        filtering_assumptions=("fixture contains only TCP packets in scope for the filter",),
    )
    doc = report.to_json()

    assert doc["ok"] is True
    assert doc["checked_unit_count"] == 2
    assert doc["matched_unit_count"] == 0
    assert doc["aggregate_matched_rate"] == 0.0
    assert doc["false_positive_estimate"] is True
    assert doc["false_positive_claim_status"] == "false_positive_estimate_ready"
    assert doc["false_positive_claim_blockers"] == []
    assert doc["aggregate_false_positive_rate"] == 0.0
    result = doc["mechanisms"][0]
    assert result["ok"] is True
    assert result["false_positive_estimate"] is True
    assert result["matched_rate"] == 0.0
    assert result["false_positive_rate"] == 0.0
    provenance = result["detector_provenance"]
    assert provenance["checked_units"] == 2
    assert provenance["matched_units"] == 0
    assert provenance["returncode"] == 0
    assert provenance["benign_basis"] == "public_benign_trace"
    assert provenance["false_positive_estimate"] is True


def test_detector_replay_uses_protocol_eligible_denominator(tmp_path):
    if shutil.which("tcpdump") is None:
        pytest.skip("tcpdump is not installed")
    m = mechs()["tcp-reserved-bits"]
    config = default_ipv4_packet_path_config_for(m.id)
    tcp_clean = build_tcp_reserved_bits_frame(config, 0, index=0)
    tcp_match = build_tcp_reserved_bits_frame(config, 0x05, index=1)
    not_tcp = bytearray(build_tcp_reserved_bits_frame(config, 0, index=2))
    not_tcp[14 + 9] = 17
    pcap = tmp_path / "mixed-public-trace.pcap"
    _write_test_ethernet_pcap(pcap, [tcp_clean, tcp_match, bytes(not_tcp)])

    report = replay_detectors_on_pcap(
        [m],
        pcap,
        source_kind=TraceSourceKind.PUBLIC_BENIGN_TRACE,
        trace_name="unit-test-mixed-public-trace",
        origin_url="https://example.invalid/public-trace",
        license="unit-test fixture",
        filtering_assumptions=("two TCP packets and one non-TCP packet",),
    ).to_json()

    assert report["trace"]["packet_count"] == 3
    assert report["checked_unit_count"] == 2
    assert report["matched_unit_count"] == 1
    assert report["aggregate_false_positive_rate"] == 0.5
    provenance = report["mechanisms"][0]["detector_provenance"]
    assert provenance["checked_units"] == 2
    assert provenance["matched_units"] == 1
    assert "eligible filter 'tcp'" in provenance["notes"]


def test_detector_trace_manifest_and_corpus_replay_do_not_claim_fp_without_execution(
    tmp_path,
):
    m = mechs()["tcp-reserved-bits"]
    trace_dir = tmp_path / "traces"
    trace_dir.mkdir()
    pcap = trace_dir / "clean-public.pcap"
    _write_test_ethernet_pcap(
        pcap,
        [build_tcp_reserved_bits_frame(default_ipv4_packet_path_config_for(m.id), 0, index=0)],
    )
    manifest = tmp_path / "trace-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "celatim.detector_trace_manifest.v1",
                "traces": [
                    {
                        "path": "traces/clean-public.pcap",
                        "source_kind": "public_benign_trace",
                        "trace_name": "unit-test-public-clean",
                        "origin_url": "https://example.invalid/public-trace",
                        "license": "unit-test fixture",
                        "filtering_assumptions": [
                            "fixture stands in for a licensed benign-trace campaign"
                        ],
                    }
                ],
            },
            sort_keys=True,
        )
        + "\n"
    )

    traces = load_trace_manifest(manifest)
    assert traces[0].path == pcap
    report = replay_detector_corpus(
        [m],
        traces,
        tcpdump_path="tcpdump-definitely-not-installed",
        command=("unit-test", "corpus"),
    )
    doc = report.to_json()

    assert doc["schema_version"] == "celatim.detector_replay_corpus.v1"
    assert doc["ok"] is False
    assert doc["trace_count"] == 1
    assert doc["mechanism_count"] == 1
    assert doc["result_count"] == 1
    assert doc["executed_count"] == 0
    assert doc["checked_unit_count"] == 0
    assert doc["matched_unit_count"] == 0
    assert doc["false_positive_estimate"] is False
    assert doc["false_positive_claim_status"] == "not_false_positive_estimate"
    assert doc["false_positive_claim_blockers"] == ["detector_execution_incomplete"]
    assert doc["aggregate_false_positive_rate"] is None
    assert doc["trace_source_kind_counts"] == {"public_benign_trace": 1}
    trace = doc["traces"][0]
    assert trace["trace"]["source_kind"] == "public_benign_trace"
    assert trace["false_positive_estimate"] is False
    assert trace["false_positive_claim_status"] == "not_false_positive_estimate"
    assert trace["false_positive_claim_blockers"] == ["detector_execution_incomplete"]


def test_detector_replay_corpus_public_benign_aggregate_when_tcpdump_available(
    tmp_path,
):
    if shutil.which("tcpdump") is None:
        pytest.skip("tcpdump is not installed")
    m = mechs()["tcp-reserved-bits"]
    pcaps = [tmp_path / "clean-public-a.pcap", tmp_path / "clean-public-b.pcap"]
    _write_test_ethernet_pcap(
        pcaps[0],
        [
            build_tcp_reserved_bits_frame(default_ipv4_packet_path_config_for(m.id), 0, index=0),
            build_tcp_reserved_bits_frame(default_ipv4_packet_path_config_for(m.id), 0, index=1),
        ],
    )
    _write_test_ethernet_pcap(
        pcaps[1],
        [build_tcp_reserved_bits_frame(default_ipv4_packet_path_config_for(m.id), 0, index=0)],
    )

    report = replay_detector_corpus(
        [
            m,
        ],
        [
            load_trace_manifest(
                _write_trace_manifest(tmp_path, "trace-a.json", pcaps[0], "public-a")
            )[0],
            load_trace_manifest(
                _write_trace_manifest(tmp_path, "trace-b.json", pcaps[1], "public-b")
            )[0],
        ],
    )
    doc = report.to_json()

    assert doc["ok"] is True
    assert doc["trace_count"] == 2
    assert doc["ok_trace_count"] == 2
    assert doc["result_count"] == 2
    assert doc["executed_count"] == 2
    assert doc["checked_unit_count"] == 3
    assert doc["matched_unit_count"] == 0
    assert doc["aggregate_matched_rate"] == 0.0
    assert doc["false_positive_estimate"] is True
    assert doc["false_positive_claim_status"] == "false_positive_estimate_ready"
    assert doc["false_positive_claim_blockers"] == []
    assert doc["aggregate_false_positive_rate"] == 0.0
    assert len(doc["mechanisms"]) == 1
    mechanism = doc["mechanisms"][0]
    assert mechanism["mechanism_id"] == "tcp-reserved-bits"
    assert mechanism["trace_count"] == 2
    assert mechanism["executed_trace_count"] == 2
    assert mechanism["failed_trace_count"] == 0
    assert mechanism["checked_unit_count"] == 3
    assert mechanism["matched_unit_count"] == 0
    assert mechanism["false_positive_estimate"] is True
    assert mechanism["false_positive_rate"] == 0.0
    assert mechanism["false_positive_wilson95"][0] == 0.0
    assert mechanism["false_positive_wilson95"][1] > 0.0
    assert mechanism["trace_false_positive_rates"] == [0.0, 0.0]


def _write_trace_manifest(tmp_path: Path, name: str, pcap: Path, trace_name: str) -> Path:
    manifest = tmp_path / name
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "celatim.detector_trace_manifest.v1",
                "traces": [
                    {
                        "path": str(pcap),
                        "source_kind": "public_benign_trace",
                        "trace_name": trace_name,
                        "origin_url": "https://example.invalid/public-trace",
                        "license": "unit-test fixture",
                        "filtering_assumptions": [
                            "fixture contains only TCP packets in scope for the filter"
                        ],
                    }
                ],
            },
            sort_keys=True,
        )
        + "\n"
    )
    return manifest


# --- Scapy cross-check (dev-only) -------------------------------------------


def test_scapy_crosschecks_tcp_reserved_byte():
    scapy_all = pytest.importorskip("scapy.all")
    # RFC 9768 leaves three Reserved bits in byte 12 and assigns the low-order
    # former NS bit to AE. Scapy's independent layout puts reserved=7 at 0x0e.
    raw = bytes(scapy_all.TCP(dataofs=15, reserved=7))
    assert raw[12] & 0xF0 == 0xF0
    assert raw[12] & 0x0E == 0x0E
    assert raw[12] & 0x01 == 0


def _write_test_ethernet_pcap(path: Path, frames: list[bytes]) -> None:
    global_header = struct.Struct("<IHHIIII")
    packet_header = struct.Struct("<IIII")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        fh.write(global_header.pack(0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames):
            fh.write(packet_header.pack(index, 0, len(frame), len(frame)))
            fh.write(frame)


def _read_test_ethernet_pcap(path: Path) -> list[bytes]:
    data = path.read_bytes()
    global_header = struct.Struct("<IHHIIII")
    packet_header = struct.Struct("<IIII")
    offset = global_header.size
    frames: list[bytes] = []
    while offset + packet_header.size <= len(data):
        _ts_sec, _ts_usec, incl_len, _orig_len = packet_header.unpack(
            data[offset : offset + packet_header.size]
        )
        offset += packet_header.size
        frames.append(data[offset : offset + incl_len])
        offset += incl_len
    return frames


def _write_fake_suricata(path: Path, *, alert_count: int) -> Path:
    path.write_text(
        f"""#!/usr/bin/env python3
import json
import pathlib
import sys

log_dir = pathlib.Path(sys.argv[sys.argv.index("-l") + 1])
log_dir.mkdir(parents=True, exist_ok=True)
with (log_dir / "eve.json").open("w") as fh:
    for index in range({alert_count}):
        fh.write(json.dumps({{"event_type": "alert", "alert": {{"signature_id": 9301001}}, "packet": index + 1}}) + "\\n")
print("fake suricata replay")
"""
    )
    path.chmod(0o755)
    return path
