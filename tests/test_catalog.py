"""Loading the structured mechanism catalog (single source of truth)."""

from pathlib import Path

from celatim.catalog import load_mechanisms

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def test_loads_spike_rows():
    # the provenance/capacity-model spanning rows are present (catalog grows around them).
    ids = {m.id for m in load_mechanisms(DATA)}
    assert {
        "ipv4-id-atomic",
        "tcp-reserved-bits",
        "quic-spin-bit",
        "http3-reserved-frame-types",
        "quic-padding-frame-count",
        "rsa-pss-salt",
    } <= ids
    assert len(ids) >= 6


def test_loads_capacity_model_rows():
    from celatim.model import CapacityModel

    mechs = {m.id: m for m in load_mechanisms(DATA)}
    http3 = mechs["http3-reserved-frame-types"]
    assert http3.unbounded is True
    assert http3.bits_max is None
    assert http3.capacity_model is CapacityModel.STORAGE  # D is still a storage class
    assert mechs["quic-padding-frame-count"].capacity_model is CapacityModel.TIMING
    salt = mechs["rsa-pss-salt"]
    assert salt.capacity_model is CapacityModel.SUBLIMINAL
    assert (salt.bits_min, salt.raw_capacity_bits, salt.bits_max) == (160, 256, 512)


def test_survivability_loaded_from_catalog():
    from celatim.model import OnPathVisibility, Survivability

    mechs = {m.id: m for m in load_mechanisms(DATA)}
    # The canonical "easy" header channels are exactly the ones the path mangles:
    # IP ID is NAT-rewritten, TCP reserved bits are normalizer-scrubbed.
    assert mechs["ipv4-id-atomic"].survivability is Survivability.PATH_DEPENDENT
    assert mechs["tcp-reserved-bits"].survivability is Survivability.NORMALIZED
    # QUIC frames ride inside AEAD -> intact but endpoint-only.
    assert mechs["http3-reserved-frame-types"].survivability is Survivability.INTEGRITY_BOUND
    assert mechs["http3-reserved-frame-types"].on_path_visibility is OnPathVisibility.ENCRYPTED
    assert mechs["ah-reserved"].on_path_visibility is OnPathVisibility.CLEARTEXT
    assert mechs["http2-ping-opaque"].on_path_visibility is OnPathVisibility.DEPLOYMENT_DEPENDENT
    # The canonical "easy" header channels fail the high-threat bar (scrubbed / NAT'd /
    # endpoint-only) -- but the catalog does contain robust-unwitting channels, e.g. the
    # ICMP unused error-message fields, which survive a path against an unmodified receiver.
    assert not mechs["tcp-reserved-bits"].robust_unwitting
    assert not mechs["ipv4-id-atomic"].robust_unwitting
    assert mechs["icmpv4-unused"].robust_unwitting


def test_negative_results_loaded_and_flagged():
    mechs = {m.id: m for m in load_mechanisms(DATA)}
    negatives = {
        "oscore-reserved-neg",
        "bgpsec-signed-neg",
        "quic-hdr-protected-neg",
        "ah-reserved-external-neg",
    }
    assert negatives <= set(mechs)
    assert all(not mechs[i].is_usable_channel for i in negatives)
    # every non-negative row is a usable channel
    assert all(m.is_usable_channel for m in mechs.values() if m.id not in negatives)


def test_wiki_tunneling_techniques_present():
    ids = {m.id for m in load_mechanisms(DATA)}
    # the prior-art tunnels from sources/wiki are now in the catalog (status DOC)
    for i in (
        "ntp-extension-field",
        "dns-txt-tunnel",
        "icmp-echo-payload",
        "websocket-tunnel",
        "webrtc-datachannel",
        "dhcp-option-tunnel",
        "coap-tunnel",
        "mqtt-tunnel",
        "lorawan-frame",
        "ntp-timing",
        "dns-timing",
    ):
        assert i in ids, i


def test_analysis_populations_separate_primary_and_comparison_rows():
    from collections import Counter

    from celatim.model import AnalysisPopulation

    usable = [mechanism for mechanism in load_mechanisms(DATA) if mechanism.is_usable_channel]
    counts = Counter(mechanism.analysis_population for mechanism in usable)

    assert counts == {
        AnalysisPopulation.PRIMARY_RFC_CARRIER: 133,
        AnalysisPopulation.COMPARISON_ORDINARY_PAYLOAD: 7,
        AnalysisPopulation.COMPARISON_NON_IETF: 2,
    }
    by_id = {mechanism.id: mechanism for mechanism in usable}
    assert by_id["dns-txt-tunnel"].analysis_population is (
        AnalysisPopulation.COMPARISON_ORDINARY_PAYLOAD
    )
    assert by_id["mqtt-tunnel"].analysis_population is AnalysisPopulation.COMPARISON_NON_IETF


def test_ipv6_flow_label_spec_acknowledged():
    m = next(x for x in load_mechanisms(DATA) if x.id == "ipv6-flow-label")
    assert "RFC 6437" in m.rfcs  # the fifth spec-acknowledged covert channel


def test_evidence_backed_marquee_rows_have_authored_detection_posture():
    from celatim.model import DetectionAnnotationSource, DetectPredicate, FalsePositive

    mechs = {m.id: m for m in load_mechanisms(DATA)}
    expected = {
        "tcp-reserved-bits": (DetectPredicate.NONZERO, FalsePositive.BENIGN_RARE),
        "ipv4-id-atomic": (DetectPredicate.STATISTICAL, FalsePositive.BENIGN_COMMON),
        "ipv6-flow-label": (DetectPredicate.STATISTICAL, FalsePositive.BENIGN_COMMON),
        "quic-connection-id": (DetectPredicate.STATISTICAL, FalsePositive.BENIGN_COMMON),
        "http2-ping-opaque": (DetectPredicate.STATISTICAL, FalsePositive.BENIGN_COMMON),
        "edns0-padding": (DetectPredicate.ENTROPY, FalsePositive.BENIGN_COMMON),
        "rtp-rtcp-ext-app": (DetectPredicate.PRESENCE, FalsePositive.BENIGN_COMMON),
    }

    for mechanism_id, (predicate, false_positive) in expected.items():
        mechanism = mechs[mechanism_id]
        assert mechanism.detect_predicate is predicate
        assert mechanism.false_positive is false_positive
        assert mechanism.detection_annotation_source is DetectionAnnotationSource.EXPLICIT_CATALOG


def test_catalog_detection_annotation_migration_coverage_is_explicit():
    from celatim.model import DetectionAnnotationSource

    mechs = load_mechanisms(DATA)
    explicit = [
        mechanism
        for mechanism in mechs
        if mechanism.detection_annotation_source is DetectionAnnotationSource.EXPLICIT_CATALOG
    ]

    assert len(explicit) == len(mechs) == 146


def test_scrub_strategy_derived_for_catalog_rows():
    from celatim.model import ScrubStrategy

    mechs = {m.id: m for m in load_mechanisms(DATA)}
    # The scrub follows the structure and stays consistent with survivability:
    # Normalizers zero TCP reserved bits; IPv4-ID treatment varies by path.
    assert mechs["tcp-reserved-bits"].scrub_strategy is ScrubStrategy.CANONICALIZE_ZERO
    assert mechs["ipv4-id-atomic"].scrub_strategy is ScrubStrategy.REWRITE_FIELD
    # AEAD-protected frames can only be refused at the endpoint.
    assert mechs["http3-reserved-frame-types"].scrub_strategy is ScrubStrategy.ENDPOINT_ONLY
    # Timing -> shaping; subliminal salt -> deterministic generation (RFC 6979).
    assert mechs["quic-padding-frame-count"].scrub_strategy is ScrubStrategy.SHAPE_TIMING
    assert mechs["rsa-pss-salt"].scrub_strategy is ScrubStrategy.ENFORCE_DETERMINISTIC


def test_rejects_duplicate_ids(tmp_path):
    row = (
        '{"id": "dup", "name": "n", "rfcs": ["RFC 1"], "protocol": "P", '
        '"layer": "transport", "carrier_class": "A", "status": "NEW", '
        '"carrier_unit": "packet", "raw_capacity_bits": 1, "header_bits": 8, '
        '"wire_bits_typical": 8, "reach": "unwitting", '
        '"survivability": "end_to_end", "provenance": "spec", '
        '"spec_quote": "q"}'
    )
    p = tmp_path / "dupes.jsonl"
    p.write_text(row + "\n" + row + "\n")
    import pytest

    with pytest.raises(ValueError):
        load_mechanisms(p)


def test_tcp_row_fields():
    mechs = {m.id: m for m in load_mechanisms(DATA)}
    tcp = mechs["tcp-reserved-bits"]
    assert tcp.raw_capacity_bits == 3
    assert tcp.carrier_class.value == "A"
    assert "RFC 9768" in tcp.rfcs
    assert "RFC 9293" in tcp.rfcs
