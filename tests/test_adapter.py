"""Mechanism adapter registry."""

from pathlib import Path

from celatim.adapter import AdapterCapability, AdapterStatus, adapter_for, adapters_for
from celatim.catalog import load_mechanisms

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def mechs_by_id():
    return {m.id: m for m in load_mechanisms(DATA)}


def test_every_catalog_row_has_adapter_metadata():
    adapters = adapters_for(list(mechs_by_id().values()))

    assert len(adapters) == len(mechs_by_id())
    assert adapters["tcp-reserved-bits"].status is AdapterStatus.MINIMAL_PACKET_TEMPLATE
    assert adapters["http2-ping-opaque"].status is AdapterStatus.REAL_PDU_FIXTURE
    assert adapters["bgp-path-attr-flags"].status is AdapterStatus.OFFSET_REPRESENTED_ZERO_BLOB
    assert adapters["edns0-padding"].status is AdapterStatus.REAL_DAEMON_PATH
    assert adapters["rsa-pss-salt"].status is AdapterStatus.REAL_CRYPTO_PATH
    assert adapters["ntp-timing"].status is AdapterStatus.TIMING_SCHEME
    assert adapters["tls-record-padding"].status is AdapterStatus.CODEC_ONLY
    assert AdapterCapability.REAL_PDU_FIXTURE not in adapters["tls-record-padding"].capabilities


def test_real_pdu_adapters_build_parser_validated_carrier_bytes():
    mechs = mechs_by_id()
    payload = b"\x00\xff\x80adapter"

    for mechanism_id in ("http2-ping-opaque", "quic-connection-id", "rtp-rtcp-ext-app"):
        adapter = adapter_for(mechs[mechanism_id])
        units = adapter.encode_payload(payload)

        assert adapter.status is AdapterStatus.REAL_PDU_FIXTURE
        assert AdapterCapability.REAL_PDU_FIXTURE in adapter.capabilities
        assert AdapterCapability.PARSER_VALIDATED in adapter.capabilities
        assert units
        assert all(unit.has_carrier_bytes for unit in units)
        assert all(adapter.parse_carrier(unit.carrier) == unit.symbol for unit in units)
        assert adapter.decode_units(units) == payload


def test_application_pdu_fixtures_report_bytes_without_packet_path_registration():
    adapter = adapter_for(mechs_by_id()["http3-reserved-settings"])
    units = adapter.encode_payload(b"\x00\xffhttp3")

    assert adapter.status is AdapterStatus.REAL_PDU_FIXTURE
    assert adapter.supports_carrier_bytes is True
    assert units
    assert all(unit.has_carrier_bytes for unit in units)
    assert not adapter.supports_transport("afpacket_ipv4")
    assert not adapter.supports_transport("pcap")


def test_minimal_packet_template_adapters_build_parser_validated_carrier_bytes():
    adapter = adapter_for(mechs_by_id()["tcp-reserved-bits"])
    payload = b"\x00\xff\x80tcp"
    units = adapter.encode_payload(payload)

    assert adapter.status is AdapterStatus.MINIMAL_PACKET_TEMPLATE
    assert AdapterCapability.PACKET_PATH_TEMPLATE in adapter.capabilities
    assert AdapterCapability.PARSER_VALIDATED in adapter.capabilities
    assert units
    assert all(unit.has_carrier_bytes for unit in units)
    assert all(adapter.parse_carrier(unit.carrier) == unit.symbol for unit in units)
    assert {unit.symbol for unit in units}.issubset(set(range(8)))
    assert adapter.decode_units(units) == payload


def test_offset_represented_adapters_stay_symbol_only():
    adapter = adapter_for(mechs_by_id()["bgp-path-attr-flags"])
    payload = b"symbol-only"
    units = adapter.encode_payload(payload)

    assert adapter.status is AdapterStatus.OFFSET_REPRESENTED_ZERO_BLOB
    assert AdapterCapability.OFFSET_REPRESENTED in adapter.capabilities
    assert units
    assert all(not unit.has_carrier_bytes for unit in units)
    assert adapter.decode_units(units) == payload
