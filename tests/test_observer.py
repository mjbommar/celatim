"""Independent observer checks over real-PDU carrier bytes."""

import struct
from pathlib import Path

from celatim.adapter import CarrierUnit, adapter_for
from celatim.catalog import load_mechanisms
from celatim.observer import (
    observer_mutation_controls_for,
    observer_validations_for,
    parser_provenance_for,
)
from celatim.pdu import DCID_LEN, RTCP_APP_DATA_LEN, build_initial_packet
from celatim.testbed import build_tcp_reserved_bits_frame, default_ipv4_packet_path_config_for

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def mechs_by_id():
    return {m.id: m for m in load_mechanisms(DATA)}


def test_observer_validates_real_pdu_fixture_carriers():
    mechanisms = mechs_by_id()
    for mechanism_id in (
        "tcp-reserved-bits",
        "http2-ping-opaque",
        "quic-connection-id",
        "rtp-rtcp-ext-app",
    ):
        units = adapter_for(mechanisms[mechanism_id]).encode_payload(b"\x00\xffobserver")

        records = observer_validations_for(mechanism_id, units)

        assert len(records) == 1
        record = records[0]
        assert record.ok is True
        assert record.checked_units == len(units)
        assert record.failed_units == 0
        assert record.field_offset is not None
        assert record.field_len is not None
        assert len(record.extracted_field_sha256) == len(units)
        assert record.nonzero_surrounding_bytes_min is not None
        assert record.nonzero_surrounding_bytes_min > 0
        assert record.error is None


def test_observer_mutation_controls_fail_discriminating_bad_carriers():
    mechanisms = mechs_by_id()
    for mechanism_id in (
        "tcp-reserved-bits",
        "http2-ping-opaque",
        "quic-connection-id",
        "rtp-rtcp-ext-app",
    ):
        units = adapter_for(mechanisms[mechanism_id]).encode_payload(b"\x00\xffobserver")

        controls = observer_mutation_controls_for(mechanism_id, units)

        assert [control.control_type for control in controls] == [
            "wrong_nominal_offset",
            "zero_surrounding_bytes",
        ]
        for control in controls:
            assert control.ok is True
            assert control.tested_units == len(units)
            assert control.expected_failure_units == len(units)
            assert control.unexpected_pass_units == 0
            assert control.setup_failed_units == 0
            assert control.error_samples


def test_observer_rejects_wrong_nominal_quic_offset():
    symbol = bytes(range(DCID_LEN))
    carrier = bytearray(build_initial_packet(b"\x00" * DCID_LEN))
    carrier[:DCID_LEN] = symbol
    units = [CarrierUnit(0, symbol, bytes(carrier))]

    record = observer_validations_for("quic-connection-id", units)[0]

    assert record.ok is False
    assert record.checked_units == 1
    assert record.failed_units == 1
    assert "first byte" in str(record.error)


def test_observer_rejects_missing_nonzero_surrounding_bytes():
    symbol = b"\x00" * RTCP_APP_DATA_LEN
    units = [CarrierUnit(0, symbol, symbol)]

    record = observer_validations_for("rtp-rtcp-ext-app", units)[0]

    assert record.ok is False
    assert record.checked_units == 1
    assert record.failed_units == 1
    assert record.extracted_field_sha256 == ()
    assert record.nonzero_surrounding_bytes_min is None


def test_observer_skips_unsupported_symbol_only_mechanisms():
    records = observer_validations_for("bgp-path-attr-flags", [CarrierUnit(0, 1, None)])
    controls = observer_mutation_controls_for("bgp-path-attr-flags", [CarrierUnit(0, 1, None)])

    assert records == ()
    assert controls == ()


def test_parser_provenance_records_missing_tshark_without_failing(tmp_path):
    pcap = tmp_path / "tcp-clean.pcap"
    _write_test_ethernet_pcap(
        pcap,
        [
            build_tcp_reserved_bits_frame(
                default_ipv4_packet_path_config_for("tcp-reserved-bits"), 0
            )
        ],
    )

    record = parser_provenance_for(
        "tcp-reserved-bits",
        pcap,
        tshark_path="tshark-definitely-not-installed",
    )[0]

    assert record.name == "tcp-reserved-bits-tshark-dissector"
    assert record.implementation_kind == "independent_tool_output"
    assert record.executed is False
    assert record.result == "tool_missing"
    assert record.field_paths == ("tcp.flags.res",)
    assert record.checked_units == 1
    assert record.parsed_units == 0
    assert record.failed_units == 1
    assert record.command[0] == "tshark-definitely-not-installed"
    assert record.to_json()["stderr_excerpt"] == "tshark-definitely-not-installed: not found"


def test_parser_provenance_counts_tshark_field_rows_from_fake_tool(tmp_path):
    pcap = tmp_path / "tcp-parsed.pcap"
    _write_test_ethernet_pcap(
        pcap,
        [
            build_tcp_reserved_bits_frame(
                default_ipv4_packet_path_config_for("tcp-reserved-bits"),
                0,
                index=0,
            ),
            build_tcp_reserved_bits_frame(
                default_ipv4_packet_path_config_for("tcp-reserved-bits"),
                1,
                index=1,
            ),
        ],
    )
    fake_tshark = tmp_path / "tshark"
    fake_tshark.write_text("#!/usr/bin/env sh\nprintf '1\\t0\\n2\\t1\\n'\n")
    fake_tshark.chmod(0o755)

    record = parser_provenance_for(
        "tcp-reserved-bits",
        pcap,
        tshark_path=str(fake_tshark),
    )[0]
    doc = record.to_json()

    assert record.executed is True
    assert record.result == "parsed"
    assert record.checked_units == 2
    assert record.parsed_units == 2
    assert record.failed_units == 0
    assert record.returncode == 0
    assert doc["stdout_sha256"] is not None
    assert doc["stderr_sha256"] is not None
    command = doc["command"]
    assert isinstance(command, list)
    assert command[-2:] == ["-e", "tcp.flags.res"]


def _write_test_ethernet_pcap(path: Path, frames: list[bytes]) -> None:
    global_header = struct.Struct("<IHHIIII")
    packet_header = struct.Struct("<IIII")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        fh.write(global_header.pack(0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames):
            fh.write(packet_header.pack(index, 0, len(frame), len(frame)))
            fh.write(frame)
