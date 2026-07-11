"""Reusable transport implementations."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from celatim.errors import ReceiveTimeoutError, TransportError
from celatim.session import ChannelSession, MechanismProfile, PacingConfig
from celatim.transports import (
    FILE_TRANSPORT_SCHEMA,
    PCAP_TRANSPORT_LINKTYPE_ETHERNET,
    FileTransport,
    PcapTransport,
    TimedMemoryTransport,
    extract_pcap_carriers,
)

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def test_file_transport_roundtrips_across_separate_instances(tmp_path):
    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    pacing = PacingConfig(unit_rate_hz=20.0, timing_quantum_s=0.005)
    sender_transport = FileTransport(profile, tmp_path / "wire")
    receiver_transport = FileTransport(profile, tmp_path / "wire")

    sender = ChannelSession(profile, sender_transport)
    receipt = sender.send_message(b"\x00\xff\x80A", session_id="file-live", pacing=pacing)
    result = ChannelSession(profile, receiver_transport).receive_message(receipt.session_id)

    assert result.payload == b"\x00\xff\x80A"
    assert result.evidence.pacing == pacing
    assert result.evidence.carrier_units == receipt.carrier_units

    record = json.loads(sender_transport.path_for("file-live").read_text())
    assert record["schema_version"] == FILE_TRANSPORT_SCHEMA
    assert record["mechanism_id"] == "http2-ping-opaque"
    assert record["carrier_encoding"] == "hex"
    assert record["carrier_units_with_bytes"] == receipt.carrier_units
    assert len(record["carriers"]) == receipt.carrier_units
    assert len(record["carrier_unit_sha256"]) == receipt.carrier_units


def test_file_transport_keeps_offset_represented_rows_symbol_only(tmp_path):
    profile = MechanismProfile.from_catalog("bgp-path-attr-flags", DATA)
    transport = FileTransport(profile, tmp_path / "wire")

    result = ChannelSession(profile, transport).run_roundtrip(
        b"offset represented",
        session_id="offset-row",
    )
    record = json.loads(transport.path_for("offset-row").read_text())

    assert result.payload == b"offset represented"
    assert record["carrier_encoding"] is None
    assert record["carriers"] == []
    assert record["carrier_units_with_bytes"] == 0


def test_file_transport_rejects_tampered_carrier_hash(tmp_path):
    profile = MechanismProfile.from_catalog("quic-connection-id", DATA)
    transport = FileTransport(profile, tmp_path / "wire")
    ChannelSession(profile, transport).send_message(b"\x00\xff\x80A", session_id="tamper-hash")
    path = transport.path_for("tamper-hash")
    record = json.loads(path.read_text())
    record["carrier_unit_sha256"][0] = "0" * 64
    path.write_text(json.dumps(record))

    with pytest.raises(TransportError, match="carrier hashes do not match carrier bytes"):
        ChannelSession(profile, transport).receive_message("tamper-hash")


def test_file_transport_rejects_wrong_mechanism_record(tmp_path):
    sender_profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    receiver_profile = MechanismProfile.from_catalog("rtp-rtcp-ext-app", DATA)
    root = tmp_path / "wire"
    sender_transport = FileTransport(sender_profile, root)
    ChannelSession(sender_profile, sender_transport).send_message(
        b"\x00\xff\x80A", session_id="wrong"
    )

    with pytest.raises(TransportError, match="mechanism id mismatch"):
        FileTransport(receiver_profile, root).receive_symbols("wrong")


def test_file_transport_missing_record_raises_transport_error(tmp_path):
    profile = MechanismProfile.from_catalog("tcp-reserved-bits", DATA)
    transport = FileTransport(profile, tmp_path / "wire")

    with pytest.raises(TransportError, match="no file transport record"):
        transport.receive_symbols("missing")


def test_file_transport_missing_record_can_timeout(tmp_path):
    profile = MechanismProfile.from_catalog("tcp-reserved-bits", DATA)
    transport = FileTransport(profile, tmp_path / "wire")

    with pytest.raises(ReceiveTimeoutError, match="timed out waiting for file transport record"):
        transport.receive_symbols_with_timeout("missing", timeout_s=0.001)


def test_pcap_transport_roundtrips_parser_visible_carriers(tmp_path):
    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    pacing = PacingConfig(unit_rate_hz=10.0)
    sender_transport = PcapTransport(profile, tmp_path / "pcaps")
    receiver_transport = PcapTransport(profile, tmp_path / "pcaps")

    receipt = ChannelSession(profile, sender_transport).send_message(
        b"\x00\xffpcap",
        session_id="pcap-live",
        pacing=pacing,
    )
    result = ChannelSession(profile, receiver_transport).receive_message(receipt.session_id)

    path = sender_transport.path_for("pcap-live")
    data = path.read_bytes()
    assert result.payload == b"\x00\xffpcap"
    assert path.suffix == ".pcap"
    assert data[:4] == bytes.fromhex("d4 c3 b2 a1")
    assert int.from_bytes(data[20:24], "little") == PCAP_TRANSPORT_LINKTYPE_ETHERNET
    assert result.evidence.carrier_units == receipt.carrier_units


def test_extract_pcap_carriers_decodes_standalone_capture(tmp_path):
    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    transport = PcapTransport(profile, tmp_path / "pcaps")
    receipt = ChannelSession(profile, transport).send_message(
        b"\x00\xffpcap",
        session_id="standalone",
    )

    extraction = extract_pcap_carriers(profile, transport.path_for("standalone"))

    assert extraction.linktype == PCAP_TRANSPORT_LINKTYPE_ETHERNET
    assert extraction.packet_count == receipt.carrier_units
    assert len(extraction.carrier_bytes) == receipt.carrier_units
    assert len(extraction.symbols) == receipt.carrier_units
    assert all(isinstance(symbol, bytes) for symbol in extraction.symbols)


def test_pcap_transport_tcp_reserved_bits_is_tcpdump_filterable(tmp_path):
    if shutil.which("tcpdump") is None:
        pytest.skip("tcpdump is not installed")
    profile = MechanismProfile.from_catalog("tcp-reserved-bits", DATA)
    transport = PcapTransport(profile, tmp_path / "pcaps")
    ChannelSession(profile, transport).send_message(b"\x00\xfftcpdump", session_id="tcpdump")

    result = subprocess.run(
        [
            "tcpdump",
            "-tt",
            "-n",
            "-r",
            str(transport.path_for("tcpdump")),
            "tcp[12] & 0x0e != 0",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout.strip()
    assert "link-type EN10MB" in result.stderr


def test_pcap_transport_requires_carrier_bytes(tmp_path):
    profile = MechanismProfile.from_catalog("bgp-path-attr-flags", DATA)
    transport = PcapTransport(profile, tmp_path / "pcaps")

    with pytest.raises(TransportError, match="pcap transport requires carrier bytes"):
        ChannelSession(profile, transport).send_message(b"offset represented", session_id="pcap")


def test_pcap_transport_missing_record_can_timeout(tmp_path):
    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    transport = PcapTransport(profile, tmp_path / "pcaps")

    with pytest.raises(ReceiveTimeoutError, match="timed out waiting for pcap transport record"):
        transport.receive_symbols_with_timeout("missing", timeout_s=0.001)


def test_pcap_transport_rejects_wrong_mechanism_record(tmp_path):
    sender_profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    receiver_profile = MechanismProfile.from_catalog("rtp-rtcp-ext-app", DATA)
    root = tmp_path / "pcaps"
    sender_transport = PcapTransport(sender_profile, root)
    ChannelSession(sender_profile, sender_transport).send_message(
        b"\x00\xffpcap", session_id="wrong"
    )

    with pytest.raises(TransportError, match="invalid pcap carrier bytes"):
        PcapTransport(receiver_profile, root).receive_symbols("wrong")


def test_timed_memory_transport_applies_pacing_and_records_trace():
    class FakeClock:
        def __init__(self) -> None:
            self.now = 100.0

        def __call__(self) -> float:
            return self.now

        def sleep(self, delay: float) -> None:
            assert delay >= 0
            self.now += delay

    clock = FakeClock()
    profile = MechanismProfile.from_catalog("tcp-reserved-bits", DATA)
    transport = TimedMemoryTransport(clock=clock, sleeper=clock.sleep)
    pacing = PacingConfig(symbol_period_s=0.25, base_delay_s=0.5)

    result = ChannelSession(profile, transport).run_roundtrip(
        b"\x00timed\xff",
        session_id="timed",
        pacing=pacing,
    )

    trace = result.evidence.timing_trace
    assert result.payload == b"\x00timed\xff"
    assert trace is not None
    assert len(trace.samples) == result.evidence.carrier_units
    assert trace.samples[0].scheduled_offset_s == 0.5
    assert trace.samples[0].observed_offset_s == 0.5
    assert trace.scheduled_duration_s == pacing.scheduled_duration_s(result.evidence.carrier_units)
    assert trace.observed_duration_s == trace.scheduled_duration_s
    assert trace.mean_abs_error_s == 0.0
    assert trace.max_abs_error_s == 0.0
    assert trace.inter_arrival_s
    assert all(interval == pytest.approx(0.25) for interval in trace.inter_arrival_s)
    assert all(error == pytest.approx(0.0) for error in trace.inter_arrival_error_s)


def test_timed_memory_transport_missing_symbols_can_timeout():
    transport = TimedMemoryTransport()

    with pytest.raises(ReceiveTimeoutError, match="timed out waiting for timed memory symbols"):
        transport.receive_symbols_with_timeout("missing", timeout_s=0.001)
