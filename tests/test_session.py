"""Library-facing ChannelSession API."""

from pathlib import Path

import pytest

from celatim.errors import (
    ConfigurationError,
    DecodeError,
    ReceiveTimeoutError,
    TransportError,
    UnsupportedMechanismError,
)
from celatim.evidence import EvidenceBucket, ThroughputStatus
from celatim.session import (
    ChannelSession,
    EndpointOsMetadata,
    InMemoryTransport,
    MechanismProfile,
    PacingConfig,
    Receiver,
    ReliabilityPolicy,
    Sender,
    SessionFramingConfig,
    Symbol,
    ThroughputProfile,
    TimingTrace,
    cross_host_endpoint_os,
    local_endpoint_os,
)

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def test_profile_loads_mechanism_and_current_evidence():
    profile = MechanismProfile.from_catalog("tcp-reserved-bits", DATA)
    assert profile.id == "tcp-reserved-bits"
    assert profile.evidence.bucket is EvidenceBucket.REAL_PDU_PACKET_PATH


def test_profile_uses_packaged_catalog_by_default():
    profile = MechanismProfile.from_catalog("http2-ping-opaque")

    assert profile.id == "http2-ping-opaque"
    assert profile.adapter.supports_carrier_bytes is True


def test_in_memory_session_roundtrips_payload_with_evidence():
    profile = MechanismProfile.from_catalog("tcp-reserved-bits", DATA)
    session = ChannelSession(profile, InMemoryTransport())

    result = session.run_roundtrip(b"library payload", session_id="s1")

    assert result.payload == b"library payload"
    assert result.session_id == "s1"
    assert result.evidence.ok is True
    assert result.evidence.mechanism_id == "tcp-reserved-bits"
    assert result.evidence.evidence_bucket is EvidenceBucket.REAL_PDU_PACKET_PATH
    assert result.evidence.payload_len == len(b"library payload")
    assert result.evidence.recovered_len == len(b"library payload")
    assert result.evidence.carrier_units > 0
    assert result.evidence.pacing is None
    assert result.evidence.scheduled_duration_s is None
    assert result.evidence.endpoint_os.topology_kind == "same_process"
    assert result.evidence.endpoint_os.independent_receiver_os is False
    assert result.evidence.endpoint_os.sender.role == "sender"
    assert result.evidence.endpoint_os.receiver.role == "receiver"
    throughput = result.evidence.throughput_profile
    assert throughput is not None
    assert throughput.throughput_status is ThroughputStatus.SENDER_BOUND
    assert throughput.payload_len == len(b"library payload")
    assert throughput.payload_rate_bps is None
    assert throughput.rate_basis == "sender_bound_no_production_window"
    assert throughput.claim_status == "sender_bound_no_bits_per_second_claim"


def test_channel_session_satisfies_sender_receiver_protocols():
    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    session = ChannelSession(profile, InMemoryTransport())

    assert isinstance(session, Sender)
    assert isinstance(session, Receiver)


def test_session_roundtrips_nonzero_binary_payload_with_pacing_evidence():
    profile = MechanismProfile.from_catalog("rtp-rtcp-ext-app", DATA)
    transport = InMemoryTransport()
    session = ChannelSession(profile, transport)
    payload = b"\x00\xff\x80binary\x00payload" + bytes(range(1, 16))
    pacing = PacingConfig(unit_rate_hz=25.0, timing_quantum_s=0.004, timeout_s=2.0)

    receipt = session.send_message(payload, session_id="binary", pacing=pacing)
    result = session.receive_message("binary")

    assert result.payload == payload
    assert transport.pacing_for("binary") == pacing
    assert receipt.pacing == pacing
    assert result.evidence.pacing == pacing
    assert result.evidence.payload_len == len(payload)
    assert result.evidence.recovered_len == len(payload)
    assert result.evidence.scheduled_duration_s == pacing.scheduled_duration_s(
        result.evidence.carrier_units
    )
    assert result.evidence.throughput_profile is not None
    assert result.evidence.throughput_profile.scheduled_unit_rate_hz == 25.0


def test_production_throughput_profile_reports_rates_only_for_measured_paths():
    profile = ThroughputProfile.from_observation(
        throughput_status=ThroughputStatus.PRODUCTION_PATH_MEASURED,
        payload_len=100,
        recovered_len=100,
        carrier_units=25,
        elapsed_s=2.0,
        pacing=PacingConfig(unit_rate_hz=50.0),
        ok=True,
    )

    assert profile is not None
    assert profile.measurement_window_s == 2.0
    assert profile.scheduled_unit_rate_hz == 50.0
    assert profile.observed_unit_rate_hz == 12.5
    assert profile.payload_rate_bps == 400.0
    assert profile.claim_status == "production_path_measured"


def test_send_and_receive_can_be_separate_steps():
    profile = MechanismProfile.from_catalog("edns0-padding", DATA)
    transport = InMemoryTransport()
    sender = ChannelSession(profile, transport)
    receiver = ChannelSession(profile, transport)

    receipt = sender.send_message(b"split endpoint", session_id="split")
    result = receiver.receive_message(receipt)

    assert receipt.carrier_units > 0
    assert receipt.evidence_bucket is EvidenceBucket.REAL_DAEMON_OR_CRYPTO_PATH
    assert result.payload == b"split endpoint"


def test_session_accepts_explicit_endpoint_os_metadata():
    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    endpoint_os = local_endpoint_os(
        "same_kernel_netns",
        sender_namespace="snd",
        receiver_namespace="rcv",
        tap_namespace="rcv",
        tap_interface="vr",
        include_tap=True,
    )
    session = ChannelSession(profile, InMemoryTransport(), endpoint_os=endpoint_os)

    result = session.run_roundtrip(b"endpoint metadata", session_id="endpoints")

    assert result.evidence.endpoint_os == endpoint_os
    assert result.evidence.endpoint_os.tap is not None
    assert result.evidence.endpoint_os.tap.namespace == "rcv"


def test_cross_host_endpoint_os_records_two_host_identity():
    endpoint_os = cross_host_endpoint_os(
        sender_node="alice-host",
        sender_ip="10.200.0.7",
        sender_mac="02:00:00:00:00:07",
        sender_interface="vxlan-ab",
        receiver_node="bob-host",
        receiver_ip="10.200.0.6",
        receiver_mac="02:00:00:00:00:06",
        receiver_interface="vxlan-ab",
    )

    assert endpoint_os.topology_kind == "cross_host"
    assert endpoint_os.independent_receiver_os is True
    # Sender and receiver are genuinely distinct hosts.
    assert endpoint_os.sender.node == "alice-host"
    assert endpoint_os.receiver.node == "bob-host"
    assert endpoint_os.sender.node != endpoint_os.receiver.node
    # The remote sender platform fields are not copied from the local receiver.
    assert endpoint_os.sender.source == "remote_peer_reported"
    assert endpoint_os.sender.system == ""
    assert endpoint_os.receiver.source == "local_platform"
    # Round-trips through JSON without losing the two-host labels.
    payload = endpoint_os.to_json()
    assert payload["topology_kind"] == "cross_host"
    assert payload["independent_receiver_os"] is True
    assert payload["sender"]["node"] == "alice-host"
    assert payload["receiver"]["node"] == "bob-host"


def test_cross_host_endpoint_os_threads_through_session_evidence():
    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    endpoint_os = cross_host_endpoint_os(sender_node="alice", receiver_node="bob")
    session = ChannelSession(profile, InMemoryTransport(), endpoint_os=endpoint_os)

    result = session.run_roundtrip(b"cross host payload", session_id="xh")

    assert result.payload == b"cross host payload"
    assert result.evidence.endpoint_os.topology_kind == "cross_host"
    assert result.evidence.endpoint_os.independent_receiver_os is True
    assert result.evidence.endpoint_os.sender.node == "alice"
    assert result.evidence.endpoint_os.receiver.node == "bob"


def test_independent_receiver_os_rejected_for_same_process_topology():
    sender = EndpointOsMetadata(
        topology_kind="same_process",
        independent_receiver_os=False,
        sender=local_endpoint_os().sender,
        receiver=local_endpoint_os().receiver,
    )
    assert sender.independent_receiver_os is False
    with pytest.raises(ConfigurationError):
        EndpointOsMetadata(
            topology_kind="same_process",
            independent_receiver_os=True,
            sender=local_endpoint_os().sender,
            receiver=local_endpoint_os().receiver,
        )


def test_session_default_pacing_is_used_when_send_does_not_override():
    profile = MechanismProfile.from_catalog("tcp-reserved-bits", DATA)
    pacing = PacingConfig(symbol_period_s=0.01, base_delay_s=0.05, decode_tolerance_s=0.002)
    transport = InMemoryTransport()
    session = ChannelSession(profile, transport, pacing=pacing)

    result = session.run_roundtrip(b"default pacing", session_id="paced")

    assert result.evidence.pacing == pacing
    assert transport.pacing_for("paced") == pacing
    assert result.evidence.scheduled_duration_s == pacing.scheduled_duration_s(
        result.evidence.carrier_units
    )


def test_timing_profile_reports_jitter_snr_error_rate_and_rate_label():
    class JitterTap:
        def __init__(self, transport: InMemoryTransport) -> None:
            self.transport = transport

        def receive_symbols(self, session_id: str) -> list[Symbol]:
            return self.transport.receive_symbols(session_id)

        def pacing_for(self, session_id: str) -> PacingConfig | None:
            return self.transport.pacing_for(session_id)

        def timing_trace_for(self, session_id: str) -> TimingTrace:
            count = len(self.transport.receive_symbols(session_id))
            scheduled = tuple(index * 0.1 for index in range(count))
            observed = tuple(
                scheduled[index] + (0.0 if index == 0 else (0.001 if index % 2 else -0.001))
                for index in range(count)
            )
            return TimingTrace.from_offsets(scheduled, observed)

    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    transport = InMemoryTransport()
    pacing = PacingConfig(
        symbol_period_s=0.1,
        timing_quantum_s=0.01,
        decode_tolerance_s=0.0015,
    )
    sender = ChannelSession(profile, transport)
    receipt = sender.send_message(b"timing profile payload", session_id="timing", pacing=pacing)
    receiver = ChannelSession(profile, transport, tap=JitterTap(transport))

    result = receiver.receive_message(receipt)

    profile_doc = result.evidence.timing_profile
    assert profile_doc is not None
    assert profile_doc.sample_count == result.evidence.carrier_units
    assert profile_doc.nominal_symbol_period_s == 0.1
    assert profile_doc.timing_quantum_s == 0.01
    assert profile_doc.decode_tolerance_s == 0.0015
    assert profile_doc.tolerance_source == "decode_tolerance_s"
    assert profile_doc.error_basis == "inter_arrival_error_s"
    assert profile_doc.jitter_sample_count == result.evidence.carrier_units - 1
    assert profile_doc.jitter_max_abs_s is not None
    assert profile_doc.jitter_stddev_s is not None
    assert profile_doc.snr_db is not None
    assert profile_doc.symbol_error_count is not None
    assert profile_doc.symbol_error_count > 0
    assert profile_doc.symbol_error_rate is not None
    assert profile_doc.symbol_error_rate > 0
    assert profile_doc.scheduled_unit_rate_hz == pytest.approx(10.0)
    assert profile_doc.observed_unit_rate_hz is not None
    assert profile_doc.effective_goodput_bps is not None
    assert profile_doc.rate_status == "local_scheme_demonstration_not_capacity"


def test_unknown_profile_and_missing_session_fail_loudly():
    with pytest.raises(UnsupportedMechanismError):
        MechanismProfile.from_catalog("no-such-mechanism", DATA)

    profile = MechanismProfile.from_catalog("tcp-reserved-bits", DATA)
    session = ChannelSession(profile, InMemoryTransport())
    with pytest.raises(TransportError):
        session.receive_message("missing")


def test_receive_decode_failure_raises_structured_error():
    class NoopTransport:
        def send_symbols(
            self,
            session_id: str,
            symbols: list[Symbol],
            pacing: PacingConfig | None = None,
        ) -> None:
            pass

    class BadTap:
        def receive_symbols(self, session_id: str) -> list[Symbol]:
            _ = session_id
            return [123]

    profile = MechanismProfile.from_catalog("quic-connection-id", DATA)
    session = ChannelSession(profile, NoopTransport(), tap=BadTap())

    with pytest.raises(DecodeError, match="bad: decode failed"):
        session.receive_message("bad")


def test_session_roundtrips_large_payload_with_chunked_integrity():
    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    transport = InMemoryTransport()
    session = ChannelSession(profile, transport)
    payload = bytes(range(256)) * 300

    receipt = session.send_message(payload, session_id="large")
    result = session.receive_message(receipt)

    assert result.payload == payload
    assert receipt.session_framing == "chunked"
    assert receipt.chunk_count > 1
    assert receipt.integrity_sha256 == result.evidence.integrity_sha256
    assert result.evidence.session_framing == "chunked"
    assert result.evidence.chunk_count == receipt.chunk_count
    assert result.evidence.payload_len == len(payload)
    assert result.evidence.recovered_len == len(payload)


def test_chunked_session_detects_dropped_symbols():
    class DropLastTap:
        def __init__(self, transport: InMemoryTransport) -> None:
            self.transport = transport

        def receive_symbols(self, session_id: str) -> list[Symbol]:
            return self.transport.receive_symbols(session_id)[:-1]

    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    transport = InMemoryTransport()
    framing = SessionFramingConfig(chunk_payload_bytes=32, force_chunked=True)
    sender = ChannelSession(profile, transport, framing=framing)
    receipt = sender.send_message(b"dropped-symbol-test" * 8, session_id="drop")
    receiver = ChannelSession(profile, transport, tap=DropLastTap(transport), framing=framing)

    with pytest.raises(DecodeError, match="drop: decode failed"):
        receiver.receive_message(receipt)


def test_chunked_session_detects_tampered_symbols():
    class TamperTap:
        def __init__(self, transport: InMemoryTransport) -> None:
            self.transport = transport

        def receive_symbols(self, session_id: str) -> list[Symbol]:
            symbols = self.transport.receive_symbols(session_id)
            symbol = bytearray(symbols[5])
            symbol[0] ^= 0x01
            symbols[5] = bytes(symbol)
            return symbols

    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    transport = InMemoryTransport()
    framing = SessionFramingConfig(chunk_payload_bytes=32, force_chunked=True)
    sender = ChannelSession(profile, transport, framing=framing)
    receipt = sender.send_message(b"tamper-symbol-test" * 8, session_id="tamper")
    receiver = ChannelSession(profile, transport, tap=TamperTap(transport), framing=framing)

    with pytest.raises(DecodeError, match="tamper: decode failed"):
        receiver.receive_message(receipt)


def test_chunked_session_suppresses_identical_duplicate_chunks():
    class DuplicateFirstChunkTap:
        def __init__(self, transport: InMemoryTransport, first_chunk_symbols: int) -> None:
            self.transport = transport
            self.first_chunk_symbols = first_chunk_symbols

        def receive_symbols(self, session_id: str) -> list[Symbol]:
            symbols = self.transport.receive_symbols(session_id)
            return symbols[: self.first_chunk_symbols] + symbols

    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    transport = InMemoryTransport()
    framing = SessionFramingConfig(chunk_payload_bytes=16, force_chunked=True)
    sender = ChannelSession(profile, transport, framing=framing)
    receipt = sender.send_message(b"duplicate-chunk-test" * 4, session_id="duplicate")
    first_chunk_symbols = len(transport.receive_symbols(receipt.session_id)) // receipt.chunk_count
    receiver = ChannelSession(
        profile,
        transport,
        tap=DuplicateFirstChunkTap(transport, first_chunk_symbols),
        framing=framing,
    )

    result = receiver.receive_message(receipt)

    assert result.payload == b"duplicate-chunk-test" * 4
    assert result.evidence.reliability.duplicate_chunks == 1
    assert result.evidence.reliability.recovered_chunks == receipt.chunk_count


def test_chunked_session_rejects_conflicting_duplicate_chunks():
    class ConflictingDuplicateTap:
        def __init__(self, transport: InMemoryTransport, first_chunk_symbols: int) -> None:
            self.transport = transport
            self.first_chunk_symbols = first_chunk_symbols

        def receive_symbols(self, session_id: str) -> list[Symbol]:
            symbols = self.transport.receive_symbols(session_id)
            duplicate = list(symbols[: self.first_chunk_symbols])
            symbol = bytearray(duplicate[1])
            symbol[-1] ^= 0x01
            duplicate[1] = bytes(symbol)
            return [*duplicate, *symbols]

    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    transport = InMemoryTransport()
    framing = SessionFramingConfig(chunk_payload_bytes=16, force_chunked=True)
    sender = ChannelSession(profile, transport, framing=framing)
    receipt = sender.send_message(b"conflicting-duplicate-test" * 3, session_id="conflict")
    first_chunk_symbols = len(transport.receive_symbols(receipt.session_id)) // receipt.chunk_count
    receiver = ChannelSession(
        profile,
        transport,
        tap=ConflictingDuplicateTap(transport, first_chunk_symbols),
        framing=framing,
    )

    with pytest.raises(DecodeError, match="conflict: decode failed"):
        receiver.receive_message(receipt)


def test_receive_retries_after_transient_missing_symbols():
    class FlakyTap:
        def __init__(self, transport: InMemoryTransport) -> None:
            self.transport = transport
            self.calls = 0

        def receive_symbols(self, session_id: str) -> list[Symbol]:
            self.calls += 1
            symbols = self.transport.receive_symbols(session_id)
            if self.calls == 1:
                return symbols[:-1]
            return symbols

    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    transport = InMemoryTransport()
    framing = SessionFramingConfig(chunk_payload_bytes=16, force_chunked=True)
    sender = ChannelSession(profile, transport, framing=framing)
    receipt = sender.send_message(b"retry-after-loss" * 5, session_id="retry")
    receiver = ChannelSession(
        profile,
        transport,
        tap=FlakyTap(transport),
        framing=framing,
        reliability=ReliabilityPolicy(max_receive_attempts=2),
    )

    result = receiver.receive_message(receipt)

    assert result.payload == b"retry-after-loss" * 5
    assert result.evidence.reliability.receive_attempts == 2
    assert result.evidence.reliability.retry_count == 1
    assert result.evidence.reliability.loss_detected is True
    assert result.evidence.reliability.last_error is not None


def test_receive_requests_retransmission_after_loss_like_decode_failure():
    class RetransmitTransport(InMemoryTransport):
        def __init__(self) -> None:
            super().__init__()
            self.retransmit_calls = 0
            self.retransmitted = False

        def receive_symbols(self, session_id: str) -> list[Symbol]:
            symbols = super().receive_symbols(session_id)
            if not self.retransmitted:
                return symbols[:-1]
            return symbols

        def retransmit_symbols(self, session_id: str) -> None:
            _ = session_id
            self.retransmit_calls += 1
            self.retransmitted = True

    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    transport = RetransmitTransport()
    framing = SessionFramingConfig(chunk_payload_bytes=16, force_chunked=True)
    sender = ChannelSession(profile, transport, framing=framing)
    receipt = sender.send_message(b"retransmit-after-loss" * 5, session_id="retransmit")
    receiver = ChannelSession(
        profile,
        transport,
        framing=framing,
        reliability=ReliabilityPolicy(max_receive_attempts=2, max_retransmissions=1),
    )

    result = receiver.receive_message(receipt)

    assert result.payload == b"retransmit-after-loss" * 5
    assert transport.retransmit_calls == 1
    assert result.evidence.reliability.receive_attempts == 2
    assert result.evidence.reliability.retry_count == 1
    assert result.evidence.reliability.retransmit_requests == 1
    assert result.evidence.reliability.loss_detected is True


def test_receive_timeout_uses_pacing_timeout_and_retries():
    class TimeoutThenSuccessTap:
        def __init__(self, transport: InMemoryTransport) -> None:
            self.transport = transport
            self.calls = 0
            self.timeouts: list[float | None] = []

        def receive_symbols(self, session_id: str) -> list[Symbol]:
            _ = session_id
            raise AssertionError("timeout-aware tap should be used")

        def receive_symbols_with_timeout(
            self,
            session_id: str,
            timeout_s: float | None,
        ) -> list[Symbol]:
            self.calls += 1
            self.timeouts.append(timeout_s)
            if self.calls == 1:
                raise ReceiveTimeoutError(f"{session_id}: timed out waiting for symbols")
            return self.transport.receive_symbols(session_id)

    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    transport = InMemoryTransport()
    pacing = PacingConfig(timeout_s=0.25)
    sender = ChannelSession(profile, transport)
    receipt = sender.send_message(b"timeout retry", session_id="timeout-retry", pacing=pacing)
    tap = TimeoutThenSuccessTap(transport)
    receiver = ChannelSession(
        profile,
        transport,
        tap=tap,
        reliability=ReliabilityPolicy(max_receive_attempts=2),
    )

    result = receiver.receive_message(receipt)

    assert result.payload == b"timeout retry"
    assert tap.timeouts == [0.25, 0.25]
    assert result.evidence.reliability.receive_attempts == 2
    assert result.evidence.reliability.retry_count == 1
    assert result.evidence.reliability.loss_detected is True
    assert result.evidence.reliability.timed_out is True
    assert result.evidence.reliability.last_error is not None


def test_receive_does_not_request_retransmission_without_policy_budget():
    class RetransmitTransport(InMemoryTransport):
        def __init__(self) -> None:
            super().__init__()
            self.retransmit_calls = 0

        def receive_symbols(self, session_id: str) -> list[Symbol]:
            return super().receive_symbols(session_id)[:-1]

        def retransmit_symbols(self, session_id: str) -> None:
            _ = session_id
            self.retransmit_calls += 1

    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    transport = RetransmitTransport()
    framing = SessionFramingConfig(chunk_payload_bytes=16, force_chunked=True)
    sender = ChannelSession(profile, transport, framing=framing)
    receipt = sender.send_message(b"no-retransmit-budget" * 5, session_id="no-retransmit")
    receiver = ChannelSession(
        profile,
        transport,
        framing=framing,
        reliability=ReliabilityPolicy(max_receive_attempts=2),
    )

    with pytest.raises(DecodeError, match="no-retransmit: decode failed"):
        receiver.receive_message(receipt)
    assert transport.retransmit_calls == 0


def test_failure_result_returns_structured_evidence():
    profile = MechanismProfile.from_catalog("tcp-reserved-bits", DATA)
    session = ChannelSession(profile, InMemoryTransport())

    result = session.failure_result(
        "failed",
        DecodeError("decode failed"),
        expected_payload_len=12,
        carrier_units=3,
        elapsed_s=0.01,
    )

    assert result.payload == b""
    assert result.evidence.ok is False
    assert result.evidence.payload_len == 12
    assert result.evidence.recovered_len == 0
    assert result.evidence.carrier_units == 3
    assert result.evidence.error == "DecodeError: decode failed"


def test_invalid_pacing_config_fails_loudly():
    with pytest.raises(ValueError):
        PacingConfig(unit_rate_hz=10.0, symbol_period_s=0.1)
    with pytest.raises(ValueError):
        PacingConfig(unit_rate_hz=0)
    with pytest.raises(ValueError):
        PacingConfig(base_delay_s=-0.1)
    with pytest.raises(ValueError):
        PacingConfig(jitter_sample_window=-1)
