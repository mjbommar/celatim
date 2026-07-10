"""HTTP/2 hyper-h2 testbed helper tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from celatim.errors import TransportError
from celatim.session import MechanismProfile
from celatim.testbed import (
    HTTP2_HYPER_H2_TRANSPORT_KIND,
    HyperH2PingPathConfig,
    run_hyper_h2_ping_roundtrip,
)

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


class RemoteSettingsChanged:
    pass


class SettingsAcknowledged:
    pass


class PingReceived:
    def __init__(self, ping_data: bytes) -> None:
        self.ping_data = ping_data


class PingAckReceived:
    def __init__(self, ping_data: bytes) -> None:
        self.ping_data = ping_data


class _FakeH2Connection:
    def __init__(self, *, client_side: bool, bad_ack: bool = False) -> None:
        self.client_side = client_side
        self.bad_ack = bad_ack
        self._out: list[bytes] = []

    def initiate_connection(self) -> None:
        self._out.append(b"client-preface" if self.client_side else b"server-settings")

    def data_to_send(self) -> bytes:
        data = b"".join(self._out)
        self._out.clear()
        return data

    def ping(self, opaque: bytes) -> None:
        self._out.append(b"PING:" + opaque)

    def receive_data(self, data: bytes) -> list[object]:
        if data.startswith(b"PING:"):
            opaque = data.removeprefix(b"PING:")
            self._out.append(b"ACK:" + (b"BAD-ACK!" if self.bad_ack else opaque))
            return [PingReceived(opaque)]
        if data.startswith(b"ACK:"):
            return [PingAckReceived(data.removeprefix(b"ACK:"))]
        if self.client_side:
            return [RemoteSettingsChanged(), SettingsAcknowledged()]
        self._out.append(b"server-settings-ack")
        return [RemoteSettingsChanged()]


def _fake_factory(*, bad_ack: bool = False):
    def factory(client_side: bool) -> _FakeH2Connection:
        return _FakeH2Connection(client_side=client_side, bad_ack=bad_ack)

    return factory


def test_hyper_h2_ping_roundtrip_writes_transcript_with_fake_connections(tmp_path):
    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)
    transcript = tmp_path / "h2-transcript.json"

    live = run_hyper_h2_ping_roundtrip(
        profile,
        b"\x00\xff\x80ABC",
        session_id="http2-test",
        config=HyperH2PingPathConfig(transcript_json=transcript),
        connection_factory=_fake_factory(),
    )

    assert live.result.payload == b"\x00\xff\x80ABC"
    assert live.result.evidence.carrier_units == live.receipt.carrier_units
    assert live.transport_metadata["schema_version"] == (
        "celatim.transport_metadata.http2_hyper_h2.v1"
    )
    assert live.transport_metadata["implementation"] == "hyper-h2"
    assert live.transport_metadata["ping_count"] == live.receipt.carrier_units
    assert live.transport_metadata["ping_ack_count"] == live.receipt.carrier_units
    assert live.transport_metadata["transcript_json"] == str(transcript)

    document = json.loads(transcript.read_text())
    assert document["schema_version"] == "celatim.http2_hyper_h2_transcript.v1"
    assert document["transport_kind"] == HTTP2_HYPER_H2_TRANSPORT_KIND
    assert document["ping_count"] == live.receipt.carrier_units
    assert document["ping_ack_count"] == live.receipt.carrier_units
    assert "ping_data" not in document


def test_hyper_h2_ping_roundtrip_rejects_bad_ack_with_fake_connections():
    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)

    with pytest.raises(TransportError, match="PING ACK opaque data"):
        run_hyper_h2_ping_roundtrip(
            profile,
            b"payload",
            config=HyperH2PingPathConfig(validate_ack=True),
            connection_factory=_fake_factory(bad_ack=True),
        )
