"""aioquic QUIC connection-ID testbed helper tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from celatim.errors import TransportError
from celatim.session import MechanismProfile
from celatim.testbed import (
    QUIC_AIOQUIC_CLAIM_STATUS,
    QUIC_AIOQUIC_TRANSPORT_KIND,
    AioquicConnectionIdPathConfig,
    run_aioquic_connection_id_roundtrip,
)

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def _fake_exchange(symbols: tuple[bytes, ...], validate_server_response: bool) -> dict[str, object]:
    return {
        "schema_version": "celatim.quic_aioquic_transcript.v1",
        "implementation": "aioquic",
        "aioquic_version": "test",
        "claim_status": QUIC_AIOQUIC_CLAIM_STATUS,
        "controlled_hook": "test pre-connect peer CID hook",
        "validate_server_response": validate_server_response,
        "symbol_count": len(symbols),
        "observed_dcid_hex": [symbol.hex() for symbol in symbols],
        "packets": [
            {
                "index": index,
                "dcid_hex": symbol.hex(),
                "client_initial_len": 1200,
                "client_initial_sha256": "0" * 64,
                "client_scid_hex": "11" * 20,
                "server_response_count": 1,
                "server_response_lengths": [1200],
                "server_response_sha256": ["1" * 64],
            }
            for index, symbol in enumerate(symbols)
        ],
    }


def test_aioquic_connection_id_roundtrip_writes_transcript_with_fake_exchange(tmp_path):
    profile = MechanismProfile.from_catalog("quic-connection-id", DATA)
    transcript = tmp_path / "quic-transcript.json"

    live = run_aioquic_connection_id_roundtrip(
        profile,
        b"\x00\xff\x80QUIC",
        session_id="quic-test",
        config=AioquicConnectionIdPathConfig(
            transcript_json=transcript,
            validate_server_response=True,
        ),
        exchange_runner=_fake_exchange,
    )

    assert live.result.payload == b"\x00\xff\x80QUIC"
    assert live.result.evidence.carrier_units == live.receipt.carrier_units
    assert live.transport_metadata["schema_version"] == (
        "celatim.transport_metadata.quic_aioquic_connection_id.v1"
    )
    assert live.transport_metadata["implementation"] == "aioquic"
    assert live.transport_metadata["claim_status"] == QUIC_AIOQUIC_CLAIM_STATUS
    assert live.transport_metadata["symbol_count"] == live.receipt.carrier_units
    assert live.transport_metadata["transcript_json"] == str(transcript)

    document = json.loads(transcript.read_text())
    assert document["schema_version"] == "celatim.quic_aioquic_transcript.v1"
    assert document["transport_kind"] == QUIC_AIOQUIC_TRANSPORT_KIND
    assert document["symbol_count"] == live.receipt.carrier_units
    assert "observed_dcid_hex" in document


def test_aioquic_connection_id_roundtrip_rejects_mismatched_observation():
    profile = MechanismProfile.from_catalog("quic-connection-id", DATA)

    def bad_exchange(
        symbols: tuple[bytes, ...],
        validate_server_response: bool,
    ) -> dict[str, object]:
        document = _fake_exchange(symbols, validate_server_response)
        document["observed_dcid_hex"] = ["00" * 20 for _ in symbols]
        return document

    with pytest.raises(TransportError, match="observed DCID symbols"):
        run_aioquic_connection_id_roundtrip(
            profile,
            b"payload",
            exchange_runner=bad_exchange,
        )
