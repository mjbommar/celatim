"""aioquic HTTP/3 reserved SETTINGS testbed helper tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from celatim.errors import TransportError
from celatim.session import MechanismProfile
from celatim.testbed import (
    HTTP3_AIOQUIC_SETTINGS_CLAIM_STATUS,
    HTTP3_AIOQUIC_SETTINGS_TRANSPORT_KIND,
    HTTP3_RESERVED_SETTINGS_ID,
    AioquicH3SettingsPathConfig,
    run_aioquic_h3_settings_roundtrip,
)

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def _fake_exchange(
    symbols: tuple[int, ...],
    validate_receiver_settings: bool,
) -> dict[str, object]:
    return {
        "schema_version": "celatim.http3_aioquic_settings_transcript.v1",
        "implementation": "aioquic.h3",
        "aioquic_version": "test",
        "claim_status": HTTP3_AIOQUIC_SETTINGS_CLAIM_STATUS,
        "controlled_hook": "test local SETTINGS hook",
        "validate_receiver_settings": validate_receiver_settings,
        "reserved_setting_id": HTTP3_RESERVED_SETTINGS_ID,
        "symbol_count": len(symbols),
        "observed_setting_values": list(symbols),
        "settings": [
            {
                "index": index,
                "reserved_setting_id": HTTP3_RESERVED_SETTINGS_ID,
                "sent_setting_value": symbol,
                "observed_setting_value": symbol,
                "control_stream_id": 2,
                "control_stream_len": 12,
                "control_stream_sha256": "0" * 64,
                "receiver_settings": {str(HTTP3_RESERVED_SETTINGS_ID): symbol},
            }
            for index, symbol in enumerate(symbols)
        ],
    }


def test_aioquic_h3_settings_roundtrip_writes_transcript_with_fake_exchange(tmp_path):
    profile = MechanismProfile.from_catalog("http3-reserved-settings", DATA)
    transcript = tmp_path / "h3-transcript.json"

    live = run_aioquic_h3_settings_roundtrip(
        profile,
        b"\x00\xff\x80H3",
        session_id="h3-test",
        config=AioquicH3SettingsPathConfig(
            transcript_json=transcript,
            validate_receiver_settings=True,
        ),
        exchange_runner=_fake_exchange,
    )

    assert live.result.payload == b"\x00\xff\x80H3"
    assert live.result.evidence.carrier_units == live.receipt.carrier_units
    assert live.transport_metadata["schema_version"] == (
        "celatim.transport_metadata.http3_aioquic_reserved_settings.v1"
    )
    assert live.transport_metadata["implementation"] == "aioquic.h3"
    assert live.transport_metadata["claim_status"] == HTTP3_AIOQUIC_SETTINGS_CLAIM_STATUS
    assert live.transport_metadata["reserved_setting_id"] == HTTP3_RESERVED_SETTINGS_ID
    assert live.transport_metadata["symbol_count"] == live.receipt.carrier_units
    assert live.transport_metadata["transcript_json"] == str(transcript)

    document = json.loads(transcript.read_text())
    assert document["schema_version"] == "celatim.http3_aioquic_settings_transcript.v1"
    assert document["transport_kind"] == HTTP3_AIOQUIC_SETTINGS_TRANSPORT_KIND
    assert document["reserved_setting_id"] == HTTP3_RESERVED_SETTINGS_ID
    assert document["symbol_count"] == live.receipt.carrier_units


def test_aioquic_h3_settings_roundtrip_rejects_mismatched_observation():
    profile = MechanismProfile.from_catalog("http3-reserved-settings", DATA)

    def bad_exchange(
        symbols: tuple[int, ...],
        validate_receiver_settings: bool,
    ) -> dict[str, object]:
        document = _fake_exchange(symbols, validate_receiver_settings)
        document["observed_setting_values"] = [0 for _ in symbols]
        return document

    with pytest.raises(TransportError, match="observed HTTP/3 SETTINGS"):
        run_aioquic_h3_settings_roundtrip(
            profile,
            b"payload",
            exchange_runner=bad_exchange,
        )
