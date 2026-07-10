"""Aggregate detectability controls for Class-G crypto transcripts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from celatim.analysis.subliminal_controls import build_subliminal_control_report
from celatim.crypto_transcript import (
    EcdsaNonceTranscriptConfig,
    EcdsaNonceTranscriptTransport,
    RsaPssSaltTranscriptConfig,
    RsaPssSaltTranscriptTransport,
)
from celatim.session import ChannelSession, MechanismProfile

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def test_subliminal_control_report_requires_requested_control_power(tmp_path):
    pytest.importorskip("ecdsa")
    pytest.importorskip("cryptography")
    ecdsa_path = tmp_path / "ecdsa.json"
    rsa_path = tmp_path / "rsa.json"

    _write_ecdsa_transcript(ecdsa_path, controls=4)
    _write_rsa_transcript(rsa_path, controls=4)

    report = build_subliminal_control_report(
        [ecdsa_path, rsa_path],
        min_control_signatures=4,
        min_p_value=0.0,
        generated_at_unix_s=1.0,
    )
    assert report["schema_version"] == "celatim.subliminal_control_report.v1"
    assert report["ok"] is True
    assert report["passed_count"] == 2
    assert {case["mechanism_id"] for case in report["cases"]} == {
        "ecdsa-nonce",
        "rsa-pss-salt",
    }
    assert all(case["honest_control_signature_count"] == 4 for case in report["cases"])
    assert all(
        case["signature_bit_balance_test"]["p_value"] is not None for case in report["cases"]
    )

    underpowered = build_subliminal_control_report(
        [ecdsa_path, rsa_path],
        min_control_signatures=5,
        min_p_value=0.0,
        generated_at_unix_s=1.0,
    )
    assert underpowered["ok"] is False
    assert underpowered["claim_status"] == "underpowered_or_anomalous_controls"


def test_subliminal_control_report_rejects_old_transcripts_without_bit_stats(tmp_path):
    path = tmp_path / "old.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "celatim.crypto_transcript.ecdsa_nonce.v1",
                "session_id": "old",
                "signatures": [{"verified": True}],
                "honest_random_control": {
                    "embedded_symbol_like_count": 0,
                    "records": [{"verified": True}],
                },
            }
        )
    )

    report = build_subliminal_control_report(
        [path],
        min_control_signatures=1,
        min_p_value=0.0,
        generated_at_unix_s=1.0,
    )

    assert report["ok"] is False
    assert report["cases"][0]["signature_bit_balance_test"]["p_value"] is None


def _write_ecdsa_transcript(path: Path, *, controls: int) -> None:
    profile = MechanismProfile.from_catalog("ecdsa-nonce", DATA)
    transport = EcdsaNonceTranscriptTransport(
        profile,
        EcdsaNonceTranscriptConfig(
            transcript_path=path,
            honest_random_control_signatures=controls,
        ),
    )
    ChannelSession(profile, transport).run_roundtrip(b"\x00\xffcrypto", session_id="ecdsa-controls")


def _write_rsa_transcript(path: Path, *, controls: int) -> None:
    profile = MechanismProfile.from_catalog("rsa-pss-salt", DATA)
    transport = RsaPssSaltTranscriptTransport(
        profile,
        RsaPssSaltTranscriptConfig(
            transcript_path=path,
            honest_random_control_signatures=controls,
        ),
    )
    ChannelSession(profile, transport).run_roundtrip(b"\x00\xffcrypto", session_id="rsa-controls")
