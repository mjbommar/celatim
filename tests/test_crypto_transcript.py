"""Class G crypto transcript transports."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from celatim.crypto_transcript import (
    ECDSA_NONCE_CLAIM_STATUS,
    ECDSA_NONCE_TRANSCRIPT_SCHEMA_VERSION,
    ECDSA_NONCE_TRANSPORT_METADATA_SCHEMA_VERSION,
    RSA_PSS_SALT_CLAIM_STATUS,
    RSA_PSS_SALT_TRANSCRIPT_SCHEMA_VERSION,
    RSA_PSS_SALT_TRANSPORT_METADATA_SCHEMA_VERSION,
    EcdsaNonceTranscriptConfig,
    EcdsaNonceTranscriptReplayTransport,
    EcdsaNonceTranscriptTransport,
    RsaPssSaltTranscriptConfig,
    RsaPssSaltTranscriptReplayTransport,
    RsaPssSaltTranscriptTransport,
)
from celatim.errors import TransportError
from celatim.session import ChannelSession, MechanismProfile

pytest.importorskip("cryptography")

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def test_ecdsa_nonce_transcript_roundtrip_signs_verifies_and_recovers_symbols(tmp_path):
    profile = MechanismProfile.from_catalog("ecdsa-nonce", DATA)
    transcript_path = tmp_path / "ecdsa-transcript.json"
    transport = EcdsaNonceTranscriptTransport(
        profile,
        EcdsaNonceTranscriptConfig(transcript_path=transcript_path),
    )
    payload = b"\x00\xffcrypto"

    result = ChannelSession(profile, transport).run_roundtrip(
        payload,
        session_id="ecdsa-transcript-test",
    )

    transcript = json.loads(transcript_path.read_text())
    metadata = transport.metadata_for("ecdsa-transcript-test")
    assert result.payload == payload
    assert result.evidence.ok is True
    assert result.evidence.carrier_structure.value == "crypto_transcript"
    assert transcript["schema_version"] == ECDSA_NONCE_TRANSCRIPT_SCHEMA_VERSION
    assert transcript["mechanism_id"] == "ecdsa-nonce"
    assert transcript["claim_status"] == ECDSA_NONCE_CLAIM_STATUS
    assert transcript["signing_backend"] == "cryptography_openssl_with_explicit_research_nonce"
    assert transcript["key_scope"] == "ephemeral_per_transcript"
    assert transcript["signature_count"] == 1
    assert transcript["verified_signature_count"] == 1
    assert transcript["recovered_symbol_count"] == 1
    assert transcript["signatures"][0]["verified"] is True
    assert transcript["signatures"][0]["signature_bit_count"] > 0
    assert transcript["signatures"][0]["signature_bit_one_count"] > 0
    assert (
        bytes.fromhex(transcript["signatures"][0]["recovered_symbol_hex"])
        == (transport.receive_symbols("ecdsa-transcript-test")[0])
    )
    assert transcript["honest_random_control"]["signature_count"] == 2
    assert transcript["honest_random_control"]["verified_signature_count"] == 2
    assert transcript["honest_random_control"]["embedded_symbol_like_count"] == 0
    assert transcript["honest_random_control"]["records"][0]["signature_bit_count"] > 0
    assert transcript["honest_random_control"]["records"][0]["signature_bit_one_count"] > 0
    assert metadata["schema_version"] == ECDSA_NONCE_TRANSPORT_METADATA_SCHEMA_VERSION
    assert metadata["transcript_sha256"] == hashlib.sha256(transcript_path.read_bytes()).hexdigest()
    assert metadata["transcript_size_bytes"] == transcript_path.stat().st_size


def test_ecdsa_nonce_transcript_replay_decodes_persisted_artifact(tmp_path):
    profile = MechanismProfile.from_catalog("ecdsa-nonce", DATA)
    transcript_path = tmp_path / "ecdsa-transcript.json"
    writer = EcdsaNonceTranscriptTransport(
        profile,
        EcdsaNonceTranscriptConfig(transcript_path=transcript_path),
    )
    payload = b"\x00\xffreplay"

    ChannelSession(profile, writer).send_message(payload, session_id="ecdsa-replay-test")
    replay = EcdsaNonceTranscriptReplayTransport(profile, transcript_path)
    result = ChannelSession(profile, replay).receive_message("ecdsa-replay-test")
    metadata = replay.metadata_for("ecdsa-replay-test")

    assert result.payload == payload
    assert result.evidence.ok is True
    assert replay.path_for("ecdsa-replay-test") == transcript_path
    assert metadata["schema_version"] == ECDSA_NONCE_TRANSPORT_METADATA_SCHEMA_VERSION
    assert metadata["transcript_sha256"] == hashlib.sha256(transcript_path.read_bytes()).hexdigest()


def test_ecdsa_nonce_transcript_truncates_wide_digest_to_curve_order(tmp_path):
    profile = MechanismProfile.from_catalog("ecdsa-nonce", DATA)
    transcript_path = tmp_path / "ecdsa-p384-sha512.json"
    transport = EcdsaNonceTranscriptTransport(
        profile,
        EcdsaNonceTranscriptConfig(
            transcript_path=transcript_path,
            curve="NIST384p",
            hash_name="sha512",
            honest_random_control_signatures=1,
        ),
    )

    result = ChannelSession(profile, transport).run_roundtrip(
        b"digest truncation",
        session_id="ecdsa-p384-sha512",
    )

    transcript = json.loads(transcript_path.read_text())
    assert result.payload == b"digest truncation"
    assert transcript["curve"] == "NIST384p"
    assert transcript["hash_name"] == "sha512"
    assert transcript["verified_signature_count"] == transcript["signature_count"]
    assert transcript["honest_random_control"]["verified_signature_count"] == 1


def test_ecdsa_nonce_transcript_rejects_non_ecdsa_mechanism():
    profile = MechanismProfile.from_catalog("rsa-pss-salt", DATA)

    with pytest.raises(TransportError, match="only supports ecdsa-nonce"):
        EcdsaNonceTranscriptTransport(profile)


def test_rsa_pss_salt_transcript_roundtrip_signs_verifies_and_recovers_symbols(tmp_path):
    pytest.importorskip("cryptography")
    profile = MechanismProfile.from_catalog("rsa-pss-salt", DATA)
    transcript_path = tmp_path / "rsa-pss-transcript.json"
    transport = RsaPssSaltTranscriptTransport(
        profile,
        RsaPssSaltTranscriptConfig(transcript_path=transcript_path),
    )
    payload = b"\x00\xffrsa-pss"

    result = ChannelSession(profile, transport).run_roundtrip(
        payload,
        session_id="rsa-pss-transcript-test",
    )

    transcript = json.loads(transcript_path.read_text())
    metadata = transport.metadata_for("rsa-pss-transcript-test")
    assert result.payload == payload
    assert result.evidence.ok is True
    assert result.evidence.carrier_structure.value == "crypto_transcript"
    assert transcript["schema_version"] == RSA_PSS_SALT_TRANSCRIPT_SCHEMA_VERSION
    assert transcript["mechanism_id"] == "rsa-pss-salt"
    assert transcript["claim_status"] == RSA_PSS_SALT_CLAIM_STATUS
    assert transcript["signature_count"] == 1
    assert transcript["verified_signature_count"] == 1
    assert transcript["recovered_symbol_count"] == 1
    assert transcript["signatures"][0]["verified"] is True
    assert transcript["signatures"][0]["signature_bit_count"] > 0
    assert transcript["signatures"][0]["signature_bit_one_count"] > 0
    assert (
        bytes.fromhex(transcript["signatures"][0]["recovered_salt_hex"])
        == (transport.receive_symbols("rsa-pss-transcript-test")[0])
    )
    assert transcript["honest_random_control"]["signature_count"] == 2
    assert transcript["honest_random_control"]["verified_signature_count"] == 2
    assert transcript["honest_random_control"]["recovered_salt_count"] == 2
    assert transcript["honest_random_control"]["distinct_recovered_salt_sha256_count"] == 2
    assert transcript["honest_random_control"]["embedded_payload_match_count"] == 0
    assert transcript["honest_random_control"]["records"][0]["signature_bit_count"] > 0
    assert transcript["honest_random_control"]["records"][0]["signature_bit_one_count"] > 0
    assert metadata["schema_version"] == RSA_PSS_SALT_TRANSPORT_METADATA_SCHEMA_VERSION
    assert metadata["transcript_sha256"] == hashlib.sha256(transcript_path.read_bytes()).hexdigest()
    assert metadata["transcript_size_bytes"] == transcript_path.stat().st_size


def test_rsa_pss_salt_transcript_replay_decodes_persisted_artifact(tmp_path):
    pytest.importorskip("cryptography")
    profile = MechanismProfile.from_catalog("rsa-pss-salt", DATA)
    transcript_path = tmp_path / "rsa-pss-transcript.json"
    writer = RsaPssSaltTranscriptTransport(
        profile,
        RsaPssSaltTranscriptConfig(transcript_path=transcript_path),
    )
    payload = b"\x00\xffrsa-replay"

    ChannelSession(profile, writer).send_message(payload, session_id="rsa-pss-replay-test")
    replay = RsaPssSaltTranscriptReplayTransport(profile, transcript_path)
    result = ChannelSession(profile, replay).receive_message("rsa-pss-replay-test")
    metadata = replay.metadata_for("rsa-pss-replay-test")

    assert result.payload == payload
    assert result.evidence.ok is True
    assert replay.path_for("rsa-pss-replay-test") == transcript_path
    assert metadata["schema_version"] == RSA_PSS_SALT_TRANSPORT_METADATA_SCHEMA_VERSION
    assert metadata["transcript_sha256"] == hashlib.sha256(transcript_path.read_bytes()).hexdigest()


def test_rsa_pss_salt_transcript_rejects_non_rsa_pss_mechanism():
    profile = MechanismProfile.from_catalog("ecdsa-nonce", DATA)

    with pytest.raises(TransportError, match="only supports rsa-pss-salt"):
        RsaPssSaltTranscriptTransport(profile)
