"""Production OpenSSH KEXINIT transport tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from celatim.errors import TransportError
from celatim.session import MechanismProfile
from celatim.testbed import OpenSshKexinitPathConfig, run_openssh_kexinit_roundtrip

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def _accepted_handshake(cookie: bytes, config: OpenSshKexinitPathConfig) -> dict[str, object]:
    return {
        "sent_cookie_hex": cookie.hex(),
        "reserved_uint32_hex": "00000000",
        "kexinit_payload_len": 512,
        "kexinit_payload_sha256": "a" * 64,
        "key_exchange_completed": True,
        "remote_version": "SSH-2.0-OpenSSH_test",
        "host_key_type": "ssh-ed25519",
        "host_key_sha256": "b" * 64,
        "local_cipher": "aes128-ctr",
        "remote_cipher": "aes128-ctr",
        "elapsed_s": 0.01,
    }


def test_openssh_roundtrip_recovers_framed_payload_and_writes_transcript(tmp_path):
    profile = MechanismProfile.from_catalog("ssh-kexinit-cookie", DATA)
    transcript = tmp_path / "openssh.json"

    live = run_openssh_kexinit_roundtrip(
        profile,
        b"\x00\xff\x80SSH",
        session_id="openssh-test",
        config=OpenSshKexinitPathConfig(
            host="ssh.example",
            port=2222,
            transcript_json=transcript,
        ),
        connector=_accepted_handshake,
    )

    assert live.result.payload == b"\x00\xff\x80SSH"
    assert live.transport_metadata["all_key_exchanges_completed"] is True
    assert live.transport_metadata["all_reserved_words_zero"] is True
    assert live.transport_metadata["server_versions"] == ["SSH-2.0-OpenSSH_test"]
    assert live.transport_metadata["handshake_count"] == live.receipt.carrier_units

    document = json.loads(transcript.read_text())
    assert document["schema_version"] == "celatim.ssh_kexinit_openssh_transcript.v1"
    assert document["server_host"] == "ssh.example"
    assert document["server_port"] == 2222
    assert all(item["reserved_uint32_hex"] == "00000000" for item in document["handshakes"])


def test_openssh_transport_rejects_wrong_width_symbols():
    profile = MechanismProfile.from_catalog("ssh-kexinit-cookie", DATA)

    def bad_connector(cookie: bytes, config: OpenSshKexinitPathConfig) -> dict[str, object]:
        raise AssertionError("connector must not be called")

    from celatim.testbed import OpenSshKexinitTransport

    transport = OpenSshKexinitTransport(profile, connector=bad_connector)
    with pytest.raises(TransportError, match="cookie symbols must be 16 bytes"):
        transport.send_symbols("bad", [b"short"])
