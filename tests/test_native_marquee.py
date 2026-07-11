"""Live split-process checks for the native-protocol marquee endpoints."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from celatim.catalog import load_mechanisms
from celatim.channel.framer import Framer
from celatim.channel.registry import codec_for
from celatim.resources import catalog_path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNNER = PROJECT_ROOT / "experiments" / "native_marquee.py"
PAYLOAD = bytes(range(16))
SUPPORTED_MECHANISMS = (
    "http2-ping-opaque",
    "quic-connection-id",
    "ssh-kexinit-cookie",
    "bgp-optional-transitive",
    "edns0-padding",
    "rtp-rtcp-ext-app",
    "stun-attr-padding",
    "coap-tunnel",
)


def _expected_symbol_count(mechanism_id: str) -> int:
    with catalog_path() as path:
        mechanism = next(item for item in load_mechanisms(path) if item.id == mechanism_id)
    return len(Framer(codec_for(mechanism)).encode(PAYLOAD))


def _wait_for_ready(path: Path, receiver: subprocess.Popen[str]) -> dict[str, object]:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if path.exists():
            try:
                return json.loads(path.read_text())
            except json.JSONDecodeError:
                pass
        if receiver.poll() is not None:
            _, stderr = receiver.communicate()
            pytest.fail(f"receiver exited before readiness: {stderr}")
        time.sleep(0.02)
    receiver.terminate()
    _, stderr = receiver.communicate(timeout=5)
    pytest.fail(f"receiver did not become ready: {stderr}")


@pytest.mark.parametrize("mechanism_id", SUPPORTED_MECHANISMS)
def test_native_marquee_split_process_roundtrip(mechanism_id: str, tmp_path: Path):
    payload_path = tmp_path / "payload.bin"
    ready_path = tmp_path / "ready.json"
    receiver_path = tmp_path / "receiver.json"
    sender_path = tmp_path / "sender.json"
    payload_path.write_bytes(PAYLOAD)
    payload_hash = hashlib.sha256(PAYLOAD).hexdigest()
    expected_symbols = _expected_symbol_count(mechanism_id)

    receiver = subprocess.Popen(
        [
            sys.executable,
            str(RUNNER),
            "receiver",
            "--mechanism",
            mechanism_id,
            "--bind",
            "127.0.0.1",
            "--port",
            "0",
            "--expected-symbols",
            str(expected_symbols),
            "--expected-payload-len",
            str(len(PAYLOAD)),
            "--expected-payload-sha256",
            payload_hash,
            "--sender-node",
            "loopback-client",
            "--endpoint-node",
            "loopback-server",
            "--source-revision",
            "working-tree-test",
            "--topology-kind",
            "loopback_split_process",
            "--ready-file",
            str(ready_path),
            "--output",
            str(receiver_path),
        ],
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    ready = _wait_for_ready(ready_path, receiver)
    sender = subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "sender",
            "--mechanism",
            mechanism_id,
            "--host",
            "127.0.0.1",
            "--port",
            str(ready["port"]),
            "--payload-file",
            str(payload_path),
            "--receiver-node",
            "loopback-server",
            "--endpoint-node",
            "loopback-client",
            "--source-revision",
            "working-tree-test",
            "--topology-kind",
            "loopback_split_process",
            "--output",
            str(sender_path),
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    if sender.returncode != 0:
        receiver.terminate()
    _, receiver_stderr = receiver.communicate(timeout=20)

    assert sender.returncode == 0, sender.stderr
    assert receiver.returncode == 0, receiver_stderr
    sender_doc = json.loads(sender_path.read_text())
    receiver_doc = json.loads(receiver_path.read_text())
    assert sender_doc["ok"] is True
    assert sender_doc["topology_kind"] == "loopback_split_process"
    assert sender_doc["sender"]["node"] == "loopback-client"
    assert sender_doc["source_revision"] == "working-tree-test"
    assert sender_doc["carrier_surface"]
    assert sender_doc["implementation_scope"]
    assert sender_doc["carrier_units"] == expected_symbols
    assert sender_doc["responses_validated"] == expected_symbols
    assert sender_doc["response_validation_complete"] is True
    assert sender_doc["payload_sha256"] == payload_hash
    assert receiver_doc["ok"] is True
    assert receiver_doc["topology_kind"] == "loopback_split_process"
    assert receiver_doc["receiver"]["node"] == "loopback-server"
    assert receiver_doc["source_revision"] == "working-tree-test"
    assert receiver_doc["carrier_surface"] == sender_doc["carrier_surface"]
    assert receiver_doc["implementation_scope"] == sender_doc["implementation_scope"]
    assert receiver_doc["observed_symbols"] == expected_symbols
    assert receiver_doc["recovered_payload_sha256"] == payload_hash
    assert receiver_doc["exact_recovery"] is True
    assert PAYLOAD.hex() not in sender_path.read_text()
    assert PAYLOAD.hex() not in receiver_path.read_text()
