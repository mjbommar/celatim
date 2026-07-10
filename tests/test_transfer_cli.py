"""Product transfer CLI commands share the typed SDK implementation."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from celatim.cli import main
from celatim.transfer import TransferOffer


def _offer() -> TransferOffer:
    return TransferOffer.create(
        host="127.0.0.1",
        port=8443,
        tls_cert_sha256="a" * 64,
        providers=("tcp-tls",),
        max_file_size=1024,
    )


def test_transfer_cli_lists_typed_provider_manifest(capsys):
    assert main(["transfer", "providers", "--format", "json"]) == 0

    document = json.loads(capsys.readouterr().out)
    assert document["schema_version"] == "celatim.provider_inventory.v1"
    assert document["providers"][0]["name"] == "tcp-tls"
    assert document["providers"][0]["resumable"] is True
    assert document["providers"][0]["evidence_level"] == "direct_tls_control"


def test_transfer_cli_inspects_offer_without_disclosing_access_token(capsys):
    offer = _offer()

    assert (
        main(
            [
                "transfer",
                "inspect-offer",
                "--offer",
                offer.to_uri(),
                "--format",
                "json",
            ]
        )
        == 0
    )

    output = capsys.readouterr().out
    document = json.loads(output)
    assert document["access_token"] == "[redacted]"
    assert offer.access_token not in output


def test_transfer_cli_status_is_machine_readable_for_empty_home(tmp_path, capsys):
    assert (
        main(
            [
                "transfer",
                "status",
                "--home",
                str(tmp_path / "home"),
                "--format",
                "json",
            ]
        )
        == 0
    )

    document = json.loads(capsys.readouterr().out)
    assert document == {
        "schema_version": "celatim.transfer_status.v1",
        "listener": None,
        "transfer_count": 0,
        "transfers": [],
    }


def test_transfer_cli_two_process_file_exchange(tmp_path):
    executable = Path(sys.executable).with_name("celatim")
    source = tmp_path / "alice" / "report.bin"
    source.parent.mkdir()
    payload = b"\x00\xffcli transfer" * 1000
    source.write_bytes(payload)
    receiver = subprocess.Popen(
        [
            str(executable),
            "transfer",
            "listen",
            "--output-dir",
            str(tmp_path / "bob" / "received"),
            "--home",
            str(tmp_path / "bob" / "home"),
            "--idle-timeout-s",
            "10",
            "--format",
            "jsonl",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert receiver.stdout is not None
    ready_line = receiver.stdout.readline()
    ready = json.loads(ready_line)
    sender = subprocess.run(
        [
            str(executable),
            "transfer",
            "send",
            str(source),
            "--to",
            ready["offer_uri"],
            "--home",
            str(tmp_path / "alice" / "home"),
            "--format",
            "json",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    remaining_stdout, receiver_stderr = receiver.communicate(timeout=15)

    assert sender.returncode == 0, sender.stderr
    assert receiver.returncode == 0, receiver_stderr
    sender_receipt = json.loads(sender.stdout)
    receiver_event = json.loads(remaining_stdout)
    assert sender_receipt["authenticated"] is True
    assert sender_receipt["acknowledged"] is True
    assert receiver_event["event"] == "completed"
    assert (tmp_path / "bob" / "received" / "report.bin").read_bytes() == payload
    assert payload.hex() not in sender.stdout


def test_transfer_cli_generates_packet_service_unit(capsys, tmp_path):
    assert (
        main(
            [
                "transfer",
                "packet-service",
                "unit",
                "--socket",
                str(tmp_path / "packet.sock"),
                "--allow-provider",
                "afpacket-ipv4",
                "--allow-interface",
                "eth0",
                "--allow-uid",
                "1000",
                "--user",
                "celatim-packet",
                "--executable",
                "/usr/bin/celatim",
            ]
        )
        == 0
    )

    unit = capsys.readouterr().out
    assert "ExecStart=/usr/bin/celatim transfer packet-service serve" in unit
    assert "AmbientCapabilities=CAP_NET_RAW" in unit


def test_transfer_cli_status_and_stop_manage_registered_listener(tmp_path):
    executable = Path(sys.executable).with_name("celatim")
    home = tmp_path / "home"
    receiver = subprocess.Popen(
        [
            str(executable),
            "transfer",
            "listen",
            "--output-dir",
            str(tmp_path / "received"),
            "--home",
            str(home),
            "--idle-timeout-s",
            "30",
            "--format",
            "jsonl",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert receiver.stdout is not None
    json.loads(receiver.stdout.readline())
    status = subprocess.run(
        [
            str(executable),
            "transfer",
            "status",
            "--home",
            str(home),
            "--format",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    stopped = subprocess.run(
        [
            str(executable),
            "transfer",
            "stop",
            "--home",
            str(home),
            "--format",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    receiver.wait(timeout=5)

    status_document = json.loads(status.stdout)
    stop_document = json.loads(stopped.stdout)
    assert status_document["listener"]["active"] is True
    assert status_document["listener"]["output_dir"] is None
    assert stop_document["pid"] == receiver.pid
    assert stop_document["stopped"] is True
    assert receiver.returncode == -15
