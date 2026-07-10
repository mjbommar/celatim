"""DNS EDNS(0) daemon-path helpers."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from celatim.errors import TransportError
from celatim.session import ChannelSession, InMemoryTransport, MechanismProfile, PacingConfig
from celatim.testbed import (
    CommandResult,
    DnsEdnsPaddingPathConfig,
    edns_padding_options_from_pcap,
    receive_dns_edns0_padding,
    run_dns_edns0_padding_roundtrip,
    send_dns_edns0_padding,
)

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


@dataclass
class FakeProcess:
    returncode: int | None = None
    terminated: bool = False
    killed: bool = False

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout: float | None = None) -> int:
        self.returncode = 0
        return 0

    def kill(self) -> None:
        self.killed = True


@dataclass
class QueueProcessRunner:
    processes: list[FakeProcess]
    started: list[tuple[str, ...]] = field(default_factory=list)

    def start(self, argv: Sequence[str]) -> FakeProcess:
        self.started.append(tuple(argv))
        if not self.processes:
            raise AssertionError("no fake process left")
        return self.processes.pop(0)


@dataclass
class FakeCommandRunner:
    stdout: str = "10.10.0.2\n"
    argv: list[tuple[str, ...]] = field(default_factory=list)

    def run(self, argv: Sequence[str], *, check: bool = True) -> CommandResult:
        self.argv.append(tuple(argv))
        return CommandResult(tuple(argv), 0, stdout=self.stdout, stderr="")


def test_dns_edns_padding_roundtrip_uses_real_tool_commands_with_injected_runners(tmp_path):
    profile = MechanismProfile.from_catalog("edns0-padding", DATA)
    command_runner = FakeCommandRunner()
    process_runner = QueueProcessRunner([FakeProcess(), FakeProcess()])
    capture_pcap = tmp_path / "dns.pcap"

    def decoder(path: Path, optcode: int) -> tuple[bytes, ...]:
        assert path == capture_pcap
        assert optcode == 12
        return tuple(
            bytes.fromhex(argv[-1].split(":", 1)[1])
            for argv in command_runner.argv
            if argv[-1].startswith("+ednsopt=12:")
        )

    result = run_dns_edns0_padding_roundtrip(
        profile,
        b"\x00\xffdns",
        session_id="dns-live",
        config=DnsEdnsPaddingPathConfig(
            capture_pcap=capture_pcap,
            capture_start_delay_s=0.0,
            capture_require_output=False,
        ),
        pacing=PacingConfig(unit_rate_hz=20.0),
        command_runner=command_runner,
        process_runner=process_runner,
        pcap_decoder=decoder,
        sleeper=lambda _delay: None,
    )

    assert result.result.payload == b"\x00\xffdns"
    assert result.capture_pcap == capture_pcap
    assert len(result.symbols) == result.receipt.carrier_units
    assert process_runner.started[0][:5] == ("ip", "netns", "exec", "rcv", "dnsmasq")
    assert process_runner.started[1][:8] == (
        "ip",
        "netns",
        "exec",
        "rcv",
        "tcpdump",
        "-i",
        "vr",
        "-U",
    )
    assert process_runner.started[1][-7:] == (
        "udp",
        "port",
        "53",
        "and",
        "src",
        "host",
        "10.10.0.1",
    )
    assert command_runner.argv[0] == ("dnsmasq", "--version")
    assert command_runner.argv[1] == ("dig", "-v")
    assert command_runner.argv[2][-1] == "+edns=0"
    assert all(argv[-1].startswith("+ednsopt=12:") for argv in command_runner.argv[3:])
    assert result.daemon_readiness is not None
    assert result.daemon_readiness["ok"] is True
    assert [record.tool for record in result.tool_versions] == ["dnsmasq", "dig"]
    assert result.tool_versions[0].argv == ("dnsmasq", "--version")
    assert result.tool_versions[0].returncode == 0
    assert result.tool_versions[0].stdout_sha256 is not None
    assert result.result.evidence.endpoint_os.topology_kind == "same_kernel_netns"
    assert result.result.evidence.endpoint_os.sender.namespace == "snd"
    assert result.result.evidence.endpoint_os.receiver.namespace == "rcv"
    assert result.result.evidence.endpoint_os.independent_receiver_os is False


def test_dns_edns_padding_empty_payload_emits_no_padding_control_query(tmp_path):
    profile = MechanismProfile.from_catalog("edns0-padding", DATA)
    command_runner = FakeCommandRunner()
    process_runner = QueueProcessRunner([FakeProcess(), FakeProcess()])

    result = run_dns_edns0_padding_roundtrip(
        profile,
        b"",
        session_id="dns-control",
        config=DnsEdnsPaddingPathConfig(
            capture_pcap=tmp_path / "control.pcap",
            capture_start_delay_s=0.0,
            capture_require_output=False,
        ),
        command_runner=command_runner,
        process_runner=process_runner,
        pcap_decoder=lambda _path, _optcode: (),
        sleeper=lambda _delay: None,
    )

    assert result.result.payload == b""
    assert result.result.evidence.carrier_units == 0
    assert result.symbols == ()
    assert command_runner.argv == [
        ("dnsmasq", "--version"),
        ("dig", "-v"),
        (
            "ip",
            "netns",
            "exec",
            "snd",
            "dig",
            "@10.10.0.2",
            "-p",
            "53",
            "covert.test",
            "+timeout=2",
            "+tries=1",
            "+short",
            "+edns=0",
        ),
        (
            "ip",
            "netns",
            "exec",
            "snd",
            "dig",
            "@10.10.0.2",
            "-p",
            "53",
            "covert.test",
            "+timeout=2",
            "+tries=1",
            "+short",
            "+edns=0",
        ),
    ]


def test_dns_edns_padding_split_send_emits_dig_queries_without_daemon(tmp_path):
    profile = MechanismProfile.from_catalog("edns0-padding", DATA)
    command_runner = FakeCommandRunner()

    result = send_dns_edns0_padding(
        profile,
        b"\x00\xffdns",
        session_id="dns-split",
        config=DnsEdnsPaddingPathConfig(
            capture_pcap=tmp_path / "unused.pcap",
            capture_start_delay_s=0.0,
        ),
        pacing=PacingConfig(unit_rate_hz=20.0),
        command_runner=command_runner,
        sleeper=lambda _delay: None,
    )

    assert result.receipt.session_id == "dns-split"
    assert result.receipt.carrier_units == len(result.symbols)
    assert result.answers == ("10.10.0.2",) * len(result.symbols)
    assert command_runner.argv[0] == ("dnsmasq", "--version")
    assert command_runner.argv[1] == ("dig", "-v")
    assert all(argv[-1].startswith("+ednsopt=12:") for argv in command_runner.argv[2:])


def test_dns_edns_padding_split_receive_waits_for_capture_and_decodes(tmp_path):
    profile = MechanismProfile.from_catalog("edns0-padding", DATA)
    command_runner = FakeCommandRunner()
    process_runner = QueueProcessRunner([FakeProcess(), FakeProcess()])
    memory_transport = InMemoryTransport()
    receipt = ChannelSession(profile, memory_transport).send_message(
        b"\x00\xffdns",
        session_id="dns-split",
    )
    expected_symbols = tuple(memory_transport.receive_symbols(receipt.session_id))
    capture_pcap = tmp_path / "dns-split.pcap"

    def decoder(path: Path, optcode: int) -> tuple[bytes, ...]:
        assert path == capture_pcap
        assert optcode == 12
        return tuple(bytes(symbol) for symbol in expected_symbols)

    result = receive_dns_edns0_padding(
        profile,
        "dns-split",
        expected_queries=len(expected_symbols),
        config=DnsEdnsPaddingPathConfig(
            capture_pcap=capture_pcap,
            capture_start_delay_s=0.0,
            capture_require_output=False,
        ),
        command_runner=command_runner,
        process_runner=process_runner,
        pcap_decoder=decoder,
        sleeper=lambda _delay: None,
    )

    assert result.result.payload == b"\x00\xffdns"
    assert result.symbols == expected_symbols
    assert result.capture_pcap == capture_pcap
    assert process_runner.started[0][:5] == ("ip", "netns", "exec", "rcv", "dnsmasq")
    assert process_runner.started[1][:8] == (
        "ip",
        "netns",
        "exec",
        "rcv",
        "tcpdump",
        "-i",
        "vr",
        "-U",
    )
    assert process_runner.started[1][-7:] == (
        "udp",
        "port",
        "53",
        "and",
        "src",
        "host",
        "10.10.0.1",
    )
    assert command_runner.argv[0] == ("dnsmasq", "--version")
    assert command_runner.argv[1] == ("dig", "-v")
    assert command_runner.argv[2][-1] == "+edns=0"
    assert result.daemon_readiness is not None
    assert result.daemon_readiness["ok"] is True
    assert [record.tool for record in result.tool_versions] == ["dnsmasq", "dig"]


def test_dns_edns_padding_rejects_wrong_mechanism(tmp_path):
    profile = MechanismProfile.from_catalog("http2-ping-opaque", DATA)

    with pytest.raises(TransportError, match="only supports edns0-padding"):
        run_dns_edns0_padding_roundtrip(
            profile,
            b"payload",
            config=DnsEdnsPaddingPathConfig(capture_pcap=tmp_path / "x.pcap"),
        )


def test_edns_padding_pcap_decoder_reports_missing_packet_extra(monkeypatch, tmp_path):
    def fail_import(name: str):
        if name == "scapy.all":
            raise ImportError("missing")
        raise AssertionError(name)

    monkeypatch.setattr("importlib.import_module", fail_import)

    with pytest.raises(TransportError, match="packet extra"):
        edns_padding_options_from_pcap(tmp_path / "missing.pcap")
