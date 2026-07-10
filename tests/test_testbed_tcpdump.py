"""tcpdump capture context helper."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import pytest

from celatim.errors import TransportError
from celatim.testbed.tcpdump import TcpdumpCapture, TcpdumpCaptureConfig


@dataclass
class FakeProcess:
    returncode: int | None = None
    terminated: bool = False
    killed: bool = False
    waits: int = 0
    time_out_once: bool = False

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout: float | None = None) -> int:
        self.waits += 1
        if self.time_out_once and self.waits == 1:
            import subprocess

            raise subprocess.TimeoutExpired("tcpdump", timeout or 0.0)
        self.returncode = 0
        return 0

    def kill(self) -> None:
        self.killed = True


@dataclass
class FakeProcessRunner:
    process: FakeProcess
    argv: tuple[str, ...] | None = None

    def start(self, argv: Sequence[str]) -> FakeProcess:
        self.argv = tuple(argv)
        return self.process


def test_tcpdump_capture_builds_netns_command(tmp_path):
    output = tmp_path / "cap.pcap"
    capture = TcpdumpCapture(
        TcpdumpCaptureConfig(
            namespace="rcv",
            interface="vr",
            output=output,
            packet_count=4,
            filter_expr=("tcp", "port", "443"),
        ),
        FakeProcessRunner(FakeProcess(returncode=0)),
    )

    assert capture.argv == (
        "ip",
        "netns",
        "exec",
        "rcv",
        "tcpdump",
        "-i",
        "vr",
        "-U",
        "-s",
        "65535",
        "-w",
        str(output),
        "-c",
        "4",
        "tcp",
        "port",
        "443",
    )


def test_tcpdump_capture_context_starts_and_stops_process(tmp_path):
    output = tmp_path / "cap.pcap"
    process = FakeProcess()
    runner = FakeProcessRunner(process)
    capture = TcpdumpCapture(
        TcpdumpCaptureConfig(namespace="rcv", interface="vr", output=output),
        runner,
    )

    with capture:
        assert runner.argv == capture.argv
        output.write_bytes(b"pcap")

    assert process.terminated is True
    assert process.waits == 1
    assert process.killed is False


def test_tcpdump_capture_kills_process_after_stop_timeout(tmp_path):
    output = tmp_path / "cap.pcap"
    output.write_bytes(b"pcap")
    process = FakeProcess(time_out_once=True)

    capture = TcpdumpCapture(
        TcpdumpCaptureConfig(namespace="rcv", interface="vr", output=output),
        FakeProcessRunner(process),
    )
    capture.start()
    capture.stop()

    assert process.terminated is True
    assert process.killed is True
    assert process.waits == 2


def test_tcpdump_capture_requires_output_by_default(tmp_path):
    capture = TcpdumpCapture(
        TcpdumpCaptureConfig(namespace="rcv", interface="vr", output=tmp_path / "missing.pcap"),
        FakeProcessRunner(FakeProcess(returncode=0)),
    )

    capture.start()
    with pytest.raises(TransportError, match="did not create pcap"):
        capture.stop()


def test_tcpdump_capture_can_skip_output_check(tmp_path):
    capture = TcpdumpCapture(
        TcpdumpCaptureConfig(
            namespace="rcv",
            interface="vr",
            output=tmp_path / "missing.pcap",
            require_output=False,
        ),
        FakeProcessRunner(FakeProcess(returncode=0)),
    )

    capture.start()
    capture.stop()


def test_tcpdump_capture_rejects_invalid_config(tmp_path):
    with pytest.raises(ValueError, match="namespace"):
        TcpdumpCaptureConfig(namespace="", interface="vr", output=tmp_path / "x.pcap")
    with pytest.raises(ValueError, match="packet_count"):
        TcpdumpCaptureConfig(
            namespace="rcv", interface="vr", output=tmp_path / "x.pcap", packet_count=0
        )
