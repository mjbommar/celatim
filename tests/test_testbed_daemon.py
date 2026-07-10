"""Daemon lifecycle helpers for production-stack scenarios."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence

import pytest

from celatim.errors import TransportError
from celatim.testbed import (
    CommandReadinessProbe,
    CommandResult,
    DaemonReadinessResult,
    DigQueryConfig,
    DnsmasqResolverConfig,
    ManagedDaemon,
    ManagedDaemonConfig,
)


class FakeProcess:
    def __init__(self, returncode: int | None = None, wait_timeout: bool = False) -> None:
        self.returncode = returncode
        self.wait_timeout = wait_timeout
        self.terminated = False
        self.killed = False
        self.waits = 0

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout: float | None = None) -> int:
        self.waits += 1
        if self.wait_timeout and self.waits == 1:
            raise subprocess.TimeoutExpired("daemon", 0.0 if timeout is None else timeout)
        self.returncode = -9 if self.killed else 0
        return self.returncode

    def kill(self) -> None:
        self.killed = True


class FakeProcessRunner:
    def __init__(self, process: FakeProcess) -> None:
        self.process = process
        self.started: list[tuple[str, ...]] = []

    def start(self, argv: Sequence[str]) -> FakeProcess:
        self.started.append(tuple(argv))
        return self.process


class CountingProbe:
    def __init__(self, ready_on: int) -> None:
        self.ready_on = ready_on
        self.attempts = 0

    def check(self) -> DaemonReadinessResult:
        self.attempts += 1
        return DaemonReadinessResult(
            self.attempts >= self.ready_on,
            f"attempt {self.attempts}",
            {"probe_attempt": self.attempts},
        )


class FakeCommandRunner:
    def __init__(self, returncodes: tuple[int, ...]) -> None:
        self.returncodes = list(returncodes)
        self.argv: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str], *, check: bool = True) -> CommandResult:
        self.argv.append(tuple(argv))
        return CommandResult(
            argv=tuple(argv),
            returncode=self.returncodes.pop(0),
            stdout="ok\n",
            stderr="",
        )


def test_managed_daemon_waits_for_readiness_and_stops():
    process = FakeProcess()
    runner = FakeProcessRunner(process)
    probe = CountingProbe(ready_on=3)
    daemon = ManagedDaemon(
        ManagedDaemonConfig(
            argv=("dnsmasq", "-d"),
            name="dnsmasq",
            ready_timeout_s=1.0,
            ready_interval_s=0.0,
        ),
        runner=runner,
        readiness_probe=probe,
    )

    with daemon:
        assert runner.started == [("dnsmasq", "-d")]
        assert daemon.readiness_result is not None
        assert daemon.readiness_result.ok is True
        assert daemon.readiness_result.details["attempts"] == 3
        assert process.terminated is False

    assert process.terminated is True
    assert process.killed is False


def test_managed_daemon_kills_after_stop_timeout():
    process = FakeProcess(wait_timeout=True)
    daemon = ManagedDaemon(
        ManagedDaemonConfig(argv=("server",), stop_timeout_s=0.1),
        runner=FakeProcessRunner(process),
    )
    daemon.start()
    daemon.stop()

    assert process.terminated is True
    assert process.killed is True


def test_managed_daemon_fails_if_process_exits_before_ready():
    process = FakeProcess(returncode=2)
    daemon = ManagedDaemon(
        ManagedDaemonConfig(argv=("server",), ready_interval_s=0.0),
        runner=FakeProcessRunner(process),
        readiness_probe=CountingProbe(ready_on=1),
    )

    with pytest.raises(TransportError, match="exited before readiness"):
        daemon.start()


def test_command_readiness_probe_reports_command_result():
    runner = FakeCommandRunner((1, 0))
    probe = CommandReadinessProbe(
        ("dig", "@10.10.0.2", "covert.test", "+short"),
        runner=runner,
        name="dig",
    )

    first = probe.check()
    second = probe.check()

    assert first.ok is False
    assert first.details["returncode"] == 1
    assert second.ok is True
    assert second.details["argv"] == ["dig", "@10.10.0.2", "covert.test", "+short"]
    assert runner.argv == [
        ("dig", "@10.10.0.2", "covert.test", "+short"),
        ("dig", "@10.10.0.2", "covert.test", "+short"),
    ]


def test_dnsmasq_resolver_config_builds_legacy_experiment_command():
    config = DnsmasqResolverConfig(
        namespace="rcv",
        listen_address="10.10.0.2",
        answer_name="covert.test",
        answer_address="10.10.0.2",
    )

    assert config.argv == (
        "ip",
        "netns",
        "exec",
        "rcv",
        "dnsmasq",
        "-d",
        "--conf-file=/dev/null",
        "--no-resolv",
        "--no-hosts",
        "--bind-interfaces",
        "--listen-address=10.10.0.2",
        "--address=/covert.test/10.10.0.2",
        "--port=53",
    )


def test_dig_query_config_builds_padding_and_control_commands():
    config = DigQueryConfig(
        namespace="snd",
        server_address="10.10.0.2",
        query_name="covert.test",
    )

    assert config.argv("00ff") == (
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
        "+ednsopt=12:00ff",
    )
    assert config.argv(None)[-1] == "+edns=0"
