"""Reusable netns topology helpers."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import pytest

from celatim.testbed import CommandError, CommandResult, NetnsPair, NetnsPairConfig


@dataclass
class RecordingRunner:
    fail_on: tuple[str, ...] | None = None
    calls: list[tuple[tuple[str, ...], bool]] | None = None

    def run(self, argv: Sequence[str], *, check: bool = True) -> CommandResult:
        if self.calls is None:
            self.calls = []
        command = tuple(argv)
        self.calls.append((command, check))
        result = CommandResult(argv=command, returncode=1 if command == self.fail_on else 0)
        if check and result.returncode:
            raise CommandError(result)
        return result


def test_netns_pair_builds_privileged_topology_commands():
    config = NetnsPairConfig(
        sender_ns="s",
        receiver_ns="r",
        sender_iface="left",
        receiver_iface="right",
        sender_ipv4_cidr="192.0.2.1/24",
        receiver_ipv4_cidr="192.0.2.2/24",
        mtu=9000,
    )
    pair = NetnsPair(config, RecordingRunner())

    commands = pair.up_commands()

    assert commands[0] == (("ip", "netns", "add", "s"), True)
    assert commands[1] == (("ip", "netns", "add", "r"), True)
    assert " ".join(commands[2][0]) == "ip link add left type veth peer name right"
    assert ("ip", "-n", "s", "addr", "add", "192.0.2.1/24", "dev", "left") in [
        command for command, _check in commands
    ]
    assert ("ip", "-n", "r", "link", "set", "dev", "right", "up", "mtu", "9000") in [
        command for command, _check in commands
    ]
    assert commands[-2] == (
        (
            "ip",
            "netns",
            "exec",
            "s",
            "ethtool",
            "-K",
            "left",
            "tso",
            "off",
            "gso",
            "off",
            "gro",
            "off",
            "lro",
            "off",
            "tx",
            "off",
            "rx",
            "off",
        ),
        False,
    )


def test_netns_pair_context_cleans_up_even_when_body_raises():
    runner = RecordingRunner()

    with pytest.raises(RuntimeError, match="boom"), NetnsPair(runner=runner):
        raise RuntimeError("boom")

    calls = runner.calls or []
    assert calls[0] == (("ip", "netns", "del", "snd"), False)
    assert calls[1] == (("ip", "netns", "del", "rcv"), False)
    assert calls[-2] == (("ip", "netns", "del", "snd"), False)
    assert calls[-1] == (("ip", "netns", "del", "rcv"), False)


def test_netns_pair_exec_wraps_command_in_namespace():
    runner = RecordingRunner()
    pair = NetnsPair(runner=runner)

    result = pair.exec("snd", ["python", "-m", "celatim.experiment"], check=False)

    assert result.argv == (
        "ip",
        "netns",
        "exec",
        "snd",
        "python",
        "-m",
        "celatim.experiment",
    )
    assert runner.calls == [(result.argv, False)]


def test_netns_pair_propagates_checked_command_failures():
    runner = RecordingRunner(fail_on=("ip", "netns", "add", "snd"))
    pair = NetnsPair(runner=runner)

    with pytest.raises(CommandError, match="command failed"):
        pair.up()


def test_netns_pair_rejects_invalid_mtu():
    with pytest.raises(ValueError, match="mtu"):
        NetnsPairConfig(mtu=0)
