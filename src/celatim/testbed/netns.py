"""Linux network namespace topology helpers."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Self

from .commands import CommandResult, CommandRunner, SubprocessCommandRunner


@dataclass(frozen=True)
class NetnsPairConfig:
    sender_ns: str = "snd"
    receiver_ns: str = "rcv"
    sender_iface: str = "vs"
    receiver_iface: str = "vr"
    sender_ipv4_cidr: str = "10.10.0.1/24"
    receiver_ipv4_cidr: str = "10.10.0.2/24"
    mtu: int = 16000
    ip_binary: str = "ip"
    ethtool_binary: str = "ethtool"
    disable_offloads: bool = True
    cleanup_existing: bool = True

    def __post_init__(self) -> None:
        if self.mtu <= 0:
            raise ValueError("mtu must be > 0")


class NetnsPair:
    """Context manager for the snd<->rcv veth topology used by live scenarios."""

    def __init__(
        self,
        config: NetnsPairConfig | None = None,
        runner: CommandRunner | None = None,
    ) -> None:
        self.config = config or NetnsPairConfig()
        self.runner = runner or SubprocessCommandRunner()
        self._up = False

    def __enter__(self) -> Self:
        self.up()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.down()

    def up(self) -> None:
        cfg = self.config
        if cfg.cleanup_existing:
            self.down()
        for argv, check in self.up_commands():
            self.runner.run(argv, check=check)
        self._up = True

    def down(self) -> None:
        for argv, check in self.down_commands():
            self.runner.run(argv, check=check)
        self._up = False

    def exec(self, namespace: str, argv: Sequence[str], *, check: bool = True) -> CommandResult:
        return self.runner.run(
            [self.config.ip_binary, "netns", "exec", namespace, *argv],
            check=check,
        )

    def up_commands(self) -> tuple[tuple[tuple[str, ...], bool], ...]:
        cfg = self.config
        commands: list[tuple[tuple[str, ...], bool]] = [
            ((cfg.ip_binary, "netns", "add", cfg.sender_ns), True),
            ((cfg.ip_binary, "netns", "add", cfg.receiver_ns), True),
            (
                (
                    cfg.ip_binary,
                    "link",
                    "add",
                    cfg.sender_iface,
                    "type",
                    "veth",
                    "peer",
                    "name",
                    cfg.receiver_iface,
                ),
                True,
            ),
            ((cfg.ip_binary, "link", "set", cfg.sender_iface, "netns", cfg.sender_ns), True),
            ((cfg.ip_binary, "link", "set", cfg.receiver_iface, "netns", cfg.receiver_ns), True),
            (
                (
                    cfg.ip_binary,
                    "-n",
                    cfg.sender_ns,
                    "addr",
                    "add",
                    cfg.sender_ipv4_cidr,
                    "dev",
                    cfg.sender_iface,
                ),
                True,
            ),
            (
                (
                    cfg.ip_binary,
                    "-n",
                    cfg.receiver_ns,
                    "addr",
                    "add",
                    cfg.receiver_ipv4_cidr,
                    "dev",
                    cfg.receiver_iface,
                ),
                True,
            ),
            (
                (
                    cfg.ip_binary,
                    "-n",
                    cfg.sender_ns,
                    "link",
                    "set",
                    "dev",
                    cfg.sender_iface,
                    "up",
                    "mtu",
                    str(cfg.mtu),
                ),
                True,
            ),
            (
                (
                    cfg.ip_binary,
                    "-n",
                    cfg.receiver_ns,
                    "link",
                    "set",
                    "dev",
                    cfg.receiver_iface,
                    "up",
                    "mtu",
                    str(cfg.mtu),
                ),
                True,
            ),
            ((cfg.ip_binary, "-n", cfg.sender_ns, "link", "set", "dev", "lo", "up"), True),
            ((cfg.ip_binary, "-n", cfg.receiver_ns, "link", "set", "dev", "lo", "up"), True),
        ]
        if cfg.disable_offloads:
            commands.extend(
                [
                    (_offload_command(cfg, cfg.sender_ns, cfg.sender_iface), False),
                    (_offload_command(cfg, cfg.receiver_ns, cfg.receiver_iface), False),
                ]
            )
        return tuple(commands)

    def down_commands(self) -> tuple[tuple[tuple[str, ...], bool], ...]:
        cfg = self.config
        return (
            ((cfg.ip_binary, "netns", "del", cfg.sender_ns), False),
            ((cfg.ip_binary, "netns", "del", cfg.receiver_ns), False),
        )


def _offload_command(config: NetnsPairConfig, namespace: str, iface: str) -> tuple[str, ...]:
    return (
        config.ip_binary,
        "netns",
        "exec",
        namespace,
        config.ethtool_binary,
        "-K",
        iface,
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
    )


__all__ = [
    "NetnsPair",
    "NetnsPairConfig",
]
