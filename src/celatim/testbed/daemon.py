"""Daemon lifecycle helpers for production-stack testbed scenarios."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from time import monotonic, sleep
from typing import Any, Protocol, Self

from celatim.errors import TransportError

from .commands import CommandResult, CommandRunner, SubprocessCommandRunner
from .tcpdump import ProcessHandle, ProcessRunner, SubprocessProcessRunner


@dataclass(frozen=True)
class DaemonReadinessResult:
    ok: bool
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "message": self.message,
            "details": dict(self.details),
        }


class ReadinessProbe(Protocol):
    def check(self) -> DaemonReadinessResult: ...


@dataclass(frozen=True)
class CommandReadinessProbe:
    argv: tuple[str, ...]
    expected_returncodes: tuple[int, ...] = (0,)
    runner: CommandRunner = field(default_factory=SubprocessCommandRunner)
    name: str = "command"

    def __post_init__(self) -> None:
        if not self.argv:
            raise ValueError("argv must be non-empty")
        if not self.expected_returncodes:
            raise ValueError("expected_returncodes must be non-empty")

    def check(self) -> DaemonReadinessResult:
        result = self.runner.run(self.argv, check=False)
        ok = result.returncode in self.expected_returncodes
        return DaemonReadinessResult(
            ok=ok,
            message=f"{self.name} readiness {'passed' if ok else 'failed'}",
            details=_command_result_json(result),
        )


@dataclass(frozen=True)
class ManagedDaemonConfig:
    argv: tuple[str, ...]
    name: str = "daemon"
    ready_timeout_s: float = 5.0
    ready_interval_s: float = 0.1
    stop_timeout_s: float = 2.0

    def __post_init__(self) -> None:
        if not self.argv:
            raise ValueError("argv must be non-empty")
        if not self.name:
            raise ValueError("name must be non-empty")
        if self.ready_timeout_s <= 0:
            raise ValueError("ready_timeout_s must be > 0")
        if self.ready_interval_s < 0:
            raise ValueError("ready_interval_s must be >= 0")
        if self.stop_timeout_s <= 0:
            raise ValueError("stop_timeout_s must be > 0")


class ManagedDaemon:
    """Context manager for a long-running daemon with optional readiness probing."""

    def __init__(
        self,
        config: ManagedDaemonConfig,
        runner: ProcessRunner | None = None,
        readiness_probe: ReadinessProbe | None = None,
    ) -> None:
        self.config = config
        self.runner = runner or SubprocessProcessRunner()
        self.readiness_probe = readiness_probe
        self._process: ProcessHandle | None = None
        self.readiness_result: DaemonReadinessResult | None = None

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.stop()

    @property
    def process(self) -> ProcessHandle | None:
        return self._process

    @property
    def argv(self) -> tuple[str, ...]:
        return self.config.argv

    def start(self) -> None:
        if self._process is not None:
            raise TransportError(f"{self.config.name} already started")
        self._process = self.runner.start(self.config.argv)
        if self.readiness_probe is None:
            self.readiness_result = DaemonReadinessResult(
                ok=True,
                message="no readiness probe configured",
                details={"daemon": self.config.name},
            )
            return
        self.readiness_result = self.wait_ready()

    def wait_ready(self) -> DaemonReadinessResult:
        process = self._process
        if process is None:
            raise TransportError(f"{self.config.name} is not started")

        deadline = monotonic() + self.config.ready_timeout_s
        attempts = 0
        last_result: DaemonReadinessResult | None = None
        while True:
            returncode = process.poll()
            if returncode is not None:
                raise TransportError(
                    f"{self.config.name} exited before readiness check passed rc={returncode}"
                )

            attempts += 1
            result = self._readiness_check(attempts)
            last_result = result
            if result.ok:
                return result

            if monotonic() >= deadline:
                self.stop()
                raise TransportError(
                    f"{self.config.name} did not become ready after {attempts} attempts"
                    + (
                        f": {last_result.message}"
                        if last_result is not None and last_result.message
                        else ""
                    )
                )
            if self.config.ready_interval_s:
                sleep(self.config.ready_interval_s)

    def stop(self) -> None:
        process = self._process
        if process is None:
            return
        try:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=self.config.stop_timeout_s)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=self.config.stop_timeout_s)
        finally:
            self._process = None

    def _readiness_check(self, attempts: int) -> DaemonReadinessResult:
        if self.readiness_probe is None:
            return DaemonReadinessResult(
                ok=True,
                message="no readiness probe configured",
                details={"daemon": self.config.name, "attempts": attempts},
            )
        result = self.readiness_probe.check()
        details = dict(result.details)
        details.setdefault("attempts", attempts)
        details.setdefault("daemon", self.config.name)
        return DaemonReadinessResult(result.ok, result.message, details)


@dataclass(frozen=True)
class DnsmasqResolverConfig:
    namespace: str
    listen_address: str
    answer_name: str
    answer_address: str
    port: int = 53
    ip_binary: str = "ip"
    dnsmasq_binary: str = "dnsmasq"

    def __post_init__(self) -> None:
        if not self.namespace:
            raise ValueError("namespace must be non-empty")
        if not self.listen_address:
            raise ValueError("listen_address must be non-empty")
        if not self.answer_name:
            raise ValueError("answer_name must be non-empty")
        if not self.answer_address:
            raise ValueError("answer_address must be non-empty")
        if self.port <= 0:
            raise ValueError("port must be > 0")

    @property
    def argv(self) -> tuple[str, ...]:
        return (
            self.ip_binary,
            "netns",
            "exec",
            self.namespace,
            self.dnsmasq_binary,
            "-d",
            "--conf-file=/dev/null",
            "--no-resolv",
            "--no-hosts",
            "--bind-interfaces",
            f"--listen-address={self.listen_address}",
            f"--address=/{self.answer_name}/{self.answer_address}",
            f"--port={self.port}",
        )


@dataclass(frozen=True)
class DigQueryConfig:
    namespace: str
    server_address: str
    query_name: str
    port: int = 53
    timeout_s: float = 2.0
    tries: int = 1
    padding_optcode: int = 12
    ip_binary: str = "ip"
    dig_binary: str = "dig"

    def __post_init__(self) -> None:
        if not self.namespace:
            raise ValueError("namespace must be non-empty")
        if not self.server_address:
            raise ValueError("server_address must be non-empty")
        if not self.query_name:
            raise ValueError("query_name must be non-empty")
        if self.port <= 0:
            raise ValueError("port must be > 0")
        if self.timeout_s <= 0:
            raise ValueError("timeout_s must be > 0")
        if self.tries <= 0:
            raise ValueError("tries must be > 0")
        if self.padding_optcode <= 0:
            raise ValueError("padding_optcode must be > 0")

    def argv(self, padding_hex: str | None = None) -> tuple[str, ...]:
        command = [
            self.ip_binary,
            "netns",
            "exec",
            self.namespace,
            self.dig_binary,
            f"@{self.server_address}",
            "-p",
            str(self.port),
            self.query_name,
            f"+timeout={self.timeout_s:g}",
            f"+tries={self.tries}",
            "+short",
        ]
        if padding_hex is None:
            command.append("+edns=0")
        else:
            command.append(f"+ednsopt={self.padding_optcode}:{padding_hex}")
        return tuple(command)


def _command_result_json(result: CommandResult) -> dict[str, Any]:
    return {
        "argv": list(result.argv),
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


__all__ = [
    "CommandReadinessProbe",
    "DaemonReadinessResult",
    "DigQueryConfig",
    "DnsmasqResolverConfig",
    "ManagedDaemon",
    "ManagedDaemonConfig",
    "ReadinessProbe",
]
