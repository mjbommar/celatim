"""tcpdump capture helpers for live pcap taps."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Self

from celatim.errors import TransportError


class ProcessHandle(Protocol):
    def poll(self) -> int | None: ...

    def terminate(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def kill(self) -> None: ...


class ProcessRunner(Protocol):
    def start(self, argv: Sequence[str]) -> ProcessHandle: ...


class SubprocessProcessRunner:
    """Process runner used by live capture contexts."""

    def start(self, argv: Sequence[str]) -> ProcessHandle:
        return subprocess.Popen(list(argv))


@dataclass(frozen=True)
class TcpdumpCaptureConfig:
    namespace: str
    interface: str
    output: Path
    packet_count: int | None = None
    filter_expr: tuple[str, ...] = ()
    snaplen: int = 65535
    ip_binary: str = "ip"
    tcpdump_binary: str = "tcpdump"
    stop_timeout_s: float = 2.0
    require_output: bool = True

    def __post_init__(self) -> None:
        if not self.namespace:
            raise ValueError("namespace must be non-empty")
        if not self.interface:
            raise ValueError("interface must be non-empty")
        if self.packet_count is not None and self.packet_count <= 0:
            raise ValueError("packet_count must be > 0")
        if self.snaplen <= 0:
            raise ValueError("snaplen must be > 0")
        if self.stop_timeout_s <= 0:
            raise ValueError("stop_timeout_s must be > 0")


class TcpdumpCapture:
    """Context manager for `ip netns exec <ns> tcpdump ... -w <pcap>`."""

    def __init__(
        self,
        config: TcpdumpCaptureConfig,
        runner: ProcessRunner | None = None,
    ) -> None:
        self.config = config
        self.runner = runner or SubprocessProcessRunner()
        self._process: ProcessHandle | None = None

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.stop()

    @property
    def argv(self) -> tuple[str, ...]:
        cfg = self.config
        command: list[str] = [
            cfg.ip_binary,
            "netns",
            "exec",
            cfg.namespace,
            cfg.tcpdump_binary,
            "-i",
            cfg.interface,
            "-U",
            "-s",
            str(cfg.snaplen),
            "-w",
            str(cfg.output),
        ]
        if cfg.packet_count is not None:
            command.extend(["-c", str(cfg.packet_count)])
        command.extend(cfg.filter_expr)
        return tuple(command)

    def start(self) -> None:
        if self._process is not None:
            raise TransportError("tcpdump capture already started")
        self.config.output.parent.mkdir(parents=True, exist_ok=True)
        self._process = self.runner.start(self.argv)

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
        if self.config.require_output and not self.config.output.exists():
            raise TransportError(f"tcpdump did not create pcap: {self.config.output}")

    def wait(self, timeout: float | None = None) -> int:
        """Wait for tcpdump to exit, usually after ``-c`` captured enough packets."""

        process = self._process
        if process is None:
            raise TransportError("tcpdump capture is not started")
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise TransportError("tcpdump capture did not finish before timeout") from exc


__all__ = [
    "ProcessHandle",
    "ProcessRunner",
    "SubprocessProcessRunner",
    "TcpdumpCapture",
    "TcpdumpCaptureConfig",
]
