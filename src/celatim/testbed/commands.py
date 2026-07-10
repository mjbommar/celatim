"""Command-runner primitives for privileged testbed adapters."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from celatim.errors import TransportError


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""


class CommandError(TransportError):
    """Raised when a testbed command fails with ``check=True``."""

    def __init__(self, result: CommandResult) -> None:
        self.result = result
        super().__init__(
            f"command failed rc={result.returncode}: {' '.join(result.argv)}"
            + (f"\nstderr: {result.stderr.strip()}" if result.stderr.strip() else "")
        )


class CommandRunner(Protocol):
    def run(self, argv: Sequence[str], *, check: bool = True) -> CommandResult: ...


class SubprocessCommandRunner:
    """Command runner used by live privileged scenarios."""

    def run(self, argv: Sequence[str], *, check: bool = True) -> CommandResult:
        completed = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            check=False,
        )
        result = CommandResult(
            argv=tuple(argv),
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
        if check and result.returncode != 0:
            raise CommandError(result)
        return result


__all__ = [
    "CommandError",
    "CommandResult",
    "CommandRunner",
    "SubprocessCommandRunner",
]
