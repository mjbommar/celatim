"""QEMU/KVM TAP topology helpers for cross-stack scenarios."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from time import time
from typing import Any, Self

from celatim.errors import TransportError

from .commands import CommandRunner, SubprocessCommandRunner
from .tcpdump import ProcessHandle, ProcessRunner, SubprocessProcessRunner

QEMU_TAP_PREFLIGHT_SCHEMA_VERSION = "celatim.qemu_tap_preflight.v1"
QEMU_TAP_PREFLIGHT_CLAIM_STATUS = "preflight_only_no_vm_started"


@dataclass(frozen=True)
class HostTapConfig:
    tap_name: str = "rfctap0"
    host_ipv4_cidr: str | None = "10.77.0.1/24"
    mtu: int = 1500
    ip_binary: str = "ip"
    owner: str | None = None
    group: str | None = None
    cleanup_existing: bool = True

    def __post_init__(self) -> None:
        if not self.tap_name:
            raise ValueError("tap_name must be non-empty")
        if self.mtu <= 0:
            raise ValueError("mtu must be > 0")
        if not self.ip_binary:
            raise ValueError("ip_binary must be non-empty")


@dataclass(frozen=True)
class QemuGuestConfig:
    disk_image: Path | str
    qemu_binary: str = "qemu-system-x86_64"
    memory_mib: int = 1024
    smp: int = 1
    mac_address: str = "52:54:00:72:63:74"
    netdev_id: str = "net0"
    network_device: str = "virtio-net-pci"
    drive_interface: str = "virtio"
    disk_format: str | None = "qcow2"
    enable_kvm: bool = True
    snapshot: bool = True
    display: str | None = "none"
    machine: str | None = None
    cpu: str | None = None
    extra_args: tuple[str, ...] = ()
    stop_timeout_s: float = 5.0

    def __post_init__(self) -> None:
        if not str(self.disk_image):
            raise ValueError("disk_image must be non-empty")
        if not self.qemu_binary:
            raise ValueError("qemu_binary must be non-empty")
        if self.memory_mib <= 0:
            raise ValueError("memory_mib must be > 0")
        if self.smp <= 0:
            raise ValueError("smp must be > 0")
        if not self.mac_address:
            raise ValueError("mac_address must be non-empty")
        if not self.netdev_id:
            raise ValueError("netdev_id must be non-empty")
        if not self.network_device:
            raise ValueError("network_device must be non-empty")
        if not self.drive_interface:
            raise ValueError("drive_interface must be non-empty")
        if self.stop_timeout_s <= 0:
            raise ValueError("stop_timeout_s must be > 0")


class QemuTapVm:
    """Context manager for a host TAP device plus one attached QEMU guest."""

    def __init__(
        self,
        guest_config: QemuGuestConfig,
        tap_config: HostTapConfig | None = None,
        command_runner: CommandRunner | None = None,
        process_runner: ProcessRunner | None = None,
    ) -> None:
        self.guest_config = guest_config
        self.tap_config = tap_config or HostTapConfig()
        self.command_runner = command_runner or SubprocessCommandRunner()
        self.process_runner = process_runner or SubprocessProcessRunner()
        self._process: ProcessHandle | None = None
        self._tap_up = False

    def __enter__(self) -> Self:
        self.up()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.down()

    @property
    def process(self) -> ProcessHandle | None:
        return self._process

    @property
    def qemu_argv(self) -> tuple[str, ...]:
        guest = self.guest_config
        tap = self.tap_config
        drive = f"file={guest.disk_image},if={guest.drive_interface}"
        if guest.disk_format is not None:
            drive = f"{drive},format={guest.disk_format}"
        netdev = f"tap,id={guest.netdev_id},ifname={tap.tap_name},script=no,downscript=no"
        device = f"{guest.network_device},netdev={guest.netdev_id},mac={guest.mac_address}"

        command: list[str] = [guest.qemu_binary]
        if guest.enable_kvm:
            command.append("-enable-kvm")
        if guest.machine is not None:
            command.extend(["-machine", guest.machine])
        if guest.cpu is not None:
            command.extend(["-cpu", guest.cpu])
        command.extend(["-m", str(guest.memory_mib), "-smp", str(guest.smp)])
        if guest.snapshot:
            command.append("-snapshot")
        if guest.display is not None:
            command.extend(["-display", guest.display])
        command.extend(["-drive", drive, "-netdev", netdev, "-device", device])
        command.extend(guest.extra_args)
        return tuple(command)

    def tap_up_commands(self) -> tuple[tuple[tuple[str, ...], bool], ...]:
        cfg = self.tap_config
        tuntap = [cfg.ip_binary, "tuntap", "add", "dev", cfg.tap_name, "mode", "tap"]
        if cfg.owner is not None:
            tuntap.extend(["user", cfg.owner])
        if cfg.group is not None:
            tuntap.extend(["group", cfg.group])

        commands: list[tuple[tuple[str, ...], bool]] = [(tuple(tuntap), True)]
        if cfg.host_ipv4_cidr is not None:
            commands.append(
                (
                    (
                        cfg.ip_binary,
                        "addr",
                        "add",
                        cfg.host_ipv4_cidr,
                        "dev",
                        cfg.tap_name,
                    ),
                    True,
                )
            )
        commands.append(
            (
                (
                    cfg.ip_binary,
                    "link",
                    "set",
                    "dev",
                    cfg.tap_name,
                    "up",
                    "mtu",
                    str(cfg.mtu),
                ),
                True,
            )
        )
        return tuple(commands)

    def tap_down_commands(self) -> tuple[tuple[tuple[str, ...], bool], ...]:
        cfg = self.tap_config
        return (((cfg.ip_binary, "link", "del", cfg.tap_name), False),)

    def up(self) -> None:
        if self._process is not None:
            raise TransportError("QEMU TAP VM already started")
        if self.tap_config.cleanup_existing:
            self._tap_down()
        try:
            for argv, check in self.tap_up_commands():
                self.command_runner.run(argv, check=check)
            self._tap_up = True
            self._process = self.process_runner.start(self.qemu_argv)
        except Exception:
            self._tap_down()
            raise

    def down(self) -> None:
        process = self._process
        try:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=self.guest_config.stop_timeout_s)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=self.guest_config.stop_timeout_s)
        finally:
            self._process = None
            self._tap_down()

    def _tap_down(self) -> None:
        for argv, check in self.tap_down_commands():
            self.command_runner.run(argv, check=check)
        self._tap_up = False


@dataclass(frozen=True)
class QemuTapPreflightCheck:
    check_id: str
    status: str
    message: str
    required: bool
    details: dict[str, Any]

    def to_json(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "status": self.status,
            "message": self.message,
            "required": self.required,
            "details": self.details,
        }


@dataclass(frozen=True)
class QemuTapPreflightReport:
    schema_version: str
    generated_at_unix_s: float
    claim_status: str
    profile_id: str
    ok: bool
    checks: tuple[QemuTapPreflightCheck, ...]
    guest_config: QemuGuestConfig
    tap_config: HostTapConfig
    tcpdump_binary: str
    kvm_device: Path
    qemu_argv: tuple[str, ...]
    tap_cleanup_commands: tuple[tuple[str, ...], ...]
    tap_up_commands: tuple[tuple[str, ...], ...]
    tap_down_commands: tuple[tuple[str, ...], ...]
    notes: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at_unix_s": self.generated_at_unix_s,
            "claim_status": self.claim_status,
            "profile_id": self.profile_id,
            "ok": self.ok,
            "checks": [check.to_json() for check in self.checks],
            "guest_config": _guest_config_to_json(self.guest_config),
            "tap_config": _tap_config_to_json(self.tap_config),
            "tcpdump_binary": self.tcpdump_binary,
            "kvm_device": str(self.kvm_device),
            "qemu_argv": list(self.qemu_argv),
            "tap_cleanup_commands": [list(command) for command in self.tap_cleanup_commands],
            "tap_up_commands": [list(command) for command in self.tap_up_commands],
            "tap_down_commands": [list(command) for command in self.tap_down_commands],
            "notes": list(self.notes),
        }


def build_qemu_tap_preflight_report(
    guest_config: QemuGuestConfig,
    tap_config: HostTapConfig | None = None,
    *,
    tcpdump_binary: str = "tcpdump",
    kvm_device: Path | str = Path("/dev/kvm"),
) -> QemuTapPreflightReport:
    """Build a non-mutating readiness report for a QEMU/TAP topology."""

    tap = tap_config or HostTapConfig()
    vm = QemuTapVm(guest_config, tap)
    kvm_path = Path(kvm_device)
    checks = (
        _path_exists_check("disk_image", Path(guest_config.disk_image), required=True),
        _which_check("qemu_binary", guest_config.qemu_binary, required=True),
        _which_check("ip_binary", tap.ip_binary, required=True),
        _which_check("tcpdump_binary", tcpdump_binary, required=True),
        _kvm_check(kvm_path, required=guest_config.enable_kvm),
    )
    ok = all(check.status == "pass" or not check.required for check in checks)
    return QemuTapPreflightReport(
        schema_version=QEMU_TAP_PREFLIGHT_SCHEMA_VERSION,
        generated_at_unix_s=time(),
        claim_status=QEMU_TAP_PREFLIGHT_CLAIM_STATUS,
        profile_id="qemu-cross-stack",
        ok=ok,
        checks=checks,
        guest_config=guest_config,
        tap_config=tap,
        tcpdump_binary=tcpdump_binary,
        kvm_device=kvm_path,
        qemu_argv=vm.qemu_argv,
        tap_cleanup_commands=(
            _commands_only(vm.tap_down_commands()) if tap.cleanup_existing else ()
        ),
        tap_up_commands=_commands_only(vm.tap_up_commands()),
        tap_down_commands=_commands_only(vm.tap_down_commands()),
        notes=(
            "This report is non-mutating: no TAP device is created and no VM is started.",
            "A passing preflight is readiness evidence only, not cross-stack channel evidence.",
        ),
    )


def _commands_only(
    commands: tuple[tuple[tuple[str, ...], bool], ...],
) -> tuple[tuple[str, ...], ...]:
    return tuple(argv for argv, _check in commands)


def _path_exists_check(check_id: str, path: Path, *, required: bool) -> QemuTapPreflightCheck:
    exists = path.exists()
    return QemuTapPreflightCheck(
        check_id,
        "pass" if exists else "fail",
        f"{check_id} exists" if exists else f"{check_id} is missing",
        required,
        {
            "path": str(path),
            "exists": exists,
        },
    )


def _which_check(check_id: str, binary: str, *, required: bool) -> QemuTapPreflightCheck:
    binary_path = shutil.which(binary)
    return QemuTapPreflightCheck(
        check_id,
        "pass" if binary_path is not None else "fail",
        f"{binary} is installed" if binary_path is not None else f"{binary} is missing",
        required,
        {
            "binary": binary,
            "path": binary_path,
        },
    )


def _kvm_check(kvm_device: Path, *, required: bool) -> QemuTapPreflightCheck:
    exists = kvm_device.exists()
    read_write = exists and os.access(kvm_device, os.R_OK | os.W_OK)
    if not required:
        return QemuTapPreflightCheck(
            "kvm_device",
            "skip",
            "KVM was not requested",
            False,
            {
                "device": str(kvm_device),
                "exists": exists,
                "read_write": read_write,
            },
        )
    return QemuTapPreflightCheck(
        "kvm_device",
        "pass" if read_write else "fail",
        "KVM device is readable and writable"
        if read_write
        else "KVM device is not readable and writable",
        True,
        {
            "device": str(kvm_device),
            "exists": exists,
            "read_write": read_write,
        },
    )


def _guest_config_to_json(config: QemuGuestConfig) -> dict[str, Any]:
    return {
        "disk_image": str(config.disk_image),
        "qemu_binary": config.qemu_binary,
        "memory_mib": config.memory_mib,
        "smp": config.smp,
        "mac_address": config.mac_address,
        "netdev_id": config.netdev_id,
        "network_device": config.network_device,
        "drive_interface": config.drive_interface,
        "disk_format": config.disk_format,
        "enable_kvm": config.enable_kvm,
        "snapshot": config.snapshot,
        "display": config.display,
        "machine": config.machine,
        "cpu": config.cpu,
        "extra_args": list(config.extra_args),
        "stop_timeout_s": config.stop_timeout_s,
    }


def _tap_config_to_json(config: HostTapConfig) -> dict[str, Any]:
    return {
        "tap_name": config.tap_name,
        "host_ipv4_cidr": config.host_ipv4_cidr,
        "mtu": config.mtu,
        "ip_binary": config.ip_binary,
        "owner": config.owner,
        "group": config.group,
        "cleanup_existing": config.cleanup_existing,
    }


@dataclass(frozen=True)
class HostTcpdumpCaptureConfig:
    interface: str
    output: Path
    packet_count: int | None = None
    filter_expr: tuple[str, ...] = ()
    snaplen: int = 65535
    tcpdump_binary: str = "tcpdump"
    stop_timeout_s: float = 2.0
    require_output: bool = True

    def __post_init__(self) -> None:
        if not self.interface:
            raise ValueError("interface must be non-empty")
        if self.packet_count is not None and self.packet_count <= 0:
            raise ValueError("packet_count must be > 0")
        if self.snaplen <= 0:
            raise ValueError("snaplen must be > 0")
        if self.stop_timeout_s <= 0:
            raise ValueError("stop_timeout_s must be > 0")


class HostTcpdumpCapture:
    """Context manager for host-side ``tcpdump -i <tap> -w <pcap>`` captures."""

    def __init__(
        self,
        config: HostTcpdumpCaptureConfig,
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
            raise TransportError("host tcpdump capture already started")
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
            raise TransportError(f"host tcpdump did not create pcap: {self.config.output}")


__all__ = [
    "HostTapConfig",
    "HostTcpdumpCapture",
    "HostTcpdumpCaptureConfig",
    "QemuGuestConfig",
    "QemuTapVm",
]
