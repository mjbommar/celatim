"""QEMU/TAP lifecycle helpers for cross-stack scenarios."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field

import pytest

import celatim.testbed.qemu as qemu_module
from celatim.errors import TransportError
from celatim.resources import schema_text
from celatim.testbed import (
    QEMU_TAP_PREFLIGHT_CLAIM_STATUS,
    QEMU_TAP_PREFLIGHT_SCHEMA_VERSION,
    HostTapConfig,
    HostTcpdumpCapture,
    HostTcpdumpCaptureConfig,
    QemuGuestConfig,
    QemuTapVm,
    build_qemu_tap_preflight_report,
)
from celatim.testbed.commands import CommandResult


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
            raise subprocess.TimeoutExpired("qemu", 0.0 if timeout is None else timeout)
        self.returncode = -9 if self.killed else 0
        return self.returncode

    def kill(self) -> None:
        self.killed = True


@dataclass
class FakeCommandRunner:
    commands: list[tuple[tuple[str, ...], bool]] = field(default_factory=list)

    def run(self, argv: Sequence[str], *, check: bool = True) -> CommandResult:
        command = tuple(argv)
        self.commands.append((command, check))
        return CommandResult(argv=command, returncode=0)


@dataclass
class FakeProcessRunner:
    process: FakeProcess
    started: list[tuple[str, ...]] = field(default_factory=list)

    def start(self, argv: Sequence[str]) -> FakeProcess:
        self.started.append(tuple(argv))
        return self.process


def test_qemu_tap_vm_builds_tap_and_qemu_commands(tmp_path):
    commands = FakeCommandRunner()
    process = FakeProcess()
    processes = FakeProcessRunner(process)
    disk = tmp_path / "receiver.qcow2"
    vm = QemuTapVm(
        QemuGuestConfig(
            disk_image=disk,
            memory_mib=512,
            smp=2,
            mac_address="52:54:00:12:34:56",
            extra_args=("-nographic",),
        ),
        HostTapConfig(
            tap_name="tap-rfc0",
            host_ipv4_cidr="192.0.2.1/24",
            mtu=1400,
            owner="tester",
        ),
        command_runner=commands,
        process_runner=processes,
    )

    with vm:
        assert commands.commands == [
            (("ip", "link", "del", "tap-rfc0"), False),
            (
                (
                    "ip",
                    "tuntap",
                    "add",
                    "dev",
                    "tap-rfc0",
                    "mode",
                    "tap",
                    "user",
                    "tester",
                ),
                True,
            ),
            (
                ("ip", "addr", "add", "192.0.2.1/24", "dev", "tap-rfc0"),
                True,
            ),
            (
                ("ip", "link", "set", "dev", "tap-rfc0", "up", "mtu", "1400"),
                True,
            ),
        ]
        assert processes.started == [
            (
                "qemu-system-x86_64",
                "-enable-kvm",
                "-m",
                "512",
                "-smp",
                "2",
                "-snapshot",
                "-display",
                "none",
                "-drive",
                f"file={disk},if=virtio,format=qcow2",
                "-netdev",
                "tap,id=net0,ifname=tap-rfc0,script=no,downscript=no",
                "-device",
                "virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56",
                "-nographic",
            )
        ]

    assert process.terminated is True
    assert process.killed is False
    assert commands.commands[-1] == (("ip", "link", "del", "tap-rfc0"), False)


def test_qemu_tap_vm_kills_guest_after_stop_timeout(tmp_path):
    process = FakeProcess(time_out_once=True)
    vm = QemuTapVm(
        QemuGuestConfig(disk_image=tmp_path / "receiver.qcow2", stop_timeout_s=0.1),
        HostTapConfig(tap_name="tap-rfc0"),
        command_runner=FakeCommandRunner(),
        process_runner=FakeProcessRunner(process),
    )

    vm.up()
    vm.down()

    assert process.terminated is True
    assert process.killed is True
    assert process.waits == 2


def test_qemu_tap_vm_rejects_double_start(tmp_path):
    vm = QemuTapVm(
        QemuGuestConfig(disk_image=tmp_path / "receiver.qcow2"),
        command_runner=FakeCommandRunner(),
        process_runner=FakeProcessRunner(FakeProcess()),
    )

    vm.up()
    try:
        with pytest.raises(TransportError, match="already started"):
            vm.up()
    finally:
        vm.down()


def test_qemu_tap_preflight_reports_non_mutating_readiness(tmp_path, monkeypatch):
    disk = tmp_path / "receiver.qcow2"
    disk.write_bytes(b"qcow2")
    kvm = tmp_path / "kvm"
    kvm.write_text("")

    monkeypatch.setattr(qemu_module.shutil, "which", lambda binary: f"/usr/bin/{binary}")

    report = build_qemu_tap_preflight_report(
        QemuGuestConfig(
            disk_image=disk,
            memory_mib=512,
            smp=2,
            mac_address="52:54:00:12:34:56",
            extra_args=("-nographic",),
        ),
        HostTapConfig(tap_name="tap-preflight", host_ipv4_cidr="192.0.2.1/24"),
        kvm_device=kvm,
    )
    doc = report.to_json()
    checks = {check["check_id"]: check for check in doc["checks"]}

    assert doc["schema_version"] == QEMU_TAP_PREFLIGHT_SCHEMA_VERSION
    assert doc["claim_status"] == QEMU_TAP_PREFLIGHT_CLAIM_STATUS
    assert doc["profile_id"] == "qemu-cross-stack"
    assert doc["ok"] is True
    assert all(check["status"] == "pass" for check in checks.values())
    assert doc["guest_config"]["disk_image"] == str(disk)
    assert doc["tap_config"]["tap_name"] == "tap-preflight"
    assert doc["qemu_argv"] == [
        "qemu-system-x86_64",
        "-enable-kvm",
        "-m",
        "512",
        "-smp",
        "2",
        "-snapshot",
        "-display",
        "none",
        "-drive",
        f"file={disk},if=virtio,format=qcow2",
        "-netdev",
        "tap,id=net0,ifname=tap-preflight,script=no,downscript=no",
        "-device",
        "virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56",
        "-nographic",
    ]
    assert doc["tap_cleanup_commands"] == [["ip", "link", "del", "tap-preflight"]]
    assert doc["tap_up_commands"] == [
        ["ip", "tuntap", "add", "dev", "tap-preflight", "mode", "tap"],
        ["ip", "addr", "add", "192.0.2.1/24", "dev", "tap-preflight"],
        ["ip", "link", "set", "dev", "tap-preflight", "up", "mtu", "1500"],
    ]
    assert "no VM is started" in doc["notes"][0]


def test_qemu_tap_preflight_report_matches_schema_top_level(tmp_path, monkeypatch):
    disk = tmp_path / "receiver.qcow2"
    disk.touch()
    monkeypatch.setattr(qemu_module.shutil, "which", lambda binary: f"/usr/bin/{binary}")

    report = build_qemu_tap_preflight_report(
        QemuGuestConfig(disk_image=disk, enable_kvm=False),
        HostTapConfig(tap_name="tap-schema"),
        kvm_device=tmp_path / "missing-kvm",
    ).to_json()
    schema = json.loads(schema_text("qemu-tap-preflight-v1"))

    assert set(schema["required"]) == set(report)
    assert schema["properties"]["schema_version"]["const"] == report["schema_version"]
    assert schema["properties"]["claim_status"]["const"] == report["claim_status"]
    assert schema["properties"]["profile_id"]["const"] == report["profile_id"]
    assert {check["check_id"] for check in report["checks"]} == {
        "disk_image",
        "qemu_binary",
        "ip_binary",
        "tcpdump_binary",
        "kvm_device",
    }


def test_qemu_tap_preflight_skips_kvm_when_disabled(tmp_path, monkeypatch):
    disk = tmp_path / "receiver.raw"
    disk.touch()
    monkeypatch.setattr(qemu_module.shutil, "which", lambda binary: f"/usr/bin/{binary}")

    report = build_qemu_tap_preflight_report(
        QemuGuestConfig(disk_image=disk, disk_format=None, enable_kvm=False),
        HostTapConfig(tap_name="tap-nokvm", cleanup_existing=False),
        kvm_device=tmp_path / "missing-kvm",
    )
    doc = report.to_json()
    checks = {check["check_id"]: check for check in doc["checks"]}

    assert doc["ok"] is True
    assert checks["kvm_device"]["status"] == "skip"
    assert "-enable-kvm" not in doc["qemu_argv"]
    assert doc["tap_cleanup_commands"] == []
    assert f"file={disk},if=virtio" in doc["qemu_argv"]


def test_qemu_tap_preflight_fails_missing_required_inputs(tmp_path, monkeypatch):
    monkeypatch.setattr(qemu_module.shutil, "which", lambda _binary: None)

    report = build_qemu_tap_preflight_report(
        QemuGuestConfig(disk_image=tmp_path / "missing.qcow2"),
        HostTapConfig(tap_name="tap-missing"),
        kvm_device=tmp_path / "missing-kvm",
    )
    checks = {check.check_id: check for check in report.checks}

    assert report.ok is False
    assert checks["disk_image"].status == "fail"
    assert checks["qemu_binary"].status == "fail"
    assert checks["ip_binary"].status == "fail"
    assert checks["tcpdump_binary"].status == "fail"
    assert checks["kvm_device"].status == "fail"


def test_host_tcpdump_capture_builds_tap_capture_command(tmp_path):
    output = tmp_path / "tap.pcap"
    capture = HostTcpdumpCapture(
        HostTcpdumpCaptureConfig(
            interface="tap-rfc0",
            output=output,
            packet_count=3,
            filter_expr=("ip", "host", "192.0.2.2"),
        ),
        FakeProcessRunner(FakeProcess(returncode=0)),
    )

    assert capture.argv == (
        "tcpdump",
        "-i",
        "tap-rfc0",
        "-U",
        "-s",
        "65535",
        "-w",
        str(output),
        "-c",
        "3",
        "ip",
        "host",
        "192.0.2.2",
    )


def test_host_tcpdump_capture_requires_output_by_default(tmp_path):
    capture = HostTcpdumpCapture(
        HostTcpdumpCaptureConfig(interface="tap-rfc0", output=tmp_path / "missing.pcap"),
        FakeProcessRunner(FakeProcess(returncode=0)),
    )

    capture.start()
    with pytest.raises(TransportError, match="did not create pcap"):
        capture.stop()


def test_qemu_tap_config_rejects_invalid_values(tmp_path):
    with pytest.raises(ValueError, match="tap_name"):
        HostTapConfig(tap_name="")
    with pytest.raises(ValueError, match="memory_mib"):
        QemuGuestConfig(disk_image=tmp_path / "receiver.qcow2", memory_mib=0)
    with pytest.raises(ValueError, match="packet_count"):
        HostTcpdumpCaptureConfig(
            interface="tap-rfc0",
            output=tmp_path / "x.pcap",
            packet_count=0,
        )
