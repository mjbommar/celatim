"""Reviewer-visible requirements for privileged and daemon-backed testbeds."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from time import time
from typing import Any

TESTBED_REQUIREMENTS_SCHEMA_VERSION = "celatim.testbed_requirements.v1"
TESTBED_PROFILE_STATUSES = (
    "packaged",
    "legacy_experiment",
    "planned",
    "planned_manual",
)


@dataclass(frozen=True)
class TestbedRequirementProfile:
    profile_id: str
    description: str
    status: str
    evidence_tiers: tuple[str, ...]
    required_privileges: tuple[str, ...]
    required_tools: tuple[str, ...]
    optional_tools: tuple[str, ...] = ()
    required_extras: tuple[str, ...] = ()
    reviewer_commands: tuple[tuple[str, ...], ...] = ()
    legacy_experiments: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "description": self.description,
            "status": self.status,
            "evidence_tiers": list(self.evidence_tiers),
            "required_privileges": list(self.required_privileges),
            "required_tools": list(self.required_tools),
            "optional_tools": list(self.optional_tools),
            "required_extras": list(self.required_extras),
            "reviewer_commands": [list(command) for command in self.reviewer_commands],
            "legacy_experiments": list(self.legacy_experiments),
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class TestbedRequirementInventory:
    schema_version: str
    generated_at_unix_s: float
    profile_count: int
    profile_ids: tuple[str, ...]
    required_privileges: tuple[str, ...]
    required_tools: tuple[str, ...]
    optional_tools: tuple[str, ...]
    required_extras: tuple[str, ...]
    profiles: tuple[TestbedRequirementProfile, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at_unix_s": self.generated_at_unix_s,
            "profile_count": self.profile_count,
            "profile_ids": list(self.profile_ids),
            "required_privileges": list(self.required_privileges),
            "required_tools": list(self.required_tools),
            "optional_tools": list(self.optional_tools),
            "required_extras": list(self.required_extras),
            "profiles": [profile.to_json() for profile in self.profiles],
        }


TESTBED_REQUIREMENT_PROFILES: tuple[TestbedRequirementProfile, ...] = (
    TestbedRequirementProfile(
        profile_id="netns-afpacket",
        description="Linux netns/veth topology with AF_PACKET live packet I/O and optional tcpdump capture.",
        status="packaged",
        evidence_tiers=("real_pdu_packet_path",),
        required_privileges=("cap_net_admin", "cap_net_raw"),
        required_tools=("ip", "tcpdump"),
        optional_tools=("ethtool",),
        reviewer_commands=(
            (
                "make",
                "reviewer-afpacket-tcp",
            ),
        ),
        notes=(
            "Requires a Linux host that allows network namespaces and AF_PACKET sockets.",
            "Checked-in manual scenario id: tcp-reserved-bits-afpacket-netns.",
            "The checked-in default smoke scenarios are non-privileged pcap-backed runs; this profile covers live packet paths.",
        ),
    ),
    TestbedRequirementProfile(
        profile_id="dns-daemon-netns",
        description="Real dig client to real dnsmasq server over netns/veth with passive pcap recovery.",
        status="packaged",
        evidence_tiers=("real_daemon_path",),
        required_privileges=("cap_net_admin",),
        required_tools=("dig", "dnsmasq", "ip", "tcpdump"),
        required_extras=("packet",),
        legacy_experiments=("measurement/experiments/run_realistic_dns.py",),
        reviewer_commands=(
            (
                "make",
                "reviewer-dns-daemon",
            ),
        ),
        notes=(
            "Checked-in scenario id: edns0-padding-dnsmasq-dig-real-daemon.",
            "Scapy is used to read EDNS(0) padding from the captured DNS query.",
        ),
    ),
    TestbedRequirementProfile(
        profile_id="three-tap-middlebox",
        description="Middlebox ingress, egress, and receiver taps for survivability localization.",
        status="legacy_experiment",
        evidence_tiers=("crafted_production_path",),
        required_privileges=("cap_net_admin", "cap_net_raw"),
        required_tools=("ip", "tcpdump"),
        legacy_experiments=("measurement/experiments/run_taps.py",),
        notes=(
            "Documents where a field survives or is scrubbed across a controlled middlebox path.",
            "The runner still depends on experiment-script topology wrappers.",
        ),
    ),
    TestbedRequirementProfile(
        profile_id="docker-daemon",
        description="Containerized production-daemon scenarios with pinned daemon/library images.",
        status="planned",
        evidence_tiers=("real_daemon_path",),
        required_privileges=("docker",),
        required_tools=("docker",),
        optional_tools=("tcpdump", "tshark"),
        legacy_experiments=("measurement/experiments/Dockerfile",),
        notes=(
            "Docker packaging exists only as a base experiment artifact today.",
            "Future scenarios should record image digests in evidence metadata.",
        ),
    ),
    TestbedRequirementProfile(
        profile_id="qemu-cross-stack",
        description="QEMU/KVM TAP topology for independent receiver OS stacks.",
        status="planned_manual",
        evidence_tiers=("cross_stack_vm_path",),
        required_privileges=("cap_net_admin", "kvm"),
        required_tools=("ip", "qemu-system-x86_64", "tcpdump"),
        optional_tools=("tshark",),
        reviewer_commands=(("make", "reviewer-qemu-preflight"),),
        notes=(
            "Reusable HostTapConfig, QemuTapVm, and HostTcpdumpCapture helpers are packaged and unit-tested.",
            "The reviewer-qemu-preflight target writes a non-mutating readiness report without starting a guest.",
            "No packaged VM image or cross-stack evidence scenario is implemented yet.",
            "This profile records the manual/nightly requirements for future Linux-to-FreeBSD or Linux-to-Windows evidence.",
        ),
    ),
)


def build_testbed_requirements_inventory(
    profile_ids: Iterable[str] | None = None,
) -> TestbedRequirementInventory:
    profiles = _selected_profiles(profile_ids)
    return TestbedRequirementInventory(
        schema_version=TESTBED_REQUIREMENTS_SCHEMA_VERSION,
        generated_at_unix_s=time(),
        profile_count=len(profiles),
        profile_ids=tuple(profile.profile_id for profile in profiles),
        required_privileges=_unique(
            privilege for profile in profiles for privilege in profile.required_privileges
        ),
        required_tools=_unique(tool for profile in profiles for tool in profile.required_tools),
        optional_tools=_unique(tool for profile in profiles for tool in profile.optional_tools),
        required_extras=_unique(extra for profile in profiles for extra in profile.required_extras),
        profiles=profiles,
    )


def testbed_profile_ids() -> tuple[str, ...]:
    return tuple(profile.profile_id for profile in TESTBED_REQUIREMENT_PROFILES)


def testbed_profiles_by_id(profile_ids: Iterable[str]) -> tuple[TestbedRequirementProfile, ...]:
    return _selected_profiles(profile_ids)


def _selected_profiles(profile_ids: Iterable[str] | None) -> tuple[TestbedRequirementProfile, ...]:
    if profile_ids is None:
        return TESTBED_REQUIREMENT_PROFILES
    by_id = {profile.profile_id: profile for profile in TESTBED_REQUIREMENT_PROFILES}
    selected: list[TestbedRequirementProfile] = []
    for profile_id in profile_ids:
        try:
            selected.append(by_id[profile_id])
        except KeyError as exc:
            raise ValueError(f"unknown testbed profile: {profile_id}") from exc
    return tuple(selected)


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(sorted(values)))


__all__ = [
    "TESTBED_PROFILE_STATUSES",
    "TESTBED_REQUIREMENTS_SCHEMA_VERSION",
    "TESTBED_REQUIREMENT_PROFILES",
    "TestbedRequirementInventory",
    "TestbedRequirementProfile",
    "build_testbed_requirements_inventory",
    "testbed_profile_ids",
    "testbed_profiles_by_id",
]
