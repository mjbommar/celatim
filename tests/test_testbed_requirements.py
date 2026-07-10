"""Reviewer-visible privileged testbed requirement profiles."""

import pytest

from celatim.testbed import (
    TESTBED_REQUIREMENTS_SCHEMA_VERSION,
    build_testbed_requirements_inventory,
)
from celatim.testbed import (
    testbed_profile_ids as requirement_profile_ids,
)


def test_testbed_requirements_inventory_lists_privileged_paths():
    inventory = build_testbed_requirements_inventory()
    doc = inventory.to_json()

    assert doc["schema_version"] == TESTBED_REQUIREMENTS_SCHEMA_VERSION
    assert doc["profile_ids"] == [
        "netns-afpacket",
        "dns-daemon-netns",
        "three-tap-middlebox",
        "docker-daemon",
        "qemu-cross-stack",
    ]
    assert doc["profile_count"] == 5
    assert "cap_net_admin" in doc["required_privileges"]
    assert "cap_net_raw" in doc["required_privileges"]
    assert "docker" in doc["required_privileges"]
    assert "kvm" in doc["required_privileges"]
    assert "qemu-system-x86_64" in doc["required_tools"]
    netns = next(
        profile for profile in doc["profiles"] if profile["profile_id"] == "netns-afpacket"
    )
    assert netns["status"] == "packaged"
    assert netns["reviewer_commands"] == [["make", "reviewer-afpacket-tcp"]]
    dns = next(
        profile for profile in doc["profiles"] if profile["profile_id"] == "dns-daemon-netns"
    )
    assert dns["status"] == "packaged"
    assert dns["required_tools"] == ["dig", "dnsmasq", "ip", "tcpdump"]
    assert dns["required_extras"] == ["packet"]
    assert dns["reviewer_commands"] == [["make", "reviewer-dns-daemon"]]
    qemu = next(
        profile for profile in doc["profiles"] if profile["profile_id"] == "qemu-cross-stack"
    )
    assert qemu["status"] == "planned_manual"
    assert qemu["evidence_tiers"] == ["cross_stack_vm_path"]


def test_testbed_requirements_inventory_can_filter_profiles():
    inventory = build_testbed_requirements_inventory(("qemu-cross-stack",))
    doc = inventory.to_json()

    assert doc["profile_count"] == 1
    assert doc["profile_ids"] == ["qemu-cross-stack"]
    assert doc["required_privileges"] == ["cap_net_admin", "kvm"]
    assert doc["required_tools"] == ["ip", "qemu-system-x86_64", "tcpdump"]


def test_testbed_profile_ids_are_stable():
    assert requirement_profile_ids() == (
        "netns-afpacket",
        "dns-daemon-netns",
        "three-tap-middlebox",
        "docker-daemon",
        "qemu-cross-stack",
    )


def test_testbed_requirements_rejects_unknown_profile():
    with pytest.raises(ValueError, match="unknown testbed profile"):
        build_testbed_requirements_inventory(("missing",))
