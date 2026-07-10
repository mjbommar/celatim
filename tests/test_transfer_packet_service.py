"""Privilege-separated packet-service request, peer, and policy boundaries."""

from __future__ import annotations

import asyncio
import os
import struct
from pathlib import Path

import pytest

from celatim import MechanismProfile
from celatim.testbed.packet_path import (
    Ipv4PacketPathConfig,
    PacketProtocol,
    build_ipv4_carrier_frame,
    run_afpacket_roundtrip,
)
from celatim.transfer.packet_service import (
    MAX_PACKET_SERVICE_PAYLOAD,
    PacketCaptureFilter,
    PacketOperation,
    PacketService,
    PacketServiceClient,
    PacketServiceRequest,
    PacketServiceSocketFactory,
    packet_service_preflight,
    packet_service_systemd_unit,
)


def test_packet_capture_filter_matches_only_the_authorized_ipv4_flow():
    config = Ipv4PacketPathConfig()
    capture_filter = PacketCaptureFilter(
        src_mac=config.src_mac,
        dst_mac=config.dst_mac,
        src_ip=config.src_ip,
        dst_ip=config.dst_ip,
        ip_protocol=config.protocol.ip_proto,
        src_port=config.src_port,
        dst_port=config.dst_port,
    )
    frame = build_ipv4_carrier_frame(config, b"carrier")

    assert capture_filter.matches(frame)
    assert not capture_filter.matches(
        build_ipv4_carrier_frame(
            Ipv4PacketPathConfig(dst_port=config.dst_port + 1),
            b"other",
        )
    )


def test_packet_service_roundtrips_bounded_payload_for_allowed_peer(tmp_path):
    async def run() -> None:
        seen: list[PacketServiceRequest] = []

        async def handler(request: PacketServiceRequest) -> bytes:
            seen.append(request)
            return request.payload[::-1]

        socket_path = tmp_path / "run" / "packet.sock"
        async with PacketService(
            socket_path,
            handler,
            allowed_uids={os.getuid()},
            allowed_providers={"afpacket-ipv4"},
            allowed_interfaces={"eth0"},
        ):
            response = await PacketServiceClient(socket_path).request(
                PacketServiceRequest.create(
                    PacketOperation.SEND,
                    "afpacket-ipv4",
                    "eth0",
                    b"\x00\xffpacket",
                )
            )
            assert socket_path.stat().st_mode & 0o777 == 0o660

        assert response.ok
        assert response.payload == b"tekcap\xff\x00"
        assert seen[0].operation is PacketOperation.SEND
        assert not socket_path.exists()

    asyncio.run(run())


def test_packet_service_rejects_provider_and_interface_outside_allowlist(tmp_path):
    async def run() -> None:
        async def handler(request: PacketServiceRequest) -> bytes:
            raise AssertionError(f"blocked request reached handler: {request}")

        socket_path = tmp_path / "packet.sock"
        async with PacketService(
            socket_path,
            handler,
            allowed_providers={"allowed"},
            allowed_interfaces={"eth0"},
        ):
            provider_response = await PacketServiceClient(socket_path).request(
                PacketServiceRequest.create(PacketOperation.SEND, "blocked", "eth0")
            )
            interface_response = await PacketServiceClient(socket_path).request(
                PacketServiceRequest.create(PacketOperation.SEND, "allowed", "eth1")
            )

        assert not provider_response.ok
        assert provider_response.error_code == "policy_blocked"
        assert provider_response.detail == "packet provider is not allowed by the service"
        assert not interface_response.ok
        assert interface_response.error_code == "policy_blocked"
        assert interface_response.detail == "packet interface is not allowed by the service"

    asyncio.run(run())


def test_packet_service_request_rejects_oversized_payload():
    with pytest.raises(ValueError, match="size limit"):
        PacketServiceRequest.create(
            PacketOperation.SEND,
            "afpacket-ipv4",
            "eth0",
            b"x" * (MAX_PACKET_SERVICE_PAYLOAD + 1),
        )


def test_packet_service_preflight_and_systemd_unit_are_capability_bounded(tmp_path):
    socket_path = tmp_path / "run" / "packet.sock"
    document = packet_service_preflight(
        socket_path,
        providers={"afpacket-ipv4"},
        interfaces={"eth0"},
        allowed_uids={1000},
    )
    unit = packet_service_systemd_unit(
        executable=Path("/usr/bin/celatim"),
        user="celatim-packet",
        socket_path=socket_path,
        providers={"afpacket-ipv4"},
        interfaces={"eth0"},
        allowed_uids={1000},
    )

    assert document["schema_version"] == "celatim.packet_service_preflight.v1"
    assert document["allowed_providers"] == ["afpacket-ipv4"]
    assert "User=celatim-packet" in unit
    assert "AmbientCapabilities=CAP_NET_RAW" in unit
    assert "CapabilityBoundingSet=CAP_NET_RAW" in unit
    assert "NoNewPrivileges=yes" in unit
    assert "ProtectSystem=strict" in unit
    assert "RestrictAddressFamilies=AF_UNIX AF_PACKET" in unit
    assert "sudo" not in unit


def test_existing_afpacket_mechanism_runs_through_unprivileged_service_client(tmp_path):
    async def run() -> None:
        frames: asyncio.Queue[bytes] = asyncio.Queue()

        async def handler(request: PacketServiceRequest) -> bytes:
            if request.operation is PacketOperation.SEND_BATCH:
                offset = 0
                count = 0
                while offset < len(request.payload):
                    (length,) = struct.unpack("!I", request.payload[offset : offset + 4])
                    offset += 4
                    await frames.put(request.payload[offset : offset + length])
                    offset += length
                    count += 1
                return count.to_bytes(8, "big")
            if request.operation is PacketOperation.SEND:
                await frames.put(request.payload)
                return len(request.payload).to_bytes(8, "big")
            if request.operation is PacketOperation.RECEIVE:
                count, _ = struct.unpack("!II", request.payload)
                batch = [await frames.get() for _ in range(count)]
                return b"".join(struct.pack("!I", len(frame)) + frame for frame in batch)
            return b"ready"

        socket_path = tmp_path / "packet.sock"
        async with PacketService(
            socket_path,
            handler,
            allowed_providers={"afpacket-carrier"},
            allowed_interfaces={"loop0"},
        ):
            profile = MechanismProfile.from_catalog("http2-ping-opaque")
            config = Ipv4PacketPathConfig(
                sender_interface="loop0",
                receiver_interface="loop0",
                src_mac="02:00:00:00:00:01",
                dst_mac="02:00:00:00:00:02",
                src_ip="192.0.2.1",
                dst_ip="192.0.2.2",
                protocol=PacketProtocol.TCP,
                timeout_s=2,
            )
            result = await asyncio.to_thread(
                run_afpacket_roundtrip,
                profile,
                b"\x00\xffservice path",
                config=config,
                socket_factory=PacketServiceSocketFactory(socket_path, timeout_s=2),
            )

        assert result.result.payload == b"\x00\xffservice path"
        assert result.result.evidence.ok
        assert result.expected_frames > 0

    asyncio.run(run())
