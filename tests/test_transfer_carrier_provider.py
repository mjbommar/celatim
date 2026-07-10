"""Encrypted file chunks traverse a mechanism through the packet-service boundary."""

from __future__ import annotations

import asyncio
import struct
from pathlib import Path

from celatim.testbed.packet_path import Ipv4PacketPathConfig, PacketProtocol
from celatim.transfer import ProviderRegistry, TransferClient, TransferServer
from celatim.transfer.carrier import (
    PACKET_SERVICE_CARRIER_POLICY,
    AfpacketCarrierProvider,
    CarrierEndpointConfig,
)
from celatim.transfer.packet_service import PacketOperation, PacketService, PacketServiceRequest


def test_file_transfer_uses_encrypted_http2_carriers_through_two_packet_services(tmp_path):
    async def run() -> None:
        wire: asyncio.Queue[bytes] = asyncio.Queue()
        observed_frames: list[bytes] = []

        async def alice_packet_handler(request: PacketServiceRequest) -> bytes:
            assert request.operation is PacketOperation.SEND_BATCH
            offset = 0
            count = 0
            while offset < len(request.payload):
                (length,) = struct.unpack("!I", request.payload[offset : offset + 4])
                offset += 4
                frame = request.payload[offset : offset + length]
                offset += length
                observed_frames.append(frame)
                await wire.put(frame)
                count += 1
            return count.to_bytes(8, "big")

        async def bob_packet_handler(request: PacketServiceRequest) -> bytes:
            assert request.operation is PacketOperation.RECEIVE
            count = struct.unpack("!I", request.payload[1:5])[0]
            batch = [await wire.get() for _ in range(count)]
            return b"".join(struct.pack("!I", len(frame)) + frame for frame in batch)

        alice_config = CarrierEndpointConfig(
            mechanism_id="http2-ping-opaque",
            packet_service_socket=tmp_path / "alice-packet.sock",
            packet_path=Ipv4PacketPathConfig(
                sender_interface="alice0",
                receiver_interface="unused0",
                src_mac="02:00:00:00:00:01",
                dst_mac="02:00:00:00:00:02",
                src_ip="192.0.2.1",
                dst_ip="192.0.2.2",
                protocol=PacketProtocol.TCP,
                timeout_s=5,
            ),
            priority=200,
        )
        bob_config = CarrierEndpointConfig(
            mechanism_id="http2-ping-opaque",
            packet_service_socket=tmp_path / "bob-packet.sock",
            packet_path=Ipv4PacketPathConfig(
                sender_interface="unused1",
                receiver_interface="bob0",
                src_mac="02:00:00:00:00:01",
                dst_mac="02:00:00:00:00:02",
                src_ip="192.0.2.1",
                dst_ip="192.0.2.2",
                protocol=PacketProtocol.TCP,
                timeout_s=5,
            ),
            priority=200,
        )
        source = tmp_path / "alice" / "carrier.bin"
        source.parent.mkdir()
        payload = b"\x00\xffmechanism carrier file" * 20
        source.write_bytes(payload)
        async with (
            PacketService(
                alice_config.packet_service_socket,
                alice_packet_handler,
                allowed_providers={PACKET_SERVICE_CARRIER_POLICY},
                allowed_interfaces={"alice0"},
            ),
            PacketService(
                bob_config.packet_service_socket,
                bob_packet_handler,
                allowed_providers={PACKET_SERVICE_CARRIER_POLICY},
                allowed_interfaces={"bob0"},
            ),
            TransferServer(
                tmp_path / "bob" / "received",
                home=tmp_path / "bob" / "home",
                carrier_receivers=(bob_config,),
                timeout_s=10,
            ) as server,
        ):
            offer = await server.create_offer()
            provider = AfpacketCarrierProvider(alice_config)
            registry = ProviderRegistry((provider,))
            async with TransferClient(
                home=tmp_path / "alice" / "home",
                registry=registry,
                timeout_s=10,
            ) as client:
                operation = await client.send_file(
                    source,
                    offer,
                    provider=provider.manifest.name,
                    chunk_size=4096,
                )
                sender_receipt = await operation.result()
            receiver_receipt = await server.receive(timeout_s=5)

        assert sender_receipt.provider == "afpacket.http2-ping-opaque"
        assert sender_receipt.authenticated
        assert sender_receipt.acknowledged
        assert receiver_receipt.provider == sender_receipt.provider
        assert Path(receiver_receipt.path or "").read_bytes() == payload
        assert provider.manifest.evidence_level.value == "synthetic_outer_frame"
        assert observed_frames
        assert all(payload not in frame for frame in observed_frames)
        sender_state = next(
            state
            for state in await TransferClient(home=tmp_path / "alice" / "home").status()
            if state.transfer_id == sender_receipt.transfer_id
        )
        assert "fernet_key" in sender_state.provider_state
        assert sender_state.to_json(redact_private=True)["provider_state"] == {
            "fernet_key": "[redacted]"
        }
        assert CarrierEndpointConfig.from_json(alice_config.to_json()) == alice_config

    asyncio.run(run())
