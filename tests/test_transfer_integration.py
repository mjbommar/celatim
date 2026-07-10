"""End-to-end TLS file transfer, progress, trust failure, and resume."""

from __future__ import annotations

import asyncio
import socket
from dataclasses import replace
from pathlib import Path

import pytest

from celatim.transfer import (
    MIN_CHUNK_SIZE,
    TransferClient,
    TransferErrorCode,
    TransferEventKind,
    TransferFailure,
    TransferServer,
    TransferStateStore,
    TransferStatus,
)


def test_tls_transfer_api_roundtrips_binary_file_and_emits_ordered_events(tmp_path):
    async def run() -> None:
        source = tmp_path / "report.bin"
        payload = b"\x00\xffbinary" * 10_000
        source.write_bytes(payload)
        async with TransferServer(
            tmp_path / "received",
            home=tmp_path / "bob-home",
        ) as server:
            offer = await server.create_offer(receiver_label="Bob")
            async with TransferClient(home=tmp_path / "alice-home") as client:
                operation = await client.send_file(source, offer, chunk_size=MIN_CHUNK_SIZE)
                sender_receipt = await operation.result()
                events = [event async for event in operation.events()]
            receiver_receipt = await server.receive(timeout_s=2)

        assert sender_receipt.authenticated
        assert sender_receipt.verified
        assert sender_receipt.acknowledged
        assert receiver_receipt.authenticated
        assert Path(receiver_receipt.path or "").read_bytes() == payload
        assert [event.sequence for event in events] == list(range(len(events)))
        assert events[-1].kind is TransferEventKind.COMPLETED
        assert events[-1].bytes_transferred == len(payload)
        sender_state = TransferStateStore(tmp_path / "alice-home").read_state(
            sender_receipt.transfer_id,
            "sender",
        )
        receiver_state = TransferStateStore(tmp_path / "bob-home").read_state(
            sender_receipt.transfer_id,
            "receiver",
        )
        assert sender_state.status is TransferStatus.COMPLETED
        assert receiver_state.status is TransferStatus.COMPLETED

    asyncio.run(run())


def test_tls_transfer_rejects_offer_with_wrong_certificate_pin(tmp_path):
    async def run() -> None:
        source = tmp_path / "secret.bin"
        source.write_bytes(b"not delivered")
        async with TransferServer(
            tmp_path / "received",
            home=tmp_path / "bob-home",
        ) as server:
            offer = await server.create_offer()
            modified = replace(offer, tls_cert_sha256="0" * 64)
            async with TransferClient(home=tmp_path / "alice-home") as client:
                operation = await client.send_file(source, modified)
                with pytest.raises(TransferFailure) as error:
                    await operation.result()

        assert error.value.code is TransferErrorCode.TRUST_FAILED
        assert not list((tmp_path / "received").glob("secret*"))

    asyncio.run(run())


def test_tls_transfer_resumes_after_sender_cancellation(tmp_path):
    async def run() -> None:
        source = tmp_path / "large.bin"
        payload = bytes(range(256)) * 8192
        source.write_bytes(payload)
        async with TransferServer(
            tmp_path / "received",
            home=tmp_path / "bob-home",
            timeout_s=10,
        ) as server:
            offer = await server.create_offer()
            async with TransferClient(home=tmp_path / "alice-home", timeout_s=10) as client:
                first = await client.send_file(source, offer, chunk_size=MIN_CHUNK_SIZE)
                async for event in first.events():
                    if event.kind is TransferEventKind.PROGRESS:
                        await first.cancel()
                        break
                cancelled = TransferStateStore(tmp_path / "alice-home").read_state(
                    first.transfer_id,
                    "sender",
                )
                assert cancelled.status is TransferStatus.CANCELLED
                assert cancelled.acknowledged_chunks
                resumed = await client.resume(first.transfer_id)
                sender_receipt = await resumed.result()
            receiver_receipt = await server.receive(timeout_s=5)

        assert sender_receipt.transfer_id == first.transfer_id
        assert receiver_receipt.transfer_id == first.transfer_id
        assert Path(receiver_receipt.path or "").read_bytes() == payload
        final_state = TransferStateStore(tmp_path / "alice-home").read_state(
            first.transfer_id,
            "sender",
        )
        assert final_state.status is TransferStatus.COMPLETED
        assert len(final_state.acknowledged_chunks) == final_state.manifest.chunk_count

    asyncio.run(run())


def test_transfer_offer_is_single_use_for_new_transfer_ids(tmp_path):
    async def run() -> None:
        first_source = tmp_path / "first.bin"
        second_source = tmp_path / "second.bin"
        first_source.write_bytes(b"first")
        second_source.write_bytes(b"second")
        async with TransferServer(
            tmp_path / "received",
            home=tmp_path / "bob-home",
        ) as server:
            offer = await server.create_offer()
            async with TransferClient(home=tmp_path / "alice-home") as client:
                first = await client.send_file(first_source, offer)
                await first.result()
                await server.receive(timeout_s=2)
                replay = await client.send_file(second_source, offer)
                with pytest.raises(TransferFailure) as error:
                    await replay.result()

        assert error.value.code is TransferErrorCode.OFFER_REPLAYED
        assert (tmp_path / "received" / "first.bin").read_bytes() == b"first"
        assert not (tmp_path / "received" / "second.bin").exists()

    asyncio.run(run())


def test_listener_restart_reloads_identity_and_unexpired_offer(tmp_path):
    async def run() -> None:
        source = tmp_path / "restart.bin"
        source.write_bytes(b"listener restart")
        host = "127.0.0.1"
        with socket.socket() as probe:
            probe.bind((host, 0))
            port = probe.getsockname()[1]
        first_server = TransferServer(
            tmp_path / "received",
            home=tmp_path / "bob-home",
            host=host,
            port=port,
        )
        await first_server.start()
        offer = await first_server.create_offer()
        await first_server.close()

        async with TransferServer(
            tmp_path / "received",
            home=tmp_path / "bob-home",
            host=host,
            port=port,
        ) as restarted:
            async with TransferClient(home=tmp_path / "alice-home") as client:
                operation = await client.send_file(source, offer)
                receipt = await operation.result()
            received = await restarted.receive(timeout_s=2)

        assert receipt.verified
        assert received.transfer_id == receipt.transfer_id
        assert (tmp_path / "received" / "restart.bin").read_bytes() == b"listener restart"

    asyncio.run(run())


def test_streaming_transfer_memory_is_bounded_below_file_size(tmp_path):
    async def run() -> None:
        import tracemalloc

        source = tmp_path / "stream.bin"
        with source.open("wb") as output:
            for _ in range(512):
                output.write(b"x" * 65536)
        file_size = source.stat().st_size
        tracemalloc.start()
        try:
            async with TransferServer(
                tmp_path / "received",
                home=tmp_path / "bob-home",
                timeout_s=30,
            ) as server:
                offer = await server.create_offer()
                async with TransferClient(home=tmp_path / "alice-home", timeout_s=30) as client:
                    operation = await client.send_file(source, offer, chunk_size=65536)
                    receipt = await operation.result()
                await server.receive(timeout_s=5)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        assert receipt.file_size == file_size
        assert peak < file_size // 2
        assert (tmp_path / "received" / "stream.bin").stat().st_size == file_size

    asyncio.run(run())


def test_resume_refuses_source_changed_after_acknowledged_interruption(tmp_path):
    async def run() -> None:
        source = tmp_path / "mutable.bin"
        source.write_bytes(b"A" * (MIN_CHUNK_SIZE * 3))
        async with TransferServer(
            tmp_path / "received",
            home=tmp_path / "bob-home",
            timeout_s=10,
        ) as server:
            offer = await server.create_offer()
            async with TransferClient(home=tmp_path / "alice-home", timeout_s=10) as client:
                first = await client.send_file(source, offer, chunk_size=MIN_CHUNK_SIZE)
                async for event in first.events():
                    if event.kind is TransferEventKind.PROGRESS:
                        await first.cancel()
                        break
                source.write_bytes(b"B" * (MIN_CHUNK_SIZE * 3))
                resumed = await client.resume(first.transfer_id)
                with pytest.raises(TransferFailure) as error:
                    await resumed.result()

        assert error.value.code is TransferErrorCode.INTEGRITY_FAILED
        assert not (tmp_path / "received" / "mutable.bin").exists()

    asyncio.run(run())


def test_async_stream_source_spools_privately_and_cleans_up_after_completion(tmp_path):
    async def run() -> None:
        async def chunks():
            yield b"streamed "
            yield b"file\x00\xff"

        async with TransferServer(
            tmp_path / "received",
            home=tmp_path / "bob-home",
        ) as server:
            offer = await server.create_offer()
            async with TransferClient(home=tmp_path / "alice-home") as client:
                operation = await client.send_stream(
                    chunks(),
                    offer,
                    file_name="stream.bin",
                    chunk_size=MIN_CHUNK_SIZE,
                )
                receipt = await operation.result()
            await server.receive(timeout_s=2)

        assert receipt.verified
        assert (tmp_path / "received" / "stream.bin").read_bytes() == b"streamed file\x00\xff"
        assert not list((tmp_path / "alice-home" / "outgoing").glob("*"))

    asyncio.run(run())


def test_async_stream_source_enforces_offer_size_before_network_transfer(tmp_path):
    async def run() -> None:
        async def chunks():
            yield b"abc"
            yield b"def"

        async with TransferServer(
            tmp_path / "received",
            home=tmp_path / "bob-home",
            max_file_size=4,
        ) as server:
            offer = await server.create_offer()
            async with TransferClient(home=tmp_path / "alice-home") as client:
                with pytest.raises(TransferFailure) as error:
                    await client.send_stream(chunks(), offer, file_name="too-large.bin")

        assert error.value.code is TransferErrorCode.POLICY_BLOCKED
        assert not list((tmp_path / "alice-home" / "outgoing").glob("*"))
        assert not (tmp_path / "received" / "too-large.bin").exists()

    asyncio.run(run())
