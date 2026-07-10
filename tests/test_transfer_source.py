"""Stable sender source identity and public input validation."""

from __future__ import annotations

import asyncio

import pytest

from celatim.transfer import (
    MIN_CHUNK_SIZE,
    StableSourceFile,
    TransferClient,
    TransferErrorCode,
    TransferFailure,
    TransferServer,
)


def test_stable_source_rejects_symlinks_and_detects_in_place_mutation(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"A" * MIN_CHUNK_SIZE)
    link = tmp_path / "link.bin"
    link.symlink_to(source)

    with pytest.raises(TransferFailure) as symlink_error:
        StableSourceFile.open(link)
    assert symlink_error.value.code is TransferErrorCode.INPUT_INVALID

    with StableSourceFile.open(source) as opened:
        manifest = opened.create_manifest(
            offer_id="00000000-0000-4000-8000-000000000001",
            provider="tcp-tls",
            chunk_size=MIN_CHUNK_SIZE,
        )
        source.write_bytes(b"B" * MIN_CHUNK_SIZE)
        with pytest.raises(TransferFailure) as mutation_error:
            opened.read_chunk(manifest, 0)
    assert mutation_error.value.code is TransferErrorCode.INTEGRITY_FAILED


def test_transfer_client_rejects_invalid_chunk_size_before_starting_operation(tmp_path):
    async def run() -> None:
        source = tmp_path / "source.bin"
        source.write_bytes(b"payload")
        async with TransferServer(
            tmp_path / "received",
            home=tmp_path / "bob-home",
        ) as server:
            offer = await server.create_offer()
            async with TransferClient(home=tmp_path / "alice-home") as client:
                with pytest.raises(TransferFailure) as error:
                    await client.send_file(source, offer, chunk_size=1024)

        assert error.value.code is TransferErrorCode.INPUT_INVALID
        assert not (tmp_path / "alice-home" / "transfers").exists()

    asyncio.run(run())
