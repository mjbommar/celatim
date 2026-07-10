"""Safe file sinks and durable receiver chunk behavior."""

from __future__ import annotations

import hashlib
import os

import pytest

from celatim.transfer import (
    DEFAULT_CHUNK_SIZE,
    ReceiverFile,
    TransferErrorCode,
    TransferFailure,
    TransferManifest,
    TransferOffer,
    TransferStateStore,
    TransferStatus,
    choose_destination,
    sanitize_file_name,
)


def _offer() -> TransferOffer:
    return TransferOffer.create(
        host="127.0.0.1",
        port=8443,
        tls_cert_sha256="a" * 64,
        providers=("tcp-tls",),
        max_file_size=10 * DEFAULT_CHUNK_SIZE,
    )


def test_sanitize_file_name_preserves_safe_names_and_rejects_paths():
    assert sanitize_file_name("report 2026.pdf") == "report 2026.pdf"
    assert sanitize_file_name("resume.txt") == "resume.txt"

    for unsafe in ("", ".", "..", "../report", "a/b", "a\\b", "nul", "CON.txt", "x\x00y"):
        with pytest.raises(TransferFailure) as error:
            sanitize_file_name(unsafe)
        assert error.value.code is TransferErrorCode.INPUT_INVALID


def test_choose_destination_fails_or_renames_without_overwrite(tmp_path):
    existing = tmp_path / "report.pdf"
    existing.write_bytes(b"existing")

    with pytest.raises(TransferFailure, match="already exists"):
        choose_destination(tmp_path, "report.pdf")

    assert choose_destination(tmp_path, "report.pdf", collision="rename") == (
        tmp_path / "report (1).pdf"
    )
    assert existing.read_bytes() == b"existing"


def test_receiver_file_durably_writes_out_of_order_chunks_and_finalizes(tmp_path):
    payload = b"A" * DEFAULT_CHUNK_SIZE + b"\x00\xfftail"
    source = tmp_path / "source.bin"
    source.write_bytes(payload)
    offer = _offer()
    manifest = TransferManifest.from_path(
        source,
        offer_id=offer.offer_id,
        provider="tcp-tls",
    )
    store = TransferStateStore(tmp_path / "home")
    incoming = tmp_path / "incoming"
    receiver = ReceiverFile.create(store, manifest, offer.to_json(), incoming)
    first = payload[:DEFAULT_CHUNK_SIZE]
    second = payload[DEFAULT_CHUNK_SIZE:]

    receiver.write_chunk(1, second, hashlib.sha256(second).digest())
    receiver.write_chunk(0, first, hashlib.sha256(first).digest())
    receiver.write_chunk(0, first, hashlib.sha256(first).digest())
    destination = receiver.finalize()

    assert destination == incoming / "source.bin"
    assert destination.read_bytes() == payload
    assert not (incoming / f".celatim-{manifest.transfer_id}.part").exists()
    state = store.read_state(manifest.transfer_id, "receiver")
    assert state.status is TransferStatus.COMPLETED
    assert state.acknowledged_chunks == (0, 1)


def test_receiver_file_rejects_wrong_digest_and_retains_private_partial(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"integrity")
    offer = _offer()
    manifest = TransferManifest.from_path(
        source,
        offer_id=offer.offer_id,
        provider="tcp-tls",
    )
    store = TransferStateStore(tmp_path / "home")
    receiver = ReceiverFile.create(store, manifest, offer.to_json(), tmp_path / "incoming")

    with pytest.raises(TransferFailure) as error:
        receiver.write_chunk(0, b"integrity", b"\x00" * 32)

    assert error.value.code is TransferErrorCode.INTEGRITY_FAILED
    assert receiver.spool_path.exists()
    assert store.read_state(manifest.transfer_id, "receiver").acknowledged_chunks == ()


def test_receiver_does_not_acknowledge_chunk_when_durable_write_fails(tmp_path, monkeypatch):
    source = tmp_path / "source.bin"
    source.write_bytes(b"disk full")
    offer = _offer()
    manifest = TransferManifest.from_path(
        source,
        offer_id=offer.offer_id,
        provider="tcp-tls",
    )
    store = TransferStateStore(tmp_path / "home")
    receiver = ReceiverFile.create(store, manifest, offer.to_json(), tmp_path / "incoming")

    def fail_fsync(descriptor: int) -> None:
        del descriptor
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fsync", fail_fsync)
    payload = source.read_bytes()
    with pytest.raises(TransferFailure) as error:
        receiver.write_chunk(0, payload, hashlib.sha256(payload).digest())

    assert error.value.code is TransferErrorCode.STORAGE_FAILED
    assert error.value.resumable
    assert store.read_state(manifest.transfer_id, "receiver").acknowledged_chunks == ()
