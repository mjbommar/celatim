"""Product-oriented `celatim transfer` command surface."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from functools import partial
from pathlib import Path
from typing import Any

from .carrier import AfpacketCarrierProvider, CarrierEndpointConfig
from .client import TransferClient, TransferOperation
from .direct import DirectTlsProvider
from .errors import TransferErrorCode, TransferFailure
from .listener import (
    clear_listener_status,
    load_listener_status,
    stop_listener,
    write_listener_status,
)
from .models import DEFAULT_CHUNK_SIZE, TransferEvent, TransferEventKind, TransferOffer
from .packet_service import (
    PacketService,
    packet_service_preflight,
    packet_service_systemd_unit,
    raw_packet_handler,
)
from .providers import ProviderRegistry
from .server import TransferServer
from .state import TransferStateStore


def add_transfer_parser(subparsers: argparse._SubParsersAction) -> None:
    transfer = subparsers.add_parser("transfer", help="Send and receive authenticated files.")
    commands = transfer.add_subparsers(dest="transfer_command", required=True)

    listen = commands.add_parser("listen", help="Create an offer and receive files.")
    listen.add_argument("--output-dir", type=Path, required=True)
    listen.add_argument("--home", type=Path)
    listen.add_argument("--host", default="127.0.0.1")
    listen.add_argument("--port", type=_port, default=0)
    listen.add_argument("--advertise-host")
    listen.add_argument("--expires-in-s", type=_positive_int, default=900)
    listen.add_argument("--idle-timeout-s", type=_positive_float, default=900.0)
    listen.add_argument("--connection-timeout-s", type=_positive_float, default=60.0)
    listen.add_argument("--max-file-size", type=_positive_int, default=1024 * 1024 * 1024)
    listen.add_argument("--max-concurrent", type=_positive_int, default=4)
    listen.add_argument("--max-transfers", type=_positive_int, default=1)
    listen.add_argument("--collision", choices=("fail", "rename"), default="fail")
    listen.add_argument("--receiver-label")
    listen.add_argument("--offer-out", type=Path)
    listen.add_argument("--carrier-config", type=Path, action="append", default=[])
    listen.add_argument("--format", choices=("human", "jsonl"), default="human")

    send = commands.add_parser("send", help="Send one file using a receiver offer.")
    send.add_argument("path", type=Path)
    destination = send.add_mutually_exclusive_group(required=True)
    destination.add_argument("--to", dest="offer")
    destination.add_argument("--to-file", type=Path)
    _add_sender_options(send)

    resume = commands.add_parser("resume", help="Resume one interrupted transfer.")
    resume.add_argument("transfer_id")
    resume.add_argument("--home", type=Path)
    resume.add_argument("--timeout-s", type=_positive_float, default=60.0)
    resume.add_argument("--max-retries", type=_nonnegative_int, default=2)
    resume.add_argument("--retry-backoff-s", type=_nonnegative_float, default=0.25)
    resume.add_argument("--carrier-config", type=Path, action="append", default=[])
    resume.add_argument("--format", choices=("human", "json", "jsonl"), default="human")

    status = commands.add_parser("status", help="Show local sender and receiver state.")
    status.add_argument("--home", type=Path)
    status.add_argument("--format", choices=("human", "json"), default="human")

    stop = commands.add_parser("stop", help="Stop the registered CLI transfer listener.")
    stop.add_argument("--home", type=Path)
    stop.add_argument("--format", choices=("human", "json"), default="human")

    inspect = commands.add_parser("inspect-offer", help="Inspect an offer with secrets redacted.")
    source = inspect.add_mutually_exclusive_group(required=True)
    source.add_argument("--offer")
    source.add_argument("--file", type=Path)
    inspect.add_argument("--format", choices=("human", "json"), default="human")

    providers = commands.add_parser("providers", help="List installed transfer providers.")
    providers.add_argument("--format", choices=("human", "json"), default="human")

    packet = commands.add_parser("packet-service", help="Manage privileged packet I/O.")
    packet_commands = packet.add_subparsers(dest="packet_service_command", required=True)
    packet_serve = packet_commands.add_parser("serve", help="Run the local packet service.")
    _add_packet_service_policy(packet_serve)
    packet_serve.add_argument("--packet-timeout-s", type=_positive_float, default=10.0)
    packet_serve.add_argument("--batch-frame-rate", type=_positive_float, default=2_000.0)
    packet_serve.add_argument("--max-concurrent", type=_positive_int, default=16)
    packet_serve.add_argument("--request-timeout-s", type=_positive_float, default=30.0)
    packet_preflight = packet_commands.add_parser(
        "preflight", help="Inspect packet-service configuration."
    )
    _add_packet_service_policy(packet_preflight)
    packet_preflight.add_argument("--format", choices=("human", "json"), default="human")
    packet_unit = packet_commands.add_parser("unit", help="Generate a hardened systemd unit.")
    _add_packet_service_policy(packet_unit)
    packet_unit.add_argument("--user", required=True)
    packet_unit.add_argument("--executable", type=Path, default=Path(sys.argv[0]).resolve())


def run_transfer_command(args: argparse.Namespace) -> int:
    try:
        if args.transfer_command == "listen":
            return asyncio.run(_listen(args))
        if args.transfer_command == "send":
            return asyncio.run(_send(args))
        if args.transfer_command == "resume":
            return asyncio.run(_resume(args))
        if args.transfer_command == "status":
            return _status(args)
        if args.transfer_command == "stop":
            return _stop(args)
        if args.transfer_command == "inspect-offer":
            return _inspect_offer(args)
        if args.transfer_command == "providers":
            return _providers(args)
        if args.transfer_command == "packet-service":
            return asyncio.run(_packet_service(args))
    except TransferFailure as exc:
        if getattr(args, "format", "human") in {"json", "jsonl"}:
            sys.stderr.write(json.dumps(exc.to_json(), sort_keys=True) + "\n")
        else:
            sys.stderr.write(f"Transfer failed [{exc.code.value}]: {exc.detail}\n")
            sys.stderr.write(f"Next action: {exc.to_json()['next_action']}\n")
        return 2
    raise AssertionError(f"unknown transfer command: {args.transfer_command}")


def _add_sender_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--home", type=Path)
    parser.add_argument("--provider")
    parser.add_argument("--allow-fallback", action="store_true")
    parser.add_argument("--chunk-size", type=_positive_int, default=DEFAULT_CHUNK_SIZE)
    parser.add_argument("--timeout-s", type=_positive_float, default=60.0)
    parser.add_argument("--max-retries", type=_nonnegative_int, default=2)
    parser.add_argument("--retry-backoff-s", type=_nonnegative_float, default=0.25)
    parser.add_argument("--carrier-config", type=Path, action="append", default=[])
    parser.add_argument("--format", choices=("human", "json", "jsonl"), default="human")


def _add_packet_service_policy(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--allow-provider", action="append", required=True)
    parser.add_argument("--allow-interface", action="append", required=True)
    parser.add_argument("--allow-uid", action="append", type=int, required=True)


async def _listen(args: argparse.Namespace) -> int:
    async with TransferServer(
        args.output_dir,
        home=args.home,
        host=args.host,
        port=args.port,
        advertise_host=args.advertise_host,
        max_file_size=args.max_file_size,
        max_concurrent=args.max_concurrent,
        timeout_s=args.connection_timeout_s,
        collision=args.collision,
        carrier_receivers=_carrier_configs(args),
    ) as server:
        store = TransferStateStore(args.home)
        write_listener_status(
            store,
            host=server.address.host,
            port=server.address.port,
            output_dir=args.output_dir,
        )
        try:
            for _ in range(args.max_transfers):
                offer = await server.create_offer(
                    expires_in_s=args.expires_in_s,
                    receiver_label=args.receiver_label,
                )
                if args.offer_out is not None:
                    _write_private_text(args.offer_out, offer.to_uri() + "\n")
                if args.format == "jsonl":
                    _write_stdout(
                        {
                            "event": "ready",
                            "offer": offer.to_json(),
                            "offer_uri": offer.to_uri(),
                        }
                    )
                else:
                    sys.stdout.write(f"Ready: {offer.to_uri()}\n")
                    sys.stdout.write(f"Listening until {offer.to_json()['expires_at']}\n")
                    sys.stdout.flush()
                receipt = await server.receive(timeout_s=args.idle_timeout_s)
                if args.format == "jsonl":
                    _write_stdout({"event": "completed", "receipt": receipt.to_json()})
                else:
                    sys.stdout.write(f"Saved: {receipt.path}\n")
                    sys.stdout.write("Complete: authenticated and verified\n")
                    sys.stdout.flush()
        finally:
            clear_listener_status(store, pid=os.getpid())
    return 0


async def _send(args: argparse.Namespace) -> int:
    offer = _offer_from_args(args)
    async with TransferClient(
        home=args.home,
        registry=_carrier_registry(args),
        timeout_s=args.timeout_s,
        max_retries=args.max_retries,
        retry_backoff_s=args.retry_backoff_s,
    ) as client:
        operation = await client.send_file(
            args.path,
            offer,
            provider=args.provider,
            allow_fallback=args.allow_fallback,
            chunk_size=args.chunk_size,
        )
        receipt = await _render_operation(operation, args.format)
    if args.format == "json":
        _write_stdout(receipt.to_json(include_path=False))
    elif args.format == "human":
        sys.stdout.write(
            f"Complete: {receipt.file_size} bytes, authenticated, acknowledged, and verified\n"
        )
    return 0


async def _resume(args: argparse.Namespace) -> int:
    async with TransferClient(
        home=args.home,
        registry=_carrier_registry(args),
        timeout_s=args.timeout_s,
        max_retries=args.max_retries,
        retry_backoff_s=args.retry_backoff_s,
    ) as client:
        operation = await client.resume(args.transfer_id)
        receipt = await _render_operation(operation, args.format)
    if args.format == "json":
        _write_stdout(receipt.to_json(include_path=False))
    elif args.format == "human":
        sys.stdout.write(
            f"Complete: {receipt.file_size} bytes, authenticated, acknowledged, and verified\n"
        )
    return 0


async def _render_operation(operation: TransferOperation, output_format: str):
    async def consume_events() -> None:
        async for event in operation.events():
            if output_format == "jsonl":
                _write_stdout(event.to_json())
            elif output_format == "human":
                _render_human_event(event)

    consumer = asyncio.create_task(consume_events())
    try:
        receipt = await operation.result()
        await consumer
        if output_format == "jsonl":
            _write_stdout(receipt.to_json(include_path=False))
        return receipt
    finally:
        if not consumer.done():
            consumer.cancel()


def _render_human_event(event: TransferEvent) -> None:
    if event.kind is TransferEventKind.PROGRESS and event.total_bytes:
        percentage = event.bytes_transferred * 100 / event.total_bytes
        sys.stderr.write(
            f"\rSending {event.bytes_transferred}/{event.total_bytes} bytes ({percentage:.1f}%)"
        )
        if event.bytes_transferred >= event.total_bytes:
            sys.stderr.write("\n")
        sys.stderr.flush()
    elif event.kind is TransferEventKind.STATE and event.message:
        sys.stderr.write(f"{event.message}\n")
        sys.stderr.flush()


def _status(args: argparse.Namespace) -> int:
    store = TransferStateStore(args.home)
    states = store.list_states()
    listener = load_listener_status(store)
    if args.format == "json":
        _write_stdout(
            {
                "schema_version": "celatim.transfer_status.v1",
                "listener": None if listener is None else listener.to_json(redact_private=True),
                "transfer_count": len(states),
                "transfers": [record.to_json(redact_private=True) for record in states],
            }
        )
        return 0
    if listener is not None:
        sys.stdout.write(
            f"Listener: {'active' if listener.active else 'stale'} "
            f"on {listener.host}:{listener.port}\n"
        )
    if not states and listener is None:
        sys.stdout.write("No local transfers.\n")
        return 0
    for record in states:
        acknowledged = len(record.acknowledged_chunks)
        total = record.manifest.chunk_count
        sys.stdout.write(
            f"{record.transfer_id}  {record.role}  {record.status.value}  "
            f"{acknowledged}/{total} chunks  {record.manifest.file_name}\n"
        )
    return 0


def _stop(args: argparse.Namespace) -> int:
    status = stop_listener(TransferStateStore(args.home))
    if args.format == "json":
        _write_stdout(
            {
                "schema_version": "celatim.transfer_listener_stop.v1",
                "pid": status.pid,
                "stopped": True,
            }
        )
    else:
        sys.stdout.write(f"Stopped transfer listener process {status.pid}.\n")
    return 0


def _inspect_offer(args: argparse.Namespace) -> int:
    raw = args.offer if args.offer is not None else args.file.read_text().strip()
    offer = TransferOffer.parse(raw)
    document = offer.to_json(redact_secret=True)
    if args.format == "json":
        _write_stdout(document)
    else:
        sys.stdout.write(f"Offer: {offer.offer_id}\n")
        sys.stdout.write(f"Receiver: {offer.receiver_label or '[unverified label not provided]'}\n")
        sys.stdout.write(f"Endpoint: {offer.host}:{offer.port}\n")
        sys.stdout.write(f"Trust: {offer.trust_mode.value}\n")
        sys.stdout.write(f"Expires: {document['expires_at']}\n")
        sys.stdout.write(f"Providers: {', '.join(offer.providers)}\n")
    return 0


def _providers(args: argparse.Namespace) -> int:
    registry = ProviderRegistry((DirectTlsProvider(),))
    registry.discover()
    manifests = registry.manifests()
    if args.format == "json":
        _write_stdout(
            {
                "schema_version": "celatim.provider_inventory.v1",
                "providers": [manifest.to_json() for manifest in manifests],
                "load_failures": {
                    name: failure.to_json() for name, failure in registry.failures.items()
                },
            }
        )
    else:
        for manifest in manifests:
            sys.stdout.write(
                f"{manifest.name}  {manifest.evidence_level.value}  "
                f"resumable={str(manifest.resumable).lower()}\n"
            )
    return 0


async def _packet_service(args: argparse.Namespace) -> int:
    providers = set(args.allow_provider)
    interfaces = set(args.allow_interface)
    allowed_uids = set(args.allow_uid)
    if args.packet_service_command == "preflight":
        document = packet_service_preflight(
            args.socket,
            providers=providers,
            interfaces=interfaces,
            allowed_uids=allowed_uids,
        )
        if args.format == "json":
            _write_stdout(document)
        else:
            sys.stdout.write(
                f"Packet service ready: {str(document['ready']).lower()}\n"
                f"Socket: {document['socket_path']}\n"
                f"Providers: {', '.join(document['allowed_providers'])}\n"
                f"Interfaces: {', '.join(document['allowed_interfaces'])}\n"
            )
        return 0 if document["ready"] else 2
    if args.packet_service_command == "unit":
        sys.stdout.write(
            packet_service_systemd_unit(
                executable=args.executable,
                user=args.user,
                socket_path=args.socket,
                providers=providers,
                interfaces=interfaces,
                allowed_uids=allowed_uids,
            )
        )
        return 0
    handler = partial(
        raw_packet_handler,
        timeout_s=args.packet_timeout_s,
        batch_frame_rate_hz=args.batch_frame_rate,
    )
    async with PacketService(
        args.socket,
        handler,
        allowed_uids=allowed_uids,
        allowed_providers=providers,
        allowed_interfaces=interfaces,
        max_concurrent=args.max_concurrent,
        timeout_s=args.request_timeout_s,
    ):
        await asyncio.Event().wait()
    return 0


def _offer_from_args(args: argparse.Namespace) -> TransferOffer:
    if args.offer is not None:
        return TransferOffer.parse(args.offer)
    return TransferOffer.parse(args.to_file.read_text().strip())


def _carrier_configs(args: argparse.Namespace) -> tuple[CarrierEndpointConfig, ...]:
    try:
        return tuple(CarrierEndpointConfig.load(path) for path in args.carrier_config)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise TransferFailure(
            code=TransferErrorCode.INPUT_INVALID,
            detail=f"could not load carrier configuration: {exc}",
        ) from exc


def _carrier_registry(args: argparse.Namespace) -> ProviderRegistry | None:
    configs = _carrier_configs(args)
    if not configs:
        return None
    registry = ProviderRegistry(
        (DirectTlsProvider(), *(AfpacketCarrierProvider(config) for config in configs))
    )
    registry.discover()
    return registry


def _write_stdout(document: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(document, sort_keys=True) + "\n")
    sys.stdout.flush()


def _write_private_text(path: Path, content: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return parsed


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return parsed


def _nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return parsed


def _nonnegative_float(value: str) -> float:
    parsed = float(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return parsed


def _port(value: str) -> int:
    parsed = int(value)
    if not 0 <= parsed <= 65535:
        raise argparse.ArgumentTypeError("must be between 0 and 65535")
    return parsed


__all__ = ["add_transfer_parser", "run_transfer_command"]
