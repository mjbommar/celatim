#!/usr/bin/env python3
"""Coordinate repeated native-protocol marquee trials on two staged lab hosts.

This controller runs locally. Each remote host must already contain the same Celatim
Docker image and a writable ``REMOTE_ROOT/results`` directory. Public result files hold
only payload hashes and endpoint metadata; generated payload bytes remain in the remote
staging directory and are overwritten for every trial.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import socket
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROJECT_SRC = PROJECT_ROOT / "src"
if PROJECT_SRC.exists():
    sys.path.insert(0, str(PROJECT_SRC))

from native_marquee import SUPPORTED_MECHANISMS  # noqa: E402

from celatim.catalog import load_mechanisms  # noqa: E402
from celatim.channel.framer import Framer  # noqa: E402
from celatim.channel.registry import codec_for  # noqa: E402
from celatim.resources import catalog_path  # noqa: E402

SCHEMA_VERSION = "celatim.native_marquee_campaign.v1"
TRIAL_SCHEMA_VERSION = "celatim.native_marquee_trial.v1"
RUNNER_IN_IMAGE = "/work/celatim/experiments/native_marquee.py"
READY_TIMEOUT_S = 15.0
TRIAL_TIMEOUT_S = 30.0


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _json_bytes(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()


def _payload(size: int, repetition: int) -> bytes:
    seed = f"celatim-native-marquee-v1\0{size}\0{repetition}".encode()
    return hashlib.shake_256(seed).digest(size)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _mechanisms() -> dict[str, Any]:
    with catalog_path() as path:
        return {item.id: item for item in load_mechanisms(path)}


def _symbol_count(mechanism: Any, payload: bytes) -> int:
    return len(Framer(codec_for(mechanism)).encode(payload))


class Remote:
    def __init__(self, host: str, remote_root: str, image: str, ssh: str, docker: str) -> None:
        self.host = host
        self.remote_root = remote_root
        self.image = image
        self.ssh = ssh
        self.docker = docker

    def run(
        self,
        command: str,
        *,
        input_bytes: bytes | None = None,
        timeout_s: float | None = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        result = subprocess.run(
            [self.ssh, self.host, command],
            input=input_bytes,
            capture_output=True,
            timeout=timeout_s,
            check=False,
        )
        if check and result.returncode != 0:
            raise RuntimeError(
                f"{self.host}: command failed rc={result.returncode}: {command}\n"
                f"stdout={result.stdout.decode(errors='replace')}\n"
                f"stderr={result.stderr.decode(errors='replace')}"
            )
        return result

    def popen(self, command: str) -> subprocess.Popen[str]:
        return subprocess.Popen(
            [self.ssh, self.host, command],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

    def result_host_path(self, name: str) -> str:
        return f"{self.remote_root}/results/{name}"

    @staticmethod
    def result_container_path(name: str) -> str:
        return f"/results/{name}"

    def docker_command(
        self,
        argv: Sequence[str],
        *,
        name: str | None = None,
    ) -> str:
        parts = [*shlex.split(self.docker), "run", "--rm"]
        if name is not None:
            parts.extend(("--name", name))
        parts.extend(
            (
                "--network",
                "host",
                "-v",
                f"{self.remote_root}/results:/results",
                self.image,
                *argv,
            )
        )
        return " ".join(shlex.quote(part) for part in parts)

    def read_json(self, name: str) -> dict[str, Any]:
        result = self.run(f"cat {shlex.quote(self.result_host_path(name))}", check=True)
        return json.loads(result.stdout)

    def write_payload(self, name: str, payload: bytes) -> None:
        command = f"cat > {shlex.quote(self.result_host_path(name))}"
        self.run(command, input_bytes=payload, check=True)

    def remove_results(self, *names: str) -> None:
        paths = " ".join(shlex.quote(self.result_host_path(name)) for name in names)
        self.run(f"rm -f {paths}", check=True)

    def metadata(self) -> dict[str, Any]:
        script = (
            "set -eu; "
            'printf \'{"hostname":"%s","kernel":"%s","machine":"%s",\' '
            '"$(hostname)" "$(uname -r)" "$(uname -m)"; '
            'printf \'"docker_version":"%s","image_id":"%s"}\\n\' '
            f'"$({self.docker} version --format {{{{.Server.Version}}}})" '
            f'"$({self.docker} image inspect --format {{{{.Id}}}} {shlex.quote(self.image)})"'
        )
        result = self.run(script, check=True)
        return json.loads(result.stdout)


def _validate_pair(
    *,
    sender_doc: dict[str, Any],
    receiver_doc: dict[str, Any],
    sender_node: str,
    receiver_node: str,
    payload_sha256: str,
    expected_symbols: int,
    source_revision: str,
) -> list[str]:
    failures: list[str] = []
    if sender_node == receiver_node:
        failures.append("sender_and_receiver_labels_not_distinct")
    checks = {
        "sender_not_ok": sender_doc.get("ok") is True,
        "receiver_not_ok": receiver_doc.get("ok") is True,
        "sender_topology_not_cross_host": sender_doc.get("topology_kind") == "cross_host",
        "receiver_topology_not_cross_host": receiver_doc.get("topology_kind") == "cross_host",
        "sender_node_mismatch": sender_doc.get("sender", {}).get("node") == sender_node,
        "receiver_node_mismatch": receiver_doc.get("receiver", {}).get("node") == receiver_node,
        "sender_peer_label_mismatch": sender_doc.get("receiver_node") == receiver_node,
        "receiver_peer_label_mismatch": receiver_doc.get("sender_node") == sender_node,
        "sender_payload_hash_mismatch": sender_doc.get("payload_sha256") == payload_sha256,
        "receiver_payload_hash_mismatch": (
            receiver_doc.get("recovered_payload_sha256") == payload_sha256
        ),
        "receiver_not_exact": receiver_doc.get("exact_recovery") is True,
        "sender_symbol_count_mismatch": sender_doc.get("carrier_units") == expected_symbols,
        "receiver_symbol_count_mismatch": (
            receiver_doc.get("observed_symbols") == expected_symbols
        ),
        "sender_response_validation_incomplete": (
            sender_doc.get("response_validation_complete") is True
        ),
        "sender_revision_mismatch": sender_doc.get("source_revision") == source_revision,
        "receiver_revision_mismatch": receiver_doc.get("source_revision") == source_revision,
    }
    failures.extend(label for label, passed in checks.items() if not passed)
    return failures


class Campaign:
    def __init__(
        self,
        *,
        hosts: tuple[Remote, Remote],
        output_dir: Path,
        source_revision: str,
        payload_sizes: Sequence[int],
        repetitions: int,
        mechanism_ids: Sequence[str],
        directions: str,
    ) -> None:
        self.hosts = hosts
        self.output_dir = output_dir
        self.raw_dir = output_dir / "raw"
        self.source_revision = source_revision
        self.payload_sizes = tuple(payload_sizes)
        self.repetitions = repetitions
        self.mechanism_ids = tuple(mechanism_ids)
        self.directions = directions
        self.catalog = _mechanisms()
        self.trials: list[dict[str, Any]] = []

    def _directions(self) -> tuple[tuple[Remote, Remote], ...]:
        forward = (self.hosts,)
        if self.directions == "forward":
            return forward
        return (*forward, (self.hosts[1], self.hosts[0]))

    def _write_campaign(self, *, completed: bool, host_metadata: dict[str, Any]) -> None:
        counts = Counter("pass" if trial.get("ok") else "fail" for trial in self.trials)
        document = {
            "schema_version": SCHEMA_VERSION,
            "source_revision": self.source_revision,
            "completed": completed,
            "generated_at": _utc_now(),
            "payload_generation": "SHAKE256(celatim-native-marquee-v1\\0size\\0repetition)",
            "payload_sizes": list(self.payload_sizes),
            "repetitions": self.repetitions,
            "directions": self.directions,
            "mechanisms": list(self.mechanism_ids),
            "hosts": host_metadata,
            "trial_count": len(self.trials),
            "pass_count": counts["pass"],
            "fail_count": counts["fail"],
            "required_pass": completed and counts["fail"] == 0,
            "trials": self.trials,
        }
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "campaign.json").write_bytes(_json_bytes(document))

    def run(self) -> int:
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        host_metadata = {remote.host: remote.metadata() for remote in self.hosts}
        self._write_campaign(completed=False, host_metadata=host_metadata)
        for sender, receiver in self._directions():
            receiver_ip = socket.gethostbyname(receiver.host)
            for mechanism_id in self.mechanism_ids:
                mechanism = self.catalog[mechanism_id]
                for size in self.payload_sizes:
                    for repetition in range(1, self.repetitions + 1):
                        payload = _payload(size, repetition)
                        trial = self._run_trial(
                            sender=sender,
                            receiver=receiver,
                            receiver_ip=receiver_ip,
                            mechanism=mechanism,
                            payload=payload,
                            repetition=repetition,
                        )
                        self.trials.append(trial)
                        self._write_campaign(completed=False, host_metadata=host_metadata)
                        state = "pass" if trial["ok"] else "FAIL"
                        print(
                            f"[{state}] {trial['trial_id']} ({len(self.trials)} completed)",
                            flush=True,
                        )
        self._write_campaign(completed=True, host_metadata=host_metadata)
        return 0 if all(trial["ok"] for trial in self.trials) else 1

    def _run_trial(
        self,
        *,
        sender: Remote,
        receiver: Remote,
        receiver_ip: str,
        mechanism: Any,
        payload: bytes,
        repetition: int,
    ) -> dict[str, Any]:
        size = len(payload)
        trial_id = f"{sender.host}-to-{receiver.host}-{mechanism.id}-b{size}-r{repetition}"
        slug = hashlib.sha256(trial_id.encode()).hexdigest()[:16]
        payload_name = f"native-{slug}.payload.bin"
        ready_name = f"native-{slug}.ready.json"
        receiver_name = f"native-{slug}.receiver.json"
        sender_name = f"native-{slug}.sender.json"
        container_name = f"celatim-native-{slug}"
        payload_hash = _sha256(payload)
        expected_symbols = _symbol_count(mechanism, payload)
        started = time.monotonic()
        receiver_process: subprocess.Popen[str] | None = None
        try:
            sender.write_payload(payload_name, payload)
            receiver.remove_results(ready_name, receiver_name)
            sender.remove_results(sender_name)
            receiver_command = receiver.docker_command(
                [
                    "python",
                    RUNNER_IN_IMAGE,
                    "receiver",
                    "--mechanism",
                    mechanism.id,
                    "--bind",
                    "0.0.0.0",
                    "--port",
                    "0",
                    "--expected-symbols",
                    str(expected_symbols),
                    "--expected-payload-len",
                    str(size),
                    "--expected-payload-sha256",
                    payload_hash,
                    "--sender-node",
                    sender.host,
                    "--endpoint-node",
                    receiver.host,
                    "--source-revision",
                    self.source_revision,
                    "--topology-kind",
                    "cross_host",
                    "--ready-file",
                    receiver.result_container_path(ready_name),
                    "--output",
                    receiver.result_container_path(receiver_name),
                ],
                name=container_name,
            )
            receiver_process = receiver.popen(receiver_command)
            ready = self._wait_ready(receiver, ready_name, receiver_process)
            sender_command = sender.docker_command(
                [
                    "python",
                    RUNNER_IN_IMAGE,
                    "sender",
                    "--mechanism",
                    mechanism.id,
                    "--host",
                    receiver_ip,
                    "--port",
                    str(ready["port"]),
                    "--payload-file",
                    sender.result_container_path(payload_name),
                    "--receiver-node",
                    receiver.host,
                    "--endpoint-node",
                    sender.host,
                    "--source-revision",
                    self.source_revision,
                    "--topology-kind",
                    "cross_host",
                    "--output",
                    sender.result_container_path(sender_name),
                ]
            )
            sender_result = sender.run(sender_command, timeout_s=TRIAL_TIMEOUT_S)
            receiver_output, _ = receiver_process.communicate(timeout=TRIAL_TIMEOUT_S)
            sender_doc = sender.read_json(sender_name)
            receiver_doc = receiver.read_json(receiver_name)
            failures = _validate_pair(
                sender_doc=sender_doc,
                receiver_doc=receiver_doc,
                sender_node=sender.host,
                receiver_node=receiver.host,
                payload_sha256=payload_hash,
                expected_symbols=expected_symbols,
                source_revision=self.source_revision,
            )
            if sender_result.returncode != 0:
                failures.append(f"sender_process_rc_{sender_result.returncode}")
            if receiver_process.returncode != 0:
                failures.append(f"receiver_process_rc_{receiver_process.returncode}")
            (self.raw_dir / f"{trial_id}.sender.json").write_bytes(_json_bytes(sender_doc))
            (self.raw_dir / f"{trial_id}.receiver.json").write_bytes(_json_bytes(receiver_doc))
            return {
                "schema_version": TRIAL_SCHEMA_VERSION,
                "trial_id": trial_id,
                "mechanism_id": mechanism.id,
                "sender_node": sender.host,
                "receiver_node": receiver.host,
                "payload_len": size,
                "payload_sha256": payload_hash,
                "carrier_units": expected_symbols,
                "repetition": repetition,
                "sender_artifact": f"raw/{trial_id}.sender.json",
                "receiver_artifact": f"raw/{trial_id}.receiver.json",
                "sender_process_stderr": sender_result.stderr.decode(errors="replace").strip(),
                "receiver_process_output": receiver_output.strip(),
                "elapsed_s": time.monotonic() - started,
                "failures": failures,
                "ok": not failures,
            }
        except Exception as exc:
            if receiver_process is not None and receiver_process.poll() is None:
                receiver.run(f"{receiver.docker} rm -f {shlex.quote(container_name)}")
                receiver_process.terminate()
                receiver_process.communicate(timeout=5)
            return {
                "schema_version": TRIAL_SCHEMA_VERSION,
                "trial_id": trial_id,
                "mechanism_id": mechanism.id,
                "sender_node": sender.host,
                "receiver_node": receiver.host,
                "payload_len": size,
                "payload_sha256": payload_hash,
                "carrier_units": expected_symbols,
                "repetition": repetition,
                "elapsed_s": time.monotonic() - started,
                "failures": [f"{type(exc).__name__}: {exc}"],
                "ok": False,
            }
        finally:
            sender.remove_results(payload_name)

    @staticmethod
    def _wait_ready(
        receiver: Remote,
        ready_name: str,
        process: subprocess.Popen[str],
    ) -> dict[str, Any]:
        deadline = time.monotonic() + READY_TIMEOUT_S
        while time.monotonic() < deadline:
            result = receiver.run(
                f"cat {shlex.quote(receiver.result_host_path(ready_name))} 2>/dev/null"
            )
            if result.returncode == 0 and result.stdout:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    pass
            if process.poll() is not None:
                output, _ = process.communicate()
                raise RuntimeError(f"receiver exited before readiness: {output.strip()}")
            time.sleep(0.05)
        raise TimeoutError(f"receiver readiness timed out after {READY_TIMEOUT_S}s")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alice", required=True)
    parser.add_argument("--bob", required=True)
    parser.add_argument("--remote-root", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--payload-sizes", type=int, nargs="+", default=(1, 16, 64, 256))
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--directions", choices=("forward", "both"), default="both")
    parser.add_argument(
        "--mechanism",
        action="append",
        dest="mechanisms",
        choices=SUPPORTED_MECHANISMS,
    )
    parser.add_argument("--ssh", default="ssh")
    parser.add_argument("--docker", default="docker")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.alice == args.bob:
        raise SystemExit("--alice and --bob must identify distinct hosts")
    if args.repetitions < 1:
        raise SystemExit("--repetitions must be positive")
    if any(size < 1 for size in args.payload_sizes):
        raise SystemExit("--payload-sizes must all be positive")
    hosts = (
        Remote(args.alice, args.remote_root, args.image, args.ssh, args.docker),
        Remote(args.bob, args.remote_root, args.image, args.ssh, args.docker),
    )
    campaign = Campaign(
        hosts=hosts,
        output_dir=args.output_dir,
        source_revision=args.source_revision,
        payload_sizes=args.payload_sizes,
        repetitions=args.repetitions,
        mechanism_ids=args.mechanisms or SUPPORTED_MECHANISMS,
        directions=args.directions,
    )
    return campaign.run()


if __name__ == "__main__":
    raise SystemExit(main())
