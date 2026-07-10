#!/usr/bin/env python3
"""Controller and in-container helpers for reproducible Alice/Bob cross-host runs.

The top-level shell script stages the repository and Docker image on both hosts. This
module then runs as a controller on the machine where the script was launched, while
also providing small helper subcommands that run inside the staged container.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import socket
import struct
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MEASUREMENT_SRC = Path(__file__).resolve().parents[2] / "src"
if MEASUREMENT_SRC.exists():
    sys.path.insert(0, str(MEASUREMENT_SRC))

from celatim.analysis.crosshost_metrics import (  # noqa: E402
    METRICS_SCHEMA_VERSION,
    MechanismMetricInput,
    carrier_lengths_from_envelope,
    metric_record,
    metrics_summary,
    packet_method_wire_bytes,
)

RUNNER_IN_IMAGE = "/work/measurement/experiments/crosshost/alice_bob_runner.py"
CATALOG_IN_IMAGE = "/work/measurement/data/mechanisms.jsonl"
LOCAL_CATALOG = Path("measurement/data/mechanisms.jsonl")
VXLAN_UNDERLAY_OVERHEAD_NO_FCS_BYTES = 50
MESSAGE_QNAME = "covert.example."
MESSAGE_CARRIER_MECHS = {
    "dns-txt-tunnel": "dns_txt_dnspython",
    "dns-null-tunnel": "dns_null_dnspython",
    "ssh-kexinit-cookie": "ssh_kexinit_paramiko",
    "coap-tunnel": "coap_aiocoap",
    "websocket-tunnel": "websocket_websockets",
    "bgp-optional-transitive": "bgp_scapy",
}


def _json_print(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def _load_mechanisms(catalog: str | Path = CATALOG_IN_IMAGE) -> list[Any]:
    from celatim.catalog import load_mechanisms

    return load_mechanisms(Path(catalog))


def _usable_mechanisms(catalog: str | Path = CATALOG_IN_IMAGE) -> list[Any]:
    return [m for m in _load_mechanisms(catalog) if m.is_usable_channel]


def _mechanism_ids(kind: str, catalog: str | Path = CATALOG_IN_IMAGE) -> list[str]:
    from celatim.adapter import adapter_for

    usable = _usable_mechanisms(catalog)
    if kind == "all-usable":
        return [m.id for m in usable]
    if kind == "packet":
        return [m.id for m in usable if adapter_for(m).supports_transport("afpacket_ipv4")]
    if kind == "non-packet":
        return [m.id for m in usable if not adapter_for(m).supports_transport("afpacket_ipv4")]
    if kind == "message":
        present = {m.id for m in usable}
        return [m for m in MESSAGE_CARRIER_MECHS if m in present]
    raise ValueError(f"unknown mechanism set: {kind}")


def _catalog_metadata(catalog: Path = LOCAL_CATALOG) -> dict[str, dict[str, Any]]:
    if not catalog.exists():
        return {}
    out: dict[str, dict[str, Any]] = {}
    for line in catalog.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        row = json.loads(stripped)
        out[str(row["id"])] = {
            "raw_capacity_bits": int(row["raw_capacity_bits"]),
            "carrier_unit": str(row["carrier_unit"]),
            "protocol": str(row["protocol"]),
        }
    return out


def _packet_config(mechanism_id: str) -> dict[str, Any]:
    from celatim.testbed.packet_path import default_ipv4_packet_path_config_for

    cfg = default_ipv4_packet_path_config_for(mechanism_id)
    return {
        "protocol": cfg.protocol.value,
        "dst_port": cfg.dst_port,
    }


def _send_framed(sock: socket.socket, obj: dict[str, Any]) -> None:
    blob = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(blob)) + blob)


def _recv_framed(sock: socket.socket) -> dict[str, Any]:
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            raise ConnectionError("connection closed before frame header")
        header += chunk
    size = struct.unpack(">I", header)[0]
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise ConnectionError("connection closed before frame body")
        buf += chunk
    return json.loads(buf.decode())


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except TypeError, ValueError:
        return None


def _number_or_none(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(value)
    except TypeError, ValueError:
        return None


def _mapping_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def cmd_list_mechanisms(args: argparse.Namespace) -> int:
    _json_print(_mechanism_ids(args.set, args.catalog))
    return 0


def cmd_packet_config(args: argparse.Namespace) -> int:
    _json_print(_packet_config(args.mechanism))
    return 0


def cmd_message_server(args: argparse.Namespace) -> int:
    from celatim.channel.framer import Framer
    from celatim.channel.registry import codec_for
    from celatim.testbed.message_carrier import MESSAGE_CARRIER_KINDS

    mechanisms = {m.id: m for m in _load_mechanisms(args.catalog)}
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.bind, args.port))
    server.listen(16)
    print(f"message server listening on {args.bind}:{args.port}", flush=True)

    handled = 0
    while args.max_connections is None or handled < args.max_connections:
        conn, peer = server.accept()
        try:
            request = _recv_framed(conn)
            mechanism_id = request["mechanism"]
            spec = MESSAGE_CARRIER_KINDS[MESSAGE_CARRIER_MECHS[mechanism_id]]
            wires = [bytes.fromhex(w) for w in request["wires"]]
            symbols = [spec.parse(wire) for wire in wires]
            framer = Framer(codec_for(mechanisms[mechanism_id]))
            recovered = framer.decode(symbols)
            _send_framed(
                conn,
                {
                    "ok": True,
                    "mechanism": mechanism_id,
                    "recovered_hex": recovered.hex(),
                    "node": socket.gethostname(),
                    "peer": peer[0],
                    "server_role": spec.server_role,
                    "independent_validator": spec.independent_validator,
                },
            )
        except Exception as exc:
            _send_framed(conn, {"ok": False, "error": f"{type(exc).__name__}: {exc}"})
        finally:
            conn.close()
            handled += 1
    return 0


def cmd_message_client(args: argparse.Namespace) -> int:
    from celatim.channel.framer import Framer
    from celatim.channel.registry import codec_for
    from celatim.testbed.message_carrier import MESSAGE_CARRIER_KINDS

    mechanisms = {m.id: m for m in _load_mechanisms(args.catalog)}
    payload = Path(args.payload_file).read_bytes()
    payload_sha256 = hashlib.sha256(payload).hexdigest()
    chosen = args.mechanism or _mechanism_ids("message", args.catalog)
    results: list[dict[str, Any]] = []
    for mechanism_id in chosen:
        spec = MESSAGE_CARRIER_KINDS[MESSAGE_CARRIER_MECHS[mechanism_id]]
        framer = Framer(codec_for(mechanisms[mechanism_id]))
        symbols = framer.encode(payload)
        started = time.monotonic()
        try:
            wires = [spec.build(symbol, MESSAGE_QNAME) for symbol in symbols]
            with socket.create_connection((args.host, args.port), timeout=args.timeout_s) as sock:
                _send_framed(
                    sock,
                    {
                        "mechanism": mechanism_id,
                        "wires": [wire.hex() for wire in wires],
                    },
                )
                response = _recv_framed(sock)
            elapsed_s = time.monotonic() - started
            recovered = bytes.fromhex(response.get("recovered_hex", ""))
            recovered_sha256 = hashlib.sha256(recovered).hexdigest()
            ok = bool(response.get("ok")) and recovered == payload
            results.append(
                {
                    "mechanism": mechanism_id,
                    "result": "pass" if ok else "fail",
                    "wire_count": len(wires),
                    "server": response.get("node"),
                    "server_role": response.get("server_role"),
                    "independent_validator": response.get("independent_validator"),
                    "server_ok": response.get("ok"),
                    "expected_len": len(payload),
                    "recovered_len": len(recovered),
                    "wire_bytes": sum(len(wire) for wire in wires),
                    "expected_sha256": payload_sha256,
                    "recovered_sha256": recovered_sha256,
                    "elapsed_s": elapsed_s,
                    "error": response.get("error"),
                }
            )
        except Exception as exc:
            results.append(
                {
                    "mechanism": mechanism_id,
                    "result": "fail",
                    "elapsed_s": time.monotonic() - started,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )

    output = {"results": results, "pass": sum(r["result"] == "pass" for r in results)}
    if args.output:
        Path(args.output).write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    else:
        _json_print(output)
    return 0 if all(r["result"] == "pass" for r in results) else 1


@dataclass(frozen=True)
class RemoteConfig:
    host: str
    remote_root: str
    image: str
    ssh: str
    docker: str


class Controller:
    def __init__(
        self,
        *,
        alice: RemoteConfig,
        bob: RemoteConfig,
        output_dir: Path,
        payload: bytes,
        alice_vx_ip: str,
        bob_vx_ip: str,
        alice_vx_mac: str,
        bob_vx_mac: str,
        vxlan_dev: str,
        message_port: int,
        receiver_ready_s: float,
        packet_timeout_s: float,
        unit_rate_hz: float,
        packet_backend: str,
        message_backend: str,
    ) -> None:
        self.alice = alice
        self.bob = bob
        self.output_dir = output_dir
        self.payload = payload
        self.payload_sha256 = hashlib.sha256(payload).hexdigest()
        self.alice_vx_ip = alice_vx_ip
        self.bob_vx_ip = bob_vx_ip
        self.alice_vx_mac = alice_vx_mac
        self.bob_vx_mac = bob_vx_mac
        self.vxlan_dev = vxlan_dev
        self.message_port = message_port
        self.receiver_ready_s = receiver_ready_s
        self.packet_timeout_s = packet_timeout_s
        self.unit_rate_hz = unit_rate_hz
        self.packet_backend = packet_backend
        self.message_backend = message_backend
        self.mechanism_metadata = _catalog_metadata()

    def ssh_run(
        self,
        remote: RemoteConfig,
        command: str,
        *,
        input_bytes: bytes | None = None,
        timeout_s: float | None = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        result = subprocess.run(
            [remote.ssh, remote.host, command],
            input=input_bytes,
            capture_output=True,
            timeout=timeout_s,
            check=False,
        )
        if check and result.returncode != 0:
            raise RuntimeError(
                f"{remote.host}: command failed rc={result.returncode}\n"
                f"cmd={command}\nstdout={result.stdout.decode(errors='replace')}\n"
                f"stderr={result.stderr.decode(errors='replace')}"
            )
        return result

    def ssh_popen(self, remote: RemoteConfig, command: str) -> subprocess.Popen[str]:
        return subprocess.Popen(
            [remote.ssh, remote.host, command],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

    def docker_command(
        self,
        remote: RemoteConfig,
        argv: Sequence[str],
        *,
        privileged: bool = False,
        remove: bool = True,
        detach: bool = False,
        name: str | None = None,
    ) -> str:
        parts = [*shlex.split(remote.docker), "run"]
        if remove:
            parts.append("--rm")
        if detach:
            parts.append("-d")
        if name:
            parts.extend(["--name", name])
        if privileged:
            parts.append("--privileged")
        parts.extend(
            [
                "--network",
                "host",
                "-v",
                f"{remote.remote_root}/results:/results",
                remote.image,
            ]
        )
        parts.extend(argv)
        return " ".join(shlex.quote(p) for p in parts)

    def docker_run(
        self,
        remote: RemoteConfig,
        argv: Sequence[str],
        *,
        privileged: bool = False,
        input_bytes: bytes | None = None,
        timeout_s: float | None = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        return self.ssh_run(
            remote,
            self.docker_command(remote, argv, privileged=privileged),
            input_bytes=input_bytes,
            timeout_s=timeout_s,
            check=check,
        )

    def host_python_command(
        self,
        remote: RemoteConfig,
        argv: Sequence[str],
        *,
        sudo: bool = False,
    ) -> str:
        mapped = list(argv)
        if mapped[0] in {"python", "python3"}:
            mapped[0] = "python3"
        elif mapped[0] == "celatim":
            mapped = [
                "python3",
                "-c",
                "from celatim.cli import session_main; raise SystemExit(session_main())",
                *mapped[1:],
            ]
        pythonpath = (
            f"{remote.remote_root}/repo/measurement/src:"
            f"{remote.remote_root}/host-python/site-packages"
        )
        parts = ["env", "PYTHONDONTWRITEBYTECODE=1", f"PYTHONPATH={pythonpath}", *mapped]
        if sudo:
            parts = ["sudo", "-n", *parts]
        command = " ".join(shlex.quote(p) for p in parts)
        return f"cd {shlex.quote(remote.remote_root + '/repo')} && {command}"

    def host_python_run(
        self,
        remote: RemoteConfig,
        argv: Sequence[str],
        *,
        sudo: bool = False,
        input_bytes: bytes | None = None,
        timeout_s: float | None = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        return self.ssh_run(
            remote,
            self.host_python_command(remote, argv, sudo=sudo),
            input_bytes=input_bytes,
            timeout_s=timeout_s,
            check=check,
        )

    def host_python_popen(
        self,
        remote: RemoteConfig,
        argv: Sequence[str],
        *,
        sudo: bool = False,
    ) -> subprocess.Popen[str]:
        return self.ssh_popen(remote, self.host_python_command(remote, argv, sudo=sudo))

    def packet_run(
        self,
        remote: RemoteConfig,
        argv: Sequence[str],
        *,
        privileged: bool = False,
        timeout_s: float | None = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        if self.packet_backend == "docker":
            return self.docker_run(
                remote,
                argv,
                privileged=privileged,
                timeout_s=timeout_s,
                check=check,
            )
        if self.packet_backend == "host-python":
            return self.host_python_run(
                remote,
                argv,
                sudo=privileged,
                timeout_s=timeout_s,
                check=check,
            )
        raise ValueError(f"unknown packet backend: {self.packet_backend}")

    def packet_popen(
        self,
        remote: RemoteConfig,
        argv: Sequence[str],
        *,
        privileged: bool = False,
    ) -> subprocess.Popen[str]:
        if self.packet_backend == "docker":
            return self.ssh_popen(
                remote,
                self.docker_command(remote, argv, privileged=privileged),
            )
        if self.packet_backend == "host-python":
            return self.host_python_popen(remote, argv, sudo=privileged)
        raise ValueError(f"unknown packet backend: {self.packet_backend}")

    def packet_result_path(self, remote: RemoteConfig, name: str) -> str:
        if self.packet_backend == "docker":
            return f"/results/{name}"
        return f"{remote.remote_root}/results/{name}"

    def payload_path(self, remote: RemoteConfig, backend: str) -> str:
        if backend == "docker":
            return "/results/payload.bin"
        return f"{remote.remote_root}/results/payload.bin"

    def helper_runner_path(self, backend: str) -> str:
        return (
            RUNNER_IN_IMAGE
            if backend == "docker"
            else "measurement/experiments/crosshost/alice_bob_runner.py"
        )

    def message_run(
        self,
        remote: RemoteConfig,
        argv: Sequence[str],
        *,
        timeout_s: float | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        if self.message_backend == "docker":
            return self.docker_run(remote, argv, timeout_s=timeout_s)
        if self.message_backend == "host-python":
            return self.host_python_run(remote, argv, timeout_s=timeout_s)
        raise ValueError(f"unknown message backend: {self.message_backend}")

    def message_popen(self, remote: RemoteConfig, argv: Sequence[str]) -> subprocess.Popen[str]:
        if self.message_backend == "docker":
            return self.ssh_popen(remote, self.docker_command(remote, argv))
        if self.message_backend == "host-python":
            return self.host_python_popen(remote, argv)
        raise ValueError(f"unknown message backend: {self.message_backend}")

    def list_mechanisms(self, kind: str) -> list[str]:
        result = self.docker_run(
            self.alice,
            ["python", RUNNER_IN_IMAGE, "list-mechanisms", "--set", kind],
            check=True,
        )
        return json.loads(result.stdout.decode())

    def packet_config(self, mechanism_id: str) -> dict[str, Any]:
        runner_path = self.helper_runner_path(self.packet_backend)
        result = self.packet_run(
            self.alice,
            ["python", runner_path, "packet-config", "--mechanism", mechanism_id],
            check=True,
        )
        return json.loads(result.stdout.decode())

    def packet_frame_count(self, mechanism_id: str) -> int:
        result = self.packet_run(
            self.alice,
            [
                "celatim",
                "send",
                "--mechanism",
                mechanism_id,
                "--file",
                self.payload_path(self.alice, self.packet_backend),
                "--session-id",
                f"dry-{mechanism_id}",
            ],
            check=True,
        )
        return int(json.loads(result.stdout.decode())["carrier_units"])

    def packet_receive_timeout_s(self, frame_count: int) -> float:
        scheduled = frame_count / self.unit_rate_hz if self.unit_rate_hz > 0 else 0.0
        return max(self.packet_timeout_s, scheduled + self.receiver_ready_s + 20.0)

    def packet_command_timeout_s(self, frame_count: int) -> float:
        scheduled = frame_count / self.unit_rate_hz if self.unit_rate_hz > 0 else 0.0
        return max(120.0, scheduled + self.receiver_ready_s + 60.0)

    def run_packet_suite(self, mechanisms: Sequence[str]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for index, mechanism_id in enumerate(mechanisms, 1):
            print(f"[packet {index:03}/{len(mechanisms):03}] {mechanism_id}", flush=True)
            record = self.run_packet_mechanism(mechanism_id)
            results.append(record)
            print(f"  -> {record['result']} {record.get('reason', '')}", flush=True)
        return results

    def run_packet_mechanism(self, mechanism_id: str) -> dict[str, Any]:
        try:
            count = self.packet_frame_count(mechanism_id)
            cfg = self.packet_config(mechanism_id)
        except Exception as exc:
            return {"mechanism": mechanism_id, "result": "skip", "reason": f"dry-run: {exc}"}

        session_id = f"ab-{mechanism_id}"
        alice_output_name = f"packet-send-{mechanism_id}.json"
        bob_output_name = f"packet-{mechanism_id}.json"
        bob_output = self.packet_result_path(self.bob, bob_output_name)
        receive_timeout_s = self.packet_receive_timeout_s(count)
        command_timeout_s = self.packet_command_timeout_s(count)
        common = [
            "--mechanism",
            mechanism_id,
            "--session-id",
            session_id,
            "--afpacket-protocol",
            str(cfg["protocol"]),
            "--afpacket-src-mac",
            self.alice_vx_mac,
            "--afpacket-dst-mac",
            self.bob_vx_mac,
            "--afpacket-src-ip",
            self.alice_vx_ip,
            "--afpacket-dst-ip",
            self.bob_vx_ip,
            "--afpacket-src-port",
            "40000",
            "--afpacket-dst-port",
            str(cfg["dst_port"]),
        ]
        recv_argv = [
            "celatim",
            "recv",
            "--afpacket-ipv4",
            *common,
            "--expected-frames",
            str(count),
            "--afpacket-receiver-interface",
            self.vxlan_dev,
            "--afpacket-timeout-s",
            str(receive_timeout_s),
            # The receiver runs on bob; the sender (alice) is a separate host
            # reachable over the VXLAN overlay. Record the true two-host identity
            # rather than the default same_process / local-only endpoint metadata.
            "--endpoint-cross-host",
            "--endpoint-sender-node",
            self.alice.host,
            "--endpoint-sender-ip",
            self.alice_vx_ip,
            "--endpoint-sender-mac",
            self.alice_vx_mac,
            "--endpoint-receiver-node",
            self.bob.host,
            "--endpoint-receiver-ip",
            self.bob_vx_ip,
            "--endpoint-receiver-mac",
            self.bob_vx_mac,
            "--output",
            bob_output,
        ]
        recv = self.packet_popen(self.bob, recv_argv, privileged=True)
        time.sleep(self.receiver_ready_s)

        send_argv = [
            "celatim",
            "send",
            "--afpacket-ipv4",
            *common,
            "--file",
            self.payload_path(self.alice, self.packet_backend),
            "--afpacket-sender-interface",
            self.vxlan_dev,
            "--unit-rate-hz",
            str(self.unit_rate_hz),
            "--output",
            self.packet_result_path(self.alice, alice_output_name),
        ]
        send = self.packet_run(
            self.alice,
            send_argv,
            privileged=True,
            timeout_s=command_timeout_s,
        )
        try:
            recv.wait(timeout=receive_timeout_s + 15)
        except subprocess.TimeoutExpired:
            recv.kill()
        recv_output = recv.stdout.read() if recv.stdout else ""

        send_doc: dict[str, Any] | None = None
        send_cat = self.ssh_run(
            self.alice,
            f"cat {shlex.quote(self.remote_result_file(self.alice, alice_output_name))}",
        )
        if send_cat.returncode == 0:
            try:
                send_doc = json.loads(send_cat.stdout.decode())
            except Exception:
                send_doc = None

        cat = self.ssh_run(
            self.bob,
            f"cat {shlex.quote(self.remote_result_file(self.bob, bob_output_name))}",
        )
        if cat.returncode != 0:
            return {
                "mechanism": mechanism_id,
                "result": "fail",
                "reason": "no receiver JSON",
                "frames": count,
                "send_rc": send.returncode,
                "recv_rc": recv.returncode,
                "recv_output": recv_output[-800:],
                "send_stderr": send.stderr.decode(errors="replace")[-800:],
                "metrics": self.metric_for_packet(
                    mechanism_id,
                    result="fail",
                    send_doc=send_doc,
                    recv_doc=None,
                ),
            }
        try:
            doc = json.loads(cat.stdout.decode())
            recovered = bytes.fromhex(doc["recovered_hex"])
            ok = recovered == self.payload and doc.get("evidence", {}).get("ok") is True
        except Exception as exc:
            return {
                "mechanism": mechanism_id,
                "result": "fail",
                "reason": f"receiver JSON parse: {exc}",
                "frames": count,
                "metrics": self.metric_for_packet(
                    mechanism_id,
                    result="fail",
                    send_doc=send_doc,
                    recv_doc=None,
                ),
            }
        result = "pass" if ok else "fail"
        return {
            "mechanism": mechanism_id,
            "result": result,
            "frames": count,
            "payload_len": len(self.payload),
            "expected_sha256": self.payload_sha256,
            "protocol": cfg["protocol"],
            "dst_port": cfg["dst_port"],
            "receiver_node": (
                doc.get("evidence", {}).get("endpoint_os", {}).get("receiver", {}).get("node")
            ),
            "recovered_sha256": doc.get("recovered_sha256"),
            "evidence_ok": doc.get("evidence", {}).get("ok"),
            "metrics": self.metric_for_packet(
                mechanism_id,
                result=result,
                send_doc=send_doc,
                recv_doc=doc,
            ),
        }

    def run_envelope_suite(self, mechanisms: Sequence[str]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for index, mechanism_id in enumerate(mechanisms, 1):
            print(f"[envelope {index:03}/{len(mechanisms):03}] {mechanism_id}", flush=True)
            record = self.run_envelope_mechanism(mechanism_id)
            results.append(record)
            print(f"  -> {record['result']} {record.get('reason', '')}", flush=True)
        return results

    def run_envelope_mechanism(self, mechanism_id: str) -> dict[str, Any]:
        send_started = time.monotonic()
        send = self.docker_run(
            self.alice,
            [
                "celatim",
                "send",
                "--mechanism",
                mechanism_id,
                "--file",
                self.payload_path(self.alice, "docker"),
                "--session-id",
                f"env-{mechanism_id}",
            ],
            timeout_s=120,
        )
        send_elapsed_s = time.monotonic() - send_started
        send_doc: dict[str, Any] | None = None
        if send.returncode != 0:
            return {
                "mechanism": mechanism_id,
                "result": "fail",
                "reason": send.stderr.decode(errors="replace")[-800:],
                "metrics": self.metric_for_envelope(
                    mechanism_id,
                    result="fail",
                    send_doc=None,
                    recv_doc=None,
                    harness_send_elapsed_s=send_elapsed_s,
                ),
            }
        try:
            send_doc = json.loads(send.stdout.decode())
        except Exception:
            send_doc = None
        remote_rx = f"{self.bob.remote_root}/results/envelope-rx-{mechanism_id}.json"
        remote_rec = f"{self.bob.remote_root}/results/envelope-rec-{mechanism_id}.json"
        bob_cmd = (
            f"cat > {shlex.quote(remote_rx)} && "
            + self.docker_command(
                self.bob,
                [
                    "celatim",
                    "recv",
                    "--input",
                    f"/results/envelope-rx-{mechanism_id}.json",
                    "--output",
                    f"/results/envelope-rec-{mechanism_id}.json",
                ],
            )
            + f" && cat {shlex.quote(remote_rec)}"
        )
        recv_started = time.monotonic()
        recv = self.ssh_run(self.bob, bob_cmd, input_bytes=send.stdout, timeout_s=120)
        recv_elapsed_s = time.monotonic() - recv_started
        if recv.returncode != 0:
            return {
                "mechanism": mechanism_id,
                "result": "fail",
                "reason": recv.stderr.decode(errors="replace")[-800:],
                "metrics": self.metric_for_envelope(
                    mechanism_id,
                    result="fail",
                    send_doc=send_doc,
                    recv_doc=None,
                    harness_send_elapsed_s=send_elapsed_s,
                    harness_recv_elapsed_s=recv_elapsed_s,
                ),
            }
        try:
            doc = json.loads(recv.stdout.decode())
            recovered = bytes.fromhex(doc["recovered_hex"])
            ok = recovered == self.payload and doc.get("evidence", {}).get("ok") is True
        except Exception as exc:
            return {
                "mechanism": mechanism_id,
                "result": "fail",
                "reason": f"parse: {exc}",
                "metrics": self.metric_for_envelope(
                    mechanism_id,
                    result="fail",
                    send_doc=send_doc,
                    recv_doc=None,
                    harness_send_elapsed_s=send_elapsed_s,
                    harness_recv_elapsed_s=recv_elapsed_s,
                ),
            }
        result = "pass" if ok else "fail"
        return {
            "mechanism": mechanism_id,
            "result": result,
            "payload_len": len(self.payload),
            "expected_sha256": self.payload_sha256,
            "carrier_units": doc.get("evidence", {}).get("carrier_units"),
            "carrier_units_with_bytes": doc.get("carrier_units_with_bytes"),
            "evidence_bucket": doc.get("evidence", {}).get("evidence_bucket"),
            "recovered_sha256": doc.get("recovered_sha256"),
            "evidence_ok": doc.get("evidence", {}).get("ok"),
            "metrics": self.metric_for_envelope(
                mechanism_id,
                result=result,
                send_doc=send_doc,
                recv_doc=doc,
                harness_send_elapsed_s=send_elapsed_s,
                harness_recv_elapsed_s=recv_elapsed_s,
            ),
        }

    def run_message_suite(self) -> list[dict[str, Any]]:
        runner_path = self.helper_runner_path(self.message_backend)
        server_argv = [
            "python",
            runner_path,
            "message-server",
            "--port",
            str(self.message_port),
            "--max-connections",
            str(len(MESSAGE_CARRIER_MECHS)),
        ]
        client_argv = [
            "python",
            runner_path,
            "message-client",
            "--host",
            self.bob.host,
            "--port",
            str(self.message_port),
            "--payload-file",
            self.payload_path(self.alice, self.message_backend),
        ]
        if self.message_backend == "host-python":
            server_argv.extend(["--catalog", "measurement/data/mechanisms.jsonl"])
            client_argv.extend(["--catalog", "measurement/data/mechanisms.jsonl"])

        name = f"celatim-message-{int(time.time())}"
        stop_cmd = f"{self.bob.docker} rm -f {shlex.quote(name)} >/dev/null 2>&1 || true"
        server: subprocess.Popen[str] | None = None
        if self.message_backend == "docker":
            self.ssh_run(self.bob, stop_cmd)
            start_cmd = self.docker_command(
                self.bob,
                server_argv,
                remove=False,
                detach=True,
                name=name,
            )
            started = self.ssh_run(self.bob, start_cmd)
            if started.returncode != 0:
                return [
                    {
                        "mechanism": "*",
                        "result": "fail",
                        "reason": started.stderr.decode(errors="replace")[-800:],
                    }
                ]
        else:
            server = self.message_popen(self.bob, server_argv)
        time.sleep(2.0)
        try:
            client = self.message_run(self.alice, client_argv, timeout_s=120)
            if client.stdout:
                payload = json.loads(client.stdout.decode())
                results = payload["results"]
                for record in results:
                    if record.get("mechanism") in MESSAGE_CARRIER_MECHS:
                        record["metrics"] = self.metric_for_message(record)
                return results
            return [
                {
                    "mechanism": "*",
                    "result": "fail",
                    "reason": client.stderr.decode(errors="replace")[-800:],
                }
            ]
        finally:
            if self.message_backend == "docker":
                self.ssh_run(self.bob, stop_cmd)
            elif server is not None:
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.terminate()
                    try:
                        server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()

    def run_negative_suite(self) -> list[dict[str, Any]]:
        results = []
        for role, remote in (("alice", self.alice), ("bob", self.bob)):
            result = self.docker_run(
                remote,
                ["python", "/work/measurement/experiments/run_negatives.py"],
                timeout_s=120,
            )
            results.append(
                {
                    "role": role,
                    "host": remote.host,
                    "result": "pass" if result.returncode == 0 else "fail",
                    "returncode": result.returncode,
                    "stdout_tail": result.stdout.decode(errors="replace")[-2000:],
                    "stderr_tail": result.stderr.decode(errors="replace")[-2000:],
                }
            )
        return results

    def write_json(self, name: str, obj: Any) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / name).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")

    def raw_capacity_bits(self, mechanism_id: str) -> int | None:
        value = self.mechanism_metadata.get(mechanism_id, {}).get("raw_capacity_bits")
        return int(value) if value is not None else None

    def remote_result_file(self, remote: RemoteConfig, name: str) -> str:
        return f"{remote.remote_root}/results/{name}"

    def metric_for_packet(
        self,
        mechanism_id: str,
        *,
        result: str,
        send_doc: dict[str, Any] | None,
        recv_doc: dict[str, Any] | None,
    ) -> dict[str, Any]:
        send_doc = send_doc or {}
        recv_doc = recv_doc or {}
        recv_evidence = _mapping_or_empty(recv_doc.get("evidence"))
        carrier_lengths = carrier_lengths_from_envelope(send_doc)
        carrier_wire_bytes = sum(carrier_lengths) if carrier_lengths else None
        packet_path_value = send_doc.get("packet_path")
        packet_path = packet_path_value if isinstance(packet_path_value, dict) else {}
        protocol = str(packet_path.get("protocol", "tcp"))
        method_wire_bytes = (
            packet_method_wire_bytes(mechanism_id, carrier_lengths, protocol)
            if carrier_lengths
            else None
        )
        vxlan_bytes = (
            method_wire_bytes + len(carrier_lengths) * VXLAN_UNDERLAY_OVERHEAD_NO_FCS_BYTES
            if method_wire_bytes is not None
            else None
        )
        timing = send_doc.get("transport_timing")
        if not isinstance(timing, dict):
            timing = {}
        send_elapsed_s = _number_or_none(timing.get("send_elapsed_s"))
        metric = metric_record(
            MechanismMetricInput(
                mechanism_id=mechanism_id,
                suite="packet",
                result=result,
                payload_bytes=len(self.payload),
                recovered_bytes=_int_or_none(recv_doc.get("payload_len")),
                carrier_units=_int_or_none(send_doc.get("carrier_units"))
                or _int_or_none(recv_evidence.get("carrier_units")),
                raw_capacity_bits=self.raw_capacity_bits(mechanism_id),
                carrier_wire_bytes=carrier_wire_bytes,
                method_wire_bytes=method_wire_bytes,
                method_wire_basis="inner_ethernet_ipv4_l4_no_fcs",
                vxlan_underlay_bytes_no_fcs=vxlan_bytes,
                measured_window_s=send_elapsed_s,
                measured_window_basis=timing.get("measurement_basis"),
                scheduled_unit_rate_hz=_number_or_none(timing.get("scheduled_unit_rate_hz")),
                scheduled_duration_s=_number_or_none(timing.get("scheduled_duration_s")),
                timing_claim_status=(
                    "sender_process_afpacket_send_symbols_exact_recovery"
                    if result == "pass" and send_elapsed_s is not None
                    else "not_measured"
                ),
            )
        )
        metric["packet_wire_bytes"] = {
            "inner_l2_no_fcs": method_wire_bytes,
            "vxlan_underlay_l2_no_fcs": vxlan_bytes,
            "vxlan_overhead_per_frame_no_fcs": VXLAN_UNDERLAY_OVERHEAD_NO_FCS_BYTES,
        }
        if recv_evidence:
            metric["timing"]["receiver_elapsed_s"] = _number_or_none(recv_evidence.get("elapsed_s"))
            metric["timing"]["receiver_elapsed_basis"] = (
                "receiver_process_wait_decode_includes_startup_ready_delay"
            )
        return metric

    def metric_for_envelope(
        self,
        mechanism_id: str,
        *,
        result: str,
        send_doc: dict[str, Any] | None,
        recv_doc: dict[str, Any] | None,
        harness_send_elapsed_s: float | None = None,
        harness_recv_elapsed_s: float | None = None,
    ) -> dict[str, Any]:
        send_doc = send_doc or {}
        recv_doc = recv_doc or {}
        recv_evidence = _mapping_or_empty(recv_doc.get("evidence"))
        carrier_lengths = carrier_lengths_from_envelope(send_doc)
        carrier_wire_bytes = sum(carrier_lengths) if carrier_lengths else None
        metric = metric_record(
            MechanismMetricInput(
                mechanism_id=mechanism_id,
                suite="envelope",
                result=result,
                payload_bytes=len(self.payload),
                recovered_bytes=_int_or_none(recv_doc.get("payload_len")),
                carrier_units=_int_or_none(send_doc.get("carrier_units"))
                or _int_or_none(recv_evidence.get("carrier_units")),
                raw_capacity_bits=self.raw_capacity_bits(mechanism_id),
                carrier_wire_bytes=carrier_wire_bytes,
                method_wire_bytes=carrier_wire_bytes,
                method_wire_basis="protocol_carrier_bytes_from_json_envelope",
                measured_window_s=None,
                measured_window_basis=None,
                scheduled_unit_rate_hz=None,
                scheduled_duration_s=_number_or_none(send_doc.get("scheduled_duration_s")),
                timing_claim_status="artifact_elapsed_not_native_network_goodput",
            )
        )
        metric["timing"]["harness_send_command_elapsed_s"] = harness_send_elapsed_s
        metric["timing"]["harness_recv_command_elapsed_s"] = harness_recv_elapsed_s
        return metric

    def metric_for_message(self, record: dict[str, Any]) -> dict[str, Any]:
        mechanism_id = str(record["mechanism"])
        elapsed_s = _number_or_none(record.get("elapsed_s"))
        return metric_record(
            MechanismMetricInput(
                mechanism_id=mechanism_id,
                suite="message_carrier",
                result=str(record.get("result", "unknown")),
                payload_bytes=len(self.payload),
                recovered_bytes=_int_or_none(record.get("recovered_len")),
                carrier_units=_int_or_none(record.get("wire_count")),
                raw_capacity_bits=self.raw_capacity_bits(mechanism_id),
                carrier_wire_bytes=_int_or_none(record.get("wire_bytes")),
                method_wire_bytes=_int_or_none(record.get("wire_bytes")),
                method_wire_basis="protocol_message_bytes_sent_inside_crosshost_control_tcp",
                measured_window_s=elapsed_s,
                measured_window_basis="message_client_build_tcp_request_response_elapsed_s",
                timing_claim_status=(
                    "crosshost_control_exchange_not_native_protocol_goodput"
                    if elapsed_s is not None
                    else "not_measured"
                ),
            )
        )

    def run(self, args: argparse.Namespace) -> int:
        all_usable = self.list_mechanisms("all-usable")
        packet_mechs = [] if args.skip_packet else self.list_mechanisms("packet")
        non_packet_mechs = self.list_mechanisms("non-packet")

        packet_results = self.run_packet_suite(packet_mechs)
        self.write_json("packet-results.json", packet_results)

        envelope_results = self.run_envelope_suite(non_packet_mechs)
        self.write_json("envelope-results.json", envelope_results)

        message_results = [] if args.skip_message else self.run_message_suite()
        self.write_json("message-results.json", message_results)

        negative_results = [] if args.skip_negative else self.run_negative_suite()
        self.write_json("negative-results.json", negative_results)

        metric_records = [
            metric
            for record in packet_results + envelope_results + message_results
            if isinstance((metric := record.get("metrics")), dict)
        ]

        covered = {
            r["mechanism"] for r in packet_results + envelope_results if r.get("result") == "pass"
        }
        packet_pass = sum(r.get("result") == "pass" for r in packet_results)
        envelope_pass = sum(r.get("result") == "pass" for r in envelope_results)
        message_pass = sum(r.get("result") == "pass" for r in message_results)
        negative_pass = sum(r.get("result") == "pass" for r in negative_results)
        summary = {
            "schema_version": "celatim.alice_bob_crosshost.v1",
            "alice": self.alice.host,
            "bob": self.bob.host,
            "packet_backend": self.packet_backend,
            "message_backend": self.message_backend,
            "payload": {
                "len": len(self.payload),
                "sha256": self.payload_sha256,
            },
            "metrics": {
                "enabled": True,
                "schema_version": METRICS_SCHEMA_VERSION,
                "records": len(metric_records),
                "results": "metrics-results.json",
                "summary": "metrics-summary.json",
            },
            "all_usable": len(all_usable),
            "usable_covered_by_required_suites": len(covered),
            "missing_usable": sorted(set(all_usable) - covered),
            "packet": {
                "enabled": not args.skip_packet,
                "pass": packet_pass,
                "total": len(packet_results),
            },
            "envelope": {
                "pass": envelope_pass,
                "total": len(envelope_results),
            },
            "message_carrier": {
                "enabled": not args.skip_message,
                "pass": message_pass,
                "total": len(message_results),
            },
            "negative": {
                "enabled": not args.skip_negative,
                "pass": negative_pass,
                "total": len(negative_results),
            },
            "required_pass": (
                len(covered) == len(all_usable)
                and packet_pass == len(packet_results)
                and envelope_pass == len(envelope_results)
                and (args.skip_message or message_pass == len(message_results))
                and (args.skip_negative or negative_pass == len(negative_results))
            ),
        }
        metrics_payload = summary["payload"]
        self.write_json(
            "metrics-results.json",
            {
                "schema_version": METRICS_SCHEMA_VERSION,
                "payload": metrics_payload,
                "records": metric_records,
            },
        )
        self.write_json(
            "metrics-summary.json",
            metrics_summary(metric_records, payload=metrics_payload),
        )
        self.write_json("summary.json", summary)
        _json_print(summary)
        return 0 if summary["required_pass"] else 1


def cmd_coordinate(args: argparse.Namespace) -> int:
    controller = Controller(
        alice=RemoteConfig(
            host=args.alice,
            remote_root=args.remote_root,
            image=args.image,
            ssh=args.ssh,
            docker=args.docker,
        ),
        bob=RemoteConfig(
            host=args.bob,
            remote_root=args.remote_root,
            image=args.image,
            ssh=args.ssh,
            docker=args.docker,
        ),
        output_dir=Path(args.output_dir),
        payload=Path(args.payload_file).read_bytes(),
        alice_vx_ip=args.alice_vx_ip,
        bob_vx_ip=args.bob_vx_ip,
        alice_vx_mac=args.alice_vx_mac,
        bob_vx_mac=args.bob_vx_mac,
        vxlan_dev=args.vxlan_dev,
        message_port=args.message_port,
        receiver_ready_s=args.receiver_ready_s,
        packet_timeout_s=args.packet_timeout_s,
        unit_rate_hz=args.unit_rate_hz,
        packet_backend=args.packet_backend,
        message_backend=args.message_backend,
    )
    return controller.run(args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    list_p = sub.add_parser("list-mechanisms")
    list_p.add_argument(
        "--set", choices=["all-usable", "packet", "non-packet", "message"], required=True
    )
    list_p.add_argument("--catalog", default=CATALOG_IN_IMAGE)
    list_p.set_defaults(func=cmd_list_mechanisms)

    cfg_p = sub.add_parser("packet-config")
    cfg_p.add_argument("--mechanism", required=True)
    cfg_p.set_defaults(func=cmd_packet_config)

    server_p = sub.add_parser("message-server")
    server_p.add_argument("--bind", default="0.0.0.0")
    server_p.add_argument("--port", type=int, default=9911)
    server_p.add_argument("--max-connections", type=int)
    server_p.add_argument("--catalog", default=CATALOG_IN_IMAGE)
    server_p.set_defaults(func=cmd_message_server)

    client_p = sub.add_parser("message-client")
    client_p.add_argument("--host", required=True)
    client_p.add_argument("--port", type=int, default=9911)
    client_p.add_argument("--timeout-s", type=float, default=20.0)
    client_p.add_argument("--output")
    client_p.add_argument("--catalog", default=CATALOG_IN_IMAGE)
    client_p.add_argument("--payload-file", required=True)
    client_p.add_argument("mechanism", nargs="*")
    client_p.set_defaults(func=cmd_message_client)

    coord_p = sub.add_parser("coordinate")
    coord_p.add_argument("--alice", required=True)
    coord_p.add_argument("--bob", required=True)
    coord_p.add_argument("--remote-root", required=True)
    coord_p.add_argument("--image", required=True)
    coord_p.add_argument("--output-dir", required=True)
    coord_p.add_argument("--payload-file", required=True)
    coord_p.add_argument("--vxlan-dev", required=True)
    coord_p.add_argument("--alice-vx-ip", required=True)
    coord_p.add_argument("--bob-vx-ip", required=True)
    coord_p.add_argument("--alice-vx-mac", required=True)
    coord_p.add_argument("--bob-vx-mac", required=True)
    coord_p.add_argument("--message-port", type=int, default=9911)
    coord_p.add_argument("--receiver-ready-s", type=float, default=4.0)
    coord_p.add_argument("--packet-timeout-s", type=float, default=45.0)
    coord_p.add_argument("--unit-rate-hz", type=float, default=800.0)
    coord_p.add_argument("--packet-backend", choices=["docker", "host-python"], default="docker")
    coord_p.add_argument("--message-backend", choices=["docker", "host-python"], default="docker")
    coord_p.add_argument("--ssh", default="ssh")
    coord_p.add_argument("--docker", default="docker")
    coord_p.add_argument("--skip-packet", action="store_true")
    coord_p.add_argument("--skip-message", action="store_true")
    coord_p.add_argument("--skip-negative", action="store_true")
    coord_p.set_defaults(func=cmd_coordinate)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
