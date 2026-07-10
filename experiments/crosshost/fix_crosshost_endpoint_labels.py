#!/usr/bin/env python3
"""One-off corrector for the cross-host AF_PACKET endpoint-identity mislabel.

Background
----------
Cross-host Alice/Bob AF_PACKET runs recorded the receiver's local endpoint metadata
with ``topology_kind="same_process"`` and ``independent_receiver_os=false``, and copied
the *receiver's* platform identity into the *sender* block as well -- so each AF_PACKET
receiver record showed ``sender.node == receiver.node`` (the receiver's own hostname),
even though the run was genuinely two-host (Alice and Bob on separate machines, real
frames over a VXLAN overlay).

Root cause: ``celatim.session.local_endpoint_os()`` defaults
``topology_kind="same_process"`` and samples only the local (receiver) platform for both
endpoints, and the runner never overrode it with the true two-host identity. The code has
since been fixed (``cross_host_endpoint_os`` + runner wiring); this script re-stamps the
*already produced* evidence to its TRUE value.

What this corrects -- and what it does NOT touch
-----------------------------------------------
This re-stamps ONLY topology/endpoint-identity labels on AF_PACKET receiver records
(``transport == "afpacket_ipv4"``):

  * ``evidence.endpoint_os.topology_kind``:        same_process -> cross_host
  * ``evidence.endpoint_os.independent_receiver_os``: false     -> true
  * ``evidence.endpoint_os.sender``: the receiver's platform was wrongly copied here;
    replace it with the remote sender's (Alice's) TRUE identity -- node set to Alice's
    real hostname, remote platform fields blanked (the receiver never observed them),
    source = "remote_peer_reported", interface = the run's real src_ip/src_mac.

The receiver block is left exactly as recorded -- it already holds Bob's true local
platform identity (the only correct part of the original record).

NO measured value is altered: recovered SHAs, recovered_hex, payload hashes, recovered
byte counts, carrier units/capacities, timings, packet_path, and pass/fail are untouched.

Hostname recovery (no fabrication)
----------------------------------
Each run's ``summary.json`` records the short aliases ``alice`` / ``bob`` (e.g. "s6",
"s7"). The TRUE per-host hostnames are recovered purely from observed data already in the
artifacts, from two independent sources, and only the alias actually observed is used:

  * the receiver.node in that host's AF_PACKET records (Bob's ``platform.node()``), and
  * the ``server`` node in message-results.json (the message server runs on Bob).

Both consistently yield ``s6 -> server6`` and ``s7 -> server7``. The corrector requires
each host's true hostname to be observed in the corpus before re-stamping; it never
guesses one.

Usage
-----
    python3 fix_crosshost_endpoint_labels.py [--artifacts-root PATH] [--apply]

Without ``--apply`` it runs as a dry run and prints what it would change.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ARTIFACTS_ROOT = REPO_ROOT / "artifacts" / "alice-bob"

BAD_TOPOLOGY_KIND = "same_process"
GOOD_TOPOLOGY_KIND = "cross_host"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _serialize_record(doc: Any) -> str:
    """Match the CLI's on-disk convention: compact, sort_keys, trailing newline."""
    return json.dumps(doc, sort_keys=True) + "\n"


def _find_summary(run_dir: Path) -> dict[str, Any] | None:
    for candidate in sorted(run_dir.rglob("summary.json")):
        try:
            data = _load_json(candidate)
        except Exception:
            continue
        if isinstance(data, dict) and "alice" in data and "bob" in data:
            return data
    return None


def _afpacket_records(run_dir: Path) -> list[Path]:
    bob_results = run_dir / "remote" / "bob-results"
    out: list[Path] = []
    for path in sorted(bob_results.glob("*.json")):
        try:
            doc = _load_json(path)
        except Exception:
            continue
        if isinstance(doc, dict) and doc.get("transport") == "afpacket_ipv4":
            out.append(path)
    return out


def build_alias_hostname_map(artifacts_root: Path) -> dict[str, str]:
    """Recover ``alias -> true hostname`` purely from observed artifact data.

    For each run we know Bob's true hostname from two independent sources (the AF_PACKET
    receiver.node and the message-server node). We map Bob's alias to that observed
    hostname. Aggregated across all runs this covers every host that ever played Bob.
    """
    observed: dict[str, set[str]] = {}
    for run_dir in sorted(p for p in artifacts_root.glob("*") if p.is_dir()):
        summary = _find_summary(run_dir)
        if summary is None:
            continue
        bob_alias = summary.get("bob")
        if not isinstance(bob_alias, str):
            continue
        # Bob's true hostname from the AF_PACKET receiver.node (platform.node()).
        for record_path in _afpacket_records(run_dir):
            doc = _load_json(record_path)
            node = doc.get("evidence", {}).get("endpoint_os", {}).get("receiver", {}).get("node")
            if isinstance(node, str) and node:
                observed.setdefault(bob_alias, set()).add(node)
                break
        # Cross-check from the message server node (server runs on Bob).
        message_results = run_dir / "message-results.json"
        if message_results.exists():
            try:
                rows = _load_json(message_results)
            except Exception:
                rows = []
            for row in rows if isinstance(rows, list) else []:
                server = row.get("server") if isinstance(row, dict) else None
                if isinstance(server, str) and server:
                    observed.setdefault(bob_alias, set()).add(server)
                    break

    mapping: dict[str, str] = {}
    for alias, hostnames in observed.items():
        if len(hostnames) != 1:
            raise SystemExit(f"ambiguous true hostname for alias {alias!r}: {sorted(hostnames)}")
        mapping[alias] = next(iter(hostnames))
    return mapping


def _join_ip_mac(ip: Any, mac: Any) -> str | None:
    parts = [str(part) for part in (ip, mac) if part]
    return " ".join(parts) if parts else None


def correct_record(doc: dict[str, Any], *, alice_hostname: str) -> bool:
    """Re-stamp one AF_PACKET record in place. Return True if it changed.

    Only topology/identity labels are touched; every measured value is preserved.
    """
    endpoint_os = doc.get("evidence", {}).get("endpoint_os")
    if not isinstance(endpoint_os, dict):
        return False
    if endpoint_os.get("topology_kind") != BAD_TOPOLOGY_KIND:
        return False

    changed = False
    packet_path = doc.get("packet_path", {})
    sender_interface = _join_ip_mac(packet_path.get("src_ip"), packet_path.get("src_mac"))

    if endpoint_os.get("topology_kind") != GOOD_TOPOLOGY_KIND:
        endpoint_os["topology_kind"] = GOOD_TOPOLOGY_KIND
        changed = True
    if endpoint_os.get("independent_receiver_os") is not True:
        endpoint_os["independent_receiver_os"] = True
        changed = True

    sender = endpoint_os.get("sender")
    if isinstance(sender, dict):
        # The receiver's platform was wrongly copied into the sender block. Replace it
        # with the remote sender's (Alice's) true, receiver-observable identity.
        corrected_sender = {
            "role": "sender",
            "system": "",
            "release": "",
            "version": "",
            "machine": "",
            "platform": "",
            "node": alice_hostname,
            "namespace": None,
            "interface": sender_interface,
            "source": "remote_peer_reported",
        }
        if sender != corrected_sender:
            endpoint_os["sender"] = corrected_sender
            changed = True

    return changed


def correct_artifacts(artifacts_root: Path, *, apply: bool) -> dict[str, Any]:
    mapping = build_alias_hostname_map(artifacts_root)
    report: dict[str, Any] = {
        "alias_hostname_map": dict(sorted(mapping.items())),
        "runs": [],
        "records_restamped": 0,
        "records_already_correct": 0,
        "records_skipped_no_hostname": 0,
    }

    for run_dir in sorted(p for p in artifacts_root.glob("*") if p.is_dir()):
        summary = _find_summary(run_dir)
        if summary is None:
            continue
        alice_alias = summary.get("alice")
        bob_alias = summary.get("bob")
        if not isinstance(alice_alias, str) or not isinstance(bob_alias, str):
            continue
        records = _afpacket_records(run_dir)
        if not records:
            continue
        alice_hostname = mapping.get(alice_alias)
        run_report: dict[str, Any] = {
            "run": run_dir.name,
            "alice_alias": alice_alias,
            "bob_alias": bob_alias,
            "alice_hostname": alice_hostname,
            "afpacket_records": len(records),
            "restamped": 0,
        }
        if not alice_hostname:
            run_report["error"] = (
                f"no observed true hostname for alice alias {alice_alias!r}; skipped"
            )
            report["records_skipped_no_hostname"] += len(records)
            report["runs"].append(run_report)
            continue

        for record_path in records:
            original_text = record_path.read_text()
            doc = json.loads(original_text)
            before = doc.get("evidence", {}).get("endpoint_os", {}).get("topology_kind")
            label_changed = correct_record(doc, alice_hostname=alice_hostname)
            # Re-serialize in the exact on-disk convention the CLI uses
            # (compact, sort_keys, trailing newline) so corrected records keep the
            # same formatting as the runner's original output and do not introduce a
            # spurious whitespace diff.
            new_text = _serialize_record(doc)
            if label_changed:
                if apply and new_text != original_text:
                    record_path.write_text(new_text)
                run_report["restamped"] += 1
                report["records_restamped"] += 1
            elif before == GOOD_TOPOLOGY_KIND:
                # Already re-stamped; still normalise formatting back to the canonical
                # compact form if a previous run wrote it indented.
                if apply and new_text != original_text:
                    record_path.write_text(new_text)
                report["records_already_correct"] += 1
        report["runs"].append(run_report)

    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--artifacts-root",
        type=Path,
        default=DEFAULT_ARTIFACTS_ROOT,
        help="Root of the alice-bob artifact runs (default: %(default)s).",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write corrected records to disk (default: dry run).",
    )
    args = parser.parse_args(argv)

    if not args.artifacts_root.exists():
        print(f"artifacts root not found: {args.artifacts_root}", file=sys.stderr)
        return 1

    report = correct_artifacts(args.artifacts_root, apply=args.apply)
    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"[{mode}] alias->hostname: {report['alias_hostname_map']}")
    for run in report["runs"]:
        note = run.get("error", "")
        print(
            f"  {run['run']}: alice={run['alice_alias']}->{run.get('alice_hostname')} "
            f"bob={run['bob_alias']} afpacket={run['afpacket_records']} "
            f"restamped={run['restamped']} {note}"
        )
    print(
        f"[{mode}] records_restamped={report['records_restamped']} "
        f"already_correct={report['records_already_correct']} "
        f"skipped_no_hostname={report['records_skipped_no_hostname']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
