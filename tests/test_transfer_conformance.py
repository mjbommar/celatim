"""The built-in provider passes the same public conformance API as plugins."""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path

from celatim.transfer import DirectTlsProvider, TransferServer
from celatim.transfer.conformance import run_provider_conformance

PROJECT = Path(__file__).resolve().parents[1]


def test_direct_tls_provider_passes_public_conformance_suite(tmp_path):
    async def run() -> None:
        source = tmp_path / "source.bin"
        source.write_bytes(b"provider conformance\x00\xff")
        async with TransferServer(
            tmp_path / "received",
            home=tmp_path / "bob-home",
        ) as server:
            offer = await server.create_offer()
            result = await run_provider_conformance(
                DirectTlsProvider(),
                source=source,
                offer=offer,
                home=tmp_path / "alice-home",
            )
            receipt = await server.receive(timeout_s=2)

        assert result.ok
        assert result.provider == "tcp-tls"
        assert result.checks == (
            "manifest_offered",
            "duplex_feedback",
            "preflight_eligible",
            "completed_receipt",
            "verified_acknowledgement",
            "provider_identity",
        )
        assert receipt.verified

    asyncio.run(run())


def test_external_wheel_provider_is_discovered_through_entry_point(tmp_path):
    main_dist = tmp_path / "main-dist"
    fixture_dist = tmp_path / "fixture-dist"
    environment = tmp_path / "venv"
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(main_dist), str(PROJECT)],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            "uv",
            "build",
            "--wheel",
            "--out-dir",
            str(fixture_dist),
            str(PROJECT / "tests" / "fixtures" / "provider_package"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["uv", "venv", "--python", sys.executable, str(environment)],
        check=True,
        capture_output=True,
        text=True,
    )
    python = environment / "bin" / "python"
    wheels = [*main_dist.glob("*.whl"), *fixture_dist.glob("*.whl")]
    subprocess.run(
        ["uv", "pip", "install", "--python", str(python), "--no-deps", *map(str, wheels)],
        check=True,
        capture_output=True,
        text=True,
    )
    script = """
import json
from celatim.transfer import ProviderRegistry

registry = ProviderRegistry()
registry.discover()
provider = registry.get("fixture-entry")
print(json.dumps(provider.manifest.to_json(), sort_keys=True))
"""
    result = subprocess.run(
        [str(python), "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )
    manifest = json.loads(result.stdout)
    assert manifest["name"] == "fixture-entry"
    assert manifest["resumable"] is True
    assert manifest["schema_version"] == "celatim.provider_manifest.v1"
