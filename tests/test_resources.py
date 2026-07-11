"""Packaged defaults stay in sync with repo source-of-truth files."""

from __future__ import annotations

import re
import tomllib
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace

import pytest

from celatim.resources import (
    catalog_path,
    doc_names,
    doc_text,
    protocol_rates_path,
    scenario_dir_path,
    schema_text,
)

PROJECT = Path(__file__).resolve().parents[1]
ROOT = PROJECT.parent
CELATIM = PROJECT
PAPER_ARTIFACT_AVAILABLE = (ROOT / "paper").is_dir() and (ROOT / "measurement") == PROJECT
requires_paper_artifact = pytest.mark.skipif(
    not PAPER_ARTIFACT_AVAILABLE,
    reason="requires the companion RFC survey repository",
)


def test_packaged_catalog_matches_source_catalog():
    with catalog_path() as packaged_catalog:
        assert packaged_catalog.read_text() == (PROJECT / "data" / "mechanisms.jsonl").read_text()


def test_packaged_protocol_rates_match_source_rates():
    with protocol_rates_path() as packaged_rates:
        assert packaged_rates.read_text() == (PROJECT / "data" / "protocol_rates.toml").read_text()


def test_packaged_schemas_match_source_schemas():
    schemas = PROJECT / "schemas"

    assert (
        schema_text("detector-replay-v1")
        == (schemas / "detector-replay-v1.schema.json").read_text()
    )
    assert (
        schema_text("detector-replay-corpus-v1")
        == (schemas / "detector-replay-corpus-v1.schema.json").read_text()
    )
    assert (
        schema_text("detector-trace-manifest-v1")
        == (schemas / "detector-trace-manifest-v1.schema.json").read_text()
    )
    assert schema_text("evidence-run-v1") == (schemas / "evidence-run-v1.schema.json").read_text()
    assert (
        schema_text("evidence-index-v1") == (schemas / "evidence-index-v1.schema.json").read_text()
    )
    assert (
        schema_text("public-evidence-index-v1")
        == (schemas / "public-evidence-index-v1.schema.json").read_text()
    )
    assert schema_text("doctor-v1") == (schemas / "doctor-v1.schema.json").read_text()
    assert schema_text("pcap-decode-v1") == (schemas / "pcap-decode-v1.schema.json").read_text()
    assert schema_text("public-bundle-v1") == (schemas / "public-bundle-v1.schema.json").read_text()
    assert (
        schema_text("public-bundle-verify-v1")
        == (schemas / "public-bundle-verify-v1.schema.json").read_text()
    )
    assert (
        schema_text("qemu-tap-preflight-v1")
        == (schemas / "qemu-tap-preflight-v1.schema.json").read_text()
    )
    assert (
        schema_text("reviewer-bundle-v1")
        == (schemas / "reviewer-bundle-v1.schema.json").read_text()
    )
    assert (
        schema_text("reviewer-bundle-verify-v1")
        == (schemas / "reviewer-bundle-verify-v1.schema.json").read_text()
    )
    assert schema_text("scenario-v1") == (schemas / "scenario-v1.schema.json").read_text()
    assert (
        schema_text("scenario-execution-plan-v1")
        == (schemas / "scenario-execution-plan-v1.schema.json").read_text()
    )
    assert (
        schema_text("scenario-inventory-v1")
        == (schemas / "scenario-inventory-v1.schema.json").read_text()
    )
    assert schema_text("scrub-report-v1") == (schemas / "scrub-report-v1.schema.json").read_text()
    assert (
        schema_text("support-matrix-v1") == (schemas / "support-matrix-v1.schema.json").read_text()
    )
    assert (
        schema_text("testbed-requirements-v1")
        == (schemas / "testbed-requirements-v1.schema.json").read_text()
    )
    assert schema_text("timing-sweep-v1") == (schemas / "timing-sweep-v1.schema.json").read_text()


def test_packaged_scenarios_match_source_scenarios():
    source = PROJECT / "scenarios"
    with scenario_dir_path() as packaged_scenarios:
        assert sorted(path.name for path in packaged_scenarios.glob("*.toml")) == sorted(
            path.name for path in source.glob("*.toml")
        )
        for source_path in sorted(source.glob("*.toml")):
            assert (packaged_scenarios / source_path.name).read_text() == source_path.read_text()


def test_resource_packages_are_importable():
    assert (files("celatim.data") / "mechanisms.jsonl").is_file()
    assert (files("celatim.data") / "protocol_rates.toml").is_file()
    assert (files("celatim.schemas") / "detector-replay-v1.schema.json").is_file()
    assert (files("celatim.schemas") / "detector-replay-corpus-v1.schema.json").is_file()
    assert (files("celatim.schemas") / "detector-trace-manifest-v1.schema.json").is_file()
    assert (files("celatim.schemas") / "evidence-run-v1.schema.json").is_file()
    assert (files("celatim.schemas") / "public-evidence-index-v1.schema.json").is_file()
    assert (files("celatim.schemas") / "doctor-v1.schema.json").is_file()
    assert (files("celatim.schemas") / "pcap-decode-v1.schema.json").is_file()
    assert (files("celatim.schemas") / "public-bundle-v1.schema.json").is_file()
    assert (files("celatim.schemas") / "public-bundle-verify-v1.schema.json").is_file()
    assert (files("celatim.schemas") / "qemu-tap-preflight-v1.schema.json").is_file()
    assert (files("celatim.schemas") / "reviewer-bundle-v1.schema.json").is_file()
    assert (files("celatim.schemas") / "reviewer-bundle-verify-v1.schema.json").is_file()
    assert (files("celatim.schemas") / "scenario-v1.schema.json").is_file()
    assert (files("celatim.schemas") / "scenario-execution-plan-v1.schema.json").is_file()
    assert (files("celatim.schemas") / "scenario-inventory-v1.schema.json").is_file()
    assert (files("celatim.schemas") / "scrub-report-v1.schema.json").is_file()
    assert (files("celatim.schemas") / "support-matrix-v1.schema.json").is_file()
    assert (files("celatim.schemas") / "testbed-requirements-v1.schema.json").is_file()
    assert (files("celatim.schemas") / "timing-sweep-v1.schema.json").is_file()
    assert (files("celatim.scenarios") / "http2-ping-opaque.toml").is_file()
    assert (files("celatim.docs") / "api-guide.md").is_file()


def test_packaged_docs_are_available_by_stable_name():
    assert doc_names() == (
        "api-guide",
        "reviewer-quickstart",
        "scenario-authoring",
        "troubleshooting",
    )
    assert doc_text("api-guide").startswith("# celatim API Guide\n")
    assert "celatim scenario run" in doc_text("scenario-authoring")
    assert "make reviewer-smoke" in doc_text("reviewer-quickstart")
    assert "AF_PACKET" in doc_text("troubleshooting")


@requires_paper_artifact
def test_root_makefile_exposes_manual_dns_daemon_target():
    makefile = (ROOT / "Makefile").read_text()

    assert "reviewer-dns-daemon" in makefile
    assert "--require-testbed-profile dns-daemon-netns" in makefile
    assert "edns0-padding-dnsmasq-dig-real-daemon" in makefile
    assert "--transport-capture-pcap ../$(DNS_DIR)/pcaps/{scenario_id}-{case}.pcap" in makefile


@requires_paper_artifact
def test_root_makefile_exposes_manual_afpacket_tcp_target():
    makefile = (ROOT / "Makefile").read_text()

    assert "reviewer-afpacket-tcp" in makefile
    assert "--require-testbed-profile netns-afpacket" in makefile
    assert "tcp-reserved-bits-afpacket-netns" in makefile
    assert "--transport-capture-pcap ../$(AFPACKET_DIR)/pcaps/{scenario_id}-{case}.pcap" in makefile


@requires_paper_artifact
def test_root_makefile_exposes_qemu_preflight_target():
    makefile = (ROOT / "Makefile").read_text()

    assert "reviewer-qemu-preflight" in makefile
    assert "QEMU_GUEST_IMAGE" in makefile
    assert "testbed qemu-preflight" in makefile
    assert "--disk-image $(abspath $(QEMU_GUEST_IMAGE))" in makefile


@requires_paper_artifact
def test_root_makefile_exposes_installed_wheel_smoke_target():
    makefile = (ROOT / "Makefile").read_text()

    assert "package-smoke" in makefile
    assert "scripts/installed_wheel_smoke.py" in makefile
    assert "PACKAGE_SMOKE_DIR" in makefile


@requires_paper_artifact
def test_root_makefile_exposes_celatim_smoke_target():
    makefile = (ROOT / "Makefile").read_text()

    assert "celatim-test" in makefile
    assert "cd $(MEASUREMENT_DIR) && $(UV) run python -m pytest" in makefile
    assert "celatim-smoke" in makefile
    assert "celatim-smoke: package-smoke" in makefile
    assert "CELATIM_SMOKE_DIR" not in makefile
    assert "CELATIM_PACKAGE_DIR" not in makefile


def test_unified_celatim_project_owns_the_only_distribution_and_namespace():
    search_root = ROOT if PAPER_ARTIFACT_AVAILABLE else PROJECT
    pyprojects = [
        path
        for path in search_root.rglob("pyproject.toml")
        if ".venv" not in path.parts
        and "artifacts" not in path.parts
        and not {"tests", "fixtures"}.issubset(path.parts)
    ]
    project_pyprojects = [
        path for path in pyprojects if "project" in tomllib.loads(path.read_text())
    ]
    assert project_pyprojects == [PROJECT / "pyproject.toml"]

    pyproject = tomllib.loads((PROJECT / "pyproject.toml").read_text())
    project = pyproject["project"]

    assert project["name"] == "celatim"
    assert project["version"] == "0.2.4"
    assert project["requires-python"] == ">=3.14"
    assert project["license"] == "Apache-2.0"
    assert project["license-files"] == ["LICENSE"]
    assert project["dependencies"] == []
    assert project["optional-dependencies"]["crypto"] == ["cryptography>=46.0.3"]
    assert project["scripts"]["celatim"] == "celatim.cli:main"
    assert pyproject["tool"]["uv"]["build-backend"]["module-name"] == ["celatim"]
    assert "src" not in pyproject["tool"]["ty"]
    assert 'name = "ecdsa"' not in (PROJECT / "uv.lock").read_text()
    assert not (search_root / "packages" / "celatim").exists()
    retired_namespace = "rfc" + "tunnel"
    assert not (PROJECT / "src" / retired_namespace).exists()

    license_text = (PROJECT / "LICENSE").read_text()
    assert "Apache License" in license_text
    assert "Version 2.0, January 2004" in license_text

    package = PROJECT / "src" / "celatim"
    for relative in (
        "__init__.py",
        "api.py",
        "cli.py",
        "cli_endpoints.py",
        "discovery.py",
        "errors.py",
        "inspection.py",
        "transports.py",
        "py.typed",
    ):
        assert (package / relative).is_file()

    readme = (PROJECT / "README.md").read_text()
    assert "celatim" in readme
    assert "roundtrip_payload" in readme
    assert "profile.adapter.paths" in readme


@requires_paper_artifact
def test_root_makefile_exposes_paper_macro_generation():
    makefile = (ROOT / "Makefile").read_text()

    assert "paper-macros" in makefile
    assert "celatim-paper-macros" in makefile
    assert "survey-scale-macros.tex" in makefile
    assert "paper-artifacts: paper-macros paper-tables paper-figures" in makefile


@requires_paper_artifact
def test_root_makefile_public_bundle_includes_detector_scrub_guidance():
    makefile = (ROOT / "Makefile").read_text()

    assert "detector-scrub-guidance.md" in makefile
    assert "guidance generate" in makefile
    assert "--detector-scrub-guidance" in makefile
    assert "detector-rules-manifest.json" in makefile
    assert "--detector-rule-artifact" in makefile
    assert "windows-pktmon-etw-guidance.md" in makefile
    assert "--windows-capture-guidance" in makefile


@requires_paper_artifact
def test_root_makefile_exposes_detector_rule_artifacts_target():
    makefile = (ROOT / "Makefile").read_text()

    assert "detector-rules" in makefile
    assert "detector rules" in makefile
    assert "detector-rules-manifest.json" in makefile


@requires_paper_artifact
def test_root_makefile_exposes_windows_capture_guidance_target():
    makefile = (ROOT / "Makefile").read_text()

    assert "windows-capture-guidance" in makefile
    assert "detector windows-guidance" in makefile
    assert "windows-pktmon-etw-guidance.md" in makefile


@requires_paper_artifact
def test_root_makefile_exposes_reviewer_package_artifacts():
    makefile = (ROOT / "Makefile").read_text()

    assert "reviewer-package" in makefile
    assert "PACKAGE_WHEEL" in makefile
    assert "celatim-*.whl" in makefile
    assert "--package-wheel" in makefile
    assert "--lockfile" in makefile
    assert "--scenario-spec" in makefile
    assert "--testbed-package" in makefile
    assert "$(MEASUREMENT_DIR)/scenarios/*.toml" in makefile
    assert "TESTBED_PACKAGE_FILES" in makefile
    assert "$(MEASUREMENT_DIR)/uv.lock" in makefile


def test_installed_wheel_smoke_script_covers_all_console_entry_points():
    script = (PROJECT / "scripts" / "installed_wheel_smoke.py").read_text()

    for expected in (
        "celatim",
        "celatim-paper-figures",
        "celatim-paper-macros",
        "celatim-paper-tables",
        "celatim-support-matrix",
        "outside-checkout",
        "performance.json",
        "all-extras.json",
        "scenario",
        "evidence",
        "support-matrix.json",
        "survey-scale-macros.tex",
        "field-catalog-longtable.tex",
        "figures-manifest.json",
        "--no-deps",
    ):
        assert expected in script


def test_unified_installed_wheel_smoke_covers_public_package_surface():
    script = (PROJECT / "scripts" / "installed_wheel_smoke.py").read_text()

    assert "celatim-*.whl" in script
    assert "metadata.version('celatim')" in script
    assert "celatim.cli:main" in script
    assert "outside-checkout" in script
    assert "performance.json" in script
    assert "EXPECTED_EXTRAS" in script
    assert "all-extras.json" in script
    assert '"performance": performance' in script
    assert '"extras": extras_report' in script
    assert "forbidden release content" in script
    assert '"pip",' in script
    assert '"install",' in script
    assert '"check",' in script
    assert "--no-deps" in script
    assert "packages" + "/celatim" not in script
    assert "rfc" + "tunnel" not in script


def test_standalone_docs_and_crosshost_tools_do_not_depend_on_workstation_paths():
    readme = (PROJECT / "README.md").read_text()
    assert "../PLAN.md" not in readme
    assert "make reviewer-" not in readme
    assert "measurement/data/" not in readme

    crosshost = PROJECT / "experiments" / "crosshost"
    sources = [*crosshost.glob("*.py"), crosshost / "Dockerfile.alicebob"]
    forbidden = ("/home/", "/nas", "/work/measurement", "measurement/data/")
    for source in sources:
        text = source.read_text()
        for value in forbidden:
            assert value not in text, f"{source.name}: {value}"

    dockerfile = (crosshost / "Dockerfile.alicebob").read_text()
    assert "ARG CELATIM_SOURCE=." in dockerfile
    assert "COPY ${CELATIM_SOURCE} /work/celatim" in dockerfile
    assert "FROM python:3.14-slim" in dockerfile

    lab_dockerfile = (PROJECT / "experiments" / "Dockerfile").read_text()
    assert "FROM python:3.14-slim" in lab_dockerfile
    assert "python:3.13" not in lab_dockerfile

    lab_script = (PROJECT / "experiments" / "lab.py").read_text()
    assert 'PROJECT_ROOT / "data" / "mechanisms.jsonl"' in lab_script
    assert 'CATALOG = "/work/' not in lab_script

    for result_file in ("applayer-results.json", "packet-family-results.json"):
        assert (crosshost / result_file).stat().st_mode & 0o111 == 0


def test_lab_packet_constructors_resolve_concrete_scapy_modules(monkeypatch):
    monkeypatch.syspath_prepend(str(PROJECT))
    from experiments import lab

    assert lab._template_by_id("http2-ping-opaque", lab.SND_IP, lab.RCV_IP) is not None
    for protocol in (
        "ICMP",
        "IPv4",
        "TCP",
        "UDP",
        "IPv6",
        "ICMPv6",
        "SCTP",
        "VXLAN",
        "GRE",
        "Geneve",
        "AH",
        "IGMP",
        "RIP",
        "OSPF",
        "DHCP",
        "NTP",
        "ESP",
    ):
        mechanism = SimpleNamespace(id=f"test-{protocol.lower()}", protocol=protocol)
        assert bytes(lab._base_packet(mechanism, lab.SND_IP, lab.RCV_IP, 1))


def test_lab_scrubber_uses_ip_header_length_in_bits(monkeypatch):
    monkeypatch.syspath_prepend(str(PROJECT))
    from scapy.layers.inet import IP, TCP

    from celatim.catalog import load_mechanisms
    from experiments import lab

    mechanism = next(
        item
        for item in load_mechanisms(PROJECT / "data" / "mechanisms.jsonl")
        if item.id == "tcp-reserved-bits"
    )
    locator = mechanism.locator
    assert locator is not None
    packet = IP(src=lab.SND_IP, dst=lab.RCV_IP) / TCP(reserved=7)
    raw = bytearray(bytes(packet))
    destination_before = bytes(raw[16:20])
    offset = lab._abs_bit_offset(locator, lab._ip_hdr_bits(raw))
    assert lab._read_bits(bytes(raw), offset, locator.bit_width) != 0

    lab._scrub_field(raw, locator)

    assert bytes(raw[16:20]) == destination_before
    assert lab._read_bits(bytes(raw), offset, locator.bit_width) == 0


def test_crosshost_runner_resolves_standalone_and_paper_snapshot_layouts(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(PROJECT))
    from experiments.crosshost.alice_bob_runner import Controller, RemoteConfig

    remote = RemoteConfig(
        host="example",
        remote_root="/tmp/celatim-run",
        image="celatim:test",
        ssh="ssh",
        docker="docker",
    )

    def controller(project_subdir: str) -> Controller:
        return Controller(
            alice=remote,
            bob=remote,
            output_dir=tmp_path,
            payload=b"test",
            alice_vx_ip="10.200.0.7",
            bob_vx_ip="10.200.0.6",
            alice_vx_mac="02:00:00:00:00:07",
            bob_vx_mac="02:00:00:00:00:06",
            vxlan_dev="vxlan0",
            message_port=9911,
            receiver_ready_s=0.0,
            packet_timeout_s=1.0,
            unit_rate_hz=1.0,
            packet_backend="host-python",
            message_backend="host-python",
            project_subdir=project_subdir,
        )

    standalone = controller(".")
    paper_snapshot = controller("measurement")
    assert standalone.remote_project_dir(remote) == "/tmp/celatim-run/repo"
    assert paper_snapshot.remote_project_dir(remote) == "/tmp/celatim-run/repo/measurement"
    assert standalone.helper_runner_path("host-python") == (
        "experiments/crosshost/alice_bob_runner.py"
    )
    assert "PYTHONPATH=/tmp/celatim-run/repo/src:" in standalone.host_python_command(
        remote, ("python", "--version")
    )
    assert "PYTHONPATH=/tmp/celatim-run/repo/measurement/src:" in (
        paper_snapshot.host_python_command(remote, ("python", "--version"))
    )
    with pytest.raises(ValueError, match="unsafe project subdirectory"):
        controller("../escape")


def test_api_guide_python_examples_execute_against_packaged_resources(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.syspath_prepend(str(CELATIM / "src"))
    blocks = re.findall(r"```python\n(.*?)\n```", doc_text("api-guide"), flags=re.S)

    assert len(blocks) == 9
    for index, block in enumerate(blocks, start=1):
        exec(
            compile(block, f"api-guide.md python block {index}", "exec"),
            {"__name__": f"api_guide_block_{index}"},
        )
