"""Doctor/preflight checks for reviewer runs."""

from __future__ import annotations

import tomllib
from pathlib import Path

import celatim.doctor as doctor_module
from celatim.doctor import DOCTOR_SCHEMA_VERSION, PACKAGE_EXTRA_MODULES, DoctorStatus, run_doctor

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"
SCENARIOS = Path(__file__).resolve().parents[1] / "scenarios"
PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_doctor_passes_packaged_resources_with_no_optional_tool_checks(tmp_path):
    result = run_doctor(artifact_dir=tmp_path / "artifacts", optional_tools=())
    doc = result.to_json()

    assert result.ok is True
    assert doc["schema_version"] == DOCTOR_SCHEMA_VERSION
    assert {check["check_id"] for check in doc["checks"]} == {
        "environment",
        "catalog",
        "schemas",
        "scenarios",
        "artifact_dir",
    }
    assert all(check["status"] == "pass" for check in doc["checks"])
    environment = next(check for check in doc["checks"] if check["check_id"] == "environment")
    assert environment["details"]["package_version"]
    assert environment["details"]["python_version"]
    assert environment["details"]["python_executable"]
    assert environment["details"]["release"]


def test_doctor_uses_explicit_catalog_and_scenario_dir(tmp_path):
    result = run_doctor(
        catalog=DATA,
        scenario_dir=SCENARIOS,
        artifact_dir=tmp_path / "artifacts",
        optional_tools=(),
    )
    checks = {check.check_id: check for check in result.checks}

    assert result.ok is True
    assert checks["catalog"].details is not None
    assert checks["catalog"].details["path"] == str(DATA)
    assert checks["scenarios"].details is not None
    assert checks["scenarios"].details["schema_version"] == "celatim.scenario_inventory.v1"
    assert checks["scenarios"].details["scenario_count"] == 17
    assert checks["scenarios"].details["schema"] == "celatim.scenario.v1"
    assert checks["scenarios"].details["evidence_tier_counts"] == {
        "real_daemon_path": 9,
        "real_crypto_path": 2,
        "real_pdu_packet_path": 6,
    }
    assert checks["scenarios"].details["privilege_counts"] == {
        "cap_net_admin": 1,
        "none": 15,
        "root": 1,
    }
    assert checks["scenarios"].details["expected_runtime_s_total"] == 115.0
    assert checks["scenarios"].details["required_tools"] == ["dig", "dnsmasq", "ip", "tcpdump"]
    assert checks["scenarios"].details["required_extras"] == [
        "crypto",
        "daemon",
        "dns",
        "iot",
        "packet",
        "realtime",
        "ssh",
    ]
    first_scenario = checks["scenarios"].details["scenarios"][0]
    assert first_scenario["scenario_id"] == "http2-ping-opaque-real-pdu-smoke"
    assert first_scenario["evidence_tier"] == "real_pdu_packet_path"
    assert first_scenario["privilege"] == "none"
    assert first_scenario["expected_runtime_s"] == 5.0
    assert checks["schemas"].details is not None
    assert checks["schemas"].details["public_evidence_index"] == "celatim.public_evidence_index.v1"
    assert checks["schemas"].details["public_bundle"] == "celatim.public_bundle.v1"
    assert checks["schemas"].details["public_bundle_verify"] == "celatim.public_bundle_verify.v1"
    assert checks["schemas"].details["qemu_tap_preflight"] == "celatim.qemu_tap_preflight.v1"
    assert checks["schemas"].details["reviewer_bundle"] == "celatim.reviewer_bundle.v1"
    assert (
        checks["schemas"].details["reviewer_bundle_verify"] == "celatim.reviewer_bundle_verify.v1"
    )
    assert checks["schemas"].details["scenario"] == "celatim.scenario.v1"
    assert (
        checks["schemas"].details["scenario_execution_plan"] == "celatim.scenario_execution_plan.v1"
    )
    assert checks["schemas"].details["scenario_inventory"] == "celatim.scenario_inventory.v1"
    assert checks["schemas"].details["support_matrix"] == "celatim.support_matrix.v1"
    assert checks["schemas"].details["testbed_requirements"] == "celatim.testbed_requirements.v1"
    assert checks["schemas"].details["timing_sweep"] == "celatim.timing_sweep.v1"
    assert checks["environment"].details is not None
    assert checks["environment"].details["system"]


def test_doctor_enforces_scenario_declared_requirements(tmp_path):
    scenario_dir = tmp_path / "scenarios"
    scenario_dir.mkdir()
    (scenario_dir / "requires.toml").write_text(
        "\n".join(
            [
                'schema_version = "celatim.scenario.v1"',
                'scenario_id = "requires-missing"',
                'mechanism_id = "http2-ping-opaque"',
                'evidence_tier = "crafted_production_path"',
                'privilege = "cap_net_raw"',
                'requires_tools = ["celatim-definitely-missing-tool"]',
                'requires_extras = ["not-an-extra"]',
                'payload_hex = "00 ff 80 41"',
            ]
        )
    )

    result = run_doctor(scenario_dir=scenario_dir, optional_tools=())
    checks = {check.check_id: check for check in result.checks}

    assert result.ok is False
    assert checks["scenarios"].status is DoctorStatus.PASS
    assert checks["scenarios"].details is not None
    assert checks["scenarios"].details["required_tools"] == ["celatim-definitely-missing-tool"]
    assert checks["scenarios"].details["required_extras"] == ["not-an-extra"]
    assert checks["tool:celatim-definitely-missing-tool"].status is DoctorStatus.FAIL
    assert checks["tool:celatim-definitely-missing-tool"].details is not None
    assert checks["tool:celatim-definitely-missing-tool"].details["required"] is True
    assert checks["extra:not-an-extra"].status is DoctorStatus.FAIL
    assert checks["extra:not-an-extra"].details is not None
    assert checks["extra:not-an-extra"].details["required"] is True


def test_doctor_fails_scenario_schema_drift(tmp_path):
    scenario_dir = tmp_path / "scenarios"
    scenario_dir.mkdir()
    (scenario_dir / "bad.toml").write_text(
        "\n".join(
            [
                'schema_version = "celatim.scenario.v1"',
                'scenario_id = "bad-schema"',
                'mechanism_id = "http2-ping-opaque"',
                'payload_hex = "00 ff 80 41"',
                "unexpected_top_level = true",
            ]
        )
    )

    result = run_doctor(scenario_dir=scenario_dir, optional_tools=())

    assert result.ok is False
    checks = {check.check_id: check for check in result.checks}
    assert checks["scenarios"].status is DoctorStatus.FAIL
    assert checks["scenarios"].details is not None
    assert checks["scenarios"].details["path"] == str(scenario_dir)
    errors = checks["scenarios"].details["errors"]
    assert errors[0]["path"] == str(scenario_dir / "bad.toml")
    assert "unexpected key 'unexpected_top_level'" in errors[0]["errors"][0]


def test_doctor_marks_missing_required_tool_as_failure():
    result = run_doctor(
        optional_tools=(),
        required_tools=("celatim-definitely-missing-tool",),
    )

    assert result.ok is False
    tool_check = result.checks[-1]
    assert tool_check.check_id == "tool:celatim-definitely-missing-tool"
    assert tool_check.status is DoctorStatus.FAIL


def test_doctor_enforces_required_testbed_profile(monkeypatch):
    def fake_which(tool: str) -> str | None:
        return f"/usr/bin/{tool}" if tool in {"ip", "tcpdump"} else None

    def fake_run(
        argv: tuple[str, ...],
        *,
        capture_output: bool,
        text: bool,
        timeout: float,
        check: bool,
    ) -> object:
        class Completed:
            returncode = 0
            stdout = f"{argv[0]} version\n"
            stderr = ""

        return Completed()

    def fake_privilege_available(privilege: str) -> tuple[bool, dict[str, object]]:
        return True, {"method": "test", "privilege": privilege}

    monkeypatch.setattr(doctor_module.shutil, "which", fake_which)
    monkeypatch.setattr(doctor_module.subprocess, "run", fake_run)
    monkeypatch.setattr(doctor_module, "_privilege_available", fake_privilege_available)

    result = run_doctor(
        optional_tools=(),
        testbed_profiles=("netns-afpacket",),
    )
    checks = {check.check_id: check for check in result.checks}

    assert result.ok is True
    assert checks["testbed_profiles"].status is DoctorStatus.PASS
    assert checks["testbed_profiles"].details is not None
    assert checks["testbed_profiles"].details["profile_ids"] == ["netns-afpacket"]
    assert checks["tool:ip"].status is DoctorStatus.PASS
    assert checks["tool:tcpdump"].status is DoctorStatus.PASS
    assert checks["privilege:cap_net_admin"].status is DoctorStatus.PASS
    assert checks["privilege:cap_net_raw"].status is DoctorStatus.PASS


def test_doctor_fails_unknown_testbed_profile():
    result = run_doctor(
        optional_tools=(),
        testbed_profiles=("not-a-profile",),
    )
    checks = {check.check_id: check for check in result.checks}

    assert result.ok is False
    assert checks["testbed_profiles"].status is DoctorStatus.FAIL
    assert checks["testbed_profiles"].details is not None
    assert "unknown testbed profile" in checks["testbed_profiles"].details["error"]


def test_doctor_marks_missing_required_privilege_as_failure(monkeypatch, tmp_path):
    def fake_privilege_available(privilege: str) -> tuple[bool, dict[str, object]]:
        return False, {"method": "test", "privilege": privilege}

    monkeypatch.setattr(doctor_module, "_privilege_available", fake_privilege_available)

    scenario_dir = tmp_path / "scenarios"
    scenario_dir.mkdir()
    (scenario_dir / "requires.toml").write_text(
        "\n".join(
            [
                'schema_version = "celatim.scenario.v1"',
                'scenario_id = "requires-cap"',
                'mechanism_id = "http2-ping-opaque"',
                'privilege = "cap_net_raw"',
                'payload_hex = "00 ff 80 41"',
            ]
        )
    )

    result = run_doctor(scenario_dir=scenario_dir, optional_tools=())
    checks = {check.check_id: check for check in result.checks}

    assert result.ok is False
    assert checks["scenarios"].status is DoctorStatus.PASS
    assert checks["privilege:cap_net_raw"].status is DoctorStatus.FAIL
    assert checks["privilege:cap_net_raw"].details is not None
    assert checks["privilege:cap_net_raw"].details["required"] is True


def test_doctor_records_external_tool_version(monkeypatch):
    def fake_which(tool: str) -> str | None:
        return "/usr/sbin/ip" if tool == "ip" else None

    def fake_run(
        argv: tuple[str, ...],
        *,
        capture_output: bool,
        text: bool,
        timeout: float,
        check: bool,
    ) -> object:
        assert argv == ("/usr/sbin/ip", "-V")
        assert capture_output is True
        assert text is True
        assert timeout == doctor_module.TOOL_VERSION_TIMEOUT_S
        assert check is False

        class Completed:
            returncode = 0
            stdout = "ip utility, iproute2-6.18.0\n"
            stderr = ""

        return Completed()

    monkeypatch.setattr(doctor_module.shutil, "which", fake_which)
    monkeypatch.setattr(doctor_module.subprocess, "run", fake_run)

    result = run_doctor(optional_tools=("ip",))
    checks = {check.check_id: check for check in result.checks}
    details = checks["tool:ip"].details

    assert checks["tool:ip"].status is DoctorStatus.PASS
    assert details is not None
    assert details["path"] == "/usr/sbin/ip"
    assert details["version_command"] == ["/usr/sbin/ip", "-V"]
    assert details["version_status"] == "ok"
    assert details["version_returncode"] == 0
    assert details["version_output"] == "ip utility, iproute2-6.18.0"


def test_doctor_marks_unknown_tool_version_command_as_not_configured(monkeypatch):
    monkeypatch.setattr(
        doctor_module.shutil,
        "which",
        lambda tool: "/usr/bin/custom-tool" if tool == "custom-tool" else None,
    )

    result = run_doctor(optional_tools=("custom-tool",))
    checks = {check.check_id: check for check in result.checks}
    details = checks["tool:custom-tool"].details

    assert checks["tool:custom-tool"].status is DoctorStatus.PASS
    assert details is not None
    assert details["version_command"] is None
    assert details["version_status"] == "not_configured"
    assert details["version_output"] is None


def test_doctor_reports_missing_catalog_as_failure():
    result = run_doctor(catalog=Path("/definitely/missing/catalog.jsonl"), optional_tools=())

    assert result.ok is False
    checks = {check.check_id: check for check in result.checks}
    assert checks["catalog"].status is DoctorStatus.FAIL


def test_doctor_reports_package_extra_readiness():
    result = run_doctor(optional_tools=(), optional_extras=("packet", "daemon"))

    checks = {check.check_id: check for check in result.checks}
    assert checks["extra:packet"].status in {DoctorStatus.PASS, DoctorStatus.WARN}
    assert checks["extra:packet"].details is not None
    assert checks["extra:packet"].details["modules"][0]["module"] == "scapy"
    assert checks["extra:packet"].details["modules"][0]["distribution"] == "scapy"
    assert checks["extra:packet"].details["required"] is False
    assert checks["extra:daemon"].status in {DoctorStatus.PASS, DoctorStatus.WARN}
    assert checks["extra:daemon"].details is not None
    assert checks["extra:daemon"].details["modules"][0]["module"] == "aioquic"
    assert checks["extra:daemon"].details["modules"][0]["distribution"] == "aioquic"
    assert checks["extra:daemon"].details["modules"][1]["module"] == "h2"
    assert checks["extra:daemon"].details["modules"][1]["distribution"] == "h2"
    assert checks["extra:daemon"].details["required"] is False
    assert set(PACKAGE_EXTRA_MODULES) == {
        "packet",
        "crypto",
        "daemon",
        "dns",
        "ssh",
        "iot",
        "realtime",
    }


def test_doctor_fails_unknown_required_extra():
    result = run_doctor(optional_tools=(), required_extras=("not-an-extra",))

    assert result.ok is False
    checks = {check.check_id: check for check in result.checks}
    assert checks["extra:not-an-extra"].status is DoctorStatus.FAIL
    assert checks["extra:not-an-extra"].details is not None
    assert checks["extra:not-an-extra"].details["known_extras"] == [
        "crypto",
        "daemon",
        "dns",
        "iot",
        "packet",
        "realtime",
        "ssh",
    ]


def test_pyproject_optional_extras_match_doctor_registry():
    pyproject = tomllib.loads(PYPROJECT.read_text())
    extras = pyproject["project"]["optional-dependencies"]

    assert set(extras) == set(PACKAGE_EXTRA_MODULES)
    assert extras["packet"] == ["scapy>=2.6.1"]
    assert extras["crypto"] == ["cryptography>=46.0.3", "ecdsa>=0.19.1"]
    assert extras["daemon"] == ["aioquic>=1.3.0", "h2>=4.3.0"]
    assert extras["dns"] == ["dnspython>=2.8.0"]
    assert extras["ssh"] == ["paramiko>=3.5.0"]
    assert extras["iot"] == ["aiocoap>=0.4.12", "paho-mqtt>=2.1.0"]
    assert extras["realtime"] == ["websockets>=13.0"]
