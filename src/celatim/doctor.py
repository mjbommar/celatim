"""Preflight checks for installed reviewer artifacts."""

from __future__ import annotations

import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from enum import Enum
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from time import time
from typing import Any

from .catalog import load_mechanisms
from .resources import catalog_path, scenario_dir_path, schema_text
from .scenario import build_scenario_execution_plan, build_scenario_inventory
from .testbed import build_testbed_requirements_inventory

DOCTOR_SCHEMA_VERSION = "celatim.doctor.v1"
DEFAULT_OPTIONAL_TOOLS = ("ip", "tcpdump")
TOOL_VERSION_TIMEOUT_S = 2.0
TOOL_VERSION_COMMANDS = {
    "dig": ("dig", "-v"),
    "dnsmasq": ("dnsmasq", "--version"),
    "docker": ("docker", "--version"),
    "ethtool": ("ethtool", "--version"),
    "ip": ("ip", "-V"),
    "qemu-system-x86_64": ("qemu-system-x86_64", "--version"),
    "suricata": ("suricata", "--version"),
    "tcpdump": ("tcpdump", "--version"),
    "tshark": ("tshark", "--version"),
}
PACKAGE_EXTRA_MODULES = {
    "packet": (("scapy", "scapy"),),
    "crypto": (("cryptography", "cryptography"), ("ecdsa", "ecdsa")),
    "daemon": (("aioquic", "aioquic"), ("h2", "h2")),
    "dns": (("dns", "dnspython"),),
    "ssh": (("paramiko", "paramiko"),),
    "iot": (("aiocoap", "aiocoap"), ("paho", "paho-mqtt")),
    "realtime": (("websockets", "websockets"),),
}


class DoctorStatus(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


@dataclass(frozen=True)
class DoctorCheck:
    check_id: str
    status: DoctorStatus
    message: str
    details: dict[str, Any] | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "status": self.status.value,
            "message": self.message,
            "details": {} if self.details is None else self.details,
        }


@dataclass(frozen=True)
class DoctorResult:
    schema_version: str
    generated_at_unix_s: float
    ok: bool
    checks: tuple[DoctorCheck, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at_unix_s": self.generated_at_unix_s,
            "ok": self.ok,
            "checks": [check.to_json() for check in self.checks],
        }


def run_doctor(
    *,
    catalog: Path | None = None,
    scenario_dir: Path | None = None,
    artifact_dir: Path | None = None,
    optional_tools: tuple[str, ...] = DEFAULT_OPTIONAL_TOOLS,
    required_tools: tuple[str, ...] = (),
    optional_extras: tuple[str, ...] = (),
    required_extras: tuple[str, ...] = (),
    testbed_profiles: tuple[str, ...] = (),
) -> DoctorResult:
    checks: list[DoctorCheck] = []
    checks.append(_environment_check())
    checks.append(_catalog_check(catalog))
    checks.append(_schema_check())
    scenario_check = _scenario_check(scenario_dir)
    checks.append(scenario_check)
    testbed_check: DoctorCheck | None = None
    if testbed_profiles:
        testbed_check = _testbed_profiles_check(testbed_profiles)
        checks.append(testbed_check)
    if artifact_dir is not None:
        checks.append(_artifact_dir_check(artifact_dir))
    scenario_required_tools = _scenario_requirement_values(
        scenario_check,
        "default_required_tools",
    )
    scenario_required_extras = _scenario_requirement_values(
        scenario_check,
        "default_required_extras",
    )
    scenario_required_privileges = _scenario_requirement_values(
        scenario_check,
        "default_required_privileges",
    )
    testbed_required_tools = _requirement_values(testbed_check, "required_tools")
    testbed_required_extras = _requirement_values(testbed_check, "required_extras")
    testbed_required_privileges = _requirement_values(testbed_check, "required_privileges")
    required_tool_names = _unique(
        (*required_tools, *scenario_required_tools, *testbed_required_tools)
    )
    required_extra_names = _unique(
        (*required_extras, *scenario_required_extras, *testbed_required_extras)
    )
    required_privilege_names = _unique(
        (*scenario_required_privileges, *testbed_required_privileges)
    )
    optional_tool_names = _without(_unique(optional_tools), required_tool_names)
    optional_extra_names = _without(_unique(optional_extras), required_extra_names)
    checks.extend(_tool_checks(optional_tool_names, required=False))
    checks.extend(_tool_checks(required_tool_names, required=True))
    checks.extend(_extra_checks(optional_extra_names, required=False))
    checks.extend(_extra_checks(required_extra_names, required=True))
    checks.extend(_privilege_checks(required_privilege_names))
    return DoctorResult(
        schema_version=DOCTOR_SCHEMA_VERSION,
        generated_at_unix_s=time(),
        ok=not any(check.status is DoctorStatus.FAIL for check in checks),
        checks=tuple(checks),
    )


def _environment_check() -> DoctorCheck:
    return DoctorCheck(
        "environment",
        DoctorStatus.PASS,
        "runtime environment captured",
        {
            "package_version": _package_version(),
            "python_version": sys.version.split()[0],
            "python_executable": sys.executable,
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
    )


def _catalog_check(catalog: Path | None) -> DoctorCheck:
    try:
        with catalog_path(catalog) as resolved:
            mechanisms = load_mechanisms(resolved)
            return DoctorCheck(
                "catalog",
                DoctorStatus.PASS,
                "catalog is readable",
                {
                    "path": str(resolved),
                    "mechanism_count": len(mechanisms),
                },
            )
    except Exception as exc:
        return DoctorCheck(
            "catalog",
            DoctorStatus.FAIL,
            "catalog is not readable",
            {"error": f"{type(exc).__name__}: {exc}"},
        )


def _schema_check() -> DoctorCheck:
    try:
        evidence_run = json.loads(schema_text("evidence-run-v1"))
        evidence_index = json.loads(schema_text("evidence-index-v1"))
        doctor = json.loads(schema_text("doctor-v1"))
        public_evidence_index = json.loads(schema_text("public-evidence-index-v1"))
        public_bundle = json.loads(schema_text("public-bundle-v1"))
        public_bundle_verify = json.loads(schema_text("public-bundle-verify-v1"))
        qemu_tap_preflight = json.loads(schema_text("qemu-tap-preflight-v1"))
        reviewer_bundle = json.loads(schema_text("reviewer-bundle-v1"))
        reviewer_bundle_verify = json.loads(schema_text("reviewer-bundle-verify-v1"))
        scenario = json.loads(schema_text("scenario-v1"))
        scenario_execution_plan = json.loads(schema_text("scenario-execution-plan-v1"))
        scenario_inventory = json.loads(schema_text("scenario-inventory-v1"))
        support_matrix = json.loads(schema_text("support-matrix-v1"))
        testbed_requirements = json.loads(schema_text("testbed-requirements-v1"))
        timing_sweep = json.loads(schema_text("timing-sweep-v1"))
        return DoctorCheck(
            "schemas",
            DoctorStatus.PASS,
            "packaged JSON schemas are readable",
            {
                "evidence_run": evidence_run.get("properties", {})
                .get("schema_version", {})
                .get("const"),
                "evidence_index": evidence_index.get("properties", {})
                .get("schema_version", {})
                .get("const"),
                "doctor": doctor.get("properties", {}).get("schema_version", {}).get("const"),
                "public_evidence_index": public_evidence_index.get("properties", {})
                .get("schema_version", {})
                .get("const"),
                "public_bundle": public_bundle.get("properties", {})
                .get("schema_version", {})
                .get("const"),
                "public_bundle_verify": public_bundle_verify.get("properties", {})
                .get("schema_version", {})
                .get("const"),
                "qemu_tap_preflight": qemu_tap_preflight.get("properties", {})
                .get("schema_version", {})
                .get("const"),
                "reviewer_bundle": reviewer_bundle.get("properties", {})
                .get("schema_version", {})
                .get("const"),
                "reviewer_bundle_verify": reviewer_bundle_verify.get("properties", {})
                .get("schema_version", {})
                .get("const"),
                "scenario": scenario.get("properties", {}).get("schema_version", {}).get("const"),
                "scenario_execution_plan": scenario_execution_plan.get("properties", {})
                .get("schema_version", {})
                .get("const"),
                "scenario_inventory": scenario_inventory.get("properties", {})
                .get("schema_version", {})
                .get("const"),
                "support_matrix": support_matrix.get("properties", {})
                .get("schema_version", {})
                .get("const"),
                "testbed_requirements": testbed_requirements.get("properties", {})
                .get("schema_version", {})
                .get("const"),
                "timing_sweep": timing_sweep.get("properties", {})
                .get("schema_version", {})
                .get("const"),
            },
        )
    except Exception as exc:
        return DoctorCheck(
            "schemas",
            DoctorStatus.FAIL,
            "packaged JSON schemas are not readable",
            {"error": f"{type(exc).__name__}: {exc}"},
        )


def _scenario_check(scenario_dir: Path | None) -> DoctorCheck:
    try:
        with scenario_dir_path(scenario_dir) as resolved:
            schema = json.loads(schema_text("scenario-v1"))
            validation_errors = _scenario_schema_errors(resolved, schema)
            if validation_errors:
                return DoctorCheck(
                    "scenarios",
                    DoctorStatus.FAIL,
                    "scenario specs do not match scenario-v1 schema",
                    {"path": str(resolved), "errors": validation_errors},
                )
            inventory = build_scenario_inventory(resolved)
            if inventory.scenario_count == 0:
                return DoctorCheck(
                    "scenarios",
                    DoctorStatus.FAIL,
                    "no scenario specs found",
                    {"path": str(resolved)},
                )
            details = inventory.to_json()
            plan = build_scenario_execution_plan(resolved)
            default_items = tuple(item for item in plan.scenarios if item.default_included)
            active_items = default_items or plan.scenarios
            details["default_required_tools"] = sorted(
                {tool for item in active_items for tool in item.requires_tools}
            )
            details["default_required_extras"] = sorted(
                {extra for item in active_items for extra in item.requires_extras}
            )
            details["default_required_privileges"] = sorted(
                {item.privilege for item in active_items if item.privilege != "none"}
            )
            details["schema"] = schema.get("properties", {}).get("schema_version", {}).get("const")
            return DoctorCheck(
                "scenarios",
                DoctorStatus.PASS,
                "scenario specs are readable",
                details,
            )
    except Exception as exc:
        return DoctorCheck(
            "scenarios",
            DoctorStatus.FAIL,
            "scenario specs are not readable",
            {"error": f"{type(exc).__name__}: {exc}"},
        )


def _scenario_schema_errors(root: Path, schema: dict[str, Any]) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.toml")):
        try:
            document = tomllib.loads(path.read_text())
        except Exception as exc:
            errors.append({"path": str(path), "errors": [f"TOML parse error: {exc}"]})
            continue
        node_errors: list[str] = []
        _validate_schema_node(schema, document, schema, "$", node_errors)
        if node_errors:
            errors.append({"path": str(path), "errors": node_errors})
    return errors


def _validate_schema_node(
    schema: dict[str, Any],
    value: Any,
    root: dict[str, Any],
    path: str,
    errors: list[str],
) -> None:
    if "$ref" in schema:
        _validate_schema_node(
            _resolve_schema_ref(root, str(schema["$ref"])), value, root, path, errors
        )
        return

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}, got {value!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: expected one of {schema['enum']!r}, got {value!r}")

    if "type" in schema:
        expected = schema["type"]
        expected_types = expected if isinstance(expected, list) else [expected]
        if not any(
            _matches_json_type(value, str(expected_type)) for expected_type in expected_types
        ):
            errors.append(f"{path}: expected type {expected_types!r}, got {type(value).__name__}")
            return

    properties = schema.get("properties")
    if isinstance(properties, dict) and isinstance(value, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                errors.append(f"{path}: missing required key {key!r}")
        if schema.get("additionalProperties") is False:
            for key in sorted(set(value) - set(properties)):
                errors.append(f"{path}: unexpected key {key!r}")
        for key, child_schema in properties.items():
            if key in value:
                _validate_schema_node(child_schema, value[key], root, f"{path}.{key}", errors)

    items = schema.get("items")
    if isinstance(items, dict) and isinstance(value, list):
        for index, item in enumerate(value):
            _validate_schema_node(items, item, root, f"{path}[{index}]", errors)


def _resolve_schema_ref(root: dict[str, Any], ref: str) -> dict[str, Any]:
    if not ref.startswith("#/"):
        raise ValueError(f"unsupported schema ref: {ref}")
    node: Any = root
    for raw_part in ref[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        node = node[part]
    if not isinstance(node, dict):
        raise ValueError(f"schema ref is not an object: {ref}")
    return node


def _matches_json_type(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "number":
        return isinstance(value, int | float) and not isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    raise ValueError(f"unsupported schema type: {expected}")


def _scenario_requirement_values(check: DoctorCheck, key: str) -> tuple[str, ...]:
    if check.status is not DoctorStatus.PASS or check.details is None:
        return ()
    value = check.details.get(key, ())
    if not isinstance(value, list | tuple):
        return ()
    return tuple(str(item) for item in value)


def _requirement_values(check: DoctorCheck | None, key: str) -> tuple[str, ...]:
    if check is None or check.status is not DoctorStatus.PASS or check.details is None:
        return ()
    value = check.details.get(key, ())
    if not isinstance(value, list | tuple):
        return ()
    return tuple(str(item) for item in value)


def _testbed_profiles_check(profile_ids: tuple[str, ...]) -> DoctorCheck:
    try:
        inventory = build_testbed_requirements_inventory(profile_ids)
    except Exception as exc:
        return DoctorCheck(
            "testbed_profiles",
            DoctorStatus.FAIL,
            "testbed requirement profiles are not readable",
            {"profiles": list(profile_ids), "error": f"{type(exc).__name__}: {exc}"},
        )
    return DoctorCheck(
        "testbed_profiles",
        DoctorStatus.PASS,
        "testbed requirement profiles are readable",
        inventory.to_json(),
    )


def _unique(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _without(values: tuple[str, ...], excluded: tuple[str, ...]) -> tuple[str, ...]:
    excluded_set = set(excluded)
    return tuple(value for value in values if value not in excluded_set)


def _artifact_dir_check(artifact_dir: Path) -> DoctorCheck:
    try:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        probe = artifact_dir / ".celatim-doctor-write-test"
        probe.write_text("ok\n")
        probe.unlink()
        return DoctorCheck(
            "artifact_dir",
            DoctorStatus.PASS,
            "artifact directory is writable",
            {"path": str(artifact_dir)},
        )
    except Exception as exc:
        return DoctorCheck(
            "artifact_dir",
            DoctorStatus.FAIL,
            "artifact directory is not writable",
            {"path": str(artifact_dir), "error": f"{type(exc).__name__}: {exc}"},
        )


def _tool_checks(tools: tuple[str, ...], *, required: bool) -> tuple[DoctorCheck, ...]:
    checks: list[DoctorCheck] = []
    for tool in tools:
        path = shutil.which(tool)
        if path is None:
            checks.append(
                DoctorCheck(
                    f"tool:{tool}",
                    DoctorStatus.FAIL if required else DoctorStatus.WARN,
                    f"{tool} is not installed",
                    {"tool": tool, "required": required},
                )
            )
        else:
            checks.append(
                DoctorCheck(
                    f"tool:{tool}",
                    DoctorStatus.PASS,
                    f"{tool} is installed",
                    {
                        "tool": tool,
                        "path": path,
                        "required": required,
                        **_tool_version_detail(tool, path),
                    },
                )
            )
    return tuple(checks)


def _tool_version_detail(tool: str, path: str) -> dict[str, Any]:
    command = TOOL_VERSION_COMMANDS.get(tool)
    if command is None:
        return {
            "version_command": None,
            "version_status": "not_configured",
            "version_output": None,
        }
    argv = (path, *command[1:])
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=TOOL_VERSION_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "version_command": list(argv),
            "version_status": "timeout",
            "version_output": None,
            "version_timeout_s": TOOL_VERSION_TIMEOUT_S,
        }
    except OSError as exc:
        return {
            "version_command": list(argv),
            "version_status": "error",
            "version_output": None,
            "version_error": f"{type(exc).__name__}: {exc}",
        }

    output = "\n".join(
        part.strip() for part in (completed.stdout, completed.stderr) if part and part.strip()
    )
    return {
        "version_command": list(argv),
        "version_status": "ok" if completed.returncode == 0 else "error",
        "version_returncode": completed.returncode,
        "version_output": output[:4000],
    }


def _extra_checks(extras: tuple[str, ...], *, required: bool) -> tuple[DoctorCheck, ...]:
    return tuple(_extra_check(extra, required=required) for extra in extras)


def _extra_check(extra: str, *, required: bool) -> DoctorCheck:
    modules = PACKAGE_EXTRA_MODULES.get(extra)
    if modules is None:
        return DoctorCheck(
            f"extra:{extra}",
            DoctorStatus.FAIL if required else DoctorStatus.WARN,
            f"{extra} is not a known package extra",
            {
                "extra": extra,
                "required": required,
                "known_extras": sorted(PACKAGE_EXTRA_MODULES),
            },
        )

    module_details = [_module_detail(module, distribution) for module, distribution in modules]
    missing = [detail["module"] for detail in module_details if not detail["installed"]]
    status = DoctorStatus.PASS
    if missing:
        status = DoctorStatus.FAIL if required else DoctorStatus.WARN
    return DoctorCheck(
        f"extra:{extra}",
        status,
        _extra_message(extra, missing, required=required),
        {
            "extra": extra,
            "required": required,
            "modules": module_details,
            "missing_modules": missing,
        },
    )


def _module_detail(module: str, distribution: str) -> dict[str, Any]:
    spec = importlib.util.find_spec(module)
    installed = spec is not None
    details: dict[str, Any] = {
        "module": module,
        "distribution": distribution,
        "installed": installed,
    }
    if installed:
        details["origin"] = spec.origin
        try:
            details["version"] = version(distribution)
        except PackageNotFoundError:
            details["version"] = None
    return details


def _extra_message(extra: str, missing: list[str], *, required: bool) -> str:
    if not PACKAGE_EXTRA_MODULES[extra]:
        return f"{extra} extra currently has no Python module dependencies"
    if not missing:
        return f"{extra} extra dependencies are installed"
    prefix = "required" if required else "optional"
    return f"{prefix} {extra} extra dependencies are missing: {', '.join(missing)}"


def _privilege_checks(privileges: tuple[str, ...]) -> tuple[DoctorCheck, ...]:
    return tuple(_privilege_check(privilege) for privilege in privileges)


def _privilege_check(privilege: str) -> DoctorCheck:
    available, details = _privilege_available(privilege)
    details = {"privilege": privilege, "required": True, **details}
    return DoctorCheck(
        f"privilege:{privilege}",
        DoctorStatus.PASS if available else DoctorStatus.FAIL,
        f"{privilege} privilege is {'available' if available else 'not available'}",
        details,
    )


def _privilege_available(privilege: str) -> tuple[bool, dict[str, Any]]:
    if privilege == "none":
        return True, {"method": "none"}
    if privilege == "root":
        euid = os.geteuid()
        return euid == 0, {"method": "euid", "euid": euid}
    if privilege == "cap_net_admin":
        return _linux_capability_available("CAP_NET_ADMIN", 12)
    if privilege == "cap_net_raw":
        return _linux_capability_available("CAP_NET_RAW", 13)
    if privilege == "docker":
        return _docker_privilege_available()
    if privilege == "kvm":
        return _kvm_privilege_available()
    return False, {"method": "unknown", "known_privileges": _known_privileges()}


def _linux_capability_available(name: str, bit: int) -> tuple[bool, dict[str, Any]]:
    cap_eff = _effective_capabilities()
    if cap_eff is None:
        euid = os.geteuid()
        return euid == 0, {
            "method": "euid_root_fallback",
            "capability": name,
            "capability_bit": bit,
            "euid": euid,
            "cap_eff": None,
        }
    available = bool(cap_eff & (1 << bit))
    return available, {
        "method": "linux_cap_eff",
        "capability": name,
        "capability_bit": bit,
        "cap_eff": f"0x{cap_eff:x}",
    }


def _effective_capabilities() -> int | None:
    status = Path("/proc/self/status")
    try:
        for line in status.read_text().splitlines():
            if line.startswith("CapEff:"):
                return int(line.split(":", 1)[1].strip(), 16)
    except OSError:
        return None
    return None


def _docker_privilege_available() -> tuple[bool, dict[str, Any]]:
    docker_path = shutil.which("docker")
    docker_host = os.environ.get("DOCKER_HOST")
    socket = Path("/var/run/docker.sock")
    socket_access = socket.exists() and os.access(socket, os.R_OK | os.W_OK)
    available = docker_path is not None and (docker_host is not None or socket_access)
    return available, {
        "method": "docker_client_and_socket",
        "docker_path": docker_path,
        "docker_host": docker_host,
        "socket": str(socket),
        "socket_exists": socket.exists(),
        "socket_read_write": socket_access,
    }


def _kvm_privilege_available() -> tuple[bool, dict[str, Any]]:
    kvm = Path("/dev/kvm")
    access = kvm.exists() and os.access(kvm, os.R_OK | os.W_OK)
    return access, {
        "method": "device_access",
        "device": str(kvm),
        "device_exists": kvm.exists(),
        "device_read_write": access,
    }


def _known_privileges() -> tuple[str, ...]:
    return ("none", "cap_net_admin", "cap_net_raw", "root", "docker", "kvm")


def _package_version() -> str:
    try:
        return version("celatim")
    except PackageNotFoundError:
        return "0.1.0"


__all__ = [
    "DEFAULT_OPTIONAL_TOOLS",
    "DOCTOR_SCHEMA_VERSION",
    "PACKAGE_EXTRA_MODULES",
    "TOOL_VERSION_COMMANDS",
    "DoctorCheck",
    "DoctorResult",
    "DoctorStatus",
    "run_doctor",
]
