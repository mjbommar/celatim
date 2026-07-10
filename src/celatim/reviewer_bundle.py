"""Reviewer artifact bundle manifests."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from time import time
from typing import Any

from .detect.replay import DETECTOR_REPLAY_CORPUS_SCHEMA_VERSION, DETECTOR_REPLAY_SCHEMA_VERSION
from .detect.scrub import SCRUB_REPORT_SCHEMA_VERSION
from .doctor import DOCTOR_SCHEMA_VERSION
from .evidence_index import INDEX_SCHEMA_VERSION, PUBLIC_INDEX_SCHEMA_VERSION
from .scenario import (
    SCENARIO_EXECUTION_PLAN_SCHEMA_VERSION,
    SCENARIO_INVENTORY_SCHEMA_VERSION,
)
from .testbed import TESTBED_REQUIREMENTS_SCHEMA_VERSION
from .testbed.qemu import QEMU_TAP_PREFLIGHT_SCHEMA_VERSION

BUNDLE_SCHEMA_VERSION = "celatim.reviewer_bundle.v1"
BUNDLE_VERIFY_SCHEMA_VERSION = "celatim.reviewer_bundle_verify.v1"
PUBLIC_BUNDLE_SCHEMA_VERSION = "celatim.public_bundle.v1"
PUBLIC_BUNDLE_VERIFY_SCHEMA_VERSION = "celatim.public_bundle_verify.v1"
PUBLIC_BUNDLE_RELEASE_SCOPE = "public_safe"
PUBLIC_BUNDLE_PRIVATE_REFERENCE_POLICY = "hash_only_no_channel_artifacts"
EVIDENCE_INDEX_SUMMARY_FIELDS = (
    "evidence_count",
    "ok_count",
    "failed_count",
    "run_log_artifact_count",
    "transport_artifact_count",
    "evidence_tier_counts",
    "privilege_counts",
    "expected_runtime_s_total",
    "required_tools",
    "required_extras",
)
PUBLIC_BUNDLE_ARTIFACT_KINDS = (
    "mechanism_catalog",
    "support_matrix",
    "detector_scrub_guidance",
    "detector_rule_artifact",
    "windows_capture_guidance",
    "scenario_inventory",
    "scenario_execution_plan",
    "testbed_requirements",
    "evidence_index",
    "paper_table",
    "reviewer_bundle_manifest",
    "reviewer_bundle_verification",
)
PUBLIC_BUNDLE_REQUIRED_ARTIFACT_KINDS = (
    "mechanism_catalog",
    "support_matrix",
    "detector_scrub_guidance",
    "scenario_inventory",
    "evidence_index",
    "reviewer_bundle_manifest",
    "reviewer_bundle_verification",
)
PUBLIC_BUNDLE_FORBIDDEN_PATH_PARTS = (
    "carriers",
    "evidence",
    "experiments",
    "pcaps",
    "run-logs",
    "src",
)
PUBLIC_BUNDLE_FORBIDDEN_SUFFIXES = (
    ".pcap",
    ".py",
    ".pyc",
    ".jsonl",
)
DETECTOR_REPLAY_SCHEMA_VERSIONS = (
    DETECTOR_REPLAY_SCHEMA_VERSION,
    DETECTOR_REPLAY_CORPUS_SCHEMA_VERSION,
)
TESTBED_PREFLIGHT_SCHEMA_VERSIONS = (QEMU_TAP_PREFLIGHT_SCHEMA_VERSION,)
SCRUB_REPORT_SCHEMA_VERSIONS = (SCRUB_REPORT_SCHEMA_VERSION,)


@dataclass(frozen=True)
class BundleArtifactRef:
    kind: str
    path: str
    sha256: str
    size_bytes: int

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class ReviewerBundleManifest:
    schema_version: str
    generated_at_unix_s: float
    bundle_name: str
    bundle_root: str
    artifact_count: int
    doctor_ok: bool
    scenario_count: int
    evidence_count: int
    ok_count: int
    failed_count: int
    run_log_artifact_count: int
    transport_artifact_count: int
    evidence_tier_counts: dict[str, int]
    privilege_counts: dict[str, int]
    expected_runtime_s_total: float | None
    required_tools: tuple[str, ...]
    required_extras: tuple[str, ...]
    artifacts: tuple[BundleArtifactRef, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at_unix_s": self.generated_at_unix_s,
            "bundle_name": self.bundle_name,
            "bundle_root": self.bundle_root,
            "artifact_count": self.artifact_count,
            "doctor_ok": self.doctor_ok,
            "scenario_count": self.scenario_count,
            "evidence_count": self.evidence_count,
            "ok_count": self.ok_count,
            "failed_count": self.failed_count,
            "run_log_artifact_count": self.run_log_artifact_count,
            "transport_artifact_count": self.transport_artifact_count,
            "evidence_tier_counts": dict(self.evidence_tier_counts),
            "privilege_counts": dict(self.privilege_counts),
            "expected_runtime_s_total": self.expected_runtime_s_total,
            "required_tools": list(self.required_tools),
            "required_extras": list(self.required_extras),
            "artifacts": [artifact.to_json() for artifact in self.artifacts],
        }


@dataclass(frozen=True)
class PublicBundleManifest:
    schema_version: str
    generated_at_unix_s: float
    bundle_name: str
    bundle_root: str
    release_scope: str
    private_reference_policy: str
    artifact_count: int
    private_reviewer_bundle_name: str | None
    private_reviewer_bundle_verified: bool
    private_reviewer_artifact_count: int
    private_reviewer_artifact_kinds: tuple[str, ...]
    scenario_count: int
    evidence_count: int
    ok_count: int
    failed_count: int
    run_log_artifact_count: int
    transport_artifact_count: int
    evidence_tier_counts: dict[str, int]
    privilege_counts: dict[str, int]
    expected_runtime_s_total: float | None
    required_tools: tuple[str, ...]
    required_extras: tuple[str, ...]
    artifacts: tuple[BundleArtifactRef, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at_unix_s": self.generated_at_unix_s,
            "bundle_name": self.bundle_name,
            "bundle_root": self.bundle_root,
            "release_scope": self.release_scope,
            "private_reference_policy": self.private_reference_policy,
            "artifact_count": self.artifact_count,
            "private_reviewer_bundle_name": self.private_reviewer_bundle_name,
            "private_reviewer_bundle_verified": self.private_reviewer_bundle_verified,
            "private_reviewer_artifact_count": self.private_reviewer_artifact_count,
            "private_reviewer_artifact_kinds": list(self.private_reviewer_artifact_kinds),
            "scenario_count": self.scenario_count,
            "evidence_count": self.evidence_count,
            "ok_count": self.ok_count,
            "failed_count": self.failed_count,
            "run_log_artifact_count": self.run_log_artifact_count,
            "transport_artifact_count": self.transport_artifact_count,
            "evidence_tier_counts": dict(self.evidence_tier_counts),
            "privilege_counts": dict(self.privilege_counts),
            "expected_runtime_s_total": self.expected_runtime_s_total,
            "required_tools": list(self.required_tools),
            "required_extras": list(self.required_extras),
            "artifacts": [artifact.to_json() for artifact in self.artifacts],
        }


@dataclass(frozen=True)
class BundleArtifactVerification:
    kind: str | None
    path: str | None
    expected_sha256: str | None
    actual_sha256: str | None
    expected_size_bytes: int | None
    actual_size_bytes: int | None
    ok: bool
    error: str | None

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "expected_sha256": self.expected_sha256,
            "actual_sha256": self.actual_sha256,
            "expected_size_bytes": self.expected_size_bytes,
            "actual_size_bytes": self.actual_size_bytes,
            "ok": self.ok,
            "error": self.error,
        }


@dataclass(frozen=True)
class BundleConsistencyCheck:
    check: str
    expected: Any
    actual: Any
    ok: bool
    error: str | None

    def to_json(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "expected": self.expected,
            "actual": self.actual,
            "ok": self.ok,
            "error": self.error,
        }


@dataclass(frozen=True)
class ReviewerBundleVerification:
    schema_version: str
    generated_at_unix_s: float
    manifest_path: str
    manifest_schema_version: str | None
    bundle_name: str | None
    ok: bool
    error: str | None
    artifact_count: int
    ok_count: int
    missing_count: int
    mismatch_count: int
    invalid_count: int
    consistency_check_count: int
    consistency_ok_count: int
    consistency_failed_count: int
    artifacts: tuple[BundleArtifactVerification, ...]
    consistency_checks: tuple[BundleConsistencyCheck, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at_unix_s": self.generated_at_unix_s,
            "manifest_path": self.manifest_path,
            "manifest_schema_version": self.manifest_schema_version,
            "bundle_name": self.bundle_name,
            "ok": self.ok,
            "error": self.error,
            "artifact_count": self.artifact_count,
            "ok_count": self.ok_count,
            "missing_count": self.missing_count,
            "mismatch_count": self.mismatch_count,
            "invalid_count": self.invalid_count,
            "consistency_check_count": self.consistency_check_count,
            "consistency_ok_count": self.consistency_ok_count,
            "consistency_failed_count": self.consistency_failed_count,
            "artifacts": [artifact.to_json() for artifact in self.artifacts],
            "consistency_checks": [check.to_json() for check in self.consistency_checks],
        }


@dataclass(frozen=True)
class PublicBundleVerification:
    schema_version: str
    generated_at_unix_s: float
    manifest_path: str
    manifest_schema_version: str | None
    bundle_name: str | None
    ok: bool
    error: str | None
    artifact_count: int
    ok_count: int
    missing_count: int
    mismatch_count: int
    invalid_count: int
    policy_check_count: int
    policy_ok_count: int
    policy_failed_count: int
    artifacts: tuple[BundleArtifactVerification, ...]
    policy_checks: tuple[BundleConsistencyCheck, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at_unix_s": self.generated_at_unix_s,
            "manifest_path": self.manifest_path,
            "manifest_schema_version": self.manifest_schema_version,
            "bundle_name": self.bundle_name,
            "ok": self.ok,
            "error": self.error,
            "artifact_count": self.artifact_count,
            "ok_count": self.ok_count,
            "missing_count": self.missing_count,
            "mismatch_count": self.mismatch_count,
            "invalid_count": self.invalid_count,
            "policy_check_count": self.policy_check_count,
            "policy_ok_count": self.policy_ok_count,
            "policy_failed_count": self.policy_failed_count,
            "artifacts": [artifact.to_json() for artifact in self.artifacts],
            "policy_checks": [check.to_json() for check in self.policy_checks],
        }


def build_reviewer_bundle_manifest(
    *,
    bundle_name: str,
    bundle_root: Path | str,
    doctor_path: Path | str,
    scenario_inventory_path: Path | str,
    evidence_index_path: Path | str,
    paper_table_path: Path | str | None = None,
    package_wheel_path: Path | str | None = None,
    lockfile_path: Path | str | None = None,
    detector_replay_paths: Iterable[Path | str] = (),
    scrub_report_paths: Iterable[Path | str] = (),
    scenario_spec_paths: Iterable[Path | str] = (),
    testbed_package_paths: Iterable[Path | str] = (),
    testbed_preflight_paths: Iterable[Path | str] = (),
) -> ReviewerBundleManifest:
    root = Path(bundle_root)
    doctor = _load_json(doctor_path, "doctor")
    scenario_inventory = _load_json(scenario_inventory_path, "scenario_inventory")
    evidence_index = _load_json(evidence_index_path, "evidence_index")
    _validate_schema_version(doctor, DOCTOR_SCHEMA_VERSION, "doctor")
    _validate_schema_version(
        scenario_inventory,
        SCENARIO_INVENTORY_SCHEMA_VERSION,
        "scenario_inventory",
    )
    _validate_schema_version(evidence_index, INDEX_SCHEMA_VERSION, "evidence_index")
    artifacts = [
        _artifact_ref("doctor_report", doctor_path, root),
        _artifact_ref("scenario_inventory", scenario_inventory_path, root),
        _artifact_ref("evidence_index", evidence_index_path, root),
    ]
    for path in detector_replay_paths:
        _validate_detector_replay(path)
        artifacts.append(_artifact_ref("detector_replay", path, root))
    for path in scrub_report_paths:
        _validate_scrub_report(path)
        artifacts.append(_artifact_ref("scrub_report", path, root))
    if paper_table_path is not None:
        artifacts.append(_artifact_ref("paper_table", paper_table_path, root))
    if package_wheel_path is not None:
        artifacts.append(_artifact_ref("package_wheel", package_wheel_path, root))
    if lockfile_path is not None:
        artifacts.append(_artifact_ref("lockfile", lockfile_path, root))
    artifacts.extend(_artifact_ref("scenario_spec", path, root) for path in scenario_spec_paths)
    artifacts.extend(_artifact_ref("testbed_package", path, root) for path in testbed_package_paths)
    for path in testbed_preflight_paths:
        _validate_testbed_preflight(path)
        artifacts.append(_artifact_ref("testbed_preflight", path, root))
    return ReviewerBundleManifest(
        schema_version=BUNDLE_SCHEMA_VERSION,
        generated_at_unix_s=time(),
        bundle_name=bundle_name,
        bundle_root=str(root),
        artifact_count=len(artifacts),
        doctor_ok=_bool(doctor, "ok"),
        scenario_count=int(scenario_inventory.get("scenario_count", 0)),
        evidence_count=int(evidence_index.get("evidence_count", 0)),
        ok_count=int(evidence_index.get("ok_count", 0)),
        failed_count=int(evidence_index.get("failed_count", 0)),
        run_log_artifact_count=int(evidence_index.get("run_log_artifact_count", 0)),
        transport_artifact_count=int(evidence_index.get("transport_artifact_count", 0)),
        evidence_tier_counts=_count_map(evidence_index.get("evidence_tier_counts", {})),
        privilege_counts=_count_map(evidence_index.get("privilege_counts", {})),
        expected_runtime_s_total=_optional_float(evidence_index.get("expected_runtime_s_total")),
        required_tools=_str_tuple(evidence_index.get("required_tools", ()), "required_tools"),
        required_extras=_str_tuple(
            evidence_index.get("required_extras", ()),
            "required_extras",
        ),
        artifacts=tuple(artifacts),
    )


def build_public_bundle_manifest(
    *,
    bundle_name: str,
    bundle_root: Path | str,
    catalog_path: Path | str,
    support_matrix_path: Path | str,
    detector_scrub_guidance_path: Path | str,
    scenario_inventory_path: Path | str,
    scenario_execution_plan_path: Path | str | None = None,
    testbed_requirements_path: Path | str | None = None,
    evidence_index_path: Path | str,
    reviewer_manifest_path: Path | str,
    reviewer_verification_path: Path | str,
    paper_table_path: Path | str | None = None,
    detector_rule_artifact_paths: Iterable[Path | str] = (),
    windows_capture_guidance_path: Path | str | None = None,
) -> PublicBundleManifest:
    root = Path(bundle_root)
    scenario_inventory = _load_json(scenario_inventory_path, "scenario_inventory")
    evidence_index = _load_json(evidence_index_path, "evidence_index")
    reviewer_manifest = _load_json(reviewer_manifest_path, "reviewer_bundle_manifest")
    reviewer_verification = _load_json(
        reviewer_verification_path,
        "reviewer_bundle_verification",
    )
    _validate_schema_version(
        scenario_inventory,
        SCENARIO_INVENTORY_SCHEMA_VERSION,
        "scenario_inventory",
    )
    if scenario_execution_plan_path is not None:
        scenario_execution_plan = _load_json(
            scenario_execution_plan_path,
            "scenario_execution_plan",
        )
    if testbed_requirements_path is not None:
        testbed_requirements = _load_json(
            testbed_requirements_path,
            "testbed_requirements",
        )
        _validate_schema_version(
            testbed_requirements,
            TESTBED_REQUIREMENTS_SCHEMA_VERSION,
            "testbed_requirements",
        )
        _validate_schema_version(
            scenario_execution_plan,
            SCENARIO_EXECUTION_PLAN_SCHEMA_VERSION,
            "scenario_execution_plan",
        )
    _validate_schema_version(evidence_index, PUBLIC_INDEX_SCHEMA_VERSION, "public_evidence_index")
    _validate_schema_version(
        reviewer_manifest,
        BUNDLE_SCHEMA_VERSION,
        "reviewer_bundle_manifest",
    )
    _validate_schema_version(
        reviewer_verification,
        BUNDLE_VERIFY_SCHEMA_VERSION,
        "reviewer_bundle_verification",
    )
    if reviewer_verification.get("ok") is not True:
        raise ValueError("reviewer_bundle_verification ok must be true")
    _validate_reviewer_manifest_summaries(reviewer_manifest, evidence_index)
    detector_rule_artifact_paths = tuple(detector_rule_artifact_paths)
    detector_artifacts = [
        _artifact_ref("detector_rule_artifact", path, root) for path in detector_rule_artifact_paths
    ]
    if windows_capture_guidance_path is not None:
        detector_artifacts.append(
            _artifact_ref("windows_capture_guidance", windows_capture_guidance_path, root)
        )
    artifacts = [
        _artifact_ref("mechanism_catalog", catalog_path, root),
        _artifact_ref("support_matrix", support_matrix_path, root),
        _artifact_ref("detector_scrub_guidance", detector_scrub_guidance_path, root),
        *detector_artifacts,
        _artifact_ref("scenario_inventory", scenario_inventory_path, root),
    ]
    if scenario_execution_plan_path is not None:
        artifacts.append(
            _artifact_ref("scenario_execution_plan", scenario_execution_plan_path, root)
        )
    if testbed_requirements_path is not None:
        artifacts.append(_artifact_ref("testbed_requirements", testbed_requirements_path, root))
    artifacts.append(_artifact_ref("evidence_index", evidence_index_path, root))
    if paper_table_path is not None:
        artifacts.append(_artifact_ref("paper_table", paper_table_path, root))
    artifacts.extend(
        [
            _artifact_ref("reviewer_bundle_manifest", reviewer_manifest_path, root),
            _artifact_ref("reviewer_bundle_verification", reviewer_verification_path, root),
        ]
    )
    return PublicBundleManifest(
        schema_version=PUBLIC_BUNDLE_SCHEMA_VERSION,
        generated_at_unix_s=time(),
        bundle_name=bundle_name,
        bundle_root=str(root),
        release_scope=PUBLIC_BUNDLE_RELEASE_SCOPE,
        private_reference_policy=PUBLIC_BUNDLE_PRIVATE_REFERENCE_POLICY,
        artifact_count=len(artifacts),
        private_reviewer_bundle_name=_optional_json_str(reviewer_manifest.get("bundle_name")),
        private_reviewer_bundle_verified=True,
        private_reviewer_artifact_count=int(reviewer_verification.get("artifact_count", 0)),
        private_reviewer_artifact_kinds=_artifact_kinds(reviewer_verification),
        scenario_count=int(scenario_inventory.get("scenario_count", 0)),
        evidence_count=int(evidence_index.get("evidence_count", 0)),
        ok_count=int(evidence_index.get("ok_count", 0)),
        failed_count=int(evidence_index.get("failed_count", 0)),
        run_log_artifact_count=int(evidence_index.get("run_log_artifact_count", 0)),
        transport_artifact_count=int(evidence_index.get("transport_artifact_count", 0)),
        evidence_tier_counts=_count_map(evidence_index.get("evidence_tier_counts", {})),
        privilege_counts=_count_map(evidence_index.get("privilege_counts", {})),
        expected_runtime_s_total=_optional_float(evidence_index.get("expected_runtime_s_total")),
        required_tools=_str_tuple(evidence_index.get("required_tools", ()), "required_tools"),
        required_extras=_str_tuple(
            evidence_index.get("required_extras", ()),
            "required_extras",
        ),
        artifacts=tuple(artifacts),
    )


def verify_public_bundle_manifest(manifest_path: Path | str) -> PublicBundleVerification:
    path = Path(manifest_path)
    try:
        manifest = _load_json(path, "public_bundle_manifest")
    except Exception as exc:
        return _public_verification_failure(
            path,
            manifest_schema_version=None,
            bundle_name=None,
            error=f"{type(exc).__name__}: {exc}",
        )

    schema_version = manifest.get("schema_version")
    bundle_name = manifest.get("bundle_name")
    if not isinstance(schema_version, str):
        return _public_verification_failure(
            path,
            manifest_schema_version=None,
            bundle_name=_optional_json_str(bundle_name),
            error="public_bundle_manifest schema_version must be a string",
        )
    if schema_version != PUBLIC_BUNDLE_SCHEMA_VERSION:
        return _public_verification_failure(
            path,
            manifest_schema_version=schema_version,
            bundle_name=_optional_json_str(bundle_name),
            error=f"public_bundle_manifest schema_version must be {PUBLIC_BUNDLE_SCHEMA_VERSION!r}",
        )
    artifacts_value = manifest.get("artifacts")
    if not isinstance(artifacts_value, list):
        return _public_verification_failure(
            path,
            manifest_schema_version=schema_version,
            bundle_name=_optional_json_str(bundle_name),
            error="public_bundle_manifest artifacts must be an array",
        )

    root = _verification_root(path, manifest.get("bundle_root"))
    artifacts = tuple(
        _verify_public_artifact(artifact, bundle_root=root) for artifact in artifacts_value
    )
    policy_checks = _public_policy_checks(manifest, artifacts_value, root)
    ok_count = sum(1 for artifact in artifacts if artifact.ok)
    missing_count = sum(1 for artifact in artifacts if artifact.error == "missing")
    mismatch_count = sum(
        1
        for artifact in artifacts
        if artifact.error in {"sha256_mismatch", "size_mismatch", "hash_and_size_mismatch"}
    )
    invalid_count = sum(
        1
        for artifact in artifacts
        if artifact.error is not None
        and artifact.error
        not in {"missing", "sha256_mismatch", "size_mismatch", "hash_and_size_mismatch"}
    )
    policy_ok_count = sum(1 for check in policy_checks if check.ok)
    policy_failed_count = len(policy_checks) - policy_ok_count
    artifact_failed = len(artifacts) != ok_count
    policy_failed = policy_failed_count != 0
    ok = not artifact_failed and not policy_failed
    return PublicBundleVerification(
        schema_version=PUBLIC_BUNDLE_VERIFY_SCHEMA_VERSION,
        generated_at_unix_s=time(),
        manifest_path=str(path),
        manifest_schema_version=schema_version,
        bundle_name=_optional_json_str(bundle_name),
        ok=ok,
        error=_public_bundle_verification_error(
            artifact_failed=artifact_failed,
            policy_failed=policy_failed,
        ),
        artifact_count=len(artifacts),
        ok_count=ok_count,
        missing_count=missing_count,
        mismatch_count=mismatch_count,
        invalid_count=invalid_count,
        policy_check_count=len(policy_checks),
        policy_ok_count=policy_ok_count,
        policy_failed_count=policy_failed_count,
        artifacts=artifacts,
        policy_checks=policy_checks,
    )


def verify_reviewer_bundle_manifest(manifest_path: Path | str) -> ReviewerBundleVerification:
    path = Path(manifest_path)
    try:
        manifest = _load_json(path, "bundle_manifest")
    except Exception as exc:
        return _verification_failure(
            path,
            manifest_schema_version=None,
            bundle_name=None,
            error=f"{type(exc).__name__}: {exc}",
        )

    schema_version = manifest.get("schema_version")
    bundle_name = manifest.get("bundle_name")
    if not isinstance(schema_version, str):
        return _verification_failure(
            path,
            manifest_schema_version=None,
            bundle_name=_optional_json_str(bundle_name),
            error="bundle_manifest schema_version must be a string",
        )
    if schema_version != BUNDLE_SCHEMA_VERSION:
        return _verification_failure(
            path,
            manifest_schema_version=schema_version,
            bundle_name=_optional_json_str(bundle_name),
            error=f"bundle_manifest schema_version must be {BUNDLE_SCHEMA_VERSION!r}",
        )
    artifacts_value = manifest.get("artifacts")
    if not isinstance(artifacts_value, list):
        return _verification_failure(
            path,
            manifest_schema_version=schema_version,
            bundle_name=_optional_json_str(bundle_name),
            error="bundle_manifest artifacts must be an array",
        )

    root = _verification_root(path, manifest.get("bundle_root"))
    direct_artifacts = tuple(
        _verify_artifact(artifact, manifest_path=path, bundle_root=root)
        for artifact in artifacts_value
    )
    nested_artifacts = tuple(
        nested
        for value, verification in zip(artifacts_value, direct_artifacts, strict=True)
        for nested in _nested_artifact_verifications(
            value,
            verification,
            manifest_path=path,
            bundle_root=root,
        )
    )
    artifacts = (*direct_artifacts, *nested_artifacts)
    consistency_checks = _consistency_checks(
        manifest,
        artifacts_value,
        direct_artifacts,
        manifest_path=path,
        bundle_root=root,
    )
    ok_count = sum(1 for artifact in artifacts if artifact.ok)
    missing_count = sum(1 for artifact in artifacts if artifact.error == "missing")
    mismatch_count = sum(
        1
        for artifact in artifacts
        if artifact.error in {"sha256_mismatch", "size_mismatch", "hash_and_size_mismatch"}
    )
    invalid_count = sum(
        1
        for artifact in artifacts
        if artifact.error is not None
        and artifact.error
        not in {"missing", "sha256_mismatch", "size_mismatch", "hash_and_size_mismatch"}
    )
    consistency_ok_count = sum(1 for check in consistency_checks if check.ok)
    consistency_failed_count = len(consistency_checks) - consistency_ok_count
    artifact_failed = len(artifacts) != ok_count
    consistency_failed = consistency_failed_count != 0
    ok = not artifact_failed and not consistency_failed
    return ReviewerBundleVerification(
        schema_version=BUNDLE_VERIFY_SCHEMA_VERSION,
        generated_at_unix_s=time(),
        manifest_path=str(path),
        manifest_schema_version=schema_version,
        bundle_name=_optional_json_str(bundle_name),
        ok=ok,
        error=_bundle_verification_error(
            artifact_failed=artifact_failed,
            consistency_failed=consistency_failed,
        ),
        artifact_count=len(artifacts),
        ok_count=ok_count,
        missing_count=missing_count,
        mismatch_count=mismatch_count,
        invalid_count=invalid_count,
        consistency_check_count=len(consistency_checks),
        consistency_ok_count=consistency_ok_count,
        consistency_failed_count=consistency_failed_count,
        artifacts=artifacts,
        consistency_checks=consistency_checks,
    )


def _load_json(path: Path | str, label: str) -> dict[str, Any]:
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict):
        raise ValueError(f"{label} must be a JSON object")
    return data


def _validate_schema_version(
    document: dict[str, Any],
    expected: str,
    label: str,
) -> None:
    actual = document.get("schema_version")
    if actual != expected:
        raise ValueError(f"{label} schema_version must be {expected!r}")


def _validate_detector_replay(path: Path | str) -> None:
    document = _load_json(path, "detector_replay")
    actual = document.get("schema_version")
    if actual not in DETECTOR_REPLAY_SCHEMA_VERSIONS:
        expected = ", ".join(repr(version) for version in DETECTOR_REPLAY_SCHEMA_VERSIONS)
        raise ValueError(f"detector_replay schema_version must be one of {expected}")


def _validate_scrub_report(path: Path | str) -> None:
    document = _load_json(path, "scrub_report")
    actual = document.get("schema_version")
    if actual not in SCRUB_REPORT_SCHEMA_VERSIONS:
        expected = ", ".join(repr(version) for version in SCRUB_REPORT_SCHEMA_VERSIONS)
        raise ValueError(f"scrub_report schema_version must be one of {expected}")


def _validate_testbed_preflight(path: Path | str) -> None:
    document = _load_json(path, "testbed_preflight")
    actual = document.get("schema_version")
    if actual not in TESTBED_PREFLIGHT_SCHEMA_VERSIONS:
        expected = ", ".join(repr(version) for version in TESTBED_PREFLIGHT_SCHEMA_VERSIONS)
        raise ValueError(f"testbed_preflight schema_version must be one of {expected}")


def _validate_reviewer_manifest_summaries(
    reviewer_manifest: dict[str, Any],
    evidence_index: dict[str, Any],
) -> None:
    for field in EVIDENCE_INDEX_SUMMARY_FIELDS:
        if not _json_values_equal(reviewer_manifest.get(field), evidence_index.get(field)):
            raise ValueError(f"reviewer manifest field {field!r} does not match evidence index")


def _artifact_ref(kind: str, path: Path | str, root: Path) -> BundleArtifactRef:
    artifact_path = Path(path)
    raw = artifact_path.read_bytes()
    return BundleArtifactRef(
        kind=kind,
        path=_display_path(artifact_path, root),
        sha256=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
    )


def _artifact_kinds(reviewer_verification: dict[str, Any]) -> tuple[str, ...]:
    artifacts = reviewer_verification.get("artifacts", [])
    if not isinstance(artifacts, list):
        raise ValueError("reviewer_bundle_verification artifacts must be an array")
    kinds: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ValueError("reviewer_bundle_verification artifact must be an object")
        kind = artifact.get("kind")
        if isinstance(kind, str):
            kinds.add(kind)
    return tuple(sorted(kinds))


def _verify_public_artifact(
    value: Any,
    *,
    bundle_root: Path,
) -> BundleArtifactVerification:
    if not isinstance(value, dict):
        return BundleArtifactVerification(
            kind=None,
            path=None,
            expected_sha256=None,
            actual_sha256=None,
            expected_size_bytes=None,
            actual_size_bytes=None,
            ok=False,
            error="artifact_entry_not_object",
        )
    kind = _optional_json_str(value.get("kind"))
    path_value = _optional_json_str(value.get("path"))
    expected_sha256 = _optional_json_str(value.get("sha256"))
    expected_size = value.get("size_bytes")
    if kind is None:
        error = "artifact_kind_missing"
    elif path_value is None:
        error = "artifact_path_missing"
    elif kind not in PUBLIC_BUNDLE_ARTIFACT_KINDS:
        error = "public_artifact_kind_forbidden"
    elif expected_sha256 is None:
        error = "artifact_sha256_missing"
    elif not isinstance(expected_size, int) or isinstance(expected_size, bool):
        error = "artifact_size_invalid"
    elif not _public_artifact_path_allowed(path_value):
        error = "public_artifact_path_forbidden"
    else:
        error = None
    if error is not None:
        return BundleArtifactVerification(
            kind=kind,
            path=path_value,
            expected_sha256=expected_sha256,
            actual_sha256=None,
            expected_size_bytes=expected_size if isinstance(expected_size, int) else None,
            actual_size_bytes=None,
            ok=False,
            error=error,
        )

    artifact_path = (bundle_root / str(path_value)).resolve()
    try:
        artifact_path.relative_to(bundle_root.resolve())
    except ValueError:
        return BundleArtifactVerification(
            kind=kind,
            path=path_value,
            expected_sha256=expected_sha256,
            actual_sha256=None,
            expected_size_bytes=expected_size,
            actual_size_bytes=None,
            ok=False,
            error="public_artifact_path_forbidden",
        )
    if not artifact_path.is_file():
        return BundleArtifactVerification(
            kind=kind,
            path=path_value,
            expected_sha256=expected_sha256,
            actual_sha256=None,
            expected_size_bytes=expected_size,
            actual_size_bytes=None,
            ok=False,
            error="missing",
        )
    raw = artifact_path.read_bytes()
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    actual_size = len(raw)
    hash_ok = actual_sha256 == expected_sha256
    size_ok = actual_size == expected_size
    semantic_error = None
    if hash_ok and size_ok and kind == "evidence_index":
        semantic_error = _public_evidence_index_error(raw)
    return BundleArtifactVerification(
        kind=kind,
        path=_display_path(artifact_path, bundle_root),
        expected_sha256=expected_sha256,
        actual_sha256=actual_sha256,
        expected_size_bytes=expected_size,
        actual_size_bytes=actual_size,
        ok=hash_ok and size_ok and semantic_error is None,
        error=semantic_error or _verification_error(hash_ok=hash_ok, size_ok=size_ok),
    )


def _public_evidence_index_error(raw: bytes) -> str | None:
    try:
        document = json.loads(raw)
    except Exception:
        return "public_evidence_index_invalid_json"
    if not isinstance(document, dict):
        return "public_evidence_index_not_object"
    if document.get("schema_version") != PUBLIC_INDEX_SCHEMA_VERSION:
        return "public_evidence_index_schema_invalid"
    text = raw.decode(errors="ignore")
    forbidden_markers = ("pcaps/", "carriers/", "run-logs/", "../artifacts/reviewer/")
    if any(marker in text for marker in forbidden_markers):
        return "public_evidence_index_private_path_reference"
    return None


def _public_policy_checks(
    manifest: dict[str, Any],
    artifacts_value: list[Any],
    bundle_root: Path,
) -> tuple[BundleConsistencyCheck, ...]:
    listed_kinds = sorted(
        artifact["kind"]
        for artifact in artifacts_value
        if isinstance(artifact, dict) and isinstance(artifact.get("kind"), str)
    )
    unknown_kinds = sorted(set(listed_kinds) - set(PUBLIC_BUNDLE_ARTIFACT_KINDS))
    missing_required_kinds = sorted(set(PUBLIC_BUNDLE_REQUIRED_ARTIFACT_KINDS) - set(listed_kinds))
    forbidden_listed_paths = sorted(
        artifact["path"]
        for artifact in artifacts_value
        if isinstance(artifact, dict)
        and isinstance(artifact.get("path"), str)
        and not _public_artifact_path_allowed(artifact["path"])
    )
    return (
        _consistency_check(
            "public_bundle.release_scope",
            PUBLIC_BUNDLE_RELEASE_SCOPE,
            manifest.get("release_scope"),
        ),
        _consistency_check(
            "public_bundle.private_reference_policy",
            PUBLIC_BUNDLE_PRIVATE_REFERENCE_POLICY,
            manifest.get("private_reference_policy"),
        ),
        _consistency_check(
            "public_bundle.artifact_count",
            len(artifacts_value),
            manifest.get("artifact_count"),
        ),
        _consistency_check(
            "public_bundle.unknown_artifact_kinds",
            [],
            unknown_kinds,
        ),
        _consistency_check(
            "public_bundle.missing_required_artifact_kinds",
            [],
            missing_required_kinds,
        ),
        _consistency_check(
            "public_bundle.forbidden_listed_paths",
            [],
            forbidden_listed_paths,
        ),
        _consistency_check(
            "public_bundle.forbidden_bundle_files",
            [],
            _forbidden_public_bundle_files(bundle_root),
        ),
    )


def _public_artifact_path_allowed(value: str) -> bool:
    path = Path(value)
    if path.is_absolute():
        return False
    if ".." in path.parts:
        return False
    return not _public_path_forbidden(path)


def _forbidden_public_bundle_files(bundle_root: Path) -> list[str]:
    root = bundle_root.resolve()
    if not root.exists():
        return []
    forbidden: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.resolve().relative_to(root)
        if _public_path_forbidden(relative):
            forbidden.append(str(relative))
    return forbidden


def _public_path_forbidden(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    if parts & set(PUBLIC_BUNDLE_FORBIDDEN_PATH_PARTS):
        return True
    if path.name == "mechanisms.jsonl":
        return False
    return path.suffix.lower() in PUBLIC_BUNDLE_FORBIDDEN_SUFFIXES


def _verification_failure(
    path: Path,
    *,
    manifest_schema_version: str | None,
    bundle_name: str | None,
    error: str,
) -> ReviewerBundleVerification:
    return ReviewerBundleVerification(
        schema_version=BUNDLE_VERIFY_SCHEMA_VERSION,
        generated_at_unix_s=time(),
        manifest_path=str(path),
        manifest_schema_version=manifest_schema_version,
        bundle_name=bundle_name,
        ok=False,
        error=error,
        artifact_count=0,
        ok_count=0,
        missing_count=0,
        mismatch_count=0,
        invalid_count=1,
        consistency_check_count=0,
        consistency_ok_count=0,
        consistency_failed_count=0,
        artifacts=(),
        consistency_checks=(),
    )


def _public_verification_failure(
    path: Path,
    *,
    manifest_schema_version: str | None,
    bundle_name: str | None,
    error: str,
) -> PublicBundleVerification:
    return PublicBundleVerification(
        schema_version=PUBLIC_BUNDLE_VERIFY_SCHEMA_VERSION,
        generated_at_unix_s=time(),
        manifest_path=str(path),
        manifest_schema_version=manifest_schema_version,
        bundle_name=bundle_name,
        ok=False,
        error=error,
        artifact_count=0,
        ok_count=0,
        missing_count=0,
        mismatch_count=0,
        invalid_count=1,
        policy_check_count=0,
        policy_ok_count=0,
        policy_failed_count=0,
        artifacts=(),
        policy_checks=(),
    )


def _consistency_checks(
    manifest: dict[str, Any],
    artifacts_value: list[Any],
    direct_artifacts: tuple[BundleArtifactVerification, ...],
    *,
    manifest_path: Path,
    bundle_root: Path,
) -> tuple[BundleConsistencyCheck, ...]:
    checks: list[BundleConsistencyCheck] = []

    doctor, error = _verified_json_artifact(
        "doctor_report",
        DOCTOR_SCHEMA_VERSION,
        artifacts_value,
        direct_artifacts,
        manifest_path=manifest_path,
        bundle_root=bundle_root,
    )
    if doctor is None:
        checks.append(_source_available_check("doctor_report.available", error))
    else:
        checks.append(_consistency_check("doctor.ok", manifest.get("doctor_ok"), doctor.get("ok")))

    scenario_inventory, error = _verified_json_artifact(
        "scenario_inventory",
        SCENARIO_INVENTORY_SCHEMA_VERSION,
        artifacts_value,
        direct_artifacts,
        manifest_path=manifest_path,
        bundle_root=bundle_root,
    )
    if scenario_inventory is None:
        checks.append(_source_available_check("scenario_inventory.available", error))
    else:
        checks.append(
            _consistency_check(
                "scenario_inventory.scenario_count",
                manifest.get("scenario_count"),
                scenario_inventory.get("scenario_count"),
            )
        )

    evidence_index, error = _verified_json_artifact(
        "evidence_index",
        INDEX_SCHEMA_VERSION,
        artifacts_value,
        direct_artifacts,
        manifest_path=manifest_path,
        bundle_root=bundle_root,
    )
    if evidence_index is None:
        checks.append(_source_available_check("evidence_index.available", error))
    else:
        checks.extend(
            _consistency_check(
                f"evidence_index.{field}",
                manifest.get(field),
                evidence_index.get(field),
            )
            for field in EVIDENCE_INDEX_SUMMARY_FIELDS
        )

    return tuple(checks)


def _verified_json_artifact(
    kind: str,
    schema_version: str,
    artifacts_value: list[Any],
    direct_artifacts: tuple[BundleArtifactVerification, ...],
    *,
    manifest_path: Path,
    bundle_root: Path,
) -> tuple[dict[str, Any] | None, str | None]:
    for value, verification in zip(artifacts_value, direct_artifacts, strict=True):
        if verification.kind != kind:
            continue
        if not verification.ok or not isinstance(verification.path, str):
            return None, "source_unavailable"
        if not isinstance(value, dict):
            return None, "artifact_entry_not_object"
        artifact_path = _resolve_artifact_path(
            verification.path,
            manifest_path=manifest_path,
            bundle_root=bundle_root,
        )
        try:
            document = _load_json(artifact_path, kind)
            _validate_schema_version(document, schema_version, kind)
        except Exception as exc:
            return None, f"{type(exc).__name__}: {exc}"
        return document, None
    return None, "artifact_not_found"


def _source_available_check(check: str, error: str | None) -> BundleConsistencyCheck:
    return BundleConsistencyCheck(
        check=check,
        expected=True,
        actual=False,
        ok=False,
        error=error or "source_unavailable",
    )


def _consistency_check(check: str, expected: Any, actual: Any) -> BundleConsistencyCheck:
    ok = _json_values_equal(expected, actual)
    return BundleConsistencyCheck(
        check=check,
        expected=expected,
        actual=actual,
        ok=ok,
        error=None if ok else "value_mismatch",
    )


def _json_values_equal(left: Any, right: Any) -> bool:
    return json.dumps(left, sort_keys=True, separators=(",", ":")) == json.dumps(
        right,
        sort_keys=True,
        separators=(",", ":"),
    )


def _bundle_verification_error(
    *,
    artifact_failed: bool,
    consistency_failed: bool,
) -> str | None:
    if artifact_failed and consistency_failed:
        return "bundle_verification_failed"
    if artifact_failed:
        return "artifact_verification_failed"
    if consistency_failed:
        return "consistency_verification_failed"
    return None


def _public_bundle_verification_error(
    *,
    artifact_failed: bool,
    policy_failed: bool,
) -> str | None:
    if artifact_failed and policy_failed:
        return "public_bundle_verification_failed"
    if artifact_failed:
        return "artifact_verification_failed"
    if policy_failed:
        return "public_policy_verification_failed"
    return None


def _verification_root(manifest_path: Path, value: Any) -> Path:
    if not isinstance(value, str) or not value:
        return manifest_path.parent
    root = Path(value)
    if root.is_absolute():
        return root
    cwd_root = (Path.cwd() / root).resolve()
    if cwd_root.exists():
        return cwd_root
    if root.name == manifest_path.parent.name:
        return manifest_path.parent.resolve()
    return (manifest_path.parent / root).resolve()


def _verify_artifact(
    value: Any,
    *,
    manifest_path: Path,
    bundle_root: Path,
) -> BundleArtifactVerification:
    if not isinstance(value, dict):
        return BundleArtifactVerification(
            kind=None,
            path=None,
            expected_sha256=None,
            actual_sha256=None,
            expected_size_bytes=None,
            actual_size_bytes=None,
            ok=False,
            error="artifact_entry_not_object",
        )
    kind = _optional_json_str(value.get("kind"))
    path_value = _optional_json_str(value.get("path"))
    expected_sha256 = _optional_json_str(value.get("sha256"))
    expected_size = value.get("size_bytes")
    if kind is None:
        error = "artifact_kind_missing"
    elif path_value is None:
        error = "artifact_path_missing"
    elif expected_sha256 is None:
        error = "artifact_sha256_missing"
    elif not isinstance(expected_size, int) or isinstance(expected_size, bool):
        error = "artifact_size_invalid"
    else:
        error = None
    if error is not None:
        return BundleArtifactVerification(
            kind=kind,
            path=path_value,
            expected_sha256=expected_sha256,
            actual_sha256=None,
            expected_size_bytes=expected_size if isinstance(expected_size, int) else None,
            actual_size_bytes=None,
            ok=False,
            error=error,
        )

    artifact_path = _resolve_artifact_path(
        str(path_value),
        manifest_path=manifest_path,
        bundle_root=bundle_root,
    )
    if not artifact_path.is_file():
        return BundleArtifactVerification(
            kind=kind,
            path=path_value,
            expected_sha256=expected_sha256,
            actual_sha256=None,
            expected_size_bytes=expected_size,
            actual_size_bytes=None,
            ok=False,
            error="missing",
        )
    raw = artifact_path.read_bytes()
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    actual_size = len(raw)
    hash_ok = actual_sha256 == expected_sha256
    size_ok = actual_size == expected_size
    return BundleArtifactVerification(
        kind=kind,
        path=_display_path(artifact_path, bundle_root),
        expected_sha256=expected_sha256,
        actual_sha256=actual_sha256,
        expected_size_bytes=expected_size,
        actual_size_bytes=actual_size,
        ok=hash_ok and size_ok,
        error=_verification_error(hash_ok=hash_ok, size_ok=size_ok),
    )


def _nested_artifact_verifications(
    value: Any,
    verification: BundleArtifactVerification,
    *,
    manifest_path: Path,
    bundle_root: Path,
) -> tuple[BundleArtifactVerification, ...]:
    if verification.kind != "evidence_index" or not verification.ok:
        return ()
    if not isinstance(value, dict) or not isinstance(verification.path, str):
        return ()
    evidence_index_path = _resolve_artifact_path(
        verification.path,
        manifest_path=manifest_path,
        bundle_root=bundle_root,
    )
    try:
        evidence_index = _load_json(evidence_index_path, "evidence_index")
        _validate_schema_version(evidence_index, INDEX_SCHEMA_VERSION, "evidence_index")
        items = evidence_index.get("items", [])
        if not isinstance(items, list):
            raise ValueError("evidence_index items must be an array")
    except Exception as exc:
        return (
            BundleArtifactVerification(
                kind="evidence_index_nested_artifacts",
                path=verification.path,
                expected_sha256=None,
                actual_sha256=None,
                expected_size_bytes=None,
                actual_size_bytes=None,
                ok=False,
                error=f"{type(exc).__name__}: {exc}",
            ),
        )

    verifications: list[BundleArtifactVerification] = []
    seen: set[tuple[str | None, str | None]] = set()
    for item in items:
        if not isinstance(item, dict):
            verifications.append(
                BundleArtifactVerification(
                    kind="evidence_run",
                    path=None,
                    expected_sha256=None,
                    actual_sha256=None,
                    expected_size_bytes=None,
                    actual_size_bytes=None,
                    ok=False,
                    error="evidence_index_item_not_object",
                )
            )
            continue
        evidence_run_ref = _artifact_value_from_mapping(item, default_kind="evidence_run")
        evidence_run_verification = _append_verified_artifact(
            verifications,
            seen,
            evidence_run_ref,
            manifest_path=manifest_path,
            bundle_root=bundle_root,
        )
        if evidence_run_verification is not None and evidence_run_verification.ok:
            verifications.extend(
                _carrier_artifact_verifications(
                    evidence_run_verification.path,
                    manifest_path=manifest_path,
                    bundle_root=bundle_root,
                    seen=seen,
                )
            )

        run_log = item.get("run_log")
        if run_log is not None:
            _append_verified_artifact(
                verifications,
                seen,
                run_log,
                manifest_path=manifest_path,
                bundle_root=bundle_root,
            )
        transport_artifacts = item.get("transport_artifacts", [])
        if isinstance(transport_artifacts, list):
            for artifact in transport_artifacts:
                _append_verified_artifact(
                    verifications,
                    seen,
                    artifact,
                    manifest_path=manifest_path,
                    bundle_root=bundle_root,
                )
        else:
            verifications.append(
                BundleArtifactVerification(
                    kind="transport_artifact",
                    path=None,
                    expected_sha256=None,
                    actual_sha256=None,
                    expected_size_bytes=None,
                    actual_size_bytes=None,
                    ok=False,
                    error="transport_artifacts_not_array",
                )
            )
    return tuple(verifications)


def _append_verified_artifact(
    verifications: list[BundleArtifactVerification],
    seen: set[tuple[str | None, str | None]],
    value: Any,
    *,
    manifest_path: Path,
    bundle_root: Path,
) -> BundleArtifactVerification | None:
    key = _artifact_identity(value)
    if key in seen:
        return None
    seen.add(key)
    verification = _verify_artifact(
        value,
        manifest_path=manifest_path,
        bundle_root=bundle_root,
    )
    verifications.append(verification)
    return verification


def _carrier_artifact_verifications(
    evidence_run_path: str | None,
    *,
    manifest_path: Path,
    bundle_root: Path,
    seen: set[tuple[str | None, str | None]],
) -> tuple[BundleArtifactVerification, ...]:
    if evidence_run_path is None:
        return ()
    path = _resolve_artifact_path(
        evidence_run_path,
        manifest_path=manifest_path,
        bundle_root=bundle_root,
    )
    try:
        evidence_run = _load_json(path, "evidence_run")
    except Exception as exc:
        return (
            BundleArtifactVerification(
                kind="carrier_artifact",
                path=evidence_run_path,
                expected_sha256=None,
                actual_sha256=None,
                expected_size_bytes=None,
                actual_size_bytes=None,
                ok=False,
                error=f"{type(exc).__name__}: {exc}",
            ),
        )

    verifications: list[BundleArtifactVerification] = []
    for case_name in ("covert", "benign_control"):
        case = evidence_run.get(case_name)
        if not isinstance(case, dict):
            continue
        artifacts = case.get("artifacts", [])
        if not isinstance(artifacts, list):
            verifications.append(
                BundleArtifactVerification(
                    kind="carrier_artifact",
                    path=None,
                    expected_sha256=None,
                    actual_sha256=None,
                    expected_size_bytes=None,
                    actual_size_bytes=None,
                    ok=False,
                    error=f"{case_name}_artifacts_not_array",
                )
            )
            continue
        for artifact in artifacts:
            _append_verified_artifact(
                verifications,
                seen,
                artifact,
                manifest_path=manifest_path,
                bundle_root=bundle_root,
            )
    return tuple(verifications)


def _artifact_value_from_mapping(value: dict[str, Any], *, default_kind: str) -> dict[str, Any]:
    return {
        "kind": value.get("kind", default_kind),
        "path": value.get("path"),
        "sha256": value.get("sha256"),
        "size_bytes": value.get("size_bytes"),
    }


def _artifact_identity(value: Any) -> tuple[str | None, str | None]:
    if not isinstance(value, dict):
        return None, None
    return _optional_json_str(value.get("kind")), _optional_json_str(value.get("path"))


def _resolve_artifact_path(
    value: str,
    *,
    manifest_path: Path,
    bundle_root: Path,
) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    candidates = (
        manifest_path.parent / path,
        bundle_root / path,
        _bundle_suffix_candidate(path, bundle_root),
        Path.cwd() / path,
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


def _bundle_suffix_candidate(path: Path, bundle_root: Path) -> Path:
    parts = path.parts
    bundle_name = bundle_root.name
    if bundle_name in parts:
        index = parts.index(bundle_name)
        suffix = parts[index + 1 :]
        if suffix:
            return bundle_root.joinpath(*suffix)
    return bundle_root / path


def _verification_error(*, hash_ok: bool, size_ok: bool) -> str | None:
    if hash_ok and size_ok:
        return None
    if not hash_ok and not size_ok:
        return "hash_and_size_mismatch"
    if not hash_ok:
        return "sha256_mismatch"
    return "size_mismatch"


def _optional_json_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _display_path(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def _bool(document: dict[str, Any], key: str) -> bool:
    value = document.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value


def _count_map(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        raise ValueError("count map must be an object")
    result: dict[str, int] = {}
    for key, count in value.items():
        if not isinstance(key, str):
            raise ValueError("count map keys must be strings")
        if not isinstance(count, int) or isinstance(count, bool):
            raise ValueError("count map values must be integers")
        result[key] = count
    return dict(sorted(result.items()))


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    if not isinstance(value, int | float) or isinstance(value, bool):
        raise ValueError("expected number or null")
    return float(value)


def _str_tuple(value: Any, path: str) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        raise ValueError(f"{path} must be an array")
    values: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{path} must contain strings")
        values.append(item)
    return tuple(values)


__all__ = [
    "BUNDLE_SCHEMA_VERSION",
    "BUNDLE_VERIFY_SCHEMA_VERSION",
    "PUBLIC_BUNDLE_PRIVATE_REFERENCE_POLICY",
    "PUBLIC_BUNDLE_RELEASE_SCOPE",
    "PUBLIC_BUNDLE_SCHEMA_VERSION",
    "PUBLIC_BUNDLE_VERIFY_SCHEMA_VERSION",
    "BundleArtifactRef",
    "BundleArtifactVerification",
    "BundleConsistencyCheck",
    "PublicBundleManifest",
    "PublicBundleVerification",
    "ReviewerBundleManifest",
    "ReviewerBundleVerification",
    "build_public_bundle_manifest",
    "build_reviewer_bundle_manifest",
    "verify_public_bundle_manifest",
    "verify_reviewer_bundle_manifest",
]
