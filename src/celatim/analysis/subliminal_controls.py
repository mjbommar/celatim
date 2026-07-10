"""Aggregate controls for Class-G subliminal crypto transcript artifacts."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from pathlib import Path
from time import time
from typing import Any

from celatim.crypto_transcript import (
    ECDSA_NONCE_TRANSCRIPT_SCHEMA_VERSION,
    RSA_PSS_SALT_TRANSCRIPT_SCHEMA_VERSION,
)

SUBLIMINAL_CONTROL_REPORT_SCHEMA_VERSION = "celatim.subliminal_control_report.v1"
DEFAULT_MIN_CONTROL_SIGNATURES = 100
DEFAULT_MIN_P_VALUE = 0.001


def build_subliminal_control_report(
    transcript_paths: Sequence[Path | str],
    *,
    min_control_signatures: int = DEFAULT_MIN_CONTROL_SIGNATURES,
    min_p_value: float = DEFAULT_MIN_P_VALUE,
    generated_at_unix_s: float | None = None,
) -> dict[str, Any]:
    if not transcript_paths:
        raise ValueError("at least one crypto transcript is required")
    if min_control_signatures < 0:
        raise ValueError("min_control_signatures must be >= 0")
    if not 0.0 <= min_p_value <= 1.0:
        raise ValueError("min_p_value must be in [0, 1]")
    cases = [
        _case_report(
            Path(path),
            min_control_signatures=min_control_signatures,
            min_p_value=min_p_value,
        )
        for path in transcript_paths
    ]
    return {
        "schema_version": SUBLIMINAL_CONTROL_REPORT_SCHEMA_VERSION,
        "generated_at_unix_s": time() if generated_at_unix_s is None else generated_at_unix_s,
        "min_control_signatures": min_control_signatures,
        "min_p_value": min_p_value,
        "case_count": len(cases),
        "passed_count": sum(1 for case in cases if case["ok"]),
        "ok": all(case["ok"] for case in cases),
        "claim_status": (
            "distributional_smoke_controls_passed"
            if all(case["ok"] for case in cases)
            else "underpowered_or_anomalous_controls"
        ),
        "limitations": (
            "Bit-balance is a smoke test over public signature bytes. It is not a "
            "proof of cryptographic indistinguishability or broad undetectability."
        ),
        "cases": cases,
    }


def _case_report(
    path: Path,
    *,
    min_control_signatures: int,
    min_p_value: float,
) -> dict[str, Any]:
    raw_bytes = path.read_bytes()
    raw = json.loads(raw_bytes)
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: transcript must be a JSON object")
    schema_version = str(raw.get("schema_version"))
    if schema_version == ECDSA_NONCE_TRANSCRIPT_SCHEMA_VERSION:
        mechanism_id = "ecdsa-nonce"
        special = {
            "embedded_symbol_like_count": _int_at(
                raw,
                ("honest_random_control", "embedded_symbol_like_count"),
            ),
        }
    elif schema_version == RSA_PSS_SALT_TRANSCRIPT_SCHEMA_VERSION:
        mechanism_id = "rsa-pss-salt"
        special = {
            "recovered_salt_count": _int_at(raw, ("honest_random_control", "recovered_salt_count")),
            "distinct_recovered_salt_sha256_count": _int_at(
                raw,
                ("honest_random_control", "distinct_recovered_salt_sha256_count"),
            ),
            "embedded_payload_match_count": _int_at(
                raw,
                ("honest_random_control", "embedded_payload_match_count"),
            ),
        }
    else:
        raise ValueError(f"{path}: unsupported crypto transcript schema")

    channel_records = _records(raw.get("signatures"), f"{path}: signatures")
    control = raw.get("honest_random_control")
    if not isinstance(control, Mapping):
        raise ValueError(f"{path}: honest_random_control must be an object")
    control_records = _records(control.get("records"), f"{path}: honest_random_control.records")
    channel_bits = _bit_summary(channel_records)
    control_bits = _bit_summary(control_records)
    comparison = _two_proportion_z(
        channel_bits["one_count"],
        channel_bits["bit_count"],
        control_bits["one_count"],
        control_bits["bit_count"],
    )
    control_count = len(control_records)
    channel_verified = sum(1 for record in channel_records if record.get("verified") is True)
    control_verified = sum(1 for record in control_records if record.get("verified") is True)
    p_value = comparison["p_value"]
    ok = (
        control_count >= min_control_signatures
        and channel_verified == len(channel_records)
        and control_verified == control_count
        and p_value is not None
        and p_value >= min_p_value
    )
    return {
        "path": str(path),
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "size_bytes": len(raw_bytes),
        "schema_version": schema_version,
        "mechanism_id": mechanism_id,
        "session_id": raw.get("session_id"),
        "ok": ok,
        "claim_status": (
            "distributional_smoke_controls_passed" if ok else "underpowered_or_anomalous_controls"
        ),
        "signature_count": len(channel_records),
        "verified_signature_count": channel_verified,
        "honest_control_signature_count": control_count,
        "honest_control_verified_signature_count": control_verified,
        "channel_signature_bit_summary": channel_bits,
        "honest_control_signature_bit_summary": control_bits,
        "signature_bit_balance_test": comparison,
        **special,
    }


def _records(value: Any, context: str) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list):
        raise ValueError(f"{context} must be an array")
    records: list[Mapping[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise ValueError(f"{context}[{index}] must be an object")
        records.append({str(key): value for key, value in item.items()})
    return tuple(records)


def _bit_summary(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    bit_count = sum(_int(record.get("signature_bit_count")) for record in records)
    one_count = sum(_int(record.get("signature_bit_one_count")) for record in records)
    return {
        "sample_count": len(records),
        "bit_count": bit_count,
        "one_count": one_count,
        "one_rate": None if bit_count == 0 else one_count / bit_count,
    }


def _two_proportion_z(x1: int, n1: int, x2: int, n2: int) -> dict[str, Any]:
    if n1 <= 0 or n2 <= 0:
        return {"z": None, "p_value": None}
    p1 = x1 / n1
    p2 = x2 / n2
    pooled = (x1 + x2) / (n1 + n2)
    variance = pooled * (1.0 - pooled) * (1.0 / n1 + 1.0 / n2)
    if variance <= 0.0:
        return {"z": 0.0, "p_value": 1.0}
    z = (p1 - p2) / math.sqrt(variance)
    return {
        "z": z,
        "p_value": math.erfc(abs(z) / math.sqrt(2.0)),
    }


def _int_at(value: Mapping[str, Any], path: Sequence[str]) -> int:
    item: Any = value
    for key in path:
        if not isinstance(item, Mapping):
            return 0
        item = item.get(key)
    return _int(item)


def _int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return value


__all__ = [
    "DEFAULT_MIN_CONTROL_SIGNATURES",
    "DEFAULT_MIN_P_VALUE",
    "SUBLIMINAL_CONTROL_REPORT_SCHEMA_VERSION",
    "build_subliminal_control_report",
]
