"""Evidence index generation for reviewer bundles."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from celatim.evidence_index import INDEX_SCHEMA_VERSION, build_evidence_index
from celatim.scenario import ScenarioConfig, TransportConfig, run_evidence

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def test_build_evidence_index_summarizes_evidence_json_and_transport_artifacts(tmp_path):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    memory_path = evidence_dir / "memory.json"
    pcap_path = evidence_dir / "pcap.json"
    ignored_path = evidence_dir / "ignored.json"
    pcap_dir = tmp_path / "pcaps"

    memory_doc = _write_evidence(
        memory_path,
        ScenarioConfig(
            scenario_id="index-memory",
            mechanism_id="http2-ping-opaque",
            payload=b"\x00\xffmemory",
            description="Index memory metadata",
            evidence_tier="real_pdu_packet_path",
            privilege="none",
            expected_runtime_s=7.5,
            requires_tools=("tcpdump",),
            requires_extras=("packet",),
            control_payload=b"control",
            control_kind="control_message",
            log_dir=str(tmp_path / "logs"),
            run_id="index-memory-run",
        ),
    )
    pcap_doc = _write_evidence(
        pcap_path,
        ScenarioConfig(
            scenario_id="index-pcap",
            mechanism_id="http2-ping-opaque",
            payload=b"\x00\xffpcap",
            control_payload=b"control",
            control_kind="control_message",
            transport=TransportConfig("pcap", str(pcap_dir)),
        ),
    )
    pcap_doc["covert"]["transport_metadata"] = {"probe": "ok"}
    pcap_path.write_text(json.dumps(pcap_doc, sort_keys=True) + "\n")
    ignored_path.write_text(json.dumps({"schema_version": "not-evidence"}) + "\n")

    result = build_evidence_index([evidence_dir])
    doc = result.to_json()

    assert doc["schema_version"] == INDEX_SCHEMA_VERSION
    assert doc["evidence_roots"] == [str(evidence_dir)]
    assert doc["evidence_count"] == 2
    assert doc["ok_count"] == 2
    assert doc["failed_count"] == 0
    assert doc["skipped_json_count"] == 1
    assert doc["run_log_artifact_count"] == 1
    assert doc["transport_artifact_count"] == 2
    assert doc["observer_validation_count"] == 4
    assert doc["observer_validation_ok_count"] == 4
    assert doc["detector_count"] == 4
    assert doc["detector_executed_count"] == 4
    assert doc["mutation_control_count"] == 8
    assert doc["mutation_control_ok_count"] == 8
    assert doc["evidence_tier_counts"] == {
        "in_memory_regression": 1,
        "real_pdu_packet_path": 1,
    }
    assert doc["privilege_counts"] == {"none": 2}
    assert doc["expected_runtime_s_total"] is None
    assert doc["required_tools"] == ["tcpdump"]
    assert doc["required_extras"] == ["packet"]
    assert [item["scenario_id"] for item in doc["items"]] == ["index-memory", "index-pcap"]

    memory_item = doc["items"][0]
    assert memory_item["run_id"] == "index-memory-run"
    assert memory_item["sha256"] == hashlib.sha256(memory_path.read_bytes()).hexdigest()
    assert memory_item["mechanism_id"] == memory_doc["mechanism_id"]
    assert memory_item["package_version"] == memory_doc["reproducibility"]["package_version"]
    assert memory_item["python_version"] == memory_doc["reproducibility"]["python_version"]
    assert memory_item["platform"] == memory_doc["reproducibility"]["platform"]
    assert memory_item["system"] == memory_doc["reproducibility"]["system"]
    assert memory_item["release"] == memory_doc["reproducibility"]["release"]
    assert memory_item["machine"] == memory_doc["reproducibility"]["machine"]
    assert memory_item["scenario_spec_path"] == memory_doc["reproducibility"]["scenario_spec_path"]
    assert memory_item["scenario_metadata"] == memory_doc["scenario_metadata"]
    assert memory_item["scenario_metadata"] == {
        "description": "Index memory metadata",
        "evidence_tier": "real_pdu_packet_path",
        "privilege": "none",
        "expected_runtime_s": 7.5,
        "requires_tools": ["tcpdump"],
        "requires_extras": ["packet"],
    }
    assert memory_item["run_log"] == memory_doc["run_log"]
    assert Path(memory_item["run_log"]["path"]).is_file()
    assert memory_item["transport_artifacts"] == []
    assert memory_item["cases"][0]["transport_artifact"] is None
    assert memory_item["cases"][0]["transport_metadata"] is None
    assert memory_item["cases"][0]["observer_validation_count"] == 1
    assert memory_item["cases"][0]["observer_validation_ok_count"] == 1
    assert memory_item["cases"][0]["observer_validators"] == ["second_parser"]
    assert memory_item["cases"][0]["detector_count"] == 1
    assert memory_item["cases"][0]["detector_executed_count"] == 1
    assert memory_item["cases"][0]["detector_implementation_kinds"] == ["same_code"]
    assert memory_item["cases"][0]["mutation_control_count"] == 2
    assert memory_item["cases"][0]["mutation_control_ok_count"] == 2

    pcap_item = doc["items"][1]
    assert pcap_item["run_id"] == pcap_doc["run_id"]
    assert pcap_item["run_log"] is None
    assert pcap_item["sha256"] == hashlib.sha256(pcap_path.read_bytes()).hexdigest()
    assert pcap_item["mechanism_id"] == pcap_doc["mechanism_id"]
    assert len(pcap_item["transport_artifacts"]) == 2
    assert pcap_item["cases"][0]["transport_kind"] == "pcap"
    assert pcap_item["cases"][0]["transport_artifact"] == pcap_doc["covert"]["transport_artifact"]
    assert pcap_item["cases"][0]["transport_metadata"] == {"probe": "ok"}
    assert pcap_item["cases"][0]["observer_validation_count"] == 1
    assert pcap_item["cases"][0]["observer_validation_ok_count"] == 1
    assert pcap_item["cases"][0]["detector_count"] == 1
    assert pcap_item["cases"][0]["detector_executed_count"] == 1
    assert pcap_item["cases"][0]["detector_implementation_kinds"] == ["same_code"]
    assert pcap_item["cases"][0]["mutation_control_count"] == 2
    assert pcap_item["cases"][0]["mutation_control_ok_count"] == 2
    for artifact in pcap_item["transport_artifacts"]:
        path = Path(artifact["path"])
        assert path.is_file()
        assert artifact["size_bytes"] == path.stat().st_size
        assert artifact["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()

    relative_doc = build_evidence_index([evidence_dir], path_root=tmp_path).to_json()
    assert relative_doc["evidence_roots"] == ["evidence"]
    assert relative_doc["items"][0]["path"] == "evidence/memory.json"
    assert relative_doc["items"][0]["run_log"]["path"] == str(
        Path(memory_doc["run_log"]["path"]).relative_to(tmp_path)
    )
    assert relative_doc["items"][1]["path"] == "evidence/pcap.json"
    assert relative_doc["items"][1]["transport_artifacts"] == [
        {
            **pcap_doc["covert"]["transport_artifact"],
            "path": str(
                Path(pcap_doc["covert"]["transport_artifact"]["path"]).relative_to(tmp_path)
            ),
        },
        {
            **pcap_doc["benign_control"]["transport_artifact"],
            "path": str(
                Path(pcap_doc["benign_control"]["transport_artifact"]["path"]).relative_to(tmp_path)
            ),
        },
    ]
    assert relative_doc["items"][1]["cases"][0]["transport_record"] == str(
        Path(pcap_doc["covert"]["transport_record"]).relative_to(tmp_path)
    )


def test_build_evidence_index_rejects_empty_inputs(tmp_path):
    with pytest.raises(ValueError, match="no evidence-run JSON files"):
        build_evidence_index([tmp_path])


def _write_evidence(path: Path, config: ScenarioConfig) -> dict[str, Any]:
    document = run_evidence(config, DATA).to_json()
    path.write_text(json.dumps(document, sort_keys=True) + "\n")
    return document
