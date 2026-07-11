"""Generated detector rule files and manifest."""

from pathlib import Path

from celatim.catalog import load_mechanisms
from celatim.report.detector_rules import (
    BPF_FILTERS_FILENAME,
    DETECTOR_RULES_MARKDOWN_FILENAME,
    DETECTOR_RULES_SCHEMA_VERSION,
    IPTABLES_U32_RULES_FILENAME,
    NFTABLES_RULES_FILENAME,
    STATEFUL_PLAN_MARKDOWN_FILENAME,
    STATEFUL_SURICATA_FILENAME,
    STATEFUL_ZEEK_FILENAME,
    detector_rule_artifacts,
    detector_rule_manifest,
    write_detector_rule_artifacts,
)

DATA = Path(__file__).resolve().parents[1] / "data" / "mechanisms.jsonl"


def test_detector_rule_artifacts_include_all_generated_formats():
    mechanisms = load_mechanisms(DATA)
    artifacts = {artifact.filename: artifact for artifact in detector_rule_artifacts(mechanisms)}

    assert set(artifacts) == {
        DETECTOR_RULES_MARKDOWN_FILENAME,
        NFTABLES_RULES_FILENAME,
        IPTABLES_U32_RULES_FILENAME,
        BPF_FILTERS_FILENAME,
        STATEFUL_PLAN_MARKDOWN_FILENAME,
        STATEFUL_ZEEK_FILENAME,
        STATEFUL_SURICATA_FILENAME,
    }
    assert "@th,100,3 != 0" in artifacts[NFTABLES_RULES_FILENAME].content
    assert "(@nh,224,32 & 0x0f0f0f0f == 0x0a0a0a0a)" in artifacts[NFTABLES_RULES_FILENAME].content
    assert "0>>22&0x3C@12>>24&0x0E=0x1:0x0E" in artifacts[IPTABLES_U32_RULES_FILENAME].content
    assert "tcp[12] & 0x0e != 0" in artifacts[BPF_FILTERS_FILENAME].content
    assert (
        "generated_not_executed_no_false_positive_estimate"
        in artifacts[DETECTOR_RULES_MARKDOWN_FILENAME].content
    )
    assert "padding_entropy" in artifacts[STATEFUL_PLAN_MARKDOWN_FILENAME].content
    assert "False-positive posture" in artifacts[STATEFUL_PLAN_MARKDOWN_FILENAME].content
    assert "`explicit_catalog`" in artifacts[STATEFUL_PLAN_MARKDOWN_FILENAME].content
    assert "const detector_plan" in artifacts[STATEFUL_ZEEK_FILENAME].content
    assert "annotation_source: string" in artifacts[STATEFUL_ZEEK_FILENAME].content
    assert (
        "generated_not_executed_requires_trace_baseline"
        in artifacts[STATEFUL_SURICATA_FILENAME].content
    )
    assert "celatim_false_positive benign_common" in artifacts[STATEFUL_SURICATA_FILENAME].content


def test_detector_rule_manifest_records_claim_boundary_and_hashes():
    manifest = detector_rule_manifest(load_mechanisms(DATA), output_dir="rules")

    assert manifest["schema_version"] == DETECTOR_RULES_SCHEMA_VERSION
    assert manifest["claim_status"] == "generated_not_executed_no_false_positive_estimate"
    assert manifest["rule_mechanism_count"] == 68
    assert manifest["stateful_plan_mechanism_count"] == 52
    assert manifest["stateful_claim_status"] == "generated_not_executed_requires_trace_baseline"
    assert manifest["coverage"]["stateless_filter"] == 70
    assert manifest["output_dir"] == "rules"
    assert {artifact["rule_format"] for artifact in manifest["artifacts"]} == {
        "markdown",
        "nftables",
        "iptables-u32",
        "bpf",
        "stateful-plan",
        "zeek",
        "suricata",
    }
    assert all(len(str(artifact["sha256"])) == 64 for artifact in manifest["artifacts"])


def test_write_detector_rule_artifacts_writes_expected_files(tmp_path):
    paths = write_detector_rule_artifacts(load_mechanisms(DATA), tmp_path)

    assert {path.name for path in paths} == {
        DETECTOR_RULES_MARKDOWN_FILENAME,
        NFTABLES_RULES_FILENAME,
        IPTABLES_U32_RULES_FILENAME,
        BPF_FILTERS_FILENAME,
        STATEFUL_PLAN_MARKDOWN_FILENAME,
        STATEFUL_ZEEK_FILENAME,
        STATEFUL_SURICATA_FILENAME,
    }
    assert "# Detector Rule Appendix" in (tmp_path / DETECTOR_RULES_MARKDOWN_FILENAME).read_text()
    assert "# Stateful Detector Plan" in (tmp_path / STATEFUL_PLAN_MARKDOWN_FILENAME).read_text()
