from __future__ import annotations

import runpy
from pathlib import Path
from typing import cast

from celatim.testbed import build_tcp_reserved_bits_frame, default_ipv4_packet_path_config_for

CAMPAIGN = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "experiments" / "detector_population_campaign.py")
)
WINDOW_SIZE = cast("int", CAMPAIGN["WINDOW_SIZE"])
_filter_classic_pcap = CAMPAIGN["_filter_classic_pcap"]
_ipv4_id_record = CAMPAIGN["_ipv4_id_record"]
_ipv4_id_score = CAMPAIGN["_ipv4_id_score"]
_iter_classic_pcap = CAMPAIGN["_iter_classic_pcap"]
_prevalence_precision = CAMPAIGN["_prevalence_precision"]
_wilson95 = CAMPAIGN["_wilson95"]
_write_classic_pcap = CAMPAIGN["_write_classic_pcap"]


def test_ipv4_id_detector_parses_flow_and_scores_randomized_ids_higher():
    frame = build_tcp_reserved_bits_frame(
        default_ipv4_packet_path_config_for("tcp-reserved-bits"),
        0,
        index=7,
    )

    record = _ipv4_id_record(frame)

    assert record is not None
    flow, identifier = record
    assert len(flow) == 13
    assert identifier & 0x3FFF == 7
    sequential = list(range(WINDOW_SIZE))
    spread = [(index * 30_011) & 0xFFFF for index in range(WINDOW_SIZE)]
    assert _ipv4_id_score(sequential) < _ipv4_id_score(spread)


def test_classic_pcap_cutoff_preserves_only_earlier_records(tmp_path):
    config = default_ipv4_packet_path_config_for("tcp-reserved-bits")
    frames = [build_tcp_reserved_bits_frame(config, 0, index=index) for index in range(3)]
    source = tmp_path / "source.pcap"
    filtered = tmp_path / "filtered.pcap"
    _write_classic_pcap(source, frames)

    kept = _filter_classic_pcap(source, filtered, 2.0)

    assert kept == 2
    records = list(_iter_classic_pcap(filtered))
    assert [timestamp for timestamp, _frame in records] == [0.0, 1.0]
    assert [frame for _timestamp, frame in records] == frames[:2]


def test_wilson_bound_prevents_zero_observed_fp_from_implying_perfect_precision():
    tpr_interval = _wilson95(1_024, 1_024)
    fpr_interval = _wilson95(0, 380_000)

    point = _prevalence_precision(1.0, 0.0, 0.0001)
    conservative = _prevalence_precision(tpr_interval[0], fpr_interval[1], 0.0001)

    assert point == 1.0
    assert 0 < conservative < point
