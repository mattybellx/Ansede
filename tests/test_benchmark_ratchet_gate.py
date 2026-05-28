from __future__ import annotations

import json

from tools.benchmark_ratchet_gate import _aggregate


def test_ratchet_gate_aggregate_tracks_clustering_metrics(tmp_path):
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "sampled_files": 10,
                    "labeled_files": 5,
                    "tp": 4,
                    "fp": 1,
                    "fn": 1,
                    "raw_noise_quotient": 1.4,
                    "cluster_adjusted_noise_quotient": 0.9,
                },
                "elapsed_seconds": 1.5,
                "clustering_summary": {
                    "raw_findings": 7,
                    "clustered_findings": 5,
                    "raw_noise_quotient": 1.4,
                    "cluster_adjusted_noise_quotient": 0.9,
                },
            }
        ),
        encoding="utf-8",
    )

    payload = json.loads(report_path.read_text(encoding="utf-8"))
    aggregate = _aggregate([payload])

    assert aggregate.raw_findings == 7
    assert aggregate.clustered_findings == 5
    assert aggregate.cluster_adjusted_noise_quotient <= aggregate.raw_noise_quotient