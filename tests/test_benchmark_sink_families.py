from __future__ import annotations

from benchmarks.cve_corpus import CVEEntry, entry_sink_family, sink_families_for_cwes, sink_family_for_cwe
from benchmarks.cve_recall_runner import run_cve_recall
from benchmarks.web_wild_harness import _summarize_sink_families


def test_sink_family_helpers_group_related_cwes():
    assert sink_family_for_cwe("CWE-89") == "data-injection"
    assert sink_family_for_cwe("CWE-943") == "data-injection"
    assert sink_families_for_cwes(["CWE-89", "CWE-943", "CWE-79"]) == (
        "data-injection",
        "xss-template-injection",
    )


def test_entry_sink_family_prefers_explicit_override():
    entry = CVEEntry(
        cve_id="TEST-1",
        language="python",
        description="demo",
        cwe="CWE-89",
        snippet="print('x')",
        expected_hit="demo",
        sink_family="custom-family",
    )

    assert entry_sink_family(entry) == "custom-family"


def test_cve_recall_report_includes_sink_family_scoreboard():
    report = run_cve_recall(case_limit=2, quiet=True)

    assert "per_sink_family" in report
    assert report["per_sink_family"]
    assert "cluster_adjusted_noise_quotient" in report["summary"]
    assert "total_clustered_findings" in report["summary"]
    assert report["clustering_summary"]["gate_ready"] is True
    first_case = report["cases"][0]
    assert "expected_sink_family" in first_case
    assert "predicted_sink_families" in first_case
    assert "findings_clustered" in first_case
    assert first_case["findings_clustered"] <= first_case["findings_considered"]


def test_web_wild_sink_family_summary_aggregates_expected_and_predicted_families():
    sink_summary, per_sink_family = _summarize_sink_families(
        [
            {
                "expected_sink_families": ["data-injection"],
                "predicted_sink_families": ["data-injection", "code-execution"],
                "label_source": "weak",
                "sink_family_tp": 1,
                "sink_family_fp": 1,
                "sink_family_fn": 0,
            },
            {
                "expected_sink_families": ["access-control"],
                "predicted_sink_families": [],
                "label_source": "weak",
                "sink_family_tp": 0,
                "sink_family_fp": 0,
                "sink_family_fn": 1,
            },
        ]
    )

    assert sink_summary["tp"] == 1
    assert sink_summary["fp"] == 1
    assert sink_summary["fn"] == 1
    assert per_sink_family["data-injection"]["tp"] == 1
    assert per_sink_family["code-execution"]["fp"] == 1
    assert per_sink_family["access-control"]["fn"] == 1