from __future__ import annotations

import benchmarks.final_scorecard as final_scorecard


def test_generate_final_scorecard_exposes_verification_gates(monkeypatch):
    monkeypatch.setattr(
        final_scorecard,
        "run_cve_recall",
        lambda quiet=True: {
            "summary": {
                "recall": 95.0,
                "precision": 90.0,
                "f1": 92.0,
                "fp_rate": 5.0,
                "tp": 19,
                "fp": 1,
                "fn": 1,
                "passed_cases": 10,
                "total_cases": 10,
            },
            "clustering_summary": {
                "gate_ready": True,
                "raw_findings": 12,
                "clustered_findings": 8,
                "reduced_findings": 4,
                "reduction_pct": 33.33,
                "raw_noise_quotient": 1.1,
                "cluster_adjusted_noise_quotient": 0.7,
                "noise_improved_or_equal": True,
            },
        },
    )
    monkeypatch.setattr(
        final_scorecard,
        "run_quality_benchmark",
        lambda quiet=True: {
            "summary": {"score_pct": 100.0, "checks_passed": 4, "checks_total": 4},
            "guard_summary": {
                "total_cases": 3,
                "passed_cases": 3,
                "score_pct": 100.0,
                "families_total": 2,
                "families_passed": 2,
                "gate_ready": True,
                "per_guard_family": {
                    "access-control": {"cases": 2, "passed_cases": 2, "gate_ready": True},
                    "auth-guard": {"cases": 1, "passed_cases": 1, "gate_ready": True},
                },
            },
            "shadow_detector_summary": {
                "total_cases": 2,
                "passed_cases": 2,
                "score_pct": 100.0,
                "gate_ready": True,
            },
        },
    )
    monkeypatch.setattr(
        final_scorecard,
        "run_external_corpus",
        lambda manifest, quiet=True: {
            "summary": {"score_pct": 100.0, "checks_passed": 5, "checks_total": 5},
            "clustering_summary": {
                "gate_ready": True,
                "raw_findings": 8,
                "clustered_findings": 5,
                "reduced_findings": 3,
                "reduction_pct": 37.5,
                "raw_noise_quotient": 1.2,
                "cluster_adjusted_noise_quotient": 0.8,
                "noise_improved_or_equal": True,
            },
        },
    )

    scorecard = final_scorecard.generate_final_scorecard()

    assert scorecard["verification_gates"]["incident_clustering"]["passed"] is True
    assert scorecard["verification_gates"]["symbolic_guards"]["passed"] is True
    assert scorecard["verification_gates"]["shadow_detectors"]["passed"] is True
    assert "cve" in scorecard["verification_gates"]["incident_clustering"]["details"]
    assert scorecard["metrics"]["quality"]["guard_summary"]["total_cases"] == 3
    assert scorecard["metrics"]["quality"]["shadow_detector_summary"]["passed_cases"] == 2
    assert scorecard["metrics"]["external"]["clustering_summary"]["reduced_findings"] == 3