from __future__ import annotations

import benchmarks.quality_benchmark as quality_benchmark
from benchmarks.quality_corpus import QualityCase
from benchmarks.perf_benchmark import run_perf_benchmark
from benchmarks.quality_benchmark import run_quality_benchmark


def test_quality_benchmark_corpus_is_green():
    report = run_quality_benchmark(quiet=True)

    assert report["summary"]["checks_total"] > 0
    assert report["summary"]["score_pct"] == 100.0
    assert report["guard_summary"]["total_cases"] > 0
    assert report["guard_summary"]["passed_cases"] == report["guard_summary"]["total_cases"]
    assert report["guard_summary"]["gate_ready"] is True
    assert "access-control" in report["guard_summary"]["per_guard_family"]
    assert "auth-guard" in report["guard_summary"]["per_guard_family"]
    assert "rate-limit" in report["guard_summary"]["per_guard_family"]
    assert report["shadow_detector_summary"]["total_cases"] > 0
    assert report["shadow_detector_summary"]["passed_cases"] == report["shadow_detector_summary"]["total_cases"]
    assert report["shadow_detector_summary"]["gate_ready"] is True


def test_quality_benchmark_guard_summary_aggregates_guard_cases(monkeypatch):
    monkeypatch.setattr(
        quality_benchmark,
        "QUALITY_CORPUS",
        (
            QualityCase(case_id="guard-pass", language="python", snippet="pass", guard_family="access-control"),
            QualityCase(case_id="guard-fail", language="python", snippet="pass", guard_family="rate-limit"),
        ),
    )

    def _fake_evaluate_case(case: QualityCase):
        passed = case.case_id == "guard-pass"
        return {
            "case_id": case.case_id,
            "language": case.language,
            "js_backend": case.js_backend,
            "guard_family": case.guard_family,
            "passed": passed,
            "checks": [{"token": case.case_id, "kind": "synthetic", "passed": passed}],
            "findings": [],
            "notes": case.notes,
        }

    monkeypatch.setattr(quality_benchmark, "_evaluate_case", _fake_evaluate_case)

    report = quality_benchmark.run_quality_benchmark(quiet=True)

    assert report["guard_summary"]["total_cases"] == 2
    assert report["guard_summary"]["passed_cases"] == 1
    assert report["guard_summary"]["gate_ready"] is False
    assert report["guard_summary"]["per_guard_family"]["access-control"]["passed_cases"] == 1
    assert report["guard_summary"]["per_guard_family"]["rate-limit"]["passed_cases"] == 0


def test_perf_benchmark_returns_positive_metrics():
    report = run_perf_benchmark(iterations=1, quiet=True)

    assert report["cases_per_iteration"] > 0
    assert report["avg_ms"] > 0
    assert report["cases_per_second"] > 0


def test_perf_benchmark_within_timing_budget():
    report = run_perf_benchmark(iterations=1, quiet=True)
    n = max(1, report["cases_per_iteration"])
    per_case_ms = report["avg_ms"] / n
    assert per_case_ms < 60_000, (
        f"Performance regression: {per_case_ms:.1f} ms per case "
        f"(budget: 60 000 ms/case). Total for {n} cases: {report['avg_ms']:.1f} ms."
    )
