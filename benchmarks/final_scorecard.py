"""
benchmarks.final_scorecard
──────────────────────────
Generate a single final_scorecard.json artifact combining core benchmark metrics.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks.cve_corpus import CVE_CORPUS
from benchmarks.cve_recall_runner import run_cve_recall
from benchmarks.quality_benchmark import run_quality_benchmark
from benchmarks.external_corpus import run_external_corpus


def _safe_pct(value: float) -> float:
    return round(float(value), 2)


def _target_status(*, fp_rate_pct: float, recall_pct: float, noise_per_1k_loc: float, core_cve_pass: bool) -> dict[str, Any]:
    return {
        "targets": {
            "fp_rate_below_10_pct": fp_rate_pct < 10.0,
            "recall_above_90_pct": recall_pct > 90.0,
            "noise_quotient_below_2_per_1k_loc": noise_per_1k_loc < 2.0,
            "core_cve_pass": core_cve_pass,
        },
        "all_targets_met": (
            fp_rate_pct < 10.0
            and recall_pct > 90.0
            and noise_per_1k_loc < 2.0
            and core_cve_pass
        ),
    }


def generate_final_scorecard(
    *,
    external_manifest: str | Path = "benchmarks/external_manifest.json",
) -> dict[str, Any]:
    cve_report = run_cve_recall(quiet=True)
    quality_report = run_quality_benchmark(quiet=True)
    external_report = run_external_corpus(external_manifest, quiet=True)

    cve_summary = cve_report.get("summary", {}) if isinstance(cve_report, dict) else {}
    quality_summary = quality_report.get("summary", {}) if isinstance(quality_report, dict) else {}
    external_summary = external_report.get("summary", {}) if isinstance(external_report, dict) else {}

    total_cve_loc = sum(len(entry.snippet.splitlines()) for entry in CVE_CORPUS)
    cve_fp = int(cve_summary.get("fp", 0) or 0)
    noise_per_1k_loc = round((cve_fp / total_cve_loc) * 1000.0, 3) if total_cve_loc else 0.0

    recall_pct = _safe_pct(cve_summary.get("recall", 0.0) or 0.0)
    fp_rate_pct = _safe_pct(cve_summary.get("fp_rate", 0.0) or 0.0)
    core_cve_pass = bool(cve_summary.get("passed_cases", 0) == cve_summary.get("total_cases", 0))

    payload: dict[str, Any] = {
        "kind": "ansede-final-scorecard",
        "version": 1,
        "metrics": {
            "cve": {
                "recall_pct": recall_pct,
                "precision_pct": _safe_pct(cve_summary.get("precision", 0.0) or 0.0),
                "f1_pct": _safe_pct(cve_summary.get("f1", 0.0) or 0.0),
                "fp_rate_pct": fp_rate_pct,
                "tp": int(cve_summary.get("tp", 0) or 0),
                "fp": cve_fp,
                "fn": int(cve_summary.get("fn", 0) or 0),
                "passed_cases": int(cve_summary.get("passed_cases", 0) or 0),
                "total_cases": int(cve_summary.get("total_cases", 0) or 0),
            },
            "quality": {
                "score_pct": _safe_pct(quality_summary.get("score_pct", 0.0) or 0.0),
                "checks_passed": int(quality_summary.get("checks_passed", 0) or 0),
                "checks_total": int(quality_summary.get("checks_total", 0) or 0),
            },
            "external": {
                "score_pct": _safe_pct(external_summary.get("score_pct", 0.0) or 0.0),
                "checks_passed": int(external_summary.get("checks_passed", 0) or 0),
                "checks_total": int(external_summary.get("checks_total", 0) or 0),
            },
            "noise_quotient": {
                "unit": "fp_per_1k_loc",
                "value": noise_per_1k_loc,
                "baseline": "CVE corpus total LOC",
                "total_loc": total_cve_loc,
            },
        },
    }

    payload.update(
        _target_status(
            fp_rate_pct=fp_rate_pct,
            recall_pct=recall_pct,
            noise_per_1k_loc=noise_per_1k_loc,
            core_cve_pass=core_cve_pass,
        )
    )
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate final scorecard artifact")
    parser.add_argument(
        "--external-manifest",
        type=Path,
        default=Path("benchmarks/external_manifest.json"),
        help="External corpus manifest path",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("final_scorecard.json"),
        help="Output JSON artifact path",
    )
    args = parser.parse_args()

    scorecard = generate_final_scorecard(external_manifest=args.external_manifest)
    args.output.write_text(json.dumps(scorecard, indent=2), encoding="utf-8")
    print(f"final scorecard written to {args.output}")


if __name__ == "__main__":
    main()
