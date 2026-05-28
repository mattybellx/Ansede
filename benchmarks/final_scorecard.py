"""
benchmarks.final_scorecard
──────────────────────────
Generate a single final_scorecard.json artifact combining core benchmark metrics.

Optionally accepts a web-wild harness JSON report (--web-wild-report) to embed
real-world noise quotient measurements alongside the CVE and quality results.
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


def _parse_web_wild_report(report_path: str | Path | None) -> dict[str, Any] | None:
    """Load and extract noise metrics from a web-wild harness JSON report."""
    if report_path is None:
        return None
    path = Path(report_path)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None

    summary = payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {}
    total_loc = int(summary.get("total_lines_scanned", summary.get("total_loc", 0)) or 0)
    high_critical_count = int(summary.get("total_findings_scored", summary.get("high_critical_count", 0)) or 0)
    cluster_adjusted_count = int(summary.get("total_clustered_findings_scored", high_critical_count) or 0)
    raw_noise_quotient = float(summary.get("raw_noise_quotient", 0.0) or 0.0)
    cluster_adjusted_noise_quotient = float(summary.get("cluster_adjusted_noise_quotient", raw_noise_quotient) or 0.0)

    if total_loc > 0:
        noise_quotient = raw_noise_quotient or round(high_critical_count / total_loc * 1000.0, 3)
    else:
        # Derive from sample-level data if summary is unavailable
        samples = payload.get("samples", []) if isinstance(payload.get("samples"), list) else []
        sample_loc = 0
        sample_hc = 0
        sample_clustered = 0
        for sample in samples:
            if not isinstance(sample, dict):
                continue
            sample_loc += int(sample.get("lines_scanned", sample.get("loc", 0)) or 0)
            sample_hc += int(sample.get("finding_count_scored", 0) or 0)
            sample_clustered += int(sample.get("clustered_finding_count_scored", sample.get("finding_count_scored", 0)) or 0)
        noise_quotient = round(sample_hc / sample_loc * 1000.0, 3) if sample_loc else 0.0
        cluster_adjusted_noise_quotient = round(sample_clustered / sample_loc * 1000.0, 3) if sample_loc else 0.0
        total_loc = sample_loc
        high_critical_count = sample_hc
        cluster_adjusted_count = sample_clustered

    fp_rate_pct = _safe_pct(float(summary.get("fp_rate", 0.0) or 0.0))
    recall_pct = _safe_pct(float(summary.get("recall", 0.0) or 0.0))
    clustering_summary = payload.get("clustering_summary", {}) if isinstance(payload.get("clustering_summary"), dict) else {}

    return {
        "noise_quotient_per_1k_loc": noise_quotient,
        "cluster_adjusted_noise_quotient_per_1k_loc": cluster_adjusted_noise_quotient,
        "total_loc": total_loc,
        "high_critical_findings": high_critical_count,
        "cluster_adjusted_high_critical_findings": cluster_adjusted_count,
        "fp_rate_pct": fp_rate_pct,
        "recall_pct": recall_pct,
        "n_files": int(summary.get("n_files", 0) or 0),
        "clustering_summary": clustering_summary,
        "report_path": str(report_path),
    }


def _target_status(
    *,
    fp_rate_pct: float,
    recall_pct: float,
    noise_per_1k_loc: float,
    core_cve_pass: bool,
) -> dict[str, Any]:
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
    web_wild_report: str | Path | None = None,
) -> dict[str, Any]:
    cve_report = run_cve_recall(quiet=True)
    quality_report = run_quality_benchmark(quiet=True)
    external_report = run_external_corpus(external_manifest, quiet=True)

    cve_summary = cve_report.get("summary", {}) if isinstance(cve_report, dict) else {}
    quality_summary = quality_report.get("summary", {}) if isinstance(quality_report, dict) else {}
    external_summary = external_report.get("summary", {}) if isinstance(external_report, dict) else {}

    total_cve_loc = sum(len(entry.snippet.splitlines()) for entry in CVE_CORPUS)
    cve_fp = int(cve_summary.get("fp", 0) or 0)
    cve_noise_per_1k_loc = round((cve_fp / total_cve_loc) * 1000.0, 3) if total_cve_loc else 0.0

    recall_pct = _safe_pct(cve_summary.get("recall", 0.0) or 0.0)
    fp_rate_pct = _safe_pct(cve_summary.get("fp_rate", 0.0) or 0.0)
    core_cve_pass = bool(cve_summary.get("passed_cases", 0) == cve_summary.get("total_cases", 0))

    wild_metrics = _parse_web_wild_report(web_wild_report)
    # Primary noise quotient: use web-wild real-world corpus if available,
    # otherwise fall back to the CVE-corpus-derived metric.
    noise_per_1k_loc = wild_metrics["noise_quotient_per_1k_loc"] if wild_metrics else cve_noise_per_1k_loc
    guard_summary = quality_report.get("guard_summary", {}) if isinstance(quality_report, dict) else {}
    shadow_detector_summary = quality_report.get("shadow_detector_summary", {}) if isinstance(quality_report, dict) else {}
    clustering_summary = external_report.get("clustering_summary", {}) if isinstance(external_report, dict) else {}
    cve_clustering_summary = cve_report.get("clustering_summary", {}) if isinstance(cve_report, dict) else {}
    wild_clustering_summary = wild_metrics.get("clustering_summary", {}) if wild_metrics else {}
    symbolic_guard_gate = bool(guard_summary.get("gate_ready", False))
    shadow_detector_gate = bool(shadow_detector_summary.get("gate_ready", False))
    clustering_sources = {
        "external": clustering_summary,
        "cve": cve_clustering_summary,
        **({"web_wild": wild_clustering_summary} if wild_metrics else {}),
    }
    incident_clustering_gate = bool(clustering_sources) and all(
        isinstance(source, dict) and bool(source.get("gate_ready", False))
        for source in clustering_sources.values()
    )

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
                "guard_summary": guard_summary,
                "shadow_detector_summary": shadow_detector_summary,
            },
            "external": {
                "score_pct": _safe_pct(external_summary.get("score_pct", 0.0) or 0.0),
                "checks_passed": int(external_summary.get("checks_passed", 0) or 0),
                "checks_total": int(external_summary.get("checks_total", 0) or 0),
                "clustering_summary": clustering_summary,
            },
            "noise_quotient": {
                "unit": "fp_per_1k_loc",
                "value": noise_per_1k_loc,
                "baseline": "web_wild" if wild_metrics else "CVE corpus total LOC",
                "total_loc": wild_metrics["total_loc"] if wild_metrics else total_cve_loc,
                "cve_corpus_noise_per_1k_loc": cve_noise_per_1k_loc,
            },
            **({"web_wild": wild_metrics} if wild_metrics else {}),
        },
        "verification_gates": {
            "incident_clustering": {
                "passed": incident_clustering_gate,
                "details": clustering_sources,
            },
            "symbolic_guards": {
                "passed": symbolic_guard_gate,
                "details": guard_summary,
            },
            "shadow_detectors": {
                "passed": shadow_detector_gate,
                "details": shadow_detector_summary,
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
        "--web-wild-report",
        type=Path,
        default=None,
        metavar="JSON",
        help="Path to a web-wild harness JSON report; embeds real-world noise quotient.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("final_product_scorecard.json"),
        help="Output JSON artifact path (default: final_product_scorecard.json)",
    )
    args = parser.parse_args()

    scorecard = generate_final_scorecard(
        external_manifest=args.external_manifest,
        web_wild_report=args.web_wild_report,
    )
    args.output.write_text(json.dumps(scorecard, indent=2), encoding="utf-8")
    print(f"final scorecard written to {args.output}")


if __name__ == "__main__":
    main()
