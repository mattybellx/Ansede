from __future__ import annotations

import argparse
import glob
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class Aggregate:
    sampled: int
    labeled: int
    tp: int
    fp: int
    fn: int
    recall_pct: float
    precision_pct: float
    f1_pct: float
    fp_rate_pct: float
    elapsed_seconds: float
    raw_findings: int
    clustered_findings: int
    raw_noise_quotient: float
    cluster_adjusted_noise_quotient: float


def _safe_div(n: float, d: float) -> float:
    return n / d if d else 0.0


def _compute(tp: int, fp: int, fn: int) -> tuple[float, float, float, float]:
    recall_raw = _safe_div(tp, tp + fn)
    precision_raw = _safe_div(tp, tp + fp)
    f1_raw = _safe_div(2.0 * precision_raw * recall_raw, precision_raw + recall_raw)
    fp_rate_raw = _safe_div(fp, tp + fp)

    recall = 100.0 * recall_raw
    precision = 100.0 * precision_raw
    f1 = 100.0 * f1_raw
    fp_rate = 100.0 * fp_rate_raw
    return (recall, precision, f1, fp_rate)


def _read_reports(patterns: list[str]) -> list[dict[str, Any]]:
    files: list[str] = []
    for pattern in patterns:
        matches = sorted(glob.glob(pattern))
        files.extend(matches)
    files = sorted(set(files))
    if not files:
        raise RuntimeError(f"No report files matched: {patterns}")

    reports: list[dict[str, Any]] = []
    for file in files:
        payload = json.loads(Path(file).read_text(encoding="utf-8"))
        payload["__file"] = file
        reports.append(payload)
    return reports


def _aggregate(reports: list[dict[str, Any]]) -> Aggregate:
    sampled = labeled = tp = fp = fn = 0
    elapsed = 0.0
    raw_findings = clustered_findings = 0
    raw_noise_weighted = clustered_noise_weighted = 0.0
    raw_noise_weight = 0
    for report in reports:
        summary = report.get("summary", {})
        sampled += int(summary.get("sampled_files", 0) or 0)
        labeled += int(summary.get("labeled_files", 0) or 0)
        tp += int(summary.get("tp", 0) or 0)
        fp += int(summary.get("fp", 0) or 0)
        fn += int(summary.get("fn", 0) or 0)
        elapsed += float(report.get("elapsed_seconds", 0.0) or 0.0)
        clustering_summary = report.get("clustering_summary", {}) if isinstance(report.get("clustering_summary"), dict) else {}
        raw_findings += int(clustering_summary.get("raw_findings", summary.get("total_findings_scored", 0)) or 0)
        clustered_findings += int(clustering_summary.get("clustered_findings", summary.get("total_clustered_findings_scored", 0)) or 0)
        report_sampled = int(summary.get("sampled_files", 0) or 0)
        raw_noise = float(clustering_summary.get("raw_noise_quotient", summary.get("raw_noise_quotient", 0.0)) or 0.0)
        clustered_noise = float(clustering_summary.get("cluster_adjusted_noise_quotient", summary.get("cluster_adjusted_noise_quotient", 0.0)) or 0.0)
        raw_noise_weighted += raw_noise * max(1, report_sampled)
        clustered_noise_weighted += clustered_noise * max(1, report_sampled)
        raw_noise_weight += max(1, report_sampled)

    recall, precision, f1, fp_rate = _compute(tp, fp, fn)
    return Aggregate(
        sampled=sampled,
        labeled=labeled,
        tp=tp,
        fp=fp,
        fn=fn,
        recall_pct=round(recall, 2),
        precision_pct=round(precision, 2),
        f1_pct=round(f1, 2),
        fp_rate_pct=round(fp_rate, 2),
        elapsed_seconds=round(elapsed, 2),
        raw_findings=raw_findings,
        clustered_findings=clustered_findings,
        raw_noise_quotient=round(raw_noise_weighted / raw_noise_weight, 4) if raw_noise_weight else 0.0,
        cluster_adjusted_noise_quotient=round(clustered_noise_weighted / raw_noise_weight, 4) if raw_noise_weight else 0.0,
    )


def _load_baseline(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    required = {"recall_pct", "precision_pct", "f1_pct", "fp_rate_pct"}
    missing = [k for k in required if k not in payload.get("aggregate", {})]
    if missing:
        raise RuntimeError(f"Baseline missing aggregate keys: {missing}")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate web-wild benchmark reports against absolute gates and a no-regression ratchet baseline."
    )
    parser.add_argument(
        "--reports",
        nargs="+",
        required=True,
        help="One or more glob patterns for live_web_wild_benchmark JSON outputs",
    )
    parser.add_argument("--profile", default="unspecified", help="Profile label for output metadata")
    parser.add_argument("--baseline", type=Path, default=None, help="Optional baseline JSON for ratchet checks")
    parser.add_argument("--min-recall", type=float, default=None)
    parser.add_argument("--max-fp-rate", type=float, default=None)
    parser.add_argument("--min-precision", type=float, default=None)
    parser.add_argument("--min-f1", type=float, default=None)
    parser.add_argument(
        "--regression-tolerance",
        type=float,
        default=0.0,
        help="Allowed decrease for recall/precision/f1 and allowed increase for fp_rate relative to baseline",
    )
    parser.add_argument("--output", type=Path, default=Path("benchmark_ratchet_gate_result.json"))
    args = parser.parse_args()

    reports = _read_reports(args.reports)
    aggregate = _aggregate(reports)

    failures: list[str] = []
    checks: dict[str, bool] = {}
    checks["clustering_gate"] = aggregate.cluster_adjusted_noise_quotient <= aggregate.raw_noise_quotient and aggregate.clustered_findings <= aggregate.raw_findings
    if not checks["clustering_gate"]:
        failures.append(
            f"clustering gate failed: clustered noise {aggregate.cluster_adjusted_noise_quotient:.4f} > raw noise {aggregate.raw_noise_quotient:.4f}"
        )

    if args.min_recall is not None:
        checks["abs_min_recall"] = aggregate.recall_pct >= args.min_recall
        if not checks["abs_min_recall"]:
            failures.append(f"recall {aggregate.recall_pct:.2f}% < min {args.min_recall:.2f}%")
    if args.max_fp_rate is not None:
        checks["abs_max_fp_rate"] = aggregate.fp_rate_pct <= args.max_fp_rate
        if not checks["abs_max_fp_rate"]:
            failures.append(f"fp_rate {aggregate.fp_rate_pct:.2f}% > max {args.max_fp_rate:.2f}%")
    if args.min_precision is not None:
        checks["abs_min_precision"] = aggregate.precision_pct >= args.min_precision
        if not checks["abs_min_precision"]:
            failures.append(f"precision {aggregate.precision_pct:.2f}% < min {args.min_precision:.2f}%")
    if args.min_f1 is not None:
        checks["abs_min_f1"] = aggregate.f1_pct >= args.min_f1
        if not checks["abs_min_f1"]:
            failures.append(f"f1 {aggregate.f1_pct:.2f}% < min {args.min_f1:.2f}%")

    baseline_payload: dict[str, Any] | None = None
    baseline_aggregate: dict[str, Any] | None = None
    if args.baseline is not None:
        baseline_payload = _load_baseline(args.baseline)
        baseline_aggregate = baseline_payload["aggregate"]
        tol = max(0.0, float(args.regression_tolerance))

        ratchet_checks = {
            "ratchet_recall": aggregate.recall_pct + tol >= float(baseline_aggregate["recall_pct"]),
            "ratchet_precision": aggregate.precision_pct + tol >= float(baseline_aggregate["precision_pct"]),
            "ratchet_f1": aggregate.f1_pct + tol >= float(baseline_aggregate["f1_pct"]),
            "ratchet_fp_rate": aggregate.fp_rate_pct <= float(baseline_aggregate["fp_rate_pct"]) + tol,
        }
        checks.update(ratchet_checks)

        if not ratchet_checks["ratchet_recall"]:
            failures.append(
                f"recall regressed: {aggregate.recall_pct:.2f}% < baseline {float(baseline_aggregate['recall_pct']):.2f}%"
            )
        if not ratchet_checks["ratchet_precision"]:
            failures.append(
                f"precision regressed: {aggregate.precision_pct:.2f}% < baseline {float(baseline_aggregate['precision_pct']):.2f}%"
            )
        if not ratchet_checks["ratchet_f1"]:
            failures.append(
                f"f1 regressed: {aggregate.f1_pct:.2f}% < baseline {float(baseline_aggregate['f1_pct']):.2f}%"
            )
        if not ratchet_checks["ratchet_fp_rate"]:
            failures.append(
                f"fp_rate regressed: {aggregate.fp_rate_pct:.2f}% > baseline {float(baseline_aggregate['fp_rate_pct']):.2f}%"
            )

    result = {
        "kind": "ansede-benchmark-ratchet-gate",
        "version": 1,
        "profile": args.profile,
        "reports": [r["__file"] for r in reports],
        "aggregate": {
            "sampled": aggregate.sampled,
            "labeled": aggregate.labeled,
            "tp": aggregate.tp,
            "fp": aggregate.fp,
            "fn": aggregate.fn,
            "recall_pct": aggregate.recall_pct,
            "precision_pct": aggregate.precision_pct,
            "f1_pct": aggregate.f1_pct,
            "fp_rate_pct": aggregate.fp_rate_pct,
            "elapsed_seconds": aggregate.elapsed_seconds,
            "raw_findings": aggregate.raw_findings,
            "clustered_findings": aggregate.clustered_findings,
            "raw_noise_quotient": aggregate.raw_noise_quotient,
            "cluster_adjusted_noise_quotient": aggregate.cluster_adjusted_noise_quotient,
        },
        "baseline": str(args.baseline) if args.baseline else None,
        "baseline_aggregate": baseline_aggregate,
        "checks": checks,
        "failures": failures,
        "passed": len(failures) == 0,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(json.dumps(result, indent=2))
    if failures:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
