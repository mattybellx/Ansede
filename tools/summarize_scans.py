#!/usr/bin/env python3
"""Summarize zero-day scan results and identify actionable findings."""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCANS_DIR = REPO_ROOT / "tmp" / "scans"


def main() -> int:
    if not SCANS_DIR.is_dir():
        print("No scan results found. Run tools/day_zero_scanner.py first.")
        return 1

    report_files = sorted(SCANS_DIR.glob("zd_scan_*.json"))
    if not report_files:
        print("No scan reports found.")
        return 1

    latest = report_files[-1]
    report = json.loads(latest.read_text(encoding="utf-8"))

    log = report.get("high_critical_log", [])
    results = report.get("results", [])

    print(f"=== Zero-Day Scan Summary ===")
    print(f"Report: {latest.name}")
    print(f"Repos scanned: {len(results)}")
    print(f"Total high/critical findings: {len(log)}")
    print()

    # Findings by confidence label
    structural = [f for f in log if f.get("confidence_label") == "structural"]
    heuristic = [f for f in log if f.get("confidence_label") in ("heuristic", None)]
    augmented = [f for f in log if f.get("confidence_label") == "augmented"]

    if structural:
        print(f"\n### STRUCTURAL FINDINGS (highest confidence) — {len(structural)}")
        for f in structural:
            print(f"  [{f['severity'].upper()}] {f['repo_id']}")
            print(f"    {f['rule_id']} {f['cwe']}: {f['title'][:100]}")
            print(f"    {f['file']}:{f['line']} confidence={f['confidence']}")

    if augmented:
        print(f"\n### AUGMENTED FINDINGS — {len(augmented)}")
        for f in augmented:
            print(f"  [{f['severity'].upper()}] {f['repo_id']}")
            print(f"    {f['rule_id']} {f['cwe']}: {f['title'][:100]}")

    if heuristic:
        print(f"\n### HEURISTIC FINDINGS (needs human review) — {len(heuristic)}")
        for f in heuristic:
            print(f"  [{f['severity'].upper()}] {f['rule_id']} {f['cwe']}: {f['title'][:80]}")
            print(f"    repo={f['repo_id']} file={f['file']}:{f['line']} conf={f['confidence']}")

    print(f"\nFull report: {latest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
