"""
benchmarks.nvd_benchmark
─────────────────────────
Run ansede-static against the NVD CVE corpus and report recall metrics.

Usage:
    python benchmarks/nvd_benchmark.py           # full benchmark
    python benchmarks/nvd_benchmark.py --verbose  # show failures in detail
    python benchmarks/nvd_benchmark.py --lang python  # Python only
"""
from __future__ import annotations

import argparse
import re
import sys
import textwrap
import time
from pathlib import Path

# Ensure Unicode box-drawing characters print correctly on Windows consoles
# (cp1252 / cp850 do not include them; reconfigure stdout to UTF-8 when safe).
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Allow running from repository root without installing the package
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from benchmarks.cve_corpus import CVE_CORPUS, CVEEntry
from ansede_static.python_analyzer import analyze_python
from ansede_static.js_analyzer import analyze_js
from ansede_static._types import Finding, Severity


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _run_entry(entry: CVEEntry) -> tuple[bool, list[Finding]]:
    """Return (detected, findings) for one CVE entry."""
    if entry.language == "python":
        result = analyze_python(entry.snippet, filename=f"{entry.cve_id}.py")
    else:
        result = analyze_js(entry.snippet, filename=f"{entry.cve_id}.js")

    pattern = re.compile(entry.expected_hit, re.IGNORECASE)
    for finding in result.findings:
        combined = f"{finding.title} {finding.description} {finding.cwe}"
        if pattern.search(combined):
            return True, result.findings

    return False, result.findings


def _sev_counts(findings: list[Finding]) -> str:
    c = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        k = f.severity.value
        if k in c:
            c[k] += 1
    parts = [f"{v} {k}" for k, v in c.items() if v]
    return ", ".join(parts) if parts else "0 findings"


# ──────────────────────────────────────────────────────────────────────────────
# Main benchmark runner
# ──────────────────────────────────────────────────────────────────────────────

def run_benchmark(
    lang_filter: str | None = None,
    verbose: bool = False,
    quiet: bool = False,
) -> dict:
    entries = [e for e in CVE_CORPUS if lang_filter is None or e.language == lang_filter]
    if not entries:
        print(f"No entries for language filter: {lang_filter!r}")
        return {}

    total = len(entries)
    detected = 0
    missed: list[CVEEntry] = []
    hits: list[CVEEntry] = []

    sep = "─" * 70

    if not quiet:
        print()
        print("┌" + "─" * 68 + "┐")
        print("│{:^68}│".format("ansede-static  NVD CVE Benchmark"))
        print("│{:^68}│".format("Zero dependencies · Pure Python · No GPU"))
        print("└" + "─" * 68 + "┘")
        print()

    t0 = time.perf_counter()

    for entry in entries:
        was_detected, findings = _run_entry(entry)
        status = "✓" if was_detected else "✗"

        if was_detected:
            detected += 1
            hits.append(entry)
        else:
            missed.append(entry)

        if not quiet:
            sev_str = _sev_counts(findings)
            print(f"  {status}  {entry.cve_id:<28}  {entry.cwe:<12}  {entry.language:<12}  [{sev_str}]")

        if verbose and not was_detected:
            print(f"\n     ↳ MISS — expected pattern: {entry.expected_hit!r}")
            print(f"       {entry.description}")
            if findings:
                print(f"       Findings returned ({len(findings)}):")
                for f in findings[:3]:
                    print(f"         • [{f.severity.value.upper()}] {f.title[:70]}")
            else:
                print("       No findings returned at all.")
            print()

    elapsed = time.perf_counter() - t0
    recall = detected / total * 100 if total else 0.0

    if not quiet:
        print()
        print(sep)

    # Break down by language
    py_entries = [e for e in entries if e.language == "python"]
    js_entries = [e for e in entries if e.language == "javascript"]
    py_hits    = sum(1 for e in py_entries if e in hits)
    js_hits    = sum(1 for e in js_entries if e in hits)

    if not quiet:
        print()
        if py_entries:
            pct = py_hits / len(py_entries) * 100
            bar = "█" * py_hits + "░" * (len(py_entries) - py_hits)
            print(f"  Python  ({len(py_entries):>2} CVEs):  [{bar}]  {py_hits}/{len(py_entries)} detected  ({pct:.0f}% recall)")
        if js_entries:
            pct = js_hits / len(js_entries) * 100
            bar = "█" * js_hits + "░" * (len(js_entries) - js_hits)
            print(f"  JS/TS   ({len(js_entries):>2} CVEs):  [{bar}]  {js_hits}/{len(js_entries)} detected  ({pct:.0f}% recall)")
        print()
        print(f"  Overall: {detected}/{total} CVEs detected  ·  {recall:.1f}% recall  ·  {elapsed*1000:.1f}ms")
        print()

        if missed:
            print("  Missed:")
            for e in missed:
                print(f"    ✗  {e.cve_id:<28}  {e.cwe}  — {e.description[:55]}…")
            print()

        print(sep)
        print()

    return {
        "total": total,
        "detected": detected,
        "recall_pct": recall,
        "elapsed_ms": elapsed * 1000,
        "python": {"total": len(py_entries), "detected": py_hits},
        "javascript": {"total": len(js_entries), "detected": js_hits},
        "missed": [e.cve_id for e in missed],
    }


# ──────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="ansede-static NVD CVE recall benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python benchmarks/nvd_benchmark.py
              python benchmarks/nvd_benchmark.py --verbose
              python benchmarks/nvd_benchmark.py --lang python
              python benchmarks/nvd_benchmark.py --fail-under 80
        """),
    )
    parser.add_argument("--lang", choices=["python", "javascript"], default=None,
                        help="Only benchmark a specific language")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show details for missed CVEs")
    parser.add_argument("--fail-under", type=float, default=0.0, metavar="PCT",
                        help="Exit with code 1 if recall is below this percentage (e.g. 80)")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress progress output, only print final JSON")
    parser.add_argument("--json", action="store_true",
                        help="Print JSON summary to stdout")
    args = parser.parse_args()

    results = run_benchmark(
        lang_filter=args.lang,
        verbose=args.verbose,
        quiet=args.quiet,
    )

    if args.json or args.quiet:
        import json
        print(json.dumps(results, indent=2))

    if args.fail_under and results.get("recall_pct", 0) < args.fail_under:
        sys.exit(1)


if __name__ == "__main__":
    main()
