"""Full benchmark integration test suite (TASK-4.x).
Runs all benchmark suites and validates they pass."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _run(label: str, cmd: list[str], *, timeout: int = 300) -> bool:
    print(f"  {label}...", end=" ", flush=True)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=str(ROOT))
        if result.returncode == 0:
            print("PASS")
            return True
        else:
            print("FAIL")
            print(f"    stdout: {result.stdout[:300]}")
            print(f"    stderr: {result.stderr[:300]}")
            return False
    except Exception as e:
        print(f"ERROR: {e}")
        return False


def main() -> int:
    print("TASK-4.x Integration Test Suite")
    print("=" * 50)

    python = [sys.executable]
    results: list[tuple[str, bool]] = []

    # Core test suite
    results.append(("Unit tests", _run("Unit tests", [*python, "-m", "pytest", "tests/", "--tb=short", "-q"], timeout=120)))

    # Benchmark suites
    results.append(("CVE recall (10-case)", _run("CVE recall", [*python, "-m", "benchmarks.cve_recall_runner", "--limit", "10", "--quiet"], timeout=120)))
    results.append(("Quality benchmark", _run("Quality", [*python, "-m", "benchmarks.quality_benchmark", "--quiet"], timeout=120)))
    results.append(("External corpus", _run("External", [*python, "-m", "benchmarks.external_corpus", "--quiet"], timeout=120)))
    results.append(("Perf benchmark", _run("Perf", [*python, "-m", "benchmarks.perf_benchmark", "--iterations", "3", "--quiet"], timeout=120)))

    # Guardrails
    results.append(("Binary guardrails", _run("Binary guardrails", [*python, "tools/check_binary_guardrails.py", "--json"], timeout=30)))
    results.append(("Semgrep transpiler", _run("Semgrep transpiler", [*python, "-m", "pytest", "tests/test_engine/test_semgrep_transpiler.py", "-q"], timeout=30)))
    results.append(("Cache tests", _run("Cache", [*python, "-m", "pytest", "tests/test_cache.py", "-q"], timeout=30)))
    results.append(("Gate regressions", _run("Gates", [*python, "-m", "pytest", "tests/test_final_scorecard.py", "tests/test_clustering.py", "tests/test_triage.py", "tests/test_benchmark_ratchet_gate.py", "-q"], timeout=60)))

    # Summary
    print()
    print("=" * 50)
    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"  {passed}/{total} suites passed ({passed/total*100:.0f}%)")
    print()
    for label, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")

    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
