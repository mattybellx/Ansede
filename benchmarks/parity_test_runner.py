#!/usr/bin/env python3
"""Language parity test runner.

Validates that the analyzer for each language produces expected findings
on curated fixture files (see ``benchmarks/fixtures/`` and
``benchmarks/language_parity_manifest.json``).

Exit codes:
  0 — all parity checks pass
  1 — one or more checks failed
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "benchmarks" / "language_parity_manifest.json"
FIXTURES = REPO_ROOT / "benchmarks" / "fixtures"

# Language → analyzer module mapping (used to invoke the right analyzer)
_LANG_ANALYZER: dict[str, str] = {
    "java": "ansede_static.java_analyzer",
    "csharp": "ansede_static.csharp_analyzer",
    "go": "ansede_static.go_engine.go_analyzer",
    "ruby": "ansede_static.ruby_analyzer",
    "php": "ansede_static.php_analyzer",
}


def _run_analyzer(file_path: Path, lang: str) -> dict | None:
    """Run ansede-static on a fixture file and return parsed JSON."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ansede_static.cli",
            str(file_path),
            "--format",
            "json",
            "--fail-on",
            "never",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        print(f"  ERROR: scan failed (exit {result.returncode}): {result.stderr[:300]}")
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"  ERROR: JSON parse failed: {result.stdout[:200]}")
        return None


def _has_finding(data: dict | None, cwe: str | None = None,
                 rule_family: str | None = None) -> bool:
    if data is None:
        return False
    results_list = data if isinstance(data, list) else data.get("results", [])
    for r in results_list:
        for f in r.get("findings", []):
            if cwe and f.get("cwe") == cwe:
                return True
            if rule_family and f.get("rule_id", "").startswith(rule_family.split("-")[0]):
                return True
    return False


def main() -> int:
    if not MANIFEST.is_file():
        print(f"SKIP: manifest not found at {MANIFEST}")
        return 0

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    entries = manifest.get("entries", [])
    if not entries:
        print("SKIP: no entries in manifest")
        return 0

    passed = 0
    failed = 0
    skipped = 0

    for entry in entries:
        case_id = entry["case_id"]
        lang = entry["language"]
        file_rel = entry["file"]
        expected = entry.get("expected", {})
        expect_no_finding = expected.get("no_finding", False)
        expected_cwe = expected.get("cwe")
        expected_family = expected.get("rule_family")

        fixture = FIXTURES / file_rel.split("/", 1)[1] if "/" in file_rel else FIXTURES / file_rel
        # Try relative path from fixtures/
        fixture_alt = FIXTURES / file_rel

        test_file = fixture if fixture.is_file() else fixture_alt
        if not test_file.is_file():
            print(f"  SKIP [{case_id}]: fixture not found at {test_file}")
            skipped += 1
            continue

        print(f"  RUN  [{case_id}]: {lang} → {test_file.name}")

        data = _run_analyzer(test_file, lang)
        if data is None:
            print(f"  FAIL [{case_id}]: analyzer did not return valid JSON")
            failed += 1
            continue

        has_cwe = _has_finding(data, cwe=expected_cwe)
        has_family = _has_finding(data, rule_family=expected_family)

        if expect_no_finding:
            if has_cwe or has_family:
                print(f"  FAIL [{case_id}]: expected NO finding but got one")
                failed += 1
            else:
                print(f"  PASS [{case_id}]: correctly clean (no finding)")
                passed += 1
        else:
            if has_cwe or has_family:
                print(f"  PASS [{case_id}]: {expected_cwe or expected_family} detected")
                passed += 1
            else:
                print(f"  FAIL [{case_id}]: expected {expected_cwe or expected_family} but not found")
                failed += 1

    print()
    print(f"Results: {passed} passed, {failed} failed, {skipped} skipped out of {len(entries)}")
    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
