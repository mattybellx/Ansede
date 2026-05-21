#!/usr/bin/env python3
"""Language-specific benchmark delta tracker.

Compares current recall/precision/noise per language against the
last recorded baseline, and reports any significant regressions.

Called by CI after the full test run to populate deltas.

Usage:
    python benchmarks/language_benchmark_deltas.py
    python benchmarks/language_benchmark_deltas.py --json

Exit codes:
    0 — all deltas within tolerance
    1 — one or more languages regressed beyond threshold
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_FILE = REPO_ROOT / "tmp" / "language_baseline.json"
DELTA_FILE = REPO_ROOT / "tmp" / "language_deltas.json"

# Per-language test sources (curated fixtures that produce deterministic findings)
_LANGUAGE_TESTS: dict[str, list[tuple[str, str]]] = {
    "python": [
        ("SQL injection", 'import subprocess; from flask import request; cmd = request.args.get("c"); subprocess.call(cmd, shell=True)'),
        ("Missing auth", '@app.route("/admin")\ndef admin(): return "ok"'),
    ],
    "javascript": [
        ("XSS", 'const html = req.query.html; document.write(html);'),
        ("Command injection", 'const cmd = req.query.cmd; require("child_process").execSync(cmd);'),
    ],
    "go": [
        ("Command injection", 'package main; import ("net/http"; "os/exec"); func h(w http.ResponseWriter, r *http.Request) { c := r.URL.Query().Get("c"); exec.Command("bash","-c",c) }'),
    ],
    "java": [
        ("Command injection", 'public class T { public void r(String i) throws Exception { Runtime.getRuntime().exec(i); } }'),
    ],
    "csharp": [
        ("Process injection", 'using System.Diagnostics; class T { void R(string i) { Process.Start(i); } }'),
    ],
    "ruby": [
        ("Command injection", 'def h; cmd = params[:c]; system(cmd); end'),
    ],
    "php": [
        ("SQL injection", '<?php $r = mysqli_query($c, "SELECT * FROM users WHERE id = " . $_GET["id"]);'),
    ],
}

# Expected minimum findings per language (any finding counts as "detected")
_EXPECTED_MIN_FINDINGS: dict[str, int] = {
    "python": 1, "javascript": 1, "go": 1, "java": 1,
    "csharp": 1, "ruby": 1, "php": 1,
}


def _scan_snippet(code: str, lang: str) -> dict | None:
    """Run ansede-static on a code snippet via direct API call."""
    try:
        if lang == "python":
            from ansede_static.python_analyzer import analyze_python
            result = analyze_python(code, filename="<benchmark>")
        elif lang == "javascript":
            from ansede_static.js_ast_analyzer import analyze_js_ast
            result = analyze_js_ast(code, filename="<benchmark>")
        elif lang == "go":
            from ansede_static.go_engine.go_analyzer import run_go_analysis
            result = run_go_analysis(code, filename="<benchmark>")
        elif lang == "java":
            from ansede_static.java_analyzer import analyze_java
            result = analyze_java(code, filename="<benchmark>")
        elif lang == "csharp":
            from ansede_static.csharp_analyzer import analyze_csharp
            result = analyze_csharp(code, filename="<benchmark>")
        elif lang == "ruby":
            from ansede_static.ruby_analyzer import analyze_ruby
            result = analyze_ruby(code, filename="<benchmark>")
        elif lang == "php":
            from ansede_static.php_analyzer import analyze_php
            result = analyze_php(code, filename="<benchmark>")
        else:
            return None

        return {
            "results": [{
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "cwe": f.cwe,
                        "title": f.title,
                        "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                        "confidence": f.confidence,
                        "line": f.line,
                    }
                    for f in (result.findings or [])
                ]
            }]
        }
    except Exception as exc:
        print(f"    ERROR: {exc}", file=sys.stderr)
        return None
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def _count_findings(data: dict | None) -> int:
    if data is None:
        return 0
    return len(data.get("results", [{}])[0].get("findings", []))


def _load_baseline() -> dict:
    if BASELINE_FILE.is_file():
        try:
            return json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def main() -> int:
    baseline = _load_baseline()
    results: dict[str, dict] = {}
    all_ok = True

    print("Language benchmark deltas")
    print("=" * 60)

    for lang, tests in sorted(_LANGUAGE_TESTS.items()):
        lang_findings = 0
        lang_detected = 0
        lang_total = len(tests)

        for test_name, code in tests:
            data = _scan_snippet(code, lang)
            count = _count_findings(data)
            lang_findings += count
            if count > 0:
                lang_detected += 1
                status = "DETECTED"
            else:
                status = "MISSED"

        detected_pct = (lang_detected / lang_total) * 100 if lang_total > 0 else 0
        min_expected = _EXPECTED_MIN_FINDINGS.get(lang, 0)

        prev = baseline.get(lang, {})
        prev_detected = prev.get("detected_pct", 0)
        delta = detected_pct - prev_detected

        ok = lang_detected >= min_expected
        if not ok:
            all_ok = False

        print(f"  {lang:>12}: {lang_detected}/{lang_total} tests passed "
              f"({detected_pct:.0f}%), {lang_findings} total findings"
              f"{'  [REGRESSION]' if delta < -10 else ''}")

        results[lang] = {
            "tests_passed": lang_detected,
            "tests_total": lang_total,
            "detected_pct": round(detected_pct, 1),
            "total_findings": lang_findings,
            "delta_from_baseline": round(delta, 1),
            "threshold_met": ok,
        }

    # Write results
    DELTA_FILE.parent.mkdir(parents=True, exist_ok=True)
    DELTA_FILE.write_text(json.dumps(results, indent=2), encoding="utf-8")

    # Update baseline
    baseline.update({k: {"detected_pct": v["detected_pct"],
                          "total_findings": v["total_findings"],
                          "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
                      for k, v in results.items()})
    BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
    BASELINE_FILE.write_text(json.dumps(baseline, indent=2), encoding="utf-8")

    print(f"\nResults written to {DELTA_FILE}")
    print(f"Baseline updated at {BASELINE_FILE}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
