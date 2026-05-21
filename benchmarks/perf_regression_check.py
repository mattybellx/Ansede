#!/usr/bin/env python3
"""Performance regression checker. Uses direct Python API calls."""
from __future__ import annotations
import json, sys, time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_FILE = REPO_ROOT / "tmp" / "perf_regression_results.json"
_SPEED_BUDGET = {"python": 5.0, "javascript": 5.0, "go": 3.0, "java": 3.0, "csharp": 3.0, "ruby": 2.0, "php": 2.0}

_SNIPPETS = {
    "python": "import subprocess\nfrom flask import request\ncmd = request.args.get('c')\nsubprocess.call(cmd, shell=True)\n" * 200,
    "javascript": "const cmd = req.query.cmd;\nrequire('child_process').execSync(cmd);\n" * 20,
    "go": 'package main\nimport ("net/http";"os/exec")\nfunc h(w http.ResponseWriter,r *http.Request){\nc:=r.URL.Query().Get("c")\nexec.Command("bash","-c",c)\n}\n' * 200,
    "java": 'public class T {\npublic void r(String i) throws Exception { Runtime.getRuntime().exec(i); }\n}\n' * 200,
    "csharp": 'using System.Diagnostics;\nclass T {\nvoid R(string i) { Process.Start(i); }\n}\n' * 200,
    "ruby": 'def h\ncmd = params[:c]\nsystem(cmd)\nend\n' * 200,
    "php": '<?php\n$r = mysqli_query($c, "SELECT * FROM users WHERE id = " . $_GET["id"]);\n' * 200,
}

def _scan(code: str, lang: str) -> float:
    fn = {
        "python": lambda c: __import__("ansede_static.python_analyzer", fromlist=["x"]).analyze_python(c, filename="<bm>"),
        "javascript": lambda c: __import__("ansede_static.js_analyzer", fromlist=["x"]).analyze_js(c, filename="<bm>"),
        "go": lambda c: __import__("ansede_static.go_engine.go_analyzer", fromlist=["x"]).run_go_analysis(c, filename="<bm>"),
        "java": lambda c: __import__("ansede_static.java_analyzer", fromlist=["x"]).analyze_java(c, filename="<bm>"),
        "csharp": lambda c: __import__("ansede_static.csharp_analyzer", fromlist=["x"]).analyze_csharp(c, filename="<bm>"),
        "ruby": lambda c: __import__("ansede_static.ruby_analyzer", fromlist=["x"]).analyze_ruby(c, filename="<bm>"),
        "php": lambda c: __import__("ansede_static.php_analyzer", fromlist=["x"]).analyze_php(c, filename="<bm>"),
    }.get(lang)
    if not fn: return 0.0
    start = time.perf_counter(); fn(code); return time.perf_counter() - start

def main() -> int:
    print(f"{'Language':>12} {'Time':>8} {'Budget':>8} {'Result':>8}")
    print("-" * 40)
    results, ok = {}, True
    for lang, code in sorted(_SNIPPETS.items()):
        b = _SPEED_BUDGET.get(lang, 5.0)
        e = _scan(code, lang)
        p = e <= b
        if not p: ok = False
        print(f"  {lang:>12} {e:>7.3f}s {b:>7.1f}s {'PASS' if p else 'FAIL':>8}")
        results[lang] = {"elapsed": round(e, 3), "budget": b, "passed": p}
    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_FILE.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
