"""Run all CI jobs locally to catch failures before pushing."""
import subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PIP = [sys.executable, "-m", "pip"]
PY = [sys.executable]

def run(cmd, label, timeout=120):
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    sys.stdout.flush()
    t0 = time.perf_counter()
    try:
        r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        elapsed = time.perf_counter() - t0
        if r.returncode == 0:
            print(f"  ✅ PASSED ({elapsed:.1f}s)")
        else:
            print(f"  ❌ FAILED (exit {r.returncode}, {elapsed:.1f}s)")
            out = (r.stdout or "")[-500:] + (r.stderr or "")[-500:]
            print(f"  Last output: {out[-300:]}")
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        print(f"  ❌ TIMEOUT after {timeout}s")
        return False
    except Exception as e:
        print(f"  ❌ ERROR: {e}")
        return False

results = []

# 1. Test suite (full CI list)
results.append(run(PY + ["-m", "pytest"] + [
    "tests/test_async_scanner.py", "tests/test_audit_engine.py",
    "tests/test_cache.py", "tests/test_cli.py", "tests/test_clustering.py",
    "tests/test_community_rules.py", "tests/test_confidence.py",
    "tests/test_config.py", "tests/test_cross_file.py", "tests/test_cvss.py",
    "tests/test_datascience.py", "tests/test_entropy.py",
    "tests/test_explain.py", "tests/test_java_csharp_analyzers.py",
    "tests/test_js.py", "tests/test_js_ast.py",
    "tests/test_js_minified_project_index.py", "tests/test_js_structure_cache.py",
    "tests/test_noise_policies.py",
    "tests/test_phase2_registry_expansion.py", "tests/test_phase4_diagnostics.py",
    "tests/test_python.py", "tests/test_remediation.py",
    "tests/test_reporters.py", "tests/test_rules.py",
    "tests/test_symbolic_guards.py", "tests/test_triage.py",
    "tests/test_yaml_rules.py",
    "--tb=short", "-q"
], "1. Unit tests"))

# 2. Quality benchmark
results.append(run(PY + ["-m", "benchmarks.quality_benchmark", "--fail-under", "100", "--quiet"],
                   "2. Quality benchmark", timeout=120))

# 3. External corpus
results.append(run(PY + ["-m", "benchmarks.external_corpus",
                         "--manifest", "benchmarks/external_manifest.json",
                         "--fail-under", "100", "--quiet"],
                   "3. External corpus", timeout=120))

# 4. Perf smoke
results.append(run(PY + ["-m", "benchmarks.perf_benchmark", "--iterations", "3", "--quiet", "--json"],
                   "4. Perf smoke", timeout=120))
results.append(run(PY + ["benchmarks/perf_regression_check.py"],
                   "5. Perf regression check", timeout=300))

# 5. Platform smoke
results.append(run(PY + ["-m", "pytest", "tests/test_cli.py", "tests/test_reporters.py",
                         "tests/test_config.py", "-q"],
                   "6. Platform smoke", timeout=60))

# 6. Binary guardrails
results.append(run(PY + ["tools/check_binary_guardrails.py"],
                   "7. Binary guardrails", timeout=60))

print(f"\n{'='*60}")
print(f"  RESULTS: {sum(results)}/{len(results)} passed")
if all(results):
    print("  ✅ ALL JOBS PASS — READY TO PUSH")
else:
    print("  ❌ SOME JOBS FAILED — Fix before pushing")
print(f"{'='*60}")
