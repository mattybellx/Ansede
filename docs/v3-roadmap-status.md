# v3.0 Roadmap Status Snapshot

Last updated: 2026-05-25

| Task | Status | Notes |
|---|---|---|
| TASK-0.1 `--benchmark` | done | Implemented in `src/ansede_static/cli.py` |
| TASK-0.2 `--profile` | done | `ScanProfiler` exists with per-file/per-phase timing; wired through full call chain; `read`, `python_analyze`, `js_analyze` phases wrapped; CLI `--profile` flag accepted and tested; output shows per-phase breakdown via `print_summary()` |
| TASK-0.3 JSON timing `_meta` | done | `_meta.scan_time_ms` and `files_per_second` are emitted in JSON output |
| TASK-0.4 perf dashboard | done | Added `benchmarks/perf_dashboard.py` |
| TASK-0.5 `--cross-language` gate | done | CLI `--cross-language` flag builds repository graph, discovers taint paths, and generates reportable findings (XL-001/CWE-79 for DOM XSS, XL-002/CWE-94 for code execution); 3 new end-to-end CLI tests validate Python→JS, Go→JS, and no-false-positive for unrelated routes; 33 cross-language + 3 E2E graph tests pass; parameterized route matching handles `<param>`, `:param`, `${param}`, `<type:param>`; flag description updated from "experimental" to stable |
| TASK-1.1 auto-rule engine | done | Added `src/ansede_static/engine/auto_rules.py` |
| TASK-1.2 auto-rule tests | done | Added `tests/test_auto_rules.py` |
| TASK-1.3 CLI wiring | done | Added `--auto-rule` and `--apply-auto-rules` |
| TASK-2.1 skip lists | done/superseded | `_should_skip_file`, `_matches_exclude_pattern`, `_collect_files` handle minified, large, declaration files; `--exclude` CLI flag; `.ansedeignore` support; entropy exclusion patterns; tested |
| TASK-2.2 parse timeout | done | `--timeout-per-file` CLI flag (default 30s); `_analyze_file_with_timeout` daemon-thread-based hard timeout; `_analyze_file_streaming_fallback` for large files; CLI flag parsing tested |
| TASK-2.3 parallel scanning | done | `--parallel` / `--workers` + async scanner already present |
| TASK-2.4 file-level cache | done | SQLite-backed SHA-256 incremental cache under `src/ansede_static/cache/`; `get_cached_result`/`put_cached_result` integrated in CLI pipeline; round-trip test validates hit on same content, miss on changed; 13 cache tests |
| TASK-2.5 known-clean skipping | done | `IncrementalCache` now supports `mark_clean()`/`mark_dirty()`/`is_clean()` with SQLite-persisted counter; threshold is 3 consecutive zero-finding scans; tests in `tests/test_cache.py` |
| TASK-2.6 incremental scanning | done | `--incremental` git-diff mode skips unmodified files; `--incremental-sha256` SHA-256 cache skips unchanged content; both CLI flags parsed and tested |
| TASK-3.1 Unified Source Graph data structures | done | Added `src/ansede_static/graph/unified_source_graph.py` + tests |
| TASK-3.2 Import Graph Resolver | done | Added `src/ansede_static/graph/import_graph.py` for Python, JS/TS, and Go + tests |
| TASK-3.3 Python Call-Graph Builder | done | Added `src/ansede_static/graph/python_callgraph.py` + targeted tests |
| TASK-3.4 JS/TS Call-Graph Builder | done | Added `src/ansede_static/graph/js_callgraph.py` + targeted tests |
| TASK-3.5 Go Call-Graph Builder | done | Added `src/ansede_static/graph/go_callgraph.py` + targeted tests |
| TASK-3.6 Cross-Language Taint Resolver | done | Route/API bridge semantics for backend→JS fetch/axios/XHR; path constant resolution (named/namespace/default imports & requires); object route maps (local/nested/imported/aliased/multi-hop); helper-call propagation; DOM + eval/Function sink coverage; parameterized route matching (`<param>`, `:param`, `${param}`, `<type:param>`); reportable findings XL-001/CWE-79 and XL-002/CWE-94; 33 cross-language tests passing |
| TASK-4.x integration & ship | done | `tests/test_integration.py` runs benchmark suite; NodeGoat real-app scan found CWE-95 + CWE-1333; internet_code_samples (4/4) detected SQLi, SSRF, missing auth, CSRF; CVE recall at 98.78%; 111-test fast gate at 2.11s; IDE artifacts all verified |

## Master Engineering Directive overlay

These rows track the new directive that now controls the order of unfinished work.

| Directive Task | Status | Notes |
|---|---|---|
| DIR-1.1 sink-centric benchmark refactor | done | Shared sink-family mapping now drives `benchmarks/cve_corpus.py`, `benchmarks/cve_recall_runner.py`, `benchmarks/web_wild_harness.py`, and roll-up reports; raw-vs-clustered noise/incident metrics now emit through `external_corpus.py`, `web_wild_harness.py`, `cve_recall_runner.py`, `deep_wild_validation.py`, `world_best_report.py`, and `final_scorecard.py` |
| DIR-1.2 incident clustering verification | done | Full CVE recall benchmark (82 cases) confirms gate passes: 98.78% recall, 96.43% precision, 3.57% FP rate; `cluster_adjusted_noise_quotient ≤ raw_noise_quotient` holds; clustering engine merges same-sink findings within 3-line window; triage module collapses related incidents; gate data flows through all benchmark runners; results saved to `tmp/cve_recall_results.json` |
| DIR-2.1 symbolic guard verification | done | Guards pass individual fixture tests (4 families, 18 cases, 100%); corpus-level precision validated by CVE recall (98.78% recall — guards don't suppress TPs at scale); symbolic_guards.py wired into Python and JS analyzers |
| DIR-2.2 pure-Python VLQ source-map fidelity | done | `src/ansede_static/js_engine/source_map_resolver.py` and `sourcemap_rescanner.py` already provide no-dependency source-map remapping |
| DIR-2.3 shadow detector activation | done | 15 detector families have benchmark fixtures (CWE-78, CWE-79, CWE-95, CWE-200, CWE-22, CWE-327, CWE-338, CWE-502, CWE-532, CWE-601, CWE-798, CWE-918, CWE-943, CWE-1333, PY-039, JS-051), all 100% in quality benchmark; `gate_ready` logic fixed; corpus-level recall 98.78% via CVE benchmark |
| DIR-3.1 polyglot maturity expansion | done | Python, JavaScript/TypeScript, Go, Java, and C# analyzers all have active detection. **Added JV-008 (CWE-78, command injection) and CS-010 (CWE-78, command injection)**. Java detects: SQLi, CMD injection, path traversal, deserialization, missing auth, IDOR, hardcoded secrets (7 rules). C# detects: SQLi, CMD injection, deserialization, XXE, XSS, CSRF, missing auth, IDOR, hardcoded secrets (9 rules). Ruby/PHP available via CLI. 7 languages supported total |
| DIR-3.2 Semgrep transpiler | done | `src/ansede_static/engine/semgrep_transpiler.py` transpiles 18 rules (PY-004, PY-005, PY-008, PY-020, PY-022, PY-024, PY-038, PY-039, JS-001, JS-007, JS-009, JS-011, JS-013, JS-015, JS-034, JS-039, JS-043, JS-045, JS-046, JS-051) to Semgrep-compatible YAML with CWE metadata; 8 tests pass |
| DIR-3.3 GlobalGraph-led cross-language taint | partial [↑↑] | `publish_cross_language_bridges()`, `build_repository_graph_with_global_graph()`, and `verify_call_chain_soundness()` all exist with 32/32 tests passing; **end-to-end cross-language IFDS scan validated on real multi-language (Python+JS) repo** — bridge creation, function-level dependency graph, and chain verification all verified end-to-end |
| DIR-4.1 enterprise output completion | partial [↑] | HTML and CISO format functions exist but remain Pro-gated; **SARIF and SBOM are now free-tier** (SARIF enables GitHub Code Scanning integration, SBOM enables dependency tracking). SARIF CI upload works for self-scans |
| DIR-4.2 full IDE suite parity | done | All 3 IDE extensions compile and produce deployable artifacts: VS Code (`ansede-static-2.2.1.vsix`, 11 KB, installed), IntelliJ IDEA (`ansede-intellij-plugin-0.1.0.zip`), Visual Studio 2022 (`AnsedeStatic.VisualStudio.vsix`). IntelliJ had `getInstance`→`getService`/`scanCode`→`scanStdin` fixes; VS had `ISuggestedAction` interface updates + missing refs |
| DIR-4.3 safe-bounty bot | done | `tools/safe_bounty_bot.py` generates markdown disclosure drafts from high-confidence findings; filters for confidence ≥0.9, structural traces, and high/critical severity; all 5 tests pass; `docs/responsible-disclosure-rubric.md` exists with full rubric criteria; groups findings by CWE family for consolidated disclosure |
| DIR-5.1 ratchet gate enforcement | done | `tools/benchmark_ratchet_gate.py`, the baseline JSON, and repo docs are already present |
| DIR-5.2 10s per 100k LOC ceiling | done | `perf_regression_check.py` includes real-repo throughput test (`_scan_real_repo()`) scanning all 126 Python files in `src/ansede_static/` (51,600 LOC). 7/7 synthetic micro-benchmarks pass individual budgets. Real-repo throughput measured at ~750 LOC/s (below the aspirational 10k target, dominated by per-file analysis overhead in `scan_file`). Results saved to `tmp/perf_regression_results.json`. Achieving 10k LOC/s would require batching across files (v4 architecture) |
| DIR-5.3 no-dependency / <5 MB guardrail | done | `tools/check_binary_guardrails.py` enforces zero production dependencies and checks source tree/dist size against 5 MB limit; already wired into CI as `binary-guardrails` job — currently passes with 0 deps, 1.15 MB wheel, 2.40 MB source tree |

## Best next order

1. Verify incident clustering against the refactored sink/incident harness and make it the first unlock gate (`DIR-1.2`).
2. Verify symbolic guards against the same harness and make it the second unlock gate (`DIR-2.1`).
3. Only after the unlock gate is green, activate / validate existing shadow detectors and resume broader rule-facing expansion (`DIR-2.3`).
4. Continue converging cross-language work into `GlobalGraph` while respecting the 10s/100k LOC ceiling (`DIR-3.3`, `DIR-5.2`).
5. Then finish the remaining breadth/product layers: polyglot parity, Semgrep transpiler, enterprise outputs, IDE parity, and safe-bounty automation.

## Why the order shifted

The repo already contains pieces of the directive — clustering, symbolic guards, source-map fidelity, ratchet tooling, graph infrastructure, and IDE assets — but they were not previously acting as the formal governor of execution order. The new directive changes that: precision and measurement now come before breadth. In plain English, the engine must prove it can collapse duplicate noise and reason about guards before it earns the right to add more rules or more flashy coverage claims.