# 5thMay.md Remaining Work Checklist

This checklist maps 1:1 to the `5thMay.md` v3.0 prompt and reflects the repo state audited on 2026-05-07.

Status legend:

- `[done]` implemented and verified in the current codebase
- `[partial]` partially implemented or implemented with material spec drift
- `[todo]` not implemented yet
- `[in-progress]` actively being worked now

## Task A — Complete Go + Architect Java & C# Analyzers

- `[done]` A1 — Finalize Go integration in `cli.py` / `scan_code`
- `[done]` A2 — Create `src/ansede_static/java_analyzer.py` with `JV-001` through `JV-007`
- `[done]` A3 — Create `src/ansede_static/csharp_analyzer.py` with `CS-001` through `CS-007`
- `[done]` A4 — Extend public API for `java`, `csharp`, and `go`
- `[done]` A5 — Update CLI rule catalog / stdin language handling for new languages

## Task B — Strengthen IFDS/IDE Inter-procedural Taint Engine

- `[done]` B1 — Audit and improve call-string depth
  - Document the current shared bound and benchmark evidence.
  - Re-run perf after any proposed increase.
  - Keep `python_analyzer.py` and `ir/global_graph.py` in sync.
- `[done]` B2 — Fix three known taint propagation gaps
  - Gap 1: helper return-value propagation is fixed and covered with regression test + corpus entry.
  - Gap 2: chained/form-sourced ORM IDOR detection is fixed and covered with regression test + corpus entry.
  - Gap 3: dict-construction taint is covered with explicit regression test + corpus entry.
- `[done]` B3 — Add Django CBV + FastAPI dependency heuristics exactly as `PY-028` through `PY-032`
  - Implemented with rule-ID migration: prior `PY-028` through `PY-032` semantics were moved to `PY-044` through `PY-048`.
  - Added positive/negative regression tests and CVE corpus coverage for all five required heuristics.
- `[done]` B4 — Add Hapi / Restify / tRPC / GraphQL heuristics exactly as `JS-024` through `JS-028`
  - Implemented with rule-ID migration: prior `JS-024`, `JS-026`, `JS-027`, and `JS-028` semantics were moved to `JS-057` through `JS-060`.
  - Added focused JS + JS-AST regression tests and CVE corpus coverage for all five required heuristics.

## Task C — Real-World Corpus Expansion

- `[done]` C1 — Expand `benchmarks/real_world_manifest.json` with pinned WebGoat / NodeGoat full / flask-login / DVNA entries and calibrated expected ranges
  - Added repo-level pinned entries for all four repositories with verified SHAs and calibrated `expected_findings` ranges from isolated runs.
- `[done]` C2 — Add aggregate noise gate (`--noise-gate` or equivalent) to `benchmarks/external_corpus.py`
  - Implemented `--noise-gate` using excess findings above calibrated repo maxima, while also reporting raw findings density per kLOC.
- `[done]` C3 — Harden offline/cache mode fully
  - Added explicit `OfflineCacheMissError`, repo-cache tests, refresh coverage, exclude-path filtering, and multi-language manifest support.
- `[done]` C4 — Create `benchmarks/REPRODUCING.md`

## Task D — Community Rule Ecosystem

- `[done]` D1 — Create `tools/community_rule_schema.yaml`
- `[done]` D2 — Create `community_rules/index.json`
- `[done]` D3 — Create `tools/registry.py` and expose `ansede-static registry --fetch|--list|--remove`
- `[done]` D4 — Merge community rules into scan engine with installed-cache workflow
  - Runtime scan loading now merges cached `~/.ansede/community_rules/` rules with repo-local `custom_rules_file` rules.
  - Community findings honor `disable_rules`, inline suppressions, and baseline diffing via stable `rule_id` values.
- `[done]` D5 — Create `tests/test_community_rules.py`

## Task E — Developer Experience & Tooling Improvements

- `[done]` E1 — `--explain` flag support
- `[done]` E2 — Machine-readable rule catalog export
  - `--export-rules` now accepts `json|yaml`, emits `schema_version` / `generated`, and includes built-in plus installed community rules.
- `[done]` E3 — JSON summary statistics block
- `[done]` E4 — `--output-dir PATH`

## Task F — Cross-Language Remediation & Integration Scaling

- `[done]` F1 — Expand `--apply-fixes` to new Java / C# / Go analyzers
  - Added safe inline auto-fixes for Java / C# auth findings and Go handler auth wrapping, plus Go remediation suggestions and parser repairs needed for live scans.
- `[done]` F2 — Source map resolution for bundled JS
- `[done]` F3 — Upgrade existing integrations
  - VS Code now runs scans with `--explain`, shows rich hover details for findings, and covers Java / C# / Go alongside Python / JS / TS.
  - GitHub Action now exposes `output-dir` and `noise-gate` inputs and forwards them through its scan invocations.
- `[done]` F4 — IntelliJ IDEA / Visual Studio plugin scaffolding and architecture docs
  - Added shared IDE architecture documentation plus starter IntelliJ and Visual Studio plugin trees that mirror the VS Code extension contract.

## Ordered implementation sequence from this point

1. Re-run any final packaging / marketplace validation when shipping the editor integrations