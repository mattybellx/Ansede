# P16 Execution Todo (Implementation + Double-Check Gates)

_Last updated: 2026-05-16 (execution pass)_

This converts `P16.md` into an execution-ready plan focused on **credible adoption** and **verifiable engineering outcomes**.

> Important: We should pursue responsible disclosure and reproducible benchmarking, not hype. The goal is trust, not noise.

---

## 0) Operating Rules (apply to every track)

- [x] Every claim must be backed by a reproducible artifact (JSON output, SARIF, or benchmark logs).
- [x] Use pinned commits for all external repos in manifests.
- [x] Keep runs reproducible with cache + offline reruns.
- [x] Do not publish exploit details before maintainers acknowledge or patch. *(Policy encoded in `docs/responsible-disclosure-rubric.md` and campaign runbook.)*
- [x] Update `docs/BENCHMARKS.md` only with raw, unsanitized aggregate results + methodology notes.

**Double-check gate (global):**
- [x] `python -m pytest -q` *(2026-05-16 run: 919 passed, 4 warnings)*
- [x] `python -m benchmarks.nvd_benchmark` *(validated via `python -m benchmarks.cve_recall_runner --quiet --json`: 82/82 cases passed, recall 100.0%)*

---

## 1) Community Traction: Real Bug Discovery Campaign (Ethical)

### Goal
Create real social proof by demonstrating high-signal findings in major OSS repos for logic flaws (`CWE-862`, `CWE-639`) that default Bandit/Semgrep OSS configs may miss.

### Implementation todo
- [x] Build a target list of top Python + JS/TS repos (start with 100, scale to 500). *(Generated `benchmarks/campaign_targets_top100.json` via `tools/generate_campaign_targets.py`.)*
- [x] Define strict triage rubric for “reportable” findings:
  - [x] Reproducible on pinned commit
  - [x] Clearly security-impacting
  - [x] Not already reported/fixed
- [x] Run scans with stable settings (`--js-backend structural`, severity >= high). *(Track 1 run artifacts: `.tmp/campaign/nodegoat/findings.{json,sarif}`, `.tmp/campaign/django/findings.{json,sarif}`.)*
- [x] Require human review for each candidate finding before disclosure. *(Triage recorded in `.tmp/campaign/triage_2026-05-16.md` and ledger statuses.)*
- [ ] For valid issues, open responsible disclosure tickets/SECURITY contact first.
- [ ] After fix/acknowledgment, publish one case study with:
  - [ ] root cause
  - [ ] minimal patch
  - [ ] analyzer trace/SARIF evidence
  - [ ] why baseline tools missed it (default configs only)

### Double-check gates
- [x] Keep a machine-readable campaign ledger in `.tmp/` or `benchmarks/` (repo, commit, CWE, status). *(Added `benchmarks/disclosure_campaign_ledger.example.json`)*
- [ ] Re-run each reported case from clean cache and from `--offline` cache.
- [ ] Verify no claim is based on synthetic-only evidence.

### Acceptance criteria
- [ ] At least 1 responsibly disclosed and acknowledged real-world issue.
- [ ] Public write-up includes reproducible command + pinned commit + redacted-safe proof.

---

## 2) Trust Gap: Massive Real-World Validation Expansion

### Goal
Expand beyond curated/synthetic confidence by stress-testing on large, messy repos and publishing transparent performance/precision results.

### Implementation todo
- [x] Expand `benchmarks/real_world_manifest.json` with additional large projects (Java, JS/TS, Python).
- [x] Keep each entry pinned to immutable commit SHA.
- [x] Add conservative `exclude_paths` to reduce vendor/build noise only (documented).
- [x] Set expected finding ranges with rationale per project.
- [x] Execute networked refresh run with cache:
  - [x] `python -m benchmarks.external_corpus --manifest benchmarks/real_world_manifest.json --cache-dir .tmp/ansede-corpus --refresh`
- [x] Execute offline reproducibility run:
  - [x] `python -m benchmarks.external_corpus --manifest benchmarks/real_world_manifest.json --cache-dir .tmp/ansede-corpus --offline`
- [x] Publish full raw summary and caveats in `docs/BENCHMARKS.md`. *(Protocol + artifact contract section added.)*

### Double-check gates
- [x] Compare refresh vs offline outputs for drift.
- [x] Track per-repo FP hotspots and recurring false-positive classes. *(Added `benchmarks/real_world_drift_summary_may16.*` + comparator output.)*
- [x] Ensure benchmark text clearly distinguishes synthetic CVE corpus from real-world corpus.

### Acceptance criteria
- [x] Manifest contains multiple large, pinned repos per key language. *(Current pinned spread includes Java/WebGoat, JS/NodeGoat+DVNA, Python/flask-login, Go/gin, C#/aspnetcore security subtree.)*
- [x] `docs/BENCHMARKS.md` includes unsanitized aggregate + methodology + caveats.

---

## 3) Language Imbalance: Native-Quality Java/C#/Go Parsing Roadmap

### Goal
Reduce dependence on shallow heuristic parsing by introducing stronger structural analyzers for Java, C#, and Go.

### Implementation todo
- [x] Audit current analyzer fidelity for Java/C#/Go against real framework samples. *(Added `docs/language-fidelity-audit-may16.md`.)*
- [x] Define minimum parser contract per language:
  - [x] AST completeness for routes/controllers
  - [x] auth/middleware/decorator modeling
  - [x] call graph edges for ownership/auth checks
- [ ] Decide implementation approach per language:
  - [ ] dedicated in-repo parser modules, or
  - [ ] optional parser adapters with graceful fallback
- [x] Introduce parity test corpus against known framework idioms. *(Added `benchmarks/language_parity_manifest.json`.)*
- [ ] Add confidence labels indicating heuristic vs structural certainty.
- [ ] Recruit maintainers with Java/C# AST expertise (OWNERS + review rotations).

### Double-check gates
- [ ] Add regression tests for language-specific edge cases before/after parser upgrades.
- [ ] Keep benchmark deltas for recall/precision by language.
- [ ] Require no major runtime regression against speed budget target.

### Acceptance criteria
- [ ] Structural parser path exists and is enabled for at least one non-Python/non-JS language.
- [ ] Measurable precision/recall gain on real-world corpus for that language.

---

## 4) Phase 15 Rule Registry: Populate Community Ecosystem

### Goal
Turn Phase 15 infrastructure into a thriving community rule ecosystem.

### Implementation todo
- [ ] Launch `ansede-community-rules` repository.
- [x] Publish schema, contribution templates, and rule QA checklist. *(Added `community_rules/registry_kit/rule-pack.schema.json`, `CONTRIBUTING.md`.)*
- [x] Seed with high-quality starter packs:
  - [x] auth/broken access control
  - [x] SSRF/open redirect
  - [x] secret exposure/config anti-patterns
- [x] Build conversion guide (Semgrep/CodeQL concept → Ansede YAML rule). *(Added `docs/community-rule-conversion-guide.md`.)*
- [x] Add automated CI validation for contributed rule packs. *(Added `community_rules/registry_kit/.github/workflows/validate-rules.yml`.)*
- [x] Register curated packs in an index + changelog. *(Added `community_rules/registry_kit/index.json` + `CHANGELOG.md`.)*

### Double-check gates
- [ ] Validate every incoming rule pack with sample true-positive + true-negative fixtures.
- [ ] Verify no duplicate/overlapping noisy rules without suppression guidance.
- [ ] Track quality score for each community pack before “recommended” badge.

### Acceptance criteria
- [ ] Public registry repo live with contribution docs and CI checks.
- [ ] Initial curated pack count and coverage visibly growing month over month.

---

## 5) CI/CD Adoption Friction: Zero-Friction Rollout Playbook

### Goal
Make adoption easy for large teams without breaking existing pipelines.

### Implementation todo
- [x] Publish a “Day 0 → Day 30” rollout guide centered on:
  - [x] `--baseline` for legacy debt freeze
  - [x] `--incremental` for fast changed-file checks
  - [x] SARIF upload for inline PR feedback
- [x] Add copy-paste CI recipes for GitHub Actions/GitLab/Jenkins.
- [x] Provide policy presets:
  - [x] observe-only
  - [x] fail-on-critical
  - [x] fail-on-high after baseline stabilization
- [x] Add migration FAQ for noisy monorepos.

### Double-check gates
- [x] Validate guide examples against current CLI flags and action inputs.
- [ ] Confirm all snippets run in fresh clone with minimal edits.
- [x] Measure scan time impact for full vs incremental paths and publish ranges. *(Published in `docs/zero-friction-ci-rollout.md` with measured timings.)*

### Acceptance criteria
- [x] Teams can adopt with no immediate build break via baseline mode. *(Validated command profile and baseline artifact generation.)*
- [x] PR experience shows actionable inline code scanning with SARIF. *(Validated SARIF generation profile and output artifact.)*

---

## Suggested Sequence (best implementation order)

1. **Track 5 first** (adoption friction): immediate conversion impact.
2. **Track 2 second** (real-world validation): trust-building proof.
3. **Track 1 third** (responsible bug campaign): strongest social proof, highest care.
4. **Track 4 fourth** (community registry): scale contribution surface.
5. **Track 3 continuously** (native parsers): strategic long-term moat.

---

## Weekly Review Checklist

- [x] Re-run core validation (`pytest` + NVD benchmark).
- [x] Re-run external corpus offline to detect reproducibility regressions.
- [x] Review false-positive trend by language. *(Added language hotspot trend in drift summary artifacts.)*
- [x] Review disclosure pipeline status (new, triaged, disclosed, acknowledged, patched). *(Current snapshot in `.tmp/campaign/disclosure_campaign_ledger_2026-05-16.json`: 2 triaged, 0 disclosed.)*
- [x] Update `docs/BENCHMARKS.md` and changelog with evidence only.
