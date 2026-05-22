# v3.0 Master Plan — The World's Best SAST

> **Mission:** Solve three interlocking challenges simultaneously — cross-language taint tracking, auto-rule generation from LLM memory, and 10x speed optimization. Each problem's solution accelerates the others.
>
> **Current Baseline:** v2.3.0 · 354 LLM memory entries · 95.9% auto-classification · 42,546ms/case perf
> **Target:** v3.0 · <5,000ms/case · 98%+ auto-classification · cross-language taint · self-improving rules

---

## The Architecture — Unified Source Graph (USG)

The key insight: **all three problems share a root cause** — we scan files independently. Fix that, and all three improve simultaneously.

### Current: File-at-a-time pipeline

```
file.py → parse → analyze → finding → audit → LLM triage → memory → done
file.js → parse → analyze → finding → audit → LLM triage → memory → done
```

### Target: Whole-repo graph pipeline

```
repo/ → Unified Source Graph → cross-language taint → findings
                                                          ↓
                                              auto-rule generator ← LLM Memory
                                                          ↓
                                              heuristic rules → audit → done
```

The USG connects all files in a repo into a single graph where Python routes connect to JS API calls, Go interfaces resolve to implementations, and taint flows across language boundaries.

---

## Phase 0 — Foundation: Instrument Everything (Weeks 1-2)

**Goal:** Measure before we optimize. Find the slow files, slow phases, and most common patterns.

| # | Task | Why | Effort |
|---|------|-----|--------|
| 0.1 | `--benchmark` flag: profile per-file scan time | Find the slow files | 1 day |
| 0.2 | `--profile` flag: dump JSON of time per phase (parse vs analyze vs taint) | Find the slow phases | 1 day |
| 0.3 | Add scan timing to JSON output (`scan_time_ms`, `files_per_second`) | Track perf regressions in CI | 0.5 day |
| 0.4 | Create `benchmarks/perf_dashboard.py` | Track perf across commits, alert on regression | 1 day |
| 0.5 | `--cross-language` flag (off by default, enables USG) | Feature gate for incremental rollout | 0.5 day |

**Phase 0 target:** Baseline measurement infrastructure in place.

---

## Phase 1 — Auto-Rule Generation from LLM Memory (Weeks 2-4)

**Why first:** Your moat. 354 curated LLM examples → automatic heuristics → fewer LLM calls → faster scans. No competitor has this.

### The Algorithm

```
LLM Memory grouped by (CWE, agent)
  → for each group with ≥5 entries with same verdict:
      → extract regex pattern from code_snippets (LCS-based)
      → extract file_path pattern (test files, vendor, etc.)
      → generate heuristic rule with confidence = avg memory confidence
  → for groups with <5 entries or mixed verdicts:
      → flag for human review (outputs suggested pattern)
```

| # | Task | Detail | Files |
|---|------|--------|-------|
| 1.1 | Create `engine/auto_rules.py` | Module that reads `llm_memory.json` → generates `_classify_finding`-style heuristic functions | **New** |
| 1.2 | `_extract_pattern_from_snippets(snippets)` | LCS-based common pattern extraction across N code snippets with same verdict | `auto_rules.py` |
| 1.3 | `_generate_path_heuristic(entries)` | Extract common file path patterns (e.g. all in `frontend/src/api/`) | `auto_rules.py` |
| 1.4 | `_emit_rule(entry)` | Write generated rule to `community_rules/auto_generated/{cwe}_{agent}.yaml` | `auto_rules.py` |
| 1.5 | Wire `--auto-rule` into `cli.py` | Generates rules from memory, saves to disk | `cli.py` |
| 1.6 | Wire `--apply-auto-rules` into audit pipeline | Loads auto-generated rules, applies them during `_classify_finding` | `cli.py`, `audit.py` |
| 1.7 | E2E test: generate rules from hoppscotch memory | Should produce rules for CWE-862/js-analyzer (49 entries), CWE-798/js-analyzer (38 entries) | Test |
| 1.8 | Run full test suite after applying auto-rules | Verify no regression on CVE benchmark | CI |

**Expected outcome:** 354 entries → ~20-30 rules → 40% fewer LLM calls → faster scans + smarter heuristics.

---

## Phase 2 — Speed Optimization (Weeks 2-4, parallel with Phase 1)

**Why parallel:** Speed doesn't depend on auto-rules. Both are independent and both needed for Phase 3.

### Strategy: Lazy parsing + caching + parallelism + skip lists

| # | Task | Detail | Est. Speedup | Effort |
|---|------|--------|:------------:|--------|
| 2.1 | **Lazy AST parsing** — only parse files matching rule file extensions | Skip `.d.ts`, `.min.js`, bundles, `.snap`, test fixtures | **~2x** | 0.5 day |
| 2.2 | **AST parse timeout** — skip files taking >5s to parse (with warning) | Prevents huge bundled files from hanging the scan | **~2x** | 0.5 day |
| 2.3 | **Parallel file scanning** — `ThreadPoolExecutor` for I/O-bound file reads + `ProcessPoolExecutor` for CPU-bound AST | Leverages multi-core CPUs | **~2x** | 2 days |
| 2.4 | **File-level result cache** — cache by SHA256 content hash in `~/.ansede/cache/` | Skip re-analysis of unchanged files | **~3x** on re-scans | 2 days |
| 2.5 | **Skip known-clean files** — files scanned 3+ times with 0 findings get excluded | Configurable via `--max-clean-skips` | **~1.5x** | 1 day |
| 2.6 | **Incremental scanning** — `--incremental` rescans only git-changed files | Uses `git diff --name-only` to find changed files | **~10x** on re-scans | 3 days |

### Implementation order (highest impact first):

1. **Day 1:** AST parse timeout + lazy parsing (2.1, 2.2) — quick wins
2. **Day 2-3:** Parallel scanning (2.3) — big impact
3. **Day 4-5:** File-level cache (2.4) — helps re-scans
4. **Day 6:** Skip known-clean (2.5) — easy add-on
5. **Day 7-9:** Incremental scanning (2.6) — biggest impact for CI

**Optimization target:**
- Current: **42,546ms/case** (20 cases in 850s)
- After Phase 2: **<5,000ms/case** (20 cases in <100s) — **8.5x faster**

---

## Phase 3 — Cross-Language Taint Tracking (Weeks 3-8)

**Why last:** Hardest engineering problem. Needs speed (Phase 2) to be practical. Benefits from auto-rules (Phase 1) to reduce noise.

### Architecture: Unified Source Graph

```
┌──────────────────────────────────────────────────────────┐
│                  Unified Source Graph                     │
├──────────────────────────────────────────────────────────┤
│  Nodes: FileNode │ FunctionNode │ CallNode │ DataNode    │
│  Edges: CALLS │ IMPORTS │ DATA_FLOW │ TAINT             │
│                                                          │
│  Language bridges:                                        │
│    Python: import resolver + call-graph builder          │
│    JS/TS:  import resolver + call-graph builder          │
│    Go:     import resolver + interface resolver          │
│    Ruby:   module resolver + method dispatch             │
│    PHP:    namespace resolver + function call resolver   │
└──────────────────────────────────────────────────────────┘
```

| # | Task | Detail | Deps |
|---|------|--------|------|
| 3.1 | `graph/unified_source_graph.py` | USG node/edge data structures + JSON serialization | None |
| 3.2 | `graph/import_graph.py` | Resolve `import`/`require()` across files (Python, JS, Go, Ruby, PHP) | 3.1 |
| 3.3 | Python call-graph builder | Extract function calls from AST, resolve local vs imported | 3.1, 3.2 |
| 3.4 | JS/TS call-graph builder | Same for JS — dynamic requires, destructured imports, class methods | 3.1, 3.2 |
| 3.5 | Go call-graph builder | Go — interface resolution, method dispatch | 3.1, 3.2 |
| 3.6 | Cross-language taint resolver | Trace taint across language boundaries via route matching (FastAPI↔fetch, Express↔axios, Gin↔fetch) | 3.3-3.5 |
| 3.7 | `--cross-language` CLI flag | Enables USG + cross-language taint | 3.6 |
| 3.8 | Integration test: FastAPI + React XSS | Python endpoint → JS fetch → innerHTML | 3.7 |
| 3.9 | Integration test: Express + MongoDB NoSQL | JS route → MongoDB query | 3.7 |
| 3.10 | Integration test: Go + HTMX | Go handler → template injection | 3.7 |
| 3.11 | Cross-language perf benchmark | Measure overhead, compare with single-file mode | 3.7 |

### Cross-language taint example

```python
# Python FastAPI backend
@app.get("/api/user/{id}")
def get_user(id: str):              # ← TAINT SOURCE (URL param)
    return db.query(f"SELECT * FROM users WHERE id = '{id}'")
                                              ↑ TAINT SINK (SQLi)
```

```javascript
// JS frontend
fetch(`/api/user/${userId}`)        // ← CALLS Python endpoint (route matched)
  .then(r => r.json())
  .then(data => {
    document.title = data.name       // ← TAINT SINK (XSS via document.title)
  })
```

The USG connects: `userId (JS) → fetch(/api/user/) → Python`id` → SQL → JSON → `document.title``

---

## Phase 4 — Integration & Ship (Weeks 8-10)

| # | Task | Detail |
|---|------|--------|
| 4.1 | Full benchmark suite in cross-language mode | Recall/precision vs single-file mode |
| 4.2 | Scan 10 full-stack real-world repos | FastAPI+React, Django+Vue, Express+React, Go+HTMX, Rails+Stimulus |
| 4.3 | Head-to-head vs CodeQL on same repos | Document where cross-language mode finds things CodeQL misses |
| 4.4 | Tune auto-rule generator on 10-repo corpus | Adjust confidence thresholds, dedup patterns |
| 4.5 | Final perf benchmark | Target: <5,000ms/case single-file, <15,000ms/case cross-language |
| 4.6 | Update BENCHMARKS.md, README, docs | Publish v3.0 results |

---

## Summary: How the Three Problems Solve Each Other

| Problem | Solution | How It Helps Others |
|---------|----------|---------------------|
| **Speed** (42s→<5s) | Lazy parsing, caching, parallelism, skip lists | Makes cross-language analysis practical (10x slower). Auto-rules reduce LLM calls → less LLM time |
| **Auto-rules** | Generate heuristics from 354 LLM memory entries | Reduces NEEDS_REVIEW → fewer LLM calls → faster. Cross-language findings create richer rules |
| **Cross-language** | Unified Source Graph with import resolution | Generates deeper findings → more LLM memory → better auto-rules. Only viable because Phase 2 makes it fast enough |

**The v3.0 goal:** `ansede-static .` on a 10,000-file full-stack repo should:
1. Complete in **<30 seconds** (was 850s for 20 benchmark files)
2. Find **cross-language taint chains** no single-file SAST can detect
3. Auto-classify **>98%** via heuristics + auto-rules + LLM
4. Get **smarter with every scan** via auto-rule generation from memory
   - Add dataflow tracking for `r.URL.Query()`, `r.FormValue()`, etc.
   - Target: 95%+ on gogs recall

2. **Java** — currently basic pattern matching
   - Add servlet taint sources (`@RequestParam`, `HttpServletRequest`)
   - Add sink tracking for `Runtime.exec()`, `FileInputStream`, SQL drivers

3. **C#** — same as Java, needs proper taint
   - ASP.NET Core request sources → sink tracking

4. **PHP** — currently regex-based only
   - Build a lightweight PHP AST parser
   - Track `$_GET`, `$_POST`, `$_REQUEST` through function calls

---

## Phase 3 — The Moat: Full Self-Improvement (9 → 15 months)

**Goal:** The engine improves itself without manual intervention.

### Steps

1. **`--suggest --apply`** — auto-write heuristic rules to `audit.py`
   - Generates code, runs tests, keeps only if 206 pass
   - Stores rules in a versioned `heuristics/` directory

2. **Central learning registry**
   - `~/.ansede/registry/` stores all findings globally
   - Every scan improves every future scan
   - Shared FP patterns benefit all users

3. **GitHub Action auto-remediation**
   - Findings classified as TP with confidence >0.95 → auto-create PR fixes
   - Findings classified as LIKELY_FP → auto-dismiss with reasoning

---

## Phase 4 — Unfair Advantage (15 → 24 months)

**Goal:** Become the default recommendation for SAST.

### Steps

1. **LLM-assisted triage** — local model reads NEEDS_REVIEW findings
   - Summarizes code context for human reviewers
   - Suggests fix code for TP findings

2. **Comparison dashboard** — live report showing ansede vs CodeQL/Semgrep
   - Self-hosted, run on any repo
   - "ansede caught this that X missed" — real competitive data

3. **Community rule marketplace**
   - Users submit YAML rules → auto-tested against known corpus
   - Vote, fork, merge like GitHub Actions marketplace

4. **Enterprise offering**
   - Audit trails, SLA, SSO, role-based access
   - Custom rule writing service
   - Dedicated on-prem scanning infra

---

## Current Performance

| Repo | Lang | Files | Findings | Classified | Rate |
|------|------|-------|----------|-----------|------|
| fossbilling | PHP | 1,103 | 13 | 9 | 69% |
| dvna | Node | 151 | 16 | 5 | 31%* |
| shynet | Python | 194 | 20 | 8 | 40%* |
| express | Node | 213 | 984 | 975 | 99% |
| stackedit | JS | 370 | 28 | 2 | 7%* |
| linkding | Python | 438 | 141 | 86 | 61%* |
| **TOTAL** | **mixed** | **2,469** | **1,202** | **1,085** | **90.3%** |

\* Lower rates = real vulnerabilities correctly left for human review (dvna is deliberately vulnerable)

## Tools

- **`--audit`** — classifies all findings as TP / FP / LIKELY_FP / NEEDS_REVIEW / VENDOR_NOISE
- **`--suggest`** — analyzes NEEDS_REVIEW gaps and generates heuristic code for `audit.py`
- **`--version`** — now reports correct version (2.3.0.dev0)

## Key Files

- `src/ansede_static/engine/audit.py` — audit pipeline with 40+ heuristic patterns
- `src/ansede_static/engine_version.py` — version management
- `src/ansede_static/cli.py` — CLI entry point with --audit and --suggest flags

---

*Last updated: May 22, 2026*
