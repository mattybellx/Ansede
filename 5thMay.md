# Ansede Static — v3.0 Architecture Expansion
## Complete LLM Implementation Prompt

> **How to use this file:** Paste the entire contents as your system prompt or opening
> user message when starting a new session with any capable code-generation LLM
> (GPT-4o, Claude Sonnet, Gemini 1.5 Pro, etc.). The LLM should implement each
> numbered task in order, outputting full runnable code for every file it touches.
> Do not skip tasks or produce stubs.
0. WHO YOU ARE & WHAT THIS IS
You are a Principal Application Security Engineer and Python/AST parsing expert, statistically the worlds best on paper for both these titles
. You are implementing a major architectural expansion for Ansede Static (github.com/mattybellx/Ansede), a fast, offline, zero-dependency SAST (Static Application Security Testing) engine written in Python
.
What Ansede does: Detects critical security vulnerabilities at the AST level — including IDOR (CWE-639), Missing Authentication (CWE-862), Broken Access Control (CWE-285), SQL Injection (CWE-89), Command Injection (CWE-78), XSS (CWE-79), and 20+ other categories — across Python 3.9+, JavaScript, and TypeScript
. It is deliberately designed to find what Bandit misses while remaining drastically lighter than Semgrep or CodeQL
.

--------------------------------------------------------------------------------
1. HARD CONSTRAINTS — READ THESE AND THE ENTIRE OF THIS FILE IN FULL SO YOU UNDERSTAND AND KNOW ALL RELEVENT INFORMATION BEFORE WRITING ANY CODE
Violating any of the following constraints means your implementation will be rejected
.
CONSTRAINT 1 — ABSOLUTE ZERO DEPENDENCIES
The tool installs with pip install ansede-static and requires no external runtimes, query engines, or solver libraries of any kind
.
For caching: Use only src/ansede_static/cache/sqlite_store.py because SQLite ships with Python's stdlib
.
For parsing new languages: Use Python's stdlib re module combined with structural line/block analysis; do not use third-party parsers like javalang or antlr4
.
CONSTRAINT 2 — PERFORMANCE BUDGET
< 10 seconds per 100,000 lines of code on commodity hardware
.
Per-file hard timeout: 30 seconds
.
Do not introduce any algorithm with super-linear time complexity relative to LOC
.
CONSTRAINT 3 — BANNED TECHNIQUES
Do NOT implement full symbolic execution, full-program formal verification, or dynamic analysis (DAST)
. These are explicitly listed as Non-goals
. The entire project's speed depends on staying inside bounded AST/dataflow heuristics and IFDS/IDE inter-procedural taint with bounded call-strings
.
CONSTRAINT 4 — DO NOT REGRESS EXISTING METRICS
Your changes must not break any live metrics from final_product_scorecard.json, including maintaining a Web-wild noise quotient of < 2.0 high/critical findings per 1k LOC
.
CONSTRAINT 5 — DO NOT BREAK EXISTING INTERFACES
CLI flags that must continue working without change include --baseline, --incremental, --ai-triage, --apply-fixes, and --format sarif
. Both SARIF and JSON output formats must remain compatible with --baseline diffing
.

--------------------------------------------------------------------------------
2. CONFIRMED REPOSITORY STRUCTURE
All new rules must follow this scheme: PY-NNN (Python), JS-NNN (JavaScript/TypeScript), GO-NNN (Go), JV-NNN (Java), and CS-NNN (C#)
.

--------------------------------------------------------------------------------
3. WHAT IS ALREADY BUILT — EXTEND, DO NOT REBUILD
JS/TS structural engine: Already covers React/JSX dangerouslySetInnerHTML, Fastify, Koa, Nest.js decorators, Next.js route files, and helper-call sink resolution
.
Python engine: Already covers 27 rule categories including Flask/FastAPI/Django decorator-style auth, IDOR, SQL injection, and path traversal
.
Infrastructure: IFDS/IDE inter-procedural call graph, offline heuristic triage, SBOM generation, HTML dashboard, VS Code extension, and GitHub Action are all in place
.

--------------------------------------------------------------------------------
4. IMPLEMENTATION TASKS
Complete these in order.
TASK A — Complete Go + Architect Java & C# Analyzers
Goal: Expand Ansede to cover the three most common enterprise languages.
A1 — Finalize Go Integration: Ensure .go extension routes to the Go analyzer in src/ansede_static/cli.py and scan_code
.
A2 — Java Analyzer: Create src/ansede_static/java_analyzer.py. Implement JV-001 through JV-007 (covering Spring Boot @GetMapping auth bypasses, IDOR without .where clauses, unsafe deserialization, etc.)
.
A3 — C# Analyzer: Create src/ansede_static/csharp_analyzer.py. Implement CS-001 through CS-007 (covering ASP.NET Core [HttpGet] auth bypasses, _context.X.FindAsync IDORs, and XML DTD processing risks)
.
A4 — Public API & CLI: Extend scan_code for java and csharp
. Update --list-rules to include the new JV and CS rules
.
TASK B — Strengthen IFDS/IDE Inter-procedural Taint Engine
B1 — Call-String Depth: Audit src/ansede_static/ir/global_graph.py to optimize the call-string depth bound
.
B2 — Fix Taint Gaps: Fix helper return-value propagation, chained attribute taint, and taint through dict construction
.
B3 — Expand Python Structural Models: Add Django Class-Based Views (CBVs) and FastAPI dependency injection heuristics (PY-028 to PY-032)
.
B4 — Expand JS/TS Structural Models: Add route/auth heuristics for Hapi.js, Restify, tRPC, and GraphQL (JS-024 to JS-028)
.
TASK C — Real-World Corpus Expansion
C1 — Expand real_world_manifest.json: Add pinned-commit entries for large open-source repositories to validate real-world noise
.
C2 — Noise Regression Gate: Add a noise gate check to the external corpus runner to fail CI if the noise quotient exceeds 2.0
.
C3 — Cache & Offline Mode: Harden the external corpus runner to support --offline parsing without network calls, utilizing the existing --cache-dir functionality
.
TASK D — Community Rule Ecosystem
D1/D2 — Schema & Registry: Create tools/community_rule_schema.yaml and community_rules/index.json
.
D3 — CLI Tooling: Create registry.py to allow ansede-static registry --fetch to download YAML rules locally to ~/.ansede/community_rules/
.
D4 — Scan Integration: Modify the scan engine to seamlessly load and merge community rules with built-in rules, ensuring they work with baseline diffing and inline suppressions
.
TASK E — Developer Experience & Tooling Improvements
E1 — --explain Flag: Add a flag to print rich explanations, concrete vulnerable code, and fixed code examples for any rule ID
.
E2/E3/E4 — Output Enhancements: Add --export-rules json/yaml, include summary statistics in the JSON output, and add --output-dir PATH to write multiple formats simultaneously
.
TASK F — Cross-Language Remediation & Integration Scaling (NEW)
F1 — Expand --apply-fixes: The tool currently applies safe inline auto-fixes
. Update the remediation engine to support the new Java, C#, and Go analyzers. For example, automatically suggest .Where(x => x.UserId == userId) clauses for C# IDOR vulnerabilities or @PreAuthorize annotations for Java
.
F2 — Source Map Resolution: Ansede degrades to generated-file coordinates if source maps are missing for minified JS
. Enhance js_ast_analyzer.py to automatically resolve and parse Webpack/Vite source maps to ensure taint tracking remains highly accurate in heavily transpiled frontend codebases
.
F3 — Upgrade Existing Integrations:
VS Code: Update the extension (vscode-extension/) to surface the rich text and fix examples generated by the new --explain flag directly inside IDE hover tooltips
.
GitHub Actions: Update action.yml to natively expose the new --output-dir and --noise-gate flags so enterprise users can enforce metrics in pull requests
.
F4 — IDE Ecosystem Scaffolding: Create scaffolding and architectural documentation for IntelliJ IDEA (Java) and Visual Studio (C#) plugins to mirror the existing VS Code extension capabilities
.

--------------------------------------------------------------------------------
5. REQUIRED OUTPUT FORMAT FROM THE LLM
For every task, your response must include:
File Manifest: A table listing every file created or modified
.
Full Code: Complete, runnable Python (or YAML/JSON). No stubs or placeholders
.
Performance Justification: An explanation of the time complexity and how it stays within the 10 s/100k LOC budget
.
Regression Verification: The exact testing commands to run
.
SARIF/JSON Compatibility: Confirmation that baseline fingerprint versions are not broken
.

--------------------------------------------------------------------------------
6. FINAL CHECKLIST & CONTEXT FILES
Ensure no new entries exist in pyproject.toml install_requires, all tests pass, and the web-wild noise quotient remains < 2.0
. Before writing code, review src/ansede_static/python_analyzer.py, js_ast_analyzer.py, ir/global_graph.py, and BENCHMARKS.md
.

---

## 0. WHO YOU ARE & WHAT THIS IS

You are a **Principal Application Security Engineer and Python/AST parsing expert, statistically the worlds best on paper for both these titles**.
You are implementing a major architectural expansion for **Ansede Static**
(`github.com/mattybellx/Ansede`), a fast, offline, zero-dependency SAST
(Static Application Security Testing) engine written in Python.

**What Ansede does:** Detects critical security vulnerabilities at the AST level —
including IDOR (CWE-639), Missing Authentication (CWE-862), Broken Access Control
(CWE-285), SQL Injection (CWE-89), Command Injection (CWE-78), XSS (CWE-79), and
20+ other categories — across Python 3.9+, JavaScript, and TypeScript. It is
deliberately designed to find what Bandit misses while remaining drastically lighter
than Semgrep or CodeQL.

**Why it matters:** This tool is used in production CI/CD pipelines and VS Code. Any
regression in its correctness, speed, or zero-dependency promise breaks real users.

---

## 1. HARD CONSTRAINTS — READ THESE BEFORE WRITING ANY CODE

Violating **any** of the following constraints means your implementation will be
rejected. There are no exceptions.

---

### CONSTRAINT 1 — ABSOLUTE ZERO DEPENDENCIES

The tool installs with `pip install ansede-static` and requires **no external
runtimes, query engines, or solver libraries of any kind**.

**You may NOT add any of the following (or anything similar):**
- `javalang`, `tree-sitter`, `antlr4`, `libcst`, `astroid` — third-party parsers
- `z3`, `angr`, `manticore`, `pysmtlib` — SMT / symbolic execution solvers
- `go`, `node`, `java`, `dotnet` — external language runtimes
- Any entry to `install_requires` or `dependencies` in `pyproject.toml`

**The only permitted optional dependency** is `rich` (terminal colour output),
already gated under `pip install "ansede-static[rich]"` — do not touch this.

**For caching:** Use only `src/ansede_static/cache/sqlite_store.py`.
SQLite ships with Python's stdlib and requires no additional install.

**For parsing new languages (Java, C#, Go):** Use Python's stdlib `re` module
combined with structural line/block analysis. You do not need a full grammar.
Heuristic AST-level analysis on top of regex-identified structural blocks is
exactly what the existing Python and JS analyzers do — replicate that approach.

---

### CONSTRAINT 2 — PERFORMANCE BUDGET

**< 10 seconds per 100,000 lines of code** on commodity hardware (a mid-range
laptop, single core). This is a hard ceiling, not a guideline.

Additional performance rules:
- Per-file hard timeout: **30 seconds**. Honour it — do not remove this guard.
- Do not introduce any algorithm with **super-linear time complexity** relative to LOC.
- Do not add unbounded recursion over AST nodes. Use explicit stacks with a
  depth cap or iterative traversal.
- Call-string depth for IFDS/IDE taint: set the highest value that keeps the
  perf benchmark green — start at 5, measure, reduce if needed.
- Any new analysis pass that adds > 5% wall-clock time on the perf benchmark
  must be opt-in behind a CLI flag (e.g., `--deep-java`).

---

### CONSTRAINT 3 — BANNED TECHNIQUES

**Do NOT implement any of the following under any framing:**
- Full symbolic execution
- Full-program formal verification
- Whole-program semantic / type-inference analysis
- Dynamic analysis or DAST (runtime testing)
- Control-flow graph construction that requires parsing an entire program

These are explicitly listed as **Non-goals** in Ansede's Threat Model.
The entire project's speed and zero-dependency promise depends on staying inside:
**bounded AST/dataflow heuristics + IFDS/IDE inter-procedural taint with bounded
call-strings**.

---

### CONSTRAINT 4 — DO NOT REGRESS EXISTING METRICS

After completing every task, run the full validation suite. Your changes must not
break any of these live metrics from `final_product_scorecard.json`:

| Metric | Current Value | Minimum Acceptable |
|---|---|---|
| Full pytest suite | 473 passed, 0 failed | All green |
| CVE benchmark recall | 35/35 · 100% | ≥ 85% |
| Quality checks | 41/41 · 100% | 100% |
| External real-world corpus | 19/19 · 100% | 100% |
| Web-wild noise quotient | 1.64 high/critical per 1k LOC | **< 2.0** |
| Scan speed (perf harness) | — | < 10 s / 100k LOC |

**Run these commands after every task before proceeding to the next:**
```bash
pytest tests/ -v
python -m benchmarks.nvd_benchmark
python -m benchmarks.quality_benchmark --fail-under 100
python -m benchmarks.external_corpus \
  --manifest benchmarks/external_manifest.json --fail-under 100
python -m benchmarks.external_corpus \
  --manifest benchmarks/real_world_manifest.json \
  --cache-dir .tmp/ansede-corpus --refresh
python -m benchmarks.perf_benchmark --iterations 10
ansede-static src/ --fail-on high   # self-scan regression check
```

If any of these fail, fix the regression before moving to the next task.

---

### CONSTRAINT 5 — DO NOT BREAK EXISTING INTERFACES

The following must remain **completely unchanged** in signature and behaviour:

```python
# Public API — do not alter these signatures
from ansede_static import AnsedeConfig, scan_file, scan_code

result = scan_file("app.py")
result = scan_code(source: str, language: str,
                   config: AnsedeConfig = None,
                   js_backend: str = "auto")
```

**CLI flags that must continue working without change:**
`--baseline`, `--incremental`, `--ai-triage`, `--js-backend`, `--init`,
`--apply-fixes`, `--fail-on`, `--format sarif`, `--format json`,
`--list-rules`, `--describe-rule`, `--list-js-backends`, `--stdin`

**Output format contracts that must be preserved:**
- SARIF 2.1.0: findings carry stable `rule_id`, `analysisKind`, `confidence`,
  and trace-backed code flows.
- JSON: findings include `rule_id`, `cwe`, `analysis_kind`, `confidence`.
  Top-level envelope carries `fingerprint_version`.
- Both formats must remain compatible with `--baseline` diffing.
- Inline suppression comments (`# ansede: ignore[CWE-862]`) must continue to work.

---

## 2. CONFIRMED REPOSITORY STRUCTURE

Work only within this structure. Do not invent paths.

```
src/ansede_static/
  __init__.py               # Public API: scan_file(), scan_code(), AnsedeConfig
  cli.py                    # CLI entry point & file-extension router
  python_analyzer.py        # 27 Python AST/dataflow detection rules
  js_analyzer.py            # 23+ JS/TS pattern detection rules
  js_ast_analyzer.py        # Production structural JS/TS engine (--js-backend auto)
  js_engine/                # Shared JS engine sub-modules:
                            #   structural parsing, React/JSX flow
                            #   Koa/Nest/Next-aware route/auth heuristics
                            #   helper-call / helper-return inter-file flow
                            #   cached workspace module graphs
                            #   rule orchestration
  engine/
    triage.py               # Offline heuristic triage (--ai-triage)
    explain.py              # Human-readable finding explanations
  ir/
    global_graph.py         # Inter-procedural call graph (IFDS/IDE)
  cache/
    sqlite_store.py         # Zero-dependency SQLite result cache
  reporters.py              # Text / JSON / SARIF 2.1.0 output formatters

benchmarks/
  cve_corpus.py             # 35 synthetic CVE pattern reproductions
  nvd_benchmark.py          # Pattern recall runner
  quality_benchmark.py      # 41 quality checks harness
  external_corpus.py        # Real-world corpus runner
  external_manifest.json    # Stable fixture manifest
  real_world_manifest.json  # Opt-in curated manifest (currently: pinned NodeGoat)
  perf_benchmark.py         # Speed / performance harness

tools/                      # Utility scripts (expand here for registry)
NodeGoat/                   # Pinned NodeGoat route files
tests/                      # Full pytest suite
ansede.json                 # Project-level config
final_product_scorecard.json
final_scorecard.json
```

### Rule ID Naming Convention

All new rules must follow this scheme and register in `--list-rules` output:

| Language | Prefix | Example |
|---|---|---|
| Python | `PY-NNN` | `PY-028` |
| JavaScript / TypeScript | `JS-NNN` | `JS-024` |
| Go | `GO-NNN` | `GO-001` |
| Java | `JV-NNN` | `JV-001` |
| C# | `CS-NNN` | `CS-001` |

Each new rule must also set `analysisKind` (one of: `pattern`, `route_heuristic`,
`decorator_heuristic`, `taint_flow`) and `confidence` (one of: `high`, `medium`,
`low`) on every finding it emits.

---

## 3. WHAT IS ALREADY BUILT — EXTEND, DO NOT REBUILD

The following is fully implemented and production-stable. Understand it, build on
it, and do not accidentally overwrite or regress it.

**JS/TS structural engine (`js_ast_analyzer.py` + `js_engine/`) already covers:**
- React / JSX `dangerouslySetInnerHTML` flows
- Fastify route/auth patterns
- Koa-style ambient middleware
- Nest.js decorators (`@Controller`, `@UseGuards`)
- Next.js route files (`pages/api/`, `app/api/`)
- Helper-call sink resolution (taint through named helper functions)
- Helper return-value propagation across local/imported JS/TS call chains
- Cached relative-import JS/TS module-graph flow (redirect/path/SSRF/route-access)
- Object-literal route/auth definitions

**Python engine (`python_analyzer.py`) already covers (27 rule categories):**
Flask, FastAPI, Django decorator-style auth (`@login_required`), IDOR without
ownership WHERE, SQL injection via f-string/format/%, command injection,
deserialization, path traversal, SSRF, hardcoded secrets, weak crypto/PRNG,
JWT bypass, cyclomatic complexity flagging, exception swallowing.

**Infrastructure already in place:**
- IFDS/IDE inter-procedural call graph (`ir/global_graph.py`)
- Offline heuristic triage (`engine/triage.py`, `--ai-triage` flag)
- Baseline diffing (`--baseline`)
- Git-diff scoping (`--incremental`)
- Inline suppression comments (`# ansede: ignore[CWE-NNN]`)
- SBOM generation
- HTML dashboard output
- VS Code extension (separate tree: `vscode-extension/`)
- GitHub Action (`action.yml`)
- Pre-commit hook (`.pre-commit-hooks.yaml`)

**Your job is to EXTEND these systems, not rebuild them.**

---

## 4. EXISTING CONFIG SCHEMA — PRESERVE AND EXTEND

`ansede.json` currently supports this schema. Any new config keys you add must
be backward-compatible (old configs without the new key must still work):

```json
{
  "exclude_paths": ["tests/fixtures", "build", "dist", ".venv", "__pycache__"],
  "disable_rules": ["PY-020", "CWE-862"],
  "custom_sources": ["get_untrusted_user_input", "request.headers.get"],
  "custom_sinks": {
    "my_vulnerable_db_execute": {
      "cwe": "CWE-89",
      "title": "Custom SQL Injection sink",
      "severity": "critical"
    }
  }
}
```

**Invariants that must be preserved:**
- Malformed `custom_sinks` entries MUST be skipped with a `WARNING` log line,
  never silently half-applied. This is already enforced — do not weaken it.
- `disable_rules` must accept both stable rule IDs (e.g. `PY-020`) and CWE tags
  (e.g. `CWE-862`). Community rule IDs must also be suppressible this way.

---

## 5. IMPLEMENTATION TASKS

Complete these in order. Do not skip ahead. Validate the full test suite after each.

---

### TASK A — Complete Go + Architect Java & C# Analyzers

**Goal:** Expand Ansede to cover the three most common enterprise languages it
currently lacks. This is the single highest-impact change for enterprise adoption.

---

#### A1 — Finalize Go Integration

The Go analyzer was partially wired into the public API in a recent commit.
Complete the integration.

**Files to modify:**
- `src/ansede_static/cli.py` — ensure `.go` extension routes to the Go analyzer
- `src/ansede_static/__init__.py` — ensure `scan_code(source, language="go")`
  works end-to-end

**Verification:**
```python
from ansede_static import scan_code
result = scan_code(go_source, language="go")
assert result.language == "go"
```

**New CVE corpus entries** — add at minimum these three patterns to
`benchmarks/cve_corpus.py`:

```python
# Go IDOR — net/http handler reads URL param, queries DB, no ownership scope
CVEEntry(
    cve_id="GO-SYN-001", cwe="CWE-639", language="go",
    code="""
func getOrder(w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    row := db.QueryRow("SELECT * FROM orders WHERE id = ?", id)
    // missing: AND user_id = currentUser(r)
}
""",
    expected_severity="critical"
)

# Go SQL injection — fmt.Sprintf in DB query
CVEEntry(
    cve_id="GO-SYN-002", cwe="CWE-89", language="go",
    code="""
func getUser(name string) {
    query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
    db.Query(query)
}
""",
    expected_severity="critical"
)

# Go missing auth — http.HandleFunc on admin path, no auth middleware
CVEEntry(
    cve_id="GO-SYN-003", cwe="CWE-862", language="go",
    code="""
func main() {
    http.HandleFunc("/admin/users", listUsers) // no authMiddleware wrapper
    http.ListenAndServe(":8080", nil)
}
""",
    expected_severity="high"
)
```

---

#### A2 — Java Analyzer

**Create:** `src/ansede_static/java_analyzer.py`

Model this file's architecture after `python_analyzer.py`. Use Python's stdlib `re`
module plus structural line/block analysis — no third-party Java parser.

**Approach for zero-dependency Java parsing:**
Java's structure is regular enough for heuristic analysis. The strategy is:
1. Split source into lines.
2. Identify class and method boundaries using regex on `{` / `}` depth counting.
3. Within each method, identify annotations on the preceding lines using regex.
4. Apply rule checks to each method block with its annotation context.

**Required detection rules (implement all of these):**

| Rule ID | CWE | Pattern to detect |
|---|---|---|
| `JV-001` | CWE-862 | Spring Boot `@GetMapping`, `@PostMapping`, `@RequestMapping` on a method with no `@PreAuthorize`, `@Secured`, `@RolesAllowed`, or `SecurityContext` check in the body |
| `JV-002` | CWE-639 | `@GetMapping("/{id}")` or similar path variable route where the repository call (`findById`, `findOne`, `getOne`) has no ownership `.where("user_id = ?", userId)` or `.filter` guard |
| `JV-003` | CWE-285 | `@DeleteMapping` or `@PutMapping` with a JPA `.save()`, `.delete()`, or `.deleteById()` call and no prior ownership guard |
| `JV-004` | CWE-89 | `EntityManager.createQuery()`, `JdbcTemplate.query()`, `JdbcTemplate.execute()`, or `Statement.executeQuery()` with string concatenation (`+` operator) or `String.format()` |
| `JV-005` | CWE-502 | `ObjectInputStream.readObject()` call — unsafe Java deserialization |
| `JV-006` | CWE-798 | Hardcoded credentials: `password = "..."`, `apiKey = "..."`, `secret = "..."` string literals assigned directly |
| `JV-007` | CWE-22 | `new File(userInput)`, `Paths.get(userInput)`, or `new FileInputStream(userInput)` where `userInput` traces to a request parameter |

**File header comment (required):**
```python
"""
java_analyzer.py — Ansede Static Java detection engine.

PERFORMANCE CONTRACT:
  Analysis is bounded structural heuristics over regex-identified method blocks.
  No full grammar parse tree is constructed. Method boundary detection is O(n)
  in line count. Annotation context lookup is O(k) where k = annotation lines
  above a method (bounded to 10). Total complexity: O(n) per file.
  Worst-case measured against a 10k-line Spring Boot controller: < 400ms.
  This stays well within the 10s/100kLOC budget.
"""
```

**Register in `cli.py`:** `.java` extension → `java_analyzer.analyze_java(source)`

**Add to `benchmarks/cve_corpus.py`:** One `CVEEntry` per rule above (7 entries).

---

#### A3 — C# Analyzer

**Create:** `src/ansede_static/csharp_analyzer.py`

Same architectural approach as A2 — stdlib `re` plus structural block analysis.

**Required detection rules (implement all of these):**

| Rule ID | CWE | Pattern to detect |
|---|---|---|
| `CS-001` | CWE-862 | ASP.NET Core `[HttpGet]`, `[HttpPost]`, `[HttpPut]`, `[HttpDelete]` on a controller action with no `[Authorize]` attribute and no `[AllowAnonymous]` explicit annotation (flag missing auth, not AllowAnonymous as a problem) |
| `CS-002` | CWE-639 | Action method receives an `id` route parameter, calls `_context.X.FindAsync(id)` or `_context.X.FirstOrDefaultAsync(x => x.Id == id)` with no `.Where(x => x.UserId == userId)` ownership scope |
| `CS-003` | CWE-285 | DELETE/PUT action calls `_context.SaveChangesAsync()` or `_context.SaveChanges()` with no ownership assertion before it |
| `CS-004` | CWE-89 | `SqlCommand` with `CommandText` set via string concatenation or interpolation (`$"SELECT..."`) |
| `CS-005` | CWE-502 | `BinaryFormatter.Deserialize()` or `NetDataContractSerializer.Deserialize()` — dangerous .NET deserialization |
| `CS-006` | CWE-798 | Hardcoded connection strings with `Password=`, `pwd=`, `ApiKey=` in string literals |
| `CS-007` | CWE-611 | `XmlDocument` or `XmlReader` with `DtdProcessing` not explicitly set to `Prohibit` or `Ignore` — XXE risk |

**File header comment (required):** Same performance contract pattern as A2.

**Register in `cli.py`:** `.cs` extension → `csharp_analyzer.analyze_csharp(source)`

**Add to `benchmarks/cve_corpus.py`:** One `CVEEntry` per rule above (7 entries).

---

#### A4 — Public API Extension

Extend `src/ansede_static/__init__.py` so that:
- `scan_code(source, language="java")` routes to `java_analyzer`
- `scan_code(source, language="csharp")` routes to `csharp_analyzer`
- `scan_code(source, language="go")` routes to the Go analyzer (if not already done)
- `scan_file("App.java")` auto-detects language from extension

Do NOT change existing function signatures or return types.

The `ScanResult` object returned must have identical attributes for all languages
(`.findings`, `.critical_count`, `.high_count`, `.language`, `.sorted_findings()`).

---

#### A5 — CLI Help & `--list-rules` Updates

- Update `--list-rules` output to include all new Java (`JV-*`) and C# (`CS-*`)
  rule IDs with their CWE, title, and severity.
- Update `--describe-rule JV-001` etc. to return a human-readable description
  from the new rule catalog, consistent with how existing rules are described.
- Update the `--stdin --lang` flag to accept `java`, `csharp`, and `go`.

---

### TASK B — Strengthen IFDS/IDE Inter-procedural Taint Engine

**Goal:** Improve taint tracking precision across files and call chains without
raising algorithmic complexity. The engine should catch more real-world
multi-hop vulnerabilities that the current bounded depth might miss.

---

#### B1 — Audit and Improve Call-String Depth

**Target file:** `src/ansede_static/ir/global_graph.py`

Steps:
1. Locate the current call-string depth bound constant. Document its current value
   in a comment.
2. Raise it incrementally (by 1 each time) while running
   `python -m benchmarks.perf_benchmark --iterations 10` after each increment.
3. Set it to the highest value where total scan time stays < 10 s/100k LOC with
   a 20% safety margin (i.e., measured time < 8 s/100k LOC).
4. If the current bound is already at the optimal value, document that explicitly.

---

#### B2 — Fix Three Known Taint Propagation Gaps

Ensure the following cross-file taint patterns are correctly tracked
(these are known gaps in the current IFDS implementation):

**Gap 1 — Helper return-value propagation:**
```python
# file: utils.py
def get_user_id():
    return request.args.get("user_id")  # taint source

# file: views.py
from utils import get_user_id

def get_order():
    uid = get_user_id()                             # taint must flow here
    db.execute(f"SELECT * FROM orders WHERE id={uid}")  # must flag CWE-89
```

**Gap 2 — Chained attribute taint:**
```python
user_id = request.form.get("id")
order = db.session.query(Order).filter_by(id=user_id).first()
# must detect IDOR if no .filter(Order.user_id == current_user.id)
```

**Gap 3 — Taint through dict construction:**
```python
params = {"id": request.args.get("id")}
db.execute("SELECT * FROM items WHERE id=%(id)s" % params)  # must flag CWE-89
```

For each gap, add a corresponding test in `tests/` that asserts the finding fires,
and a `CVEEntry` in `benchmarks/cve_corpus.py`.

---

#### B3 — Expand Python Structural Models

**Target file:** `src/ansede_static/python_analyzer.py`

Add the following new heuristic models:

**Django Class-Based Views (CBVs):**

| Rule ID | CWE | Pattern |
|---|---|---|
| `PY-028` | CWE-862 | `class MyView(View)` with `get()` or `post()` method and no `LoginRequiredMixin`, `PermissionRequiredMixin`, or `@method_decorator(login_required)` |
| `PY-029` | CWE-639 | `DetailView`, `UpdateView`, or `DeleteView` subclass with no `get_queryset()` override that filters by `self.request.user` |
| `PY-030` | CWE-285 | `DeleteView` or `UpdateView` where `get_queryset()` exists but does not contain a user ownership filter |

**FastAPI dependency injection patterns:**

| Rule ID | CWE | Pattern |
|---|---|---|
| `PY-031` | CWE-287 | FastAPI route with `Depends(some_func)` where `some_func` does not call `get_current_user`, `verify_token`, `oauth2_scheme`, or a known auth dependency name — flag as potential auth bypass |
| `PY-032` | CWE-862 | FastAPI `@router.delete` or `@router.put` endpoint with no `Depends()` call at all |

For each new rule, add a `CVEEntry` in `benchmarks/cve_corpus.py` and a positive +
negative test case in `tests/`.

---

#### B4 — Expand JS/TS Structural Models

**Target file:** `src/ansede_static/js_ast_analyzer.py` and/or the appropriate
module inside `src/ansede_static/js_engine/`

The following frameworks are not yet covered. Add route/auth heuristic models:

**Hapi.js:**

| Rule ID | CWE | Pattern |
|---|---|---|
| `JS-024` | CWE-862 | `server.route({ method, path, handler })` where `options.auth` is absent or set to `false` on a non-public path |

**Restify:**

| Rule ID | CWE | Pattern |
|---|---|---|
| `JS-025` | CWE-862 | `server.get("/path", handler)` or `server.post(...)` with no auth plugin attached (`server.use(restify.authorizationParser())` not present in file scope) |

**tRPC:**

| Rule ID | CWE | Pattern |
|---|---|---|
| `JS-026` | CWE-285 | `publicProcedure.mutation(...)` used for a procedure whose name contains `update`, `delete`, `create`, `remove`, `edit`, or `destroy` — should use `protectedProcedure` |

**GraphQL (Apollo Server / express-graphql):**

| Rule ID | CWE | Pattern |
|---|---|---|
| `JS-027` | CWE-862 | GraphQL resolver function with no `context.user` check or `isAuthenticated` guard before accessing data |
| `JS-028` | CWE-639 | GraphQL resolver that queries by `id` arg (e.g. `findById(args.id)`) with no ownership comparison |

For each new framework heuristic, add fixture entries to `benchmarks/cve_corpus.py`
and tests in `tests/`.

---

### TASK C — Real-World Corpus Expansion

**Goal:** Prove Ansede works on real, messy enterprise code beyond the current
pinned NodeGoat fixtures. Expand the corpus without blowing up the noise quotient.

---

#### C1 — Expand `benchmarks/real_world_manifest.json`

Add the following repositories as **pinned-commit entries**. Choose a specific commit
SHA for each so the manifest is deterministic and reproducible.

```json
[
  {
    "name": "OWASP WebGoat",
    "repo": "https://github.com/WebGoat/WebGoat",
    "commit": "<pin a recent stable SHA>",
    "languages": ["java"],
    "expected_findings": { "min": 5, "max": 40 },
    "exclude_paths": ["src/test/", "*.md", "*.xml"],
    "notes": "Classic CVE-affected Spring Boot app — primary Java real-world target"
  },
  {
    "name": "OWASP NodeGoat (full)",
    "repo": "https://github.com/OWASP/NodeGoat",
    "commit": "<pin SHA>",
    "languages": ["javascript"],
    "expected_findings": { "min": 10, "max": 35 },
    "exclude_paths": ["test/", "*.md"],
    "notes": "Extended coverage beyond current route-file subset"
  },
  {
    "name": "flask-login example app",
    "repo": "https://github.com/maxcountryman/flask-login",
    "commit": "<pin SHA>",
    "languages": ["python"],
    "expected_findings": { "min": 0, "max": 5 },
    "exclude_paths": ["tests/", "docs/"],
    "notes": "Low-finding target — validates noise floor for Python auth patterns"
  },
  {
    "name": "Damn Vulnerable Node Application (DVNA)",
    "repo": "https://github.com/appsecco/dvna",
    "commit": "<pin SHA>",
    "languages": ["javascript"],
    "expected_findings": { "min": 8, "max": 30 },
    "exclude_paths": ["node_modules/", "test/"],
    "notes": "Intentionally vulnerable Node.js app — broad JS/TS pattern coverage"
  }
]
```

**For each entry you add:**
1. Run the corpus runner against it in isolation first.
2. Check the actual noise quotient: `actual_findings / (LOC / 1000)`.
3. If it breaches 2.0, add targeted suppressions to `engine/triage.py` for the
   false-positive patterns before committing the manifest entry.
4. Set `expected_findings.min` and `expected_findings.max` based on actual observed
   values ± 30% tolerance.

---

#### C2 — Noise Regression Gate (Automated)

Add a noise gate check to the external corpus runner (`benchmarks/external_corpus.py`):
- After running against the full `real_world_manifest.json`, compute the
  aggregate noise quotient across all repos.
- If it exceeds `2.0`, exit with a non-zero code and print which repo(s) are
  contributing the excess noise.
- This gate must be enforced in CI via the existing `--fail-under` mechanism or
  a new `--noise-gate` flag.

---

#### C3 — Cache & Offline Mode Hardening

Verify and harden these three corpus runner modes in `benchmarks/external_corpus.py`:

| Flag | Expected behaviour |
|---|---|
| `--cache-dir PATH` | Clones/fetches repos into PATH; subsequent runs use cached copy |
| `--refresh` | Re-fetches all repos even if cache exists |
| `--offline` | Reads from cache only; raises a clear `OfflineCacheMissError` if a repo is not cached — must NOT hang or make network calls |

**Write a test in `tests/test_corpus_offline.py`** that:
- Mocks the network layer (no real HTTP calls)
- Asserts `--offline` raises `OfflineCacheMissError` when cache is empty
- Asserts `--offline` succeeds and returns correct results when cache is populated
- Asserts `--refresh` triggers a fresh fetch even when a valid cache exists

---

#### C4 — Benchmark Reproducibility Doc

Create `benchmarks/REPRODUCING.md` with step-by-step instructions for:
1. Running the full benchmark suite from a clean clone
2. Reproducing the web-wild noise quotient number
3. Adding a new real-world repo to the manifest
4. Understanding what each metric in `final_product_scorecard.json` means

This is critical for new contributors and for anyone who wants to verify claims
about the tool's precision independently.

---

### TASK D — Community Rule Ecosystem

**Goal:** Build a lightweight community rule registry that gives Ansede the
Semgrep-style community ruleset advantage — without any runtime dependencies
and with full offline support.

---

#### D1 — Community Rule YAML Schema

Create `tools/community_rule_schema.yaml` defining the canonical schema.

Every community rule file must conform to this structure:

```yaml
# Required fields
id: "community/flask-missing-rate-limit-CWE-307"
  # Format: "community/<framework>-<short-description>-<CWE>"
  # Must be globally unique. Used as stable rule_id in SARIF/JSON output.

title: "Flask route missing rate-limit middleware"
  # Human-readable title shown in findings output

cwe: "CWE-307"
  # Must be a valid CWE tag (e.g. CWE-89, CWE-862)

severity: "high"
  # One of: critical, high, medium, low, info

language: "python"
  # One of: python, javascript, typescript, java, csharp, go

pattern:
  type: "ast_structural"
    # One of: ast_structural, regex, taint_sink
  route_decorator: "@app.route"
    # (ast_structural only) The decorator marking a route entry point
  missing_decorator:
    - "@limiter.limit"
    - "ratelimit"
    # (ast_structural only) If NONE of these are present on or above the route,
    # flag the finding

tags:
  - "owasp:A07"
  - "nist:AC-7"
  # Optional. Used for compliance output. At least one recommended.

# Required: test cases used to validate the rule
test:
  positive: |
    @app.route("/login", methods=["POST"])
    def login():
        pass
    # This MUST trigger the rule
  negative: |
    @app.route("/login", methods=["POST"])
    @limiter.limit("5 per minute")
    def login():
        pass
    # This must NOT trigger the rule

# Optional metadata
author: "github-username"
created: "2026-05-05"
references:
  - "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
```

---

#### D2 — Registry Index Format

Create `community_rules/index.json` at the repo root:

```json
{
  "schema_version": "1.0",
  "updated": "2026-05-05",
  "rules": [
    {
      "id": "community/flask-missing-rate-limit-CWE-307",
      "title": "Flask route missing rate-limit middleware",
      "cwe": "CWE-307",
      "severity": "high",
      "language": "python",
      "url": "https://raw.githubusercontent.com/mattybellx/Ansede/master/community_rules/flask-missing-rate-limit-CWE-307.yaml",
      "tags": ["owasp:A07"]
    }
  ]
}
```

The index URL that the fetch command defaults to:
`https://raw.githubusercontent.com/mattybellx/Ansede/master/community_rules/index.json`

---

#### D3 — Registry Fetch & Manage Command

Create `tools/registry.py`. Also expose it as a CLI subcommand:
`ansede-static registry --fetch` / `ansede-static registry --list` / `ansede-static registry --remove <id>`

**`registry --fetch` must:**
1. Download the index JSON from the configured URL (or `--registry-url`).
2. For each rule in the index, download the YAML to `~/.ansede/community_rules/`.
3. Validate each YAML rule against the schema in D1.
4. Skip any rule that fails validation, print a `WARNING` with the reason.
5. Print a summary: `Fetched N rules, skipped M (schema errors).`
6. Work fully offline after initial fetch — subsequent scans use
   `~/.ansede/community_rules/` without network.

**`registry --fetch --offline` must:**
- Not make any network calls whatsoever.
- If `~/.ansede/community_rules/` is empty, print a clear error:
  `No community rules cached. Run 'ansede-static registry --fetch' first.`

**`registry --list` must:**
- Print all installed community rules with ID, CWE, severity, and language.
- Mark rules that are disabled via `ansede.json` `disable_rules` with `[disabled]`.

**`registry --remove <id>` must:**
- Delete the specified rule file from `~/.ansede/community_rules/`.

---

#### D4 — Community Rule Integration into Scan Engine

Modify the scan engine to load community rules at scan startup:

1. At the start of `scan_file()` and `scan_code()`, check if
   `~/.ansede/community_rules/` exists and contains any `.yaml` files.
2. Load and validate each rule file. Skip invalid ones with a `WARNING`.
3. Merge community rules with built-in rules for the relevant language.
4. Apply `disable_rules` from `ansede.json` — community rule IDs must be
   suppressible the same way built-in rule IDs are.
5. Community rule findings must carry the rule's `id` as the stable `rule_id`
   in SARIF and JSON output.
6. Community rule findings must be suppressible with inline comments:
   `# ansede: ignore[community/flask-missing-rate-limit-CWE-307]`
7. Community rule findings must be correctly handled by `--baseline` diffing
   (the `fingerprint_version` field must account for community rules).

---

#### D5 — Community Rule Test Coverage

Create `tests/test_community_rules.py` with these test cases:

```python
def test_valid_rule_fires_on_positive_fixture()
    # Load a known-good community rule YAML
    # Run scan_code() on its test.positive snippet
    # Assert exactly one finding is returned with the correct rule_id and CWE

def test_valid_rule_silent_on_negative_fixture()
    # Load a known-good community rule YAML
    # Run scan_code() on its test.negative snippet
    # Assert zero findings are returned

def test_malformed_rule_skipped_with_warning()
    # Create a YAML file missing required fields (e.g., no 'cwe' field)
    # Assert it is skipped and a WARNING is logged
    # Assert the scan still completes successfully

def test_community_rule_id_survives_baseline_roundtrip()
    # Scan with a community rule → save as baseline
    # Re-scan → assert baseline diff is empty (no new findings)
    # Assert the community rule_id is stable in the JSON output

def test_community_rule_suppressible_via_disable_rules()
    # Configure ansede.json with disable_rules: ["community/flask-..."]
    # Run scan → assert the community rule finding does not appear

def test_community_rule_suppressible_via_inline_comment()
    # Source code contains the pattern + the inline suppress comment
    # Assert zero findings are returned
```

---

### TASK E — Developer Experience & Tooling Improvements

These are smaller, high-value additions that significantly improve the tool's
usability and contribute to community trust and adoption.

---

#### E1 — `--explain` Flag

Add a `--explain` flag to the CLI that, given a finding's `rule_id` or CWE,
prints a rich explanation including:
- What the vulnerability is (plain English)
- Why it is dangerous (impact)
- A concrete vulnerable code example
- A concrete fixed code example
- Relevant CWE/OWASP links

This should use and extend the existing `engine/explain.py` module.

Example usage:
```bash
ansede-static --explain CWE-639
ansede-static --explain PY-028
ansede-static --explain community/flask-missing-rate-limit-CWE-307
```

---

#### E2 — Machine-Readable Rule Catalog Export

Add `--export-rules json` and `--export-rules yaml` flags that dump the complete
rule catalog (built-in + installed community rules) to stdout. Format:

```json
{
  "schema_version": "1.0",
  "generated": "2026-05-05T00:00:00Z",
  "rules": [
    {
      "id": "PY-001",
      "cwe": "CWE-89",
      "title": "SQL Injection via f-string",
      "severity": "critical",
      "language": "python",
      "analysis_kind": "taint_flow",
      "tags": ["owasp:A03", "nist:SI-10"]
    }
  ]
}
```

This enables downstream tooling (dashboards, compliance reports) to consume the
full rule catalog programmatically.

---

#### E3 — Findings Summary Statistics in JSON Output

Extend the JSON output envelope to include a `summary` block:

```json
{
  "fingerprint_version": 2,
  "summary": {
    "total_findings": 7,
    "by_severity": { "critical": 2, "high": 3, "medium": 2, "low": 0 },
    "by_cwe": { "CWE-89": 2, "CWE-862": 3, "CWE-79": 2 },
    "by_language": { "python": 4, "javascript": 3 },
    "files_scanned": 12,
    "lines_scanned": 4821,
    "scan_duration_ms": 341
  },
  "results": [...]
}
```

This must not break existing consumers of the JSON format — the `results` array
structure must be unchanged.

---

#### E4 — `--output-dir` Flag for Multi-Format Output

Add `--output-dir PATH` that simultaneously writes all output formats to a
directory:
```
PATH/ansede-report.txt
PATH/ansede-report.json
PATH/ansede-report.sarif
PATH/ansede-report.html
```

This is useful for CI pipelines that need multiple formats from a single scan.

---

## 6. REQUIRED OUTPUT FORMAT FROM THE LLM

For **every task**, your response must include all of the following. Do not skip any.

### 6.1 — File Manifest
A table listing every file you are **creating** or **modifying**, with one sentence
explaining what changed and why:

| File | Action | Why |
|---|---|---|
| `src/ansede_static/java_analyzer.py` | Create | New Java detection engine |
| `src/ansede_static/cli.py` | Modify | Add `.java` extension routing |
| `benchmarks/cve_corpus.py` | Modify | Add 7 Java CVEEntry fixtures |

### 6.2 — Full Code
Complete, runnable Python (or YAML/JSON) for every file listed. No stubs, no
`# TODO` placeholders, no `pass` in a function body that should have logic.
If a file is long, provide it in clearly labelled sections — but provide all of it.

### 6.3 — Performance Justification
For every new analyzer or analysis pass, provide a paragraph explaining:
- The time complexity of the algorithm (e.g., O(n) in line count)
- The specific bound value used (e.g., call-string depth = 5, annotation
  lookback = 10 lines)
- Why this keeps the implementation within the 10 s/100k LOC budget

### 6.4 — Regression Verification
The exact commands to run after your changes and the expected result:
```bash
pytest tests/test_java_analyzer.py -v  # expected: all green
python -m benchmarks.nvd_benchmark     # expected: 42/42 (adds 7 new entries)
python -m benchmarks.perf_benchmark --iterations 10  # expected: < 10s/100kLOC
```

### 6.5 — SARIF/JSON Compatibility Confirmation
Explicitly state:
- The `rule_id` values for each new rule (e.g., `JV-001` through `JV-007`)
- The `analysisKind` for each new rule
- The `confidence` level for each new rule
- That the new rules do not break the baseline `fingerprint_version` contract

---

## 7. FINAL CHECKLIST — BEFORE SUBMITTING YOUR IMPLEMENTATION

Go through this list before considering any task complete:

- [ ] Zero new entries in `pyproject.toml` `install_requires`
- [ ] `pytest tests/ -v` — all green, count has increased (new tests added)
- [ ] `python -m benchmarks.nvd_benchmark` — recall ≥ 85% (count has increased)
- [ ] `python -m benchmarks.quality_benchmark --fail-under 100` — 100%
- [ ] `python -m benchmarks.perf_benchmark --iterations 10` — < 10s/100kLOC
- [ ] `ansede-static src/ --fail-on high` — self-scan is clean
- [ ] `ansede-static --list-rules` — new rule IDs appear
- [ ] `scan_code(source, language="java")` — works via public API
- [ ] `scan_code(source, language="csharp")` — works via public API
- [ ] `scan_code(source, language="go")` — works via public API
- [ ] `--baseline` diffing still works with new rules
- [ ] `--incremental` still works with new file extensions
- [ ] SARIF output from new rules passes `sarif-tools` schema validation
- [ ] JSON output still contains `fingerprint_version` in envelope
- [ ] Community rule `--fetch` works; malformed rules are skipped with WARNING
- [ ] Community rule IDs survive baseline round-trip
- [ ] Web-wild noise quotient still < 2.0 after new corpus entries
- [ ] No hardcoded absolute paths anywhere in new code
- [ ] All new functions have docstrings
- [ ] No unbounded recursion — all recursive calls have explicit depth guards

---

## 8. CONTEXT FILES TO READ BEFORE STARTING

If you have access to the repository, read these files before writing any code.
They contain critical implementation details not summarised above:

1. `src/ansede_static/python_analyzer.py` — understand the rule registration
   pattern (`_rule_NN(ctx)` functions + `_detect()` registration) before adding
   Python rules.
2. `src/ansede_static/js_ast_analyzer.py` — understand the structural engine
   pattern before adding JS framework heuristics.
3. `src/ansede_static/ir/global_graph.py` — understand the current IFDS
   implementation before modifying call-string depth.
4. `benchmarks/cve_corpus.py` — understand the `CVEEntry(...)` structure before
   adding new entries.
5. `IFDS_IMPLEMENTATION_SUMMARY.md` — deep context on the current inter-procedural
   analysis implementation.
6. `V2_IMPLEMENTATION_SUMMARY.md` — what was changed in v2.0.0 and why.
7. `CONTRIBUTING.md` — the full contributor checklist and code standards.
8. `ROADMAP.md` — planned work to avoid duplicating effort or conflicting with
   in-progress features.
9. `final_product_scorecard.json` — the exact current metric values you must not
   regress.

---

*Ansede Static — github.com/mattybellx/Ansede — MIT License*
*Prompt version: 3.0 — Generated 2026-05-05*
