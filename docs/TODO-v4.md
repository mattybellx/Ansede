# v4.0 — Post-v3 Roadmap: Adoption, Scale & Depth

> **v3.0 baseline:** 114 tests · 98.78% CVE recall · 7 languages · 3 IDE plugins · cross-language taint · all formats free
> **Mission:** Turn a technically complete SAST engine into a widely adopted, industry-credible security tool.

---

## Tier 1 — Highest Impact (Weeks 1-4)

### 1.1 Publish VS Code Extension to Marketplace

- [ ] Create Microsoft Azure DevOps publisher account
- [ ] Generate Personal Access Token (PAT) for marketplace publishing
- [ ] Update `vscode-extension/package.json` with proper icons, gallery banner, and categories
- [ ] Run `vsce package` to produce final `.vsix`
- [ ] Run `vsce publish` to push to VS Code Marketplace
- [ ] Verify extension appears in marketplace search
- [ ] Install from marketplace to confirm end-to-end flow
- **Follow-up:** Publish IntelliJ plugin to JetBrains Marketplace
- **Follow-up:** Publish VS 2022 extension to Visual Studio Marketplace

### 1.2 Publish to GitHub

- [ ] Create public GitHub repository (if not already public)
- [ ] Add `README.md` with badges (tests, version, license)
- [ ] Set up GitHub Pages or wiki for documentation
- [ ] Configure branch protection rules
- [ ] Add `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md`
- [ ] Create GitHub Issues templates (bug report, feature request)
- [ ] Add GitHub Discussions for community Q&A
- **Release workflow:**
  - [ ] Create `.github/workflows/release.yml` that:
    - Runs full test suite
    - Builds all 3 IDE plugins
    - Creates GitHub Release with artifacts
    - Publishes to VS Code Marketplace
    - Publishes to PyPI

### 1.3 Publish to PyPI

- [ ] Update `pyproject.toml` with:
  - [ ] Project description and long description
  - [ ] Classifiers (License, Python versions, Topics)
  - [ ] `[project.urls]` section (Homepage, Documentation, Issues)
  - [ ] Proper `[tool.setuptools.packages.find]` config
- [ ] Test build: `python -m build`
- [ ] Create PyPI API token
- [ ] Add PyPI publish step to CI: `twine upload dist/*`
- [ ] Verify: `pip install ansede-static` works
- **CI automation:**
  - [ ] `.github/workflows/publish.yml` triggered on tags
  - [ ] Runs tests, builds wheel, publishes to PyPI
  - [ ] Creates GitHub Release with changelog

### 1.4 Expand CVE Corpus (82 → 500+ cases)

- [ ] Research additional NVD CVEs across all 7 languages
- [ ] Target: +100 Python, +100 JS/TS, +80 Java, +80 C#, +60 Go, +40 Ruby, +40 PHP
- [ ] Add entries to `benchmarks/cve_corpus.py` using `CVEEntry` dataclass
- [ ] Validate each new entry produces the expected CWE
- [ ] Re-run full CVE recall benchmark
- [ ] Document precision/recall changes in `BENCHMARKS.md`
- **Goal:** Statistically significant corpus that produces credible precision/recall numbers

### 1.5 Java/C# Rule Depth (match Python/JS)

- **Java (7 rules → ~30 rules):**
  - [ ] CWE-89: SQL injection via JDBC `Statement.executeQuery()` with string concatenation
  - [ ] CWE-22: Path traversal via `java.nio.file.Paths.get()` / `FileSystems`
  - [ ] CWE-79: XSS via response write without encoding
  - [ ] CWE-78: Command injection via `ProcessBuilder` (✅ done — JV-008)
  - [ ] CWE-502: Deserialization via `ObjectInputStream` (✅ done — JV-005)
  - [ ] CWE-918: SSRF via `HttpURLConnection` / `URL.openConnection()`
  - [ ] CWE-601: Open redirect via `sendRedirect()`
  - [ ] CWE-200: Stack trace exposure in error handlers
  - [ ] CWE-287: Spring Security misconfiguration
  - [ ] CWE-384: Session fixation (no session change on auth)

- **C# (9 rules → ~30 rules):**
  - [ ] CWE-89: SQL injection via `SqlCommand` (✅ done — CS-004)
  - [ ] CWE-22: Path traversal via `File.ReadAllText` / `Path.Combine`
  - [ ] CWE-79: XSS via `Response.Write` (✅ done — CS-008)
  - [ ] CWE-78: Command injection via `Process.Start` (✅ done — CS-010)
  - [ ] CWE-918: SSRF via `HttpClient` / `WebClient`
  - [ ] CWE-601: Open redirect via `Redirect()`
  - [ ] CWE-200: Stack trace exposure
  - [ ] CWE-312: Cleartext storage of passwords in config
  - [ ] CWE-287: ASP.NET Identity misconfiguration
  - [ ] CWE-384: Session fixation

---

## Tier 2 — Growth & Validation (Weeks 4-8)

### 2.1 Full Head-to-Head: ansede vs Semgrep (82 cases)

- [ ] Run `benchmarks/head_to_head.py` on full 82-case CVE corpus
- [ ] Record ansede detection rate vs Semgrep detection rate
- [ ] Categorize misses: ansede-only, Semgrep-only, both
- [ ] Document findings in `BENCHMARKS.md`
- [ ] Publish results as a blog post or technical report
- **Goal:** Independent validation of our 10/10 vs 6/10 sample finding

### 2.2 Publish Docker Image + GitHub Action

- [ ] Create `Dockerfile`:
  ```dockerfile
  FROM python:3.13-slim
  RUN pip install ansede-static
  ENTRYPOINT ["ansede-static"]
  ```
- [ ] Set up GitHub Container Registry publish in CI
- [ ] Test: `docker pull ghcr.io/ansede/static-scanner:latest`
- [ ] Create GitHub Action: `.github/actions/ansede-scan/action.yml`
  ```yaml
  name: 'Ansede Static Scan'
  description: 'Run ansede-static SAST scanner'
  runs:
    using: 'docker'
    image: 'docker://ghcr.io/ansede/static-scanner:latest'
  ```
- [ ] Publish action to GitHub Marketplace
- [ ] Test on a demo repo

### 2.3 OpenAPI/Swagger Bridge Auto-Generation

- [ ] Parse OpenAPI 3.0/3.1 specs to extract route definitions
- [ ] Match OpenAPI paths to backend route handlers (Python/Go/Java/C#)
- [ ] Generate cross-language bridge edges without needing exact URL matching
- [ ] Test on a real project with OpenAPI docs
- **Benefit:** Catches cross-language flows in API-first architectures

### 2.4 Run Against Top 1,000 GitHub Repos

- [ ] Use GitHub Search API to find popular Python/JS/Go/Java/C# repos
- [ ] Create batch scanning script in `tools/batch_scan_repos.py`
- [ ] Run scans and collect aggregate stats
- [ ] Report: average findings per repo, most common CWEs, false positive rate
- **Goal:** Scale credibility — show the tool works on real production code

---

## Tier 3 — Polish (Weeks 8-12)

### 3.1 Performance Optimization

- [ ] Profile real-repo throughput bottleneck (currently ~750 LOC/s)
- [ ] Investigate batching: scan all files in a single Python process (avoid per-file import overhead)
- [ ] Implement `--batch` mode that shares GlobalGraph + rules cache across files
- [ ] Target: 5,000+ LOC/s for Python, 50,000+ LOC/s for other languages
- [ ] Update `perf_regression_check.py` thresholds

### 3.2 HTML Dashboard

- [ ] Enhance `src/ansede_static/reporters.py` `format_html()` function
- [ ] Add interactive filtering by severity, CWE, file
- [ ] Add sorting by line number, severity, confidence
- [ ] Add SARIF export from dashboard
- [ ] Add summary statistics (total findings, top CWEs, files affected)
- [ ] Test on real scan results

### 3.3 Documentation Site

- [ ] Choose static site generator (MkDocs / Docusaurus)
- [ ] Create `docs/` site structure:
  - Getting Started (installation, first scan)
  - Rules Reference (all rules by language, CWE mapping)
  - Configuration (ansede.json, .ansedeignore)
  - CI Integration (GitHub Actions, GitLab CI, Jenkins)
  - IDE Setup (VS Code, IntelliJ, VS 2022)
  - Contributing (how to add rules, community guidelines)
  - FAQ / Troubleshooting
- [ ] Deploy to GitHub Pages
- [ ] Add search functionality

### 3.4 Run Full Semgrep Public Benchmark

- [ ] Download Semgrep's public benchmark suite
- [ ] Run both tools with identical inputs
- [ ] Compare precision, recall, F1 across all test cases
- [ ] Publish independent comparison report
- **Goal:** Defensible, third-party-auditable performance claims

---

## Release Checklist

### Pre-release
- [ ] All 114+ gate tests passing
- [ ] CVE recall benchmark ≥ 95%
- [ ] Quality benchmark 100%
- [ ] Binary guardrails check (0 deps, <5 MB)
- [ ] SARIF output validatable against VS Code SARIF viewer

### Release pipeline
- [ ] Tag commit: `git tag v4.0.0 && git push --tags`
- [ ] CI triggers:
  - [ ] Full test suite
  - [ ] Build all 3 IDE plugins
  - [ ] Build Docker image
  - [ ] Build Python wheel
  - [ ] Publish to PyPI
  - [ ] Publish to VS Code Marketplace
  - [ ] Publish Docker image to GHCR
  - [ ] Create GitHub Release with changelog + artifacts

### Post-release
- [ ] Announce on Twitter/X, Reddit r/netsec, Hacker News
- [ ] Write blog post: "How we built a 100% OSS SAST engine with 98.78% CVE recall"
- [ ] Monitor GitHub Issues for feedback
- [ ] Track PyPI downloads and VS Code installs

---

## Key Files to Modify

| File | Purpose |
|------|---------|
| `.github/workflows/publish.yml` | CI/CD release pipeline |
| `.github/workflows/ci.yml` | Update with publish steps |
| `pyproject.toml` | PyPI metadata |
| `vscode-extension/package.json` | Marketplace metadata |
| `benchmarks/cve_corpus.py` | Add 400+ CVE entries |
| `src/ansede_static/java_analyzer.py` | Add ~20 Java rules |
| `src/ansede_static/csharp_analyzer.py` | Add ~20 C# rules |
| `benchmarks/head_to_head.py` | Run on full corpus |
| `Dockerfile` | New file |
| `.github/actions/ansede-scan/action.yml` | New file |
| `tools/batch_scan_repos.py` | New file |
