<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/mattybellx/Ansede/master/AS.png">
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/mattybellx/Ansede/master/AS.png">
    <img alt="Ansede Static — Offline SAST" src="https://raw.githubusercontent.com/mattybellx/Ansede/master/AS.png" width="600">
  </picture>
</p>

<p align="center">
  <strong>Offline SAST engine.</strong><br>
  <code>pip install ansede-static</code> &nbsp;·&nbsp; Zero dependencies &nbsp;·&nbsp; No telemetry
</p>

<p align="center">
  <a href="https://pypi.org/project/ansede-static"><img src="https://img.shields.io/pypi/v/ansede-static?label=pypi&color=0078D4" alt="PyPI"></a>
  <a href="https://github.com/mattybellx/Ansede/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/mattybellx/Ansede/ci.yml?branch=master&label=CI" alt="CI"></a>
  <a href="https://github.com/mattybellx/Ansede/blob/master/BENCHMARKS.md"><img src="https://img.shields.io/badge/CVE%20Recall-100%25-green" alt="100% recall"></a>
  <a href="https://github.com/mattybellx/Ansede/blob/master/BENCHMARKS.md"><img src="https://img.shields.io/badge/Precision-97.5%25-green" alt="97.5% precision"></a>
  <a href="https://github.com/mattybellx/Ansede/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"></a>
</p>

---

## Quick Start

```bash
pip install ansede-static
ansede-static src/                        # scan a directory
ansede-static src/ --format sarif         # GitHub Code Scanning
ansede-static src/ --fail-on high         # CI gate
ansede-static src/ --incremental          # git-diff mode
```

## Why ansede-static?

Most SAST tools find SQLi, command injection, and XSS. ansede-static finds the bugs they miss — **broken access control, missing authentication, and IDOR** — by modeling routes, auth guards, and ownership patterns at the AST level.

```python
@app.route("/invoice/<invoice_id>")
@login_required
def get_invoice(invoice_id):
    return db.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,))
    # → CWE-639 IDOR: any user can see any invoice
    # Bandit/Semgrep OSS: silent.  ansede: CRITICAL
```

```python
@app.route("/admin/users")
def list_users():
    return User.query.all()
    # → CWE-862: unauthenticated admin access
    # Bandit/Semgrep OSS: silent.  ansede: HIGH
```

## Benchmarks

| Metric | Result |
|--------|--------|
| **CVE recall** (115/115 synthetic) | **100%** |
| **CVE precision** | **97.5%** |
| **Quality benchmark** | **63/63 checks (100%)** |
| **Real repos scanned** | **35/35** — 12,372 files, 1.76M LOC, 71 MB |
| **CWE types detected** | **35+** |
| **Languages** | Python, JS/TS, Go, Java, C# |
| **Zero failures** | ✅ across all 35 repos |
| **Zero dependencies** | ✅ pure Python stdlib |

Full details in [`BENCHMARKS.md`](BENCHMARKS.md).

## Who is it for?

- **Developers** who want a `pip install`-and-scan experience
- **CI/CD pipelines** that need SARIF output and fail-on gates
- **Security teams** tired of triaging the same noise from heavier tools

## GitHub Action

```yaml
- uses: mattybellx/Ansede@v2.3.2
  with:
    path: src/
    fail-on: high
    upload-sarif: true
```

## Features

**Incremental** — `--incremental` (git diff) or `--incremental-sha256` for monorepos  
**Baseline** — freeze legacy debt with `--baseline baseline.json`  
**Clustering** — 49% finding reduction via incident merging  
**AI triage** — optional local Ollama integration for auto-classification  
**IDE plugins** — VS Code, IntelliJ IDEA, Visual Studio 2022  
**Outputs** — SARIF, JSON, HTML, SBOM, plain text  

## Contributing

```bash
git clone https://github.com/mattybellx/Ansede.git
cd Ansede
pip install -e ".[dev]"
pytest tests/ -q
```

---

<p align="center">
  <sub>MIT licensed · Zero telemetry · No cloud dependency · Built by <a href="https://github.com/mattybellx">Matty Bell</a></sub>
</p>
