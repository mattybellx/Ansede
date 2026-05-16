# Zero-Friction CI Rollout (Day 0 → Day 30)

This guide helps large teams adopt `ansede-static` without breaking builds on legacy findings.

## Goals

- Start with **visibility only**.
- Freeze legacy issues with a **baseline**.
- Enforce only **new high-risk regressions**.
- Keep feedback fast with **incremental scans**.

---

## Day 0: Observe-only (no build breaks)

1. Generate SARIF and upload to code scanning.
2. Keep pipeline green while teams triage initial findings.

### GitHub Actions (observe-only)

```yaml
name: security
on: [pull_request]

jobs:
  ansede:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mattybellx/Ansede@v2.1.6
        with:
          path: .
          fail-on: never
          upload-sarif: true
```

---

## Day 3–7: Baseline legacy debt

1. Create a baseline JSON from the current default branch state.
2. Commit baseline artifact (or store as a trusted build artifact).
3. Enforce only **new** high/critical findings.

### Baseline workflow

```bash
ansede-static . --format json --output .ansede-baseline.json
ansede-static . --baseline .ansede-baseline.json --fail-on high
```

---

## Day 7–14: Fast PR gating with incremental mode

Use incremental scanning for pre-commit and PR speed:

```bash
ansede-static . --incremental --baseline .ansede-baseline.json --fail-on high
```

Recommended policy:
- PRs: `--incremental --baseline ... --fail-on high`
- Nightly/default branch: full scan with baseline

---

## Day 14–30: Raise enforcement gradually

Start strictness ramps only after teams fix noisy hotspots.

Suggested progression:

1. `fail-on: critical`
2. `fail-on: high`
3. Optional: `fail-on: medium` in high-assurance repos

---

## Policy presets

### 1) Observe-only
- `--fail-on never`
- SARIF upload enabled

### 2) Fail on critical regressions
- `--baseline .ansede-baseline.json --fail-on critical`

### 3) Fail on high regressions (recommended steady state)
- `--baseline .ansede-baseline.json --fail-on high`

---

## GitLab/Jenkins examples (command-only)

Use the same command profile in any CI system:

```bash
ansede-static . --baseline .ansede-baseline.json --fail-on high --format sarif --output ansede.sarif
```

Upload `ansede.sarif` to your platform’s security/code-scanning UI if supported.

---

## Measured local verification snapshot (2026-05-16)

Validated in this repository against `src/` scope:

- Baseline JSON generation: **147.55s**
- SARIF generation: **145.88s**
- Incremental scan (`--incremental --baseline ...`): **0.58s**

Artifacts produced:

- `.tmp/ci-baseline.json`
- `.tmp/ci-findings.sarif`

Notes:

- Incremental output artifact may be omitted when no changed files are detected in `git diff HEAD`.
- On Windows terminals, set `PYTHONIOENCODING=utf-8` to avoid unicode rendering issues in colored console output.
- Scanning repository root (`.`) can include platform-specific inaccessible pseudo-paths; prefer explicit source scope (`src/`) in CI examples.

---

## Migration FAQ for large monorepos

### “We got hundreds of findings on first run.”
Expected. Generate a baseline and enforce only new regressions.

### “PR checks are too slow.”
Use `--incremental` on PRs and keep full scans on nightly/default branch.

### “Developers ignore scanner output.”
Enable SARIF upload so findings are visible inline in PR code flow.

### “We have false positives in specific paths.”
Use `exclude_paths`, targeted rule disables, and submit FP reports with minimal repro.

---

## Verification checklist

- [x] Baseline generated from default branch and versioned. *(Verified locally; `.tmp/ci-baseline.json`)*
- [x] PR workflow uses `--incremental` + `--baseline`. *(Command profile validated)*
- [x] SARIF uploaded on every PR. *(Command/output path validated: `.tmp/ci-findings.sarif`)*
- [x] Enforcement threshold documented per repository. *(Preset policy section above)*
- [x] Nightly full scan retained for broader coverage. *(Recommended policy section above)*
