# Reproducing Ansede benchmark claims

This guide explains how to reproduce the core benchmark and scorecard numbers from a clean clone of the repository.

## Prerequisites

- Windows, macOS, or Linux
- Python 3.13-compatible environment
- Git available on `PATH`
- Internet access for the first real-world corpus run, unless the cache is already populated

## 1. Start from a clean clone

Clone the repository and create an isolated Python environment.

Recommended workflow:

- create a virtual environment
- install the package in editable mode
- keep the benchmark cache outside the repo or under `.tmp/`

If you use the repo's local virtual environment layout, the commands used in this workspace were run with:

- `c:/Users/matth/OneDrive/Desktop/ansede-static-focus/.venv/Scripts/python.exe`

## 2. Run the full benchmark suite

Run each benchmark explicitly so failures are easy to attribute.

```text
python -m pytest tests -q --tb=short
python -m benchmarks.nvd_benchmark
python -m benchmarks.quality_benchmark --fail-under 100
python -m benchmarks.external_corpus --manifest benchmarks/external_manifest.json --fail-under 100
python -m benchmarks.external_corpus --manifest benchmarks/real_world_manifest.json --cache-dir .tmp/ansede-corpus --noise-gate 2.0
python -m benchmarks.perf_benchmark --iterations 10
```

## 3. Reproduce the real-world noise quotient

The curated real-world corpus uses `benchmarks/real_world_manifest.json`.

### First run with network access

```text
python -m benchmarks.external_corpus --manifest benchmarks/real_world_manifest.json --cache-dir .tmp/ansede-corpus --noise-gate 2.0
```

This will:

- clone pinned repositories into `.tmp/ansede-corpus`
- scan only the configured languages
- apply configured `exclude_paths`
- compare the observed findings count against each entry's calibrated `expected_findings` range
- compute two density metrics:
  - `raw_noise_quotient`: all findings per 1k LOC
  - `noise_quotient`: excess findings per 1k LOC above the calibrated expected maximum

The `--noise-gate` check uses the **excess** metric, not the raw density, so intentionally vulnerable repos do not fail simply because they contain expected vulnerabilities.

### Re-run fully offline

```text
python -m benchmarks.external_corpus --manifest benchmarks/real_world_manifest.json --cache-dir .tmp/ansede-corpus --offline --noise-gate 2.0
```

If the cache is missing, the runner raises `OfflineCacheMissError` immediately instead of attempting any network call.

## 4. Add a new real-world repository

When expanding `benchmarks/real_world_manifest.json`, follow this sequence:

1. Pin a commit SHA.
2. Add a new manifest entry with:
   - `case_id`
   - `name`
   - `source.kind = "git"`
   - `source.repo`
   - `source.ref`
   - `languages`
   - `exclude_paths`
   - provisional `expected_findings`
3. Run the repo in isolation:

```text
python -m benchmarks.external_corpus --manifest benchmarks/real_world_manifest.json --case <case_id> --cache-dir .tmp/ansede-corpus --json --quiet
```

4. Record the observed `findings_count` and `lines_scanned`.
5. Calibrate `expected_findings.min/max` to roughly ±30% around the observed count.
6. Re-run the isolated case.
7. Re-run the full manifest with `--noise-gate 2.0`.

If a repo still breaches the gate after calibration, investigate false positives and add targeted suppressions before committing the manifest entry.

## 5. Understand the scorecard metrics

`final_product_scorecard.json` and related scorecards combine several evidence streams.

### CVE recall

Produced by `benchmarks.nvd_benchmark`.

Measures:

- true positive recall against the synthetic CVE corpus
- precision / false-positive characteristics within that corpus

### Quality benchmark

Produced by `benchmarks.quality_benchmark`.

Measures:

- expected detections on tightly curated micro-cases
- suppression / sanitizer correctness on negative cases

### External corpus

Produced by `benchmarks.external_corpus`.

Measures:

- manifest-defined expectations against repo-shaped fixtures and pinned real-world repos
- cache reproducibility
- expected finding-range stability
- excess-noise regression through `--noise-gate`

### Performance benchmark

Produced by `benchmarks.perf_benchmark`.

Measures:

- throughput and consistency across repeated scans
- whether changes stay within the project's performance budget

## 6. Helpful one-off commands

### Inspect one curated real-world case

```text
python -m benchmarks.external_corpus --manifest benchmarks/real_world_manifest.json --case nodegoat-full-repo --cache-dir .tmp/ansede-corpus --json --quiet
```

### Refresh cached repos before a full run

```text
python -m benchmarks.external_corpus --manifest benchmarks/real_world_manifest.json --cache-dir .tmp/ansede-corpus --refresh --noise-gate 2.0
```

### Verify offline behavior after the cache is warm

```text
python -m benchmarks.external_corpus --manifest benchmarks/real_world_manifest.json --cache-dir .tmp/ansede-corpus --offline --json --quiet
```

## 7. Current calibrated repo-level entries

At the time this document was written, the repo-level entries in `benchmarks/real_world_manifest.json` were calibrated from isolated scans of:

- `OWASP WebGoat`
- `OWASP NodeGoat (full)`
- `flask-login example app`
- `Damn Vulnerable Node Application (DVNA)`

Those ranges should be re-measured if the analyzers or suppression logic change materially.
