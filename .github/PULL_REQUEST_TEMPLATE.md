## Pull Request

### What does this PR do?

<!-- A clear, concise summary of the change. -->

### Motivation / context

<!-- Why is this change needed? Link a related issue with "Closes #123" if applicable. -->

### Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New detection rule (new CWE or variant)
- [ ] False-positive / false-negative fix
- [ ] Performance improvement
- [ ] Documentation update
- [ ] Other (describe below)

### Checklist

- [ ] I have added or updated tests for the change
- [ ] All existing tests pass (`pytest tests/`)
- [ ] The benchmark still passes (`python -m benchmarks.nvd_benchmark --fail-under 90 --quiet`)
- [ ] I have updated `CHANGELOG.md` under `[Unreleased]`
- [ ] For new rules: I have added an entry to the detection-coverage table in `README.md`

### Sample output

<!-- Paste an example of `ansede-static` output that demonstrates the change, if applicable. -->
