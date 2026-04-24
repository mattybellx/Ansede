# Contributing to ansede-static

Thanks for considering contributing! Here's how to get started.

## Development Setup

```bash
git clone https://github.com/YOUR_ORG/ansede-static.git
cd ansede-static
python -m venv .venv
.venv/Scripts/activate   # Windows
# source .venv/bin/activate  # macOS/Linux
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest tests/ -v
```

All tests must pass before submitting a PR. We target **100% pass rate** on Python 3.9–3.13.

## Adding a New Rule

1. Add a `_rule_NN(ctx: _Ctx) -> list[Finding]` function in the appropriate analyzer
2. Register it in the `_detect()` dispatcher
3. Add at least two tests: one that **triggers** the rule and one that does **not**
4. Include the CWE ID in the finding title: `CWE-XXX: Description`

## Code Style

- Zero external dependencies — stdlib only
- Type hints on all public functions
- No `# type: ignore` without a comment explaining why

## Pull Request Checklist

- [ ] All tests pass (`pytest tests/ -v`)
- [ ] New rules have ≥ 2 tests (positive + negative)
- [ ] No new dependencies added
- [ ] CHANGELOG.md updated under `## [Unreleased]`

## Reporting Security Issues

See [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
