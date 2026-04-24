# ansede-static-focus

This is an isolated working copy of `ansede-static` created from the larger `X` workspace so the static scanner can be improved without risking regressions or churn in the broader multi-project repo.

## Included
- Python package source in `src/ansede_static/`
- Test suite in `tests/`
- Benchmarks in `benchmarks/`
- GitHub Action and repo metadata
- VS Code extension in `vscode-extension/`

## Current intent
- Productize and polish `ansede-static` first
- Keep scope tight around deterministic scanning, packaging, CI, and editor integration
- Avoid coupling changes to `autopoietic-nsed-engine` unless intentionally ported later

## First practical improvements to consider
1. Tighten repo messaging and install/run docs
2. Fix current packaging/editor rough edges
3. Add CI for tests + lint/type checks
4. Improve rule precision and benchmark realism
5. Decide what belongs in free vs Pro later
