# Community Rule Conversion Guide (Semgrep/CodeQL → Ansede YAML)

This guide helps contributors port high-value rules into Ansede community rule packs.

## Mapping Cheat Sheet

| Source | Ansede field |
|---|---|
| rule id | `id` |
| message/title | `title` |
| severity | `severity` |
| CWE tag | `cwe` |
| language scope | `languages` |
| pattern predicate | `pattern` |
| remediation text | `suggestion` |

## Severity normalization

- `ERROR` / critical exploitability → `critical`
- high-confidence auth/access issues → `high`
- weaker heuristic patterns → `medium`
- style/low confidence checks → `low`

## Conversion Steps

1. Start from known true-positive sample.
2. Extract minimal, anchored pattern.
3. Add language scoping and CWE.
4. Add false-positive guard notes in PR.
5. Add one true-negative fixture.
6. Run registry-kit CI validation.

## Example skeleton

```yaml
version: "1.0"
rules:
  - id: "COMM-EXAMPLE-001"
    title: "Example rule"
    description: "Why this matters"
    severity: "high"
    cwe: "CWE-862"
    category: "security"
    languages: ["python"]
    pattern: "@app\\.route\\(.*admin"
    suggestion: "Add explicit auth and authorization checks."
```

## Review standard

A converted rule is accepted only if:

- it preserves original security intent,
- it avoids obvious noisy overmatching,
- it passes schema validation,
- it includes a reproducible fixture rationale.
