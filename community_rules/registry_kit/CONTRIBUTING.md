# Contributing Community Rules

## Rule quality checklist

- Include stable `id`, `title`, `severity`, `cwe`, and `languages`
- Add concise `description` and `suggestion`
- Provide at least one true-positive fixture
- Provide at least one true-negative fixture
- Avoid duplicate/overlapping noisy patterns

## PR requirements

- Rule pack passes CI validation
- Rule rationale includes expected risk and false-positive notes
- Any broad regex includes boundary anchors or context guards
