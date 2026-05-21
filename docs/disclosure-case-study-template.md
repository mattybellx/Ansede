# Disclosure Case Study Template

Use this template when publishing a responsible disclosure case study
for a finding discovered by ansede-static in an open-source project.

---

## Case Study: [CWE-XXX] in [Project Name]

**Published:** YYYY-MM-DD
**Project:** [link to repo]
**Version/Pinned Commit:** [sha]
**Status:** Fixed / Acknowledged / Under Review

---

### Summary

[One-paragraph description of the vulnerability]

### Root Cause

[Explanation of why the vulnerability exists — what coding pattern, missing
guard, or architectural gap allows the attack]

### Minimal Reproduction

```[language]
# Code snippet that triggers the vulnerability
```

Steps to reproduce:

1. [Step 1]
2. [Step 2]
3. [Step 3]

### Minimally Invasive Patch

```diff
- [Vulnerable code]
+ [Fixed code]
```

### Ansede Static Trace

```
Rule:       [rule_id]
CWE:        [CWE-XXX]
Severity:   [critical/high/medium]
Confidence: [0.XX]
Analysis:   [structural/heuristic]
File:       [path:line]

Trace:
  1. source `[taint source description]` at [file:line]
  2. through `[propagation point]` at [file:line]
  3. sink `[dangerous call]` at [file:line]
```

### Why Baseline Tools Missed It

| Tool | Result | Reason |
|------|--------|--------|
| Bandit (default) | [FP/FN/correct] | [explanation] |
| Semgrep (default) | [FP/FN/correct] | [explanation] |
| CodeQL (default) | [FP/FN/correct] | [explanation] |
| **ansede-static** | **Correct** | [what made detection possible] |

### Reproducible Command

```bash
# Run the exact scan that produced this finding
ansede scan [path] \
    --format sarif \
    --js-backend structural \
    --fail-on high \
    --verbose
```

### SARIF Artifact

[Link to raw SARIF output or attached .sarif file]

### Timeline

- **YYYY-MM-DD** — Finding identified by ansede-static scan
- **YYYY-MM-DD** — Responsible disclosure sent to [contact method]
- **YYYY-MM-DD** — Maintainer acknowledged
- **YYYY-MM-DD** — Patch released in [version]
- **YYYY-MM-DD** — CVE assigned (if applicable)
