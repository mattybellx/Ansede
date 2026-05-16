# Responsible Disclosure Rubric (Track 1)

Use this rubric before reporting any candidate vulnerability found by `ansede-static`.

## Reportable Criteria (all required)

1. **Pinned reproducibility**
   - Reproduces on a pinned commit SHA.
   - Reproduces from clean cache and offline cache replay.
2. **Security impact**
   - Enables unauthorized access, privilege bypass, data exposure, or object-level access violation.
   - Clear attacker-controlled input and reachable sink/authorization gap.
3. **Novelty**
   - Not already fixed or publicly reported in project issues/advisories.
4. **Signal quality**
   - Manual reviewer can explain exploit path in 3-6 steps.
   - SARIF/code trace aligns with source.

## Severity Rubric

- **High**: Unauthorized access to sensitive endpoint/object without ownership guard.
- **Critical**: Privilege escalation/admin access bypass with broad impact.
- **Medium/Low**: Incomplete preconditions, weak exploitability, or uncertain impact (do not campaign-post).

## Required Evidence Package

- Repository + pinned SHA
- Minimal reproducible path/file references
- Scanner command and output artifacts (JSON + SARIF)
- Manual triage note (impact, exploit preconditions, false-positive checks)
- Proposed minimal patch

## Disclosure Policy

- Use project `SECURITY.md` or private disclosure channel first.
- Do not publish exploit details before acknowledgment/fix window.
- Public write-up must redact exploit-enabling details until maintainer-safe.

## Rejection Conditions

Reject a candidate when:

- it depends on unrealistic threat assumptions,
- ownership/auth checks exist but were missed due to unsupported framework semantics,
- it cannot be reproduced reliably across reruns,
- issue is clearly documented and already tracked by maintainers.
