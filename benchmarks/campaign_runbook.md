# Campaign Runbook (Track 1)

This runbook operationalizes the real-world bug discovery campaign for `CWE-862` and `CWE-639`.

## Inputs

- `benchmarks/campaign_targets_top100.example.json` (replace with real pinned targets)
- `benchmarks/disclosure_campaign_ledger.example.json`
- `docs/responsible-disclosure-rubric.md`

## Execution Flow

1. Select target from queued list.
2. Pin commit SHA and record in ledger.
3. Run scanner with stable profile:
   - severity >= high
   - structural JS backend
   - focus on auth/ownership findings
4. Save artifacts:
   - findings JSON
   - findings SARIF
5. Manual triage using rubric.
6. Mark ledger status: rejected/needs-review/disclosed/acknowledged/patched.

## Suggested Artifact Paths

- `.tmp/campaign/<target-id>/findings.json`
- `.tmp/campaign/<target-id>/findings.sarif`
- `.tmp/campaign/<target-id>/triage.md`

## Disclosure States

- `new`
- `triage-in-progress`
- `candidate-reportable`
- `disclosed-private`
- `acknowledged`
- `patched`
- `public-writeup-ready`

## Quality Gates

- No claim without pinned SHA and reproducible artifacts.
- No public post before maintainer-safe disclosure window.
- No campaign metric should include synthetic-only evidence.
