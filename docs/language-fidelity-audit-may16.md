# Language Fidelity Audit Snapshot (2026-05-16)

This snapshot records current analyzer confidence signals for Java, C#, and Go based on public benchmark artifacts.

## Inputs

- `python -m benchmarks.cve_recall_runner --quiet --json`
- `benchmarks/real_world_drift_summary_may16.json`
- `benchmarks/real_world_manifest.json`

## CVE recall snapshot

From local 2026-05-16 CVE runner summary:

- Java: 2/2 cases, recall 100%
- C#: 2/2 cases, recall 100%
- Go: 3/3 cases, recall 100%

## Real-world corpus snapshot

- Java (WebGoat full repo): 87 findings, 4.3719 noise/kLOC
- Current real-world manifest does not yet include large C# or Go repos at parity with Java/JS/Python coverage.

## Gap assessment

1. **Coverage imbalance**
   - Java has meaningful full-repo coverage in current manifest.
   - C# and Go still rely mostly on synthetic/smaller coverage surfaces.
2. **Structural fidelity visibility**
   - Need explicit parser-depth metadata in findings for Java/C#/Go paths.
3. **Framework semantic depth**
   - Need stronger first-class modeling for auth/middleware/decorator semantics across major frameworks.

## Next recommended actions

- Add at least one large C# and one large Go repository to `benchmarks/real_world_manifest.json`.
- Add parser-depth confidence labels in report metadata for non-Python/non-JS findings.
- Execute parity corpus from `benchmarks/language_parity_manifest.json` as a tracked CI benchmark lane.
