# IDE plugin architecture for IntelliJ IDEA and Visual Studio

This document defines the first-party plugin architecture for bringing `ansede-static` beyond the existing VS Code extension.

## goals

- Mirror the current VS Code experience:
  - inline diagnostics
  - hover details with `--explain` content
  - quick-fix actions for safe `BEFORE:` / `AFTER:` fixes
  - manual scan commands
  - workspace scan entry points
- Reuse the existing CLI and JSON schema instead of creating editor-specific scanner logic.
- Keep integrations offline-first and dependency-light.
- Support the new language surface already present in the engine:
  - Python
  - JavaScript / TypeScript
  - Java
  - C#
  - Go

## shared contract

All IDE plugins should invoke the CLI in the same way:

- stdin mode for open-buffer scans
- machine-readable JSON output
- `--fail-on never`
- `--explain` enabled for rich hover content

Canonical command shape:

`ansede-static --stdin --lang <language> --format json --fail-on never --explain`

The plugin layer should treat the CLI JSON envelope as the source of truth for:

- `severity`
- `title`
- `description`
- `line`
- `suggestion`
- `rule_id`
- `cwe`
- `confidence`
- `analysis_kind`
- `auto_fix`
- `explanation`

## IntelliJ IDEA plugin shape

Recommended stack:

- Kotlin
- Gradle IntelliJ Plugin 2.x
- IntelliJ `Annotator` or `ExternalAnnotator` for diagnostics
- `LineMarkerProvider` or `HoverProvider` equivalent for rich detail surfaces
- `IntentionAction` for inline safe fixes

Core components:

1. `AnsedeCliService`
   - resolves executable path
   - runs CLI process
   - parses JSON payload
2. `AnsedeExternalAnnotator`
   - maps findings into editor annotations
3. `AnsedeIntentionAction`
   - applies single-line `BEFORE/AFTER` replacements when safe
4. `AnsedeToolWindowFactory`
   - optional workspace summary / scan status view
5. `AnsedeSettingsConfigurable`
   - executable path
   - scan-on-save / scan-on-type
   - min severity
   - timeout

## Visual Studio plugin shape

Recommended stack:

- C#
- VSIX project
- `AsyncPackage`
- tagger / diagnostic provider integration
- light tool window or command surface for workspace scans
- command handler for safe quick fixes

Core components:

1. `AnsedeScannerService`
   - resolves executable path
   - starts CLI process
   - parses JSON payload
2. `AnsedeTextViewListener`
   - responds to open/save/edit events
3. `AnsedeErrorTagger`
   - maps findings to editor squiggles / tags
4. `AnsedeQuickFixCommand`
   - applies safe single-line replacements
5. `AnsedeOptionsPage`
   - executable path
   - min severity
   - scan timeout
   - scan triggers

## mapping model

Each IDE plugin should normalize findings into an internal editor model:

```text
EditorFinding
- filePath
- language
- severity
- title
- description
- line
- ruleId
- cwe
- explanation
- suggestion
- autoFix
- analysisKind
- confidence
```

## quick-fix policy

Only auto-apply fixes when all of the following are true:

- `auto_fix` contains both `BEFORE:` and `AFTER:`
- replacement is constrained to the reported line or exact span
- editor buffer still matches the expected `BEFORE:` content
- no multi-file mutation is required

Otherwise, show the remediation as preview-only guidance.

## future milestones

- Add SARIF export entry points from each IDE surface.
- Add background workspace indexing for large repositories.
- Add suppression UI backed by stable `rule_id` values.
- Add diff-aware rescans for changed regions only.
- Add test harnesses that replay fixed JSON fixtures into each plugin UI.
