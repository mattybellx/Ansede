# Ansede IntelliJ scaffold

This directory contains the initial IntelliJ IDEA plugin scaffold for Ansede Static.

## intended feature parity

- external-buffer scanning via `ansede-static --stdin --format json --explain`
- editor annotations for findings
- explain-rich hovers
- intention actions for safe inline fixes
- tool window summary for current file / workspace scans

## next implementation steps

1. Add a JSON model matching the CLI report envelope.
2. Implement an `ExternalAnnotator` backed by `AnsedeCliService`.
3. Add an `IntentionAction` for safe `BEFORE:` / `AFTER:` replacements.
4. Add settings UI for executable path, min severity, and timeout.
5. Add UI tests using frozen CLI fixture payloads.
