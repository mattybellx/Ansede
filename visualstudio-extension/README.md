# Ansede Visual Studio scaffold

This directory contains the initial Visual Studio extension scaffold for Ansede Static.

## intended feature parity

- inline diagnostics from `ansede-static --format json --explain`
- hover / quick info with CWE, remediation, and explanation text
- quick fixes for safe `BEFORE:` / `AFTER:` edits
- command-driven current-file and workspace scans
- settings for executable path, severity floor, and scan triggers

## next implementation steps

1. Add an editor listener that scans the current buffer on open/save.
2. Parse JSON findings into Visual Studio error tags and Error List entries.
3. Add a quick-fix command for safe inline `auto_fix` replacements.
4. Add an options page for executable path and scan timeout.
5. Add integration tests using fixed JSON fixture payloads.
