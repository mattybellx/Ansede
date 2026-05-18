# Ansede Static — IntelliJ IDEA Plugin

Fully implemented engine bridge. Compile, install, and scan from your IDE.

## How to Compile & Install

### Prerequisites
- JDK 17+ (`winget install EclipseAdoptium.Temurin.17.JDK` on Windows)
- Gradle (bundled via gradlew — no install needed)

### Build
```bash
cd intellij-plugin
./gradlew buildPlugin        # macOS/Linux
gradlew.bat buildPlugin      # Windows

# Output: build/distributions/ansede-static-intellij-0.1.0.zip
```

### Install in IntelliJ
1. Open IntelliJ IDEA → **Settings** → **Plugins** → ⚙️ → **Install Plugin from Disk…**
2. Select the `.zip` from `build/distributions/`
3. Restart IntelliJ

### Usage
- **Tools → Scan Current File with Ansede** (or `Ctrl+Alt+S`)
- The Ansede tool window opens on the right with severity-colored findings
- Click any finding to see description, remediation, and auto-fix suggestions

### What's Implemented
- **AnsedeCliService**: CLI execution, JSON parsing (v2 format + flat array fallback), stdin & file-path modes
- **ScanCurrentFileAction**: Progress-bar background scan, unsaved-buffer detection, multi-language support
- **FindingsPanel**: Sortable severity table (critical→low), detail pane with remediation, auto-fix display
- **AnsedeToolWindowFactory**: Idle instructions when no scan is active
- **Keyboard shortcut**: `Ctrl+Alt+S` from any editor

### Edge Cases Handled
- ANSEDE_EXECUTABLE env var for custom CLI paths
- Automatic OS detection for default executable location
- 30-second scan timeout
- Language mapping for Python/JS/TS/JSX/Java/C#/Go/PHP/Ruby
- Graceful error handling (CLI not found, parse failures, timeout)
