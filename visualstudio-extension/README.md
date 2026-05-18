# Ansede Static — Visual Studio Extension

Fully implemented scanner bridge. Compile and install for VS 2022.

## How to Compile & Install

### Prerequisites
- Visual Studio 2022 with ".NET desktop development" workload
- VS SDK (included with the workload above)

### Build
```bash
# From Developer Command Prompt for VS 2022:
cd visualstudio-extension
msbuild AnsedeStatic.VisualStudio.csproj /p:Configuration=Release

# Or open AnsedeStatic.VisualStudio.csproj in VS and Build → Build Solution
# Output: bin/Release/AnsedeStatic.VisualStudio.vsix
```

### Install
1. Double-click the `.vsix` file
2. Click **Install**
3. Restart Visual Studio

### Usage
- Open any Python, JS, TS, Java, C#, or Go file
- **Tools → Scan Current File with Ansede**
- Results appear in the **Ansede Static** output pane with severity, CWE, line numbers, and remediation

### What's Implemented
- **AnsedeScannerService**: Process execution, JSON deserialization (`System.Text.Json`), stdin & file-path dual mode, 30s timeout
- **AnsedePackage**: AsyncPackage with menu command registration, DTE integration, output pane formatting
- **Language detection**: Auto-maps VS language IDs to ansede-static `--lang` values
- **Unsaved buffer support**: Pipes editor text directly when file is modified

### Edge Cases Handled
- ANSEDE_EXECUTABLE env var for custom CLI paths
- Auto-detection of Windows default path (`%LOCALAPPDATA%\ansede\ansede-static.exe`)
- Graceful "CLI not found" messaging
- JSON parse fallback (v2 object format → flat array)
