using System.Collections.Generic;

namespace AnsedeStatic.VisualStudio;

internal sealed class AnsedeScannerService
{
    public IReadOnlyList<string> BuildCommand(string language)
    {
        return new[]
        {
            ResolveExecutable(),
            "--stdin",
            "--lang",
            language,
            "--format",
            "json",
            "--fail-on",
            "never",
            "--explain",
        };
    }

    public string ResolveExecutable()
    {
        return System.Environment.GetEnvironmentVariable("ANSEDE_EXECUTABLE") ?? "ansede-static";
    }
}
