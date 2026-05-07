using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.Shell;

namespace AnsedeStatic.VisualStudio;

[PackageRegistration(UseManagedResourcesOnly = true, AllowsBackgroundLoading = true)]
[Guid(PackageGuidString)]
public sealed class AnsedePackage : AsyncPackage
{
    public const string PackageGuidString = "4f7284d2-6b7e-4eab-9517-b0e4f7b80c6d";

    protected override Task InitializeAsync(CancellationToken cancellationToken, IProgress<ServiceProgressData> progress)
    {
        return Task.CompletedTask;
    }
}
