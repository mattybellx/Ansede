using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.Text;
using Microsoft.VisualStudio.Text.Adornments;
using Microsoft.VisualStudio.Text.Tagging;
using Microsoft.VisualStudio.Threading;

namespace AnsedeStatic.VisualStudio
{
    /// <summary>
    /// Provides error squiggles (inline annotations) in the VS editor
    /// for findings detected by ansede-static.
    /// </summary>
    internal sealed class AnsedeTagger : ITagger<IErrorTag>
    {
        private readonly ITextBuffer _buffer;
        private readonly AnsedeScannerService _scanner;
        private readonly JoinableTaskFactory _jtf;
        private List<Finding> _findings = new();

        public AnsedeTagger(ITextBuffer buffer, AnsedeScannerService scanner, JoinableTaskFactory jtf)
        {
            _buffer = buffer;
            _scanner = scanner;
            _jtf = jtf;
        }

        public event EventHandler<SnapshotSpanEventArgs>? TagsChanged;

        public IEnumerable<ITagSpan<IErrorTag>> GetTags(NormalizedSnapshotSpanCollection spans)
        {
            if (_findings.Count == 0)
                yield break;

            var snapshot = _buffer.CurrentSnapshot;
            foreach (var finding in _findings)
            {
                if (finding.Line < 1 || finding.Line > snapshot.LineCount)
                    continue;

                var line = snapshot.GetLineFromLineNumber(finding.Line - 1);
                var span = new SnapshotSpan(snapshot, line.Start, line.Length);

                var tagType = (finding.Severity ?? "").ToLowerInvariant() switch
                {
                    "critical" or "high" => PredefinedErrorTypeNames.OtherError,
                    "medium" => PredefinedErrorTypeNames.Warning,
                    _ => PredefinedErrorTypeNames.Suggestion,
                };

                yield return new TagSpan<IErrorTag>(
                    span,
                    new ErrorTag(tagType, $"[{finding.RuleId}] {finding.Title}")
                );
            }
        }

        public void RefreshFindings(List<Finding> findings)
        {
            _findings = findings ?? new List<Finding>();

            _ = _jtf.RunAsync(async () =>
            {
                await _jtf.SwitchToMainThreadAsync();
                var snapshot = _buffer.CurrentSnapshot;
                TagsChanged?.Invoke(this, new SnapshotSpanEventArgs(
                    new SnapshotSpan(snapshot, 0, snapshot.Length)));
            });
        }
    }

    /// <summary>
    /// Creates <see cref="AnsedeTagger"/> instances for text buffers
    /// that contain supported source code.
    /// </summary>
    internal sealed class AnsedeTaggerProvider : ITaggerProvider
    {
        private readonly AnsedeScannerService _scanner;
        private readonly JoinableTaskFactory _jtf;

        public AnsedeTaggerProvider(AnsedeScannerService scanner, JoinableTaskFactory jtf)
        {
            _scanner = scanner;
            _jtf = jtf;
        }

        public ITagger<T>? CreateTagger<T>(ITextBuffer buffer) where T : ITag
        {
            if (typeof(T) != typeof(IErrorTag))
                return null;

            if (!IsSupported(buffer))
                return null;

            var tagger = new AnsedeTagger(buffer, _scanner, _jtf);
            return tagger as ITagger<T>;
        }

        private static bool IsSupported(ITextBuffer buffer)
        {
            if (!buffer.Properties.TryGetProperty(typeof(ITextDocument), out ITextDocument doc))
                return false;
            var ext = System.IO.Path.GetExtension(doc.FilePath)?.ToLowerInvariant() ?? "";
            return _supportedExtensions.Contains(ext);
        }

        private static readonly HashSet<string> _supportedExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".cs", ".go", ".rb", ".php"
        };
    }
}
