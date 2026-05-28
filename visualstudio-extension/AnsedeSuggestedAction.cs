using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.Imaging;
using Microsoft.VisualStudio.Imaging.Interop;
using Microsoft.VisualStudio.Language.Intellisense;
using Microsoft.VisualStudio.Text;
using Microsoft.VisualStudio.Text.Editor;
using Microsoft.VisualStudio.Threading;
using Microsoft.VisualStudio.Telemetry;

namespace AnsedeStatic.VisualStudio
{
    /// <summary>
    /// A suggested action (lightbulb) that lets users suppress an ansede
    /// finding by inserting an inline suppression comment.
    /// </summary>
    internal sealed class AnsedeSuppressSuggestedAction : ISuggestedAction
    {
        private readonly string _ruleId;
        private readonly int _line;
        private readonly ITextBuffer _buffer;

        public AnsedeSuppressSuggestedAction(string ruleId, int line, ITextBuffer buffer)
        {
            _ruleId = ruleId;
            _line = line;
            _buffer = buffer;
        }

        public string DisplayText => $"Suppress ansede: {_ruleId}";

        public string? IconAutomationText => null;

        public ImageMoniker IconMoniker => default;

        public string? InputGestureText => null;

        public bool HasActionSets => false;

        public bool HasPreview => false;

        public Task<object?> GetPreviewAsync(CancellationToken cancellationToken)
            => Task.FromResult<object?>(null);

        public Task<IEnumerable<SuggestedActionSet>> GetActionSetsAsync(CancellationToken cancellationToken)
            => Task.FromResult(Enumerable.Empty<SuggestedActionSet>());

        public void Dispose() { }

        public void Invoke(CancellationToken cancellationToken) { }

        public async Task InvokeAsync(CancellationToken cancellationToken)
        {
            var snapshot = _buffer.CurrentSnapshot;
            if (_line < 1 || _line > snapshot.LineCount)
                return;

            var line = snapshot.GetLineFromLineNumber(_line - 1);
            var text = line.GetText();

            var comment = GetCommentPrefix(text);

            using var edit = _buffer.CreateEdit();
            edit.Insert(line.End.Position, $" {comment} ansede: ignore {_ruleId}");
            edit.Apply();
        }

        public bool TryGetTelemetry(out KeyValuePair<string, object>? telemetry)
        {
            telemetry = new KeyValuePair<string, object>("ansede.suppress", _ruleId);
            return true;
        }

        public bool TryGetTelemetryId(out Guid telemetryId)
        {
            telemetryId = Guid.Empty;
            return false;
        }

        private static string GetCommentPrefix(string lineText)
        {
            var trimmed = lineText.TrimStart();
            if (trimmed.StartsWith("//") || trimmed.StartsWith("/*"))
                return "//";
            if (trimmed.StartsWith("#"))
                return "#";
            if (trimmed.StartsWith("--"))
                return "--";
            return "//";
        }
    }

    /// <summary>
    /// Source of suggested actions for ansede findings, registered
    /// as an <see cref="ISuggestedActionsSource"/>.
    /// </summary>
    internal sealed class AnsedeSuggestedActionSource : ISuggestedActionsSource
    {
        private readonly ITextView _textView;
        private readonly ITextBuffer _buffer;
        private readonly AnsedeScannerService _scanner;

        public AnsedeSuggestedActionSource(ITextView textView, ITextBuffer buffer, AnsedeScannerService scanner)
        {
            _textView = textView;
            _buffer = buffer;
            _scanner = scanner;
        }

        public event EventHandler<EventArgs>? SuggestedActionsChanged;

        public void Dispose() { }

        public IEnumerable<SuggestedActionSet> GetSuggestedActions(ISuggestedActionCategorySet requestedActionCategories,
            SnapshotSpan range, CancellationToken cancellationToken)
        {
            var line = range.Start.GetContainingLine();
            var lineNumber = line.LineNumber + 1;

            var findings = GetFindingsAtLine(lineNumber, cancellationToken);
            if (findings.Count == 0)
                return Enumerable.Empty<SuggestedActionSet>();

            var actions = findings.Select(f => (ISuggestedAction)new AnsedeSuppressSuggestedAction(f.RuleId, lineNumber, _buffer)).ToList();

            return new[] { new SuggestedActionSet(actions, "Ansede Static") };
        }

        public Task<bool> HasSuggestedActionsAsync(ISuggestedActionCategorySet requestedActionCategories,
            SnapshotSpan range, CancellationToken cancellationToken)
        {
            var line = range.Start.GetContainingLine();
            var lineNumber = line.LineNumber + 1;
            var findings = GetFindingsAtLine(lineNumber, cancellationToken);
            return Task.FromResult(findings.Count > 0);
        }

        private List<FindingInfo> GetFindingsAtLine(int lineNumber, CancellationToken ct)
        {
            if (_buffer.Properties.TryGetProperty(typeof(AnsedeTagger), out AnsedeTagger tagger))
            {
                return new List<FindingInfo>();
            }
            return new List<FindingInfo>();
        }

        public bool TryGetTelemetryId(out Guid telemetryId)
        {
            telemetryId = Guid.Empty;
            return false;
        }
    }

    internal sealed class FindingInfo
    {
        public string RuleId { get; set; } = "";
        public string Cwe { get; set; } = "";
        public string Title { get; set; } = "";
        public int Line { get; set; }
    }
}
