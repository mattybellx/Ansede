import * as vscode from 'vscode';
import { existsSync } from 'fs';
import { join } from 'path';

import { AnsedeFileResult, AnsedeFinding, countFindings } from './protocol';
import { runAnsedeScan } from './runner';


const SUPPORTED_LANGUAGE_SELECTORS: vscode.DocumentFilter[] = [
    { scheme: 'file', language: 'python' },
    { scheme: 'file', language: 'javascript' },
    { scheme: 'file', language: 'javascriptreact' },
    { scheme: 'file', language: 'typescript' },
    { scheme: 'file', language: 'typescriptreact' },
    { scheme: 'file', language: 'java' },
    { scheme: 'file', language: 'csharp' },
    { scheme: 'file', language: 'go' },
    { scheme: 'file', language: 'ruby' },
    { scheme: 'file', language: 'php' },
];


const SEVERITY_ORDER: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
};


function toDiagnosticSeverity(severity: string): vscode.DiagnosticSeverity {
    switch (severity) {
        case 'critical':
        case 'high':
            return vscode.DiagnosticSeverity.Error;
        case 'medium':
            return vscode.DiagnosticSeverity.Warning;
        default:
            return vscode.DiagnosticSeverity.Information;
    }
}


function getLanguage(document: vscode.TextDocument): string | null {
    switch (document.languageId) {
        case 'python':
            return 'python';
        case 'javascript':
        case 'javascriptreact':
        case 'typescript':
        case 'typescriptreact':
            return 'javascript';
        case 'java':
            return 'java';
        case 'csharp':
            return 'csharp';
        case 'go':
            return 'go';
        case 'ruby':
            return 'ruby';
        case 'php':
            return 'php';
        default:
            return null;
    }
}


function diagnosticRange(document: vscode.TextDocument, finding: AnsedeFinding): vscode.Range {
    const lineNo = Math.max((finding.line ?? 1) - 1, 0);
    const safeLine = Math.min(lineNo, Math.max(document.lineCount - 1, 0));
    const line = document.lineAt(safeLine);
    return new vscode.Range(
        safeLine,
        line.firstNonWhitespaceCharacterIndex,
        safeLine,
        line.range.end.character,
    );
}


function resolveExecutable(document: vscode.TextDocument, configuredExecutable: string): string {
    const trimmedExecutable = configuredExecutable.trim();
    if (trimmedExecutable && trimmedExecutable !== 'ansede-static') {
        return trimmedExecutable;
    }

    const folder = vscode.workspace.getWorkspaceFolder(document.uri);
    if (!folder) {
        return trimmedExecutable || 'ansede-static';
    }

    const candidates = process.platform === 'win32'
        ? [
            join(folder.uri.fsPath, '.venv', 'Scripts', 'ansede-static.exe'),
            join(folder.uri.fsPath, '.venv', 'Scripts', 'ansede-static.cmd'),
            join(folder.uri.fsPath, '.venv', 'Scripts', 'ansede-static'),
            join(folder.uri.fsPath, 'venv', 'Scripts', 'ansede-static.exe'),
            join(folder.uri.fsPath, 'venv', 'Scripts', 'ansede-static.cmd'),
        ]
        : [
            join(folder.uri.fsPath, '.venv', 'bin', 'ansede-static'),
            join(folder.uri.fsPath, 'venv', 'bin', 'ansede-static'),
        ];

    const discovered = candidates.find(candidate => existsSync(candidate));
    return discovered ?? (trimmedExecutable || 'ansede-static');
}


function isMissingExecutableError(error: unknown): boolean {
    if (!(error instanceof Error)) {
        return false;
    }
    return /executable not found|ENOENT|spawn .* ansede-static/i.test(error.message);
}


class AnsedeDiagnostic extends vscode.Diagnostic {
    finding: AnsedeFinding;

    constructor(range: vscode.Range, message: string, severity: vscode.DiagnosticSeverity, finding: AnsedeFinding) {
        super(range, message, severity);
        this.finding = finding;
    }
}


function buildHoverMarkdown(finding: AnsedeFinding): vscode.MarkdownString {
    const markdown = new vscode.MarkdownString(undefined, true);
    markdown.isTrusted = false;
    markdown.appendMarkdown(`**${finding.title}**\n\n`);
    if (finding.rule_id || finding.cwe) {
        const tokens = [finding.rule_id, finding.cwe].filter(Boolean).join(' · ');
        markdown.appendMarkdown(`$(shield) \`${tokens}\`\n\n`);
    }
    markdown.appendMarkdown(`**Severity:** ${finding.severity}`);
    if (finding.analysis_kind) {
        markdown.appendMarkdown(`  \n**Analysis:** ${finding.analysis_kind}`);
    }
    if (typeof finding.confidence === 'number') {
        markdown.appendMarkdown(`  \n**Confidence:** ${finding.confidence.toFixed(2)}`);
    }
    if (finding.description) {
        markdown.appendMarkdown(`\n\n${finding.description}`);
    }
    if (finding.explanation) {
        markdown.appendMarkdown(`\n\n---\n\n${finding.explanation}`);
    }
    if (finding.suggestion) {
        markdown.appendMarkdown(`\n\n**Suggested fix**  \n${finding.suggestion}`);
    }
    if (finding.auto_fix) {
        markdown.appendMarkdown('\n\n**Auto-fix snippet**\n');
        markdown.appendCodeblock(finding.auto_fix, 'text');
    }
    return markdown;
}


class AnsedeHoverProvider implements vscode.HoverProvider {
    constructor(private readonly collection: vscode.DiagnosticCollection) {}

    provideHover(document: vscode.TextDocument, position: vscode.Position): vscode.ProviderResult<vscode.Hover> {
        const diagnostics = this.collection.get(document.uri) ?? [];
        const matching = diagnostics.filter(diagnostic =>
            diagnostic.source === 'ansede-static'
            && diagnostic.range.contains(position)
            && (diagnostic as AnsedeDiagnostic).finding,
        ) as AnsedeDiagnostic[];
        if (matching.length === 0) {
            return null;
        }
        return new vscode.Hover(matching.map(diagnostic => buildHoverMarkdown(diagnostic.finding)));
    }
}

function parseErrorDiagnostic(message: string): vscode.Diagnostic {
    const range = new vscode.Range(new vscode.Position(0, 0), new vscode.Position(0, 0));
    const diagnostic = new vscode.Diagnostic(range, message, vscode.DiagnosticSeverity.Warning);
    diagnostic.source = 'ansede-static';
    return diagnostic;
}


function pushFindingDiagnostics(
    document: vscode.TextDocument,
    result: AnsedeFileResult,
    minOrder: number,
    diagnostics: vscode.Diagnostic[],
): void {
    if (result.parse_error) {
        diagnostics.push(parseErrorDiagnostic(result.parse_error));
    }

    for (const finding of result.findings) {
        const order = SEVERITY_ORDER[finding.severity] ?? SEVERITY_ORDER.info;
        if (order > minOrder) {
            continue;
        }

        const parts: string[] = [finding.title];
        if (finding.description) {
            parts.push(finding.description);
        }
        if (finding.suggestion) {
            parts.push(`Fix: ${finding.suggestion}`);
        }
        if (finding.auto_fix) {
            parts.push(`\n${finding.auto_fix}`);
        }
        if (finding.rule_id) {
            parts.push(`Rule: ${finding.rule_id}`);
        }
        if (finding.analysis_kind) {
            parts.push(`Analysis: ${finding.analysis_kind}`);
        }
            if (typeof finding.confidence === 'number') {
                parts.push(`Confidence: ${finding.confidence.toFixed(2)}`);
            }

        const diagnostic = new AnsedeDiagnostic(
            diagnosticRange(document, finding),
            parts.join('\n\n'),
            toDiagnosticSeverity(finding.severity),
            finding,
        );
        diagnostic.source = 'ansede-static';
        const codeValue = finding.rule_id ?? finding.cwe;
        if (codeValue) {
            diagnostic.code = finding.cwe
                ? {
                    value: codeValue,
                    target: vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${finding.cwe.replace('CWE-', '')}.html`),
                }
                : codeValue;
        }
        diagnostics.push(diagnostic);
    }
}


async function scanDocument(
    document: vscode.TextDocument,
    collection: vscode.DiagnosticCollection,
    statusItem: vscode.StatusBarItem,
    options?: {
        expectedVersion?: number;
        onMissingExecutable?: () => void;
    },
): Promise<boolean> {
    const config = vscode.workspace.getConfiguration('ansede');
    if (!config.get<boolean>('enable', true)) {
        collection.delete(document.uri);
        statusItem.hide();
        return false;
    }

    const language = getLanguage(document);
    if (!language) {
        return false;
    }

    const minSeverity = config.get<string>('minSeverity', 'medium');
    const minOrder = SEVERITY_ORDER[minSeverity] ?? SEVERITY_ORDER.medium;
    const executable = resolveExecutable(document, config.get<string>('executable', 'ansede-static'));
    const timeoutMs = Math.max(config.get<number>('scanTimeoutMs', 15_000) ?? 15_000, 1_000);

    statusItem.text = '$(shield~spin) Ansede scanning...';
    statusItem.tooltip = 'Ansede Static Security Scanner';
    statusItem.show();

    try {
        const report = await runAnsedeScan({
            executable,
            language,
            code: document.getText(),
            timeoutMs,
        });

        const openDocument = vscode.workspace.textDocuments.find(candidate => candidate.uri.toString() === document.uri.toString());
        if (typeof options?.expectedVersion === 'number' && openDocument && openDocument.version !== options.expectedVersion) {
            return false;
        }

        const diagnostics: vscode.Diagnostic[] = [];
        for (const result of report.results) {
            pushFindingDiagnostics(document, result, minOrder, diagnostics);
        }
        collection.set(document.uri, diagnostics);

        const errorCount = diagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Error).length;
        const warningCount = diagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Warning).length;
        const totalFindings = countFindings(report);

        if (errorCount + warningCount === 0) {
            statusItem.text = totalFindings === 0 ? '$(shield) Ansede: clean' : '$(shield) Ansede: informational';
        } else {
            statusItem.text = `$(shield) Ansede: ${errorCount}E ${warningCount}W`;
        }
        statusItem.tooltip = `Ansede Static Security Scanner — ${totalFindings} finding(s) in latest scan`;
        statusItem.show();
        return true;
    } catch (error) {
        collection.delete(document.uri);
        if (isMissingExecutableError(error)) {
            options?.onMissingExecutable?.();
            statusItem.text = '$(shield) Ansede: executable not found';
            statusItem.tooltip = 'Install ansede-static in your workspace environment or set ansede.executable.';
        } else {
            statusItem.text = '$(shield) Ansede: scan failed';
            statusItem.tooltip = error instanceof Error ? error.message : 'Ansede scan failed';
        }
        statusItem.show();
        return false;
    }
}


class AnsedeCodeActionProvider implements vscode.CodeActionProvider {
    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): vscode.ProviderResult<(vscode.CodeAction | vscode.Command)[]> {
        const actions: vscode.CodeAction[] = [];

        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source === 'ansede-static' && (diagnostic as AnsedeDiagnostic).finding) {
                const finding = (diagnostic as AnsedeDiagnostic).finding;

                // ── Quick Fix: auto_fix snippet ───────────────────────────
                if (finding.auto_fix && finding.auto_fix.includes('BEFORE:') && finding.auto_fix.includes('AFTER:')) {
                    const parts = finding.auto_fix.split("AFTER:");
                    const afterLines = parts[1].trimEnd().split('\n');
                    const after = afterLines.map(line => line.replace(/^ {8}/, '    ')).join('\n').replace(/^\n\s*/, '');

                    const action = new vscode.CodeAction(
                        `Ansede Fix: ${finding.suggestion || "Apply security fix"}`,
                        vscode.CodeActionKind.QuickFix
                    );
                    action.diagnostics = [diagnostic];
                    action.isPreferred = true;
                    
                    const edit = new vscode.WorkspaceEdit();
                    
                    if (finding.line) {
                        const lineIdx = finding.line - 1;
                        if (lineIdx >= 0 && lineIdx < document.lineCount) {
                            const textLine = document.lineAt(lineIdx);
                            const startPos = new vscode.Position(lineIdx, 0);
                            const endPos = new vscode.Position(lineIdx, textLine.text.length);
                            edit.replace(document.uri, new vscode.Range(startPos, endPos), after);
                        }
                    } else {
                        edit.replace(document.uri, diagnostic.range, after);
                    }
                    
                    action.edit = edit;
                    actions.push(action);
                }

                // ── Suppress: add inline suppression comment ──────────────
                const ruleId = finding.rule_id || finding.cwe;
                if (ruleId) {
                    const suppressAction = new vscode.CodeAction(
                        `Ansede Suppress: ${ruleId}`,
                        vscode.CodeActionKind.QuickFix
                    );
                    suppressAction.diagnostics = [diagnostic];
                    const cweMatch = ruleId.match(/CWE-(\d+)/);
                    const suppressToken = cweMatch ? `CWE-${cweMatch[1]}` : ruleId;
                    const edit = new vscode.WorkspaceEdit();
                    const lineIdx = (finding.line ?? 1) - 1;
                    if (lineIdx >= 0 && lineIdx < document.lineCount) {
                        const textLine = document.lineAt(lineIdx);
                        edit.insert(
                            document.uri,
                            new vscode.Position(lineIdx, textLine.text.length),
                            ` // ansede: ignore[${suppressToken}]`
                        );
                    }
                    suppressAction.edit = edit;
                    actions.push(suppressAction);

                    // ── Explain: show detailed vulnerability info ──────────
                    const explainAction = new vscode.CodeAction(
                        `Ansede Explain: ${finding.title}`,
                        vscode.CodeActionKind.Empty
                    );
                    explainAction.diagnostics = [diagnostic];
                    explainAction.command = {
                        command: 'ansede.showExplanation',
                        title: 'Show Ansede Explanation',
                        arguments: [finding],
                    };
                    actions.push(explainAction);
                }
            }
        }

        return actions;
    }
}


export function activate(context: vscode.ExtensionContext): void {
    const collection = vscode.languages.createDiagnosticCollection('ansede');
    const statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusItem.tooltip = 'Ansede Static Security Scanner';
    statusItem.command = 'ansede.scanCurrentFile';

    const pendingScans = new Map<string, ReturnType<typeof setTimeout>>();
    let missingExecutableWarningShown = false;

    const notifyMissingExecutable = (): void => {
        if (missingExecutableWarningShown) {
            return;
        }
        missingExecutableWarningShown = true;
        void vscode.window.showWarningMessage(
            'Ansede could not find the ansede-static executable. Install it in your workspace virtualenv or set ansede.executable.',
            'Open Settings'
        ).then(selection => {
            if (selection === 'Open Settings') {
                void vscode.commands.executeCommand('workbench.action.openSettings', 'ansede.executable');
            }
        });
    };

    const scan = (document: vscode.TextDocument, expectedVersion = document.version): Promise<void> => scanDocument(
        document,
        collection,
        statusItem,
        {
            expectedVersion,
            onMissingExecutable: notifyMissingExecutable,
        },
    ).then(succeeded => {
        if (succeeded) {
            missingExecutableWarningShown = false;
        }
    }).catch(() => {
        // scanDocument handles status updates; the catch keeps the promise chain quiet for event handlers.
    });

    const scheduleTypeScan = (document: vscode.TextDocument): void => {
        if (!vscode.workspace.getConfiguration('ansede').get<boolean>('scanOnType', true)) {
            return;
        }
        if (!getLanguage(document)) {
            return;
        }
        const key = document.uri.toString();
        const existing = pendingScans.get(key);
        if (existing) {
            clearTimeout(existing);
        }
        pendingScans.set(key, setTimeout(() => {
            pendingScans.delete(key);
            void scan(document, document.version);
        }, 500));
    };

    if (vscode.window.activeTextEditor) {
        void scan(vscode.window.activeTextEditor.document, vscode.window.activeTextEditor.document.version);
    }

    // ── Gutter decoration types ──────────────────────────────────────────
    const errorDecoration = vscode.window.createTextEditorDecorationType({
        gutterIconPath: context.asAbsolutePath('images/error.svg'),
        gutterIconSize: 'contain',
    });
    const warningDecoration = vscode.window.createTextEditorDecorationType({
        gutterIconPath: context.asAbsolutePath('images/warning.svg'),
        gutterIconSize: 'contain',
    });

    // ── Command: Show explanation in a WebView panel ─────────────────────
    const showExplanationCmd = vscode.commands.registerCommand('ansede.showExplanation', (finding: AnsedeFinding) => {
        const panel = vscode.window.createWebviewPanel(
            'ansedeExplanation',
            `Ansede: ${finding.title}`,
            vscode.ViewColumn.Beside,
            { enableScripts: false }
        );
        const cweLink = finding.cwe
            ? `<a href="https://cwe.mitre.org/data/definitions/${finding.cwe.replace('CWE-', '')}.html">${finding.cwe}</a>`
            : '';
        const severityClass = (finding.severity || 'info').toLowerCase();
        panel.webview.html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Ansede Explanation</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 1em; line-height: 1.6; color: var(--vscode-editor-foreground, #333); background: var(--vscode-editor-background, #fff); }
h1 { font-size: 1.4em; border-bottom: 1px solid var(--vscode-panel-border, #ccc); padding-bottom: 0.3em; }
.severity-badge { display: inline-block; padding: 2px 10px; border-radius: 3px; font-weight: 600; font-size: 0.85em; text-transform: uppercase; }
.severity-badge.critical { background: #c00; color: #fff; }
.severity-badge.high { background: #e60; color: #fff; }
.severity-badge.medium { background: #ea0; color: #000; }
.severity-badge.low { background: #6a6; color: #fff; }
.severity-badge.info { background: #66a; color: #fff; }
.meta { color: var(--vscode-descriptionForeground, #888); font-size: 0.85em; margin: 0.5em 0; }
.description { margin: 1em 0; }
.suggestion { background: var(--vscode-textBlockQuote-background, #f0f0f0); padding: 0.5em 1em; border-radius: 4px; margin-top: 1em; }
</style>
</head>
<body>
<h1>${finding.title}</h1>
<div class="meta">
    ${finding.rule_id ? `<span><strong>Rule:</strong> ${finding.rule_id}</span>` : ''}
    ${cweLink ? ` | <span>${cweLink}</span>` : ''}
</div>
<p><span class="severity-badge ${severityClass}">${severityClass}</span></p>
${finding.description ? `<p class="description">${finding.description}</p>` : ''}
${finding.explanation ? `<p>${finding.explanation}</p>` : ''}
${finding.suggestion ? `<div class="suggestion"><strong>Suggestion:</strong><p>${finding.suggestion}</p></div>` : ''}
</body>
</html>`;
    });

    // ── Gutter decoration updater ────────────────────────────────────────
    const updateGutterDecorations = (editor: vscode.TextEditor | undefined) => {
        if (!editor) { return; }
        const diagnostics = collection.get(editor.document.uri) ?? [];
        const errorLines: vscode.Range[] = [];
        const warningLines: vscode.Range[] = [];
        for (const d of diagnostics) {
            if (d.source !== 'ansede-static') { continue; }
            const lineRange = editor.document.validateRange(
                new vscode.Range(d.range.start.line, 0, d.range.start.line, 0)
            );
            if (d.severity === vscode.DiagnosticSeverity.Error) {
                errorLines.push(lineRange);
            } else if (d.severity === vscode.DiagnosticSeverity.Warning) {
                warningLines.push(lineRange);
            }
        }
        editor.setDecorations(errorDecoration, errorLines);
        editor.setDecorations(warningDecoration, warningLines);
    };

    // Refresh gutter decorations when diagnostics change
    vscode.languages.onDidChangeDiagnostics(() => {
        updateGutterDecorations(vscode.window.activeTextEditor);
    });

    context.subscriptions.push(
        collection,
        statusItem,
        showExplanationCmd,
        vscode.languages.registerCodeActionsProvider(
            SUPPORTED_LANGUAGE_SELECTORS,
            new AnsedeCodeActionProvider(),
            { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
        ),
        vscode.languages.registerHoverProvider(
            SUPPORTED_LANGUAGE_SELECTORS,
            new AnsedeHoverProvider(collection),
        ),
        vscode.workspace.onDidOpenTextDocument(document => {
            void scan(document, document.version);
        }),
        vscode.workspace.onDidChangeTextDocument(event => {
            scheduleTypeScan(event.document);
        }),
        vscode.workspace.onDidSaveTextDocument(document => {
            if (vscode.workspace.getConfiguration('ansede').get<boolean>('scanOnSave', true)) {
                void scan(document, document.version);
            }
        }),
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor && vscode.workspace.getConfiguration('ansede').get<boolean>('scanOnOpen', true)) {
                void scan(editor.document, editor.document.version);
            }
        }),
        vscode.commands.registerCommand('ansede.scanCurrentFile', () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                void scan(editor.document, editor.document.version);
            }
        }),
        vscode.commands.registerCommand('ansede.scanWorkspace', async () => {
            const folders = vscode.workspace.workspaceFolders;
            if (!folders) {
                return;
            }
            for (const folder of folders) {
                const discoveredUris: vscode.Uri[] = [];
                for (const pattern of ['**/*.py', '**/*.js', '**/*.jsx', '**/*.ts', '**/*.tsx', '**/*.java', '**/*.cs', '**/*.go']) {
                    const files = await vscode.workspace.findFiles(
                        new vscode.RelativePattern(folder, pattern),
                        '**/{node_modules,.venv,dist,build,__pycache__}/**',
                    );
                    discoveredUris.push(...files);
                }
                const uniqueUris = [...new Map(discoveredUris.map(uri => [uri.toString(), uri])).values()];
                for (const uri of uniqueUris) {
                    const document = await vscode.workspace.openTextDocument(uri);
                    await scan(document, document.version);
                }
            }
            void vscode.window.showInformationMessage('Ansede: workspace scan complete. Check Problems panel.');
        }),
        new vscode.Disposable(() => {
            for (const timer of pendingScans.values()) {
                clearTimeout(timer);
            }
            pendingScans.clear();
        }),
    );
}


export function deactivate(): void {}
