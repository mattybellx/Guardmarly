import * as vscode from 'vscode';
import { execSync } from 'child_process';

let outputChannel: vscode.OutputChannel;

export function activate(context: vscode.ExtensionContext) {
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('guardmarly');
    context.subscriptions.push(diagnosticCollection);
    outputChannel = vscode.window.createOutputChannel('Guardmarly');
    context.subscriptions.push(outputChannel);

    // ── Resolve the guardmarly CLI command ──────────────────────────────────
    // Tries: direct guardmarly → python -m guardmarly.cli → python3 -m
    // Returns a tuple: [command_prefix, found: boolean, version: string]
    function resolveGuardmarly(): [string, boolean, string] {
        for (const candidate of ['guardmarly', 'python -m guardmarly.cli', 'python3 -m guardmarly.cli']) {
            try {
                const ver = execSync(`${candidate} --version`, {
                    encoding: 'utf-8',
                    timeout: 10000,
                    windowsHide: true
                }).trim();
                return [candidate, true, ver];
            } catch { /* try next */ }
        }
        return ['guardmarly', false, ''];
    }

    const [guardmarlyCmd, cmdFound, versionStr] = resolveGuardmarly();
    outputChannel.appendLine(`Guardmarly extension activated | cmd=${guardmarlyCmd} found=${cmdFound} version=${versionStr}`);

    // ── Status bar item ─────────────────────────────────────────────────────
    const statusBarItem = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Right, 100
    );
    statusBarItem.command = 'guardmarly.scan';
    statusBarItem.tooltip = cmdFound
        ? `Guardmarly ${versionStr} — click to scan active file`
        : 'Guardmarly: CLI not found — click for install instructions';
    statusBarItem.text = cmdFound ? '$(shield) Guardmarly' : '$(shield) Guardmarly $(warning)';
    statusBarItem.backgroundColor = cmdFound ? undefined : new vscode.ThemeColor('statusBarItem.warningBackground');
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    // ── Scan document ───────────────────────────────────────────────────────
    async function scanDocument(document: vscode.TextDocument) {
        if (!isSupportedLanguage(document.languageId)) return;
        if (!cmdFound) { return; }

        try {
            const cli = `${guardmarlyCmd} --stdin --lang ${mapLanguage(document.languageId)} --format json --fail-on never`;
            const result = execSync(cli, {
                input: document.getText(),
                encoding: 'utf-8',
                timeout: 30000,
                windowsHide: true
            });

            const findings = JSON.parse(result).results?.[0]?.findings || [];
            const diagnostics: vscode.Diagnostic[] = findings.map((f: any) => {
                const range = document.lineAt(Math.max(0, (f.line || 1) - 1)).range;
                const severity = mapSeverity(f.severity);
                const message = `[${f.cwe}] ${f.title}${f.suggestion ? '\n' + f.suggestion : ''}`;
                const diag = new vscode.Diagnostic(range, message, severity);
                diag.source = 'Guardmarly';
                diag.code = f.cwe;
                return diag;
            });

            diagnosticCollection.set(document.uri, diagnostics);
            updateStatusBar(document, diagnostics.length);
        } catch (e: any) {
            outputChannel.appendLine(`Scan error (${document.fileName}): ${e.message}`);
        }
    }

    // ── Status bar updates ──────────────────────────────────────────────────
    function updateStatusBar(document: vscode.TextDocument, findingCount: number) {
        if (!cmdFound) {
            statusBarItem.text = '$(shield) Guardmarly $(warning)';
            return;
        }
        const critical = vscode.languages.getDiagnostics(document.uri)
            .filter(d => d.severity === vscode.DiagnosticSeverity.Error).length;
        const high = vscode.languages.getDiagnostics(document.uri)
            .filter(d => d.severity === vscode.DiagnosticSeverity.Warning).length;

        if (critical > 0) {
            statusBarItem.text = `$(error) Guardmarly: ${critical}c/${high}h`;
            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        } else if (high > 0) {
            statusBarItem.text = `$(warning) Guardmarly: ${high} high`;
            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        } else if (findingCount === 0 && isSupportedLanguage(document.languageId)) {
            statusBarItem.text = '$(shield) Guardmarly: clean';
            statusBarItem.backgroundColor = undefined;
        } else {
            statusBarItem.text = '$(shield) Guardmarly';
            statusBarItem.backgroundColor = undefined;
        }
        statusBarItem.tooltip = cmdFound
            ? `Guardmarly ${versionStr}\nClick to rescan | Ctrl+Shift+P → Guardmarly`
            : 'Guardmarly: CLI not found';
    }

    // ── Event listeners ─────────────────────────────────────────────────────
    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument(scanDocument),
        vscode.workspace.onDidSaveTextDocument(scanDocument),
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor && isSupportedLanguage(editor.document.languageId)) {
                const diags = vscode.languages.getDiagnostics(editor.document.uri);
                updateStatusBar(editor.document, diags.length);
            } else {
                statusBarItem.text = '$(shield) Guardmarly';
                statusBarItem.backgroundColor = undefined;
            }
        })
    );

    // ── Commands ────────────────────────────────────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('guardmarly.scan', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) { return; }
            if (!cmdFound) {
                showInstallPrompt();
                return;
            }
            await scanDocument(editor.document);
            vscode.window.showInformationMessage(
                `Guardmarly: scanned ${editor.document.fileName.split(/[\\/]/).pop()}`
            );
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('guardmarly.scanWorkspace', async () => {
            const workspaceFolders = vscode.workspace.workspaceFolders;
            if (!workspaceFolders) { return; }
            if (!cmdFound) {
                showInstallPrompt();
                return;
            }

            outputChannel.show();
            outputChannel.appendLine(`Scanning workspace: ${workspaceFolders[0].uri.fsPath} ...`);

            try {
                const result = execSync(
                    `${guardmarlyCmd} "${workspaceFolders[0].uri.fsPath}" --format text --fail-on never`,
                    { encoding: 'utf-8', timeout: 120000, windowsHide: true }
                );
                outputChannel.appendLine(result);
                outputChannel.appendLine('Scan complete.');
            } catch (e: any) {
                // Show partial output on non-zero exit (findings cause exit 1)
                if (e.stdout) { outputChannel.appendLine(e.stdout); }
                if (e.stderr) { outputChannel.appendLine(e.stderr); }
                if (!e.stdout && !e.stderr) {
                    vscode.window.showErrorMessage(`Guardmarly scan failed: ${e.message}`);
                }
            }
        })
    );

    // ── Install prompt ──────────────────────────────────────────────────────
    function showInstallPrompt() {
        vscode.window.showWarningMessage(
            'Guardmarly CLI not found. Install it to enable security scanning.',
            'Install with pip',
            'View Docs'
        ).then(choice => {
            if (choice === 'Install with pip') {
                vscode.env.openExternal(
                    vscode.Uri.parse('https://pypi.org/project/guardmarly/')
                );
            } else if (choice === 'View Docs') {
                vscode.env.openExternal(
                    vscode.Uri.parse('https://github.com/mattybellx/Guardmarly#readme')
                );
            }
        });
    }

    // ── Initial scan ────────────────────────────────────────────────────────
    if (cmdFound) {
        vscode.workspace.textDocuments.forEach(scanDocument);
    } else if (vscode.workspace.textDocuments.some(d => isSupportedLanguage(d.languageId))) {
        // Delay the prompt slightly so the window is fully loaded
        setTimeout(() => showInstallPrompt(), 2000);
    }
}

function isSupportedLanguage(lang: string): boolean {
    return ['python', 'javascript', 'typescript', 'javascriptreact', 'typescriptreact', 'go', 'java', 'csharp'].includes(lang);
}

function mapLanguage(lang: string): string {
    const map: Record<string, string> = {
        python: 'python', javascript: 'javascript', typescript: 'javascript',
        javascriptreact: 'javascript', typescriptreact: 'javascript',
        go: 'go', java: 'java', csharp: 'csharp'
    };
    return map[lang] || 'python';
}

function mapSeverity(sev: string): vscode.DiagnosticSeverity {
    const map: Record<string, vscode.DiagnosticSeverity> = {
        critical: vscode.DiagnosticSeverity.Error,
        high: vscode.DiagnosticSeverity.Error,
        medium: vscode.DiagnosticSeverity.Warning,
        low: vscode.DiagnosticSeverity.Information,
        info: vscode.DiagnosticSeverity.Hint
    };
    return map[sev?.toLowerCase()] || vscode.DiagnosticSeverity.Warning;
}

export function deactivate() {}
