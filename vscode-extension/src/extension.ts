import * as vscode from 'vscode';
import { execSync } from 'child_process';

let outputChannel: vscode.OutputChannel;

export function activate(context: vscode.ExtensionContext) {
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('guardmarly');
    context.subscriptions.push(diagnosticCollection);
    outputChannel = vscode.window.createOutputChannel('Guardmarly');
    context.subscriptions.push(outputChannel);

    // ── Gutter decorations ──────────────────────────────────────────────────
    const gutterCritical = vscode.window.createTextEditorDecorationType({
        gutterIconPath: createColoredIconPath(context, '#e53e3e'), // red
        gutterIconSize: 'contain',
        overviewRulerColor: '#e53e3e',
        overviewRulerLane: vscode.OverviewRulerLane.Left,
    });
    const gutterHigh = vscode.window.createTextEditorDecorationType({
        gutterIconPath: createColoredIconPath(context, '#ed8936'), // orange
        gutterIconSize: 'contain',
        overviewRulerColor: '#ed8936',
        overviewRulerLane: vscode.OverviewRulerLane.Left,
    });
    const gutterMedium = vscode.window.createTextEditorDecorationType({
        gutterIconPath: createColoredIconPath(context, '#d69e2e'), // yellow
        gutterIconSize: 'contain',
        overviewRulerColor: '#d69e2e',
        overviewRulerLane: vscode.OverviewRulerLane.Left,
    });
    context.subscriptions.push(gutterCritical, gutterHigh, gutterMedium);

    // ── Resolve the guardmarly CLI command ──────────────────────────────────
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

    // ── Store latest findings for quick-pick ────────────────────────────────
    let latestFindings: any[] = [];

    // ── Status bar item ─────────────────────────────────────────────────────
    const statusBarItem = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Right, 100
    );
    statusBarItem.command = 'guardmarly.showFindings';
    statusBarItem.tooltip = cmdFound
        ? `Guardmarly ${versionStr} — click to view findings`
        : 'Guardmarly: CLI not found — click for install instructions';
    statusBarItem.text = cmdFound ? '$(shield) Guardmarly' : '$(shield) Guardmarly $(warning)';
    statusBarItem.backgroundColor = cmdFound ? undefined : new vscode.ThemeColor('statusBarItem.warningBackground');
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    let scanning = false;

    // ── Scan document ───────────────────────────────────────────────────────
    async function scanDocument(document: vscode.TextDocument) {
        if (!isSupportedLanguage(document.languageId)) return;
        if (!cmdFound) { return; }

        // Animated spinner
        scanning = true;
        let spinFrames = ['$(sync~spin)', '$(loading~spin)', '$(gear~spin)'];
        let spinIdx = 0;
        const spinInterval = setInterval(() => {
            if (scanning) {
                statusBarItem.text = `${spinFrames[spinIdx % spinFrames.length]} Guardmarly`;
                spinIdx++;
            }
        }, 150);
        context.subscriptions.push({ dispose: () => clearInterval(spinInterval) });

        try {
            const cli = `${guardmarlyCmd} --stdin --lang ${mapLanguage(document.languageId)} --format json --fail-on never`;
            const result = execSync(cli, {
                input: document.getText(),
                encoding: 'utf-8',
                timeout: 30000,
                windowsHide: true
            });

            scanning = false;
            clearInterval(spinInterval);

            latestFindings = JSON.parse(result).results?.[0]?.findings || [];
            const diagnostics: vscode.Diagnostic[] = latestFindings.map((f: any) => {
                const range = document.lineAt(Math.max(0, (f.line || 1) - 1)).range;
                const severity = mapSeverity(f.severity);
                const message = `[${f.cwe}] ${f.title}${f.suggestion ? '\n💡 ' + f.suggestion : ''}`;
                const diag = new vscode.Diagnostic(range, message, severity);
                diag.source = 'Guardmarly';
                diag.code = f.cwe;
                return diag;
            });

            diagnosticCollection.set(document.uri, diagnostics);
            updateGutterDecorations(document, latestFindings);
            updateStatusBar(document, diagnostics.length);
        } catch (e: any) {
            scanning = false;
            clearInterval(spinInterval);
            outputChannel.appendLine(`Scan error (${document.fileName}): ${e.message}`);
        }
    }

    // ── Gutter decorations ──────────────────────────────────────────────────
    function updateGutterDecorations(document: vscode.TextDocument, findings: any[]) {
        const editor = vscode.window.activeTextEditor;
        if (!editor || editor.document.uri.toString() !== document.uri.toString()) return;

        const criticalRanges: vscode.Range[] = [];
        const highRanges: vscode.Range[] = [];
        const mediumRanges: vscode.Range[] = [];

        for (const f of findings) {
            const line = Math.max(0, (f.line || 1) - 1);
            const range = document.lineAt(line).range;
            const sev = (f.severity || '').toLowerCase();
            if (sev === 'critical') criticalRanges.push(range);
            else if (sev === 'high') highRanges.push(range);
            else if (sev === 'medium') mediumRanges.push(range);
        }

        editor.setDecorations(gutterCritical, criticalRanges);
        editor.setDecorations(gutterHigh, highRanges);
        editor.setDecorations(gutterMedium, mediumRanges);
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
            statusBarItem.text = '$(pass-filled) Guardmarly: clean';
            statusBarItem.backgroundColor = undefined;
        } else {
            statusBarItem.text = '$(shield) Guardmarly';
            statusBarItem.backgroundColor = undefined;
        }
        statusBarItem.tooltip = cmdFound
            ? `Guardmarly ${versionStr}\n$(list-unordered) Click to view findings | $(refresh) Rescan: Ctrl+Shift+P → Guardmarly`
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
                updateGutterDecorations(editor.document, latestFindings);
            } else {
                statusBarItem.text = '$(shield) Guardmarly';
                statusBarItem.backgroundColor = undefined;
                if (editor) {
                    editor.setDecorations(gutterCritical, []);
                    editor.setDecorations(gutterHigh, []);
                    editor.setDecorations(gutterMedium, []);
                }
            }
        })
    );

    // ── Commands ────────────────────────────────────────────────────────────
    // Show findings quick-pick (clicking status bar)
    context.subscriptions.push(
        vscode.commands.registerCommand('guardmarly.showFindings', async () => {
            if (!cmdFound) {
                showInstallPrompt();
                return;
            }

            const editor = vscode.window.activeTextEditor;
            if (!editor) return;

            const diags = vscode.languages.getDiagnostics(editor.document.uri);
            if (diags.length === 0) {
                vscode.window.showInformationMessage('Guardmarly: No issues found in this file ✅');
                return;
            }

            const iconMap: Record<string, string> = {
                '0': '$(error)',   // Error = critical
                '1': '$(warning)', // Warning = high
                '2': '$(info)',    // Info = medium
                '3': '$(lightbulb)', // Hint = low
            };

            const items = diags.map((d, i) => ({
                label: `${iconMap[String(d.severity)] || '$(circle-outline)'} ${d.message.split('\n')[0]}`,
                description: `Line ${d.range.start.line + 1}`,
                detail: d.message.includes('\n') ? d.message.split('\n').slice(1).join(' | ') : '',
                index: i,
            }));

            const picked = await vscode.window.showQuickPick(items, {
                placeHolder: `Guardmarly: ${diags.length} finding(s) — select to jump`,
                matchOnDescription: true,
                matchOnDetail: true,
            });

            if (picked) {
                const diag = diags[picked.index];
                const range = diag.range;
                editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
                editor.selection = new vscode.Selection(range.start, range.start);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('guardmarly.scan', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) { return; }
            if (!cmdFound) {
                showInstallPrompt();
                return;
            }
            await scanDocument(editor.document);
            const count = vscode.languages.getDiagnostics(editor.document.uri).length;
            vscode.window.showInformationMessage(
                `Guardmarly: ${count} finding(s) in ${editor.document.fileName.split(/[\\/]/).pop()}`
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

            scanning = true;
            const spinInterval = setInterval(() => {
                if (scanning) statusBarItem.text = '$(sync~spin) Guardmarly: scanning workspace...';
            }, 200);

            try {
                const result = execSync(
                    `${guardmarlyCmd} "${workspaceFolders[0].uri.fsPath}" --format text --fail-on never`,
                    { encoding: 'utf-8', timeout: 120000, windowsHide: true }
                );
                scanning = false;
                clearInterval(spinInterval);
                outputChannel.appendLine(result);
                outputChannel.appendLine('Scan complete.');
                updateStatusBar(vscode.window.activeTextEditor!.document, 0);
            } catch (e: any) {
                scanning = false;
                clearInterval(spinInterval);
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
        setTimeout(() => showInstallPrompt(), 2000);
    }
}

// ── Gutter icon generator (inline SVG data URI) ────────────────────────────
function createColoredIconPath(context: vscode.ExtensionContext, color: string): vscode.Uri {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="14" height="14">
        <circle cx="8" cy="8" r="6" fill="${color}" opacity="0.9"/>
        <circle cx="8" cy="8" r="4" fill="${color}" opacity="0.3"/>
    </svg>`;
    const encoded = Buffer.from(svg).toString('base64');
    return vscode.Uri.parse(`data:image/svg+xml;base64,${encoded}`);
}

export function deactivate() {}

// ── Helpers ─────────────────────────────────────────────────────────────────
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
