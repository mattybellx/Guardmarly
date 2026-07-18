import * as vscode from 'vscode';
import { execSync } from 'child_process';

export function activate(context: vscode.ExtensionContext) {
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('guardmarly');
    context.subscriptions.push(diagnosticCollection);

    async function scanDocument(document: vscode.TextDocument) {
        if (!isSupportedLanguage(document.languageId)) return;
        
        try {
            const result = execSync(`guardmarly --stdin --lang ${mapLanguage(document.languageId)} --format json --fail-on never`, {
                input: document.getText(),
                encoding: 'utf-8',
                timeout: 30000
            });
            
            const findings = JSON.parse(result).results?.[0]?.findings || [];
            const diagnostics: vscode.Diagnostic[] = findings.map((f: any) => {
                const range = document.lineAt(Math.max(0, (f.line || 1) - 1)).range;
                const severity = mapSeverity(f.severity);
                const message = `[${f.cwe}] ${f.title}\n${f.suggestion || ''}`;
                const diag = new vscode.Diagnostic(range, message, severity);
                diag.source = 'Guardmarly';
                diag.code = f.cwe;
                return diag;
            });
            
            diagnosticCollection.set(document.uri, diagnostics);
        } catch {
            // Scanner not installed or timed out — silently ignore
        }
    }

    // Scan on open and save
    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument(scanDocument),
        vscode.workspace.onDidSaveTextDocument(scanDocument)
    );

    // Scan current file command
    context.subscriptions.push(
        vscode.commands.registerCommand('guardmarly.scan', async () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) await scanDocument(editor.document);
        })
    );

    // Scan workspace command
    context.subscriptions.push(
        vscode.commands.registerCommand('guardmarly.scanWorkspace', async () => {
            try {
                const workspaceFolders = vscode.workspace.workspaceFolders;
                if (!workspaceFolders) return;
                
                const result = execSync(`guardmarly ${workspaceFolders[0].uri.fsPath} --format text --fail-on never`, {
                    encoding: 'utf-8',
                    timeout: 120000
                });
                
                const output = vscode.window.createOutputChannel('Guardmarly Scan');
                output.append(result);
                output.show();
            } catch (e: any) {
                vscode.window.showErrorMessage(`Guardmarly scan failed: ${e.message}`);
            }
        })
    );

    // Scan all open documents on activation
    vscode.workspace.textDocuments.forEach(scanDocument);
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
