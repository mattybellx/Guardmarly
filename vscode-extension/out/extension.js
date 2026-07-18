"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = require("vscode");
const child_process_1 = require("child_process");
function activate(context) {
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('guardmarly');
    context.subscriptions.push(diagnosticCollection);
    async function scanDocument(document) {
        if (!isSupportedLanguage(document.languageId))
            return;
        try {
            const result = (0, child_process_1.execSync)(`guardmarly --stdin --lang ${mapLanguage(document.languageId)} --format json --fail-on never`, {
                input: document.getText(),
                encoding: 'utf-8',
                timeout: 30000
            });
            const findings = JSON.parse(result).results?.[0]?.findings || [];
            const diagnostics = findings.map((f) => {
                const range = document.lineAt(Math.max(0, (f.line || 1) - 1)).range;
                const severity = mapSeverity(f.severity);
                const message = `[${f.cwe}] ${f.title}\n${f.suggestion || ''}`;
                const diag = new vscode.Diagnostic(range, message, severity);
                diag.source = 'Guardmarly';
                diag.code = f.cwe;
                return diag;
            });
            diagnosticCollection.set(document.uri, diagnostics);
        }
        catch {
            // Scanner not installed or timed out — silently ignore
        }
    }
    // Scan on open and save
    context.subscriptions.push(vscode.workspace.onDidOpenTextDocument(scanDocument), vscode.workspace.onDidSaveTextDocument(scanDocument));
    // Scan current file command
    context.subscriptions.push(vscode.commands.registerCommand('guardmarly.scan', async () => {
        const editor = vscode.window.activeTextEditor;
        if (editor)
            await scanDocument(editor.document);
    }));
    // Scan workspace command
    context.subscriptions.push(vscode.commands.registerCommand('guardmarly.scanWorkspace', async () => {
        try {
            const workspaceFolders = vscode.workspace.workspaceFolders;
            if (!workspaceFolders)
                return;
            const result = (0, child_process_1.execSync)(`guardmarly ${workspaceFolders[0].uri.fsPath} --format text --fail-on never`, {
                encoding: 'utf-8',
                timeout: 120000
            });
            const output = vscode.window.createOutputChannel('Guardmarly Scan');
            output.append(result);
            output.show();
        }
        catch (e) {
            vscode.window.showErrorMessage(`Guardmarly scan failed: ${e.message}`);
        }
    }));
    // Scan all open documents on activation
    vscode.workspace.textDocuments.forEach(scanDocument);
}
function isSupportedLanguage(lang) {
    return ['python', 'javascript', 'typescript', 'javascriptreact', 'typescriptreact', 'go', 'java', 'csharp'].includes(lang);
}
function mapLanguage(lang) {
    const map = {
        python: 'python', javascript: 'javascript', typescript: 'javascript',
        javascriptreact: 'javascript', typescriptreact: 'javascript',
        go: 'go', java: 'java', csharp: 'csharp'
    };
    return map[lang] || 'python';
}
function mapSeverity(sev) {
    const map = {
        critical: vscode.DiagnosticSeverity.Error,
        high: vscode.DiagnosticSeverity.Error,
        medium: vscode.DiagnosticSeverity.Warning,
        low: vscode.DiagnosticSeverity.Information,
        info: vscode.DiagnosticSeverity.Hint
    };
    return map[sev?.toLowerCase()] || vscode.DiagnosticSeverity.Warning;
}
function deactivate() { }
//# sourceMappingURL=extension.js.map