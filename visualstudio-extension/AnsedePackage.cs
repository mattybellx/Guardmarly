using System;
using System.ComponentModel.Design;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using EnvDTE;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using Task = System.Threading.Tasks.Task;

namespace AnsedeStatic.VisualStudio;

[PackageRegistration(UseManagedResourcesOnly = true, AllowsBackgroundLoading = true)]
[ProvideMenuResource("Menus.ctmenu", 1)]
[Guid(PackageGuidString)]
public sealed class AnsedePackage : AsyncPackage
{
    public const string PackageGuidString = "4f7284d2-6b7e-4eab-9517-b0e4f7b80c6d";

    private const int ScanCommandId = 0x0100;

    private AnsedeScannerService? _scanner;

    protected override async Task InitializeAsync(CancellationToken cancellationToken, IProgress<ServiceProgressData> progress)
    {
        await JoinableTaskFactory.SwitchToMainThreadAsync(cancellationToken);

        _scanner = new AnsedeScannerService();

        var commandService = await GetServiceAsync(typeof(IMenuCommandService)) as IMenuCommandService;
        if (commandService != null)
        {
            var menuCommandID = new CommandID(Guid.Parse(PackageGuidString), ScanCommandId);
            var menuItem = new MenuCommand(async (s, e) => await ScanCurrentDocumentAsync(), menuCommandID);
            commandService.AddCommand(menuItem);
        }
    }

    /// <summary>
    /// Scans the active document in the VS editor using ansede-static
    /// and writes findings to the Output window.
    /// </summary>
    private async Task ScanCurrentDocumentAsync()
    {
        await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();

        if (_scanner == null) return;

        var dte = await GetServiceAsync(typeof(DTE)) as DTE;
        if (dte?.ActiveDocument == null)
        {
            await ShowMessageAsync("Ansede Static", "No active document to scan.");
            return;
        }

        var doc = dte.ActiveDocument;
        var language = doc.Language ?? doc.ProjectItem?.ContainingProject?.Name ?? "auto";
        var filePath = doc.FullName;

        // Get output pane
        var outputPane = GetOutputPane("Ansede Static", guid: Guid.NewGuid());
        outputPane.Clear();
        outputPane.OutputString($"── Ansede Static: {System.IO.Path.GetFileName(filePath)} ──\n");

        ScanResult result;
        if (doc.Saved)
        {
            outputPane.OutputString($"Scanning file via CLI path…\n");
            result = await Task.Run(() => _scanner.ScanFile(filePath, language));
        }
        else
        {
            outputPane.OutputString($"Scanning unsaved buffer via stdin…\n");
            var textDocument = (TextDocument)doc.Object("TextDocument");
            var selection = textDocument.Selection as TextSelection;
            selection?.SelectAll();
            var text = selection?.Text ?? textDocument.StartPoint.CreateEditPoint().GetText(textDocument.EndPoint);
            result = await Task.Run(() => _scanner.ScanStdin(text, language));
        }

        outputPane.OutputString($"\n");
        outputPane.OutputString($"File       : {System.IO.Path.GetFileName(filePath)}\n");
        outputPane.OutputString($"Findings   : {result.Findings.Count}\n");
        outputPane.OutputString($"  Critical : {result.Summary.Critical}\n");
        outputPane.OutputString($"  High     : {result.Summary.High}\n");
        outputPane.OutputString($"  Medium   : {result.Summary.Medium}\n");
        outputPane.OutputString($"  Low      : {result.Summary.Low}\n");
        outputPane.OutputString($"Time       : {result.ElapsedMs}ms\n");
        outputPane.OutputString($"Engine     : v{result.Summary.EngineVersion}\n");

        if (!string.IsNullOrWhiteSpace(result.Stderr) && result.ExitCode != 0)
        {
            outputPane.OutputString($"\n── STDERR ──\n{result.Stderr}\n");
        }

        outputPane.OutputString($"\n── Findings ──\n");
        if (result.Findings.Count == 0)
        {
            outputPane.OutputString("✓ No findings detected.\n");
        }
        else
        {
            foreach (var f in result.Findings)
            {
                var sev = f.Severity.ToUpperInvariant();
                outputPane.OutputString($"\n[{sev}] {f.Cwe} | {f.RuleId} | L{f.Line}");
                if (!string.IsNullOrWhiteSpace(f.Title))
                    outputPane.OutputString($"\n       {f.Title}");
                if (!string.IsNullOrWhiteSpace(f.Remediation))
                    outputPane.OutputString($"\n       → {Truncate(f.Remediation, 120)}");
            }
            outputPane.OutputString($"\n");
        }

        outputPane.OutputString($"\n── Scan complete ({result.ElapsedMs}ms) ──\n");
        outputPane.Activate();
    }

    private IVsOutputWindowPane GetOutputPane(string title, Guid guid)
    {
        ThreadHelper.ThrowIfNotOnUIThread();
        var outWindow = (IVsOutputWindow)GetService(typeof(SVsOutputWindow));
        outWindow.CreatePane(ref guid, title, 1, 1);
        outWindow.GetPane(ref guid, out var pane);
        return pane;
    }

    private async Task ShowMessageAsync(string title, string message)
    {
        await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();
        VsShellUtilities.ShowMessageBox(
            this,
            message,
            title,
            OLEMSGICON.OLEMSGICON_INFO,
            OLEMSGBUTTON.OLEMSGBUTTON_OK,
            OLEMSGDEFBUTTON.OLEMSGDEFBUTTON_FIRST);
    }

    private static string Truncate(string value, int maxLength) =>
        value.Length <= maxLength ? value : value.Substring(0, maxLength - 3) + "...";
}
