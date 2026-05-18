using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AnsedeStatic.VisualStudio;

/// <summary>
/// Result of an ansede-static scan, containing structured findings
/// and a summary suitable for display in the VS output pane.
/// </summary>
public sealed class ScanResult
{
    public List<Finding> Findings { get; init; } = new();
    public ScanSummary Summary { get; init; } = new();
    public long ElapsedMs { get; init; }
    public int ExitCode { get; init; }
    public string Stderr { get; init; } = "";
}

public sealed class Finding
{
    [JsonPropertyName("rule_id")]
    public string RuleId { get; set; } = "";

    [JsonPropertyName("cwe")]
    public string Cwe { get; set; } = "";

    [JsonPropertyName("title")]
    public string Title { get; set; } = "";

    [JsonPropertyName("description")]
    public string Description { get; set; } = "";

    [JsonPropertyName("severity")]
    public string Severity { get; set; } = "medium";

    [JsonPropertyName("confidence")]
    public double Confidence { get; set; }

    [JsonPropertyName("line")]
    public int Line { get; set; }

    [JsonPropertyName("column")]
    public int Column { get; set; }

    [JsonPropertyName("file")]
    public string File { get; set; } = "";

    [JsonPropertyName("remediation")]
    public string Remediation { get; set; } = "";

    [JsonPropertyName("auto_fix")]
    public string AutoFix { get; set; } = "";
}

public sealed class ScanSummary
{
    [JsonPropertyName("total_findings")]
    public int TotalFindings { get; set; }

    [JsonPropertyName("critical")]
    public int Critical { get; set; }

    [JsonPropertyName("high")]
    public int High { get; set; }

    [JsonPropertyName("medium")]
    public int Medium { get; set; }

    [JsonPropertyName("low")]
    public int Low { get; set; }

    [JsonPropertyName("files_scanned")]
    public int FilesScanned { get; set; } = 1;

    [JsonPropertyName("engine_version")]
    public string EngineVersion { get; set; } = "";
}

/// <summary>
/// Wraps the ansede-static CLI: command building, process execution,
/// and JSON output parsing into structured C# objects.
/// </summary>
internal sealed class AnsedeScannerService
{
    private static readonly Dictionary<string, string> LanguageMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Python"] = "python",
        ["JavaScript"] = "javascript",
        ["TypeScript"] = "typescript",
        ["JSX"] = "javascript",
        ["TypeScript JSX"] = "typescript",
        ["Java"] = "java",
        ["CSharp"] = "csharp",
        ["C#"] = "csharp",
        ["Go"] = "go",
        ["PHP"] = "php",
        ["Ruby"] = "ruby",
    };

    // ── Command building ──────────────────────────────────────────

    public IReadOnlyList<string> BuildCommand(string language, string? filePath = null)
    {
        var args = new List<string> { ResolveExecutable() };

        if (filePath != null)
        {
            args.Add(filePath);
        }
        else
        {
            args.Add("--stdin");
        }

        args.Add("--lang");
        args.Add(MapLanguage(language));
        args.Add("--format");
        args.Add("json");
        args.Add("--fail-on");
        args.Add("never");

        return args;
    }

    private static string MapLanguage(string vsLanguage) =>
        LanguageMap.TryGetValue(vsLanguage, out var mapped) ? mapped : "auto";

    public string ResolveExecutable()
    {
        var env = Environment.GetEnvironmentVariable("ANSEDE_EXECUTABLE");
        if (!string.IsNullOrWhiteSpace(env))
            return env;

        // Default paths per OS
        if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "ansede", "ansede-static.exe");

        return "/usr/local/bin/ansede-static";
    }

    public bool IsAvailable()
    {
        try
        {
            var path = ResolveExecutable();
            return System.IO.File.Exists(path);
        }
        catch
        {
            return false;
        }
    }

    // ── Scanning ──────────────────────────────────────────────────

    /// <summary>Scan a file on disk by passing its path to ansede-static.</summary>
    public ScanResult ScanFile(string filePath, string language)
    {
        var sw = Stopwatch.StartNew();
        var cmd = BuildCommand(language, filePath);
        return Execute(cmd, null, sw);
    }

    /// <summary>Scan source text via stdin (for unsaved buffers).</summary>
    public ScanResult ScanStdin(string source, string language)
    {
        var sw = Stopwatch.StartNew();
        var cmd = BuildCommand(language, filePath: null);
        return Execute(cmd, source, sw);
    }

    // ── Internal execution ────────────────────────────────────────

    private ScanResult Execute(IReadOnlyList<string> args, string? stdin, Stopwatch sw)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = args[0],
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = stdin != null,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };

            // Skip argv[0] (the exe itself) — build args string for net472 compat
            psi.Arguments = string.Join(" ", args.Skip(1).Select(a => $"\"{a}\""));

            using var proc = Process.Start(psi);
            if (proc == null)
                return ErrorResult("Failed to start ansede-static process.", sw);

            if (stdin != null)
            {
                proc.StandardInput.Write(stdin);
                proc.StandardInput.Close();
            }

            var stdout = proc.StandardOutput.ReadToEnd();
            var stderr = proc.StandardError.ReadToEnd();

            proc.WaitForExit(30_000); // 30s timeout
            sw.Stop();

            return ParseOutput(stdout, stderr, proc.HasExited ? proc.ExitCode : -1, sw.ElapsedMilliseconds);
        }
        catch (Exception ex)
        {
            sw.Stop();
            return ErrorResult(ex.Message, sw);
        }
    }

    // ── JSON parsing ──────────────────────────────────────────────

    private static ScanResult ParseOutput(string stdout, string stderr, int exitCode, long elapsedMs)
    {
        if (string.IsNullOrWhiteSpace(stdout))
        {
            return new ScanResult { ExitCode = exitCode, ElapsedMs = elapsedMs, Stderr = stderr };
        }

        try
        {
            // Try v2 format: { "findings": [...], "summary": {...} }
            using var doc = JsonDocument.Parse(stdout.Trim());
            var root = doc.RootElement;

            List<Finding> findings = new();
            if (root.TryGetProperty("findings", out var findingsEl) && findingsEl.ValueKind == JsonValueKind.Array)
            {
                foreach (var f in findingsEl.EnumerateArray())
                {
                    findings.Add(DeserializeFinding(f));
                }
            }

            ScanSummary summary = new() { TotalFindings = findings.Count };
            if (root.TryGetProperty("summary", out var summaryEl) && summaryEl.ValueKind == JsonValueKind.Object)
            {
                summary = JsonSerializer.Deserialize<ScanSummary>(summaryEl.GetRawText()) ?? summary;
                summary.TotalFindings = findings.Count;
            }

            summary.Critical = findings.Count(f => f.Severity == "critical");
            summary.High = findings.Count(f => f.Severity == "high");
            summary.Medium = findings.Count(f => f.Severity == "medium");
            summary.Low = findings.Count(f => f.Severity == "low");

            return new ScanResult
            {
                Findings = findings,
                Summary = summary,
                ElapsedMs = elapsedMs,
                ExitCode = exitCode,
                Stderr = stderr,
            };
        }
        catch (JsonException)
        {
            // Fallback: try flat array
            try
            {
                var findings = JsonSerializer.Deserialize<List<Finding>>(stdout.Trim()) ?? new();
                return new ScanResult
                {
                    Findings = findings,
                    Summary = new ScanSummary
                    {
                        TotalFindings = findings.Count,
                        Critical = findings.Count(f => f.Severity == "critical"),
                        High = findings.Count(f => f.Severity == "high"),
                        Medium = findings.Count(f => f.Severity == "medium"),
                        Low = findings.Count(f => f.Severity == "low"),
                    },
                    ElapsedMs = elapsedMs,
                    ExitCode = exitCode,
                    Stderr = stderr,
                };
            }
            catch
            {
                return new ScanResult { ElapsedMs = elapsedMs, ExitCode = exitCode, Stderr = $"Parse error: {stderr}" };
            }
        }
    }

    private static Finding DeserializeFinding(JsonElement el)
    {
        var finding = new Finding();
        if (el.TryGetProperty("rule_id", out var p)) finding.RuleId = p.GetString() ?? "";
        if (el.TryGetProperty("cwe", out p)) finding.Cwe = p.GetString() ?? "";
        if (el.TryGetProperty("title", out p)) finding.Title = p.GetString() ?? "";
        if (el.TryGetProperty("description", out p)) finding.Description = p.GetString() ?? "";
        if (el.TryGetProperty("severity", out p)) finding.Severity = (p.GetString() ?? "medium").ToLowerInvariant();
        if (el.TryGetProperty("confidence", out p) && p.TryGetDouble(out var d)) finding.Confidence = d;
        if (el.TryGetProperty("line", out p) && p.TryGetInt32(out var i)) finding.Line = i;
        if (el.TryGetProperty("column", out p) && p.TryGetInt32(out i)) finding.Column = i;
        if (el.TryGetProperty("file", out p)) finding.File = p.GetString() ?? "";
        if (el.TryGetProperty("remediation", out p)) finding.Remediation = p.GetString() ?? "";
        if (el.TryGetProperty("auto_fix", out p)) finding.AutoFix = p.GetString() ?? "";
        return finding;
    }

    private static ScanResult ErrorResult(string error, Stopwatch sw) =>
        new() { ElapsedMs = sw.ElapsedMilliseconds, ExitCode = -1, Stderr = error };
}
