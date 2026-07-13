"""
ansede_static.reporters
────────────────────────
Output formatters for AnalysisResult.

Supported formats:
  - plaintext  (default — human-readable terminal output)
  - json       (machine-readable, one object per file)
  - sarif      (SARIF 2.1.0 — upload to GitHub Code Scanning)

Usage:
    from ansede_static.reporters import format_text, format_json, format_sarif
    print(format_text(result))
    with open("results.sarif") as f:
        f.write(format_sarif([result1, result2]))
"""
from __future__ import annotations

import hashlib
import json as _json
from typing import Any

from ansede_static._types import AnalysisResult, Finding
from ansede_static.engine_version import get_engine_version
from ansede_static.rules import get_rule_contract, _unique_tags
from ansede_static.schema import build_report

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.tree import Tree
    from rich.text import Text
    from rich.style import Style
    from rich.syntax import Syntax
    from rich.markdown import Markdown
    console = Console()
except ImportError:
    console = None


# ──────────────────────────────────────────────────────────────────────────────
# Plain-text / Rich formatter
# ──────────────────────────────────────────────────────────────────────────────

_SEV_COLOUR_RICH = {
    "critical": "bold red",
    "high":     "yellow",
    "medium":   "cyan",
    "low":      "green",
    "info":     "white",
}

_SEV_COLOUR: dict[str, str] = {
    "critical": "\033[91m",  # bright red
    "high":     "\033[33m",  # yellow
    "medium":   "\033[36m",  # cyan
    "low":      "\033[32m",  # green
    "info":     "\033[37m",  # white
}
_RESET = "\033[0m"


def format_text(result: AnalysisResult, colour: bool = True, verbose: bool = False) -> str:
    """Return a human-readable string for one AnalysisResult. When 'rich' is available, prints directly and returns empty."""
    if console and colour:
        if result.parse_error:
            console.print(f"[bold red]  [ERROR] {result.parse_error}[/bold red]")
            return ""

        if not result.findings:
            console.print(f"[dim]  OK  No issues found ({result.lines_scanned} lines scanned)[/dim]")
            return ""
            
        for f in result.sorted_findings():
            sev_str = f.severity.value.upper()
            rich_col = _SEV_COLOUR_RICH.get(f.severity.value, "white")
            
            cwe_str = f" ({f.cwe})" if f.cwe else ""
            location = f"L{f.line}" if f.line else "?"
            conf_display = ""
            analysis_label = ""
            if f.confidence is not None and f.confidence < 0.80:
                conf_display = f" [{f.confidence:.0%}]"
            if f.confidence is not None and (f.confidence < 0.80 or f.confidence_label == "heuristic"):
                analysis_label = f"  analysis: {f.confidence_label}"

            header = Text()
            header.append(f"[{sev_str}]", style=f"reverse {rich_col}")
            header.append(f" {location:<6} ", style="dim")
            header.append(f"{f.title}{cwe_str}", style="bold")
            if conf_display:
                header.append(conf_display, style="dim")
            if analysis_label:
                header.append(analysis_label, style="dim")
            
            body = Text()
            if verbose:
                body.append(f"-> {f.description[:120]}\n")
                body.append(f"meta: {f.effective_rule_id} · {f.analysis_kind} · confidence {f.confidence:.2f}\n", style="dim")
                if f.suggestion:
                    body.append(f"* {f.suggestion[:100]}\n", style="italic cyan")
                
            panel_content = body
            
            # If we have a trace, build a visual tree
            if verbose and f.trace:
                tree = Tree("Data Flow / Trace")
                for frame in f.trace:
                    loc = f"L{frame.line}" if frame.line else "?"
                    node_style = "bold red" if frame.kind == "sink" else ("bold green" if frame.kind == "source" else "yellow")
                    tree.add(Text(f"{frame.kind.upper()}: {frame.label} ({loc})", style=node_style))
                
                # We can't put a Tree inside a Text easily, so we print the panel, then the tree
                console.print(Panel(panel_content, title=header, title_align="left", border_style=rich_col))
                console.print(tree)
                if hasattr(f, "explanation") and f.explanation:
                    console.print(Panel(Markdown(f.explanation), title="Vulnerability Explanation", border_style="blue"))
                if f.auto_fix:
                    fix_code = Syntax(f.auto_fix, result.language or "python", theme="monokai", line_numbers=False)
                    console.print(Panel(fix_code, title="Suggested Auto-Fix", border_style="green"))
                console.print("")
            else:
                if f.auto_fix and verbose:
                    panel_content.append("\nSuggested Auto-Fix:\n", style="bold green")
                    panel_content.append(f.auto_fix)
                console.print(Panel(panel_content, title=header, title_align="left", border_style=rich_col))
                if verbose and hasattr(f, "explanation") and f.explanation:
                    console.print(Panel(Markdown(f.explanation), title="Vulnerability Explanation", border_style="blue"))
                
        return ""
    
    # Fallback to legacy ANSI string output if rich is absent
    lines: list[str] = []

    if result.parse_error:
        lines.append(f"  [ERROR] {result.parse_error}")
        return "\n".join(lines)

    if not result.findings:
        lines.append(f"  OK  No issues found ({result.lines_scanned} lines scanned)")
        return "\n".join(lines)

    for f in result.sorted_findings():
        sev_str = f.severity.value.upper()
        padded = f"[{sev_str}]".ljust(10)
        if colour:
            col = _SEV_COLOUR.get(f.severity.value, "")
            sev_label = f"{col}{padded}{_RESET}"
        else:
            sev_label = padded

        location = f"L{f.line}" if f.line else "?"
        cwe = f" ({f.cwe})" if f.cwe else ""
        lines.append(f"  {sev_label}  {location:<6}  {f.title}{cwe}")

        if f.confidence is not None and (f.confidence < 0.80 or f.confidence_label == "heuristic"):
            lines.append(f"             analysis: {f.confidence_label}")

        if verbose:
            lines.append(f"             -> {f.description[:120]}")
            lines.append(
                f"             meta: {f.effective_rule_id} · {f.analysis_kind} · confidence {f.confidence:.2f}"
            )
            if f.suggestion:
                lines.append(f"             * {f.suggestion[:100]}")
            if f.trace:
                lines.append("             flow:")
                for frame in f.trace:
                    loc = f"L{frame.line}" if frame.line else "?"
                    lines.append(f"               - {frame.kind}: {frame.label} ({loc})")
            if f.auto_fix:
                for fix_line in f.auto_fix.splitlines():
                    lines.append(f"               {fix_line}")
            lines.append("")

    c = sum(1 for f in result.findings if f.severity.value in ("critical",))
    h = result.high_count
    m = sum(1 for f in result.findings if f.severity.value == "medium")
    lines.append(
        f"\n  Summary: {len(result.findings)} findings -- "
        f"{result.security_count} security, {result.quality_count} quality; "
        f"{c} critical, {h} high, {m} medium"
    )
    return "\n".join(lines)


def format_text_multi(
    results: list[AnalysisResult],
    colour: bool = True,
    verbose: bool = False,
    show_clean: bool = False,
) -> str:
    """Return a full report for multiple files."""
    if console and colour:
        total_findings = sum(len(r.findings) for r in results)
        total_critical = sum(r.critical_count for r in results)
        total_high = sum(r.high_count for r in results)
        
        console.print(f"\n[bold]{'─' * 74}[/bold]")
        console.print(f"[bold cyan]  ansede-static[/bold cyan]  --  {len(results)} file(s) scanned")
        console.print(f"[bold]{'─' * 74}[/bold]\n")

        for result in results:
            if not result.findings and not show_clean:
                continue
            label = f"{result.file_path or '<stdin>'}  ({result.language})"
            console.print(f"[bold underline]{label}[/bold underline]")
            format_text(result, colour=colour, verbose=verbose)

        console.print(f"[bold]{'─' * 74}[/bold]")
        summary_msg = Text(f"  Total: {total_findings} findings across {len(results)} file(s) -- ")
        
        c_style = "bold red" if total_critical > 0 else "dim"
        h_style = "yellow" if total_high > 0 else "dim"
        
        summary_msg.append(f"{total_critical} critical", style=c_style)
        summary_msg.append(f", {total_high} high", style=h_style)
        
        console.print(summary_msg)
        console.print(f"[bold]{'─' * 74}[/bold]")
        return ""

    # Legacy return string (for JSON/File redirection fallback without Rich TTY)
    parts: list[str] = []
    total_findings = sum(len(r.findings) for r in results)
    total_critical = sum(r.critical_count for r in results)
    total_high = sum(r.high_count for r in results)
    total_security = sum(r.security_count for r in results)
    total_quality = sum(r.quality_count for r in results)

    sep = "-" * 72
    parts.append(sep)
    parts.append(f"  ansede-static  --  {len(results)} file(s) scanned")
    parts.append(sep)
    parts.append("")

    for result in results:
        if not result.findings and not show_clean:
            continue
        label = f"{result.file_path or '<stdin>'}  ({result.language})"
        parts.append(f"  {label}")
        parts.append(format_text(result, colour=colour, verbose=verbose))
        parts.append("")

    parts.append(sep)
    parts.append(
        f"  Total: {total_findings} findings across {len(results)} file(s) -- "
        f"{total_security} security, {total_quality} quality; "
        f"{total_critical} critical, {total_high} high"
    )
    parts.append(sep)
    return "\n".join(parts)


# ──────────────────────────────────────────────────────────────────────────────
# JSON formatter
# ──────────────────────────────────────────────────────────────────────────────

def format_json(results: list[AnalysisResult], indent: int = 2, *, execution: dict[str, Any] | None = None, cluster: bool = False) -> str:
    """Return a JSON string with all results.
    
    If cluster=True, incident clustering stats are included in the output.
    """
    payload: dict[str, Any] = build_report(results, execution=execution, cluster=cluster)
    return _json.dumps(payload, indent=indent, default=str)


def format_ciso_report(results: list[AnalysisResult]) -> str:
    """Generate the 'Security Debt Executive Summary' for Phase 4."""
    if not console:
        return "Install rich library for CISO reports."
        
    from rich.table import Table
    
    total_files = len(results)
    total_vulns = sum(len(r.findings) for r in results)
    critical_vulns = sum(r.critical_count for r in results)
    high_vulns = sum(r.high_count for r in results)
    
    # Calculate simplistic financial risk (mock algorithm for the CISO view)
    base_cost_per_critical = 15000 
    base_cost_per_high = 5000
    financial = (critical_vulns * base_cost_per_critical) + (high_vulns * base_cost_per_high)
    
    cwe_counts = {}
    for r in results:
        for f in r.findings:
            cwe = f.cwe or "Unknown"
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
            
    # Draw table
    table = Table(title="🏢 Ansede-Static Executive Risk Profile", title_justify="left", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="dim", width=30)
    table.add_column("Value")
    
    table.add_row("Total Files Scanned", str(total_files))
    table.add_row("Total Vulnerabilities", f"[bold red]{total_vulns}[/bold red]")
    table.add_row("Critical Deficits (SLA 24hr)", f"[bold red]{critical_vulns}[/bold red]")
    table.add_row("High Deficits (SLA 7d)", f"[bold yellow]{high_vulns}[/bold yellow]")
    table.add_row("Estimated Remediation Debt", f"[bold green]${financial:,}[/bold green]")
    
    # Draw impact map
    impact_table = Table(title="Threat Landscape by CWE", show_header=True, header_style="bold blue")
    impact_table.add_column("Category")
    impact_table.add_column("Count")
    
    for cwe, count in sorted(cwe_counts.items(), key=lambda item: item[1], reverse=True):
        impact_table.add_row(str(cwe), str(count))
        
    console.print("\n")
    console.print(table)
    console.print()
    console.print(impact_table)
    console.print("\n")
    
    return ""


# ──────────────────────────────────────────────────────────────────────────────
# SARIF 2.1.0 formatter (GitHub Code Scanning compatible)
# ──────────────────────────────────────────────────────────────────────────────

_SARIF_LEVEL: dict[str, str] = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "note",
}

_SARIF_PRECISION_ORDER: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
}


def _enriched_properties(finding: Finding) -> dict[str, Any]:
    """Return CVSS, OWASP, and exploitability properties for a finding."""
    props: dict[str, Any] = {}
    if finding.cwe:
        try:
            from ansede_static.engine.cvss import enrich_finding_properties
            taint_depth = len(finding.trace) if finding.trace else 0
            enriched = enrich_finding_properties(finding.cwe, finding.confidence, taint_depth)
            props.update(enriched)
        except Exception:
            pass
    return props


def format_sarif(results: list[AnalysisResult], *, execution: dict[str, Any] | None = None) -> str:
    """
    Return a SARIF 2.1.0 JSON string.
    Upload to GitHub: `gh upload-scan-result results.sarif`
    """
    # Collect all unique rules
    rules_by_id: dict[str, dict] = {}
    for result in results:
        for f in result.findings:
            rule_id = f.effective_rule_id
            contract = get_rule_contract(
                f.rule_id,
                cwe=f.cwe,
                title=f.title,
                category=f.category,
                severity=f.severity.value,
                language=result.language,
            )
            precision = _more_conservative_precision(
                _contract_precision_to_sarif(contract.precision),
                _sarif_precision(f.confidence),
            )
            if rule_id not in rules_by_id:
                tags = list(_unique_tags(f.finding_class, f.category, contract.tags))
                properties: dict[str, Any] = {
                    "tags": tags,
                    "precision": precision,
                    "confidence": f.confidence,
                    "cwe": f.cwe,
                    "maturity": contract.maturity,
                    "ruleSummary": contract.summary,
                }
                if f.cwe:
                    try:
                        from ansede_static.engine.cvss import get_cvss as _cvss_get, get_owasp as _owasp_get
                        cvss = _cvss_get(f.cwe)
                        properties["cvss"] = {"vector": cvss["vector"], "score": cvss["score"], "severity": cvss["severity"]}
                        owasp = _owasp_get(f.cwe)
                        if owasp:
                            properties["owasp"] = owasp
                    except Exception:
                        pass
                if f.finding_class == "security":
                    properties["security-severity"] = _cwe_to_cvss(f.cwe)
                rules_by_id[rule_id] = {
                    "id": rule_id,
                    "name": contract.title[:80] or f.title[:80],
                    "shortDescription": {"text": contract.summary or f.description[:200]},
                    "fullDescription": {"text": contract.summary or f.description},
                    "helpUri": contract.docs_url or _cwe_help_uri(f.cwe),
                    "defaultConfiguration": {
                        "level": _SARIF_LEVEL.get(f.severity.value, "warning")
                    },
                    "help": {"text": contract.remediation or f.suggestion or "Review and fix this finding."},
                    "properties": properties,
                }
            else:
                existing_properties = rules_by_id[rule_id].setdefault("properties", {})
                existing_precision = str(existing_properties.get("precision", precision))
                existing_properties["precision"] = _more_conservative_precision(existing_precision, precision)
                if "confidence" in existing_properties:
                    existing_properties["confidence"] = min(float(existing_properties["confidence"]), f.confidence)

    sarif_results: list[dict] = []
    for result in results:
        for f in result.sorted_findings():
            rule_id = f.effective_rule_id
            physical: dict[str, Any] = {
                "artifactLocation": {
                    "uri": (result.file_path or "").lstrip("/\\"),
                    "uriBaseId": "%SRCROOT%",
                },
            }
            if f.line:
                physical["region"] = {
                    "startLine": f.line,
                    "startColumn": 1,
                }
            sarif_results.append({
                "ruleId": rule_id,
                "level": _SARIF_LEVEL.get(f.severity.value, "warning"),
                "message": {"text": f.description},
                "locations": [{
                    "physicalLocation": physical,
                }],
                **({"codeFlows": [_trace_to_sarif_codeflow(result.file_path, f)]} if f.trace else {}),
                "partialFingerprints": {
                    "primaryLocationLineHash": _finding_fingerprint(result.file_path, f),
                },
                "properties": {
                    "ruleId": rule_id,
                    "category": f.category,
                    "cwe": f.cwe,
                    "findingClass": f.finding_class,
                    "confidence": f.confidence,
                    "confidenceLabel": f.confidence_label,
                    "analysisKind": f.analysis_kind,
                    "suggestion": f.suggestion,
                    "autoFix": f.auto_fix,
                    "rule": get_rule_contract(
                        f.rule_id,
                        cwe=f.cwe,
                        title=f.title,
                        category=f.category,
                        severity=f.severity.value,
                        language=result.language,
                    ).as_dict(),
                    **_enriched_properties(f),
                },
            })

    sarif: dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ansede-static",
                    "version": get_engine_version(),
                    "informationUri": "https://github.com/mattybellx/Ansede",
                    "rules": list(rules_by_id.values()),
                }
            },
            "results": sarif_results,
            "automationDetails": {
                "id": "ansede-static/",
            },
            **({"properties": {"execution": execution}} if execution else {}),
        }],
    }
    return _json.dumps(sarif, indent=2, default=str)


def _finding_fingerprint(file_path: str, finding: Finding) -> str:
    payload = f"{file_path}|{finding.line}|{finding.effective_rule_id}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _trace_to_sarif_codeflow(file_path: str, finding: Finding) -> dict[str, Any]:
    locations: list[dict[str, Any]] = []
    for frame in finding.trace:
        # Prefer per-frame source file (set by source-map remapping) over the
        # bundle/compiled file path.  This is the path GitHub Code Scanning
        # uses to link back to the original source location.
        frame_uri = (frame.file_path or file_path or "").lstrip("/\\")
        physical_location: dict[str, Any] = {
            "artifactLocation": {
                "uri": frame_uri,
                "uriBaseId": "%SRCROOT%",
            },
        }
        if frame.line:
            physical_location["region"] = {
                "startLine": frame.line,
                "startColumn": frame.start_column,
            }
        locations.append({
            "location": {
                "physicalLocation": physical_location,
                "message": {"text": frame.label},
            },
            "importance": "essential" if frame.kind in {"source", "sink"} else "important",
        })
    return {
        "threadFlows": [{
            "locations": locations,
        }],
    }


def _sarif_precision(confidence: float) -> str:
    if confidence >= 0.95:
        return "high"
    if confidence >= 0.8:
        return "medium"
    return "low"


def _contract_precision_to_sarif(precision: str) -> str:
    normalized = precision.strip().lower()
    if normalized == "high":
        return "high"
    if normalized == "low":
        return "low"
    return "medium"


def _more_conservative_precision(existing: str, new: str) -> str:
    existing_order = _SARIF_PRECISION_ORDER.get(existing, _SARIF_PRECISION_ORDER["medium"])
    new_order = _SARIF_PRECISION_ORDER.get(new, _SARIF_PRECISION_ORDER["medium"])
    return existing if existing_order <= new_order else new

def _cwe_help_uri(cwe: str) -> str:
    if not cwe:
        return "https://cwe.mitre.org/"
    return f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html"


def _cwe_to_cvss(cwe: str) -> str:
    """Return a rough CVSS-equivalent score string for SARIF tag."""
    severe = {"CWE-78", "CWE-89", "CWE-95", "CWE-502", "CWE-798", "CWE-287", "CWE-285"}
    high   = {"CWE-918", "CWE-22", "CWE-639", "CWE-79", "CWE-345"}
    if cwe in severe:
        return "9.8"
    if cwe in high:
        return "8.1"
    return "5.5"


# ──────────────────────────────────────────────────────────────────────────────
# HTML dashboard formatter (self-contained, zero external resources)
# ──────────────────────────────────────────────────────────────────────────────

_HTML_SEV_COLOUR: dict[str, str] = {
    "critical": "#c0392b",
    "high":     "#e67e22",
    "medium":   "#2980b9",
    "low":      "#27ae60",
    "info":     "#7f8c8d",
}

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ansede-static Security Report</title>
<style>
  :root {{
    --bg: #1a1a2e; --surface: #16213e; --surface2: #0f3460;
    --text: #e0e0e0; --muted: #9e9e9e; --accent: #e94560;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 24px; }}
  h1 {{ font-size: 1.6rem; color: var(--accent); margin-bottom: 8px; }}
  .subtitle {{ color: var(--muted); font-size: 0.9rem; margin-bottom: 24px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 12px; margin-bottom: 28px; }}
  .stat-card {{ background: var(--surface); border-radius: 8px; padding: 14px; text-align: center; border-top: 3px solid var(--accent); }}
  .stat-card .num {{ font-size: 2rem; font-weight: 700; }}
  .stat-card .label {{ font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; }}
  .controls {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 20px; align-items: center; }}
  .controls label {{ font-size: 0.82rem; color: var(--muted); }}
  .controls select, .controls input {{ background: var(--surface2); color: var(--text); border: 1px solid #2a4a7f; border-radius: 4px; padding: 6px 10px; font-size: 0.82rem; }}
  .controls button {{ background: var(--accent); color: #fff; border: none; border-radius: 4px; padding: 6px 14px; font-size: 0.82rem; cursor: pointer; }}
  .controls button:hover {{ filter: brightness(1.2); }}
  .stats-row {{ display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; font-size: 0.82rem; color: var(--muted); }}
  .stats-row span {{ background: var(--surface); padding: 4px 12px; border-radius: 12px; }}
  .file-section {{ background: var(--surface); border-radius: 8px; margin-bottom: 16px; overflow: hidden; }}
  .file-header {{ background: var(--surface2); padding: 12px 16px; font-family: monospace; font-size: 0.85rem; cursor: pointer; user-select: none; display: flex; justify-content: space-between; align-items: center; }}
  .file-header:hover {{ background: #0d2d52; }}
  .file-body {{ padding: 12px; }}
  .finding {{ border-left: 4px solid; padding: 10px 14px; margin-bottom: 8px; border-radius: 0 6px 6px 0; background: rgba(255,255,255,0.03); }}
  .finding-header {{ display: flex; gap: 10px; align-items: baseline; margin-bottom: 4px; }}
  .badge {{ font-size: 0.7rem; font-weight: 700; padding: 2px 7px; border-radius: 3px; text-transform: uppercase; color: #fff; }}
  .finding-title {{ font-weight: 600; font-size: 0.9rem; }}
  .finding-location {{ font-size: 0.75rem; color: var(--muted); font-family: monospace; }}
  .finding-desc {{ font-size: 0.82rem; color: #c0c0c0; margin-top: 4px; }}
  .finding-meta {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }}
  .tag {{ font-size: 0.7rem; padding: 1px 6px; border-radius: 12px; background: rgba(255,255,255,0.1); color: var(--muted); }}
  .finding-code {{ font-family: monospace; font-size: 0.78rem; background: #0a0a1a; border-radius: 4px; padding: 8px 12px; margin-top: 6px; overflow-x: auto; white-space: pre; color: #a8d8a8; }}
  .finding-suggestion {{ font-size: 0.8rem; color: #7fbfff; margin-top: 5px; font-style: italic; }}
    .trace-block {{ margin-top: 8px; border-left: 3px solid rgba(127,191,255,0.4); padding-left: 10px; }}
    .trace-step {{ font-family: monospace; font-size: 0.76rem; color: #b8c7e0; margin: 2px 0; }}
  .clean {{ color: var(--muted); font-size: 0.85rem; padding: 10px 16px; }}
  .confidence-bar-wrap {{ display: inline-block; width: 60px; height: 6px; background: rgba(255,255,255,0.1); border-radius: 3px; vertical-align: middle; margin-left: 4px; }}
  .confidence-bar {{ height: 6px; border-radius: 3px; background: #27ae60; }}
  .hidden {{ display: none !important; }}
  details summary {{ list-style: none; }}
  details summary::-webkit-details-marker {{ display: none; }}
  .toggle {{ font-size: 0.75rem; color: var(--muted); }}
  footer {{ color: var(--muted); font-size: 0.75rem; text-align: center; margin-top: 32px; }}
</style>
</head>
<body>
<h1>&#x1F6E1; ansede-static — Security Report</h1>
<p class="subtitle">Generated: {timestamp} &nbsp;|&nbsp; Engine v{version} &nbsp;|&nbsp; {file_count} file(s) scanned</p>
<div class="summary-grid">
  <div class="stat-card" style="border-top-color:#c0392b"><div class="num" style="color:#c0392b">{critical}</div><div class="label">Critical</div></div>
  <div class="stat-card" style="border-top-color:#e67e22"><div class="num" style="color:#e67e22">{high}</div><div class="label">High</div></div>
  <div class="stat-card" style="border-top-color:#2980b9"><div class="num" style="color:#2980b9">{medium}</div><div class="label">Medium</div></div>
  <div class="stat-card" style="border-top-color:#27ae60"><div class="num" style="color:#27ae60">{low}</div><div class="label">Low</div></div>
  <div class="stat-card"><div class="num">{total}</div><div class="label">Total</div></div>
  <div class="stat-card"><div class="num">{security}</div><div class="label">Security</div></div>
  <div class="stat-card"><div class="num">{quality}</div><div class="label">Quality</div></div>
</div>
<div class="controls">
  <label>Severity: <select id="sev-filter" onchange="applyFilter()">
    <option value="all">All</option>
    <option value="critical">Critical</option>
    <option value="high">High</option>
    <option value="medium">Medium</option>
    <option value="low">Low</option>
  </select></label>
  <label>CWE: <input id="cwe-filter" type="text" placeholder="e.g. CWE-862" oninput="applyFilter()"></label>
  <label>File: <input id="file-filter" type="text" placeholder="filename contains" oninput="applyFilter()"></label>
  <label>Sort: <select id="sort-select" onchange="applyFilter()">
    <option value="severity">Severity</option>
    <option value="line">Line</option>
    <option value="confidence">Confidence</option>
  </select></label>
  <button onclick="exportSARIF()" title="Download SARIF 2.1.0">&#x1F4E5; Export SARIF</button>
</div>
<div class="stats-row" id="stats-row">
  <span id="visible-count">Showing {total} of {total} findings</span>
  <span id="cwe-distinct"></span>
</div>
{file_sections}
<footer>ansede-static &mdash; SAST engine &mdash; <a href="https://github.com/mattybellx/Ansede" style="color:#7fbfff">github.com/mattybellx/Ansede</a></footer>
<script>
  const SEV_ORDER = {{"critical":0,"high":1,"medium":2,"low":3,"info":4}};
  let findingsData = [];

  document.querySelectorAll('.file-section').forEach((fs, fi) => {{
    fs.querySelectorAll('.finding').forEach((finding, _) => {{
      const sevEl = finding.querySelector('.badge');
      const cweText = (finding.querySelector('.finding-title')?.textContent || '');
      const fileEl = fs.querySelector('.file-header span:first-child');
      const locEl = finding.querySelector('.finding-location');
      const confEl = finding.querySelector('.confidence-bar');
      findingsData.push({{
        el: finding,
        fileSection: fs,
        file: (fileEl?.textContent || '').trim(),
        severity: (sevEl?.textContent || '').trim().toLowerCase(),
        cwe: (cweText.match(/CWE-\\d+/) || [''])[0],
        line: parseInt(locEl?.textContent?.replace('L','') || '0', 10),
        confidence: confEl ? parseInt(confEl.style.width || '0', 10) / 100 : 0,
      }});
    }});
  }});

  function applyFilter() {{
    const sev = document.getElementById('sev-filter').value;
    const cwe = (document.getElementById('cwe-filter').value || '').toUpperCase();
    const fileQ = (document.getElementById('file-filter').value || '').toLowerCase();
    const sort = document.getElementById('sort-select').value;
    let visible = 0;

    findingsData.forEach(d => {{
      const matchSev = sev === 'all' || d.severity === sev;
      const matchCwe = !cwe || d.cwe.startsWith(cwe);
      const matchFile = !fileQ || d.file.toLowerCase().includes(fileQ);
      const match = matchSev && matchCwe && matchFile;
      d.el.classList.toggle('hidden', !match);
      if (match) visible++;
    }});

    // Sort visible findings per file section
    findingsData.sort((a, b) => {{
      if (sort === 'line') return a.line - b.line;
      if (sort === 'confidence') return (b.confidence - a.confidence);
      return (SEV_ORDER[a.severity] || 99) - (SEV_ORDER[b.severity] || 99);
    }});

    // Re-order DOM elements
    const sections = new Set();
    findingsData.forEach(d => sections.add(d.fileSection));
    sections.forEach(section => {{
      const body = section.querySelector('.file-body');
      const visibleFindings = findingsData.filter(d => d.fileSection === section && !d.el.classList.contains('hidden'));
      visibleFindings.forEach(d => body.appendChild(d.el));
    }});

    document.getElementById('visible-count').textContent = `Showing ${{visible}} of ${{findingsData.length}} findings`;

    const uniqueCWEs = [...new Set(findingsData.filter(d => d.cwe && !d.el.classList.contains('hidden')).map(d => d.cwe))];
    document.getElementById('cwe-distinct').textContent = uniqueCWEs.length ? `CWE types: ${{uniqueCWEs.length}} (${{uniqueCWEs.join(', ')}})` : '';
  }}

  document.querySelectorAll('.file-header').forEach(h => {{
    h.addEventListener('click', () => {{
      const body = h.nextElementSibling;
      if (body) body.style.display = body.style.display === 'none' ? '' : 'none';
      const tog = h.querySelector('.toggle');
      if (tog) tog.textContent = body.style.display === 'none' ? '▶' : '▼';
    }});
  }});

  function exportSARIF() {{
    const sarif = {{
      version: '2.1.0',
      runs: [{{
        tool: {{ driver: {{ name: 'ansede-static', version: '{version}', informationUri: 'https://github.com/mattybellx/Ansede' }} }},
        results: findingsData.filter(d => !d.el.classList.contains('hidden')).map(d => ({{
          ruleId: (d.el.querySelector('.tag:first-child')?.textContent || '').trim(),
          level: d.severity === 'critical' ? 'error' : d.severity === 'high' ? 'error' : d.severity === 'medium' ? 'warning' : 'note',
          message: {{ text: d.el.querySelector('.finding-title')?.textContent?.replace(/\\s*—\\s*CWE-\\d+$/, '') || 'Finding' }},
          locations: [{{
            physicalLocation: {{
              artifactLocation: {{ uri: d.file, uriBaseId: '%SRCROOT%' }},
              region: {{ startLine: d.line || 1 }}
            }}
          }}]
        }}))
      }}]
    }};
    const blob = new Blob([JSON.stringify(sarif, null, 2)], {{type: 'application/sarif+json'}});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'ansede-report.sarif';
    a.click();
  }}
</script>
</body>
</html>"""


def _html_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
    )


def format_html(results: list[AnalysisResult]) -> str:
    """Return a self-contained HTML security dashboard string."""
    import datetime
    from ansede_static.engine_version import get_engine_version as _gev

    total = sum(len(r.findings) for r in results)
    critical = sum(r.critical_count for r in results)
    high = sum(r.high_count for r in results)
    medium = sum(1 for r in results for f in r.findings if f.severity.value == "medium")
    low = sum(1 for r in results for f in r.findings if f.severity.value == "low")
    security = sum(r.security_count for r in results)
    quality = sum(r.quality_count for r in results)

    file_sections_html: list[str] = []
    for result in results:
        fp = _html_escape(result.file_path or "<stdin>")
        lang = _html_escape(result.language or "")
        finding_count = len(result.findings)
        badge_text = f"{finding_count} finding{'s' if finding_count != 1 else ''}" if finding_count else "clean"
        badge_colour = "#c0392b" if finding_count else "#27ae60"

        finding_cards: list[str] = []
        if result.parse_error:
            finding_cards.append(
                f'<div class="finding" style="border-color:#c0392b">'
                f'<div class="finding-header"><span class="badge" style="background:#c0392b">ERROR</span>'
                f'<span class="finding-title">{_html_escape(result.parse_error)}</span></div></div>'
            )
        elif not result.findings:
            finding_cards.append(
                f'<p class="clean">&#x2705; No issues found &mdash; {result.lines_scanned} lines scanned</p>'
            )
        else:
            for f in result.sorted_findings():
                sev = f.severity.value
                colour = _HTML_SEV_COLOUR.get(sev, "#7f8c8d")
                loc = f"L{f.line}" if f.line else "?"
                cwe_text = f" &mdash; {_html_escape(f.cwe)}" if f.cwe else ""
                rule_id = _html_escape(f.effective_rule_id)
                conf_pct = int(f.confidence * 100)
                conf_bar = (
                    f'<span class="confidence-bar-wrap">'
                    f'<span class="confidence-bar" style="width:{conf_pct}%"></span></span>'
                    f' {conf_pct}%'
                )

                # Tags (compliance + category)
                tags_html = ""
                all_tags = [f.category, f.analysis_kind] + list(getattr(f, "tags", []))
                tags_html = "".join(
                    f'<span class="tag">{_html_escape(t)}</span>'
                    for t in all_tags if t
                )

                # Triggering code snippet
                snippet_html = ""
                if getattr(f, "triggering_code", None):
                    snippet_html = (
                        f'<div class="finding-code">{_html_escape(f.triggering_code)}</div>'
                    )

                suggestion_html = ""
                if f.suggestion:
                    suggestion_html = (
                        f'<p class="finding-suggestion">&#x1F4A1; {_html_escape(f.suggestion[:200])}</p>'
                    )

                trace_html = ""
                if f.trace:
                    steps = []
                    for frame in f.trace:
                        loc = f"L{frame.line}" if frame.line else "?"
                        steps.append(
                            f'<div class="trace-step">{_html_escape(frame.kind.upper())} → {_html_escape(frame.label)} ({loc})</div>'
                        )
                    trace_html = (
                        '<details class="trace-block">'
                        '<summary class="tag" style="cursor:pointer">trace-backed code flow</summary>'
                        + "".join(steps)
                        + '</details>'
                    )

                finding_cards.append(
                    f'<div class="finding" style="border-color:{colour}">'
                    f'  <div class="finding-header">'
                    f'    <span class="badge" style="background:{colour}">{sev.upper()}</span>'
                    f'    <span class="finding-location">{loc}</span>'
                    f'    <span class="finding-title">{_html_escape(f.title)}{cwe_text}</span>'
                    f'  </div>'
                    f'  <div class="finding-desc">{_html_escape(f.description[:300])}</div>'
                    f'  {snippet_html}'
                    f'  {suggestion_html}'
                    f'  {trace_html}'
                    f'  <div class="finding-meta">'
                    f'    <span class="tag">{rule_id}</span>'
                    f'    <span class="tag">confidence {conf_bar}</span>'
                    f'    {tags_html}'
                    f'  </div>'
                    f'</div>'
                )

        body_html = "\n".join(finding_cards)
        file_sections_html.append(
            f'<div class="file-section">'
            f'<div class="file-header">'
            f'  <span>{fp} &nbsp;<span style="color:{_HTML_SEV_COLOUR.get("info","#7f8c8d")};font-size:0.75rem">[{lang}]</span></span>'
            f'  <span><span style="color:{badge_colour};font-weight:700">{badge_text}</span>&nbsp;<span class="toggle">&#x25BC;</span></span>'
            f'</div>'
            f'<div class="file-body">{body_html}</div>'
            f'</div>'
        )

    try:
        version = _gev()
    except Exception:
        version = "?"

    html = _HTML_TEMPLATE.format(
        timestamp=datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        version=version,
        file_count=len(results),
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        total=total,
        security=security,
        quality=quality,
        file_sections="\n".join(file_sections_html),
    )
    return html
