"""guardmarly.fsharp_analyzer — F#/.NET security."""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity

def analyze_fsharp(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="fsharp", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        for m in re.finditer(r'System\.Diagnostics\.Process\.Start|Process\.Start\s*\(', code, re.IGNORECASE):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="Command Injection via Process.Start", description=f"CMDi at line {line}", line=line,
                suggestion="Validate process arguments.", rule_id="FS-001", cwe="CWE-78",
                agent="fsharp-analyzer", confidence=0.80, analysis_kind="pattern"))
        for m in re.finditer(r'SQL\b|SqlCommand|ExecuteReader|ExecuteNonQuery', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="Potential SQL Injection", description=f"SQL at line {line}", line=line,
                suggestion="Use parameterized queries.", rule_id="FS-002", cwe="CWE-89",
                agent="fsharp-analyzer", confidence=0.65, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"F# error: {exc}"
    return result
