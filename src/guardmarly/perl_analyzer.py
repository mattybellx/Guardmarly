"""guardmarly.perl_analyzer — Perl security."""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity

def analyze_perl(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="perl", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        for m in re.finditer(r'(?:system|exec|qx|`)\s*[\(].*?\$', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="Command Injection", description=f"CMDi at line {line}", line=line,
                suggestion="Use taint mode (-T) and sanitize input.", rule_id="PL-001", cwe="CWE-78",
                agent="perl-analyzer", confidence=0.80, analysis_kind="pattern"))
        for m in re.finditer(r'DBI|->prepare|->execute|->do\s*\(.*?\$', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="Potential SQL Injection", description=f"SQLi at line {line}", line=line,
                suggestion="Use placeholders: ->prepare('... WHERE id = ?')", rule_id="PL-002", cwe="CWE-89",
                agent="perl-analyzer", confidence=0.75, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"Perl error: {exc}"
    return result
