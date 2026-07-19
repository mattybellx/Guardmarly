"""guardmarly.plsql_analyzer — PL/SQL Oracle security."""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity

def analyze_plsql(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="plsql", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        for m in re.finditer(r'EXECUTE\s+IMMEDIATE\s+.*?(\||\&)', code, re.IGNORECASE):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="SQL Injection via EXECUTE IMMEDIATE",
                description=f"Dynamic SQL at line {line}", line=line,
                suggestion="Use bind variables instead of concatenation.",
                rule_id="PLSQL-001", cwe="CWE-89", agent="plsql-analyzer",
                confidence=0.85, analysis_kind="pattern"))
        for m in re.finditer(r'UTL_HTTP\.REQUEST|UTL_SMTP|UTL_TCP', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.HIGH,
                title="Potentially dangerous network call",
                description=f"UTL_* network call at line {line}", line=line,
                suggestion="Validate and allowlist external hosts.",
                rule_id="PLSQL-002", cwe="CWE-918", agent="plsql-analyzer",
                confidence=0.70, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"PL/SQL error: {exc}"
    return result
