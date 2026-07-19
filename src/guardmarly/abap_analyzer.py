"""guardmarly.abap_analyzer — ABAP/SAP security."""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity

def analyze_abap(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="abap", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        for m in re.finditer(r'(?:SELECT|INSERT|UPDATE|DELETE)\s+(?!.*ORDER\s+BY)', code, re.IGNORECASE):
            if 'CONCATENATE' in code[max(0,m.start()-200):m.end()]:
                line = 1 + code[:m.start()].count('\n')
                findings.append(Finding(category="security", severity=Severity.CRITICAL,
                    title="Potential SQL Injection via concatenation",
                    description=f"Dynamic SQL at line {line}", line=line,
                    suggestion="Use parameterized Open SQL.", rule_id="ABAP-001", cwe="CWE-89",
                    agent="abap-analyzer", confidence=0.75, analysis_kind="pattern"))
        for m in re.finditer(r'CALL\s+FUNCTION.*?(?:RFC|HTTP)', code, re.IGNORECASE):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.MEDIUM,
                title="External RFC/HTTP call", description=f"Remote call at line {line}", line=line,
                suggestion="Validate RFC destinations.", rule_id="ABAP-002", cwe="CWE-918",
                agent="abap-analyzer", confidence=0.60, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"ABAP error: {exc}"
    return result
