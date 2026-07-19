"""guardmarly.vba_analyzer — VBA/Office macro security."""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity

def analyze_vba(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="vba", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        for m in re.finditer(r'(?:Shell|CreateObject|WScript\.Shell|MSXML2\.ServerXMLHTTP)\s*\(', code, re.IGNORECASE):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="Dangerous Shell/CreateObject call",
                description=f"Potentially malicious call at line {line}", line=line,
                suggestion="Avoid Shell() and CreateObject() with untrusted input.",
                rule_id="VBA-001", cwe="CWE-78", agent="vba-analyzer",
                confidence=0.85, analysis_kind="pattern"))
        for m in re.finditer(r'(?:password|secret|token|key)\s*=\s*"([^"]{6,})"', code, re.IGNORECASE):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.HIGH,
                title="Hardcoded credential in VBA", description=f"Secret at line {line}", line=line,
                suggestion="Use Windows Credential Manager.", rule_id="VBA-002", cwe="CWE-798",
                agent="vba-analyzer", confidence=0.70, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"VBA error: {exc}"
    return result
