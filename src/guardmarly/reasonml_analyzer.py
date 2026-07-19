"""guardmarly.reasonml_analyzer — ReasonML/ReScript security."""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity

def analyze_reasonml(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="reasonml", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        for m in re.finditer(r'Unix\.system|Unix\.open_process|Sys\.command', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="Command Injection", description=f"CMDi at line {line}", line=line,
                suggestion="Validate command input.", rule_id="RE-001", cwe="CWE-78",
                agent="reasonml-analyzer", confidence=0.80, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"ReasonML error: {exc}"
    return result
