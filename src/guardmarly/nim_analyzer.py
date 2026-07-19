"""guardmarly.nim_analyzer — Nim security."""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity

def analyze_nim(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="nim", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        for m in re.finditer(r'execShellCmd|osproc\.execCmd|startProcess', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="Command Injection", description=f"CMDi at line {line}", line=line,
                suggestion="Validate command args.", rule_id="NM-001", cwe="CWE-78",
                agent="nim-analyzer", confidence=0.80, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"Nim error: {exc}"
    return result
