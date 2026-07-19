"""guardmarly.cobol_analyzer — COBOL mainframe security."""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity

def analyze_cobol(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="cobol", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        for m in re.finditer(r'CALL\s+[\'"]SYSTEM[\'"]|CALL\s+[\'"]CBL_OR_RT[\'"]', code, re.IGNORECASE):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="System command execution", description=f"System call at line {line}", line=line,
                suggestion="Validate and restrict system calls.", rule_id="COB-001", cwe="CWE-78",
                agent="cobol-analyzer", confidence=0.85, analysis_kind="pattern"))
        for m in re.finditer(r'PASSWORD|SECRET|TOKEN|KEY\s+PIC\s+X', code, re.IGNORECASE):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.HIGH,
                title="Potential hardcoded credential storage",
                description=f"Sensitive data at line {line}", line=line,
                suggestion="Use external security manager (RACF/ACF2).",
                rule_id="COB-002", cwe="CWE-798", agent="cobol-analyzer",
                confidence=0.60, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"COBOL error: {exc}"
    return result
