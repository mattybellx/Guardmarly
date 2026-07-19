"""guardmarly.haskell_analyzer — Haskell security."""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity

def analyze_haskell(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="haskell", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        for m in re.finditer(r'(?:password|secret|apiKey|token)\s*=\s*"([^"]{8,})"', code, re.IGNORECASE):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.HIGH,
                title="Hardcoded secret", description=f"Secret at line {line}", line=line,
                suggestion="Use environment variables.", rule_id="HS-001", cwe="CWE-798",
                agent="haskell-analyzer", confidence=0.65, analysis_kind="pattern"))
        for m in re.finditer(r'System\.Process\.(?:system|rawSystem|readProcess)', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="Command Injection", description=f"CMDi at line {line}", line=line,
                suggestion="Sanitize args.", rule_id="HS-002", cwe="CWE-78",
                agent="haskell-analyzer", confidence=0.80, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"Haskell error: {exc}"
    return result
