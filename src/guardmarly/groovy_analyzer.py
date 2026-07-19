"""guardmarly.groovy_analyzer — Groovy/Jenkins security."""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity

def analyze_groovy(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="groovy", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        for m in re.finditer(r'(?:execute|Runtime\.exec|ProcessBuilder)\s*\(.*?(?:params\.|request\.|args)', code, re.IGNORECASE):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="Command Injection", description=f"CMDi at line {line}", line=line,
                suggestion="Sanitize command args.", rule_id="GR-001", cwe="CWE-78",
                agent="groovy-analyzer", confidence=0.80, analysis_kind="pattern"))
        for m in re.finditer(r'password|secret|apiKey|token"', code, re.IGNORECASE):
            if '="' in code[max(0, m.start()-20):m.end()+50]:
                line = 1 + code[:m.start()].count('\n')
                findings.append(Finding(category="security", severity=Severity.HIGH,
                    title="Potential hardcoded secret", description=f"Secret at line {line}", line=line,
                    suggestion="Use Jenkins credentials or env vars.", rule_id="GR-002", cwe="CWE-798",
                    agent="groovy-analyzer", confidence=0.60, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"Groovy error: {exc}"
    return result
