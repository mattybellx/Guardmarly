"""guardmarly.objc_analyzer — Objective-C security."""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity

def analyze_objc(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="objc", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        for m in re.finditer(r'system\s*\(|NSTask\s+|popen\s*\(', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="Command Injection", description=f"CMDi at line {line}", line=line,
                suggestion="Validate command input.", rule_id="OBJC-001", cwe="CWE-78",
                agent="objc-analyzer", confidence=0.80, analysis_kind="pattern"))
        for m in re.finditer(r'(?:password|secret|apiKey|token)\s*=\s*@"([^"]{8,})"', code, re.IGNORECASE):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.HIGH,
                title="Hardcoded secret", description=f"Secret at line {line}", line=line,
                suggestion="Use Keychain.", rule_id="OBJC-002", cwe="CWE-798",
                agent="objc-analyzer", confidence=0.65, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"ObjC error: {exc}"
    return result
