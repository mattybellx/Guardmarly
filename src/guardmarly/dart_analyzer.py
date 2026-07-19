"""guardmarly.dart_analyzer — Dart security analyzer."""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity

def analyze_dart(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="dart", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        for m in re.finditer(r'(?:query|execute)\s*\(.*?(?:request\.|params)', code, re.IGNORECASE):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="SQL Injection", description=f"SQLi at line {line}", line=line,
                suggestion="Use parameterized queries.", rule_id="DT-001", cwe="CWE-89",
                agent="dart-analyzer", confidence=0.80, analysis_kind="pattern"))
        for m in re.finditer(r'Process\.run\s*\(.*?(?:request\.|params)', code, re.IGNORECASE):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="Command Injection", description=f"CMDi at line {line}", line=line,
                suggestion="Sanitize command args.", rule_id="DT-002", cwe="CWE-78",
                agent="dart-analyzer", confidence=0.80, analysis_kind="pattern"))
        for m in re.finditer(r'(?:password|secret|apiKey|token)\s*=\s*[\'"]([^\'"]{8,})[\'"]', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.HIGH,
                title="Hardcoded secret", description=f"Secret at line {line}", line=line,
                suggestion="Use environment variables.", rule_id="DT-003", cwe="CWE-798",
                agent="dart-analyzer", confidence=0.65, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"Dart error: {exc}"
    return result
