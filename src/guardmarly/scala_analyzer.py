"""guardmarly.scala_analyzer — Security analyzer for Scala."""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity
from guardmarly.scala_parser import parse_scala

def analyze_scala(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="scala", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        # SQLi
        for m in re.finditer(r'(?:executeQuery|executeUpdate|execute)\s*\(.*?(?:request\.|params|getParameter)', code, re.IGNORECASE):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="SQL Injection", description=f"SQLi at line {line}", line=line,
                suggestion="Use prepared statements.", rule_id="SC-001", cwe="CWE-89",
                agent="scala-analyzer", confidence=0.80, analysis_kind="pattern"))
        # CMDi
        for m in re.finditer(r'(?:Process|Runtime\.getRuntime\.exec|sys\.process)\s*\(.*?(?:request\.|args)', code, re.IGNORECASE):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="Command Injection", description=f"CMDi at line {line}", line=line,
                suggestion="Sanitize command args.", rule_id="SC-002", cwe="CWE-78",
                agent="scala-analyzer", confidence=0.80, analysis_kind="pattern"))
        # Secrets
        for m in re.finditer(r'(?:password|secret|apiKey|token)\s*=\s*"([^"]{8,})"', code, re.IGNORECASE):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.HIGH,
                title="Hardcoded secret", description=f"Secret at line {line}", line=line,
                suggestion="Use environment variables.", rule_id="SC-003", cwe="CWE-798",
                agent="scala-analyzer", confidence=0.65, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"Scala error: {exc}"
    return result
