"""guardmarly.clojure_analyzer — Clojure security analyzer."""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity

def analyze_clojure(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="clojure", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        for m in re.finditer(r'\(jdbc/query|\(jdbc/execute!|\(clojure\.java\.jdbc/query', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="SQL Injection", description=f"SQLi at line {line}", line=line,
                suggestion="Use parameterized queries.", rule_id="CL-001", cwe="CWE-89",
                agent="clojure-analyzer", confidence=0.80, analysis_kind="pattern"))
        for m in re.finditer(r'\(clojure\.java\.shell/sh|\(shell/sh', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="Command Injection", description=f"CMDi at line {line}", line=line,
                suggestion="Sanitize shell args.", rule_id="CL-002", cwe="CWE-78",
                agent="clojure-analyzer", confidence=0.80, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"Clojure error: {exc}"
    return result
