"""guardmarly.elixir_analyzer — Elixir/Phoenix security analyzer."""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity

def analyze_elixir(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="elixir", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        for m in re.finditer(r'Ecto\.Adapters\.SQL\.query|Repo\.query|Ecto\.Query', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="Potential SQL Injection", description=f"Raw SQL at line {line}", line=line,
                suggestion="Use Ecto query DSL or parameterized queries.", rule_id="EX-001",
                cwe="CWE-89", agent="elixir-analyzer", confidence=0.75, analysis_kind="pattern"))
        for m in re.finditer(r'System\.cmd|:os\.cmd|System\.shell', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="Command Injection", description=f"CMDi at line {line}", line=line,
                suggestion="Use System.cmd/3 with arg list.", rule_id="EX-002", cwe="CWE-78",
                agent="elixir-analyzer", confidence=0.80, analysis_kind="pattern"))
        for m in re.finditer(r'(?:password|secret|api_key|token):\s*"([^"]{8,})"', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.HIGH,
                title="Hardcoded secret", description=f"Secret at line {line}", line=line,
                suggestion="Use environment variables.", rule_id="EX-003", cwe="CWE-798",
                agent="elixir-analyzer", confidence=0.65, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"Elixir error: {exc}"
    return result
