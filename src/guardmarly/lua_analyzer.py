"""guardmarly.lua_analyzer — Lua security analyzer."""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity

def analyze_lua(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="lua", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        for m in re.finditer(r'(?:os\.execute|io\.popen)\s*\(.*?(?:arg\[|io\.read)', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="Command Injection", description=f"CMDi at line {line}", line=line,
                suggestion="Validate and sanitize command args.", rule_id="LU-001", cwe="CWE-78",
                agent="lua-analyzer", confidence=0.80, analysis_kind="pattern"))
        for m in re.finditer(r'(?:password|secret|api_key|token)\s*=\s*[\'"]([^\'"]{8,})[\'"]', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.HIGH,
                title="Hardcoded secret", description=f"Secret at line {line}", line=line,
                suggestion="Use environment variables.", rule_id="LU-002", cwe="CWE-798",
                agent="lua-analyzer", confidence=0.65, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"Lua error: {exc}"
    return result
