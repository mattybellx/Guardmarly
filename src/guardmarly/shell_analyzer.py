"""guardmarly.shell_analyzer — Shell/Bash security."""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity

def analyze_shell(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="shell", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        for m in re.finditer(r'(?:curl|wget)\s+\S+\s*\|\s*(?:bash|sh|/bin/bash)', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.HIGH,
                title="curl pipe bash", description=f"curl|bash at line {line}", line=line,
                suggestion="Download and verify checksums first.", rule_id="SH-001",
                cwe="CWE-494", agent="shell-analyzer", confidence=0.85, analysis_kind="pattern"))
        for m in re.finditer(r'(?:PASSWORD|SECRET|TOKEN|API_KEY|KEY)\s*=\s*[\'"]([^\'"]{6,})[\'"]', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.HIGH,
                title="Hardcoded secret", description=f"Secret at line {line}", line=line,
                suggestion="Use environment variables or a secrets manager.", rule_id="SH-002",
                cwe="CWE-798", agent="shell-analyzer", confidence=0.75, analysis_kind="pattern"))
        for m in re.finditer(r'(?:eval\s+|bash\s+-c\s+|sh\s+-c\s+).*?\$', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.MEDIUM,
                title="Dynamic command execution", description=f"eval/bash -c at line {line}", line=line,
                suggestion="Avoid dynamic command construction.", rule_id="SH-003",
                cwe="CWE-78", agent="shell-analyzer", confidence=0.60, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"Shell error: {exc}"
    return result
