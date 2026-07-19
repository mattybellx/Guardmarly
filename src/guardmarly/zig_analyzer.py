"""guardmarly.zig_analyzer — Zig security."""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity

def analyze_zig(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="zig", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        for m in re.finditer(r'std\.process\.Child\.init|std\.os\.(?:system|execv)', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="Command Injection", description=f"CMDi at line {line}", line=line,
                suggestion="Validate command args.", rule_id="ZG-001", cwe="CWE-78",
                agent="zig-analyzer", confidence=0.80, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"Zig error: {exc}"
    return result
