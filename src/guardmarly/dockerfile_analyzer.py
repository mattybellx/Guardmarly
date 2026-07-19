"""guardmarly.dockerfile_analyzer — Dockerfile security."""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity

def analyze_dockerfile(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="dockerfile", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        # Running as root
        if not re.search(r'^USER\s+(?!root)', code, re.MULTILINE):
            findings.append(Finding(category="security", severity=Severity.MEDIUM,
                title="Container runs as root", description="No non-root USER specified.",
                line=1, suggestion="Add 'USER 1000' or similar.", rule_id="DF-001",
                cwe="CWE-250", agent="dockerfile-analyzer", confidence=0.90, analysis_kind="pattern"))
        # Exposed secrets via ARG/ENV
        for m in re.finditer(r'(?:ENV|ARG)\s+(?:PASSWORD|SECRET|TOKEN|API_KEY|KEY)\s*=\s*\S+', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.HIGH,
                title="Secret in ENV/ARG", description=f"Secret at line {line}", line=line,
                suggestion="Use build secrets or external secret management.",
                rule_id="DF-002", cwe="CWE-798", agent="dockerfile-analyzer",
                confidence=0.85, analysis_kind="pattern"))
        # curl | bash
        for m in re.finditer(r'curl\s+\S+\s*\|\s*(?:bash|sh|/bin/bash)', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.HIGH,
                title="curl pipe bash", description=f"curl|bash at line {line}", line=line,
                suggestion="Download and verify checksums before executing.",
                rule_id="DF-003", cwe="CWE-494", agent="dockerfile-analyzer",
                confidence=0.85, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"Dockerfile error: {exc}"
    return result
