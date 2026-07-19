"""guardmarly.yaml_analyzer — YAML config security (K8s, CI, etc.)."""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity

def analyze_yaml(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="yaml", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        # K8s privileged containers
        for m in re.finditer(r'privileged:\s*true', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.HIGH,
                title="Privileged container", description=f"privileged:true at line {line}", line=line,
                suggestion="Remove privileged mode or use minimal capabilities.",
                rule_id="YM-001", cwe="CWE-250", agent="yaml-analyzer",
                confidence=0.90, analysis_kind="pattern"))
        # K8s runAsRoot
        for m in re.finditer(r'runAsNonRoot:\s*false', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.MEDIUM,
                title="Container may run as root", description=f"runAsNonRoot:false at line {line}", line=line,
                suggestion="Set runAsNonRoot:true and specify runAsUser.",
                rule_id="YM-002", cwe="CWE-250", agent="yaml-analyzer",
                confidence=0.85, analysis_kind="pattern"))
        # Hardcoded secrets in CI
        for m in re.finditer(r'(?:PASSWORD|SECRET|TOKEN|API_KEY):\s*\S+', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.HIGH,
                title="Potential hardcoded secret in YAML", description=f"Secret at line {line}", line=line,
                suggestion="Use CI secrets or external secret management.",
                rule_id="YM-003", cwe="CWE-798", agent="yaml-analyzer",
                confidence=0.70, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"YAML error: {exc}"
    return result
