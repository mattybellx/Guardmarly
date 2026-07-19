"""guardmarly.nix_analyzer — Nix security."""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity

def analyze_nix(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="nix", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        for m in re.finditer(r'builtins\.(?:fetchurl|fetchTarball|fetchGit)\s+(?!.*sha256)', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.HIGH,
                title="Unpinned fetch without integrity hash",
                description=f"Unpinned fetch at line {line}", line=line,
                suggestion="Add sha256 hash to ensure reproducibility.", rule_id="NX-001",
                cwe="CWE-494", agent="nix-analyzer", confidence=0.85, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"Nix error: {exc}"
    return result
