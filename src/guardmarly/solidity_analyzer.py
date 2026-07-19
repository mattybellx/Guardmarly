"""guardmarly.solidity_analyzer — Solidity smart contract security."""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity

def analyze_solidity(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="solidity", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        for m in re.finditer(r'tx\.origin\s*==', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="tx.origin used for auth (phishing risk)",
                description=f"tx.origin at line {line}", line=line,
                suggestion="Use msg.sender instead of tx.origin.", rule_id="SO-001",
                cwe="CWE-287", agent="solidity-analyzer", confidence=0.90, analysis_kind="pattern"))
        for m in re.finditer(r'(?:private|internal)\s+key|PRIVATE_KEY\s*=', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.CRITICAL,
                title="Private key exposure risk", description=f"Key at line {line}", line=line,
                suggestion="Never store private keys on-chain.", rule_id="SO-002",
                cwe="CWE-798", agent="solidity-analyzer", confidence=0.85, analysis_kind="pattern"))
        for m in re.finditer(r'selfdestruct|suicide\s*\(', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.HIGH,
                title="selfdestruct usage", description=f"selfdestruct at line {line}", line=line,
                suggestion="Avoid selfdestruct. Use upgradeable patterns.", rule_id="SO-003",
                cwe="CWE-284", agent="solidity-analyzer", confidence=0.85, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"Solidity error: {exc}"
    return result
