"""
guardmarly.swift_analyzer — Security analyzer for Swift.
Covers: SQLi, CMDi, PathTrav, HardcodedSecrets, WeakCrypto.
"""
from __future__ import annotations
import logging, re
from typing import List, FrozenSet
from guardmarly._types import AnalysisResult, Finding, Severity
from guardmarly.swift_parser import parse_swift

_SW_SQLI="SW-001"; _SW_CMDI="SW-002"; _SW_PATH_TRAV="SW-003"; _SW_HARDCODED="SW-004"; _SW_WEAK_CRYPTO="SW-005"

_TAINT: FrozenSet[str] = frozenset({"request.parameters", "request.query", "readLine()", "CommandLine.arguments", "ProcessInfo.processInfo.environment"})
_SECRET_RE = re.compile(r'(?:password|secret|apiKey|token)\s*=\s*"([^"]{8,})"', re.IGNORECASE)

_SINKS = {
    "execute(": ("CWE-89", "SQL Injection via execute", "critical"),
    "Process(": ("CWE-78", "Command Injection via Process", "critical"),
    "FileManager.default.contents": ("CWE-22", "Path Traversal", "high"),
    "Insecure.MD5": ("CWE-327", "Weak hash MD5", "medium"),
    "Insecure.SHA1": ("CWE-327", "Weak hash SHA1", "medium"),
    "CC_MD5": ("CWE-327", "Weak hash MD5", "medium"),
    "CC_SHA1": ("CWE-327", "Weak hash SHA1", "medium"),
}

def analyze_swift(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="swift", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        sf = parse_swift(code, filename)
        for c in sf.calls:
            cl = c.name.lower()
            for pat, (cwe, title, sev) in _SINKS.items():
                if pat.lower() in cl:
                    at = " ".join(c.args)
                    if any(s in at for s in _TAINT):
                        sev_e = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM}.get(sev, Severity.MEDIUM)
                        findings.append(Finding(category="security", severity=sev_e, title=title,
                            description=f"Tainted data in {c.name} at line {c.line}", line=c.line,
                            suggestion="Sanitize input.", rule_id=_SW_SQLI if "execute" in cl else _SW_CMDI if "process" in cl else _SW_PATH_TRAV if "file" in cl else _SW_WEAK_CRYPTO,
                            cwe=cwe, agent="swift-analyzer", confidence=0.75, analysis_kind="taint"))
        for m in _SECRET_RE.finditer(code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.HIGH, title="Hardcoded secret",
                description=f"Secret at line {line}", line=line,
                suggestion="Use environment variables.", rule_id=_SW_HARDCODED, cwe="CWE-798",
                agent="swift-analyzer", confidence=0.65, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"Swift analyzer error: {exc}"
    return result
