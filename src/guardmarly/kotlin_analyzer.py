"""
guardmarly.kotlin_analyzer — Security analyzer for Kotlin.
Covers: SQLi, CMDi, PathTrav, HardcodedSecrets, WeakCrypto, SSRF.
"""
from __future__ import annotations
import logging, re
from typing import List, FrozenSet
from guardmarly._types import AnalysisResult, Finding, Severity
from guardmarly.kotlin_parser import parse_kotlin

_log = logging.getLogger(__name__)

_KT_SQLI = "KT-001"; _KT_CMDI = "KT-002"; _KT_PATH_TRAV = "KT-003"
_KT_HARDCODED = "KT-004"; _KT_WEAK_CRYPTO = "KT-005"; _KT_SSRF = "KT-006"

_TAINT: FrozenSet[str] = frozenset({
    "request.getParameter", "request.getQueryString", "readLine()",
    "Scanner(", "args[", "System.getenv", "getQueryParameter",
})

_SINKS = {
    "executeQuery": ("CWE-89", "SQL Injection via executeQuery", "critical"),
    "execute(": ("CWE-89", "SQL Injection via execute", "critical"),
    "Runtime.getRuntime().exec": ("CWE-78", "Command Injection via Runtime.exec", "critical"),
    "ProcessBuilder": ("CWE-78", "Command Injection via ProcessBuilder", "critical"),
    "File(": ("CWE-22", "Path Traversal via File", "high"),
    "URL(": ("CWE-918", "SSRF via URL", "high"),
    "MessageDigest.getInstance(\"MD5": ("CWE-327", "Weak hash MD5", "medium"),
    "MessageDigest.getInstance(\"SHA-1": ("CWE-327", "Weak hash SHA-1", "medium"),
}

_SECRET_RE = re.compile(r'(?:password|secret|apiKey|token|API_KEY)\s*=\s*"([^"]{8,})"', re.IGNORECASE)


def analyze_kotlin(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="kotlin", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        kf = parse_kotlin(code, filename)
        tainted: set[str] = set()

        for a in kf.assigns:
            if any(s in a.value_text for s in _TAINT):
                tainted.add(a.target)

        for c in kf.calls:
            cl = c.name.lower()
            for pat, (cwe, title, sev) in _SINKS.items():
                if pat.lower() in cl:
                    at = " ".join(c.args)
                    if any(t in at for t in tainted) or any(s in at for s in _TAINT):
                        severity = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM}.get(sev, Severity.MEDIUM)
                        findings.append(Finding(category="security", severity=severity, title=title,
                            description=f"Tainted data reaches {c.name} at line {c.line}",
                            line=c.line, suggestion="Sanitize input.",
                            rule_id=_KT_SQLI if "query" in cl or "execute" in cl else
                                    _KT_CMDI if "runtime" in cl or "process" in cl else
                                    _KT_PATH_TRAV if "file" in cl else
                                    _KT_SSRF if "url" in cl else _KT_WEAK_CRYPTO,
                            cwe=cwe, agent="kotlin-analyzer", confidence=0.75, analysis_kind="taint"))

        for m in _SECRET_RE.finditer(code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.HIGH,
                title="Hardcoded secret", description=f"Hardcoded secret at line {line}",
                line=line, suggestion="Use environment variables or a secrets manager.",
                rule_id=_KT_HARDCODED, cwe="CWE-798", agent="kotlin-analyzer",
                confidence=0.65, analysis_kind="pattern"))

        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"Kotlin analyzer error: {exc}"
    return result
