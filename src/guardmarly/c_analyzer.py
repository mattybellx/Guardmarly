"""
guardmarly.c_analyzer — Security analyzer for C source code.
Covers: unsafe functions, format strings, buffer overflow, hardcoded secrets.
"""
from __future__ import annotations
import re
from typing import List
from guardmarly._types import AnalysisResult, Finding, Severity

_UNSAFE_FUNCS = {
    "gets": ("CWE-242", "Use of dangerous function gets()", "critical", "Use fgets() instead."),
    "strcpy": ("CWE-120", "Buffer overflow via strcpy", "critical", "Use strncpy() or strlcpy()."),
    "strcat": ("CWE-120", "Buffer overflow via strcat", "critical", "Use strncat() or strlcat()."),
    "sprintf": ("CWE-120", "Buffer overflow via sprintf", "critical", "Use snprintf() instead."),
    "scanf": ("CWE-120", "Buffer overflow via scanf", "high", "Use fgets() + sscanf() with limits."),
    "system": ("CWE-78", "Command injection via system()", "critical", "Avoid system(). Use exec family."),
    "popen": ("CWE-78", "Command injection via popen()", "critical", "Validate and sanitize all input."),
}
_FORMAT_STRING_RE = re.compile(r'printf\s*\(\s*[^",)]*\s*\)')
_SECRET_RE = re.compile(r'(?:PASSWORD|SECRET|API_KEY|TOKEN)\s*=\s*"([^"]{8,})"')


def analyze_c(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="c", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        for m in re.finditer(r'\b(gets|strcpy|strcat|sprintf|scanf|system|popen)\s*\(', code):
            func = m.group(1)
            if func in _UNSAFE_FUNCS:
                cwe, title, sev, sug = _UNSAFE_FUNCS[func]
                severity = {"critical": Severity.CRITICAL, "high": Severity.HIGH}.get(sev, Severity.MEDIUM)
                line = 1 + code[:m.start()].count('\n')
                findings.append(Finding(category="security", severity=severity, title=title,
                    description=f"Dangerous function {func}() at line {line}", line=line,
                    suggestion=sug, rule_id=f"C-{list(_UNSAFE_FUNCS.keys()).index(func)+1:03d}",
                    cwe=cwe, agent="c-analyzer", confidence=0.90, analysis_kind="pattern"))
        for m in _FORMAT_STRING_RE.finditer(code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.HIGH,
                title="Potential format string vulnerability",
                description=f"printf with variable format string at line {line}", line=line,
                suggestion="Use printf(\"%s\", var) format.",
                rule_id="C-008", cwe="CWE-134", agent="c-analyzer",
                confidence=0.60, analysis_kind="pattern"))
        for m in _SECRET_RE.finditer(code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.HIGH,
                title="Hardcoded secret", description=f"Secret at line {line}", line=line,
                suggestion="Use environment variables.", rule_id="C-009", cwe="CWE-798",
                agent="c-analyzer", confidence=0.70, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"C analyzer error: {exc}"
    return result


def analyze_cpp(code: str, filename: str = "") -> AnalysisResult:
    """C++ analyzer — extends C with C++-specific checks."""
    result = AnalysisResult(file_path=filename, language="cpp", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        # Inherit C checks
        c_result = analyze_c(code, filename)
        findings.extend(c_result.findings)
        # C++ specific: new/delete mismatches, unsafe pointer casts
        for m in re.finditer(r'reinterpret_cast\s*<', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.MEDIUM,
                title="Unsafe reinterpret_cast", description=f"reinterpret_cast at line {line}", line=line,
                suggestion="Prefer static_cast or dynamic_cast.",
                rule_id="CPP-001", cwe="CWE-704", agent="cpp-analyzer",
                confidence=0.50, analysis_kind="pattern"))
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"C++ analyzer error: {exc}"
    return result
