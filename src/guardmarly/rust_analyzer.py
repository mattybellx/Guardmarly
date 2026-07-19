"""
guardmarly.rust_analyzer — AST-walking security analyzer for Rust.
Uses tree-sitter-rust via Rust core. Covers: unsafe, secrets, CMDi, crypto, TOCTOU.
"""
from __future__ import annotations
import logging, re
from typing import Dict, FrozenSet, List, Optional, Set, Tuple
from guardmarly._types import AnalysisResult, Finding, Severity
from guardmarly.rust_parser import HAS_RUST_CORE, parse_rust, RsCall, RsAssign, RsFile

_log = logging.getLogger(__name__)

_RS_UNSAFE="RS-001"; _RS_HARDCODED="RS-002"; _RS_CMDI="RS-003"
_RS_WEAK_CRYPTO="RS-004"; _RS_PANIC="RS-005"; _RS_TOCTOU="RS-006"

_TAINT_SOURCES: FrozenSet[str] = frozenset({
    "std::env::args", "std::env::var", "std::io::stdin",
    "env::args", "env::var", "args()", "var(",
    "read_line", "stdin().read",
})

_SINKS: Dict[str, Tuple[str, str, str]] = {
    "Command::new": ("CWE-78", "Command Injection via Command::new", "critical"),
    "std::process::Command": ("CWE-78", "Command Injection via Command", "critical"),
    "std::fs::read": ("CWE-22", "Path Traversal via fs::read", "high"),
    "std::fs::write": ("CWE-22", "Path Traversal via fs::write", "high"),
    "std::fs::read_to_string": ("CWE-22", "Path Traversal", "high"),
    "std::fs::OpenOptions": ("CWE-22", "Path Traversal via OpenOptions", "high"),
}

_SECRET_RE = re.compile(r'(?:password|secret|token|api_key|auth_key|SECRET|TOKEN|API_KEY)', re.IGNORECASE)
_SECRET_VAL_RE = re.compile(r'["\'][A-Za-z0-9+/=\-]{20,}["\']|["\'][0-9a-fA-F]{32,}["\']|["\']sk-[a-zA-Z0-9\-]{20,}["\']')
_WEAK_CRYPTO_RE = re.compile(r'\b(?:md5|sha1|MD5|SHA1)\b')
_TOCTOU_RE = re.compile(r'metadata\s*\(.*\)[\s\S]{0,200}(?:read|write|open|remove_file)')


def _analyze_ast(rf: RsFile, code: str) -> List[Finding]:
    findings: List[Finding] = []
    tainted: Set[str] = set()

    for a in rf.assigns:
        if any(s in a.value_text for s in _TAINT_SOURCES):
            tainted.add(a.target)

    # Unsafe blocks
    if rf.has_unsafe:
        for m in re.finditer(r'\bunsafe\s*\{', code):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(category="security", severity=Severity.MEDIUM,
                title="Unsafe block detected", description=f"unsafe block at line {line}",
                line=line, suggestion="Review unsafe code. Prefer safe abstractions.",
                rule_id=_RS_UNSAFE, cwe="CWE-119", agent="rust-ast-analyzer",
                confidence=0.90, analysis_kind="ast"))

    # Sink calls
    for c in rf.calls:
        cl = c.name.lower()
        matched = None; best = 0
        for pat, info in _SINKS.items():
            if pat.lower() in cl and len(pat) > best:
                matched = info; best = len(pat)
        if not matched: continue

        cwe, title, sev = matched
        severity = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM}.get(sev, Severity.MEDIUM)
        at = " ".join(c.args)
        if not any(t in at for t in tainted) and not any(s in at for s in _TAINT_SOURCES):
            continue

        findings.append(Finding(category="security", severity=severity, title=title,
            description=f"Tainted data reaches {c.name} at line {c.line}",
            line=c.line, suggestion="Validate and sanitize all external input.",
            rule_id=_RS_CMDI if "command" in cl else _RS_TOCTOU, cwe=cwe,
            agent="rust-ast-analyzer", confidence=0.80, analysis_kind="taint-tracking"))

    # Hardcoded secrets
    for a in rf.assigns:
        if _SECRET_RE.search(a.target) and _SECRET_VAL_RE.search(a.value_text):
            if not re.search(r'(?:example|sample|test|dummy)', a.value_text, re.IGNORECASE):
                findings.append(Finding(category="security", severity=Severity.HIGH,
                    title="Hardcoded secret", description=f"Secret in '{a.target}' at line {a.line}",
                    line=a.line, suggestion="Use environment variables or a secrets manager.",
                    rule_id=_RS_HARDCODED, cwe="CWE-798", agent="rust-ast-analyzer",
                    confidence=0.65, analysis_kind="pattern-ast"))

    # Weak crypto
    for m in _WEAK_CRYPTO_RE.finditer(code):
        findings.append(Finding(category="security", severity=Severity.MEDIUM,
            title="Weak cryptographic hash", description=f"Weak hash at line {1 + code[:m.start()].count(chr(10))}",
            line=1 + code[:m.start()].count('\n'),
            suggestion="Use sha2, sha3, or blake3 instead of MD5/SHA1.",
            rule_id=_RS_WEAK_CRYPTO, cwe="CWE-327", agent="rust-ast-analyzer",
            confidence=0.70, analysis_kind="pattern"))

    # Sensitive data in panic/unwrap (CWE-532)
    for m in re.finditer(r'(?:password|secret|token|key|auth|credential)\s*\.\s*(?:unwrap|expect)\s*\(', code, re.IGNORECASE):
        line = 1 + code[:m.start()].count('\n')
        findings.append(Finding(category="security", severity=Severity.MEDIUM,
            title="Sensitive data in panic/unwrap", description=f"Sensitive value may leak in panic at line {line}",
            line=line, suggestion="Use proper error handling instead of unwrap/expect on sensitive data.",
            rule_id=_RS_PANIC, cwe="CWE-532", agent="rust-ast-analyzer",
            confidence=0.50, analysis_kind="pattern"))

    # TOCTOU
    for m in _TOCTOU_RE.finditer(code):
        line = 1 + code[:m.start()].count('\n')
        findings.append(Finding(category="security", severity=Severity.MEDIUM,
            title="Potential TOCTOU race condition", description=f"metadata() then file op at line {line}",
            line=line, suggestion="Use atomic file operations or flock().",
            rule_id=_RS_TOCTOU, cwe="CWE-362", agent="rust-ast-analyzer",
            confidence=0.45, analysis_kind="pattern"))

    return findings


def _scan_regex(code: str, findings: List[Finding]):
    import re as _re
    def _add(rid, t, cwe, sev, m, sug, conf=0.7):
        ln = 1 + code[:m.start()].count('\n')
        findings.append(Finding(category="security", severity=sev, title=t,
            description=f"{cwe} at line {ln}", line=ln, suggestion=sug,
            rule_id=rid, cwe=cwe, agent="rust-regex", confidence=conf, analysis_kind="pattern"))

    for m in _re.finditer(r'\bunsafe\s*\{', code):
        _add(_RS_UNSAFE, "Unsafe block", "CWE-119", Severity.MEDIUM, m, "Review unsafe code.", 0.90)
    for m in _re.finditer(r'(?:const|static|let)\s+(?:API_KEY|SECRET|TOKEN|PASSWORD)\s*=\s*"[^"]{8,}', code, _re.IGNORECASE):
        _add(_RS_HARDCODED, "Hardcoded secret", "CWE-798", Severity.HIGH, m, "Use env vars.", 0.65)
    for m in _re.finditer(r'Command::new\s*\([^)]*\)\s*\.\s*(?:arg|args)\s*\(', code):
        _add(_RS_CMDI, "Command Injection", "CWE-78", Severity.CRITICAL, m, "Validate args.", 0.75)
    for m in _re.finditer(r'\b(?:md5|sha1)\b', code):
        _add(_RS_WEAK_CRYPTO, "Weak crypto", "CWE-327", Severity.MEDIUM, m, "Use sha2/sha3.", 0.70)
    for m in _re.finditer(r'metadata\s*\([^)]+\)[\s\S]{0,200}(?:read|write|open|remove_file)', code):
        _add(_RS_TOCTOU, "TOCTOU", "CWE-362", Severity.MEDIUM, m, "Use atomic ops.", 0.45)


def analyze_rust(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="rust", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        if HAS_RUST_CORE:
            rf = parse_rust(code, filename)
            findings = _analyze_ast(rf, code)
        else:
            _scan_regex(code, findings)
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"Rust analyzer error: {exc}"
        _log.warning("Rust analysis failed: %s", str(exc).replace('\n',' ')[:200])
    return result
