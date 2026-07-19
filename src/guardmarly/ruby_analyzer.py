"""
guardmarly.ruby_analyzer — AST-walking security analyzer for Ruby source code.

Uses tree-sitter-ruby via Rust core. 15 CWE types.
"""

from __future__ import annotations

import logging, re
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from guardmarly._types import AnalysisResult, Finding, Severity
from guardmarly.ruby_parser import HAS_RUST_RUBY, parse_ruby, RbCall, RbAssign, RbFile, RbRoute

_log = logging.getLogger(__name__)

_RB_SQLI="RB-001"; _RB_CMDI="RB-002"; _RB_PATH_TRAV="RB-003"
_RB_OPEN_REDIR="RB-004"; _RB_DESERIAL="RB-005"; _RB_WEAK_CRYPTO="RB-006"
_RB_HARDCODED="RB-007"; _RB_MISSING_AUTH="RB-008"; _RB_MASS_ASSIGN="RB-009"
_RB_CSRF="RB-010"; _RB_SSRF="RB-011"; _RB_CODE_INJ="RB-012"
_RB_LOG_INJ="RB-013"; _RB_XSS="RB-014"; _RB_SSTI="RB-015"

_TAINT_SOURCES: FrozenSet[str] = frozenset({
    "params", "params[", "request.", "cookies", "session",
    "env[", "ENV[", "gets", "ARGV", "ARGV[",
})

_SINKS: Dict[str, Tuple[str, str, str]] = {
    "find_by_sql": ("CWE-89", "SQL Injection via find_by_sql", "critical"),
    ".where(": ("CWE-89", "SQL Injection via where()", "critical"),
    ".select(": ("CWE-89", "SQL Injection via select()", "critical"),
    ".execute(": ("CWE-89", "SQL Injection via execute()", "critical"),
    "system(": ("CWE-78", "Command Injection via system()", "critical"),
    "exec(": ("CWE-78", "Command Injection via exec()", "critical"),
    "IO.popen": ("CWE-78", "Command Injection via IO.popen", "critical"),
    "Open3.": ("CWE-78", "Command Injection via Open3", "critical"),
    "File.read": ("CWE-22", "Path Traversal via File.read", "high"),
    "File.open": ("CWE-22", "Path Traversal via File.open", "high"),
    "File.join": ("CWE-22", "Path Traversal via File.join", "high"),
    "send_file": ("CWE-22", "Path Traversal via send_file", "high"),
    "eval(": ("CWE-95", "Code Injection via eval()", "critical"),
    "class_eval": ("CWE-95", "Code Injection via class_eval", "critical"),
    "instance_eval": ("CWE-95", "Code Injection via instance_eval", "critical"),
    "YAML.load": ("CWE-502", "Unsafe Deserialization via YAML.load", "critical"),
    "Marshal.load": ("CWE-502", "Unsafe Deserialization via Marshal.load", "critical"),
    "Net::HTTP.": ("CWE-918", "SSRF via Net::HTTP", "high"),
    "HTTParty.": ("CWE-918", "SSRF via HTTParty", "high"),
    "open(": ("CWE-918", "SSRF via open()", "high"),
    "redirect_to": ("CWE-601", "Open Redirect via redirect_to", "high"),
    "raw(": ("CWE-79", "XSS via raw() helper", "high"),
    "html_safe": ("CWE-79", "XSS via html_safe", "high"),
    "render(": ("CWE-1336", "SSTI via render()", "high"),
    "Digest::MD5": ("CWE-327", "Weak hash via MD5", "medium"),
    "Digest::SHA1": ("CWE-327", "Weak hash via SHA1", "medium"),
    "Rails.logger": ("CWE-117", "Log Injection via Rails.logger", "medium"),
}

_SANITIZERS: FrozenSet[str] = frozenset({
    "sanitize", "h(", "html_escape", "strip_tags",
    "shellescape", "Shellwords.escape", "to_i", "to_f",
    "CGI.escape", "URI.encode", "ERB::Util.html_escape",
})

_SECRET_NAME_RE = re.compile(r'(?:password|passwd|secret|api_key|token|private_key)', re.IGNORECASE)
_SECRET_VALUE_RE = re.compile(r'["\'][A-Za-z0-9+/=]{20,}["\']|["\']sk-[a-zA-Z0-9\-]{20,}["\']|["\'][0-9a-fA-F]{32,}["\']')
_SKIP_SECRET_RE = re.compile(r'(?:example|sample|test|dummy|mock)', re.IGNORECASE)


def _analyze_ast(rb_file: RbFile, code: str) -> List[Finding]:
    findings: List[Finding] = []
    tainted: Set[str] = set()
    sanitized: Set[str] = set()

    for a in rb_file.assigns:
        t = a.target.lstrip("@$")
        if _tainted(a.value_text): tainted.add(t)
        if _is_sanitized(a.value_text): sanitized.add(t)
    tainted -= sanitized

    for c in rb_file.calls:
        _check_sink(c, tainted, sanitized, findings)

    for a in rb_file.assigns:
        _check_secret(a, findings)

    for r in rb_file.routes:
        _check_route(r, findings)

    _check_mass_assign(code, findings)
    _check_csrf(code, findings)
    return findings


def _tainted(v: str) -> bool:
    return any(s in v for s in _TAINT_SOURCES) or bool(re.search(r'(?:params|request|cookies|session|ARGV)\b', v))


def _is_sanitized(v: str) -> bool:
    return any(s in v for s in _SANITIZERS)


def _check_sink(call: RbCall, tainted: Set[str], sanitized: Set[str], findings: List[Finding]):
    cl = call.name.lower()
    matched: Optional[Tuple[str, str, str]] = None
    best = 0
    for pat, info in _SINKS.items():
        if pat.lower() in cl and len(pat) > best:
            matched = info; best = len(pat)
    if not matched: return

    cwe, title, sev = matched
    severity = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}.get(sev, Severity.MEDIUM)

    at = " ".join(call.args)
    tainted_args = any(a.strip().lstrip("@$:") in tainted for a in call.args)
    if not tainted_args:
        tainted_args = any(f"#{tv}" in at or tv in at for tv in tainted)
    if not tainted_args:
        tainted_args = _tainted(at)
    if not tainted_args: return
    if any("?" in a for a in call.args): return
    is_san = any(s in at for s in _SANITIZERS)

    findings.append(Finding(category="security", severity=severity, title=title,
        description=f"Tainted data reaches {call.name} at line {call.line}",
        line=call.line, suggestion=_remediation(call.name),
        rule_id=_rule_id(call.name), cwe=cwe, agent="ruby-ast-analyzer",
        confidence=0.35 if is_san else 0.85, analysis_kind="taint-tracking"))


def _check_secret(a: RbAssign, findings: List[Finding]):
    if not _SECRET_NAME_RE.search(a.target): return
    if not _SECRET_VALUE_RE.search(a.value_text): return
    if _SKIP_SECRET_RE.search(a.target) or _SKIP_SECRET_RE.search(a.value_text): return
    findings.append(Finding(category="security", severity=Severity.HIGH,
        title="Hardcoded credential", description=f"Hardcoded secret at line {a.line}",
        line=a.line, suggestion="Use env vars or Rails credentials.",
        rule_id=_RB_HARDCODED, cwe="CWE-798", agent="ruby-ast-analyzer",
        confidence=0.65, analysis_kind="pattern-ast"))


def _check_route(r: RbRoute, findings: List[Finding]):
    sensitive = {"/admin", "/manage", "/dashboard", "/users", "/settings"}
    if any(r.path.startswith(s) or s in r.path for s in sensitive) and not r.has_auth:
        findings.append(Finding(category="security", severity=Severity.HIGH,
            title=f"Missing auth on {r.method} {r.path}",
            description=f"Route lacks authentication at line {r.line}",
            line=r.line, suggestion="Add before_action :authenticate_user!",
            rule_id=_RB_MISSING_AUTH, cwe="CWE-862", agent="ruby-ast-analyzer",
            confidence=0.70, analysis_kind="route-heuristic"))


def _check_mass_assign(code: str, findings: List[Finding]):
    for m in re.finditer(r'\.(update|create|update_attributes|assign_attributes)!\s*\(\s*params', code):
        line = 1 + code[:m.start()].count('\n')
        findings.append(Finding(category="security", severity=Severity.HIGH,
            title="Mass assignment via params",
            description=f"Unfiltered params at line {line}",
            line=line, suggestion="Use strong parameters: params.require(:model).permit(:attr)",
            rule_id=_RB_MASS_ASSIGN, cwe="CWE-915", agent="ruby-ast-analyzer",
            confidence=0.75, analysis_kind="pattern-ast"))


def _check_csrf(code: str, findings: List[Finding]):
    if "protect_from_forgery" not in code and re.search(r'(class\s+\w+Controller\s*<)', code):
        if re.search(r'(post|put|patch|delete)\s+[\'"]/', code):
            findings.append(Finding(category="security", severity=Severity.MEDIUM,
                title="Missing CSRF protection", description="Controller lacks protect_from_forgery",
                line=1, suggestion="Add protect_from_forgery with: :exception to ApplicationController.",
                rule_id=_RB_CSRF, cwe="CWE-352", agent="ruby-ast-analyzer",
                confidence=0.50, analysis_kind="pattern"))


def _rule_id(name: str) -> str:
    n = name.lower()
    if any(s in n for s in ("find_by_sql", ".where(", ".select(", ".execute(")): return _RB_SQLI
    if any(s in n for s in ("system(", "exec(", "io.popen", "open3.")): return _RB_CMDI
    if any(s in n for s in ("file.read", "file.open", "file.join", "send_file")): return _RB_PATH_TRAV
    if "redirect_to" in n: return _RB_OPEN_REDIR
    if any(s in n for s in ("yaml.load", "marshal.load")): return _RB_DESERIAL
    if any(s in n for s in ("digest::md5", "digest::sha1")): return _RB_WEAK_CRYPTO
    if any(s in n for s in ("eval(", "class_eval", "instance_eval")): return _RB_CODE_INJ
    if any(s in n for s in ("net::http", "httparty", "open(")): return _RB_SSRF
    if any(s in n for s in ("rails.logger",)): return _RB_LOG_INJ
    if any(s in n for s in ("raw(", "html_safe")): return _RB_XSS
    if any(s in n for s in ("render(", "send(")): return _RB_SSTI
    return _RB_SQLI


def _remediation(name: str) -> str:
    n = name.lower()
    if "find_by_sql" in n or ".where" in n: return "Use parameterized queries: Model.where('id = ?', id)"
    if "system(" in n or "exec(" in n: return "Use Shellwords.escape() or avoid shell execution."
    if "file.read" in n or "file.open" in n: return "Validate paths and verify base directory."
    if "redirect_to" in n: return "Validate redirect URLs against allowlist."
    if "yaml.load" in n: return "Use YAML.safe_load() instead."
    if "eval(" in n: return "Never pass user input to eval()."
    return "Sanitize all user input."


def _scan_regex(code: str, findings: List[Finding]):
    import re as _re
    def _add(rid, title, cwe, sev, m, sug, conf=0.7):
        line = 1 + code[:m.start()].count('\n')
        findings.append(Finding(category="security", severity=sev, title=title,
            description=f"Found {cwe} at line {line}", line=line, suggestion=sug,
            rule_id=rid, cwe=cwe, agent="ruby-regex", confidence=conf, analysis_kind="pattern"))

    for m in _re.finditer(r'(?:find_by_sql|\.where|\.select|\.execute)\s*[\(].*?(?:params|request\.)', code, _re.IGNORECASE):
        _add(_RB_SQLI, "SQL Injection", "CWE-89", Severity.CRITICAL, m, "Use parameterized queries.", 0.85)
    for m in _re.finditer(r'(?:system|exec|IO\.popen|Open3\.)\s*[\(].*?(?:params|request\.)', code, _re.IGNORECASE):
        _add(_RB_CMDI, "Command Injection", "CWE-78", Severity.CRITICAL, m, "Use Shellwords.escape().", 0.80)
    for m in _re.finditer(r'(?:File\.read|File\.open|File\.join|send_file)\s*[\(].*?(?:params|request\.)', code, _re.IGNORECASE):
        _add(_RB_PATH_TRAV, "Path Traversal", "CWE-22", Severity.HIGH, m, "Validate file paths.", 0.70)
    for m in _re.finditer(r'(?:password|secret|api_key|token)\s*=\s*["\'][^"\']{8,}["\']', code, _re.IGNORECASE):
        _add(_RB_HARDCODED, "Hardcoded credential", "CWE-798", Severity.HIGH, m, "Use env vars.", 0.60)
    for m in _re.finditer(r'(?:YAML\.load|Marshal\.load)\s*\(.*?(?:params|request\.)', code, _re.IGNORECASE):
        _add(_RB_DESERIAL, "Unsafe Deserialization", "CWE-502", Severity.CRITICAL, m, "Use YAML.safe_load().", 0.85)
    for m in _re.finditer(r'(?:eval|class_eval|instance_eval)\s*\(.*?(?:params|request\.)', code, _re.IGNORECASE):
        _add(_RB_CODE_INJ, "Code Injection", "CWE-95", Severity.CRITICAL, m, "Never eval() user input.", 0.85)
    for m in _re.finditer(r'\.(?:update|create|update_attributes)!?\s*\(\s*params', code):
        _add(_RB_MASS_ASSIGN, "Mass Assignment", "CWE-915", Severity.HIGH, m, "Use strong parameters.", 0.70)


def analyze_ruby(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="ruby", lines_scanned=len(code.splitlines()))
    try:
        findings: List[Finding] = []
        if HAS_RUST_RUBY:
            rb_file = parse_ruby(code, filename)
            findings = _analyze_ast(rb_file, code)
        else:
            _scan_regex(code, findings)
        result.findings = sorted(findings, key=lambda f: (f.line or 0, f.severity.sort_key))
    except Exception as exc:
        result.parse_error = f"Ruby analyzer error: {exc}"
        _log.warning("Ruby analysis failed: %s", str(exc).replace('\n',' ')[:200])
    return result
