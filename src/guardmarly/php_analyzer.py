"""
guardmarly.php_analyzer — AST-walking security analyzer for PHP source code.

Uses tree-sitter-php via the Rust native core for precise AST extraction.
Falls back to regex-only analysis when the Rust core is unavailable.

Detection coverage (AST mode, 15 CWE types):
  CWE-89   SQL Injection (tainted data in query contexts)
  CWE-78   Command Injection (tainted args to system/exec/shell_exec)
  CWE-79   XSS (echo/print with unsanitized superglobal input)
  CWE-22   Path Traversal (file ops with user-controlled paths)
  CWE-862  Missing Authentication (admin routes without auth middleware)
  CWE-639  IDOR (route param flows to DB without ownership check)
  CWE-352  CSRF (state-changing routes without token verification)
  CWE-798  Hardcoded Secrets (API keys, passwords in source)
  CWE-95   Code Injection (eval/assert with tainted input)
  CWE-918  SSRF (curl/file_get_contents with user-controlled URLs)
  CWE-502  Unsafe Deserialization (unserialize() on user input)
  CWE-117  Log Injection (error_log with tainted data)
  CWE-327  Weak Cryptography (MD5/SHA1 for password hashing)
  CWE-915  Mass Assignment (unfiltered request input to model)
  CWE-601  Open Redirect (header('Location: ' . $_GET['url']))
"""

from __future__ import annotations

import logging
import re
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from guardmarly._types import AnalysisResult, Finding, Severity
from guardmarly.php_parser import (
    HAS_RUST_PHP,
    PhpAssign,
    PhpCall,
    PhpFile,
    PhpRoute,
    parse_php,
)

_log = logging.getLogger(__name__)

# ── Rule IDs ──────────────────────────────────────────────────────────────────
_PH_SQLI        = "PHP-001"
_PH_CMDI        = "PHP-002"
_PH_XSS         = "PHP-003"
_PH_PATH_TRAV   = "PHP-004"
_PH_MISSING_AUTH = "PHP-005"
_PH_CSRF        = "PHP-006"
_PH_HARDCODED   = "PHP-007"
_PH_EVAL        = "PHP-008"
_PH_SSRF        = "PHP-009"
_PH_UNSERIALIZE = "PHP-010"
_PH_LOG_INJ     = "PHP-011"
_PH_IDOR        = "PHP-012"
_PH_WEAK_CRYPTO = "PHP-013"
_PH_MASS_ASSIGN = "PHP-014"
_PH_OPEN_REDIR  = "PHP-015"

# ── PHP Taint Sources ────────────────────────────────────────────────────────
_TAINT_SOURCES: Dict[str, Tuple[str, str]] = {
    "$_GET":      ("HTTP GET parameter", "superglobal"),
    "$_POST":     ("HTTP POST parameter", "superglobal"),
    "$_REQUEST":  ("HTTP request parameter", "superglobal"),
    "$_COOKIE":   ("HTTP cookie", "superglobal"),
    "$_FILES":    ("Uploaded file", "superglobal"),
    "$_SERVER":   ("Server/environment value", "superglobal"),
    "$_ENV":      ("Environment variable", "superglobal"),
    "file_get_contents('php://input'": ("Raw HTTP request body", "input_fn"),
    "php://input": ("Raw HTTP request body", "input_fn"),
    "getenv":     ("Environment variable", "input_fn"),
    "readline":   ("Console input", "input_fn"),
    "fgets(STDIN": ("Standard input", "input_fn"),
    "$this->request": ("Framework request object", "framework"),
    "request(":   ("Framework request helper", "framework"),
    "input(":     ("Laravel input helper", "framework"),
}

_TAINT_SOURCE_NAMES: FrozenSet[str] = frozenset(_TAINT_SOURCES.keys())

# ── PHP Taint Sinks ──────────────────────────────────────────────────────────
_DANGEROUS_SINKS: Dict[str, Tuple[str, str, str]] = {
    "mysqli_query":    ("CWE-89", "SQL Injection via mysqli_query", "critical"),
    "mysql_query":     ("CWE-89", "SQL Injection via mysql_query", "critical"),
    "pg_query":        ("CWE-89", "SQL Injection via pg_query", "critical"),
    "sqlsrv_query":    ("CWE-89", "SQL Injection via sqlsrv_query", "critical"),
    "odbc_exec":       ("CWE-89", "SQL Injection via odbc_exec", "critical"),
    "db_query":        ("CWE-89", "SQL Injection via db_query", "critical"),
    "->query(":        ("CWE-89", "SQL Injection via query method", "critical"),
    "->exec(":         ("CWE-78", "OS Command Injection via exec method", "critical"),  # Note: catches PDO->exec() AND shell exec
    "->raw(":          ("CWE-89", "SQL Injection via raw query", "critical"),
    "DB::select(":     ("CWE-89", "SQL Injection via DB::select", "critical"),
    "DB::raw(":        ("CWE-89", "SQL Injection via DB::raw", "critical"),
    "DB::statement(":  ("CWE-89", "SQL Injection via DB::statement", "critical"),
    "exec(":           ("CWE-78", "OS Command Injection via exec()", "critical"),
    "shell_exec(":     ("CWE-78", "OS Command Injection via shell_exec()", "critical"),
    "system(":         ("CWE-78", "OS Command Injection via system()", "critical"),
    "passthru(":       ("CWE-78", "OS Command Injection via passthru()", "critical"),
    "popen(":          ("CWE-78", "OS Command Injection via popen()", "critical"),
    "proc_open(":      ("CWE-78", "OS Command Injection via proc_open()", "critical"),
    "pcntl_exec(":     ("CWE-78", "OS Command Injection via pcntl_exec()", "critical"),
    "`":               ("CWE-78", "OS Command Injection via backticks", "critical"),
    "eval(":           ("CWE-95", "Code Injection via eval()", "critical"),
    "assert(":         ("CWE-95", "Code Injection via assert()", "critical"),
    "create_function(": ("CWE-95", "Code Injection via create_function()", "critical"),
    "preg_replace(":   ("CWE-95", "Code Injection via preg_replace /e", "high"),
    "fopen(":          ("CWE-22", "Path Traversal via fopen()", "high"),
    "file_get_contents(": ("CWE-22", "Path Traversal via file_get_contents()", "high"),
    "file_put_contents(": ("CWE-22", "Path Traversal via file_put_contents()", "high"),
    "include(":        ("CWE-22", "Path Traversal via include()", "critical"),
    "require(":        ("CWE-22", "Path Traversal via require()", "critical"),
    "include_once(":   ("CWE-22", "Path Traversal via include_once()", "critical"),
    "require_once(":   ("CWE-22", "Path Traversal via require_once()", "critical"),
    "readfile(":       ("CWE-22", "Path Traversal via readfile()", "high"),
    "unlink(":         ("CWE-22", "Path Traversal via unlink()", "medium"),
    "copy(":           ("CWE-22", "Path Traversal via copy()", "high"),
    "rename(":         ("CWE-22", "Path Traversal via rename()", "high"),
    "mkdir(":          ("CWE-22", "Path Traversal via mkdir()", "medium"),
    "rmdir(":          ("CWE-22", "Path Traversal via rmdir()", "medium"),
    "parse_ini_file(": ("CWE-22", "Path Traversal via parse_ini_file()", "high"),
    "curl_exec(":      ("CWE-918", "SSRF via curl_exec()", "high"),
    "curl_setopt(":    ("CWE-918", "SSRF via curl_setopt()", "high"),
    "unserialize(":    ("CWE-502", "Unsafe Deserialization via unserialize()", "critical"),
    "error_log(":      ("CWE-117", "Log Injection via error_log()", "medium"),
    "syslog(":         ("CWE-117", "Log Injection via syslog()", "medium"),
    "echo":            ("CWE-79", "XSS via unescaped echo", "high"),
    "print":           ("CWE-79", "XSS via unescaped print", "high"),
    "printf(":         ("CWE-79", "XSS via unescaped printf", "medium"),
    "vprintf(":        ("CWE-79", "XSS via unescaped vprintf", "medium"),
    "->innerHTML":     ("CWE-79", "XSS via innerHTML assignment", "high"),
    "md5(":            ("CWE-327", "Weak hash via md5()", "medium"),
    "sha1(":           ("CWE-327", "Weak hash via sha1()", "medium"),
    "crc32(":          ("CWE-327", "Weak hash via crc32()", "low"),
    "header(":         ("CWE-601", "Open Redirect via header()", "high"),
}

_XSS_SINKS: FrozenSet[str] = frozenset({"echo", "print", "printf(", "vprintf("})
_SQL_SINKS: FrozenSet[str] = frozenset({
    "mysqli_query", "mysql_query", "pg_query", "sqlsrv_query",
    "odbc_exec", "db_query", "->query(", "->exec(", "->raw(",
    "DB::select(", "DB::raw(", "DB::statement(",
})

# ── Sanitizers ────────────────────────────────────────────────────────────────
_SANITIZERS: FrozenSet[str] = frozenset({
    "htmlspecialchars(", "htmlentities(", "strip_tags(",
    "escapeshellarg(", "escapeshellcmd(",
    "intval(", "floatval(", "filter_var(", "filter_input(",
    "mysqli_real_escape_string(", "mysql_real_escape_string(",
    "pg_escape_string(", "pg_escape_literal(",
    "addslashes(", "preg_quote(",
    "urlencode(", "rawurlencode(",
    "realpath(", "basename(",
    "password_hash(", "hash(", "hash_hmac(",
    "json_encode(", "serialize(",
})

# ── Hardcoded Secret Patterns ─────────────────────────────────────────────────
_HARDCODED_NAME_RE = re.compile(
    r'(?:password|passwd|pwd|secret|api_key|apikey|token|private_key|'
    r'access_key|auth_token|jwt_secret|encryption_key)',
    re.IGNORECASE,
)

_HARDCODED_VALUE_RE = re.compile(
    r'["\'][A-Za-z0-9+/=]{20,}["\']|'
    r'["\']sk-[a-zA-Z0-9\-]{20,}["\']|'
    r'["\'][0-9a-fA-F]{32,}["\']|'
    r'["\']ghp_[a-zA-Z0-9]{20,}["\']|'
    r'["\']AKIA[A-Z0-9]{16}["\']',
    re.IGNORECASE,
)

_SKIP_SECRET_RE = re.compile(
    r'(?:example|sample|test|dummy|mock|fake|placeholder|xxx|todo)',
    re.IGNORECASE,
)


# ═══════════════════════════════════════════════════════════════════════════════
# AST-based analysis
# ═══════════════════════════════════════════════════════════════════════════════

def _analyze_ast(php_file: PhpFile, code: str) -> List[Finding]:
    """Analyze parsed PHP AST for security vulnerabilities."""
    findings: List[Finding] = []
    tainted_vars: Set[str] = set()
    sanitized_vars: Set[str] = set()

    # Pass 1: Collect tainted variables from assignments
    for assign in php_file.assigns:
        target = assign.target.lstrip("$")
        value = assign.value_text
        if _value_contains_taint(value):
            tainted_vars.add(target)
        if _value_contains_sanitizer(value):
            sanitized_vars.add(target)

    tainted_vars -= sanitized_vars

    # Pass 2: Check function calls against sink catalog
    for call in php_file.calls:
        _check_call_sink(call, tainted_vars, sanitized_vars, findings)

    # Pass 2b: Regex fallback for direct tainted sink calls the parser may miss
    # (catches system($_GET[...]), eval($_POST[...]), etc.)
    _check_direct_tainted_sinks(code, findings)

    # Pass 3: Hardcoded secrets
    for assign in php_file.assigns:
        _check_hardcoded_secret(assign, findings)

    # Pass 4: Route analysis (auth + CSRF + IDOR)
    _analyze_routes(php_file, findings)

    # Pass 5: Weak crypto
    for call in php_file.calls:
        _check_weak_crypto(call, findings)

    # Pass 6: Mass assignment patterns
    _check_mass_assignment(code, findings)

    return findings


def _value_contains_taint(value: str) -> bool:
    """Check if a value expression references a taint source."""
    for source in _TAINT_SOURCE_NAMES:
        if source in value:
            return True
    if re.search(r'\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV)\b', value):
        return True
    if 'php://input' in value:
        return True
    return False


def _value_contains_sanitizer(value: str) -> bool:
    """Check if a value expression applies a sanitizer function."""
    for sanitizer in _SANITIZERS:
        if sanitizer in value:
            return True
    return False


def _check_call_sink(
    call: PhpCall,
    tainted_vars: Set[str],
    sanitized_vars: Set[str],
    findings: List[Finding],
) -> None:
    """Check if a function call is a dangerous sink with tainted arguments."""
    call_name = call.name.lower() if call.name else ""

    matched_sink: Optional[Tuple[str, str, str]] = None
    best_len = 0
    for sink_pattern, sink_info in _DANGEROUS_SINKS.items():
        # Strip trailing parens for matching (parser doesn't include them)
        sink_key = sink_pattern.rstrip("(").lower()
        if sink_key in call_name or sink_pattern.lower() in call_name:
            # Skip: "->exec(" should not match "->execute(" (prepared statements)
            if sink_key == "->exec" and "->execute" in call_name:
                continue
            # Prefer longer/more specific matches
            if len(sink_key) > best_len:
                # Special: "echo" and "print" must be exact match (not substring)
                if sink_pattern in ("echo", "print") and call_name != sink_pattern:
                    continue
                matched_sink = sink_info
                best_len = len(sink_key)

    if matched_sink is None:
        return

    cwe, title, severity_str = matched_sink
    severity = _severity_from_str(severity_str)

    # Check if any argument references a tainted variable
    args_tainted = False
    sanitized = False
    args_text = " ".join(call.args)

    for arg in call.args:
        arg_clean = arg.strip().lstrip("$")
        if arg_clean in tainted_vars:
            args_tainted = True
            if arg_clean in sanitized_vars:
                sanitized = True
        # Check for $varname inside string interpolation
        for tvar in tainted_vars:
            if f"${tvar}" in arg:
                args_tainted = True
                if tvar in sanitized_vars:
                    sanitized = True

    # Check raw argument text for taint patterns
    if not args_tainted and _value_contains_taint(args_text):
        args_tainted = True

    # Check if the call itself is wrapped in a sanitizer in the raw arg text
    # e.g., echo htmlspecialchars($name, ...) → suppress XSS
    if args_tainted:
        for sanitizer in _SANITIZERS:
            if sanitizer in args_text:
                sanitized = True
                break

    if not args_tainted:
        return

    # Suppress if this looks like a safe prepared statement (SQL with ? placeholders)
    if any("?" in arg for arg in call.args):
        return

    confidence = 0.85
    if call_name in _XSS_SINKS:
        confidence = 0.60
    if sanitized:
        confidence = max(0.25, confidence - 0.30)

    findings.append(Finding(
        category="security",
        severity=severity,
        title=title,
        description=f"Tainted data from user input reaches {call.name}() at line {call.line}",
        line=call.line,
        suggestion=_remediation_for_sink(call.name),
        rule_id=_sink_to_rule_id(call.name),
        cwe=cwe,
        agent="php-ast-analyzer",
        confidence=confidence,
        analysis_kind="taint-tracking",
    ))


def _check_hardcoded_secret(assign: PhpAssign, findings: List[Finding]) -> None:
    """Check if an assignment contains a hardcoded secret."""
    target_clean = assign.target.lstrip("$")
    if not _HARDCODED_NAME_RE.search(target_clean):
        return
    value = assign.value_text
    if not _HARDCODED_VALUE_RE.search(value):
        return
    if _SKIP_SECRET_RE.search(target_clean) or _SKIP_SECRET_RE.search(value):
        return
    if re.search(r'\w+\s*\(', value):
        return
    if '://' in value or 'access_token=' in value:
        return
    findings.append(Finding(
        category="security",
        severity=Severity.HIGH,
        title="Hardcoded credential detected",
        description=f"Variable '{assign.target}' assigned a hardcoded secret at line {assign.line}",
        line=assign.line,
        suggestion="Store secrets in environment variables or a secrets manager.",
        rule_id=_PH_HARDCODED,
        cwe="CWE-798",
        agent="php-ast-analyzer",
        confidence=0.65,
        analysis_kind="pattern-ast",
    ))


def _analyze_routes(php_file: PhpFile, findings: List[Finding]) -> None:
    """Analyze route definitions for auth, CSRF, and IDOR issues."""
    state_changing = {"POST", "PUT", "PATCH", "DELETE"}

    for route in php_file.routes:
        if _is_sensitive_path(route.path) and not route.has_auth_check:
            findings.append(Finding(
                category="security",
                severity=Severity.HIGH,
                title=f"Missing authentication on {route.method} {route.path}",
                description=f"Route {route.method} {route.path} handles sensitive data "
                           f"without authentication at line {route.line}",
                line=route.line,
                suggestion="Add auth middleware: `->middleware('auth')` or verify auth in controller.",
                rule_id=_PH_MISSING_AUTH,
                cwe="CWE-862",
                agent="php-ast-analyzer",
                confidence=0.70,
                analysis_kind="route-heuristic",
            ))

        if route.method in state_changing and not route.has_csrf_check:
            findings.append(Finding(
                category="security",
                severity=Severity.MEDIUM,
                title=f"Missing CSRF protection on {route.method} {route.path}",
                description=f"State-changing route lacks CSRF protection at line {route.line}",
                line=route.line,
                suggestion="Add @csrf to forms or enable VerifyCsrfToken middleware.",
                rule_id=_PH_CSRF,
                cwe="CWE-352",
                agent="php-ast-analyzer",
                confidence=0.60,
                analysis_kind="route-heuristic",
            ))

        if "{" in route.path or ":" in route.path:
            _check_idor(route, php_file, findings)


def _is_sensitive_path(path: str) -> bool:
    """Check if a route path suggests sensitive/admin functionality."""
    sensitive = {"/admin", "/api/admin", "/manage", "/dashboard",
                 "/users", "/settings", "/config", "/secret", "/internal"}
    path_lower = path.lower()
    return any(path_lower.startswith(s) or f"/{s.strip('/')}" in path_lower
               for s in sensitive)


def _check_idor(route: PhpRoute, php_file: PhpFile, findings: List[Finding]) -> None:
    """IDOR: route params reaching DB queries without ownership filter."""
    params = re.findall(r'[:\{](\w+)[\}]', route.path)
    has_db_query = False
    has_ownership_filter = False

    for call in php_file.calls:
        call_name = call.name.lower() if call.name else ""
        if any(sink in call_name for sink in _SQL_SINKS):
            has_db_query = True
            args_text = " ".join(call.args).lower()
            if any(pat in args_text for pat in
                   ("user_id", "owner_id", "created_by", "author_id", "account_id")):
                has_ownership_filter = True

    if has_db_query and not has_ownership_filter and params:
        findings.append(Finding(
            category="security",
            severity=Severity.HIGH,
            title=f"Potential IDOR on {route.method} {route.path}",
            description=f"Route parameter '{params[0]}' reaches database query without "
                       f"ownership verification at line {route.line}",
            line=route.line,
            suggestion="Add ownership check: `WHERE id = ? AND user_id = ?`.",
            rule_id=_PH_IDOR,
            cwe="CWE-639",
            agent="php-ast-analyzer",
            confidence=0.55,
            analysis_kind="idor-heuristic",
        ))


def _check_weak_crypto(call: PhpCall, findings: List[Finding]) -> None:
    """Check for weak cryptographic function usage."""
    call_lower = call.name.lower()
    weak_funcs = {"md5(", "sha1(", "crc32("}

    for wf in weak_funcs:
        if wf in call_lower:
            args_text = " ".join(call.args).lower()
            if any(pw in args_text for pw in ("password", "passwd", "pwd", "secret", "token")):
                findings.append(Finding(
                    category="security",
                    severity=Severity.MEDIUM,
                    title=f"Weak hash function {call.name}() for sensitive data",
                    description=f"Weak hash at line {call.line}",
                    line=call.line,
                    suggestion="Use password_hash() with bcrypt/argon2id.",
                    rule_id=_PH_WEAK_CRYPTO,
                    cwe="CWE-327",
                    agent="php-ast-analyzer",
                    confidence=0.55,
                    analysis_kind="pattern-ast",
                ))
                return


def _check_mass_assignment(code: str, findings: List[Finding]) -> None:
    """Check for mass assignment (unfiltered request→model)."""
    patterns = [
        (r'->create\s*\(\s*\$_REQUEST', 'create'),
        (r'->create\s*\(\s*\$_POST', 'create'),
        (r'->fill\s*\(\s*\$_REQUEST', 'fill'),
        (r'->fill\s*\(\s*\$_POST', 'fill'),
        (r'->forceCreate\s*\(', 'forceCreate'),
        (r'->forceFill\s*\(', 'forceFill'),
    ]
    for pattern, method in patterns:
        for m in re.finditer(pattern, code, re.IGNORECASE):
            line = 1 + code[:m.start()].count('\n')
            findings.append(Finding(
                category="security",
                severity=Severity.HIGH,
                title=f"Mass assignment via {method}() with unfiltered input",
                description=f"Unfiltered request data to {method}() at line {line}",
                line=line,
                suggestion="Use $request->only(['name','email']) or $request->validated().",
                rule_id=_PH_MASS_ASSIGN,
                cwe="CWE-915",
                agent="php-ast-analyzer",
                confidence=0.75,
                analysis_kind="pattern-ast",
            ))


# ── Helpers ──────────────────────────────────────────────────────────────────

def _severity_from_str(s: str) -> Severity:
    m = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
         "medium": Severity.MEDIUM, "low": Severity.LOW}
    return m.get(s, Severity.MEDIUM)


def _sink_to_rule_id(sink_name: str) -> str:
    sink_lower = sink_name.lower() if sink_name else ""
    # CMDI first (before SQLi, since 'exec' appears in both)
    if any(s in sink_lower for s in ("shell_exec", "system(", "passthru",
                                      "popen", "proc_open", "pcntl_exec", "`")):
        return _PH_CMDI
    if sink_lower == "exec(" or sink_lower == "exec":
        return _PH_CMDI
    # DB:: scoped calls → SQLi
    if any(s in sink_lower for s in ("db::select", "db::raw", "db::statement")):
        return _PH_SQLI
    if any(s in sink_lower for s in ("query", "select", "raw", "statement")):
        return _PH_SQLI
    if any(s in sink_lower for s in ("echo", "print", "printf", "innerhtml")):
        return _PH_XSS
    if any(s in sink_lower for s in ("fopen", "file_get", "file_put", "include",
                                      "require", "readfile", "unlink", "copy",
                                      "rename", "mkdir", "rmdir", "parse_ini")):
        return _PH_PATH_TRAV
    if any(s in sink_lower for s in ("eval(", "assert(", "create_function", "preg_replace")):
        return _PH_EVAL
    if any(s in sink_lower for s in ("curl_exec", "curl_setopt")):
        return _PH_SSRF
    if "unserialize" in sink_lower:
        return _PH_UNSERIALIZE
    if any(s in sink_lower for s in ("error_log", "syslog")):
        return _PH_LOG_INJ
    if "header(" in sink_lower:
        return _PH_OPEN_REDIR
    return _PH_SQLI


def _remediation_for_sink(sink_name: str) -> str:
    sink_lower = sink_name.lower() if sink_name else ""
    if any(s in sink_lower for s in ("query", "exec", "select", "raw")):
        return "Use prepared statements: `$stmt = $pdo->prepare(...); $stmt->execute([$id]);`"
    if any(s in sink_lower for s in ("exec(", "system(", "shell_exec", "passthru")):
        return "Use escapeshellarg() on each argument, or avoid shell execution."
    if any(s in sink_lower for s in ("echo", "print", "printf")):
        return "Escape: htmlspecialchars($var, ENT_QUOTES, 'UTF-8')."
    if any(s in sink_lower for s in ("fopen", "file_get", "include", "require")):
        return "Validate paths with realpath() and verify base directory."
    if any(s in sink_lower for s in ("eval(", "assert(", "create_function")):
        return "Never pass user input to eval()/assert(). Use lookup tables."
    if any(s in sink_lower for s in ("curl_exec", "curl_setopt")):
        return "Validate URLs against allowlist. Block private IP ranges."
    if "unserialize" in sink_lower:
        return "Use json_decode() with an explicit schema instead."
    if "header(" in sink_lower:
        return "Validate redirect URLs against allowlist."
    return "Sanitize and validate all user input before use."


def _check_direct_tainted_sinks(code: str, findings: List[Finding]) -> None:
    """Regex fallback: catch direct tainted sink calls the AST parser may miss.

    Handles: system($_GET[...]), eval($_POST[...]), md5($_GET[...]),
    header('Location: ' . $_GET[...]), etc.
    """
    import re as _re

    # Direct dangerous function calls with taint patterns in args
    direct_patterns = [
        (_PH_CMDI, r'\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\([^)]*(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER|\$_FILES|php://input)',
         "OS Command Injection", "CWE-78", Severity.CRITICAL,
         "Use escapeshellarg() or avoid shell execution.", 0.80),
        (_PH_EVAL, r'\b(eval|assert|create_function)\s*\([^)]*(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)',
         "Code Injection", "CWE-95", Severity.CRITICAL,
         "Never pass user input to eval()/assert().", 0.85),
        (_PH_SQLI, r'\b(mysqli_query|mysql_query|pg_query|sqlsrv_query|odbc_exec|db_query)\s*\([^)]*(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)',
         "SQL Injection", "CWE-89", Severity.CRITICAL,
         "Use prepared statements with bound parameters.", 0.85),
        (_PH_SSRF, r'\b(curl_setopt|curl_exec)\s*\([^)]*(?:\$_GET|\$_POST|\$_REQUEST)',
         "Server-Side Request Forgery", "CWE-918", Severity.HIGH,
         "Validate and allowlist URLs.", 0.70),
        (_PH_WEAK_CRYPTO, r'\b(md5|sha1)\s*\([^)]*(?:\$_POST|\$_GET|\$_REQUEST).*?(?:password|passwd|pwd|secret|token)',
         "Weak hash for sensitive data", "CWE-327", Severity.MEDIUM,
         "Use password_hash() with bcrypt/argon2id.", 0.60),
        (_PH_OPEN_REDIR, r'\bheader\s*\([^)]*(?:\$_GET|\$_POST|\$_REQUEST).*?(?:Location|location)',
         "Open Redirect via header()", "CWE-601", Severity.HIGH,
         "Validate redirect URLs against allowlist.", 0.70),
    ]

    for rule_id, pattern, title, cwe, severity, suggestion, confidence in direct_patterns:
        for m in _re.finditer(pattern, code, _re.IGNORECASE):
            line = 1 + code[:m.start()].count('\n')
            # Skip if sanitized (htmlspecialchars, escapeshellarg, etc.)
            line_start = max(0, code.rfind('\n', 0, m.start()))
            line_end = code.find('\n', m.end())
            line_text = code[line_start:line_end] if line_end > 0 else code[line_start:]
            sanitized = any(s in line_text for s in
                          ("htmlspecialchars(", "escapeshellarg(", "intval(", "filter_var(",
                           "password_hash(", "basename(", "realpath("))
            if sanitized:
                continue
            findings.append(Finding(
                category="security",
                severity=severity,
                title=title,
                description=f"Found potential {cwe} at line {line}",
                line=line,
                suggestion=suggestion,
                rule_id=rule_id,
                cwe=cwe,
                agent="php-regex-supplement",
                confidence=confidence,
                analysis_kind="pattern-taint",
            ))


# ═══════════════════════════════════════════════════════════════════════════════
# Regex fallback
# ═══════════════════════════════════════════════════════════════════════════════

def _scan_with_regex(code: str, findings: List[Finding]) -> None:
    """Fallback regex scanning when Rust core is unavailable."""
    import re as _re

    def _add(rule_id: str, title: str, cwe: str, severity: Severity,
             m: _re.Match, suggestion: str, confidence: float = 0.7) -> None:
        line_no = 1 + code[:m.start()].count('\n')
        findings.append(Finding(
            category="security", severity=severity, title=title,
            description=f"Found potential {cwe} at line {line_no}",
            line=line_no, suggestion=suggestion, rule_id=rule_id, cwe=cwe,
            agent="php-regex-fallback", confidence=confidence, analysis_kind="pattern",
        ))

    sqli_re = _re.compile(
        r'(?:mysqli_query|mysql_query|pg_query|sqlsrv_query|db_query|'
        r'->query|->exec|->raw|DB::raw)\s*\([^)]*(?:\$_GET|\$_POST|\$_REQUEST)',
        _re.IGNORECASE,
    )
    for m in sqli_re.finditer(code):
        _add(_PH_SQLI, "SQL Injection", "CWE-89", Severity.CRITICAL, m,
             "Use prepared statements with bound parameters.", 0.85)

    cmdi_re = _re.compile(
        r'(?:shell_exec|exec|system|passthru|popen|proc_open|pcntl_exec)\s*\([^)]*'
        r'(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER)',
        _re.IGNORECASE,
    )
    for m in cmdi_re.finditer(code):
        _add(_PH_CMDI, "OS Command Injection", "CWE-78", Severity.CRITICAL, m,
             "Use escapeshellarg() on each argument.", 0.80)

    eval_re = _re.compile(
        r'(?:eval|assert|preg_replace|create_function)\s*\([^)]*(?:\$_GET|\$_POST|\$_REQUEST)',
        _re.IGNORECASE,
    )
    for m in eval_re.finditer(code):
        _add(_PH_EVAL, "Code Injection", "CWE-95", Severity.CRITICAL, m,
             "Never pass user input to eval()/assert().", 0.85)

    path_re = _re.compile(
        r'(?:include|require|include_once|require_once|fopen|file_get_contents|'
        r'file_put_contents|readfile|unlink)\s*\([^)]*(?:\$_GET|\$_POST|\$_REQUEST|\$_FILES)',
        _re.IGNORECASE,
    )
    for m in path_re.finditer(code):
        _add(_PH_PATH_TRAV, "Path Traversal", "CWE-22", Severity.HIGH, m,
             "Validate paths and use realpath().", 0.70)

    unser_re = _re.compile(
        r'unserialize\s*\([^)]*(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)',
        _re.IGNORECASE,
    )
    for m in unser_re.finditer(code):
        _add(_PH_UNSERIALIZE, "Unsafe Deserialization", "CWE-502", Severity.CRITICAL, m,
             "Use json_decode() with an explicit schema.", 0.85)

    ssrf_re = _re.compile(
        r'(?:curl_exec|curl_setopt|file_get_contents)\s*\([^)]*(?:\$_GET|\$_POST|\$_REQUEST)',
        _re.IGNORECASE,
    )
    for m in ssrf_re.finditer(code):
        _add(_PH_SSRF, "Server-Side Request Forgery", "CWE-918", Severity.HIGH, m,
             "Validate and allowlist URLs.", 0.70)

    secret_re = _re.compile(
        r'(?:password|passwd|pwd|secret|api_key|apikey|token|private_key)\s*=>?\s*["\'][^"\']{8,}["\']',
        _re.IGNORECASE,
    )
    for m in secret_re.finditer(code):
        line_start = code.rfind('\n', 0, m.start()) + 1
        line_end = code.find('\n', m.end())
        line_text = code[line_start:line_end] if line_end > line_start else code[line_start:]
        if _re.search(r'(?:example|sample|test|dummy|\$this->)', line_text, _re.IGNORECASE):
            continue
        _add(_PH_HARDCODED, "Hardcoded credential", "CWE-798", Severity.HIGH, m,
             "Store secrets in environment variables.", 0.60)


# ═══════════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_php(code: str, filename: str = "") -> AnalysisResult:
    """Analyze PHP source code for security vulnerabilities.

    Uses tree-sitter AST analysis when the Rust core is available,
    with a regex-only fallback for environments without native support.
    """
    result = AnalysisResult(
        file_path=filename,
        language="php",
        lines_scanned=len(code.splitlines()),
    )

    try:
        findings: List[Finding] = []

        if HAS_RUST_PHP:
            php_file = parse_php(code, filename)
            findings = _analyze_ast(php_file, code)
        else:
            _scan_with_regex(code, findings)

        result.findings = sorted(
            findings,
            key=lambda f: (f.line or 0, f.severity.sort_key),
        )
    except Exception as exc:
        result.parse_error = f"PHP analyzer error: {exc}"
        _log.warning("PHP analysis failed: %s", str(exc).replace('\n', ' ')[:200])

    return result
