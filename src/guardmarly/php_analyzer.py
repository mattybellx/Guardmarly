"""
guardmarly.php_analyzer
───────────────────────────
Regex-based security analyzer for PHP source code.

Zero external dependencies — pure Python 3.9+ stdlib only.

Detection coverage:
  CWE-89   SQL Injection (string interpolation in query contexts)
  CWE-78   Command Injection (system/exec/backticks with interpolation)
  CWE-79   XSS (echo/print with superglobal input)
  CWE-22   Path Traversal (file functions with user input)
  CWE-862  Missing Authentication (routes without auth checks)
  CWE-352  CSRF (state-changing actions without token verification)
  CWE-798  Hardcoded Secrets (API keys, passwords in assignments)
"""
from __future__ import annotations

import re
import warnings

# ⚠ PHP analysis is regex-only (no AST). False-positive rates may be high.
warnings.warn(
    "guardmarly: PHP analyzer is experimental (regex-only, no AST). "
    "False-positive rates may be high. Tree-sitter-php integration planned.",
    RuntimeWarning,
    stacklevel=2,
)

from guardmarly._types import AnalysisResult, Finding, Severity

# ── Rule IDs ──────────────────────────────────────────────────────────────────
_PH_SQLI       = "PHP-001"
_PH_CMDI       = "PHP-002"
_PH_XSS        = "PHP-003"
_PH_PATH_TRAV  = "PHP-004"
_PH_MISSING_AUTH = "PHP-005"
_PH_CSRF       = "PHP-006"
_PH_HARDCODED  = "PHP-007"
_PH_EVAL       = "PHP-008"  # Code Injection via eval/assert
_PH_SSRF       = "PHP-009"  # Server-Side Request Forgery
_PH_UNSERIALIZE = "PHP-010" # Unsafe Deserialization
_PH_LOG_INJ    = "PHP-011"  # Log Injection

# ── Common taint sources (PHP superglobals) ───────────────────────────────────
_SUPERGLOBALS = [
    r'\$_GET', r'\$_POST', r'\$_REQUEST', r'\$_COOKIE',
    r'\$_SERVER\s*\[', r'\$_FILES', r'\$_ENV',
    r'getenv\s*\(', r'php://input',
]

_TAINT_PAT = '(?:' + '|'.join(_SUPERGLOBALS) + ')'

# ── CWE-89: SQL Injection ─────────────────────────────────────────────────────
_SQLI_RE = re.compile(
    r'(?:mysqli_query|mysql_query|pg_query|sqlsrv_query|db_query|exec|query)\s*\('
    r'[^)]*' + _TAINT_PAT,
    re.IGNORECASE,
)

# Prepared statement with variable interpolation is still SQLi
_SQLI_PREPARE_RE = re.compile(
    r'(?:prepare|execute)\s*\(\s*["\'][^"\']*' + _TAINT_PAT,
    re.IGNORECASE,
)

# ── CWE-78: Command Injection ─────────────────────────────────────────────────
_CMDI_RE = re.compile(
    r'(?:shell_exec|exec|system|passthru|popen|proc_open|pcntl_exec)\s*\('
    r'[^)]*' + _TAINT_PAT,
    re.IGNORECASE,
)

# Backtick command execution
_BACKTICK_RE = re.compile(
    r'`[^`]*' + _TAINT_PAT,
)

# ── CWE-79: XSS ──────────────────────────────────────────────────────────────
_XSS_ECHO_RE = re.compile(
    r'(?:echo|print|printf|vprintf)\s*\(?[^)]*' + _TAINT_PAT,
    re.IGNORECASE,
)

_XSS_ASSIGN_RE = re.compile(
    r'(?:innerHTML|outerHTML|\.html\s*\(|\.append\s*\()\s*[^)]*' + _TAINT_PAT,
    re.IGNORECASE,
)

# ── CWE-22: Path Traversal ────────────────────────────────────────────────────
_PATH_TRAV_RE = re.compile(
    r'(?:file_get_contents|file_put_contents|fopen|include|require|include_once|require_once|'
    r'readfile|file|parse_ini_file|copy|rename|unlink|mkdir|rmdir)\s*\('
    r'[^)]*' + _TAINT_PAT,
    re.IGNORECASE,
)

# ── CWE-862: Missing Authentication ───────────────────────────────────────────
# Simple heuristic: detect route definitions without auth middleware calls
_PHP_ROUTE_RE = re.compile(
    r'(?:Route::(?:get|post|put|patch|delete)|'
    r'\$router->(?:get|post|put|patch|delete)|'
    r'@app\.(?:get|post|put|patch|delete))\s*\(\s*["\'](?:/admin|/api/admin|/manage|/dashboard)',
    re.IGNORECASE,
)

_PHP_AUTH_CHECK_RE = re.compile(
    r'(?:auth|Auth::check|Auth::user|Auth::id|Auth::validate|'
    r'middleware\s*\(\s*[\'"]auth|auth\s*\(\)\s*->|'
    r'\$this->middleware\s*\(\s*[\'"]auth)',
    re.IGNORECASE,
)

# ── CWE-352: CSRF ─────────────────────────────────────────────────────────────
_PHP_CSRF_RE = re.compile(
    r'(?:csrf|CSRF|_token|csrf_token|csrf_field|@csrf|verifyCsrfToken)',
)

# ── CWE-798: Hardcoded Secrets ────────────────────────────────────────────────
_HARDCODED_RE = re.compile(
    r'(?:password|passwd|pwd|secret|api_key|apikey|token|private_key)\s*=>?\s*["\'][^"\']{8,}["\']',
    re.IGNORECASE,
)
# Exclusion patterns for common FP sources:
# 1) OAuth2 $this->property references (loaded from env at runtime)
_SKIP_OAUTH_RE = re.compile(
    r'(?:client_secret|client_id|app_secret|app_id|secret_key)\s*=>?\s*\$this->',
    re.IGNORECASE,
)
# 2) URL query params (e.g. access_token=... in a URL) — not hardcoded credentials
_SKIP_URL_PARAM_RE = re.compile(r'://|access_token=|api_key=|secret=')
# 3) String identifiers/constants (e.g. 'team_invalid_secret', 'resourceToken')
#    where the value looks like a PascalCase/camelCase or lowercase_underscore identifier
#    rather than an actual credential. Key differentiator: the value is all-word-chars
#    and the left side is a class constant (uppercase) or the value is identical to the key.
_SKIP_IDENTIFIER_RE = re.compile(
    r'(?:INVALID_|CANNOT_|MODEL_)[A-Z_]+?\s*=\s*["\'][A-Za-z_][A-Za-z0-9_]*["\']',
)

# ── CWE-95: Code Injection via eval/assert ────────────────────────────────────
_EVAL_RE = re.compile(
    r'(?:eval|assert|preg_replace)\s*\([^)]*' + _TAINT_PAT,
    re.IGNORECASE,
)
_CREATE_FUNC_RE = re.compile(
    r'create_function\s*\(\s*["\'][^"\']*["\']\s*,\s*["\'][^"\']*' + _TAINT_PAT,
    re.IGNORECASE,
)

# ── CWE-918: SSRF ────────────────────────────────────────────────────────────
_SSRF_CURL_RE = re.compile(
    r'curl_exec\s*\(\s*[^)]*' + _TAINT_PAT,
    re.IGNORECASE,
)
_SSRF_FILE_GET_RE = re.compile(
    r'(?:file_get_contents|fgets|fread|readfile)\s*\(\s*[^)]*' + _TAINT_PAT,
    re.IGNORECASE,
)

# ── CWE-502: Unsafe Deserialization ──────────────────────────────────────────
_UNSERIALIZE_RE = re.compile(
    r'unserialize\s*\(\s*[^)]*' + _TAINT_PAT,
    re.IGNORECASE,
)

# ── CWE-117: Log Injection ───────────────────────────────────────────────────
_LOG_INJ_RE = re.compile(
    r'(?:error_log|syslog|trigger_error)\s*\(\s*[^)]*' + _TAINT_PAT,
    re.IGNORECASE,
)


def _scan_with_regex(code: str, findings: list[Finding]) -> None:
    """Scan PHP code with all regex patterns."""
    code.splitlines()

    def _add_finding(rule_id: str, title: str, cwe: str, severity: Severity,
                     match: re.Match, suggestion: str, confidence: float = 0.7,
                     analysis_kind: str = "pattern") -> None:
        line_no = 1 + code[:match.start()].count('\n')
        findings.append(Finding(
            category="security",
            severity=severity,
            title=title,
            description=f"Found potential {cwe} at line {line_no}",
            line=line_no,
            suggestion=suggestion,
            rule_id=rule_id,
            cwe=cwe,
            agent="php-analyzer",
            confidence=confidence,
            analysis_kind=analysis_kind,
        ))

    # SQL Injection
    for m in _SQLI_RE.finditer(code):
        _add_finding(_PH_SQLI, "SQL Injection via string concatenation", "CWE-89",
                     Severity.CRITICAL, m,
                     "Use prepared statements with bound parameters instead of concatenating "
                     "user input into SQL queries. e.g. `$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');`",
                     confidence=0.85)

    for m in _SQLI_PREPARE_RE.finditer(code):
        _add_finding(_PH_SQLI, "SQL Injection in prepared statement", "CWE-89",
                     Severity.CRITICAL, m,
                     "Prepared statements with interpolated variables are still vulnerable. "
                     "Pass values as positional parameters, not via string interpolation.",
                     confidence=0.75)

    # Command Injection
    for m in _CMDI_RE.finditer(code):
        _add_finding(_PH_CMDI, "OS Command Injection", "CWE-78",
                     Severity.CRITICAL, m,
                     "Avoid using shell execution functions with user input. "
                     "Use escapeshellarg() on each argument or use a library that handles it safely.",
                     confidence=0.80)

    for m in _BACKTICK_RE.finditer(code):
        _add_finding(_PH_CMDI, "OS Command Injection via backticks", "CWE-78",
                     Severity.CRITICAL, m,
                     "Backtick operator passes strings through the shell. "
                     "Use escapeshellarg() on all interpolated values.",
                     confidence=0.75)

    # XSS (skip framework-internal response builders)
    _XSS_SEEN: set[int] = set()
    for m in _XSS_ECHO_RE.finditer(code):
        line_no = 1 + code[:m.start()].count('\n')
        if line_no in _XSS_SEEN:
            continue
        # Skip if inside a class method returning a value (framework response builder)
        line_start = max(0, code.rfind('\n', 0, m.start()) - 200)
        context_before = code[line_start:m.start()]
        if re.search(r'(?:return|throw)\s', context_before):
            continue
        _XSS_SEEN.add(line_no)
        _add_finding(_PH_XSS, "XSS via unescaped output", "CWE-79",
                     Severity.HIGH, m,
                     "Escape all output with htmlspecialchars($var, ENT_QUOTES, 'UTF-8') "
                     "or use a templating engine with auto-escaping like Twig.",
                     confidence=0.70,
                     analysis_kind="pattern-taint")

    # Path Traversal
    for m in _PATH_TRAV_RE.finditer(code):
        _add_finding(_PH_PATH_TRAV, "Path Traversal via user input", "CWE-22",
                     Severity.HIGH, m,
                     "Validate and sanitize file paths. Use realpath() and ensure the "
                     "resolved path starts with the allowed base directory.",
                     confidence=0.70)

    # Missing Authentication
    for m in _PHP_ROUTE_RE.finditer(code):
        # Check if there's an auth check anywhere in the file
        if not _PHP_AUTH_CHECK_RE.search(code):
            _add_finding(_PH_MISSING_AUTH, "Missing authentication on admin route", "CWE-862",
                         Severity.HIGH, m,
                         "Add auth middleware to this route: e.g., `->middleware('auth')` "
                         "in Laravel or verify authentication at the start of the handler.",
                         confidence=0.65,
                         analysis_kind="route-heuristic")

    # CSRF
    if not _PHP_CSRF_RE.search(code):
        # Check for state-changing route patterns without CSRF token
        for m in re.finditer(r'(?:Route::(?:post|put|patch|delete)|'
                             r'\$router->(?:post|put|patch|delete))', code):
            _add_finding(_PH_CSRF, "CSRF protection missing on mutating route", "CWE-352",
                         Severity.MEDIUM, m,
                         "Add @csrf or verify CSRF token on all state-changing routes. "
                         "In Laravel, ensure `@csrf` is in forms or `VerifyCsrfToken` middleware is enabled.",
                         confidence=0.60,
                         analysis_kind="route-heuristic")
            break  # One CSRF finding per file

    # Hardcoded Secrets (skip OAuth2 config, URL params, and string identifiers)
    for m in _HARDCODED_RE.finditer(code):
        # Skip if the value is a $this->property reference (loaded from env)
        line_start = code.rfind('\n', 0, m.start()) + 1
        line_end = code.find('\n', m.end())
        line_text = code[line_start:line_end] if line_end > line_start else code[line_start:]
        if _SKIP_OAUTH_RE.search(line_text):
            continue
        # Skip URLs with access_token/api_key params
        if _SKIP_URL_PARAM_RE.search(line_text):
            continue
        # Skip string identifiers/constants (not actual secrets)
        if _SKIP_IDENTIFIER_RE.search(line_text):
            continue
        _add_finding(_PH_HARDCODED, "Hardcoded credential detected", "CWE-798",
                     Severity.HIGH, m,
                     "Store secrets in environment variables (e.g., `$_ENV['DB_PASSWORD']`) "
                     "or a secrets manager. Never commit credentials to version control.",
                     confidence=0.60)

    # ── CWE-95: Code Injection via eval ──────────────────────────────────────
    for m in _EVAL_RE.finditer(code):
        _add_finding(_PH_EVAL, "Code Injection via eval/assert with user input", "CWE-95",
                     Severity.CRITICAL, m,
                     "Never pass user input to eval() or assert(). Use safer alternatives "
                     "like switch/case or a lookup table.",
                     confidence=0.85)

    for m in _CREATE_FUNC_RE.finditer(code):
        _add_finding(_PH_EVAL, "Code Injection via create_function with user input", "CWE-95",
                     Severity.CRITICAL, m,
                     "create_function() is deprecated and vulnerable to code injection. "
                     "Use anonymous functions instead.",
                     confidence=0.85)

    # ── CWE-918: SSRF ────────────────────────────────────────────────────────
    for m in _SSRF_CURL_RE.finditer(code):
        _add_finding(_PH_SSRF, "Server-Side Request Forgery via curl_exec", "CWE-918",
                     Severity.HIGH, m,
                     "Validate and allowlist URLs passed to curl. Block private IP ranges "
                     "(127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).",
                     confidence=0.70)

    for m in _SSRF_FILE_GET_RE.finditer(code):
        _add_finding(_PH_SSRF, "Server-Side Request Forgery via file_get_contents", "CWE-918",
                     Severity.HIGH, m,
                     "Validate URLs passed to file_get_contents. It can fetch remote URLs "
                     "when allow_url_fopen is enabled.",
                     confidence=0.65)

    # ── CWE-502: Unsafe Deserialization ──────────────────────────────────────
    for m in _UNSERIALIZE_RE.finditer(code):
        _add_finding(_PH_UNSERIALIZE, "Unsafe deserialization via unserialize()", "CWE-502",
                     Severity.CRITICAL, m,
                     "Never call unserialize() on user-supplied data. Use json_decode() "
                     "with an explicit schema, or use a safe deserialization library.",
                     confidence=0.85)

    # ── CWE-117: Log Injection ───────────────────────────────────────────────
    for m in _LOG_INJ_RE.finditer(code):
        _add_finding(_PH_LOG_INJ, "Log Injection via error_log with user data", "CWE-117",
                     Severity.MEDIUM, m,
                     "Sanitize user input before logging: strip CRLF characters.",
                     confidence=0.60)


def analyze_php(code: str, filename: str = "") -> AnalysisResult:
    """Analyze PHP source code for security vulnerabilities."""
    result = AnalysisResult(
        file_path=filename,
        language="php",
        lines_scanned=len(code.splitlines()),
    )
    try:
        findings: list[Finding] = []
        _scan_with_regex(code, findings)
        result.findings = sorted(
            findings,
            key=lambda f: (f.line or 0, f.severity.sort_key),
        )
    except Exception as exc:
        result.parse_error = f"PHP analyzer error: {exc}"
    return result
