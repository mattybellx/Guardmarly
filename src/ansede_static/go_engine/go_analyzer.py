"""
go_engine.go_analyzer — AST-walking security analysis for Go source code.

Walks the parsed Go AST to detect:
- Tainted data flows from user input (HTTP request, CLI args) to dangerous sinks
- Missing authentication/authorization on HTTP handlers
- Hardcoded secrets, weak cryptography, SQL injection
- Path traversal, command injection, unsafe deserialization
- SSRF, open redirect, IDOR patterns

Zero dependencies — pure Python 3.9+ stdlib, parsing via go_engine.go_parser.
"""

from __future__ import annotations

from collections import defaultdict
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from ansede_static._types import AnalysisResult, Finding, Severity, TraceFrame
from ansede_static.go_engine.go_parser import (
    GoAssignStmt, GoBinaryExpr, GoBlockStmt, GoCallExpr, GoExprStmt,
    GoFile, GoFuncDecl, GoFuncLit, GoIdent, GoIfStmt, GoImportSpec,
    GoLiteral, GoReturnStmt, GoSelectorExpr, GoForStmt, GoRangeStmt,
    GoExpr, GoStmt, parse_go,
)


# ── Go security knowledge base ───────────────────────────────────────────

_GO_TAINT_SOURCES: Dict[str, str] = {
    "r.URL.Query().Get": "HTTP query parameter",
    "r.FormValue": "HTTP form value",
    "r.PostFormValue": "HTTP POST form value",
    "r.Header.Get": "HTTP header",
    "r.Cookie": "HTTP cookie",
    "r.URL": "HTTP request URL",
    "r.Body": "HTTP request body",
    "r.RemoteAddr": "Client IP address",
    "os.Args": "CLI argument",
    "flag.Args": "CLI flag argument",
    "os.Getenv": "Environment variable",
    "io.ReadAll": "IO reader (potentially untrusted)",
    "ioutil.ReadAll": "IO reader (potentially untrusted)",
    "bufio.NewScanner": "Buffered scanner input",
    "fmt.Scan": "Console input",
    "fmt.Scanf": "Console input",
    "fmt.Scanln": "Console input",
    # Chi router
    "chi.URLParam": "URL path parameter (chi router)",
    # Gin framework
    "c.Query": "Gin query parameter",
    "c.Param": "Gin URL path parameter",
    "c.PostForm": "Gin POST form value",
    "c.GetHeader": "Gin request header",
    "c.GetRawData": "Gin raw request body",
    # Echo framework
    "c.FormValue": "Echo form/query value",
    # Fiber framework
    "c.Params": "Fiber URL path parameter",
    "c.Body": "Fiber request body",
}

_GO_DANGEROUS_SINKS: Dict[str, Tuple[str, str, str]] = {
    "os/exec.Command": ("CWE-78", "OS Command Injection via exec.Command", "critical"),
    "exec.Command": ("CWE-78", "OS Command Injection via exec.Command", "critical"),
    "os/exec.CommandContext": ("CWE-78", "OS Command Injection via exec.CommandContext", "critical"),
    "exec.CommandContext": ("CWE-78", "OS Command Injection via exec.CommandContext", "critical"),
    "syscall.Exec": ("CWE-78", "OS Command Injection via syscall.Exec", "critical"),
    "os.StartProcess": ("CWE-78", "OS Command Injection via os.StartProcess", "critical"),
    "os.Open": ("CWE-22", "Path Traversal via os.Open", "high"),
    "os.OpenFile": ("CWE-22", "Path Traversal via os.OpenFile", "high"),
    "os.ReadFile": ("CWE-22", "Path Traversal via os.ReadFile", "high"),
    "os.WriteFile": ("CWE-22", "Path Traversal via os.WriteFile", "high"),
    "ioutil.ReadFile": ("CWE-22", "Path Traversal via ioutil.ReadFile", "high"),
    "ioutil.WriteFile": ("CWE-22", "Path Traversal via ioutil.WriteFile", "high"),
    "database/sql.DB.Query": ("CWE-89", "SQL Injection via db.Query", "critical"),
    "database/sql.DB.Exec": ("CWE-89", "SQL Injection via db.Exec", "critical"),
    "database/sql.DB.QueryRow": ("CWE-89", "SQL Injection via db.QueryRow", "critical"),
    # Common lowercase aliases used in real Go code (var db *sql.DB)
    "db.Query": ("CWE-89", "SQL Injection via db.Query", "critical"),
    "db.Exec": ("CWE-89", "SQL Injection via db.Exec", "critical"),
    "db.QueryRow": ("CWE-89", "SQL Injection via db.QueryRow", "critical"),
    "DB.Query": ("CWE-89", "SQL Injection via DB.Query", "critical"),
    "DB.Exec": ("CWE-89", "SQL Injection via DB.Exec", "critical"),
    "DB.QueryRow": ("CWE-89", "SQL Injection via DB.QueryRow", "critical"),
    "template.HTMLEscaper": ("CWE-79", "Unescaped template output (potential XSS)", "medium"),
    "http.Redirect": ("CWE-601", "Open Redirect via http.Redirect", "medium"),
    "http.RedirectHandler": ("CWE-601", "Open Redirect via http.RedirectHandler", "medium"),
    "http.ListenAndServe": ("CWE-400", "Unbounded HTTP server (DoS risk)", "low"),
    "net/http.Get": ("CWE-918", "SSRF via http.Get", "high"),
    "net/http.Post": ("CWE-918", "SSRF via http.Post", "high"),
    "net/http.Head": ("CWE-918", "SSRF via http.Head", "high"),
    "http.NewRequest": ("CWE-918", "SSRF via http.NewRequest", "high"),
    "json.Unmarshal": ("CWE-502", "Unsafe Deserialization via json.Unmarshal", "low"),
    "gob.NewDecoder": ("CWE-502", "Unsafe Deserialization via gob.NewDecoder", "critical"),
    "xml.Unmarshal": ("CWE-502", "XXE/Unsafe Deserialization via xml.Unmarshal", "high"),
    "crypto/md5.New": ("CWE-327", "Weak Cryptography — MD5", "medium"),
    "crypto/sha1.New": ("CWE-327", "Weak Cryptography — SHA-1", "medium"),
    "crypto/des.NewCipher": ("CWE-327", "Weak Cryptography — DES", "high"),
    "crypto/rc4.NewCipher": ("CWE-327", "Weak Cryptography — RC4", "high"),
    "math/rand.Read": ("CWE-330", "Insufficient Entropy — math/rand", "medium"),
    "log.Printf": ("CWE-532", "Sensitive Data in Logs via log.Printf", "low"),
    "log.Println": ("CWE-532", "Sensitive Data in Logs via log.Println", "low"),
    "log.Fatalf": ("CWE-532", "Sensitive Data in Logs via log.Fatalf", "low"),
    "reflect.ValueOf": ("CWE-470", "Unsafe reflection via reflect.ValueOf", "medium"),
    "unsafe.Pointer": ("CWE-822", "Unsafe pointer dereference via unsafe.Pointer", "high"),
    # Template injection / XSS via raw HTML/JS casting
    "template.HTML": ("CWE-79", "Unescaped template.HTML cast (potential XSS)", "high"),
    "template.JS": ("CWE-79", "Unescaped template.JS cast (potential XSS)", "high"),
    # Additional HTTP client sinks for SSRF
    "http.Client.Do": ("CWE-918", "SSRF via http.Client.Do", "high"),
    "resty.New": ("CWE-918", "SSRF via resty HTTP client", "high"),
}

_GO_AUTH_MIDDLEWARE_PATTERNS: List[str] = [
    "auth", "Auth", "middleware", "Middleware", "guard", "Guard",
    "RequireAuth", "WithAuth", "Authenticate", "Authorize",
    "JWT", "OAuth", "OAuth2", "Bearer", "TokenAuth", "BasicAuth",
    "Session", "CookieAuth", "APIKey", "Permission", "Role",
]

_GO_HTTP_METHODS: Set[str] = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

_GO_CWE_SUGGESTIONS: Dict[str, str] = {
    "CWE-78": "Use exec.Command with fixed arguments and validate user-controlled command parts against an allowlist.",
    "CWE-22": "Clean the path with filepath.Clean and ensure the resolved target stays under a trusted base directory.",
    "CWE-89": "Keep SQL text static and pass user values as query arguments instead of formatting them into the query string.",
    "CWE-918": "Validate outbound URLs against a strict host allowlist and reject private or loopback destinations.",
    "CWE-862": "Wrap the handler in auth middleware such as RequireAuth before registering the route.",
}


def _resolve_expr_name(expr: GoExpr) -> Optional[str]:
    """Resolve expression to a dotted name string."""
    if isinstance(expr, GoIdent):
        return expr.name
    if isinstance(expr, GoSelectorExpr):
        obj = _resolve_expr_name(expr.x)
        if obj:
            return f"{obj}.{expr.sel.name}"
        return expr.sel.name
    if isinstance(expr, GoLiteral) and isinstance(expr.value, str):
        return expr.value
    return None


def _is_taint_source(expr: GoExpr) -> Optional[str]:
    """Check if expression is a known taint source."""
    name = _resolve_expr_name(expr)
    if name is None:
        return None
    # Direct match
    if name in _GO_TAINT_SOURCES:
        return _GO_TAINT_SOURCES[name]
    # Suffix match for selector patterns
    for src, label in _GO_TAINT_SOURCES.items():
        if name.endswith(src) or (src.endswith(".Get") and name.endswith(".Get")):
            return label
    return None


def _is_request_derived(expr: GoExpr) -> bool:
    """Return True if the expression is derived from an HTTP request object.

    Recognises chained access patterns like:
      r.URL.Query().Get("key")
      req.FormValue("x")
      r.Header.Get("X-Custom")
    by checking whether the ultimate receiver is a common request variable.
    """
    if isinstance(expr, GoIdent):
        return expr.name in {"r", "req", "request", "ctx"}
    if isinstance(expr, GoSelectorExpr):
        return _is_request_derived(expr.x)
    if isinstance(expr, GoCallExpr):
        if isinstance(expr.func, GoSelectorExpr):
            return _is_request_derived(expr.func.x)
    return False


def _is_dangerous_sink(expr: GoExpr) -> Optional[Tuple[str, str, str]]:
    """Check if expression is a known dangerous sink."""
    name = _resolve_expr_name(expr)
    if name is None:
        return None
    if name in _GO_DANGEROUS_SINKS:
        return _GO_DANGEROUS_SINKS[name]
    # Qualified suffix match (name must contain '.' to avoid bare method-name
    # false positives, e.g. '.Get' matching 'net/http.Get').
    for sink_key, info in _GO_DANGEROUS_SINKS.items():
        if name.endswith(sink_key):
            return info
        if sink_key.endswith(name) and "." in name:
            return info
    return None


def _is_auth_pattern(name: str) -> bool:
    """Check if a function/type name suggests auth middleware."""
    for pat in _GO_AUTH_MIDDLEWARE_PATTERNS:
        if pat.lower() in name.lower():
            return True
    return False


def _generate_go_auto_fix(finding: Finding, lines: List[str]) -> str:
    if not finding.line or not (1 <= finding.line <= len(lines)):
        return ""
    original = lines[finding.line - 1]
    stripped = original.strip()
    indent = original[: len(original) - len(original.lstrip())]
    if not stripped or finding.rule_id != "GO-862":
        return ""

    handle_match = re.search(r"((?:[A-Za-z_][\w]*\.)?HandleFunc\s*\(\s*[^,]+,\s*)([A-Za-z_][\w]*)(\s*\))", stripped)
    if handle_match:
        updated = f"{handle_match.group(1)}RequireAuth({handle_match.group(2)}){handle_match.group(3)}"
        return f"BEFORE: {stripped}\nAFTER:  {indent}{updated}"

    route_match = re.search(r"(\.(?:GET|POST|PUT|DELETE|PATCH|Handle)\s*\(\s*[^,]+,\s*)([A-Za-z_][\w]*)(\s*\))", stripped)
    if route_match:
        updated = f"{route_match.group(1)}RequireAuth({route_match.group(2)}){route_match.group(3)}"
        return f"BEFORE: {stripped}\nAFTER:  {indent}{updated}"

    return ""


def _locate_handler_registration_line(finding: Finding, lines: List[str]) -> int | None:
    path_match = re.search(r"(/[^\s]+)", finding.title)
    handler_match = re.search(r"HTTP handler\s+([A-Za-z_][\w]*)\s+for", finding.description)
    path = path_match.group(1) if path_match else ""
    handler = handler_match.group(1) if handler_match else ""
    for index, line in enumerate(lines, start=1):
        if path and path not in line:
            continue
        if handler and handler not in line:
            continue
        if "HandleFunc(" in line or re.search(r"\.(?:GET|POST|PUT|DELETE|PATCH|Handle)\s*\(", line):
            return index
    return None


# ── AST walker ────────────────────────────────────────────────────────────

class GoSecurityWalker:
    """Walk a Go AST and collect security findings."""

    def __init__(self, filename: str = "<input>", code: str = ""):
        self.filename = filename
        self.code = code
        self.findings: List[Finding] = []
        self._imports: Dict[str, str] = {}  # local name -> import path
        self._current_func: Optional[str] = None
        self._struct_methods: Dict[str, Dict[str, GoFuncDecl]] = defaultdict(dict)
        # Track HTTP handler registrations
        self._handlers: List[Tuple[str, str, str, bool, int]] = []  # (method, path, handler, hasAuth, line)
        # Track middleware chains registered via r.Use(), router.Use(), etc.
        self._middleware_chains: List[Tuple[str, int]] = []  # (middleware_fn, line)
        # Taint tracking
        self._var_initializers: Dict[str, GoExpr] = {}
        self._tainted_vars: Set[str] = set()

    def walk(self, gofile: GoFile) -> List[Finding]:
        for imp in gofile.imports:
            alias = imp.name.name if imp.name else imp.path.rsplit("/", 1)[-1].strip('"')
            self._imports[alias] = imp.path
        for decl in gofile.decls:
            self._walk_decl(decl)
        self._check_missing_auth()
        self._detect_hardcoded_secrets()
        self._detect_dangerous_defaults()
        self._detect_regex_sinks()
        self._detect_template_ssti()
        self._detect_missing_constant_time_compare()
        return self.findings

    _GO_SECRET_PATTERNS: List[Tuple[str, str]] = [
        (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\'][A-Za-z0-9_\-]{8,}["\']', "API key"),
        (r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']', "Hardcoded password"),
        (r'(?:secret[_-]?key|secretkey)\s*[=:]\s*["\'][^"\']{4,}["\']', "Secret key"),
        (r'(?:token|auth_token|access_token)\s*[=:]\s*["\'][A-Za-z0-9_\-\.]{16,}["\']', "Auth token"),
        (r'sk-[A-Za-z0-9]{20,}', "OpenAI/Stripe secret key"),
        (r'ghp_[A-Za-z0-9]{36}', "GitHub personal access token"),
        (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', "Private key"),
        # AWS / cloud credentials
        (r'(?:aws_access_key_id|aws_secret_access_key|AKIA[A-Z0-9]{16})\s*[=:]\s*["\'][A-Za-z0-9/+=]{16,}["\']', "AWS credential"),
        # Database connection strings with embedded credentials
        (r'(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|sqlserver|redis)://[^:]+:[^@]+@', "Database connection string with credentials"),
        # JWT / signing secrets
        (r'(?:JWT_SECRET|SIGNING_KEY|HMAC_SECRET)\s*[=:]\s*["\'][^"\']{3,}["\']', "JWT or HMAC signing secret"),
    ]

    def _detect_hardcoded_secrets(self) -> None:
        """Detect hardcoded secrets in Go source code via regex."""
        for lineno, line in enumerate(self.code.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue
            for pattern, secret_type in self._GO_SECRET_PATTERNS:
                if re.search(pattern, stripped, re.IGNORECASE):
                    self.findings.append(Finding(
                        category="security",
                        severity=Severity.CRITICAL,
                        title=f"CWE-798: Hardcoded {secret_type} in Go source at line {lineno}",
                        description=f"A {secret_type} is hardcoded in Go source at L{lineno}. This is visible in version control.",
                        line=lineno,
                        suggestion="Use environment variables or a secrets manager. Rotate this credential immediately.",
                        rule_id="GO-798",
                        cwe="CWE-798",
                        agent="go-analyzer",
                        confidence=0.95,
                        analysis_kind="pattern",
                    ))
                    break

    _GO_DANGEROUS_DEFAULTS: List[Tuple[str, str, str, str]] = [
        # (regex, label, description, severity)
        (r'InsecureSkipVerify\s*:\s*true', "TLS verification disabled",
         "TLS certificate verification is disabled — vulnerable to MITM attacks", "high"),
        (r'InsecureSkipVerify\s*=\s*true', "TLS verification disabled",
         "TLS certificate verification is disabled — vulnerable to MITM attacks", "high"),
        (r'Secure\s*:\s*false', "Secure cookie flag disabled",
         "Cookie Secure flag is false — cookies sent over unencrypted HTTP", "medium"),
        (r'HttpOnly\s*:\s*false', "HttpOnly cookie flag disabled",
         "Cookie HttpOnly flag is false — cookies accessible to JavaScript (XSS risk)", "medium"),
        (r'Access-Control-Allow-Origin\s*:\s*"\*"', "CORS allow-all origin",
         "CORS allows all origins — cross-site data access possible", "high"),
        (r'SetEnv\s*\(\s*"[^"]*"\s*,\s*"[^"]*"\s*\)', "Hardcoded env var in code",
         "Environment variable set directly in code — may expose secrets", "low"),
        (r'(\*tls\.Config\{[^}]*MinVersion\s*:\s*\d+)', "TLS minimum version",
         "Check TLS MinVersion — older versions are deprecated and vulnerable", "low"),
        (r'MinVersion\s*:\s*tls\.VersionSSL30', "TLS SSLv3 enabled",
         "SSLv3 is completely broken (POODLE attack)", "critical"),
        (r'MinVersion\s*:\s*tls\.VersionTLS10', "TLS 1.0 enabled",
         "TLS 1.0 is deprecated and vulnerable to BEAST attack", "high"),
    ]

    def _detect_dangerous_defaults(self) -> None:
        """Detect dangerous default configurations in Go code (TLS, cookies, CORS)."""
        for lineno, line in enumerate(self.code.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue
            for pattern, label, desc, sev in self._GO_DANGEROUS_DEFAULTS:
                if re.search(pattern, stripped, re.IGNORECASE):
                    self.findings.append(Finding(
                        category="security",
                        severity=Severity(sev),
                        title=f"CWE-1188: Dangerous default `{label}` at line {lineno}",
                        description=f"{desc} Found at L{lineno}.",
                        line=lineno,
                        suggestion=f"Remove or gate `{label}` behind a configuration check.",
                        rule_id="GO-1188",
                        cwe="CWE-1188",
                        agent="go-analyzer",
                        confidence=0.90,
                        analysis_kind="pattern",
                    ))
                    break

    def _detect_regex_sinks(self) -> None:
        """Regex-based fallback for dangerous patterns missed by AST walker (chained calls, type conversions)."""
        _GO_REGEX_SINKS = [
            (r"gob\.NewDecoder", "CWE-502", "Unsafe deserialization via gob.NewDecoder", "critical"),
            (r"unsafe\.Pointer\s*\(", "CWE-822", "Unsafe pointer dereference via unsafe.Pointer", "high"),
        ]
        for pattern, cwe, title, severity in _GO_REGEX_SINKS:
            if re.search(pattern, self.code, re.IGNORECASE):
                for lineno, line in enumerate(self.code.splitlines(), start=1):
                    if re.search(pattern, line, re.IGNORECASE):
                        self.findings.append(Finding(
                            category="security",
                            severity=Severity(severity),
                            title=title,
                            description=f"Pattern `{pattern}` found at L{lineno} — review for security implications.",
                            line=lineno,
                            suggestion="Review this usage. If the data is untrusted, add validation or use a safer alternative.",
                            rule_id=f"GO-{cwe.replace('CWE-', '')}",
                            cwe=cwe,
                            agent="go-analyzer",
                            confidence=0.70,
                            analysis_kind="go-ast-sink",
                        ))
                        break

    def _detect_template_ssti(self) -> None:
        """CWE-94: Detect text/template used instead of html/template in web handlers.

        ``text/template`` does not auto-escape HTML, making it vulnerable to SSTI
        when user input is interpolated. Flag when it's imported in files that
        handle HTTP (have route registrations) without a corresponding
        ``html/template`` import.
        """
        has_text_template = any("text/template" in p for p in self._imports.values())
        has_html_template = any("html/template" in p for p in self._imports.values())
        is_web_handler = bool(self._handlers) or any(
            kw in self.code for kw in ("http.HandleFunc", "http.Handle", "gin.", "echo.", "fiber.", "chi.", "mux.", "router.")
        )

        if has_text_template and not has_html_template and is_web_handler:
            # Find the import line
            for lineno, line in enumerate(self.code.splitlines(), start=1):
                if "text/template" in line:
                    self.findings.append(Finding(
                        category="security",
                        severity=Severity.HIGH,
                        title="CWE-94: text/template used in web handler (SSTI risk)",
                        description="text/template is imported without html/template in a web handler file. "
                                    "text/template does not auto-escape HTML/JS, enabling server-side template "
                                    "injection when user input reaches template execution.",
                        line=lineno,
                        suggestion="Replace 'text/template' with 'html/template' for automatic context-aware escaping.",
                        rule_id="GO-94",
                        cwe="CWE-94",
                        agent="go-analyzer",
                        confidence=0.82,
                        analysis_kind="go-ast-ssti",
                    ))
                    break

    def _detect_missing_constant_time_compare(self) -> None:
        """CWE-208: Flag string comparisons that should use crypto/subtle.ConstantTimeCompare.

        Detects ``==`` or ``!=`` comparisons on strings that appear to be
        security-sensitive (tokens, HMACs, signatures, passwords) in auth
        or crypto contexts.
        """
        has_crypto_subtle = any("crypto/subtle" in p for p in self._imports.values())
        if has_crypto_subtle:
            return  # Already importing crypto/subtle — assume they know about it

        _SECURITY_STRING_CMP_RE = re.compile(
            r"(?:token|secret|hash|hmac|signature|mac|password|api[_-]?key|auth)\s*(?:==|!=)\s*",
            re.IGNORECASE,
        )

        for lineno, line in enumerate(self.code.splitlines(), start=1):
            if _SECURITY_STRING_CMP_RE.search(line):
                # Only flag in functions that look auth/crypto-related
                context_start = max(0, lineno - 10)
                context = "\n".join(self.code.splitlines()[context_start:lineno])
                if re.search(r"(?:func\s+\w*(?:Auth|Verify|Check|Validate|Login|Crypto|Hash|Sign|HMAC))", context, re.IGNORECASE):
                    self.findings.append(Finding(
                        category="security",
                        severity=Severity.MEDIUM,
                        title="CWE-208: String comparison of security value — not timing-safe",
                        description=f"Security-sensitive string comparison at L{lineno} uses `==` instead "
                                    "of `crypto/subtle.ConstantTimeCompare`. This is vulnerable to timing attacks "
                                    "that can leak the expected value byte-by-byte.",
                        line=lineno,
                        suggestion="Use `subtle.ConstantTimeCompare([]byte(a), []byte(b))` to prevent timing side-channel attacks.",
                        rule_id="GO-208",
                        cwe="CWE-208",
                        agent="go-analyzer",
                        confidence=0.68,
                        analysis_kind="go-ast-timing",
                    ))
                    break  # One finding per file is enough

    def _walk_decl(self, decl: GoFuncDecl) -> None:
        prev = self._current_func
        self._current_func = decl.name.name
        # Check if function name matches auth patterns
        if _is_auth_pattern(decl.name.name):
            self._detect_http_handler_with_auth(decl)
        self._walk_block(decl.type_.body)
        self._current_func = prev

    def _walk_block(self, block: GoBlockStmt) -> None:
        for stmt in block.body:
            self._walk_stmt(stmt)

    def _walk_stmt(self, stmt: GoStmt) -> None:
        if isinstance(stmt, GoAssignStmt):
            self._walk_assign(stmt)
        elif isinstance(stmt, GoExprStmt):
            self._walk_expr(stmt.x)
        elif isinstance(stmt, GoReturnStmt):
            for r in stmt.results:
                self._walk_expr(r)
        elif isinstance(stmt, GoIfStmt):
            self._walk_expr(stmt.cond)
            self._walk_block(stmt.body)
            if stmt.else_ and isinstance(stmt.else_, (GoBlockStmt, GoIfStmt)):
                self._walk_stmt(stmt.else_)
        elif isinstance(stmt, GoForStmt):
            if stmt.cond:
                self._walk_expr(stmt.cond)
            self._walk_block(stmt.body)
        elif isinstance(stmt, GoRangeStmt):
            self._walk_block(stmt.body)
        elif isinstance(stmt, GoBlockStmt):
            self._walk_block(stmt)
        elif isinstance(stmt, GoFuncDecl):
            self._walk_decl(stmt)

    def _walk_expr(self, expr: GoExpr) -> None:
        if isinstance(expr, GoCallExpr):
            self._walk_call(expr)
        elif isinstance(expr, GoBinaryExpr):
            self._walk_expr(expr.left)
            self._walk_expr(expr.right)
        elif isinstance(expr, GoSelectorExpr):
            self._walk_expr(expr.x)
        elif isinstance(expr, GoFuncLit):
            self._walk_block(expr.body)
        # GoIdent, GoLiteral — leaf nodes

    def _walk_call(self, call: GoCallExpr) -> None:
        func_name = _resolve_expr_name(call.func)

        # Detect HTTP route registration: http.HandleFunc("/path", handler)
        if func_name and "HandleFunc" in func_name and len(call.args) >= 2:
            path = _resolve_expr_name(call.args[0]) or "/"
            handler_name = _resolve_expr_name(call.args[1]) or "unknown"
            has_auth = _is_auth_pattern(handler_name)
            self._handlers.append(("ANY", path, handler_name, has_auth, call.loc[0]))
            return

        # Detect mux.Handle, router.GET, etc. — restrict to router-like receivers
        # to avoid treating http.Post(url, ...) as a route registration.
        if func_name:
            upper = func_name.upper()
            # Only treat as route registration if the receiver looks like a router variable
            # (short names like r, router, mux, app, srv, server) not "http", "net", etc.
            _receiver = func_name.split(".")[0].lower() if "." in func_name else ""
            if _receiver in {"r", "router", "mux", "app", "srv", "server", "engine", "group", "api"}:
                method = next((m for m in _GO_HTTP_METHODS if upper.endswith("." + m)), None)
                if method and len(call.args) >= 2:
                    path = _resolve_expr_name(call.args[0]) or "/"
                    handler_name = _resolve_expr_name(call.args[1]) or "unknown"
                    has_auth = _is_auth_pattern(handler_name)
                    self._handlers.append((method, path, handler_name, has_auth, call.loc[0]))
                    return

        # Detect middleware registration: r.Use(...), router.Use(...), ginRouter.Use(...)
        if func_name and func_name.endswith(".Use") and len(call.args) >= 1:
            for arg in call.args:
                mw_name = _resolve_expr_name(arg)
                if mw_name:
                    self._middleware_chains.append((mw_name, call.loc[0]))
            return

        # Detect gin/echo/chi group middleware: group.Use(...)
        if func_name and func_name.endswith(".Group") and len(call.args) >= 2:
            # router.Group("/admin", middlewareFn) — middleware as extra args
            for arg in call.args[1:]:
                mw_name = _resolve_expr_name(arg)
                if mw_name:
                    self._middleware_chains.append((mw_name, call.loc[0]))
            return

        # Check for dangerous sink with tainted args
        sink_info = _is_dangerous_sink(call.func)
        if sink_info:
            cwe, title, severity = sink_info
            for arg in call.args:
                source = self._check_taint(arg)
                if source:
                    sev = Severity(severity)
                    self.findings.append(Finding(
                        category="security",
                        severity=sev,
                        title=title,
                        description=f"User-controlled data from {source} flows into {func_name}",
                        line=call.loc[0],
                        rule_id=f"GO-{cwe.replace('CWE-', '')}",
                        cwe=cwe,
                        confidence=0.85,
                        trace=(
                            TraceFrame(kind="source", label=f"Taint source: {source}", line=call.loc[0]),
                            TraceFrame(kind="sink", label=f"Sink: {func_name}()", line=call.loc[0]),
                        ),
                        analysis_kind="go-ast-taint",
                    ))
                    return
            # Flag even without taint for critical sinks
            if severity in ("critical", "high"):
                sev = Severity(severity)
                self.findings.append(Finding(
                    category="security",
                    severity=sev,
                    title=title,
                    description=f"Dangerous call to {func_name} detected (no taint source identified but sink is high-risk)",
                    line=call.loc[0],
                    rule_id=f"GO-{cwe.replace('CWE-', '')}",
                    cwe=cwe,
                    confidence=0.55 if severity == "critical" else 0.40,
                    trace=(TraceFrame(kind="sink", label=f"Sink: {func_name}()", line=call.loc[0]),),
                    analysis_kind="go-ast-sink",
                ))

        # Walk sub-expressions (including func so chained calls like
        # exec.Command(...).Output() properly visit the inner dangerous call).

        # --- XSS detection for standalone response writes (not just assignments) ---
        if sink_info is None and func_name:
            _xss_pats = ["Write", "Execute", "WriteString", "Fprintf"]
            for _xp in _xss_pats:
                if _xp in func_name:
                    for _arg_idx in range(1, len(call.args)):
                        _src = self._check_taint(call.args[_arg_idx])
                        if _src:
                            self.findings.append(Finding(
                                category="security", severity=Severity.HIGH,
                                title="CWE-79: XSS via " + func_name + " with tainted content",
                                description="HTTP response write function `" + func_name + "` receives tainted data.",
                                line=getattr(call, "line", 0) or (call.loc[0] if hasattr(call, "loc") and call.loc else 0),
                                suggestion="Escape untrusted data before writing to response. Use template.HTMLEscapeString().",
                                rule_id="GO-79", cwe="CWE-79", agent="go-analyzer",
                                confidence=0.85,
                                analysis_kind="go-ast-taint",
                            ))
                            break
                    break

        self._walk_expr(call.func)
        for arg in call.args:
            self._walk_expr(arg)

    def _walk_assign(self, stmt: GoAssignStmt) -> None:
        """Track variable assignments for taint flow and detect dangerous patterns."""
        for rhs in stmt.rhs:
            self._walk_expr(rhs)
            # Track taint through variable assignments
            if stmt.op in (":=", "="):
                source = self._check_taint(rhs)
                if source:
                    for lhs in stmt.lhs:
                        name = _resolve_expr_name(lhs)
                        if name:
                            self._tainted_vars.add(name)
                # Track initializers for later resolution
                for lhs in stmt.lhs:
                    name = _resolve_expr_name(lhs)
                    if name and not isinstance(rhs, GoCallExpr):
                        self._var_initializers[name] = rhs

            # Detect XSS: w.Write([]byte(userInput)) or template.Execute(w, data)
            func_name = _resolve_expr_name(rhs) if isinstance(rhs, GoCallExpr) else None
            if func_name:
                self._detect_xss_in_response(func_name, rhs if isinstance(rhs, GoCallExpr) else None)

    def _check_taint(self, expr: GoExpr) -> Optional[str]:
        """Check if expression references a taint source."""
        # Direct source match
        source = _is_taint_source(expr)
        if source:
            return source
        # Variable that was initialized from a source
        if isinstance(expr, GoIdent):
            if expr.name in self._tainted_vars:
                return f"tainted variable '{expr.name}'"
            if expr.name in self._var_initializers:
                return self._check_taint(self._var_initializers[expr.name])
        # Binary expression: fmt.Sprintf(format, userInput)
        if isinstance(expr, GoBinaryExpr):
            return self._check_taint(expr.left) or self._check_taint(expr.right)
        # Call expression: check if the call produces tainted output
        if isinstance(expr, GoCallExpr):
            for arg in expr.args:
                src = self._check_taint(arg)
                if src:
                    return src
            # Recognise chained request access like r.URL.Query().Get("key")
            if _is_request_derived(expr):
                func_name = _resolve_expr_name(expr.func) or ""
                sel = func_name.rsplit(".", 1)[-1] if "." in func_name else func_name
                return f"HTTP request ({sel})"
            func_name = _resolve_expr_name(expr.func)
            if func_name and func_name in _GO_TAINT_SOURCES:
                return _GO_TAINT_SOURCES[func_name]
        # Selector expression: walk the object
        if isinstance(expr, GoSelectorExpr):
            return self._check_taint(expr.x)
        return None

    def _detect_xss_in_response(self, func_name: str, call: Optional[GoCallExpr]) -> None:
        """Detect XSS patterns in HTTP response writing."""
        xss_patterns = ["Write", "Execute", "ExecuteTemplate", "WriteString", "Fprintf"]
        for pat in xss_patterns:
            if pat in func_name and call:
                for arg in call.args[1:]:  # Skip the writer argument
                    source = self._check_taint(arg)
                    if source:
                        self.findings.append(Finding(
                            category="security",
                            severity=Severity.HIGH,
                            title="XSS via HTTP response writing",
                            description=f"User-controlled data from {source} written to HTTP response via {func_name}",
                            line=call.loc[0],
                            rule_id="GO-79",
                            cwe="CWE-79",
                            confidence=0.82,
                            trace=(
                                TraceFrame(kind="source", label=f"Taint source: {source}", line=call.loc[0]),
                                TraceFrame(kind="sink", label=f"XSS sink: {func_name}()", line=call.loc[0]),
                            ),
                            analysis_kind="go-ast-xss",
                        ))

    def _detect_http_handler_with_auth(self, func: GoFuncDecl) -> None:
        """Check if a handler function uses auth middleware."""
        # Walk the function body looking for auth checks
        for stmt in func.type_.body.body:
            if isinstance(stmt, GoIfStmt):
                cond_name = _resolve_expr_name(stmt.cond)
                if cond_name and _is_auth_pattern(cond_name):
                    # Handler checks auth — mark it
                    pass

    def _check_missing_auth(self) -> None:
        """Flag HTTP handlers without auth on sensitive paths.

        Checks both per-handler auth patterns AND global middleware chains
        registered via r.Use() / router.Use() / ginRouter.Use().
        """
        # Build the set of auth middleware names available in the chain
        chain_auth = any(_is_auth_pattern(mw) for mw, _ in self._middleware_chains)

        sensitive_prefixes = ("/admin", "/api/admin", "/manage", "/dashboard", "/config", "/secret", "/users", "/internal")
        for method, path, handler, has_auth, line in self._handlers:
            if has_auth or chain_auth:
                continue
            path_lower = path.lower().strip('"')
            if not any(path_lower.startswith(p) for p in sensitive_prefixes):
                continue
            if path_lower in ("/login", "/signup", "/register", "/health", "/ready", "/status"):
                continue

            # Build trace frames that show the middleware chain context
            trace_frames = [
                TraceFrame(kind="route", label=f"{method} {path}", line=line),
            ]
            if self._middleware_chains:
                mw_list = ", ".join(mw for mw, _ in self._middleware_chains)
                trace_frames.append(
                    TraceFrame(kind="middleware", label=f"Middleware chain present: [{mw_list}]", line=0),
                )
            trace_frames.append(
                TraceFrame(kind="auth", label="No auth middleware detected", line=0),
            )

            self.findings.append(Finding(
                category="security",
                severity=Severity.HIGH,
                title=f"Missing authentication on {method} {path}",
                description=f"HTTP handler {handler} for {method} {path} does not appear to enforce authentication",
                line=line,
                suggestion=_GO_CWE_SUGGESTIONS["CWE-862"],
                rule_id="GO-862",
                cwe="CWE-862",
                confidence=0.78,
                trace=tuple(trace_frames),
                analysis_kind="go-ast-auth",
            ))


def run_go_analysis(
    code: str,
    *,
    filename: str = "<input>",
    global_graph: Optional[Any] = None,
) -> AnalysisResult:
    """Run security analysis on Go source code.

    Returns an AnalysisResult containing findings from walking the parsed AST.

    When *global_graph* is provided, detected HTTP handler functions are
    recorded as ``FunctionSummary`` entries for cross-language inter-procedural
    analysis.
    """
    result = AnalysisResult(file_path=filename, language="go")
    # Skip test files — Go test helpers often write files safely
    if filename.endswith("_test.go"):
        return result
    result.lines_scanned = len(code.splitlines())

    try:
        gofile = parse_go(code, filename)
    except Exception as exc:
        result.parse_error = f"Go parse error: {exc}"
        return result

    try:
        walker = GoSecurityWalker(filename, code=code)
        result.findings = walker.walk(gofile)
    except Exception as exc:
        result.parse_error = f"Go analysis error: {exc}"

    if not result.parse_error:
        lines = code.splitlines()
        for finding in result.findings:
            if finding.rule_id == "GO-862" and not finding.line:
                resolved_line = _locate_handler_registration_line(finding, lines)
                if resolved_line is not None:
                    finding.line = resolved_line
            if not finding.suggestion and finding.cwe:
                finding.suggestion = _GO_CWE_SUGGESTIONS.get(finding.cwe, "")
            if not finding.auto_fix:
                finding.auto_fix = _generate_go_auto_fix(finding, lines)

    # ── Record FunctionSummary for detected handlers ─────────────────────
    if global_graph is not None:
        try:
            _record_go_function_summaries(global_graph, filename, result.findings)
        except Exception:
            pass  # non-blocking — summary recording is best-effort

    return result


def _record_go_function_summaries(
    global_graph: Any,
    file_path: str,
    findings: List[Finding],
) -> None:
    """Record Go handler findings as FunctionSummary entries for cross-language taint."""
    from ansede_static.ir.global_graph import FunctionSummary

    # Group findings by handler function (extracted from rule_id + line)
    handler_signatures: Dict[str, List[Finding]] = {}
    for f in findings:
        key = f"{f.rule_id}:{f.line}"
        handler_signatures.setdefault(key, []).append(f)

    for key, group in handler_signatures.items():
        rule_id = key.split(":")[0]
        handler_name = f"go_handler_{rule_id}_line{group[0].line}"
        sinks = []
        sources = []
        for f in group:
            if f.cwe:
                sinks.append(f.cwe)
            for frame in (f.trace or ()):
                if frame.kind == "source":
                    sources.append(frame.label)
        summary = FunctionSummary(
            file_path=file_path,
            function_name=handler_name,
            parameter_names=[],
            return_type="*",
            is_source=bool(sources),
            is_sink=bool(sinks),
            taint_sources=sources,
            taint_sinks=sinks,
        )
        global_graph.record_function_summary(summary)
