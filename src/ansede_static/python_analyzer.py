"""
ansede_static.python_analyzer
─────────────────────────────
Deterministic AST-based security analyzer for Python source code.

Zero external dependencies — pure Python 3.9+ stdlib only.
No GPU, no LLM, no API keys required.

Public API
──────────
    from ansede_static.python_analyzer import analyze_python
    findings = analyze_python(source_code, filename="app.py")

Each Finding has: severity, title, description, line, suggestion, cwe, auto_fix.

Detection coverage (28 rule categories):
  CWE-89   SQL Injection (taint + AST)
  CWE-78   Command Injection (subprocess + shell=True)
  CWE-95   Code Injection (eval/exec/compile)
  CWE-502  Unsafe Deserialization (pickle/marshal/yaml.load)
  CWE-22   Path Traversal (os.path.join, open(), Path.read_text)
  CWE-918  SSRF (urlopen/requests with unvalidated URL)
  CWE-798  Hardcoded Secrets (API keys, tokens, passwords, JWT secrets)
  CWE-1188 Dangerous Defaults (debug=True, verify=False, CORS wildcard)
  CWE-327  Weak Cryptography (MD5/SHA1 for passwords)
  CWE-338  Weak PRNG (random module for security tokens)
  CWE-862  Missing Authentication (Flask/FastAPI routes with no auth)
  CWE-639  IDOR (resource fetched by ID without owner check)
  CWE-285  Missing Ownership Check (mutation without prior ownership verify)
  CWE-287  Auth Bypass (presence-only token check, two-line patterns)
  CWE-617  Error Handling (silent exception swallowing)
  CWE-117  Log Injection (untrusted data in log calls)
  CWE-345  Auth decorator pattern anti-patterns
  CWE-601  Open Redirect (redirect/Response with user-controlled URL)
  CWE-532  Sensitive Data Logging (PII/credentials in log calls)
  CWE-915  Mass Assignment (request.json iterated to set DB fields)
  Cross-function taint (inter-procedural analysis)
"""
from __future__ import annotations

import ast
import io
import re
import tokenize as _tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Union


# ──────────────────────────────────────────────────────────────────────────────
# Re-export types for convenience
# ──────────────────────────────────────────────────────────────────────────────

from ansede_static._types import Finding, Severity, AnalysisResult, TraceFrame


_TaintInfo = tuple[str, int, set[str], tuple[TraceFrame, ...]]


# ──────────────────────────────────────────────────────────────────────────────
# Taint source catalogue
# ──────────────────────────────────────────────────────────────────────────────

TAINT_SOURCES: dict[str, str] = {
    # Flask / FastAPI / Django
    "request.args":         "HTTP query parameter",
    "request.form":         "HTTP form data",
    "request.data":         "raw HTTP body",
    "request.json":         "parsed HTTP JSON body",
    "request.files":        "uploaded file",
    "request.headers":      "HTTP header",
    "request.cookies":      "HTTP cookie",
    "request.GET":          "HTTP query parameter (Django)",
    "request.POST":         "HTTP form data (Django)",
    "request.body":         "raw HTTP body (Django)",
    "request.query_params": "query parameter (FastAPI)",
    "request.get_json":     "parsed HTTP JSON body (Flask get_json())",
    # Standard input
    "input":                "user console input",
    "sys.argv":             "command-line argument",
    "sys.stdin":            "stdin",
    # Environment
    "os.environ":           "environment variable",
    "os.getenv":            "environment variable",
    # Unsafe deserialization (result already tainted)
    "json.loads":           "parsed JSON (may be from untrusted source)",
    "yaml.load":            "parsed YAML (unsafe loader)",
    "yaml.unsafe_load":     "parsed YAML (unsafe)",
}

# ──────────────────────────────────────────────────────────────────────────────
# Taint sink catalogue — maps callee name → (CWE, vuln description)
# ──────────────────────────────────────────────────────────────────────────────

_SinkInfo = Union[tuple[str, str], tuple[str, str, str]]


TAINT_SINKS: dict[str, _SinkInfo] = {
    # SQL Injection — CWE-89
    "cursor.execute":             ("CWE-89", "SQL Injection"),
    "execute":                    ("CWE-89", "SQL Injection"),
    "executemany":                ("CWE-89", "SQL Injection"),
    "raw":                        ("CWE-89", "SQL Injection (Django ORM raw)"),
    "extra":                      ("CWE-89", "SQL Injection (Django ORM extra)"),
    # Command Injection — CWE-78
    "os.system":                  ("CWE-78", "OS Command Injection"),
    "os.popen":                   ("CWE-78", "OS Command Injection"),
    "subprocess.call":            ("CWE-78", "OS Command Injection"),
    "subprocess.run":             ("CWE-78", "OS Command Injection"),
    "subprocess.Popen":           ("CWE-78", "OS Command Injection"),
    "subprocess.check_output":    ("CWE-78", "OS Command Injection"),
    "subprocess.check_call":      ("CWE-78", "OS Command Injection"),
    # Code Injection — CWE-95
    "eval":                       ("CWE-95", "Code Injection via eval()"),
    "exec":                       ("CWE-95", "Code Injection via exec()"),
    "compile":                    ("CWE-95", "Code Injection via compile()"),
    "__import__":                 ("CWE-95", "Dynamic import injection"),
    # Deserialization — CWE-502
    "pickle.loads":               ("CWE-502", "Unsafe Deserialization"),
    "pickle.load":                ("CWE-502", "Unsafe Deserialization"),
    "marshal.loads":              ("CWE-502", "Unsafe Deserialization"),
    "yaml.load":                  ("CWE-502", "Unsafe Deserialization (yaml.load)"),
    # SSRF — CWE-918
    "requests.get":               ("CWE-918", "Server-Side Request Forgery"),
    "requests.post":              ("CWE-918", "Server-Side Request Forgery"),
    "urllib.request.urlopen":     ("CWE-918", "Server-Side Request Forgery"),
    "urlopen":                    ("CWE-918", "Server-Side Request Forgery"),
    "httpx.get":                  ("CWE-918", "Server-Side Request Forgery"),
    "httpx.post":                 ("CWE-918", "Server-Side Request Forgery"),
    # XSS — CWE-79
    "render_template_string":     ("CWE-79", "Cross-Site Scripting (template injection)"),
    "Markup":                     ("CWE-79", "Cross-Site Scripting (unescaped HTML)"),
}

# ──────────────────────────────────────────────────────────────────────────────
# Sanitizer catalogue — these calls neutralise taint for the listed CWEs
# ──────────────────────────────────────────────────────────────────────────────

SANITIZERS: dict[str, set[str]] = {
    "shlex.quote":                    {"CWE-78"},
    "shlex.split":                    {"CWE-78"},
    "pipes.quote":                    {"CWE-78"},
    "bleach.clean":                   {"CWE-79"},
    "markupsafe.escape":              {"CWE-79"},
    "html.escape":                    {"CWE-79"},
    "escape":                         {"CWE-79"},
    "django.utils.html.escape":       {"CWE-79"},
    "os.path.basename":               {"CWE-22"},
    "secure_filename":                {"CWE-22"},
    "werkzeug.utils.secure_filename": {"CWE-22"},
    "Path.resolve":                   {"CWE-22"},
    "json.loads":                     {"CWE-502"},
    "json.load":                      {"CWE-502"},
    "ast.literal_eval":               {"CWE-95"},
    "int":                            {"CWE-89", "CWE-78", "CWE-95"},
    "float":                          {"CWE-89", "CWE-78", "CWE-95"},
    "bool":                           {"CWE-89", "CWE-78", "CWE-95"},
    "uuid.UUID":                      {"CWE-89", "CWE-78"},
    "urllib.parse.urlparse":          {"CWE-918"},
    "validators.url":                 {"CWE-918"},
    "ipaddress.ip_address":           {"CWE-918"},
    # Regex validation (anchored patterns only — checked at use site)
    "re.match":                       {"CWE-89", "CWE-78", "CWE-22"},
    "re.fullmatch":                   {"CWE-89", "CWE-78", "CWE-22"},
    "re.search":                      {"CWE-89"},
}

# ──────────────────────────────────────────────────────────────────────────────
# Hardcoded secret patterns — CWE-798
# ──────────────────────────────────────────────────────────────────────────────

SECRET_PATTERNS: list[tuple[str, str]] = [
    (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\'][A-Za-z0-9_\-]{8,}["\']',              "API key"),
    (r'(?:secret[_-]?key|secretkey)["\']?\]?\s*[=:]\s*["\'][^"\']{4,}["\']',       "Secret key"),
    (r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']',                      "Hardcoded password"),
    (r'(?:token|auth_token|access_token)\s*[=:]\s*["\'][A-Za-z0-9_\-\.]{16,}["\']',"Auth token"),
    (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',                               "Private key"),
    (r'(?:aws_access_key_id|aws_secret_access_key)\s*[=:]\s*["\'][A-Za-z0-9/+=]{16,}["\']', "AWS credential"),
    (r'ghp_[A-Za-z0-9]{36}',                                                         "GitHub personal access token"),
    (r'sk-[A-Za-z0-9]{20,}',                                                         "OpenAI/Stripe secret key"),
    (r'(?:mongodb\+srv|postgres|mysql)://[^:]+:[^@]+@',                             "Database connection string with credentials"),
    (r'(?:JWT_SECRET|JWT_SECRET_KEY|SIGNING_KEY)\s*[=:]\s*["\'][^"\']{3,}["\']',    "JWT signing secret"),
]

# ──────────────────────────────────────────────────────────────────────────────
# Dangerous defaults — CWE-1188
# ──────────────────────────────────────────────────────────────────────────────

DANGEROUS_DEFAULTS: list[tuple[str, str, str]] = [
    (r'\bdebug\s*=\s*True\b',      "debug=True",    "Debug mode enabled — leaks stack traces and internal state in production"),
    (r'\bverify\s*=\s*False\b',    "verify=False",  "SSL verification disabled — vulnerable to MITM attacks"),
    (r'\bsecure\s*=\s*False\b',    "secure=False",  "Secure flag disabled on cookie/connection"),
    (r'\bhttponly\s*=\s*False\b',  "httponly=False","HTTPOnly disabled — cookies accessible to JavaScript (XSS risk)"),
    (r'\bSECRET_KEY\s*=\s*["\'](?:secret|changeme|password|default|test)["\']',
                                   "weak SECRET_KEY","Predictable/default secret key — session forgery possible"),
    (r'\ballowed_hosts\s*=\s*\[\s*["\']\*["\']\s*\]',
                                   "ALLOWED_HOSTS=['*']", "All hosts allowed — host header injection possible"),
    (r'\bCORS.*(?:allow_all|origins\s*=\s*\[?\s*["\']\*["\'])',
                                   "CORS allow-all",  "CORS allows all origins — cross-site data theft possible"),
]

# ──────────────────────────────────────────────────────────────────────────────
# Broken authentication patterns
# ──────────────────────────────────────────────────────────────────────────────

BROKEN_AUTH_PATTERNS: list[tuple[str, str, str, str]] = [
    (
        r'if\s+(?:request\.headers\.get|request\.cookies\.get)\s*\(.+?\)\s*:',
        "Authentication checks header/cookie presence only, not value validity",
        "The check only tests if a header/cookie EXISTS, not if its value is valid. "
        "An attacker can send any non-empty value to bypass authentication.",
        "CWE-287",
    ),
    (
        r'(?:jwt|token).*(?:verify|decode).*(?:verify\s*=\s*False|options.*verify.*False)',
        "JWT verification disabled",
        "JWT token verification is disabled. An attacker can forge arbitrary tokens.",
        "CWE-345",
    ),
    (
        r'session\[.+?\]\s*=\s*(?:True|request\.\w+)',
        "Session data set from unvalidated input",
        "Session attributes are assigned directly from request data without validation, "
        "enabling session fixation or privilege escalation.",
        "CWE-384",
    ),
]

# ──────────────────────────────────────────────────────────────────────────────
# Auth decorator names recognised as protecting a route
# ──────────────────────────────────────────────────────────────────────────────

_AUTH_DECORATORS: frozenset[str] = frozenset({
    "login_required", "require_auth", "auth_required", "jwt_required",
    "token_required", "authenticated", "permission_required",
    "requires_auth", "verify_token", "api_key_required", "requires_login",
    "admin_required", "staff_required", "superuser_required",
    "role_required", "requires_role", "requires_admin",
    "requires_permission",
})

_PRIVILEGE_DECORATORS: frozenset[str] = frozenset({
    "admin_required", "staff_required", "superuser_required",
    "role_required", "requires_role", "requires_admin",
    "permission_required", "requires_permission",
})

_FLASK_ROUTE_ATTRS: frozenset[str] = frozenset({
    "route", "get", "post", "put", "patch", "delete", "options",
})

_OWNERSHIP_RE: re.Pattern[str] = re.compile(
    r'owner(?:_id)?|user_id|account_id|tenant_id|created_by|author_id|'
    r'belongs_to|organization_id|org_id|workspace_id|project_id',
    re.IGNORECASE,
)

_ID_LIKE_NAME_RE: re.Pattern[str] = re.compile(
    r'^(?:id|uid|pk|slug|[A-Za-z_]\w*_(?:id|uid|pk|slug))$',
    re.IGNORECASE,
)

_PRINCIPAL_ALIAS_NAME_RE: re.Pattern[str] = re.compile(
    r'current_user|viewer|principal|identity|actor',
    re.IGNORECASE,
)

_PRINCIPAL_REF_RE: re.Pattern[str] = re.compile(
    r'\bg\.user(?:_id)?\b|'
    r'\bcurrent_user(?:\.\w+)?\b|'
    r'\brequest\.user(?:\.\w+)?\b|'
    r'\bsession\[[^\]]*(?:user_id|uid|sub)[^\]]*\]|'
    r'\bprincipal(?:_id)?\b|'
    r'\bidentity(?:_id)?\b|'
    r'\bactor(?:_id)?\b|'
    r'\bviewer(?:_id)?\b|'
    r'\bclaims\[[^\]]*(?:sub|user_id|uid)[^\]]*\]',
    re.IGNORECASE,
)

_OWNERSHIP_HELPER_RE: re.Pattern[str] = re.compile(
    r'owner|authori[sz]e|permission|has_access|check_access|ensure_access|'
    r'verify_access|require_(?:owner|access)|can_(?:view|edit|delete|update|manage)|'
    r'is_owner|owns|same_user',
    re.IGNORECASE,
)

_ORM_SCOPE_NAMES: frozenset[str] = frozenset({"query", "objects", "session"})

_ORM_LOOKUP_TERMINALS: frozenset[str] = frozenset({
    "get", "get_or_404", "first", "first_or_404", "one", "one_or_none",
    "scalar", "scalar_one", "scalar_one_or_none",
})

_DIRECT_MUTATION_CALLS: frozenset[str] = frozenset({"delete", "update", "save"})

_PUBLIC_ROUTE_PAT: re.Pattern[str] = re.compile(
    r'/(?:login|logout|register|signup|sign.?up|password.?reset|forgot.?password|'
    r'auth|oauth|callback|verify.?email|confirm|public|health|ping|status|'
    r'well.?known|favicon|robots|index|home|about|contact|terms|privacy|'
    r'sitemap|feed|rss|atom|api/docs|openapi|swagger|redoc|schema|'
    r'manifest|version|ready|live|liveness|readiness|healthz)',
    re.IGNORECASE,
)
_ADMIN_PATH_PAT: re.Pattern[str] = re.compile(r'/admin', re.IGNORECASE)
_PRIVILEGED_ENDPOINT_PAT: re.Pattern[str] = re.compile(r'admin|internal|staff|superuser|root', re.IGNORECASE)
_PRIVILEGE_CHECK_PAT: re.Pattern[str] = re.compile(
    r'admin|staff|superuser|root|role|privilege|permission|scope|acl|rbac|'
    r'is_admin|is_staff|is_superuser|has_role|check_role|has_permission|'
    r'check_permission|require_admin|requires_admin|require_role|authorize|can_manage',
    re.IGNORECASE,
)
_PRIVILEGE_VALUE_PAT: re.Pattern[str] = re.compile(r'admin|staff|superuser|root', re.IGNORECASE)

# Inline suppression:  # ansede: ignore  |  # ansede: ignore[CWE-862]
_SUPPRESSION_RE: re.Pattern[str] = re.compile(
    r'#\s*ansede:\s*ignore(?:\[([\w\-,\s]+)\])?', re.IGNORECASE,
)

# HTTP methods that mutate state — higher risk without auth
_MUTATING_METHODS: frozenset[str] = frozenset({
    "post", "put", "patch", "delete",
})

# Patterns in route paths that suggest resource-specific CRUD endpoints
_RESOURCE_ID_PAT: re.Pattern[str] = re.compile(
    r'<\s*(?:int|string|uuid)?\s*:?\s*\w*(?:id|slug|pk)\s*>', re.IGNORECASE,
)


# ──────────────────────────────────────────────────────────────────────────────
# Taint helper functions
# ──────────────────────────────────────────────────────────────────────────────

def _get_taint_source(node: ast.expr) -> str | None:
    """Return a human-readable taint-source description, or None if node is not tainted."""
    if isinstance(node, ast.Attribute):
        parts: list[str] = []
        cur: ast.expr = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        parts.reverse()
        dotted = ".".join(parts)
        for src, desc in TAINT_SOURCES.items():
            if dotted.startswith(src):
                return desc

    if isinstance(node, ast.Call):
        call_name = ""
        if isinstance(node.func, ast.Name):
            call_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts2: list[str] = []
            cur2: ast.expr = node.func
            while isinstance(cur2, ast.Attribute):
                parts2.append(cur2.attr)
                cur2 = cur2.value
            if isinstance(cur2, ast.Name):
                parts2.append(cur2.id)
            parts2.reverse()
            call_name = ".".join(parts2)
        for src, desc in TAINT_SOURCES.items():
            if call_name == src or call_name.startswith(src + "."):
                return desc

    if isinstance(node, ast.Subscript):
        return _get_taint_source(node.value)

    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        src = _get_taint_source(node.func.value)
        if src:
            return src

    return None


def _get_call_name(node: ast.Call) -> str:
    """Return the full dotted name of a Call node (e.g. 'shlex.quote')."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        parts: list[str] = []
        cur: ast.expr = node.func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        parts.reverse()
        return ".".join(parts)
    return ""


def _make_trace_frame(
    kind: str,
    label: str,
    node: ast.AST | None = None,
    *,
    line: int | None = None,
) -> TraceFrame:
    """Create a normalized trace frame from an AST node or explicit line number."""
    return TraceFrame(
        kind=kind,
        label=label,
        line=getattr(node, "lineno", None) or line,
    )


def _append_trace(
    trace: tuple[TraceFrame, ...],
    kind: str,
    label: str,
    node: ast.AST | None = None,
    *,
    line: int | None = None,
) -> tuple[TraceFrame, ...]:
    """Append a trace frame if it is not a duplicate of the most recent step."""
    frame = _make_trace_frame(kind, label, node, line=line)
    if trace and trace[-1] == frame:
        return trace
    return trace + (frame,)


def _merge_traces(*traces: tuple[TraceFrame, ...]) -> tuple[TraceFrame, ...]:
    """Merge multiple trace sequences while avoiding duplicate adjacent frames."""
    merged: tuple[TraceFrame, ...] = ()
    for trace in traces:
        for frame in trace:
            if merged and merged[-1] == frame:
                continue
            merged += (frame,)
    return merged


def _get_sanitized_cwes(node: ast.Call) -> set[str]:
    """Return the set of CWEs neutralised if this Call is a known sanitizer, else empty set."""
    call_name = _get_call_name(node)
    if not call_name:
        return set()
    # Check exact match first, then suffix match (e.g. "shlex.quote" matches "quote")
    if call_name in SANITIZERS:
        return SANITIZERS[call_name]
    # Check short name (last segment) for builtins only (int, float, bool)
    # Other short names like "escape" are too ambiguous — require qualified form
    _BUILTIN_SANITIZER_SHORTS = {"int", "float", "bool"}
    short = call_name.rsplit(".", 1)[-1]
    if short in SANITIZERS and short in _BUILTIN_SANITIZER_SHORTS:
        return SANITIZERS[short]
    return set()


def _is_tainted_expr(node: ast.expr, tainted: dict[str, Any]) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in tainted:
            return True
    return False


def _get_tainted_parent(node: ast.expr, tainted: dict[str, Any]) -> str | None:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in tainted:
            return child.id
    return None


def _get_sink_name(node: ast.Call) -> str | None:
    """Return the matching sink key from TAINT_SINKS for this Call node, or None."""
    if isinstance(node.func, ast.Name):
        name = node.func.id
        return name if name in TAINT_SINKS else None
    if isinstance(node.func, ast.Attribute):
        parts: list[str] = []
        cur: ast.expr = node.func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        parts.reverse()
        full = ".".join(parts)
        for sink in TAINT_SINKS:
            if full == sink or full.endswith("." + sink):
                return sink
        attr = node.func.attr
        if attr in TAINT_SINKS:
            return attr
    return None


def _unpack_sink_info(info: _SinkInfo) -> tuple[str, str, str | None]:
    if len(info) == 3:
        return info[0], info[1], info[2]
    return info[0], info[1], None


def _severity_from_name(name: str | None, default: Severity) -> Severity:
    if not name:
        return default
    try:
        return Severity(name.lower())
    except ValueError:
        return default


def _find_tainted_arg(
    node: ast.expr, tainted: dict[str, _TaintInfo]
) -> tuple[str, _TaintInfo] | None:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in tainted:
            return (child.id, tainted[child.id])
    return None


def _check_fstring_taint(
    node: ast.expr, tainted: dict[str, _TaintInfo]
) -> tuple[str, str, set[str], tuple[TraceFrame, ...]] | None:
    # f-string: f"SELECT ... {user_id}"
    if isinstance(node, ast.JoinedStr):
        for val in node.values:
            if isinstance(val, ast.FormattedValue):
                if isinstance(val.value, ast.Name) and val.value.id in tainted:
                    src, _, san, trace = tainted[val.value.id]
                    return (val.value.id, src, san, trace)
    # %-formatting: "SELECT ..." % user_id
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            r = _find_tainted_arg(node.right, tainted)
            if r:
                return (r[0], r[1][0], r[1][2], r[1][3])
    # .format(): "...{}".format(user_id)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format":
            for arg in node.args:
                r = _find_tainted_arg(arg, tainted)
                if r:
                    return (r[0], r[1][0], r[1][2], r[1][3])
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Inter-procedural taint map
# ──────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class _FunctionTaintSummary:
    """Per-function summary describing whether taint can flow to the return value."""
    parameters: tuple[str, ...] = ()
    tainted_params: tuple[str, ...] = ()
    source: str = ""
    source_line: int | None = None
    return_line: int | None = None


def _get_local_callee_name(node: ast.Call) -> str:
    """Return the simple function name for a local/user-defined call."""
    call_name = _get_call_name(node)
    if not call_name:
        return ""
    return call_name.rsplit(".", 1)[-1]


def _map_call_arguments(node: ast.Call, parameters: tuple[str, ...]) -> dict[str, ast.expr]:
    """Bind call-site expressions to a callee's parameter names."""
    bindings: dict[str, ast.expr] = {}
    for index, arg in enumerate(node.args):
        if index < len(parameters):
            bindings[parameters[index]] = arg
    for kw in node.keywords:
        if kw.arg:
            bindings[kw.arg] = kw.value
    return bindings


def _expr_param_dependencies(
    node: ast.AST,
    dep_vars: dict[str, set[str]],
    func_summaries: dict[str, _FunctionTaintSummary],
    visited: set[int] | None = None,
) -> set[str]:
    """Return the set of callee parameter names that flow into this expression."""
    if visited is None:
        visited = set()
    node_id = id(node)
    if node_id in visited:
        return set()
    visited = set(visited)
    visited.add(node_id)

    if isinstance(node, ast.Name):
        return set(dep_vars.get(node.id, set()))

    if isinstance(node, ast.Call):
        callee = _get_local_callee_name(node)
        summary = func_summaries.get(callee)
        if summary:
            deps: set[str] = set()
            arg_map = _map_call_arguments(node, summary.parameters)
            for param_name in summary.tainted_params:
                arg_node = arg_map.get(param_name)
                if arg_node is not None:
                    deps |= _expr_param_dependencies(arg_node, dep_vars, func_summaries, visited)
            if deps:
                return deps

    deps: set[str] = set()
    for child in ast.iter_child_nodes(node):
        deps |= _expr_param_dependencies(child, dep_vars, func_summaries, visited)
    return deps


def _expr_has_direct_source(
    node: ast.AST,
    source_vars: dict[str, str],
    func_summaries: dict[str, _FunctionTaintSummary],
    visited: set[int] | None = None,
) -> str | None:
    """Return a taint-source description if an expression resolves to an untrusted source."""
    if isinstance(node, ast.expr):
        src = _get_taint_source(node)
        if src:
            return src

    if visited is None:
        visited = set()
    node_id = id(node)
    if node_id in visited:
        return None
    visited = set(visited)
    visited.add(node_id)

    if isinstance(node, ast.Name) and node.id in source_vars:
        return source_vars[node.id]

    if isinstance(node, ast.Call):
        callee = _get_local_callee_name(node)
        summary = func_summaries.get(callee)
        if summary and summary.source:
            return f"calls {callee}() which returns {summary.source}"

    for child in ast.iter_child_nodes(node):
        child_src = _expr_has_direct_source(child, source_vars, func_summaries, visited)
        if child_src:
            return child_src
    return None


def _build_function_taint_summaries(
    tree: ast.Module,
    func_defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> dict[str, _FunctionTaintSummary]:
    """Summarize whether each function returns tainted data from a source or a parameter."""
    del tree  # the module is already represented via func_defs for this summary pass
    summaries: dict[str, _FunctionTaintSummary] = {
        fname: _FunctionTaintSummary(parameters=tuple(arg.arg for arg in fnode.args.args))
        for fname, fnode in func_defs.items()
    }

    for _ in range(4):
        changed = False
        for fname, fnode in func_defs.items():
            parameters = summaries[fname].parameters
            dep_vars: dict[str, set[str]] = {param: {param} for param in parameters}
            source_vars: dict[str, str] = {}
            tainted_params: set[str] = set()
            source = ""
            source_line: int | None = None
            return_line: int | None = None

            for node in ast.walk(fnode):
                if isinstance(node, ast.Assign):
                    deps = _expr_param_dependencies(node.value, dep_vars, summaries)
                    src = _get_taint_source(node.value) or _expr_has_direct_source(node.value, source_vars, summaries)
                    for target in node.targets:
                        if not isinstance(target, ast.Name):
                            continue
                        dep_vars[target.id] = set(deps)
                        if src:
                            source_vars[target.id] = src
                        else:
                            source_vars.pop(target.id, None)

                if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
                    dep_vars[node.target.id] = dep_vars.get(node.target.id, set()) | _expr_param_dependencies(
                        node.value, dep_vars, summaries
                    )
                    src = _expr_has_direct_source(node.value, source_vars, summaries)
                    if src:
                        source_vars[node.target.id] = src

                if isinstance(node, ast.Return) and node.value is not None:
                    src = _get_taint_source(node.value) or _expr_has_direct_source(node.value, source_vars, summaries)
                    if src and not source:
                        source = src
                        source_line = getattr(node.value, "lineno", node.lineno)
                    if src or _expr_param_dependencies(node.value, dep_vars, summaries):
                        return_line = node.lineno
                    tainted_params |= _expr_param_dependencies(node.value, dep_vars, summaries)

            new_summary = _FunctionTaintSummary(
                parameters=parameters,
                tainted_params=tuple(sorted(tainted_params)),
                source=source,
                source_line=source_line,
                return_line=return_line,
            )
            if new_summary != summaries[fname]:
                summaries[fname] = new_summary
                changed = True
        if not changed:
            break

    return summaries


def _call_taint_from_summary(
    node: ast.Call,
    tainted: dict[str, _TaintInfo],
    func_summaries: dict[str, _FunctionTaintSummary],
    visited: set[int] | None = None,
) -> tuple[str, str, int, set[str], tuple[TraceFrame, ...]] | None:
    """Resolve taint flowing out of a helper call using its function summary."""
    callee = _get_local_callee_name(node)
    summary = func_summaries.get(callee)
    if not summary:
        return None
    if summary.source:
        trace: tuple[TraceFrame, ...] = ()
        if summary.source_line:
            trace = _append_trace(trace, "source", summary.source, line=summary.source_line)
        trace = _append_trace(trace, "helper", f"through `{callee}()`", node)
        return (f"{callee}()", summary.source, getattr(node, "lineno", 0), set(), trace)

    arg_map = _map_call_arguments(node, summary.parameters)
    for param_name in summary.tainted_params:
        arg_node = arg_map.get(param_name)
        if arg_node is None:
            continue
        info = _find_tainted_expr_info(arg_node, tainted, func_summaries, visited)
        if info:
            label, src, line, san, trace = info
            trace = _append_trace(trace, "helper", f"through `{callee}()`", node)
            return (f"{callee}() via `{label}`", src, line, san, trace)
    return None


def _find_tainted_expr_info(
    node: ast.AST,
    tainted: dict[str, _TaintInfo],
    func_summaries: dict[str, _FunctionTaintSummary],
    visited: set[int] | None = None,
) -> tuple[str, str, int, set[str], tuple[TraceFrame, ...]] | None:
    """Return the first tainted origin found inside an expression, including helper calls."""
    if visited is None:
        visited = set()
    node_id = id(node)
    if node_id in visited:
        return None
    visited = set(visited)
    visited.add(node_id)

    if isinstance(node, ast.Name) and node.id in tainted:
        src, line, san, trace = tainted[node.id]
        return (node.id, src, line, san, trace)

    # Collection element taint: x = tainted_list[i] → x is tainted
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
        if node.value.id in tainted:
            src, line, san, trace = tainted[node.value.id]
            return (node.value.id, src, line, san, trace)

    # List/tuple literal: [tainted, clean] → result is tainted
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for elt in node.elts:
            info = _find_tainted_expr_info(elt, tainted, func_summaries, visited)
            if info:
                return info

    if isinstance(node, ast.expr):
        src = _get_taint_source(node)
        if src:
            label = _safe_unparse(node)[:80] or "untrusted input"
            trace = (_make_trace_frame("source", label, node),)
            return (label, src, getattr(node, "lineno", 0), set(), trace)

    if isinstance(node, ast.Call):
        summary_info = _call_taint_from_summary(node, tainted, func_summaries, visited)
        sanitized_cwes = _get_sanitized_cwes(node)
        if summary_info:
            label, src, line, san, trace = summary_info
            if sanitized_cwes:
                trace = _append_trace(
                    trace,
                    "sanitizer",
                    f"sanitize via `{_get_call_name(node) or 'call'}`",
                    node,
                )
            return (label, src, line, san | sanitized_cwes, trace)
        if sanitized_cwes:
            for arg in node.args:
                info = _find_tainted_expr_info(arg, tainted, func_summaries, visited)
                if info:
                    trace = _append_trace(
                        info[4],
                        "sanitizer",
                        f"sanitize via `{_get_call_name(node) or 'call'}`",
                        node,
                    )
                    return (info[0], info[1], info[2], info[3] | sanitized_cwes, trace)
            for kw in node.keywords:
                info = _find_tainted_expr_info(kw.value, tainted, func_summaries, visited)
                if info:
                    trace = _append_trace(
                        info[4],
                        "sanitizer",
                        f"sanitize via `{_get_call_name(node) or 'call'}`",
                        node,
                    )
                    return (info[0], info[1], info[2], info[3] | sanitized_cwes, trace)

    for child in ast.iter_child_nodes(node):
        info = _find_tainted_expr_info(child, tainted, func_summaries, visited)
        if info:
            return info
    return None


# ──────────────────────────────────────────────────────────────────────────────
# CWE impact / fix strings
# ──────────────────────────────────────────────────────────────────────────────

def _cwe_impact(cwe: str) -> str:
    return {
        "CWE-89":  "execute arbitrary SQL, read/modify/delete database records",
        "CWE-78":  "execute arbitrary OS commands on the server",
        "CWE-95":  "execute arbitrary Python code in the application context",
        "CWE-502": "execute arbitrary code via crafted serialized objects",
        "CWE-22":  "read/write arbitrary files on the server",
        "CWE-918": "make the server connect to internal services or arbitrary URLs",
        "CWE-79":  "inject malicious scripts that run in other users' browsers",
        "CWE-601": "redirect users to malicious sites for phishing or credential theft",
    }.get(cwe, "compromise application security")


def _cwe_fix(cwe: str, sink: str) -> str:
    return {
        "CWE-89":  "Use parameterized queries: `cursor.execute('SELECT ... WHERE id = ?', (uid,))`",
        "CWE-78":  "Pass a list to subprocess (no shell=True): `subprocess.run(['cmd', arg])`",
        "CWE-95":  "Avoid eval/exec. Use ast.literal_eval() for data, or a safe expression evaluator.",
        "CWE-502": "Use json.loads() for untrusted data. If pickle is required, verify HMAC first.",
        "CWE-22":  "Sanitize paths: `secure_filename(f)` then `assert resolved.startswith(BASE_DIR)`",
        "CWE-918": "Validate URLs against an allowlist of permitted schemes and hosts.",
        "CWE-79":  "Use auto-escaping templates; never pass user input to render_template_string.",
        "CWE-601": "Validate redirect target against an allowlist of allowed paths/domains.",
    }.get(cwe, f"Sanitize or validate input before passing to {sink}().")


# ──────────────────────────────────────────────────────────────────────────────
# Auto-fix generator
# ──────────────────────────────────────────────────────────────────────────────

def _generate_auto_fix(finding: Finding, lines: list[str]) -> str:
    if finding.line is None or finding.line < 1 or finding.line > len(lines):
        return ""
    raw = lines[finding.line - 1]
    stripped = raw.strip()
    indent = raw[: len(raw) - len(raw.lstrip())]
    t = finding.title.lower()

    if "cwe-89" in t or "sql injection" in t:
        m = re.search(r'f["\'](.+?\{(\w+)\}.*?)["\']', stripped)
        if m:
            var = m.group(2)
            safe_sql = re.sub(r'\{' + var + r'\}', '?', m.group(1))
            return f"BEFORE: {stripped}\nAFTER:  {indent}cursor.execute(\"{safe_sql}\", ({var},))"

    if "cwe-78" in t or "command injection" in t:
        if "shell=True" in stripped:
            return (f"BEFORE: {stripped}\n"
                    f"AFTER:  {indent}{stripped.replace('shell=True', 'shell=False')}"
                    f"  # never shell=True with user input")

    if "cwe-502" in t or "deserialization" in t:
        if "pickle.loads" in stripped:
            return (f"BEFORE: {stripped}\n"
                    f"AFTER:  {indent}{stripped.replace('pickle.loads', 'json.loads')}")
        if "pickle.load(" in stripped:
            return (f"BEFORE: {stripped}\n"
                    f"AFTER:  {indent}{stripped.replace('pickle.load(', 'json.load(')}")

    if "cwe-22" in t or "path traversal" in t:
        m2 = re.search(r'open\((\w+)', stripped)
        if m2:
            var2 = m2.group(1)
            return (f"BEFORE: {stripped}\n"
                    f"AFTER:  {indent}safe_path = Path(BASE_DIR, {var2}).resolve()\n"
                    f"        {indent}assert str(safe_path).startswith(str(BASE_DIR))\n"
                    f"        {indent}with open(safe_path) as f:")

    if "cwe-798" in t or "hardcoded" in t:
        m3 = re.match(r'(\w+)\s*=', stripped)
        if m3:
            var3 = m3.group(1)
            return (f"BEFORE: {stripped}\n"
                    f"AFTER:  {indent}{var3} = os.environ[\"{var3}\"]")

    if "cwe-338" in t or "weak prng" in t:
        return (f"BEFORE: {stripped}\n"
                f"AFTER:  {indent}import secrets\n"
                f"        {indent}token = secrets.token_urlsafe(32)")

    if "cwe-327" in t or ("weak" in t and "hash" in t):
        m4 = re.search(r'hashlib\.\w+\((.+?)\)', stripped)
        if m4:
            return (f"BEFORE: {stripped}\n"
                    f"AFTER:  {indent}import bcrypt\n"
                    f"        {indent}hashed = bcrypt.hashpw({m4.group(1)}, bcrypt.gensalt())")

    if "cwe-918" in t or "ssrf" in t:
        return (f"BEFORE: {stripped}\n"
                f"AFTER:  {indent}from urllib.parse import urlparse\n"
                f"        {indent}parsed = urlparse(url)\n"
                f"        {indent}if parsed.hostname not in ALLOWED_HOSTS:\n"
                f"        {indent}    raise ValueError(\"URL not in allowlist\")\n"
                f"        {indent}{stripped}")

    if "cwe-117" in t or "log injection" in t:
        return (f"BEFORE: {stripped}\n"
                f"AFTER:  {indent}safe_val = str(val).replace('\\n','').replace('\\r','')[:200]\n"
                f"        {indent}logger.info(\"Event: %s\", safe_val)")

    if "silent exception" in t:
        return (f"BEFORE: {stripped}\n"
                f"AFTER:  {indent}logger.exception(\"Unexpected error\")\n"
                f"        {indent}raise")

    if "cwe-1188" in t or "debug=true" in t:
        debug_override = 'os.environ.get("DEBUG","false").lower()=="true"'
        return (f"BEFORE: {stripped}\n"
            f"AFTER:  {indent}{stripped.replace('True', debug_override)}")

    if "cwe-601" in t or "open redirect" in t:
        return (f"BEFORE: {stripped}\n"
                f"AFTER:  {indent}from urllib.parse import urlparse\n"
                f"        {indent}parsed = urlparse(next_url)\n"
                f"        {indent}if parsed.netloc and parsed.netloc != request.host:\n"
                f"        {indent}    abort(400)  # block external redirect\n"
                f"        {indent}{stripped}")

    if "cwe-532" in t or "sensitive data logged" in t:
        return (f"BEFORE: {stripped}\n"
                f"AFTER:  {indent}# Remove sensitive data from log output\n"
                f"        {indent}# logger.info(\"Payment processed for user_id=%s\", user_id)")

    if "cwe-915" in t or "mass assignment" in t:
        return (f"BEFORE: {stripped}\n"
                f"AFTER:  {indent}ALLOWED = {{'name', 'email'}}  # explicit allowlist\n"
                f"        {indent}for key, value in data.items():\n"
                f"        {indent}    if key in ALLOWED:\n"
                f"        {indent}        db_set(table, uid, key, value)")

    return ""


# ──────────────────────────────────────────────────────────────────────────────
# String-stripping helper — prevents regex rules from firing on their own
# pattern definitions (e.g. 'pickle.loads' inside TAINT_SINKS, 'debug=True'
# inside DANGEROUS_DEFAULTS labels, or the auto-fix generator strings).
# ──────────────────────────────────────────────────────────────────────────────

def _code_sans_strings(code: str) -> list[str]:
    """
    Return a copy of *code* split into lines with every string-literal token
    replaced by spaces (preserving column positions).  Used by regex-based
    rules so they never match text that lives inside string constants.
    """
    rows: list[list[str]] = [list(line) for line in code.splitlines()]
    try:
        for tok in _tokenize.generate_tokens(io.StringIO(code).readline):
            if tok.type != _tokenize.STRING:
                continue
            sr, sc = tok.start   # 1-based row, 0-based col
            er, ec = tok.end
            if sr == er:
                for col in range(sc, min(ec, len(rows[sr - 1]))):
                    rows[sr - 1][col] = " "
            else:
                for col in range(sc, len(rows[sr - 1])):
                    rows[sr - 1][col] = " "
                for row in range(sr, er - 1):
                    rows[row] = [" "] * len(rows[row])
                for col in range(0, min(ec, len(rows[er - 1]))):
                    rows[er - 1][col] = " "
    except _tokenize.TokenError:
        pass  # best-effort; fall back to un-blanked lines
    return ["".join(chars) for chars in rows]


# ──────────────────────────────────────────────────────────────────────────────
# Main detection engine — all 28 rule categories
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class _Ctx:
    """Shared context passed to every detection-rule function."""
    lines: list[str]
    sans: list[str]
    func_defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef]
    func_summaries: dict[str, _FunctionTaintSummary]
    _tree: ast.Module = None  # type: ignore[assignment]
    filename: str = ""
    global_graph: object = None


_PY_TAINT_RULE_IDS: dict[str, str] = {
    "CWE-89": "PY-004",
    "CWE-78": "PY-005",
    "CWE-95": "PY-006",
    "CWE-502": "PY-007",
    "CWE-918": "PY-008",
    "CWE-79": "PY-009",
}

_PY_BROKEN_AUTH_RULE_IDS: dict[str, str] = {
    "CWE-287": "PY-014",
    "CWE-345": "PY-015",
    "CWE-384": "PY-016",
}


def _assign_rule_ids(findings: list[Finding], rule_id: str) -> list[Finding]:
    """Stamp a stable rule id onto every finding emitted by a rule."""
    for finding in findings:
        finding.rule_id = rule_id
    return findings

def _rule_01(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    # ── Rule 1: Silent exception swallowing ──────────────────────────────
    for fname, fnode in func_defs.items():
        for child in ast.walk(fnode):
            if not isinstance(child, ast.ExceptHandler):
                continue
            is_broad = child.type is None or (
                isinstance(child.type, ast.Name) and
                child.type.id in ("Exception", "BaseException")
            )
            is_swallowed = all(isinstance(s, (ast.Pass, ast.Continue)) for s in child.body)
            has_raise = any(isinstance(s, ast.Raise) for s in child.body)

            if is_broad and is_swallowed:
                exc = child.type.id if child.type and isinstance(child.type, ast.Name) else "all exceptions"
                findings.append(Finding(
                    category="error-handling", severity=Severity.HIGH,
                    title=f"Silent exception swallowing in {fname}()",
                    description=(
                        f"`{fname}()` catches {exc} with `pass` at L{child.lineno}, hiding disk I/O "
                        f"failures, permission errors, data corruption, and any other exception."
                    ),
                    line=child.lineno,
                    suggestion="Log and re-raise: `logger.exception('Unexpected error'); raise`",
                    rule_id="PY-001",
                    cwe="CWE-617", agent="python-analyzer",
                ))
            elif is_broad and not has_raise:
                findings.append(Finding(
                    category="error-handling", severity=Severity.MEDIUM,
                    title=f"Broad exception catch without re-raise in {fname}()",
                    description=(
                        f"`{fname}()` catches all exceptions at L{child.lineno} without re-raising. "
                        f"Errors may be silently hidden in production."
                    ),
                    line=child.lineno,
                    suggestion="Catch specific exception types, or log and re-raise broad catches.",
                    rule_id="PY-002",
                    cwe="CWE-617", agent="python-analyzer",
                ))

    return findings


def _rule_02(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    # ── Rule 2: Implicit None return (inconsistent returns) ──────────────
    for fname, fnode in func_defs.items():
        rets = [n for n in ast.walk(fnode) if isinstance(n, ast.Return)]
        if len(rets) < 2:
            continue
        valued = [r for r in rets if r.value is not None]
        none_rets = [r for r in rets if r.value is None]
        if valued and none_rets:
            findings.append(Finding(
                category="bug", severity=Severity.MEDIUM,
                title=f"Implicit None return in {fname}() — can fall off end",
                description=(
                    f"`{fname}()` has {len(valued)} branches that return a value and "
                    f"{len(none_rets)} that return None implicitly. Callers that do not check "
                    f"for None will encounter AttributeError or incorrect logic."
                ),
                line=none_rets[0].lineno,
                suggestion="Ensure all code paths return an explicit value, or annotate the return type.",
                agent="python-analyzer",
            ))

    return _assign_rule_ids(findings, "PY-003")


def _rule_03(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    func_summaries = ctx.func_summaries
    # ── Rule 3: Intra-function taint analysis ────────────────────────────
    # tainted_vars maps variable name → (source_description, line, sanitized_cwes)
    # sanitized_cwes tracks which CWEs have been neutralised by passing through
    # a known sanitizer (e.g. shlex.quote neutralises CWE-78).
    for fname, fnode in func_defs.items():
        tainted_vars: dict[str, _TaintInfo] = {}
        route_resource_names = _route_resource_names(fnode)
        for arg in fnode.args.args:
            if arg.arg in ("request", "req", "event", "body", "payload", "data"):
                tainted_vars[arg.arg] = (
                    "function parameter (likely untrusted)",
                    fnode.lineno,
                    set(),
                    (_make_trace_frame("source", f"parameter `{arg.arg}`", line=fnode.lineno),),
                )
            elif arg.arg in route_resource_names:
                tainted_vars[arg.arg] = (
                    "route path parameter",
                    fnode.lineno,
                    set(),
                    (_make_trace_frame("source", f"route parameter `{arg.arg}`", line=fnode.lineno),),
                )

        if ctx.global_graph:
            for node in ast.walk(fnode):
                if isinstance(node, ast.Name) and node.id not in tainted_vars:
                    cross_file_taint = ctx.global_graph.resolve_cross_file_taint(ctx.filename, node.id)
                    if cross_file_taint:
                        taint_source, taint_trace = cross_file_taint
                        tainted_vars[node.id] = (
                            f"imported tainted value: {taint_source}",
                            node.lineno,
                            set(),
                            taint_trace + (_make_trace_frame("import", f"imported `{node.id}`", line=node.lineno),),
                        )

        # ── Pre-pass: collect isinstance type-guards for numeric narrowing ─────
        # Detects:  if isinstance(var, (int, float, bool)):  →  strip injection taint in that branch
        _SAFE_NUMERIC = frozenset({"int", "float", "bool", "complex"})
        isinstance_safe_vars: set[str] = set()
        for if_node in ast.walk(fnode):
            if not isinstance(if_node, ast.If):
                continue
            test = if_node.test
            if not (isinstance(test, ast.Call)
                    and isinstance(test.func, ast.Name)
                    and test.func.id == "isinstance"
                    and len(test.args) == 2):
                continue
            guarded = test.args[0]
            types_arg = test.args[1]
            if not isinstance(guarded, ast.Name):
                continue
            type_names: set[str] = set()
            if isinstance(types_arg, ast.Name):
                type_names.add(types_arg.id)
            elif isinstance(types_arg, ast.Tuple):
                for elt in types_arg.elts:
                    if isinstance(elt, ast.Name):
                        type_names.add(elt.id)
            if type_names and type_names.issubset(_SAFE_NUMERIC):
                isinstance_safe_vars.add(guarded.id)

        # ── Pre-pass: collect lambda variable assignments ──────────────────────
        # Detects:  handler = lambda x: sink(x)  →  handler(tainted) propagates
        lambda_vars: dict[str, ast.Lambda] = {}
        for lnode in ast.walk(fnode):
            if not isinstance(lnode, ast.Assign):
                continue
            if not isinstance(lnode.value, ast.Lambda):
                continue
            for ltarget in lnode.targets:
                if isinstance(ltarget, ast.Name):
                    lambda_vars[ltarget.id] = lnode.value

        for node in ast.walk(fnode):
            # Track taint propagation through assignments
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if not isinstance(target, ast.Name):
                        continue
                    src = _get_taint_source(node.value)
                    if src:
                        source_label = _safe_unparse(node.value)[:80] or src
                        tainted_vars[target.id] = (
                            src,
                            node.lineno,
                            set(),
                            (
                                _make_trace_frame("source", source_label, node.value, line=node.lineno),
                                _make_trace_frame("propagator", f"assign to `{target.id}`", line=node.lineno),
                            ),
                        )
                        continue

                    # Lambda-call propagation: result = transform(tainted) where transform is a lambda
                    if (isinstance(node.value, ast.Call)
                            and isinstance(node.value.func, ast.Name)
                            and node.value.func.id in lambda_vars):
                        lam = lambda_vars[node.value.func.id]
                        # Build a tainted-vars snapshot scoped to the lambda's parameters
                        lam_tainted = dict(tainted_vars)
                        for lam_idx, lam_arg in enumerate(lam.args.args):
                            if lam_idx < len(node.value.args):
                                lam_call_arg = node.value.args[lam_idx]
                                lam_info = _find_tainted_expr_info(lam_call_arg, tainted_vars, func_summaries)
                                if lam_info:
                                    _, lsrc, lline, lsan, ltrace = lam_info
                                    lam_tainted[lam_arg.arg] = (lsrc, lline, lsan, ltrace)
                        lam_result = _find_tainted_expr_info(lam.body, lam_tainted, func_summaries)
                        if lam_result:
                            lbl, lsrc2, lline2, lsan2, ltrace2 = lam_result
                            tainted_vars[target.id] = (
                                f"lambda result from `{lbl}` ({lsrc2})",
                                lline2,
                                lsan2,
                                _append_trace(ltrace2, "propagator", f"lambda assign to `{target.id}`", line=node.lineno),
                            )
                        continue

                    taint_info = _find_tainted_expr_info(node.value, tainted_vars, func_summaries)
                    if not taint_info:
                        continue
                    label, source_desc, source_line, inherited_san, inherited_trace = taint_info
                    if isinstance(node.value, ast.Call):
                        sanitized_cwes = _get_sanitized_cwes(node.value)
                        merged = inherited_san | sanitized_cwes
                        callee = _get_local_callee_name(node.value)
                        trace = _append_trace(inherited_trace, "propagator", f"assign to `{target.id}`", line=node.lineno)
                        if sanitized_cwes:
                            tainted_vars[target.id] = (
                                f"sanitized({','.join(sorted(sanitized_cwes))}) from `{label}` ({source_desc})",
                                source_line,
                                merged,
                                trace,
                            )
                        elif callee and callee in func_summaries:
                            tainted_vars[target.id] = (
                                f"return value of {callee}() ({source_desc})",
                                node.lineno,
                                merged,
                                trace,
                            )
                        else:
                            tainted_vars[target.id] = (
                                f"derived from `{label}` ({source_desc})",
                                source_line,
                                merged,
                                trace,
                            )
                    else:
                        tainted_vars[target.id] = (
                            f"derived from `{label}` ({source_desc})",
                            source_line,
                            inherited_san,
                            _append_trace(inherited_trace, "propagator", f"assign to `{target.id}`", line=node.lineno),
                        )

            if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
                taint_info = _find_tainted_expr_info(node.value, tainted_vars, func_summaries)
                if taint_info:
                    label, source_desc, source_line, inherited_san, inherited_trace = taint_info
                    tainted_vars[node.target.id] = (
                        f"combined with `{label}` ({source_desc})",
                        source_line,
                        inherited_san,
                        _append_trace(inherited_trace, "propagator", f"combine into `{node.target.id}`", line=node.lineno),
                    )

            # Detect taint reaching a sink
            if isinstance(node, ast.Call):
                # Check if the call itself is a sanitizer wrapping tainted args
                # e.g. cursor.execute("...", (int(user_id),)) — int() sanitises CWE-89
                inline_sanitized: set[str] = set()
                for arg_node in node.args:
                    if isinstance(arg_node, ast.Call):
                        inline_sanitized |= _get_sanitized_cwes(arg_node)

                sink = _get_sink_name(node)
                if sink and sink in TAINT_SINKS:
                    cwe, vuln_type, configured_severity = _unpack_sink_info(TAINT_SINKS[sink])
                    default_severity = Severity.CRITICAL if "Injection" in vuln_type else Severity.HIGH
                    sev = _severity_from_name(configured_severity, default_severity)

                    # Deterministic Algorithmic Triage: Parameterised SQL is safe 
                    # If tainted argument is not the 1st positional arg or the string query kwarg, it's parameterised.
                    safe_params: set[ast.AST] = set()
                    if cwe == "CWE-89":
                        for idx, a in enumerate(node.args):
                            if idx > 0:
                                safe_params.add(a)
                        for kw in node.keywords:
                            if kw.arg not in ("sql", "query", "stmt", None):
                                safe_params.add(kw.value)

                    all_args = node.args + [kw.value for kw in node.keywords]
                    for arg_node in all_args:
                        hit = _find_tainted_expr_info(arg_node, tainted_vars, func_summaries)
                        if not hit:
                            continue
                        if arg_node in safe_params:
                            continue
                        
                        vname, vsrc, vline, san_cwes, trace = hit
                        # Skip if this CWE has been neutralised by a sanitizer
                        if cwe in san_cwes or cwe in inline_sanitized:
                            continue
                        # isinstance type-guard: numeric-narrowed variables are safe for injection CWEs
                        if vname in isinstance_safe_vars and cwe in {"CWE-89", "CWE-78", "CWE-95"}:
                            continue
                        finding_trace = _append_trace(trace, "sink", f"sink `{sink}()`", node)
                        findings.append(Finding(
                            category="security", severity=sev,
                            title=f"{cwe}: {vuln_type} in {fname}()",
                            description=(
                                f"Untrusted data flows from `{vname}` ({vsrc}, L{vline}) "
                                f"to `{sink}()` at L{node.lineno} without sanitization. "
                                f"An attacker can exploit this to {_cwe_impact(cwe)}."
                            ),
                            line=node.lineno,
                            suggestion=_cwe_fix(cwe, sink),
                            rule_id=_PY_TAINT_RULE_IDS.get(cwe, "PY-004"),
                            cwe=cwe, agent="python-analyzer",
                            trace=finding_trace,
                        ))
                        break

    return findings


def _rule_04(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    lines = ctx.lines
    # ── Rule 4: Hardcoded secrets ────────────────────────────────────────
    # Placeholder patterns that look like secrets but are not real credentials
    _PLACEHOLDER_RE = re.compile(
        r'your[_-]|<your[-_\w]|changeme|replace.?this|placeholder|xxx+|'  # common tokens
        r'insert.?here|foobar|dummy-|fake[_-]|test[_-]key|'               # test markers
        r'-here["\']|here["\']|default[_-]key|example[_-]key|example[_-]secret',
        re.IGNORECASE,
    )
    for lineno, line_text in enumerate(lines, 1):
        if line_text.strip().startswith("#"):
            continue
        if _PLACEHOLDER_RE.search(line_text):
            continue  # skip obvious placeholder values
        if re.search(r'os\.environ|os\.getenv|getenv|environ\[', line_text, re.IGNORECASE):
            continue  # skip env-var lookups
        for pattern, secret_type in SECRET_PATTERNS:
            if re.search(pattern, line_text, re.IGNORECASE):
                findings.append(Finding(
                    category="security", severity=Severity.CRITICAL,
                    title=f"CWE-798: Hardcoded {secret_type} at line {lineno}",
                    description=(
                        f"A {secret_type} is hardcoded in source code at L{lineno}. "
                        f"This is visible in version control. Rotate this credential immediately."
                    ),
                    line=lineno,
                    suggestion="Use environment variables or a secrets manager (Vault, AWS Secrets Manager, .env excluded from git).",
                    cwe="CWE-798", agent="python-analyzer",
                ))
                break

    return _assign_rule_ids(findings, "PY-010")


def _rule_05(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    sans = ctx.sans
    # ── Rule 5: Dangerous defaults ───────────────────────────────────────
    for lineno, line_text in enumerate(sans, 1):  # use string-blanked lines
        if line_text.strip().startswith("#"):
            continue
        for pattern, label, desc in DANGEROUS_DEFAULTS:
            if re.search(pattern, line_text, re.IGNORECASE):
                findings.append(Finding(
                    category="security", severity=Severity.HIGH,
                    title=f"CWE-1188: Dangerous default `{label}` at line {lineno}",
                    description=f"{desc} Found at L{lineno}.",
                    line=lineno,
                    suggestion=f"Remove or gate `{label}` behind an environment variable check.",
                    cwe="CWE-1188", agent="python-analyzer",
                ))
                break

    return _assign_rule_ids(findings, "PY-011")


def _rule_06(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    sans = ctx.sans
    # ── Rule 6: Unsafe deserialization ───────────────────────────────────
    for lineno, line_text in enumerate(sans, 1):  # use string-blanked lines
        if line_text.strip().startswith("#"):
            continue
        for pattern, desc in [
            (r'pickle\.loads?\(', "pickle deserialization"),
            (r'marshal\.loads?\(', "marshal deserialization"),
            (r'yaml\.load\((?!.*Loader\s*=\s*yaml\.SafeLoader)', "yaml.load without SafeLoader"),
        ]:
            if re.search(pattern, line_text):
                findings.append(Finding(
                    category="security", severity=Severity.CRITICAL,
                    title=f"CWE-502: Unsafe deserialization at line {lineno}",
                    description=(
                        f"Unsafe {desc} at L{lineno}: `{line_text.strip()[:80]}`. "
                        f"If the data comes from an untrusted source, an attacker can achieve RCE."
                    ),
                    line=lineno,
                    suggestion="Use JSON. If pickle is required, verify data integrity with HMAC before loading.",
                    cwe="CWE-502", agent="python-analyzer",
                ))
                break

    return _assign_rule_ids(findings, "PY-012")


def _rule_07(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    lines = ctx.lines
    sans = ctx.sans
    # ── Rule 7: Weak cryptographic hashing for passwords ─────────────────
    for lineno, line_text in enumerate(sans, 1):  # string-blanked
        if line_text.strip().startswith("#"):
            continue
        m = re.search(r'hashlib\.(md5|sha1|sha224)\(', line_text)
        if m:
            ctx_start = max(0, lineno - 5)
            context = "\n".join(lines[ctx_start:lineno])
            if re.search(r'password|passwd|pwd|credential|secret', context, re.IGNORECASE):
                algo = m.group(1).upper()
                findings.append(Finding(
                    category="security", severity=Severity.HIGH,
                    title=f"CWE-327: Weak password hashing ({algo}) at line {lineno}",
                    description=(
                        f"`{algo}` is cryptographically broken for password storage at L{lineno}. "
                        f"No salt is used; rainbow tables and GPU brute-force make this trivial to crack."
                    ),
                    line=lineno,
                    suggestion="Use bcrypt, argon2, or scrypt: `bcrypt.hashpw(password.encode(), bcrypt.gensalt())`",
                    cwe="CWE-327", agent="python-analyzer",
                ))

    return _assign_rule_ids(findings, "PY-013")


def _rule_08(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    sans = ctx.sans
    # ── Rule 8: Broken authentication patterns ────────────────────────────
    for lineno, line_text in enumerate(sans, 1):  # string-blanked
        if line_text.strip().startswith("#"):
            continue
        for pattern, title, desc, cwe in BROKEN_AUTH_PATTERNS:
            if re.search(pattern, line_text, re.IGNORECASE):
                findings.append(Finding(
                    category="security", severity=Severity.HIGH,
                    title=f"{cwe}: {title} at line {lineno}",
                    description=f"{desc} Found at L{lineno}: `{line_text.strip()[:80]}`.",
                    line=lineno,
                    suggestion="Validate the credential value cryptographically, not just its presence.",
                    rule_id=_PY_BROKEN_AUTH_RULE_IDS.get(cwe, "PY-014"),
                    cwe=cwe, agent="python-analyzer",
                ))
                break

    return findings


def _rule_09(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    func_summaries = ctx.func_summaries
    # ── Rule 9: Log injection ────────────────────────────────────────────
    _log_method_names = {"info","warning","error","debug","critical","warn","exception"}
    _log_obj_names = {"logger","log","logging"}
    for fname, fnode in func_defs.items():
        tainted_log: set[str] = set()
        for arg in fnode.args.args:
            if arg.arg in ("request","req","event","body","payload","data"):
                tainted_log.add(arg.arg)
        for node in ast.walk(fnode):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if _find_tainted_expr_info(
                            node.value,
                            {v: ("", 0, set(), ()) for v in tainted_log},
                            func_summaries,
                        ):
                            tainted_log.add(target.id)
            if isinstance(node, ast.Call):
                is_log = False
                if isinstance(node.func, ast.Attribute) and node.func.attr in _log_method_names:
                    obj = node.func.value
                    if isinstance(obj, ast.Name) and obj.id.lower() in _log_obj_names:
                        is_log = True
                    elif isinstance(obj, ast.Attribute) and obj.attr.lower() in _log_obj_names:
                        is_log = True
                if isinstance(node.func, ast.Name) and node.func.id == "print":
                    is_log = True
                if is_log:
                    for arg_node in node.args:
                        for child in ast.walk(arg_node):
                            if isinstance(child, ast.Name) and child.id in tainted_log:
                                findings.append(Finding(
                                    category="security", severity=Severity.MEDIUM,
                                    title=f"CWE-117: Log injection in {fname}() at line {node.lineno}",
                                    description=(
                                        f"Untrusted `{child.id}` is written to a log without sanitization "
                                        f"in `{fname}()` at L{node.lineno}. An attacker can inject fake log "
                                        f"entries or forge audit trails via CRLF injection."
                                    ),
                                    line=node.lineno,
                                    suggestion="Strip newlines before logging: `str(val).replace('\\n','').replace('\\r','')[:200]`",
                                    cwe="CWE-117", agent="python-analyzer",
                                ))
                                break
                        else:
                            continue
                        break

    return _assign_rule_ids(findings, "PY-017")


def _rule_10(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    lines = ctx.lines
    # ── Rule 10: Weak PRNG for security tokens ───────────────────────────
    for lineno, line_text in enumerate(lines, 1):
        if line_text.strip().startswith("#"):
            continue
        if re.search(r'random\.(choice|randint|random|sample|randrange)\(', line_text):
            ctx_start = max(0, lineno - 3)
            ctx_end = min(len(lines), lineno + 2)
            ctx_window = "\n".join(lines[ctx_start:ctx_end])
            if re.search(r'token|secret|key|password|nonce|session|auth|csrf|salt', ctx_window, re.IGNORECASE):
                findings.append(Finding(
                    category="security", severity=Severity.MEDIUM,
                    title=f"CWE-338: Weak PRNG for security token at line {lineno}",
                    description=(
                        f"The `random` module (Mersenne Twister) is NOT cryptographically secure. "
                        f"An attacker can predict future tokens by observing ~624 outputs. L{lineno}: "
                        f"`{line_text.strip()[:80]}`."
                    ),
                    line=lineno,
                    suggestion="Use `secrets.token_urlsafe(32)` or `os.urandom(32)` for security-sensitive values.",
                    cwe="CWE-338", agent="python-analyzer",
                ))

    return _assign_rule_ids(findings, "PY-018")


def _rule_11(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    # ── Rule 11: Weak token generation with fast hash ────────────────────
    _token_fn_pat = re.compile(
        r'token|reset|nonce|otp|csrf|verification|confirm|activation|invite|magic.?link',
        re.IGNORECASE,
    )
    for fname, fnode in func_defs.items():
        if not _token_fn_pat.search(fname):
            continue
        for node in ast.walk(fnode):
            if not isinstance(node, ast.Call):
                continue
            if not (isinstance(node.func, ast.Attribute) and
                    node.func.attr in ("md5","sha1","sha224") and
                    isinstance(node.func.value, ast.Name) and
                    node.func.value.id == "hashlib"):
                continue
            algo = node.func.attr.upper()
            findings.append(Finding(
                category="security", severity=Severity.HIGH,
                title=f"CWE-338: Weak token generation in {fname}() — {algo} is predictable",
                description=(
                    f"`{fname}()` uses `hashlib.{algo.lower()}()` to generate a security token at "
                    f"L{node.lineno}. {algo} is a fast GP hash, not a CSPRNG. If input is time-based, "
                    f"an attacker can enumerate the input space and forge the token."
                ),
                line=node.lineno,
                suggestion="Replace with `secrets.token_urlsafe(32)` — 256 bits from the OS CSPRNG.",
                cwe="CWE-338", agent="python-analyzer",
            ))
            break

    return _assign_rule_ids(findings, "PY-019")


# ──────────────────────────────────────────────────────────────────────────────
# Helpers for CWE-862 heuristic
# ──────────────────────────────────────────────────────────────────────────────

_MUTATION_CALLS: frozenset[str] = frozenset({
    # ORM / DB mutation
    "commit", "add", "save", "delete", "update", "insert", "execute",
    "bulk_create", "bulk_update", "create",
    # File / IO
    "write", "send", "send_message", "publish",
    # Session/auth
    "set_cookie", "delete_cookie",
})

_MUTATION_ATTR_PAT: re.Pattern[str] = re.compile(
    r'session\[|redirect\(|abort\(|flash\(', re.IGNORECASE,
)


def _body_has_mutation(fnode: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if the function body contains state-mutating calls."""
    for node in ast.walk(fnode):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in _MUTATION_CALLS:
                    return True
            if isinstance(node.func, ast.Name):
                if node.func.id in _MUTATION_CALLS:
                    return True
    return False


def _safe_unparse(node: ast.AST | None) -> str:
    """Best-effort AST → source reconstruction for heuristic matching."""
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _call_chain_names(node: ast.AST) -> list[str]:
    """Return the dotted call/attribute chain segments for an expression."""
    names: list[str] = []
    cur: ast.AST = node
    while True:
        if isinstance(cur, ast.Call):
            func = cur.func
            if isinstance(func, ast.Attribute):
                names.append(func.attr)
                cur = func.value
                continue
            if isinstance(func, ast.Name):
                names.append(func.id)
            break
        if isinstance(cur, ast.Attribute):
            names.append(cur.attr)
            cur = cur.value
            continue
        if isinstance(cur, ast.Name):
            names.append(cur.id)
        break
    names.reverse()
    return names


def _route_resource_names(fnode: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Return ID-like route parameter names (e.g. doc_id, id, slug)."""
    names: set[str] = {
        arg.arg for arg in fnode.args.args if _ID_LIKE_NAME_RE.search(arg.arg)
    }
    for deco in fnode.decorator_list:
        if not (isinstance(deco, ast.Call) and isinstance(deco.func, ast.Attribute)):
            continue
        if deco.func.attr not in _FLASK_ROUTE_ATTRS:
            continue
        for darg in deco.args:
            if not (isinstance(darg, ast.Constant) and isinstance(darg.value, str)):
                continue
            for match in re.findall(r'<\s*(?:int|string|uuid)?\s*:?\s*(\w+)\s*>', darg.value):
                if _ID_LIKE_NAME_RE.search(match):
                    names.add(match)
    return names


def _decorator_name(node: ast.AST) -> str | None:
    """Return the terminal decorator name for a decorator expression."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return None


def _iter_route_decorators(
    fnode: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[ast.Call, ...]:
    """Return all route decorator calls attached to a function."""
    return tuple(
        deco
        for deco in fnode.decorator_list
        if isinstance(deco, ast.Call)
        and isinstance(deco.func, ast.Attribute)
        and deco.func.attr in _FLASK_ROUTE_ATTRS
    )


def _route_decorator_label(deco: ast.Call) -> str:
    """Return a compact trace label for a route decorator."""
    path = ""
    methods: set[str] = set()
    if isinstance(deco.func, ast.Attribute) and deco.func.attr != "route":
        methods.add(deco.func.attr.upper())
    for darg in deco.args:
        if isinstance(darg, ast.Constant) and isinstance(darg.value, str) and not path:
            path = darg.value
    for kw in deco.keywords:
        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
            for elt in kw.value.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    methods.add(elt.value.upper())
    label = f"route `{path}`" if path else f"route decorator `@{_safe_unparse(deco.func) or 'route'}`"
    if methods:
        label += f" methods {', '.join(sorted(methods))}"
    return label


def _route_paths(fnode: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    """Return all literal route paths attached to a function."""
    paths: list[str] = []
    for deco in _iter_route_decorators(fnode):
        for darg in deco.args:
            if isinstance(darg, ast.Constant) and isinstance(darg.value, str) and darg.value not in paths:
                paths.append(darg.value)
                break
    return tuple(paths)


def _decorator_names(fnode: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Return the terminal names of all decorators applied to a function."""
    return {
        name
        for deco in fnode.decorator_list
        if (name := _decorator_name(deco))
    }


def _is_admin_endpoint(fnode: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True when a route/function looks administrative or privileged."""
    if _PRIVILEGED_ENDPOINT_PAT.search(fnode.name):
        return True
    return any(_PRIVILEGED_ENDPOINT_PAT.search(path) for path in _route_paths(fnode))


def _route_trace_frames(fnode: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[TraceFrame, ...]:
    """Return route-oriented trace frames for a route handler."""
    trace: tuple[TraceFrame, ...] = ()
    for deco in _iter_route_decorators(fnode):
        trace = _append_trace(trace, "source", _route_decorator_label(deco), deco)
    return trace


def _decorator_trace_frames(
    fnode: ast.FunctionDef | ast.AsyncFunctionDef,
    decorator_names: set[str] | frozenset[str] | None = None,
    *,
    kind: str = "check",
    label_prefix: str = "decorator",
) -> tuple[TraceFrame, ...]:
    """Return trace frames for matching decorators on a function."""
    names = decorator_names if decorator_names is not None else _AUTH_DECORATORS
    trace: tuple[TraceFrame, ...] = ()
    for deco in fnode.decorator_list:
        name = _decorator_name(deco)
        if name and name in names:
            trace = _append_trace(trace, kind, f"{label_prefix} `@{name}`", deco)
    return trace


def _resource_parameter_trace_frames(
    resource_names: set[str],
    *,
    line: int | None = None,
) -> tuple[TraceFrame, ...]:
    """Return trace frames for resource-identifying parameters."""
    trace: tuple[TraceFrame, ...] = ()
    for name in sorted(resource_names):
        trace = _append_trace(trace, "source", f"resource parameter `{name}`", line=line)
    return trace


def _presence_only_checked_names(test: ast.AST) -> set[str]:
    """Return names used in truthiness/presence-only checks such as `if token:`."""
    if isinstance(test, ast.Name):
        return {test.id}
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return _presence_only_checked_names(test.operand)
    if isinstance(test, ast.BoolOp):
        names: set[str] = set()
        for value in test.values:
            names |= _presence_only_checked_names(value)
        return names
    if (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and len(test.ops) == 1
        and len(test.comparators) == 1
        and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value is None
        and isinstance(test.ops[0], (ast.IsNot, ast.NotEq))
    ):
        return {test.left.id}
    return set()


def _node_references_names(node: ast.AST, names: set[str]) -> bool:
    if not names:
        return False
    return any(
        isinstance(child, ast.Name) and child.id in names
        for child in ast.walk(node)
    )


def _principal_aliases(fnode: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Track local aliases that point at the current principal/user context."""
    aliases: set[str] = {
        arg.arg for arg in fnode.args.args if _PRINCIPAL_ALIAS_NAME_RE.search(arg.arg)
    }
    for node in ast.walk(fnode):
        if not isinstance(node, ast.Assign):
            continue
        value_text = _safe_unparse(node.value)
        if isinstance(node.value, (ast.Name, ast.Attribute, ast.Subscript)):
            if not _PRINCIPAL_REF_RE.search(value_text):
                continue
        elif isinstance(node.value, ast.Call):
            if not re.search(r'current_user|principal|identity|actor', _safe_unparse(node.value.func), re.IGNORECASE):
                continue
        else:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                aliases.add(target.id)
    return aliases


def _expr_has_principal_ref(node: ast.AST, principal_aliases: set[str]) -> bool:
    if _PRINCIPAL_REF_RE.search(_safe_unparse(node)):
        return True
    return any(
        isinstance(child, ast.Name) and child.id in principal_aliases
        for child in ast.walk(node)
    )


def _expr_has_ownership_ref(node: ast.AST) -> bool:
    return bool(_OWNERSHIP_RE.search(_safe_unparse(node)))


def _call_has_ownership_constraint(
    node: ast.Call,
    principal_aliases: set[str],
) -> bool:
    """Return True when a call scopes access by owner/user/tenant identity."""
    for child in ast.walk(node):
        if isinstance(child, ast.keyword) and child.arg and _OWNERSHIP_RE.search(child.arg):
            if _expr_has_principal_ref(child.value, principal_aliases):
                return True
        if isinstance(child, ast.Compare):
            if _expr_has_ownership_ref(child) and _expr_has_principal_ref(child, principal_aliases):
                return True
    text = _safe_unparse(node)
    return bool(_OWNERSHIP_RE.search(text) and _expr_has_principal_ref(node, principal_aliases))


def _body_has_explicit_ownership_guard(
    fnode: ast.FunctionDef | ast.AsyncFunctionDef,
    principal_aliases: set[str],
) -> bool:
    """Return True when the function explicitly verifies ownership or calls an authz helper."""
    for node in ast.walk(fnode):
        if isinstance(node, (ast.If, ast.Assert)):
            test = node.test
            if _expr_has_ownership_ref(test) and _expr_has_principal_ref(test, principal_aliases):
                return True
        if isinstance(node, ast.Call):
            if _call_has_ownership_constraint(node, principal_aliases):
                return True
            if _OWNERSHIP_HELPER_RE.search(_safe_unparse(node.func)):
                return True
    return False


def _expr_has_privilege_signal(node: ast.AST, principal_aliases: set[str]) -> bool:
    """Return True when an expression appears to reason about roles/permissions."""
    text = _safe_unparse(node)
    if not _PRIVILEGE_CHECK_PAT.search(text):
        return False
    if _expr_has_principal_ref(node, principal_aliases):
        return True
    return any(
        (isinstance(child, ast.Name) and _PRIVILEGE_CHECK_PAT.search(child.id)) or
        (isinstance(child, ast.Constant) and isinstance(child.value, str) and _PRIVILEGE_VALUE_PAT.search(child.value))
        for child in ast.walk(node)
    )


def _call_has_privilege_constraint(
    node: ast.Call,
    principal_aliases: set[str],
) -> bool:
    """Return True when a helper/decorator-style call enforces privileged access."""
    fn_text = _safe_unparse(node.func)
    if not _PRIVILEGE_CHECK_PAT.search(fn_text):
        return False
    if _expr_has_principal_ref(node, principal_aliases):
        return True
    return any(
        isinstance(child, ast.Constant) and isinstance(child.value, str) and _PRIVILEGE_VALUE_PAT.search(child.value)
        for child in ast.walk(node)
    )


def _statements_deny_access(statements: list[ast.stmt]) -> bool:
    """Return True when a block appears to deny access (abort/raise/403/unauthorized)."""
    for stmt in statements:
        for child in ast.walk(stmt):
            if isinstance(child, ast.Raise):
                return True
            if isinstance(child, ast.Call):
                fn_name = _safe_unparse(child.func)
                if re.search(r'\babort\b|forbid|deny|permission', fn_name, re.IGNORECASE):
                    return True
                if any(
                    isinstance(arg, ast.Constant) and arg.value in {401, 403}
                    for arg in child.args
                ):
                    return True
            if isinstance(child, ast.Return):
                text = _safe_unparse(child.value)
                if re.search(r'403|401|forbid|unauthori[sz]ed|permission', text, re.IGNORECASE):
                    return True
    return False


def _body_has_privilege_guard(
    fnode: ast.FunctionDef | ast.AsyncFunctionDef,
    principal_aliases: set[str],
) -> bool:
    """Return True when a route explicitly enforces admin/role/permission checks."""
    for node in ast.walk(fnode):
        if isinstance(node, ast.Assert) and _expr_has_privilege_signal(node.test, principal_aliases):
            return True
        if isinstance(node, ast.If) and _expr_has_privilege_signal(node.test, principal_aliases):
            test_text = _safe_unparse(node.test)
            has_negative_guard = bool(re.search(r'\bnot\b|!=|is not|not in', test_text))
            if has_negative_guard and _statements_deny_access(node.body):
                return True
            if not has_negative_guard and _statements_deny_access(node.orelse):
                return True
        if isinstance(node, ast.Call) and _call_has_privilege_constraint(node, principal_aliases):
            return True
    return False


def _call_looks_like_orm_lookup(
    node: ast.Call,
    resource_names: set[str],
    principal_aliases: set[str],
) -> bool:
    """Detect common ORM fetch patterns like query.get(id) or filter_by(id=...).first()."""
    if not resource_names:
        return False
    chain = _call_chain_names(node)
    if not chain or not any(name in _ORM_SCOPE_NAMES for name in chain):
        return False
    terminal = chain[-1]
    if terminal not in _ORM_LOOKUP_TERMINALS:
        return False
    if not _node_references_names(node, resource_names):
        return False

    id_args: list[ast.AST] = []
    if terminal == "get" and "session" in chain:
        id_args.extend(node.args[1:2])
    else:
        id_args.extend(node.args[:1])
    id_args.extend(
        kw.value
        for kw in node.keywords
        if kw.arg and _ID_LIKE_NAME_RE.search(kw.arg)
    )

    if terminal.startswith("get"):
        if not any(_node_references_names(arg, resource_names) for arg in id_args):
            return False
        return not _call_has_ownership_constraint(node, principal_aliases)

    has_id_filter = False
    for child in ast.walk(node):
        if isinstance(child, ast.keyword) and child.arg and _ID_LIKE_NAME_RE.search(child.arg):
            if _node_references_names(child.value, resource_names):
                has_id_filter = True
                break
        if isinstance(child, ast.Compare) and _node_references_names(child, resource_names):
            text = _safe_unparse(child)
            if re.search(r'\bid\b|\bpk\b|\bslug\b|_id\b|_pk\b|_slug\b', text, re.IGNORECASE):
                has_id_filter = True
                break

    return has_id_filter and not _call_has_ownership_constraint(node, principal_aliases)


def _call_looks_like_direct_orm_mutation(
    node: ast.Call,
    resource_names: set[str],
    principal_aliases: set[str],
) -> bool:
    """Detect direct ORM mutations like filter_by(id=...).delete()."""
    chain = _call_chain_names(node)
    if not chain or chain[-1] not in {"delete", "update"}:
        return False
    if not any(name in _ORM_SCOPE_NAMES for name in chain):
        return False
    if not _node_references_names(node, resource_names):
        return False
    return not _call_has_ownership_constraint(node, principal_aliases)


def _rule_12(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    lines = ctx.lines
    func_defs = ctx.func_defs
    # ── Rule 12: Missing auth on Flask/FastAPI routes (CWE-862) ──────────
    # We only flag routes that are genuinely risky:
    #   CRITICAL — /admin paths without auth
    #   HIGH     — state-mutating routes (POST/PUT/DELETE) or routes with
    #              resource IDs (e.g. /users/<int:id>) without auth
    #   Skip     — GET-only routes matching public patterns, or pure
    #              read-only routes with no resource-ID in the path

    for fname, fnode in func_defs.items():
        has_route = is_admin = is_public = has_auth = False
        has_resource_id = False
        resource_names = _route_resource_names(fnode)
        route_methods: set[str] = set()
        route_path = ""
        for deco in fnode.decorator_list:
            if isinstance(deco, ast.Call) and isinstance(deco.func, ast.Attribute):
                attr = deco.func.attr
                if attr in _FLASK_ROUTE_ATTRS:
                    has_route = True
                    # Track explicit HTTP method from decorator name
                    if attr != "route":
                        route_methods.add(attr.lower())
                    for darg in deco.args:
                        if isinstance(darg, ast.Constant) and isinstance(darg.value, str):
                            route_path = darg.value
                            if _ADMIN_PATH_PAT.search(darg.value):
                                is_admin = True
                            if _PUBLIC_ROUTE_PAT.search(darg.value):
                                is_public = True
                            if _RESOURCE_ID_PAT.search(darg.value):
                                has_resource_id = True
                    # Check methods=['POST', ...] keyword argument
                    for kw in deco.keywords:
                        if kw.arg == "methods" and isinstance(kw.value, ast.List):
                            for elt in kw.value.elts:
                                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                    route_methods.add(elt.value.lower())
            dname = None
            if isinstance(deco, ast.Name):
                dname = deco.id
            elif isinstance(deco, ast.Attribute):
                dname = deco.attr
            elif isinstance(deco, ast.Call):
                if isinstance(deco.func, ast.Name):
                    dname = deco.func.id
                elif isinstance(deco.func, ast.Attribute):
                    dname = deco.func.attr
            if dname and dname in _AUTH_DECORATORS:
                has_auth = True

        if not has_route or has_auth or is_public:
            continue

        # Check for inline suppression on the function def or decorator lines
        check_start = max(0, fnode.lineno - len(fnode.decorator_list) - 1)
        check_end = min(len(lines), fnode.lineno + 1)
        for li in range(check_start, check_end):
            m = _SUPPRESSION_RE.search(lines[li])
            if m:
                suppressed_cwes = m.group(1)
                if not suppressed_cwes or "CWE-862" in suppressed_cwes:
                    has_auth = True  # treat as suppressed
                    break
        if has_auth:
            continue

        # Determine if the route does state-mutating work
        is_mutating_method = bool(route_methods & _MUTATING_METHODS)
        has_body_mutation = _body_has_mutation(fnode)

        if is_admin:
            sev = Severity.CRITICAL
            label = "admin route with no authentication"
        elif is_mutating_method or has_body_mutation:
            sev = Severity.HIGH
            label = "state-mutating route with no authentication"
        elif has_resource_id:
            sev = Severity.HIGH
            label = "resource-access route with no authentication"
        else:
            # Pure GET on a generic path — skip unless it looks sensitive
            continue

        trace = _merge_traces(
            _route_trace_frames(fnode),
            _resource_parameter_trace_frames(resource_names, line=fnode.lineno),
        )
        trace = _append_trace(trace, "gap", "no auth decorator detected", line=fnode.lineno)
        if is_admin:
            trace = _append_trace(trace, "sink", "admin route reachable without auth", line=fnode.lineno)
        elif is_mutating_method:
            method_list = ", ".join(sorted(method.upper() for method in route_methods & _MUTATING_METHODS))
            trace = _append_trace(
                trace,
                "sink",
                f"mutating route methods `{method_list}` reachable without auth",
                line=fnode.lineno,
            )
        elif has_body_mutation:
            trace = _append_trace(trace, "sink", "state mutation in route body reachable without auth", line=fnode.lineno)
        else:
            trace = _append_trace(trace, "sink", "resource-specific route reachable without auth", line=fnode.lineno)

        findings.append(Finding(
            category="security", severity=sev,
            title=f"CWE-862: Missing authentication on {fname}() — {label}",
            description=(
                f"`{fname}()` is a route handler with no authentication decorator. "
                f"Any unauthenticated caller can reach this endpoint."
                + (f" It is on an `/admin` path — critical privilege-escalation risk." if is_admin else "")
                + f" Missing: `@login_required` or equivalent."
            ),
            line=fnode.lineno,
            suggestion="Add `@login_required` above `@app.route`. For admin routes, also verify elevated role.",
            cwe="CWE-862", agent="python-analyzer",
            confidence=0.95,
            analysis_kind="route-heuristic",
            trace=trace,
        ))

    return _assign_rule_ids(findings, "PY-020")


def _rule_13(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    # ── Rule 13: Command injection — subprocess + shell=True + dynamic cmd ─
    _subproc_funcs = {"run","call","Popen","check_call","check_output","getoutput","getstatusoutput"}
    for fname, fnode in func_defs.items():
        for node in ast.walk(fnode):
            if not isinstance(node, ast.Call):
                continue
            fn_name = None
            if isinstance(node.func, ast.Attribute) and node.func.attr in _subproc_funcs:
                fn_name = node.func.attr
            elif isinstance(node.func, ast.Name) and node.func.id in _subproc_funcs:
                fn_name = node.func.id
            if fn_name is None:
                continue
            shell_true = any(
                isinstance(kw, ast.keyword) and kw.arg == "shell" and
                isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            if not shell_true or not node.args:
                continue
            cmd = node.args[0]
            if isinstance(cmd, ast.Constant):
                continue  # literal string — not dynamic
            findings.append(Finding(
                category="security", severity=Severity.CRITICAL,
                title=f"CWE-78: Command injection in {fname}() via shell=True",
                description=(
                    f"`{fname}()` calls `subprocess.{fn_name}()` with `shell=True` and a "
                    f"dynamically constructed command at L{node.lineno}. An attacker can inject "
                    f"arbitrary OS commands via shell metacharacters (`;`, `$(...)`, `|`)."
                ),
                line=node.lineno,
                suggestion=(
                    "Pass a list to subprocess instead: `subprocess.run(['cmd', arg], ...)`. "
                    "If shell=True is unavoidable, use `shlex.quote()` on every user-controlled part."
                ),
                cwe="CWE-78", agent="python-analyzer",
            ))

    return _assign_rule_ids(findings, "PY-021")


def _rule_14(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    # ── Rule 14: SSRF — HTTP calls with unvalidated variable URLs ─────────
    # Only flag calls on objects whose name looks like an HTTP client.
    # Generic verbs (get/post/…) are shared with dict/config/.get() — requiring
    # an HTTP-client-looking receiver eliminates nearly all false positives.
    _ssrf_funcs  = {"urlopen","urlretrieve","get","post","put","patch","delete",
                    "request","head","fetch","send"}
    _http_verbs  = {"get","post","put","patch","delete","head","request","send","fetch"}
    _HTTP_CLI_RE = re.compile(
        r'requests?|session|client|http|aiohttp|httpx|api_?client|conn|transport|agent',
        re.IGNORECASE,
    )
    _ssrf_sus_names = {
        "url","callback_url","webhook_url","endpoint","target","redirect_url",
        "next","dest","destination","host","location","callback","return_url",
    }
    for fname, fnode in func_defs.items():
        tainted_ssrf: set[str] = set()
        for node in ast.walk(fnode):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        s = _get_taint_source(node.value)
                        if s:
                            tainted_ssrf.add(t.id)
                        elif _is_tainted_expr(node.value, {v: None for v in tainted_ssrf}):
                            tainted_ssrf.add(t.id)
        for node in ast.walk(fnode):
            if not isinstance(node, ast.Call):
                continue
            fn_attr = None
            if isinstance(node.func, ast.Attribute) and node.func.attr in _ssrf_funcs:
                fn_attr = node.func.attr
                # For generic HTTP verbs, the receiver must look like an HTTP client
                # (prevents dict.get(), config.get(), etc. from being flagged)
                if fn_attr in _http_verbs:
                    obj = node.func.value
                    obj_name = obj.id if isinstance(obj, ast.Name) else (
                        obj.attr if isinstance(obj, ast.Attribute) else ""
                    )
                    if not _HTTP_CLI_RE.search(obj_name):
                        continue
            if fn_attr is None:
                continue
            url_args = list(node.args[:1])
            for kw in node.keywords:
                if kw.arg in ("url","URL"):
                    url_args.append(kw.value)
            for url_arg in url_args:
                if isinstance(url_arg, ast.Constant):
                    continue
                is_tainted = False
                var_name = "url"
                if isinstance(url_arg, ast.Name):
                    var_name = url_arg.id
                    is_tainted = (url_arg.id in tainted_ssrf or url_arg.id.lower() in _ssrf_sus_names)
                elif isinstance(url_arg, ast.Attribute):
                    # Reconstruct chain; only flag if root is a known taint source
                    _parts: list[str] = []
                    _cn: ast.expr = url_arg
                    while isinstance(_cn, ast.Attribute):
                        _parts.append(_cn.attr)
                        _cn = _cn.value
                    if isinstance(_cn, ast.Name):
                        _parts.append(_cn.id)
                    _parts.reverse()
                    root_name = _parts[0] if _parts else ""
                    is_tainted = (
                        root_name in tainted_ssrf
                        or root_name.lower() in {"request","req","event","body","payload","data"}
                    )
                    var_name = ".".join(_parts) if _parts else "attr"
                elif isinstance(url_arg, (ast.JoinedStr, ast.BinOp, ast.Call)):
                    is_tainted = _is_tainted_expr(url_arg, {v: None for v in tainted_ssrf})
                    var_name = "interpolated URL"
                if not is_tainted:
                    continue
                findings.append(Finding(
                    category="security", severity=Severity.HIGH,
                    title=f"CWE-918: SSRF in {fname}() — unvalidated URL passed to {fn_attr}()",
                    description=(
                        f"`{fname}()` calls `{fn_attr}()` with `{var_name}` at L{node.lineno}. "
                        f"If this comes from user input, an attacker can reach internal services "
                        f"(cloud metadata 169.254.169.254, Redis, databases) or arbitrary external URLs."
                    ),
                    line=node.lineno,
                    suggestion=(
                        "Validate URL against an allowlist: parse with `urllib.parse.urlparse()`, "
                        "verify scheme in ('http','https') and netloc in ALLOWED_HOSTS. "
                        "Block private/loopback IP ranges."
                    ),
                    cwe="CWE-918", agent="python-analyzer",
                ))
                break

    return _assign_rule_ids(findings, "PY-022")


def _rule_15(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    # ── Rule 15: Path traversal — os.path.join with unsanitized variable ──
    for fname, fnode in func_defs.items():
        sanitized_paths: set[str] = set()
        for node in ast.walk(fnode):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and isinstance(node.value, ast.Call):
                        called = ""
                        if isinstance(node.value.func, ast.Attribute):
                            val = node.value.func.value
                            obj = val.id if isinstance(val, ast.Name) else ""
                            called = f"{obj}.{node.value.func.attr}"
                        elif isinstance(node.value.func, ast.Name):
                            called = node.value.func.id
                        if any(s in called for s in ("basename","secure_filename","resolve")):
                            sanitized_paths.add(t.id)

        tainted_paths: set[str] = set()
        for node in ast.walk(fnode):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        s = _get_taint_source(node.value)
                        if s:
                            tainted_paths.add(t.id)
                        elif _is_tainted_expr(node.value, {v: None for v in tainted_paths}):
                            tainted_paths.add(t.id)
                        elif isinstance(node.value, ast.Subscript):
                            # Only taint if the subscript base is itself tainted
                            if _is_tainted_expr(node.value, {v: None for v in tainted_paths}):
                                tainted_paths.add(t.id)

        for node in ast.walk(fnode):
            if not isinstance(node, ast.Call):
                continue
            is_path_join = (
                isinstance(node.func, ast.Attribute) and
                node.func.attr == "join" and
                isinstance(node.func.value, ast.Attribute) and
                node.func.value.attr == "path"
            )
            if not is_path_join:
                continue
            for arg in node.args[1:]:
                var_name = None
                if isinstance(arg, ast.Name):
                    var_name = arg.id
                elif isinstance(arg, ast.Subscript):
                    var_name = "subscript"
                if var_name and var_name not in sanitized_paths:
                    findings.append(Finding(
                        category="security", severity=Severity.HIGH,
                        title=f"CWE-22: Path traversal in {fname}() via os.path.join()",
                        description=(
                            f"`{fname}()` passes `{var_name}` (possibly user-controlled or DB-sourced) "
                            f"to `os.path.join()` at L{node.lineno} without sanitization. "
                            f"`../` sequences can escape the intended directory."
                        ),
                        line=node.lineno,
                        suggestion=(
                            "Sanitize: `from werkzeug.utils import secure_filename; safe = secure_filename(filename)`. "
                            "Verify resolved path: `assert os.path.realpath(p).startswith(BASE_DIR)`."
                        ),
                        cwe="CWE-22", agent="python-analyzer",
                    ))
                    break

    return _assign_rule_ids(findings, "PY-023")


def _rule_16(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    # ── Rule 16: IDOR — auth routes that query by ID without owner check ──
    for fname, fnode in func_defs.items():
        is_authed = has_route_deco = False
        for deco in fnode.decorator_list:
            dname = None
            if isinstance(deco, ast.Name):
                dname = deco.id
            elif isinstance(deco, ast.Attribute):
                dname = deco.attr
            elif isinstance(deco, ast.Call):
                if isinstance(deco.func, ast.Name):
                    dname = deco.func.id
                elif isinstance(deco.func, ast.Attribute):
                    if deco.func.attr in _FLASK_ROUTE_ATTRS:
                        has_route_deco = True
                    dname = deco.func.attr
            if dname in _AUTH_DECORATORS:
                is_authed = True
            if dname in _FLASK_ROUTE_ATTRS:
                has_route_deco = True
        if not (is_authed and has_route_deco):
            continue
        principal_aliases = _principal_aliases(fnode)
        resource_names = _route_resource_names(fnode)
        has_guard = _body_has_explicit_ownership_guard(fnode, principal_aliases)
        base_trace = _merge_traces(
            _route_trace_frames(fnode),
            _resource_parameter_trace_frames(resource_names, line=fnode.lineno),
            _decorator_trace_frames(fnode, _AUTH_DECORATORS, label_prefix="auth decorator"),
        )
        for node in ast.walk(fnode):
            if not isinstance(node, ast.Call):
                continue
            if not (isinstance(node.func, ast.Attribute) and
                    node.func.attr == "execute" and node.args):
                if _call_looks_like_orm_lookup(node, resource_names, principal_aliases) and not has_guard:
                    call_text = _safe_unparse(node)
                    trace = _append_trace(base_trace, "gap", "no ownership guard detected", line=fnode.lineno)
                    trace = _append_trace(trace, "sink", f"resource lookup `{call_text[:100]}`", line=node.lineno)
                    findings.append(Finding(
                        category="security", severity=Severity.HIGH,
                        title=f"CWE-639: IDOR in {fname}() — ORM lookup by ID with no ownership check",
                        description=(
                            f"`{fname}()` loads a resource at L{node.lineno} using `{call_text[:100]}` "
                            f"without verifying the authenticated user owns it. Any authenticated user "
                            f"can retrieve another user's data by substituting any `id`."
                        ),
                        line=node.lineno,
                        suggestion=(
                            "Scope ORM lookups by owner/tenant as well as resource ID, for example "
                            "`Post.query.filter_by(id=post_id, owner_id=g.user_id).first()`, or "
                            "perform an explicit `if post.owner_id != g.user_id: abort(403)` guard."
                        ),
                        cwe="CWE-639", agent="python-analyzer",
                        confidence=0.92,
                        analysis_kind="route-heuristic",
                        trace=trace,
                    ))
                continue
            sql_arg = node.args[0]
            if not (isinstance(sql_arg, ast.Constant) and isinstance(sql_arg.value, str)):
                continue
            sql_str = sql_arg.value
            sql_up = sql_str.upper()
            if not any(v in sql_up for v in ("SELECT","DELETE","UPDATE")):
                continue
            if "WHERE" not in sql_up:
                continue
            if not re.search(r'\bid\b\s*=', sql_str, re.IGNORECASE):
                continue
            # Only check WHERE clause for ownership — not SELECT column list
            where_part = sql_up.split("WHERE", 1)[-1] if "WHERE" in sql_up else ""
            if _OWNERSHIP_RE.search(where_part) or has_guard:
                continue
            trace = _append_trace(base_trace, "gap", "no ownership guard detected", line=fnode.lineno)
            trace = _append_trace(trace, "sink", f"resource query `{sql_str[:100]}`", line=node.lineno)
            findings.append(Finding(
                category="security", severity=Severity.HIGH,
                title=f"CWE-639: IDOR in {fname}() — resource fetched by ID with no ownership check",
                description=(
                    f"`{fname}()` queries a resource by `id` at L{node.lineno} without verifying "
                    f"the requesting user owns it. Any authenticated user can retrieve another user's "
                    f"data by substituting any `id`. SQL: `{sql_str[:100]}`."
                ),
                line=node.lineno,
                suggestion=(
                    "Add an ownership filter: `WHERE id = ? AND owner_id = ?`, "
                    "pass `(doc_id, g.user_id)` as parameters."
                ),
                cwe="CWE-639", agent="python-analyzer",
                confidence=0.92,
                analysis_kind="route-heuristic",
                trace=trace,
            ))

    return _assign_rule_ids(findings, "PY-024")


def _rule_17(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    # ── Rule 17: Missing ownership check before mutation (CWE-285) ────────
    _mutation_re = re.compile(r'\b(?:INSERT|UPDATE|DELETE)\b', re.IGNORECASE)
    _res_id_url_pat = re.compile(
        r'<\s*(?:int|string|uuid)?\s*:\s*(?:doc_id|item_id|resource_id|post_id|note_id|'
        r'file_id|object_id|entry_id|record_id|msg_id)\s*>',
        re.IGNORECASE,
    )
    for fname, fnode in func_defs.items():
        fn_authed = fn_route = fn_res_id = False
        for deco in fnode.decorator_list:
            dn = None
            if isinstance(deco, ast.Name):
                dn = deco.id
            elif isinstance(deco, ast.Attribute):
                dn = deco.attr
            elif isinstance(deco, ast.Call):
                if isinstance(deco.func, ast.Name):
                    dn = deco.func.id
                elif isinstance(deco.func, ast.Attribute):
                    dn = deco.func.attr
                    if dn in _FLASK_ROUTE_ATTRS:
                        fn_route = True
                for darg in deco.args:
                    if isinstance(darg, ast.Constant) and isinstance(darg.value, str):
                        if _res_id_url_pat.search(darg.value):
                            fn_res_id = True
            if dn in _AUTH_DECORATORS:
                fn_authed = True
            if dn in _FLASK_ROUTE_ATTRS:
                fn_route = True
        if not (fn_authed and fn_route and fn_res_id):
            continue

        principal_aliases = _principal_aliases(fnode)
        resource_names = _route_resource_names(fnode)
        has_guard = _body_has_explicit_ownership_guard(fnode, principal_aliases)
        base_trace = _merge_traces(
            _route_trace_frames(fnode),
            _resource_parameter_trace_frames(resource_names, line=fnode.lineno),
            _decorator_trace_frames(fnode, _AUTH_DECORATORS, label_prefix="auth decorator"),
        )
        resource_vars: dict[str, tuple[int, str]] = {}
        for node in ast.walk(fnode):
            if not isinstance(node, ast.Assign):
                continue
            if not isinstance(node.value, ast.Call):
                continue
            if not _call_looks_like_orm_lookup(node.value, resource_names, principal_aliases):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    resource_vars[target.id] = (node.lineno, _safe_unparse(node.value)[:100] or "resource lookup")

        mutation_line = None
        mutation_label = "resource mutation"
        lookup_context: tuple[int, str] | None = None
        for node in ast.walk(fnode):
            if not isinstance(node, ast.Call):
                continue

            if (isinstance(node.func, ast.Attribute) and node.func.attr == "execute" and node.args):
                sql_a = node.args[0]
                if isinstance(sql_a, ast.Constant) and isinstance(sql_a.value, str):
                    sql_v = sql_a.value
                    if _mutation_re.search(sql_v) and mutation_line is None:
                        sql_up = sql_v.upper()
                        where_part = sql_up.split("WHERE", 1)[-1] if "WHERE" in sql_up else ""
                        if not (_OWNERSHIP_RE.search(where_part) or has_guard):
                            mutation_line = node.lineno
                            mutation_label = _safe_unparse(node)[:100] or "SQL mutation"

            if mutation_line is None and not has_guard:
                if _call_looks_like_direct_orm_mutation(node, resource_names, principal_aliases):
                    mutation_line = node.lineno
                    mutation_label = _safe_unparse(node)[:100] or "query mutation"
                    continue

                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in _DIRECT_MUTATION_CALLS:
                        if isinstance(node.func.value, ast.Name) and node.func.value.id in resource_vars:
                            mutation_line = node.lineno
                            mutation_label = _safe_unparse(node)[:100] or "resource mutation"
                            lookup_context = resource_vars[node.func.value.id]
                            continue
                    if (
                        node.func.attr == "delete"
                        and node.args
                        and "session" in _call_chain_names(node)
                        and isinstance(node.args[0], ast.Name)
                        and node.args[0].id in resource_vars
                    ):
                        mutation_line = node.lineno
                        mutation_label = _safe_unparse(node)[:100] or "resource mutation"
                        lookup_context = resource_vars[node.args[0].id]

        if mutation_line is not None:
            trace = base_trace
            if lookup_context is not None:
                trace = _append_trace(trace, "check", f"resource lookup `{lookup_context[1]}`", line=lookup_context[0])
            trace = _append_trace(trace, "gap", "no ownership guard detected before mutation", line=fnode.lineno)
            trace = _append_trace(trace, "sink", f"mutation `{mutation_label}`", line=mutation_line)
            findings.append(Finding(
                category="security", severity=Severity.HIGH,
                title=f"CWE-285: Missing ownership check before mutation in {fname}()",
                description=(
                    f"`{fname}()` performs an INSERT/UPDATE/DELETE at L{mutation_line} on a resource "
                    f"identified by a URL path parameter without first verifying the requesting user "
                    f"owns it. Any authenticated user can mutate another user's resource."
                ),
                line=mutation_line,
                suggestion=(
                    "Before mutating, SELECT and verify ownership: "
                    "`row = db.execute('SELECT owner_id FROM docs WHERE id=?', (id,)).fetchone()`. "
                    "Then `if row['owner_id'] != g.user_id: abort(403)`."
                ),
                cwe="CWE-285", agent="python-analyzer",
                confidence=0.91,
                analysis_kind="route-heuristic",
                trace=trace,
            ))

    return _assign_rule_ids(findings, "PY-025")


def _rule_18(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    # ── Rule 18: Auth-bypass via presence-only token check in @wraps ──────
    _val_fn_pat = re.compile(
        r'verify|decode|validate|hmac|compare|lookup|authenticate|introspect|check_token|jwt',
        re.IGNORECASE,
    )
    for fname, fnode in func_defs.items():
        for inner in ast.walk(fnode):
            if not isinstance(inner, (ast.FunctionDef, ast.AsyncFunctionDef)) or inner is fnode:
                continue
            is_wrapped = any(
                (isinstance(d, ast.Call) and
                 isinstance(d.func, ast.Name) and d.func.id == "wraps") or
                (isinstance(d, ast.Name) and d.id == "wraps")
                for d in inner.decorator_list
            )
            if not is_wrapped:
                continue
            auth_sources: dict[str, ast.Call] = {}
            for asgn in ast.walk(inner):
                if not isinstance(asgn, ast.Assign):
                    continue
                for t in asgn.targets:
                    if not isinstance(t, ast.Name):
                        continue
                    val = asgn.value
                    if not (isinstance(val, ast.Call) and
                            isinstance(val.func, ast.Attribute) and
                            val.func.attr == "get" and
                            isinstance(val.func.value, ast.Attribute) and
                            isinstance(val.func.value.value, ast.Name) and
                            val.func.value.value.id == "request" and
                            val.func.value.attr in ("headers","cookies","args")):
                        continue
                    auth_sources[t.id] = val
            if not auth_sources:
                continue
            auth_vars = set(auth_sources)
            validated: set[str] = set()
            for call_node in ast.walk(inner):
                if not isinstance(call_node, ast.Call):
                    continue
                fn_name = ""
                if isinstance(call_node.func, ast.Name):
                    fn_name = call_node.func.id
                elif isinstance(call_node.func, ast.Attribute):
                    fn_name = call_node.func.attr
                if not _val_fn_pat.search(fn_name):
                    continue
                for arg in ast.walk(call_node):
                    if isinstance(arg, ast.Name) and arg.id in auth_vars:
                        validated.add(arg.id)
                        break
            unvalidated = auth_vars - validated
            if not unvalidated:
                continue
            for if_node in ast.walk(inner):
                if not isinstance(if_node, ast.If):
                    continue
                checked_names = _presence_only_checked_names(if_node.test) & unvalidated
                if not checked_names:
                    continue
                checked_name = sorted(checked_names)[0]
                var_list = ", ".join(f"`{v}`" for v in sorted(unvalidated))
                source_node = auth_sources[checked_name]
                source_text = _safe_unparse(source_node)[:100] or checked_name
                gate_text = _safe_unparse(if_node.test)[:100] or checked_name
                trace: tuple[TraceFrame, ...] = ()
                trace = _append_trace(
                    trace,
                    "source",
                    f"credential source `{source_text}`",
                    line=getattr(source_node, "lineno", inner.lineno),
                )
                trace = _append_trace(trace, "gap", f"`{checked_name}` never validated", line=inner.lineno)
                trace = _append_trace(trace, "sink", f"presence-only gate `if {gate_text}`", line=if_node.lineno)
                findings.append(Finding(
                    category="security", severity=Severity.CRITICAL,
                    title=f"CWE-287: Auth bypass in {fname}() — token presence check only, no validation",
                    description=(
                        f"`{fname}()` assigns {var_list} from `request.headers/cookies.get()` and "
                        f"gates access on `if {gate_text}:` — checking only that the header EXISTS. "
                        f"Any non-empty string bypasses the check. Token is never validated."
                    ),
                    line=if_node.lineno,
                    suggestion=(
                        "Validate the token: decode a JWT with signature verification, compare an HMAC, "
                        "or look up an opaque token in a database. Never gate on presence alone."
                    ),
                    cwe="CWE-287", agent="python-analyzer",
                    confidence=0.9,
                    analysis_kind="decorator-heuristic",
                    trace=trace,
                ))
                break

    return _assign_rule_ids(findings, "PY-026")


def _rule_19(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    # ── Rule 19: Broken access control — admin endpoint + auth but no privilege check ──
    for fname, fnode in func_defs.items():
        route_decorators = _iter_route_decorators(fnode)
        if not route_decorators or not _is_admin_endpoint(fnode):
            continue
        decorator_names = _decorator_names(fnode)
        has_auth_d = bool(decorator_names & _AUTH_DECORATORS)
        if not has_auth_d:
            continue
        has_privilege_d = any(name in _PRIVILEGE_DECORATORS for name in decorator_names)
        principal_aliases = _principal_aliases(fnode)
        if has_privilege_d or _body_has_privilege_guard(fnode, principal_aliases):
            continue
        trace = _merge_traces(
            _route_trace_frames(fnode),
            _decorator_trace_frames(fnode, _AUTH_DECORATORS, label_prefix="auth decorator"),
        )
        trace = _append_trace(trace, "gap", "no privilege decorator or inline role/permission guard detected", line=fnode.lineno)
        trace = _append_trace(trace, "sink", "admin route reachable after auth only", line=fnode.lineno)
        findings.append(Finding(
            category="security", severity=Severity.CRITICAL,
            title=f"CWE-285: Broken access control in {fname}() — admin endpoint with no privilege check",
            description=(
                f"`{fname}()` is auth-protected but never verifies that the caller "
                f"holds an admin role or permission. Any authenticated user can reach this privileged route."
            ),
            line=fnode.lineno,
            suggestion=(
                "Add a privilege decorator such as `@admin_required` / `@requires_role('admin')`, "
                "or an explicit guard like `if not current_user.is_admin: abort(403)`. "
                "Never rely on authentication alone for admin routes."
            ),
            cwe="CWE-285", agent="python-analyzer",
            confidence=0.92,
            analysis_kind="route-heuristic",
            trace=trace,
        ))

    return _assign_rule_ids(findings, "PY-027")


def _rule_20(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    # ── Rule 20: High cyclomatic complexity ──────────────────────────────
    for fname, fnode in func_defs.items():
        cc = 1
        for child in ast.walk(fnode):
            if isinstance(child, (ast.If, ast.For, ast.While, ast.ExceptHandler,
                                   ast.With, ast.Assert)):
                cc += 1
            if isinstance(child, ast.BoolOp):
                cc += len(child.values) - 1
        if cc > 15:
            sev = Severity.HIGH if cc > 25 else Severity.MEDIUM
            findings.append(Finding(
                category="architecture", severity=sev,
                title=f"Excessive complexity in {fname}() (CC={cc})",
                description=(
                    f"`{fname}()` at L{fnode.lineno} has cyclomatic complexity {cc}. "
                    f"Functions above 15 are hard to test, debug, and maintain."
                ),
                line=fnode.lineno,
                suggestion="Extract sub-functions for distinct logic branches or use lookup tables.",
                agent="python-analyzer",
            ))

    return _assign_rule_ids(findings, "PY-028")


# ──────────────────────────────────────────────────────────────────────────────
# P0: Rule 21 — CWE-22: Path traversal via open()/Path.read_text() with tainted arg
# ──────────────────────────────────────────────────────────────────────────────

def _rule_21(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    # Detect open() / Path(...).read_text() etc. with user-controlled path argument
    _file_open_funcs = {"open", "aopen"}
    _path_read_attrs = {"read_text", "read_bytes", "open", "write_text", "write_bytes"}
    for fname, fnode in func_defs.items():
        tainted_vars: set[str] = set()
        for arg in fnode.args.args:
            if arg.arg in ("request", "req", "event", "body", "payload", "data"):
                tainted_vars.add(arg.arg)
        for node in ast.walk(fnode):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        s = _get_taint_source(node.value)
                        if s:
                            tainted_vars.add(t.id)
                        elif _is_tainted_expr(node.value, {v: None for v in tainted_vars}):
                            tainted_vars.add(t.id)

        sanitized_paths: set[str] = set()
        for node in ast.walk(fnode):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and isinstance(node.value, ast.Call):
                        called = _get_call_name(node.value)
                        if any(s in called for s in ("basename", "secure_filename", "resolve", "realpath")):
                            sanitized_paths.add(t.id)

        for node in ast.walk(fnode):
            if not isinstance(node, ast.Call):
                continue
            # open(filename, ...) or builtins.open(...)
            is_open = (isinstance(node.func, ast.Name) and node.func.id in _file_open_funcs)
            # Path(...).read_text() etc.
            is_path_method = (
                isinstance(node.func, ast.Attribute) and
                node.func.attr in _path_read_attrs and
                isinstance(node.func.value, ast.Call) and
                isinstance(node.func.value.func, ast.Name) and
                node.func.value.func.id == "Path"
            )
            if not (is_open or is_path_method):
                continue

            # Get the first argument (the path)
            if is_open:
                check_args = node.args[:1]
            elif (is_path_method and isinstance(node.func, ast.Attribute)
                  and isinstance(node.func.value, ast.Call)):
                check_args = node.func.value.args[:1]
            else:
                check_args = []
            for arg in check_args:
                # Check if the argument contains tainted data
                is_tainted = False
                var_name = "path"
                if isinstance(arg, ast.Name):
                    var_name = arg.id
                    is_tainted = arg.id in tainted_vars and arg.id not in sanitized_paths
                elif isinstance(arg, ast.JoinedStr):
                    # f-string: open(f"/data/{filename}")
                    for val in arg.values:
                        if isinstance(val, ast.FormattedValue):
                            if isinstance(val.value, ast.Name):
                                vn = val.value.id
                                if vn in tainted_vars and vn not in sanitized_paths:
                                    is_tainted = True
                                    var_name = vn
                                    break
                elif isinstance(arg, ast.BinOp):
                    # String concatenation: "/data/" + filename
                    is_tainted = _is_tainted_expr(arg, {v: None for v in tainted_vars - sanitized_paths})
                    var_name = "concatenated path"

                if not is_tainted:
                    continue
                findings.append(Finding(
                    category="security", severity=Severity.HIGH,
                    title=f"CWE-22: Path traversal in {fname}() via open()",
                    description=(
                        f"`{fname}()` passes `{var_name}` (user-controlled) to file open at "
                        f"L{node.lineno} without path sanitization. `../` sequences can escape "
                        f"the intended directory and read/write arbitrary files."
                    ),
                    line=node.lineno,
                    suggestion=(
                        "Sanitize: `from werkzeug.utils import secure_filename; safe = secure_filename(filename)`. "
                        "Verify resolved path: `assert os.path.realpath(p).startswith(BASE_DIR)`."
                    ),
                    cwe="CWE-22", agent="python-analyzer",
                ))
                break

    return _assign_rule_ids(findings, "PY-029")


# ──────────────────────────────────────────────────────────────────────────────
# P0: Rule 22 — CWE-601: Open Redirect via redirect() with user-controlled URL
# ──────────────────────────────────────────────────────────────────────────────

def _rule_22(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    _redirect_fns = {"redirect"}
    _safe_redirect_fns = {"url_for", "safe_redirect", "is_safe_url", "url_has_allowed_host_and_scheme"}
    for fname, fnode in func_defs.items():
        tainted_vars: set[str] = set()
        validated_vars: set[str] = set()
        for arg in fnode.args.args:
            if arg.arg in ("request", "req", "event", "body", "payload", "data"):
                tainted_vars.add(arg.arg)
        for node in ast.walk(fnode):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        s = _get_taint_source(node.value)
                        if s:
                            tainted_vars.add(t.id)
                        elif _is_tainted_expr(node.value, {v: None for v in tainted_vars}):
                            tainted_vars.add(t.id)
                        elif isinstance(node.value, ast.Call):
                            cn = _get_call_name(node.value)
                            if cn and any(sf in cn for sf in _safe_redirect_fns):
                                validated_vars.add(t.id)

        for node in ast.walk(fnode):
            if not isinstance(node, ast.Call):
                continue
            fn_name = ""
            if isinstance(node.func, ast.Name):
                fn_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                fn_name = node.func.attr
            if fn_name not in _redirect_fns:
                continue
            if not node.args:
                continue
            url_arg = node.args[0]
            is_tainted = False
            var_name = "url"
            if isinstance(url_arg, ast.Name):
                var_name = url_arg.id
                is_tainted = url_arg.id in tainted_vars and url_arg.id not in validated_vars
            elif isinstance(url_arg, ast.Call):
                cn = _get_call_name(url_arg)
                if cn and any(sf in cn for sf in _safe_redirect_fns):
                    continue  # redirect(url_for(...)) is safe
                is_tainted = _is_tainted_expr(url_arg, {v: None for v in tainted_vars})
                var_name = "expression"
            elif isinstance(url_arg, (ast.JoinedStr, ast.BinOp)):
                is_tainted = _is_tainted_expr(url_arg, {v: None for v in tainted_vars})
                var_name = "interpolated URL"
            elif isinstance(url_arg, ast.Subscript):
                is_tainted = _is_tainted_expr(url_arg, {v: None for v in tainted_vars})
                var_name = "subscript"
            if not is_tainted:
                continue
            findings.append(Finding(
                category="security", severity=Severity.HIGH,
                title=f"CWE-601: Open redirect in {fname}() via redirect()",
                description=(
                    f"`{fname}()` passes user-controlled `{var_name}` to `redirect()` at "
                    f"L{node.lineno}. An attacker can craft a URL that redirects victims to "
                    f"a malicious site for phishing or credential theft."
                ),
                line=node.lineno,
                suggestion=(
                    "Validate redirect targets against an allowlist of safe paths/domains. "
                    "Use `url_for()` for internal redirects. Check with "
                    "`url_has_allowed_host_and_scheme(url, allowed_hosts)`."
                ),
                cwe="CWE-601", agent="python-analyzer",
            ))

    return _assign_rule_ids(findings, "PY-030")


# ──────────────────────────────────────────────────────────────────────────────
# P1: Rule 23 — CWE-287: Two-line auth bypass (token = request...get(); if token:)
# ──────────────────────────────────────────────────────────────────────────────

def _rule_23(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    _val_fn_pat = re.compile(
        r'verify|decode|validate|hmac|compare|lookup|authenticate|introspect|check_token|jwt',
        re.IGNORECASE,
    )
    for fname, fnode in func_defs.items():
        # Check if this is a route handler (not a decorator inner function — rule_18 handles those)
        is_route = False
        for deco in fnode.decorator_list:
            if isinstance(deco, ast.Call) and isinstance(deco.func, ast.Attribute):
                if deco.func.attr in _FLASK_ROUTE_ATTRS:
                    is_route = True
        if not is_route:
            continue

        # Find variables assigned from request.headers/cookies/args.get()
        auth_sources: dict[str, ast.Call] = {}
        for node in ast.walk(fnode):
            if not isinstance(node, ast.Assign):
                continue
            for t in node.targets:
                if not isinstance(t, ast.Name):
                    continue
                val = node.value
                if not (isinstance(val, ast.Call) and
                        isinstance(val.func, ast.Attribute) and
                        val.func.attr == "get" and
                        isinstance(val.func.value, ast.Attribute) and
                        isinstance(val.func.value.value, ast.Name) and
                        val.func.value.value.id == "request" and
                        val.func.value.attr in ("headers", "cookies")):
                    continue
                auth_sources[t.id] = val

        if not auth_sources:
            continue
        auth_vars = set(auth_sources)

        # Check if any auth var is validated (passed to verify/decode/jwt etc.)
        validated: set[str] = set()
        for node in ast.walk(fnode):
            if not isinstance(node, ast.Call):
                continue
            fn_name = ""
            if isinstance(node.func, ast.Name):
                fn_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                fn_name = node.func.attr
            if not _val_fn_pat.search(fn_name):
                continue
            for arg in ast.walk(node):
                if isinstance(arg, ast.Name) and arg.id in auth_vars:
                    validated.add(arg.id)
                    break

        unvalidated = auth_vars - validated
        if not unvalidated:
            continue

        # Check if any unvalidated var is used in a bare `if var:` truthiness check
        for node in ast.walk(fnode):
            if not isinstance(node, ast.If):
                continue
            checked_names = _presence_only_checked_names(node.test) & unvalidated
            if checked_names:
                checked_name = sorted(checked_names)[0]
                var_list = ", ".join(f"`{v}`" for v in sorted(unvalidated))
                source_node = auth_sources[checked_name]
                source_text = _safe_unparse(source_node)[:100] or checked_name
                gate_text = _safe_unparse(node.test)[:100] or checked_name
                trace = _merge_traces(_route_trace_frames(fnode))
                trace = _append_trace(
                    trace,
                    "source",
                    f"credential source `{source_text}`",
                    line=getattr(source_node, "lineno", fnode.lineno),
                )
                trace = _append_trace(trace, "gap", f"`{checked_name}` never validated", line=fnode.lineno)
                trace = _append_trace(trace, "sink", f"presence-only gate `if {gate_text}`", line=node.lineno)
                findings.append(Finding(
                    category="security", severity=Severity.CRITICAL,
                    title=f"CWE-287: Auth bypass in {fname}() — token presence check without validation",
                    description=(
                        f"`{fname}()` assigns {var_list} from `request.headers/cookies.get()` and "
                        f"gates access with `if {gate_text}:` at L{node.lineno} — checking only that the "
                        f"header EXISTS. Any non-empty string bypasses the check."
                    ),
                    line=node.lineno,
                    suggestion=(
                        "Validate the token: decode a JWT with signature verification, compare an HMAC, "
                        "or look up an opaque token in a database. Never gate on presence alone."
                    ),
                    cwe="CWE-287", agent="python-analyzer",
                    confidence=0.9,
                    analysis_kind="route-heuristic",
                    trace=trace,
                ))
                break

    return _assign_rule_ids(findings, "PY-031")


# ──────────────────────────────────────────────────────────────────────────────
# P1: Rule 24 — CWE-798: JWT signing with hardcoded short secret
# ──────────────────────────────────────────────────────────────────────────────

def _rule_24(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    _jwt_sign_fns = {"encode", "sign"}
    _jwt_obj_names = {"jwt", "pyjwt", "jose", "jwk"}
    for fname, fnode in func_defs.items():
        # Collect variables that hold short hardcoded string values
        hardcoded_vars: dict[str, tuple[str, int]] = {}
        for node in ast.walk(fnode):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and isinstance(node.value, ast.Constant):
                        if isinstance(node.value.value, str) and 2 <= len(node.value.value) <= 64:
                            hardcoded_vars[t.id] = (node.value.value, node.lineno)

        # Also collect module-level hardcoded vars
        for node in ast.walk(ctx._tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue  # skip function bodies
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and isinstance(node.value, ast.Constant):
                        if isinstance(node.value.value, str) and 2 <= len(node.value.value) <= 64:
                            hardcoded_vars[t.id] = (node.value.value, node.lineno)

        for node in ast.walk(fnode):
            if not isinstance(node, ast.Call):
                continue
            if not (isinstance(node.func, ast.Attribute) and node.func.attr in _jwt_sign_fns):
                continue
            obj = node.func.value
            obj_name = obj.id if isinstance(obj, ast.Name) else ""
            if obj_name.lower() not in _jwt_obj_names:
                continue
            # Check the 'key' argument (2nd positional or keyword 'key')
            key_arg = None
            if len(node.args) >= 2:
                key_arg = node.args[1]
            for kw in node.keywords:
                if kw.arg == "key":
                    key_arg = kw.value
            if key_arg is None:
                continue
            is_hardcoded = False
            secret_val = ""
            if isinstance(key_arg, ast.Constant) and isinstance(key_arg.value, str):
                is_hardcoded = True
                secret_val = key_arg.value
            elif isinstance(key_arg, ast.Name) and key_arg.id in hardcoded_vars:
                is_hardcoded = True
                secret_val = hardcoded_vars[key_arg.id][0]
            if not is_hardcoded:
                continue
            findings.append(Finding(
                category="security", severity=Severity.CRITICAL,
                title=f"CWE-798: Hardcoded JWT signing secret in {fname}()",
                description=(
                    f"`{fname}()` signs a JWT at L{node.lineno} with a hardcoded secret "
                    f"(`{secret_val[:8]}...`). Anyone with source access can forge valid tokens."
                ),
                line=node.lineno,
                suggestion=(
                    "Load the signing key from an environment variable or secrets manager: "
                    "`key = os.environ['JWT_SECRET']`. Use RS256 with a private key for better security."
                ),
                cwe="CWE-798", agent="python-analyzer",
            ))

    return _assign_rule_ids(findings, "PY-032")


# ──────────────────────────────────────────────────────────────────────────────
# P1: Rule 25 — CWE-532: Sensitive data in log calls (PII, credentials)
# ──────────────────────────────────────────────────────────────────────────────

_PII_FIELD_PAT = re.compile(
    r'card.?num|credit.?card|ccn|cvv|cv2|cvc|ssn|social.?sec|'
    r'password|passwd|pwd|secret|private.?key|access.?token|'
    r'api.?key|auth.?token|session.?id|jwt|bearer',
    re.IGNORECASE,
)

def _rule_25(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    _log_method_names = {"info", "warning", "error", "debug", "critical", "warn", "exception"}
    _log_obj_names = {"logger", "log", "logging"}
    for fname, fnode in func_defs.items():
        # Track variables with PII-suggesting names
        pii_vars: set[str] = set()
        for arg in fnode.args.args:
            if _PII_FIELD_PAT.search(arg.arg):
                pii_vars.add(arg.arg)
        for node in ast.walk(fnode):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and _PII_FIELD_PAT.search(t.id):
                        pii_vars.add(t.id)
            # Also track request.form["card_number"] assignments
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        if isinstance(node.value, ast.Subscript):
                            if isinstance(node.value.slice, ast.Constant) and isinstance(node.value.slice.value, str):
                                if _PII_FIELD_PAT.search(node.value.slice.value):
                                    pii_vars.add(t.id)
                        elif isinstance(node.value, ast.Call):
                            # request.form.get("card_number")
                            if (isinstance(node.value.func, ast.Attribute) and
                                    node.value.func.attr == "get" and node.value.args):
                                first_arg = node.value.args[0]
                                if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                                    if _PII_FIELD_PAT.search(first_arg.value):
                                        pii_vars.add(t.id)

        if not pii_vars:
            continue

        for node in ast.walk(fnode):
            if not isinstance(node, ast.Call):
                continue
            is_log = False
            if isinstance(node.func, ast.Attribute) and node.func.attr in _log_method_names:
                obj = node.func.value
                if isinstance(obj, ast.Name) and obj.id.lower() in _log_obj_names:
                    is_log = True
                elif isinstance(obj, ast.Attribute) and obj.attr.lower() in _log_obj_names:
                    is_log = True
            if isinstance(node.func, ast.Name) and node.func.id == "print":
                is_log = True
            if not is_log:
                continue
            # Check all arguments (including f-strings) for PII variable refs
            logged_pii: set[str] = set()
            for arg_node in node.args:
                for child in ast.walk(arg_node):
                    if isinstance(child, ast.Name) and child.id in pii_vars:
                        logged_pii.add(child.id)
                    elif isinstance(child, ast.FormattedValue):
                        if isinstance(child.value, ast.Name) and child.value.id in pii_vars:
                            logged_pii.add(child.value.id)
            if logged_pii:
                var_list = ", ".join(f"`{v}`" for v in sorted(logged_pii))
                findings.append(Finding(
                    category="security", severity=Severity.HIGH,
                    title=f"CWE-532: Sensitive data logged in {fname}() at line {node.lineno}",
                    description=(
                        f"`{fname}()` logs {var_list} at L{node.lineno}. "
                        f"Credentials and PII in logs can be exposed via log aggregation services, "
                        f"SIEM dashboards, or backup files."
                    ),
                    line=node.lineno,
                    suggestion=(
                        "Never log credentials or PII. Mask sensitive values: "
                        "`card_masked = card[-4:].rjust(len(card), '*')`. "
                        "Log only non-sensitive identifiers."
                    ),
                    cwe="CWE-532", agent="python-analyzer",
                ))

    return _assign_rule_ids(findings, "PY-033")


# ──────────────────────────────────────────────────────────────────────────────
# P2: Rule 26 — CWE-639: IDOR without auth decorator (resource by ID, no owner check)
# ──────────────────────────────────────────────────────────────────────────────

def _rule_26(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    # Extends rule_16: detect IDOR even without @login_required.
    # Flags routes that query by user-supplied ID without ownership verification,
    # even if they have no auth decorator (which is actually worse).
    _id_param_pat = re.compile(r'(?:^|_)(?:id|uid|pk)$|_id$', re.IGNORECASE)
    for fname, fnode in func_defs.items():
        has_route = False
        has_auth = False
        for deco in fnode.decorator_list:
            dname = None
            if isinstance(deco, ast.Call) and isinstance(deco.func, ast.Attribute):
                if deco.func.attr in _FLASK_ROUTE_ATTRS:
                    has_route = True
                dname = deco.func.attr
            elif isinstance(deco, ast.Name):
                dname = deco.id
            elif isinstance(deco, ast.Attribute):
                dname = deco.attr
            if dname and dname in _AUTH_DECORATORS:
                has_auth = True
        if not has_route:
            continue

        principal_aliases = _principal_aliases(fnode)
        resource_names = _route_resource_names(fnode)
        has_guard = _body_has_explicit_ownership_guard(fnode, principal_aliases)
        base_trace = _merge_traces(
            _route_trace_frames(fnode),
            _resource_parameter_trace_frames(resource_names, line=fnode.lineno),
        )

        for node in ast.walk(fnode):
            if not isinstance(node, ast.Call):
                continue
            if _call_looks_like_orm_lookup(node, resource_names, principal_aliases) and not has_auth and not has_guard:
                call_text = _safe_unparse(node)
                trace = _append_trace(base_trace, "gap", "no auth decorator detected", line=fnode.lineno)
                trace = _append_trace(trace, "gap", "no ownership guard detected", line=fnode.lineno)
                trace = _append_trace(trace, "sink", f"resource lookup `{call_text[:100]}`", line=node.lineno)
                findings.append(Finding(
                    category="security", severity=Severity.CRITICAL,
                    title=f"CWE-639: IDOR in {fname}() — public ORM lookup by ID with no ownership check",
                    description=(
                        f"`{fname}()` loads a resource at L{node.lineno} using `{call_text[:100]}` "
                        f"with no ownership filter and no auth decorator. Any caller can retrieve "
                        f"another user's data by changing the route parameter."
                    ),
                    line=node.lineno,
                    suggestion=(
                        "Protect the route with authentication and scope the ORM lookup by owner/tenant, "
                        "or block access with an explicit `abort(403)` ownership guard."
                    ),
                    cwe="CWE-639", agent="python-analyzer",
                    confidence=0.92,
                    analysis_kind="route-heuristic",
                    trace=trace,
                ))

        # Look for SQL queries with f-string or format that embed an id-like parameter
        for node in ast.walk(fnode):
            if not isinstance(node, ast.Call):
                continue
            fn_attr = None
            if isinstance(node.func, ast.Attribute):
                fn_attr = node.func.attr
            if fn_attr != "execute" or not node.args:
                continue
            sql_arg = node.args[0]
            # f-string with id interpolation: f"SELECT ... WHERE id = {user_id}"
            if isinstance(sql_arg, ast.JoinedStr):
                has_id_interp = False
                for val in sql_arg.values:
                    if isinstance(val, ast.FormattedValue):
                        if isinstance(val.value, ast.Name) and _id_param_pat.search(val.value.id):
                            has_id_interp = True
                if not has_id_interp:
                    continue
                # Check if there's an ownership check anywhere in the function
                fn_src = ast.dump(fnode)
                if _OWNERSHIP_RE.search(fn_src) or has_guard:
                    continue
                sev = Severity.CRITICAL if not has_auth else Severity.HIGH
                trace = base_trace
                if not has_auth:
                    trace = _append_trace(trace, "gap", "no auth decorator detected", line=fnode.lineno)
                trace = _append_trace(trace, "gap", "no ownership guard detected", line=fnode.lineno)
                trace = _append_trace(trace, "sink", f"resource query `{_safe_unparse(node)[:100] or 'query by id'}`", line=node.lineno)
                findings.append(Finding(
                    category="security", severity=sev,
                    title=f"CWE-639: IDOR in {fname}() — query by ID with no ownership check",
                    description=(
                        f"`{fname}()` queries a resource by user-supplied ID at L{node.lineno} "
                        f"without verifying the requesting user owns it. "
                        + ("No auth decorator present — any user can access any record. " if not has_auth else "")
                        + "Any caller can retrieve/modify another user's data by changing the ID."
                    ),
                    line=node.lineno,
                    suggestion=(
                        "Add an ownership filter: `WHERE id = ? AND owner_id = ?`, "
                        "pass `(doc_id, g.user_id)` as parameters."
                    ),
                    cwe="CWE-639", agent="python-analyzer",
                    confidence=0.9,
                    analysis_kind="route-heuristic",
                    trace=trace,
                ))

    return _assign_rule_ids(findings, "PY-034")


# ──────────────────────────────────────────────────────────────────────────────
# P3: Rule 27 — CWE-915: Mass Assignment via request.json iteration
# ──────────────────────────────────────────────────────────────────────────────

def _rule_27(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    # Detect patterns like: for key, val in request.json.items(): db.set(key, val)
    # or: data = request.json; for k, v in data.items(): setattr(obj, k, v)
    for fname, fnode in func_defs.items():
        json_vars: set[str] = set()
        # Track variables assigned from request.json / request.get_json()
        for node in ast.walk(fnode):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        src = _get_taint_source(node.value)
                        if src and "JSON" in src.upper():
                            json_vars.add(t.id)
                        elif isinstance(node.value, ast.Call):
                            cn = _get_call_name(node.value)
                            if cn and "get_json" in cn:
                                json_vars.add(t.id)
                        elif isinstance(node.value, ast.Attribute):
                            if (isinstance(node.value.value, ast.Name) and
                                    node.value.value.id == "request" and
                                    node.value.attr == "json"):
                                json_vars.add(t.id)

        # Look for iteration over .items() of a JSON var
        for node in ast.walk(fnode):
            if not isinstance(node, ast.For):
                continue
            # for key, val in data.items()
            iter_call = node.iter
            if not (isinstance(iter_call, ast.Call) and
                    isinstance(iter_call.func, ast.Attribute) and
                    iter_call.func.attr == "items"):
                continue
            obj = iter_call.func.value
            is_json_iter = False
            if isinstance(obj, ast.Name) and obj.id in json_vars:
                is_json_iter = True
            elif (isinstance(obj, ast.Attribute) and
                  isinstance(obj.value, ast.Name) and
                  obj.value.id == "request" and obj.attr == "json"):
                is_json_iter = True
            if not is_json_iter:
                continue

            # Check the loop body for setattr or DB mutation calls
            body_has_mutation = False
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    if isinstance(child.func, ast.Name) and child.func.id in ("setattr", "db_set"):
                        body_has_mutation = True
                    elif isinstance(child.func, ast.Attribute) and child.func.attr in (
                        "update", "set", "__setitem__", "__setattr__", "save",
                    ):
                        body_has_mutation = True
                # Direct dict assignment: obj[key] = value
                if isinstance(child, ast.Assign):
                    for t in child.targets:
                        if isinstance(t, ast.Subscript):
                            body_has_mutation = True

            if not body_has_mutation:
                continue
            findings.append(Finding(
                category="security", severity=Severity.HIGH,
                title=f"CWE-915: Mass assignment in {fname}() at line {node.lineno}",
                description=(
                    f"`{fname}()` iterates over `request.json.items()` at L{node.lineno} and "
                    f"sets arbitrary fields on a database object. An attacker can inject unexpected "
                    f"fields like `is_admin`, `role`, or `balance` to escalate privileges."
                ),
                line=node.lineno,
                suggestion=(
                    "Use an explicit allowlist of permitted fields: "
                    "`ALLOWED = {'name', 'email'}; data = {k: v for k, v in request.json.items() if k in ALLOWED}`. "
                    "Never blindly iterate over user input to set model attributes."
                ),
                cwe="CWE-915", agent="python-analyzer",
            ))

    return _assign_rule_ids(findings, "PY-035")


def _rule_28(ctx: _Ctx) -> list[Finding]:
    """CWE-470: Use of externally-controlled input to select classes or methods (getattr dispatch)."""
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    func_summaries = ctx.func_summaries

    for fname, fnode in func_defs.items():
        tainted_vars: dict[str, _TaintInfo] = {}
        # Seed tainted vars from function parameters and direct sources
        for arg in fnode.args.args:
            if arg.arg in ("request", "req", "event", "body", "payload", "data"):
                tainted_vars[arg.arg] = (
                    "function parameter (likely untrusted)",
                    fnode.lineno,
                    set(),
                    (_make_trace_frame("source", f"parameter `{arg.arg}`", line=fnode.lineno),),
                )
        for node in ast.walk(fnode):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if not isinstance(t, ast.Name):
                        continue
                    src = _get_taint_source(node.value)
                    if src:
                        tainted_vars[t.id] = (
                            src, node.lineno, set(),
                            (_make_trace_frame("source", src, node.value, line=node.lineno),),
                        )
                    elif _find_tainted_expr_info(node.value, tainted_vars, func_summaries):
                        info = _find_tainted_expr_info(node.value, tainted_vars, func_summaries)
                        assert info is not None
                        tainted_vars[t.id] = (info[1], info[2], info[3],
                            _append_trace(info[4], "propagator", f"assign to `{t.id}`", line=node.lineno))

        for node in ast.walk(fnode):
            if not isinstance(node, ast.Call):
                continue
            call_name = _get_call_name(node)

            # Pattern: getattr(obj, method_or_attr) where method_or_attr is tainted
            if (call_name in ("getattr", "builtins.getattr")
                    and len(node.args) >= 2):
                attr_arg = node.args[1]
                attr_info = _find_tainted_expr_info(attr_arg, tainted_vars, func_summaries)
                if attr_info:
                    vname, vsrc, vline, san_cwes, trace = attr_info
                    findings.append(Finding(
                        category="security", severity=Severity.HIGH,
                        title=f"CWE-470: Externally-controlled method dispatch in {fname}() at line {node.lineno}",
                        description=(
                            f"`getattr()` is called with a tainted attribute name from `{vname}` "
                            f"({vsrc}, L{vline}). An attacker can invoke arbitrary methods on the target "
                            f"object, potentially accessing `__class__`, `__subclasses__`, or other "
                            f"introspection gadgets."
                        ),
                        line=node.lineno,
                        suggestion=(
                            "Validate attribute names against an explicit allowlist before calling getattr(): "
                            "`ALLOWED = {'view', 'edit'}; assert attr in ALLOWED; getattr(obj, attr)()`"
                        ),
                        cwe="CWE-470", rule_id="PY-036", agent="python-analyzer",
                        trace=_append_trace(trace, "sink", "sink `getattr()`", node),
                    ))

            # Pattern: __import__(tainted_module)
            if (call_name == "__import__" and len(node.args) >= 1):
                arg_info = _find_tainted_expr_info(node.args[0], tainted_vars, func_summaries)
                if arg_info:
                    vname, vsrc, vline, san_cwes, trace = arg_info
                    findings.append(Finding(
                        category="security", severity=Severity.CRITICAL,
                        title=f"CWE-470: Dynamic module import from user input in {fname}() at line {node.lineno}",
                        description=(
                            f"`__import__()` receives a tainted module name from `{vname}` "
                            f"({vsrc}, L{vline}). An attacker can import arbitrary system modules "
                            f"to escalate privileges or execute arbitrary code."
                        ),
                        line=node.lineno,
                        suggestion="Use a hardcoded allowlist of permitted modules. Never pass user-controlled strings to __import__().",
                        cwe="CWE-470", rule_id="PY-036", agent="python-analyzer",
                        trace=_append_trace(trace, "sink", "sink `__import__()`", node),
                    ))

            # Pattern: importlib.import_module(tainted_module)
            if (call_name in ("importlib.import_module", "import_module") and len(node.args) >= 1):
                arg_info = _find_tainted_expr_info(node.args[0], tainted_vars, func_summaries)
                if arg_info:
                    vname, vsrc, vline, san_cwes, trace = arg_info
                    findings.append(Finding(
                        category="security", severity=Severity.CRITICAL,
                        title=f"CWE-470: Dynamic importlib.import_module from user input in {fname}() at line {node.lineno}",
                        description=(
                            f"`importlib.import_module()` receives a tainted module name from `{vname}` "
                            f"({vsrc}, L{vline})."
                        ),
                        line=node.lineno,
                        suggestion="Validate module names against an explicit allowlist before importing.",
                        cwe="CWE-470", rule_id="PY-036", agent="python-analyzer",
                        trace=_append_trace(trace, "sink", "sink `importlib.import_module()`", node),
                    ))

    return _assign_rule_ids(findings, "PY-036")


def _rule_29(ctx: _Ctx) -> list[Finding]:
    """CPG-assisted flow — run the CPG taint engine when available and merge unique findings."""
    try:
        from ansede_static.cpg import build_cpg, CPGTaintEngine  # noqa: PLC0415
    except ImportError:
        return []

    findings: list[Finding] = []
    code = "\n".join(ctx.lines)
    if not code.strip():
        return []

    try:
        cpg = build_cpg(code, ctx.filename)
    except Exception:
        return []

    try:
        engine = CPGTaintEngine(cpg)
        paths = engine.find_taint_paths()
    except Exception:
        return []

    # Keyword-based CWE mapping derived from sink label
    _SINK_CWES: dict[str, str] = {
        "execute": "CWE-89", "sql": "CWE-89",
        "system": "CWE-78", "popen": "CWE-78", "subprocess": "CWE-78",
        "eval": "CWE-95", "exec": "CWE-95",
        "urlopen": "CWE-918", "requests.get": "CWE-918", "requests.post": "CWE-918",
        "open": "CWE-22", "path.join": "CWE-22",
        "pickle": "CWE-502", "yaml.load": "CWE-502", "marshal": "CWE-502",
        "render_template_string": "CWE-79", "markup": "CWE-79",
    }

    for tp in paths:
        try:
            sink_label_lower = tp.sink_label.lower()
            cwe = next(
                (v for k, v in _SINK_CWES.items() if k in sink_label_lower),
                "CWE-89",
            )
            sev = Severity.HIGH
            if cwe in ("CWE-78", "CWE-95", "CWE-502"):
                sev = Severity.CRITICAL
            line = (tp.sink_lineno or 0) if tp.sink_lineno else (tp.source_lineno or 0)
            findings.append(Finding(
                category="security",
                severity=sev,
                title=f"{cwe}: CPG taint path — {tp.source_label} \u2192 {tp.sink_label}",
                description=(
                    f"CPG inter-procedural analysis found a taint path from `{tp.source_label}` "
                    f"(L{tp.source_lineno}) to `{tp.sink_label}` (L{tp.sink_lineno}). "
                    f"Tags: {', '.join(sorted(tp.tags))}."
                ),
                line=line,
                suggestion=_cwe_fix(cwe, tp.sink_label),
                rule_id="PY-037",
                cwe=cwe, agent="cpg-engine",
            ))
        except Exception:
            continue
    return findings


def _detect(code: str, filename: str = "", global_graph: object = None) -> list[Finding]:
    """Run all deterministic detection rules. Returns findings sorted by severity."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    lines = code.splitlines()
    sans = _code_sans_strings(code)
    func_defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_defs[node.name] = node
    func_summaries = _build_function_taint_summaries(tree, func_defs)

    ctx = _Ctx(lines=lines, sans=sans, func_defs=func_defs, func_summaries=func_summaries, _tree=tree, filename=filename, global_graph=global_graph)
    findings: list[Finding] = []
    for rule_fn in (
        _rule_01, _rule_02, _rule_03, _rule_04, _rule_05,
        _rule_06, _rule_07, _rule_08, _rule_09, _rule_10,
        _rule_11, _rule_12, _rule_13, _rule_14, _rule_15,
        _rule_16, _rule_17, _rule_18, _rule_19, _rule_20,
        _rule_21, _rule_22, _rule_23, _rule_24, _rule_25,
        _rule_26, _rule_27, _rule_28, _rule_29,
    ):
        findings.extend(rule_fn(ctx))

    # ── Data science ruleset ───────────────────────────────────────────────
    try:
        from ansede_static.rulesets.datascience import analyze_datascience
        findings.extend(analyze_datascience(code, filename))
    except Exception:  # pragma: no cover
        pass

    # ── Entropy-based secret detection ────────────────────────────────────
    try:
        from ansede_static.entropy import scan_for_secrets
        # Only run if the file is not too large (avoid false positives in data files)
        if len(code) < 500_000:
            findings.extend(scan_for_secrets(code, filename))
    except Exception:  # pragma: no cover
        pass

    # ── Deduplicate by (title.lower(), line) ──────────────────────────────
    # First: prefer AST-based findings over CPG findings for the same (cwe, line)
    ast_covered: set[tuple[str, int]] = set()
    for f in findings:
        if f.rule_id != "PY-037" and f.cwe:
            ast_covered.add((f.cwe, f.line or 0))
    findings = [
        f for f in findings
        if f.rule_id != "PY-037" or (f.cwe, f.line or 0) not in ast_covered
    ]
    # Second: title/line dedup
    seen: set[tuple[str, int | None]] = set()
    deduped: list[Finding] = []
    for f in findings:
        key = (f.title.lower()[:60], f.line)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # ── Filter out inline-suppressed findings ─────────────────────────────
    # A comment like  # ansede: ignore  or  # ansede: ignore[CWE-89]
    # on the finding's line suppresses that finding.
    filtered: list[Finding] = []
    for f in deduped:
        if f.line and 0 < f.line <= len(lines):
            m = _SUPPRESSION_RE.search(lines[f.line - 1])
            if m:
                suppressed = m.group(1)
                if not suppressed or (f.cwe and f.cwe in suppressed):
                    continue
        filtered.append(f)

    # ── Set confidence = 1.0 and generate auto-fixes ──────────────────────
    for f in filtered:
        f.confidence = 1.0
        if not f.auto_fix:
            f.auto_fix = _generate_auto_fix(f, lines)

    filtered.sort(key=lambda f: f.severity.sort_key)
    return filtered


def index_python_file(code: str, filename: str, global_graph):
    """
    Pass 1: Parse the file and register functions, classes, dependencies, and globals
    into the `GlobalGraph` for deep reachability analysis in Pass 2.
    """
    import ast
    from ansede_static.ir.global_graph import NodeID, TaintNode, Edge
    
    if global_graph is None:
        return
        
    try:
        tree = ast.parse(code, filename=filename)
    except SyntaxError:
        return
        
    def _resolve_import_target(module_name: str, current_file: str, level: int) -> str:
        module_path = Path(*module_name.split('.')) if module_name else Path()
        current_dir = Path(current_file).resolve(strict=False).parent

        if level > 0:
            anchor = current_dir
            for _ in range(max(level - 1, 0)):
                anchor = anchor.parent
            candidate = (anchor / module_path).with_suffix('.py')
            return str(candidate.resolve(strict=False))

        candidates = [current_dir / module_path]
        candidates.extend(parent / module_path for parent in current_dir.parents)
        for candidate in candidates:
            py_candidate = candidate.with_suffix('.py')
            if py_candidate.exists():
                return str(py_candidate.resolve(strict=False))
        return str((current_dir / module_path).with_suffix('.py').resolve(strict=False))

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module_name = node.module or ""
            target_file = _resolve_import_target(module_name, filename, node.level)

            for alias in node.names:
                local_name = alias.asname if alias.asname else alias.name
                if alias.name != "*":
                    # Register an IMPORTS edge
                    source_node = NodeID(file_path=filename, symbol_name=local_name)
                    target_node = NodeID(file_path=target_file, symbol_name=alias.name)
                    global_graph.add_edge(Edge(source=source_node, target=target_node, edge_type="IMPORTS"))

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            node_id = NodeID(file_path=filename, symbol_name=node.name)
            taint_node = TaintNode(
                id=node_id, 
                ast_type="FunctionDef", 
                line_start=node.lineno,
                is_source=False, 
                is_sink=False
            )
            global_graph.add_node(taint_node)
            
        elif isinstance(node, ast.ClassDef):
            node_id = NodeID(file_path=filename, symbol_name=node.name)
            taint_node = TaintNode(
                id=node_id, 
                ast_type="ClassDef", 
                line_start=node.lineno
            )
            global_graph.add_node(taint_node)
            
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            src = _get_taint_source(node.value)
            if src:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        node_id = NodeID(file_path=filename, symbol_name=target.id)
                        taint_node = TaintNode(
                            id=node_id,
                            ast_type="Global",
                            line_start=node.lineno,
                            taint_source=src,
                            taint_trace=(_make_trace_frame("source", src, line=node.lineno),)
                        )
                        global_graph.add_node(taint_node)

def analyze_python(code: str, filename: str = "", global_graph=None) -> AnalysisResult:
    """
    Analyze Python source code for security vulnerabilities and quality issues.

    Args:
        code:     Full source code as a string.
        filename: Optional file path for reporting.

    Returns:
        AnalysisResult with all findings.
    """
    result = AnalysisResult(
        file_path=filename,
        language="python",
        lines_scanned=len(code.splitlines()),
    )
    try:
        findings = _detect(code, filename=filename, global_graph=global_graph)
    except (SyntaxError, ValueError, RecursionError, TypeError) as exc:
        result.parse_error = f"Internal analyzer error: {exc}"
        return result

    result.findings = findings
    return result


def analyze_file(path: str | Path) -> AnalysisResult:
    """Convenience wrapper that reads a file then calls analyze_python."""
    p = Path(path)
    code = p.read_text(encoding="utf-8", errors="replace")
    return analyze_python(code, filename=str(p))
