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
import warnings
import tokenize as _tokenize
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Union

from ansede_static.cache.sqlite_store import SQLiteStore, stable_hash
from ansede_static.hardening import TemplateEngineDetector
from ansede_static.ir.global_graph import GlobalGraph
from ansede_static.template_transpiler import template_taint_nodes
from ansede_static.engine.clustering import cluster_findings
from ansede_static.engine.confidence import rescore_findings


# ──────────────────────────────────────────────────────────────────────────────
# Re-export types for convenience
# ──────────────────────────────────────────────────────────────────────────────

from ansede_static._types import Finding, Severity, AnalysisResult, TraceFrame


_TaintInfo = tuple[str, int, set[str], tuple[TraceFrame, ...]]
_ExprTaintInfo = tuple[str, str, int, set[str], tuple[TraceFrame, ...], tuple[str, ...]]
# Keep the Python front-end bound sourced from the workspace-global IFDS graph
# so Task B1 tuning cannot silently diverge between modules.
DEFAULT_IFDS_CALL_STRING_K = GlobalGraph.DEFAULT_CALL_STRING_K
IFDS_RETURN_VALUE_LABEL = "$ret"


def _extend_ifds_call_string(
    call_string: tuple[str, ...],
    *,
    caller_file: str,
    caller_name: str,
    callee_name: str,
    call_line: int | None,
    call_string_k: int = DEFAULT_IFDS_CALL_STRING_K,
) -> tuple[str, ...]:
    """Return a bounded call-string that includes the current callsite."""
    caller = caller_name or "<module>"
    site_label = f"{caller_file or '<stdin>'}::{caller}@{call_line or 0}->{callee_name}"
    extended = call_string + (site_label,)
    if call_string_k <= 0:
        return ()
    return extended[-call_string_k:]


# ──────────────────────────────────────────────────────────────────────────────
# Taint source catalogue
# ──────────────────────────────────────────────────────────────────────────────

TAINT_SOURCES: dict[str, str] = {
    # Flask / FastAPI / Django / Starlette / Litestar / aiohttp
    "request.args":           "HTTP query parameter",
    "request.form":           "HTTP form data",
    "request.data":           "raw HTTP body",
    "request.json":           "parsed HTTP JSON body",
    "request.files":          "uploaded file",
    "request.headers":        "HTTP header",
    "request.cookies":        "HTTP cookie",
    "request.GET":            "HTTP query parameter (Django)",
    "request.POST":           "HTTP form data (Django)",
    "request.body":           "raw HTTP body (Django/FastAPI/aiohttp)",
    "request.query_params":   "query parameter (FastAPI/Starlette)",
    "request.get_json":       "parsed HTTP JSON body (Flask get_json())",
    "request.values":         "merged GET+POST values (Flask)",
    "request.stream":         "raw HTTP body stream (Flask/FastAPI)",
    # Tornado web framework request sources
    "self.get_argument":      "Tornado HTTP request argument",
    "self.get_query_argument": "Tornado query string argument",
    "self.get_body_argument": "Tornado request body argument",
    "self.request.body":      "Tornado raw HTTP body",
    "self.request.arguments": "Tornado multi-value request arguments",
    # aiohttp server request sources
    "request.rel_url":        "aiohttp request URL (path + query)",
    "request.match_info":     "aiohttp route path parameters",
    "request.text":           "aiohttp request body as text",
    "request.post":           "aiohttp form data",
    # Bottle web framework request sources
    "request.query":          "Bottle query parameter",
    "request.forms":          "Bottle form data",
    "request.params":         "Bottle merged GET+POST params",
    "request.json_body":      "Bottle parsed JSON body",
    # Pyramid web framework request sources
    "request.matchdict":      "Pyramid URL path parameters",
    "request.GET":            "Pyramid query parameters",  # noqa: F601
    "request.POST":           "Pyramid form data",  # noqa: F601
    # Sanic web framework request sources
    "request.args":           "Sanic query parameters",  # noqa: F601
    "request.form":           "Sanic form data",  # noqa: F601
    "request.json":           "Sanic parsed JSON body",  # noqa: F601
    "request.files":          "Sanic uploaded file",  # noqa: F601
    # Falcon web framework request sources
    "req.params":             "Falcon URL path parameters",
    "req.media":              "Falcon parsed request body",
    "req.get_param":          "Falcon query/form parameter",
    "req.stream":             "Falcon raw request body stream",
    # CherryPy web framework request sources
    "cherrypy.request.params":"CherryPy request parameters",
    "cherrypy.request.json":  "CherryPy parsed JSON body",
    # Network / socket sources
    "urllib.request.urlopen": "remote HTTP response",
    "socket.recv":            "network socket data",
    "socket.recvfrom":        "network socket data",
    "httpx.get":              "remote HTTP response",
    "httpx.post":             "remote HTTP response",
    "httpx.request":          "remote HTTP response",
    "aiohttp.ClientSession.get": "remote HTTP response",
    # XML / data format parsers
    "xml.etree.ElementTree.parse":  "parsed XML",
    "lxml.etree.parse":             "parsed XML",
    "defusedxml.ElementTree.parse": "parsed XML",
    "xml.dom.minidom.parse":        "parsed XML",
    "xml.sax.parseString":          "parsed XML",
    "toml.load":                    "parsed TOML",
    "tomllib.load":                 "parsed TOML",
    "configparser.ConfigParser.read":"parsed config",
    # Message queue / event sources
    "kafka.KafkaConsumer":   "Kafka message",
    "pika.BlockingConnection":"RabbitMQ message",
    "redis.Redis.get":       "Redis value",
    "redis.StrictRedis.get": "Redis value",
    "request.url":            "request URL",
    "request.path":           "request path",
    "request.host":           "request Host header",
    "request.referrer":       "HTTP Referer header",
    "request.user_agent":     "HTTP User-Agent header",
    # Path/route parameters
    "kwargs":                 "route parameter (dict from URL path)",
    # Standard input
    "input":                  "user console input",
    "sys.argv":               "command-line argument",
    "sys.stdin":              "stdin",
    # Environment
    "os.environ":             "environment variable",
    "os.getenv":              "environment variable",
    # File reads that may load attacker-controlled content
    "open":                   "file contents (may be attacker-controlled)",
    "pathlib.Path.read_text": "file contents (may be attacker-controlled)",
    "pathlib.Path.read_bytes":"file contents (may be attacker-controlled)",
    # Unsafe deserialization (result already tainted)
    "json.loads":             "parsed JSON (may be from untrusted source)",
    "yaml.load":              "parsed YAML (unsafe loader)",
    "yaml.unsafe_load":       "parsed YAML (unsafe)",
    # Database query results used to construct further queries
    "fetchone":               "database row (may propagate taint to nested queries)",
    "fetchall":               "database rows (may propagate taint to nested queries)",
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
    "text":                       ("CWE-89", "SQL Injection (SQLAlchemy text())"),
    # Command Injection — CWE-78
    "os.system":                  ("CWE-78", "OS Command Injection"),
    "os.popen":                   ("CWE-78", "OS Command Injection"),
    "os.execve":                  ("CWE-78", "OS Command Injection via execve()"),
    "os.execvp":                  ("CWE-78", "OS Command Injection via execvp()"),
    "os.execl":                   ("CWE-78", "OS Command Injection via execl()"),
    "subprocess.call":            ("CWE-78", "OS Command Injection"),
    "subprocess.run":             ("CWE-78", "OS Command Injection"),
    "subprocess.Popen":           ("CWE-78", "OS Command Injection"),
    "subprocess.check_output":    ("CWE-78", "OS Command Injection"),
    "subprocess.check_call":      ("CWE-78", "OS Command Injection"),
    "subprocess.getoutput":       ("CWE-78", "OS Command Injection (shell=True implicit)"),
    "subprocess.getstatusoutput": ("CWE-78", "OS Command Injection (shell=True implicit)"),
    "pty.spawn":                  ("CWE-78", "OS Command Injection via pty.spawn()"),
    # Code Injection — CWE-94/95
    "eval":                       ("CWE-95", "Code Injection via eval()"),
    "exec":                       ("CWE-94", "Code Injection via exec()"),
    "compile":                    ("CWE-95", "Code Injection via compile()"),
    "__import__":                 ("CWE-95", "Dynamic import injection"),
    "importlib.import_module":    ("CWE-95", "Dynamic module import injection"),
    # Deserialization — CWE-502
    "pickle.loads":               ("CWE-502", "Unsafe Deserialization"),
    "pickle.load":                ("CWE-502", "Unsafe Deserialization"),
    "marshal.loads":              ("CWE-502", "Unsafe Deserialization"),
    "marshal.load":               ("CWE-502", "Unsafe Deserialization"),
    "yaml.load":                  ("CWE-502", "Unsafe Deserialization (yaml.load)"),
    "shelve.open":                ("CWE-502", "Unsafe Deserialization (shelve uses pickle)"),
    "dill.loads":                 ("CWE-502", "Unsafe Deserialization (dill)"),
    "jsonpickle.decode":          ("CWE-502", "Unsafe Deserialization (jsonpickle)"),
    # SSRF — CWE-918
    "requests.get":               ("CWE-918", "Server-Side Request Forgery"),
    "requests.post":              ("CWE-918", "Server-Side Request Forgery"),
    "requests.put":               ("CWE-918", "Server-Side Request Forgery"),
    "requests.patch":             ("CWE-918", "Server-Side Request Forgery"),
    "requests.delete":            ("CWE-918", "Server-Side Request Forgery"),
    "requests.request":           ("CWE-918", "Server-Side Request Forgery"),
    "urllib.request.urlopen":     ("CWE-918", "Server-Side Request Forgery"),
    "urllib.request.urlretrieve": ("CWE-918", "Server-Side Request Forgery"),
    "urlopen":                    ("CWE-918", "Server-Side Request Forgery"),
    "httpx.get":                  ("CWE-918", "Server-Side Request Forgery"),
    "httpx.post":                 ("CWE-918", "Server-Side Request Forgery"),
    "httpx.put":                  ("CWE-918", "Server-Side Request Forgery"),
    "httpx.patch":                ("CWE-918", "Server-Side Request Forgery"),
    "httpx.delete":               ("CWE-918", "Server-Side Request Forgery"),
    "httpx.request":              ("CWE-918", "Server-Side Request Forgery"),
    "aiohttp.ClientSession.get":  ("CWE-918", "Server-Side Request Forgery (aiohttp)"),
    "aiohttp.ClientSession.post": ("CWE-918", "Server-Side Request Forgery (aiohttp)"),
    "session.get":                ("CWE-918", "Server-Side Request Forgery (aiohttp session)"),
    "session.post":               ("CWE-918", "Server-Side Request Forgery (aiohttp session)"),
    # Path Traversal — CWE-22
    "open":                       ("CWE-22", "Path Traversal via open()"),
    "os.open":                    ("CWE-22", "Path Traversal via os.open()"),
    "os.path.join":               ("CWE-22", "Path Traversal via os.path.join()"),
    "pathlib.Path":               ("CWE-22", "Path Traversal via pathlib.Path"),
    # XSS — CWE-79
    "render_template_string":     ("CWE-79", "Cross-Site Scripting (template injection)"),
    "Markup":                     ("CWE-79", "Cross-Site Scripting (unescaped HTML)"),
    "jinja2.Template":            ("CWE-79", "Cross-Site Scripting (template injection)"),
    "Environment.from_string":    ("CWE-94", "Server-Side Template Injection (SSTI)"),
    "from_string":               ("CWE-94", "SSTI via Jinja2 Environment.from_string"),
    # Log injection — CWE-117
    "logging.info":               ("CWE-117", "Log Injection"),
    "logging.warning":            ("CWE-117", "Log Injection"),
    "logging.error":              ("CWE-117", "Log Injection"),
    "logging.debug":              ("CWE-117", "Log Injection"),
    "logging.critical":           ("CWE-117", "Log Injection"),
    "logger.info":                ("CWE-117", "Log Injection"),
    "logger.warning":             ("CWE-117", "Log Injection"),
    "logger.error":               ("CWE-117", "Log Injection"),
    "logger.debug":               ("CWE-117", "Log Injection"),
    # GraphQL Injection — CWE-943
    "graphql.execute":            ("CWE-89", "GraphQL Injection"),
    "graphql.execute_sync":       ("CWE-89", "GraphQL Injection"),
    "gql":                        ("CWE-89", "GraphQL Injection (gql())"),
    # NoSQL Injection — CWE-943
    "collection.find":            ("CWE-943", "NoSQL Injection (MongoDB find)"),
    "find":                       ("CWE-943", "NoSQL Injection (MongoDB find)"),
    "collection.aggregate":       ("CWE-943", "NoSQL Injection (MongoDB aggregate)"),
    "aggregate":                  ("CWE-943", "NoSQL Injection (MongoDB aggregate)"),
    "collection.update_one":      ("CWE-943", "NoSQL Injection (MongoDB update)"),
    "update_one":                 ("CWE-943", "NoSQL Injection (MongoDB update)"),
    "collection.delete_one":      ("CWE-943", "NoSQL Injection (MongoDB delete)"),
    "delete_one":                 ("CWE-943", "NoSQL Injection (MongoDB delete)"),
    # LDAP Injection — CWE-90
    "ldap.search":                ("CWE-90", "LDAP Injection"),
    "ldap.search_s":              ("CWE-90", "LDAP Injection"),
    "ldap.search_ext":            ("CWE-90", "LDAP Injection"),
    "search":                     ("CWE-90", "LDAP Injection"),
    "search_s":                   ("CWE-90", "LDAP Injection"),
    "search_ext":                 ("CWE-90", "LDAP Injection"),
    # XPath Injection — CWE-643
    "tree.xpath":                 ("CWE-643", "XPath Injection (lxml)"),
    "etree.XPath":                ("CWE-643", "XPath Injection (lxml)"),
    "findall":                    ("CWE-643", "XPath Injection (ElementTree)"),
    "findtext":                   ("CWE-643", "XPath Injection (ElementTree)"),
    # Email Header Injection — CWE-93
    "smtplib.SMTP.sendmail":      ("CWE-93", "Email Header Injection"),
    "sendmail":                   ("CWE-93", "Email Header Injection"),
    # XXE — CWE-611
    "lxml.etree.parse":           ("CWE-611", "XML External Entity (XXE) via lxml"),
    "etree.parse":                ("CWE-611", "XML External Entity (XXE) via ElementTree"),
    "etree.fromstring":           ("CWE-611", "XML External Entity (XXE) via ElementTree"),
    "xml.etree.ElementTree.parse":("CWE-611", "XML External Entity (XXE) via ElementTree"),
    "etree.iterparse":            ("CWE-611", "XML External Entity (XXE) via iterparse"),
    "etree.XMLParser":            ("CWE-611", "XML External Entity (XXE) via custom parser"),
    # SSTI — CWE-94/1336
    "jinja2.Environment.from_string":("CWE-94", "Server-Side Template Injection (Jinja2)"),
    "mako.template.Template":     ("CWE-94", "Server-Side Template Injection (Mako)"),
    "django.template.Template":   ("CWE-94", "Server-Side Template Injection (Django)"),
    "django.template.loader.render_to_string":("CWE-94", "Server-Side Template Injection (Django)"),
    # ZipSlip — CWE-22
    "tarfile.extract":            ("CWE-22", "ZipSlip via tarfile extract"),
    "tarfile.extractall":         ("CWE-22", "ZipSlip via tarfile extractall"),
    "zipfile.ZipFile.extract":    ("CWE-22", "ZipSlip via zipfile extract"),
    "zipfile.ZipFile.extractall": ("CWE-22", "ZipSlip via zipfile extractall"),
    "shutil.unpack_archive":      ("CWE-22", "ZipSlip via shutil unpack"),
    # HTTP Response Splitting — CWE-113
    "make_response":              ("CWE-113", "HTTP Response Splitting"),
    "Response":                   ("CWE-113", "HTTP Response Splitting"),
    "redirect":                   ("CWE-601", "Open Redirect"),
}

# ──────────────────────────────────────────────────────────────────────────────
# Sanitizer catalogue — these calls neutralise taint for the listed CWEs
# ──────────────────────────────────────────────────────────────────────────────

SANITIZERS: dict[str, set[str]] = {
    # Command injection sanitizers
    "shlex.quote":                    {"CWE-78"},
    "shlex.split":                    {"CWE-78"},
    "pipes.quote":                    {"CWE-78"},
    # XSS sanitizers
    "bleach.clean":                   {"CWE-79"},
    "markupsafe.escape":              {"CWE-79"},
    "html.escape":                    {"CWE-79"},
    "escape":                         {"CWE-79"},
    "django.utils.html.escape":       {"CWE-79"},
    "nh3.clean":                      {"CWE-79"},
    # Path traversal sanitizers
    "os.path.basename":               {"CWE-22"},
    "secure_filename":                {"CWE-22"},
    "werkzeug.utils.secure_filename": {"CWE-22"},
    "Path.resolve":                   {"CWE-22"},
    "os.path.realpath":               {"CWE-22"},
    "os.path.abspath":                {"CWE-22"},
    "os.path.commonpath":             {"CWE-22"},
    "resolve_path_within_directory":  {"CWE-22"},
    "_resolve_path_within_directory": {"CWE-22"},
    "file_security.resolve_path_within_directory": {"CWE-22"},
    # Deserialization sanitizers
    "json.loads":                     {"CWE-502"},
    "json.load":                      {"CWE-502"},
    "ast.literal_eval":               {"CWE-95"},
    "yaml.safe_load":                 {"CWE-502"},
    "yaml.full_load":                 {"CWE-502"},
    # Type-casting sanitizers (narrow the type, removing injection vectors)
    "int":                            {"CWE-89", "CWE-78", "CWE-95", "CWE-22"},
    "float":                          {"CWE-89", "CWE-78", "CWE-95"},
    "bool":                           {"CWE-89", "CWE-78", "CWE-95"},
    "str.isdigit":                    {"CWE-89", "CWE-78"},
    "str.isalpha":                    {"CWE-89", "CWE-78"},
    "str.isalnum":                    {"CWE-89", "CWE-78"},
    "uuid.UUID":                      {"CWE-89", "CWE-78"},
    # URL validation sanitizers
    "urllib.parse.urlparse":          {"CWE-918", "CWE-601"},
    "urllib.parse.quote":             {"CWE-79", "CWE-601"},
    "urllib.parse.urlencode":         {"CWE-79"},
    "validators.url":                 {"CWE-918"},
    "ipaddress.ip_address":           {"CWE-918"},
    # Regex validation (anchored patterns only — checked at use site)
    "re.match":                       {"CWE-89", "CWE-78", "CWE-22"},
    "re.fullmatch":                   {"CWE-89", "CWE-78", "CWE-22"},
    "re.search":                      {"CWE-89"},
    # Schema validation libraries
    "pydantic.BaseModel":             {"CWE-89", "CWE-78", "CWE-22", "CWE-918"},
    "marshmallow.Schema":             {"CWE-89", "CWE-78", "CWE-22"},
    "cerberus.Validator":             {"CWE-89", "CWE-78"},
    "voluptuous.Schema":              {"CWE-89", "CWE-78"},
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
    # Additional secret patterns
    (r'(?:private_key|PRIVATE_KEY)\s*[=:]\s*["\'][^"\']{20,}["\']',                 "Private key string"),
    (r'(?:api[_-]?secret|client_secret)\s*[=:]\s*["\'][A-Za-z0-9_\-]{8,}["\']',    "API secret / client secret"),
    (r'(?:smtp|email)_(?:password|pass|pwd)\s*[=:]\s*["\'][^"\']{3,}["\']',        "Email/SMTP password"),
    (r'(?:redis|memcached)_(?:url|uri)\s*[=:]\s*["\']redis://[^:]+:[^@]+@',        "Redis connection string with auth"),
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
    # Additional dangerous defaults
    (r'\bSESSION_COOKIE_SECURE\s*=\s*False\b', "SESSION_COOKIE_SECURE=False", "Session cookie sent over HTTP — hijackable via MITM"),
    (r'\bSESSION_COOKIE_HTTPONLY\s*=\s*False\b', "SESSION_COOKIE_HTTPONLY=False", "Session cookie accessible to JavaScript — XSS can steal sessions"),
    (r'\bCSRF_COOKIE_SECURE\s*=\s*False\b', "CSRF_COOKIE_SECURE=False", "CSRF cookie sent over HTTP — token hijackable via MITM"),
    (r'\bCSRF_COOKIE_HTTPONLY\s*=\s*False\b', "CSRF_COOKIE_HTTPONLY=False", "CSRF cookie intentionally HTTP-only disabled"),
    # Insecure SSL/TLS
    (r'\bssl\._create_default_https_context\s*=\s*ssl\._create_unverified_context\b',
                                   "SSL verification monkeypatched", "Global SSL verification disabled — ALL HTTPS requests now vulnerable to MITM"),
    (r'\bcheck_hostname\s*=\s*False\b', "check_hostname=False", "Hostname verification disabled — MITM possible"),
    # Insecure XML parsing (XXE)
    (r'\betree\.(?:parse|fromstring|iterparse)\s*\(', "etree XML parse", "XML parsing without XXE protection — attackers can read local files"),
    (r'\blxml\.etree\.(?:parse|fromstring|XMLParser)\s*\(', "lxml XML parse", "lxml parsing without XXE protection"),
    # Insecure deserialization
    (r'\b(?:pickle\.loads?|cPickle\.loads?|dill\.loads?)\s*\(', "pickle deserialization", "Unsafe deserialization — arbitrary code execution from untrusted data"),
    (r'\byaml\.load\s*\((?!.*Loader\s*=\s*(?:yaml\.)?(?:SafeLoader|CSafeLoader))', "yaml.load without SafeLoader", "yaml.load can instantiate arbitrary Python objects"),
    # Jinja2 SSTI
    (r'\bjinja2\.Environment\s*\(|Template\s*\(|render_template_string\s*\(|flask\.render_template_string\s*\(', "Jinja2 SSTI", "Template rendering with user input — server-side template injection"),
    # Insecure temp files
    (r'\btempfile\.mktemp\s*\(', "insecure temp file", "tempfile.mktemp() is insecure — race condition allows attackers to hijack the filename"),
    # Weak randomness
    (r'\brandom\.(?:random|choice|randint|randrange|shuffle)\s*\(', "insecure random", "random module is not cryptographically secure — predictable values"),
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
        r'(?:jwt\.(?:decode|verify)|(?:decode|verify)\s*\().*(?:algorithms\s*=\s*\[\s*["\']none["\']\s*\]|["\']algorithms["\']\s*:\s*\[\s*["\']none["\']\s*\])',
        "JWT none-algorithm acceptance",
        "JWT verification configuration allows the `none` algorithm. Attackers can forge unsigned tokens.",
        "CWE-347",
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
    # Flask / generic
    "login_required", "require_auth", "auth_required", "jwt_required",
    "token_required", "authenticated", "permission_required",
    "requires_auth", "verify_token", "api_key_required", "requires_login",
    "admin_required", "staff_required", "superuser_required",
    "role_required", "requires_role", "requires_admin",
    "requires_permission",
    # Django
    "login_required", "permission_required", "user_passes_test",
    # Django REST Framework
    "api_view", "permission_classes",
    # FastAPI / Starlette
    "Depends", "Security",
    # Popular libraries
    "flask_login", "HTTPBasicAuth", "HTTPTokenAuth",
    "require_http_methods",
})

_PRIVILEGE_DECORATORS: frozenset[str] = frozenset({
    "admin_required", "staff_required", "superuser_required",
    "role_required", "requires_role", "requires_admin",
    "permission_required", "requires_permission",
    "user_passes_test",
})

# FastAPI auth dependency names — these in function params signal auth is present
_FASTAPI_AUTH_DEPENDS_RE: re.Pattern[str] = re.compile(
    r'get_current_user|current_user|require_auth|oauth2|jwt|token|bearer|'  # noqa: ISC001
    r'verify_token|check_auth|ensure_auth|authenticate|authorized|security|'  # noqa: ISC001
    r'api_key|get_user|check_token|validate_token|login_required|'  # noqa: ISC001
    r'auth_scheme|http_bearer|http_basic|http_digest|HTTPBearer|HTTPBasic',
    re.IGNORECASE,
)

_DJANGO_PERMISSION_CLASS_RE: re.Pattern[str] = re.compile(
    r'IsAuthenticated|IsAdminUser|IsAuthenticatedOrReadOnly|'  # noqa: ISC001
    r'DjangoModelPermissions|TokenHasScope|AllowAny',
    re.IGNORECASE,
)

# Django class-based view mixins that enforce authentication on all methods.
_DJANGO_AUTH_MIXINS: frozenset[str] = frozenset({
    "LoginRequiredMixin",
    "PermissionRequiredMixin",
    "UserPassesTestMixin",
    "AccessMixin",
    "StaffRequiredMixin",
    "SuperuserRequiredMixin",
    # popular third-party equivalents
    "OwnerRequiredMixin",
    "GroupRequiredMixin",
    "RoleRequiredMixin",
})

# FastAPI / Starlette security dependency class names — when assigned to a
# module-level variable and used inside Depends(), the route is authenticated.
_FASTAPI_SECURITY_CLASS_RE: re.Pattern[str] = re.compile(
    r'OAuth2|HTTPBearer|HTTPBasic|HTTPDigest|APIKey|OpenIdConnect|'
    r'OAuth2PasswordBearer|OAuth2AuthorizationCode',
    re.IGNORECASE,
)

_DJANGO_CBV_BASES: frozenset[str] = frozenset({
    "View", "TemplateView", "FormView", "ListView", "DetailView",
    "CreateView", "UpdateView", "DeleteView",
})

_DJANGO_IDOR_CBV_BASES: frozenset[str] = frozenset({
    "DetailView", "UpdateView", "DeleteView",
})

_DJANGO_MUTATING_CBVS: frozenset[str] = frozenset({
    "UpdateView", "DeleteView",
})

_FASTAPI_DEPENDENCY_CALLEES: frozenset[str] = frozenset({"Depends", "Security"})
_FASTAPI_MUTATING_METHODS: frozenset[str] = frozenset({"put", "delete"})

_AUTH_DECORATOR_SKIP_NAMES: frozenset[str] = frozenset({
    "Depends", "Security", "api_view", "permission_classes", "require_http_methods",
})

_CBV_USER_SCOPE_RE: re.Pattern[str] = re.compile(
    r'self\.request\.user|request\.user|current_user|g\.user(?:_id)?|'
    r'self\.kwargs\[["\']user(?:_id)?["\']\]|self\.kwargs\.get\(["\']user(?:_id)?["\']\)',
    re.IGNORECASE,
)

_CBV_FILTER_CALL_RE: re.Pattern[str] = re.compile(r'\bfilter(?:_by)?\s*\(', re.IGNORECASE)


def _class_has_auth_mixin(
    cls: ast.ClassDef,
    class_defs: dict[str, ast.ClassDef] | None,
    visited: set[str] | None = None,
) -> bool:
    """Return True if a class inherits from a Django auth mixin (directly or transitively)."""
    if visited is None:
        visited = set()
    if cls.name in visited:
        return False
    visited.add(cls.name)

    for base in cls.bases:
        name = (
            base.id if isinstance(base, ast.Name)
            else base.attr if isinstance(base, ast.Attribute)
            else None
        )
        if not name:
            continue
        if name in _DJANGO_AUTH_MIXINS:
            return True
        if class_defs and name in class_defs:
            if _class_has_auth_mixin(class_defs[name], class_defs, visited):
                return True
    return False


def _class_inherits_any_base(
    cls: ast.ClassDef,
    class_defs: dict[str, ast.ClassDef] | None,
    candidate_names: set[str] | frozenset[str],
    visited: set[str] | None = None,
) -> bool:
    """Return True when a class inherits from any candidate base directly or transitively."""
    if visited is None:
        visited = set()
    if cls.name in visited:
        return False
    visited.add(cls.name)

    for base in cls.bases:
        name = (
            base.id if isinstance(base, ast.Name)
            else base.attr if isinstance(base, ast.Attribute)
            else None
        )
        if not name:
            continue
        if name in candidate_names:
            return True
        if class_defs and name in class_defs:
            if _class_inherits_any_base(class_defs[name], class_defs, candidate_names, visited):
                return True
    return False


def _node_has_auth_decorator_signal(node: ast.AST) -> bool:
    """Return True when a class or function has an auth-like decorator signal."""
    decorator_list = getattr(node, "decorator_list", ())
    for deco in decorator_list:
        name = _decorator_name(deco)
        if name and name in _AUTH_DECORATORS and name not in _AUTH_DECORATOR_SKIP_NAMES:
            return True
        text = _safe_unparse(deco)
        if "method_decorator" in text:
            for auth_name in (_AUTH_DECORATORS - _AUTH_DECORATOR_SKIP_NAMES):
                if re.search(rf'\b{re.escape(auth_name)}\b', text):
                    return True
    return False


def _fastapi_dep_call_has_auth_signal(node: ast.AST, auth_aliases: set[str]) -> bool:
    """Return True when a Depends/Security call references an auth-like dependency."""
    if not isinstance(node, ast.Call):
        return False
    callee = _decorator_name(node.func)
    if callee not in {"Depends", "Security"}:
        return False
    for arg in node.args:
        if isinstance(arg, ast.Name) and arg.id in auth_aliases:
            return True
        if _FASTAPI_AUTH_DEPENDS_RE.search(_safe_unparse(arg)):
            return True
    for kw in node.keywords:
        if isinstance(kw.value, ast.Name) and kw.value.id in auth_aliases:
            return True
        if _FASTAPI_AUTH_DEPENDS_RE.search(_safe_unparse(kw.value)):
            return True
    return False


def _collect_fastapi_auth_aliases(tree: ast.Module) -> set[str]:
    """Collect symbol names that represent auth/security dependencies in a module."""
    aliases: set[str] = set()

    # Pass 1: scheme/security object aliases (oauth2_scheme = OAuth2PasswordBearer(...)).
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        callee_text = _safe_unparse(node.value.func)
        if not _FASTAPI_SECURITY_CLASS_RE.search(callee_text):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                aliases.add(target.id)

    # Pass 2: dependency provider function aliases (get_current_user, auth_*, etc.).
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        fname = node.name
        if _FASTAPI_AUTH_DEPENDS_RE.search(fname):
            aliases.add(fname)
            continue

        # If the function consumes an auth alias via Depends/Security, it is itself an auth alias.
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is None:
                continue
            if _fastapi_dep_call_has_auth_signal(default, aliases):
                aliases.add(fname)
                break

    return aliases


def _collect_fastapi_guarded_receivers(tree: ast.Module, auth_aliases: set[str]) -> set[str]:
    """Collect FastAPI/APIRouter receiver names configured with auth dependencies."""
    guarded: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        ctor = _decorator_name(node.value.func)
        if ctor not in {"FastAPI", "APIRouter"}:
            continue
        has_auth_dependency = False
        for kw in node.value.keywords:
            if kw.arg != "dependencies" or not isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                continue
            if any(_fastapi_dep_call_has_auth_signal(dep, auth_aliases) for dep in kw.value.elts):
                has_auth_dependency = True
                break
        if not has_auth_dependency:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                guarded.add(target.id)

    # ── Also detect app.include_router(router, dependencies=[Depends(auth)]) ──
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = _safe_unparse(node.func)
        if not callee.endswith(".include_router") or not node.args:
            continue
        router_arg = node.args[0]
        router_name = None
        if isinstance(router_arg, ast.Name):
            router_name = router_arg.id
        elif isinstance(router_arg, ast.Attribute):
            router_name = _safe_unparse(router_arg)
        if not router_name:
            continue
        has_auth_dep = False
        for kw in node.keywords:
            if kw.arg != "dependencies" or not isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                continue
            if any(_fastapi_dep_call_has_auth_signal(dep, auth_aliases) for dep in kw.value.elts):
                has_auth_dep = True
                break
        if has_auth_dep:
            guarded.add(router_name)

    return guarded


def _fastapi_route_has_auth_dependency(
    fnode: ast.FunctionDef | ast.AsyncFunctionDef,
    auth_aliases: set[str] | None = None,
) -> bool:
    """Return True when any function parameter uses a FastAPI Depends/Security call
    that looks like an authentication dependency."""
    aliases = auth_aliases or set()
    for dep_call in _iter_fastapi_dependency_calls(fnode):
        if _fastapi_dep_call_has_auth_signal(dep_call, aliases):
            return True
    for arg in (
        *fnode.args.args,
        *fnode.args.kwonlyargs,
        *([] if fnode.args.vararg is None else [fnode.args.vararg]),
        *([] if fnode.args.kwarg is None else [fnode.args.kwarg]),
    ):
        annotation_text = _safe_unparse(arg.annotation)
        if _FASTAPI_AUTH_DEPENDS_RE.search(annotation_text):
            return True
    # Check default values (positional and keyword-only)
    all_defaults = [*fnode.args.defaults, *fnode.args.kw_defaults]
    for default in all_defaults:
        if default is None:
            continue
        if not isinstance(default, ast.Call):
            continue
        callee_text = _safe_unparse(default.func)
        # Depends(...) or Security(...) with an auth-looking callback
        if callee_text in {"Depends", "Security"}:
            for darg in default.args:
                dep_text = _safe_unparse(darg)
                if _FASTAPI_AUTH_DEPENDS_RE.search(dep_text):
                    return True
            for kw in default.keywords:
                dep_text = _safe_unparse(kw.value)
                if _FASTAPI_AUTH_DEPENDS_RE.search(dep_text):
                    return True
    return False


def _drf_viewfunc_has_auth(fnode: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True when a Django REST framework view has permission_classes with
    a non-trivial permission (anything other than AllowAny)."""
    for deco in fnode.decorator_list:
        if not isinstance(deco, ast.Call):
            continue
        callee = _safe_unparse(deco.func)
        if callee not in {"permission_classes", "api_view"}:
            continue
        for darg in deco.args:
            text = _safe_unparse(darg)
            # AllowAny is explicitly no-auth
            if "AllowAny" in text and "IsAuthenticated" not in text:
                return False
            if _DJANGO_PERMISSION_CLASS_RE.search(text):
                return True
    return False


def _class_has_drf_auth_permission(cls: ast.ClassDef) -> bool:
    """Return True when a DRF class-based view declares authenticated permissions.

    Supports patterns like:
      permission_classes = [IsAuthenticated]
      permission_classes = (IsAuthenticated,)
      permission_classes = [permissions.IsAuthenticated]
    """
    for stmt in cls.body:
        if not isinstance(stmt, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "permission_classes" for target in stmt.targets):
            continue
        value_text = _safe_unparse(stmt.value)
        if "AllowAny" in value_text and "IsAuthenticated" not in value_text:
            return False
        if _DJANGO_PERMISSION_CLASS_RE.search(value_text):
            return True
    return False


def _class_method_named(
    cls: ast.ClassDef,
    method_name: str,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Return a method by name from a class body, if present."""
    for item in cls.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == method_name:
            return item
    return None


def _cbv_http_method_names(cls: ast.ClassDef) -> set[str]:
    """Return HTTP-style method names implemented by a class-based view."""
    return {
        item.name
        for item in cls.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.name in {"get", "post", "put", "patch", "delete"}
    }


def _cbv_get_queryset_method(cls: ast.ClassDef) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Return the `get_queryset` method for a class-based view, if present."""
    return _class_method_named(cls, "get_queryset")


def _queryset_method_has_user_scope(fnode: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True when a queryset-building method scopes results to the current user.
    
    Recognizes patterns like:
    - .filter(owner=self.request.user)
    - .filter(owner_id=self.request.user.id)
    - .filter(User__id=current_user.id)
    - .filter(owner_id__in=[...user...])
    - .all() then .filter() in a chain
    """
    # First check with simple regex for quick path
    text = _safe_unparse(fnode)
    if not text:
        return False
    if _CBV_FILTER_CALL_RE.search(text) and _CBV_USER_SCOPE_RE.search(text):
        return True
    
    # Now check AST for more sophisticated patterns
    for node in ast.walk(fnode):
        # Look for .filter() or .filter_by() calls
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        
        method_name = node.func.attr
        if method_name not in ("filter", "filter_by"):
            continue
        
        # Check keyword arguments for ownership patterns like owner=, owner_id=, user_id=
        for kw in node.keywords:
            if not kw.arg:
                continue
            # Check if kwarg name looks like ownership (owner, owner_id, user_id, User__id, etc.)
            if _OWNERSHIP_RE.search(kw.arg):
                # Check if the value references the current user
                kw_text = _safe_unparse(kw.value)
                if _CBV_USER_SCOPE_RE.search(kw_text) or _PRINCIPAL_REF_RE.search(kw_text):
                    return True
                # Also check for user variable names
                if _PRINCIPAL_ALIAS_NAME_RE.search(kw_text):
                    return True
    
    return False

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
    r'manifest|version|ready|live|liveness|readiness|healthz|'
    r'token|refresh.?token|access.?token|revoke.?token)',
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

_PATH_LIKE_NAME_RE: re.Pattern[str] = re.compile(
    r'(?:^|_)(?:path|paths|file|filename|filepath|dirname|basename|storage|repo|'
    r'package|instance|session_file|output_file|temp_dir|tempfile)(?:$|_)',
    re.IGNORECASE,
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


def _expr_looks_path_like(node: ast.AST | None) -> bool:
    """Return True if the expression name/shape suggests it carries a filesystem path.

    This is intentionally narrow and used only by framework-style CWE-22 heuristics
    to catch path builder helpers that don't flow from an obvious request source.
    """
    if node is None:
        return False
    if isinstance(node, ast.Name):
        return bool(_PATH_LIKE_NAME_RE.search(node.id))
    if isinstance(node, ast.Attribute):
        return bool(_PATH_LIKE_NAME_RE.search(node.attr)) or _expr_looks_path_like(node.value)
    if isinstance(node, ast.Subscript):
        return _expr_looks_path_like(node.value)
    if isinstance(node, ast.Starred):
        return _expr_looks_path_like(node.value)
    if isinstance(node, ast.Call):
        call_name = _get_call_name(node)
        short = call_name.rsplit('.', 1)[-1] if call_name else ''
        if _PATH_LIKE_NAME_RE.search(short):
            return True
        if short in {'join', 'abspath', 'realpath', 'resolve', 'mkstemp', 'gettempdir'}:
            return True
        return any(_expr_looks_path_like(arg) for arg in node.args)
    if isinstance(node, ast.BinOp):
        return _expr_looks_path_like(node.left) or _expr_looks_path_like(node.right)
    if isinstance(node, ast.JoinedStr):
        return any(
            isinstance(v, ast.FormattedValue) and _expr_looks_path_like(v.value)
            for v in node.values
        )
    return False


def _function_has_explicit_path_guard(fnode: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if the function contains clear path-boundary validation."""
    src = ast.dump(fnode, include_attributes=False)
    return bool(re.search(
        r'realpath|abspath|resolve|normpath|commonpath|is_relative_to|basename|'
        r'SuspiciousFileOperation|InvalidSessionKey|startswith',
        src,
        re.IGNORECASE,
    ))


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


_FUNCTION_SUMMARY_BUCKET = "function_summaries_v1"


def _summary_cache_key(code: str, filename: str) -> str:
    """Return a stable cache key for persisted function summaries."""
    return stable_hash(f"{filename}\0{code}")


def _serialise_function_summaries(
    summaries: dict[str, _FunctionTaintSummary],
) -> dict[str, dict[str, Any]]:
    return {
        name: {
            "parameters": list(summary.parameters),
            "tainted_params": list(summary.tainted_params),
            "source": summary.source,
            "source_line": summary.source_line,
            "return_line": summary.return_line,
        }
        for name, summary in summaries.items()
    }


def _deserialise_function_summaries(payload: Any) -> dict[str, _FunctionTaintSummary]:
    if not isinstance(payload, dict):
        return {}
    summaries: dict[str, _FunctionTaintSummary] = {}
    for name, data in payload.items():
        if not isinstance(name, str) or not isinstance(data, dict):
            continue
        summaries[name] = _FunctionTaintSummary(
            parameters=tuple(data.get("parameters", ())),
            tainted_params=tuple(data.get("tainted_params", ())),
            source=str(data.get("source", "")),
            source_line=data.get("source_line"),
            return_line=data.get("return_line"),
        )
    return summaries


def _load_cached_function_summaries(code: str, filename: str) -> dict[str, _FunctionTaintSummary] | None:
    """Load persisted function summaries for the exact file contents, if present."""
    cache_key = _summary_cache_key(code, filename)
    try:
        with SQLiteStore(Path(".ansede") / "cache.db") as store:
            payload = store.get_json(_FUNCTION_SUMMARY_BUCKET, cache_key)
    except Exception:
        return None
    if payload is None:
        return None
    return _deserialise_function_summaries(payload)


def _store_cached_function_summaries(
    code: str,
    filename: str,
    summaries: dict[str, _FunctionTaintSummary],
) -> None:
    """Persist function summaries for the exact file contents."""
    cache_key = _summary_cache_key(code, filename)
    try:
        with SQLiteStore(Path(".ansede") / "cache.db") as store:
            store.set_json(_FUNCTION_SUMMARY_BUCKET, cache_key, _serialise_function_summaries(summaries))
    except Exception:
        return


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


def _collect_function_dependencies(
    func_defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    filename: str,
) -> dict[str, tuple[str, ...]]:
    """Collect intra-file call dependencies for IFDS summary invalidation."""
    known_functions = set(func_defs)
    deps: dict[str, tuple[str, ...]] = {}
    for function_name, fnode in func_defs.items():
        called: set[str] = set()
        for node in ast.walk(fnode):
            if not isinstance(node, ast.Call):
                continue
            callee = _get_local_callee_name(node)
            if callee and callee in known_functions and callee != function_name:
                called.add(f"{filename or '<stdin>'}::{callee}")
        deps[function_name] = tuple(sorted(called))
    return deps


def _resolve_callee_file_for_global_graph(
    global_graph: object,
    *,
    caller_file: str,
    callee_name: str,
) -> str:
    """Resolve callee file path for IFDS propagation with fuzzy fallback."""
    if hasattr(global_graph, "get_function_summary"):
        try:
            summary = global_graph.get_function_summary(caller_file, callee_name)
            if summary is not None and getattr(summary, "file_path", None):
                return str(summary.file_path)
        except Exception:
            pass

    imports = getattr(global_graph, "imports", None)
    normalize_path = getattr(global_graph, "_normalize_path", None)
    if isinstance(imports, dict) and callable(normalize_path):
        try:
            caller_key = (normalize_path(caller_file or "<stdin>"), callee_name)
            targets = imports.get(caller_key, ())
            for target_file, target_symbol in targets:
                if target_symbol == callee_name:
                    return str(target_file)
        except Exception:
            pass

    return caller_file or "<stdin>"


def _call_taint_from_summary(
    node: ast.Call,
    tainted: dict[str, _TaintInfo],
    func_summaries: dict[str, _FunctionTaintSummary],
    visited: set[int] | None = None,
    *,
    global_graph: object | None = None,
    caller_file: str = "",
    caller_name: str = "",
    call_string: tuple[str, ...] = (),
    call_string_k: int = DEFAULT_IFDS_CALL_STRING_K,
) -> _ExprTaintInfo | None:
    """Resolve taint flowing out of a helper call using its function summary."""
    callee = _get_local_callee_name(node)
    summary = func_summaries.get(callee)
    next_call_string = _extend_ifds_call_string(
        call_string,
        caller_file=caller_file,
        caller_name=caller_name,
        callee_name=callee,
        call_line=getattr(node, "lineno", None),
        call_string_k=call_string_k,
    )

    # Prefer the unified GlobalGraph IFDS transfer when available.
    if global_graph is not None and hasattr(global_graph, "propagate_call_facts"):
        callee_file = _resolve_callee_file_for_global_graph(
            global_graph,
            caller_file=caller_file or "<stdin>",
            callee_name=callee,
        )
        tainted_arg_indexes: set[int] = set()
        nested_call_strings: list[tuple[str, ...]] = []
        if summary is not None and summary.parameters:
            arg_map = _map_call_arguments(node, summary.parameters)
            for idx, param in enumerate(summary.parameters):
                arg_node = arg_map.get(param)
                if arg_node is None:
                    continue
                info = _find_tainted_expr_info(
                    arg_node,
                    tainted,
                    func_summaries,
                    visited,
                    global_graph=global_graph,
                    caller_file=caller_file,
                    caller_name=caller_name,
                    call_string=call_string,
                    call_string_k=call_string_k,
                )
                if info:
                    tainted_arg_indexes.add(idx)
                    if info[5]:
                        nested_call_strings.append(info[5])
        else:
            for idx, arg_node in enumerate(node.args):
                info = _find_tainted_expr_info(
                    arg_node,
                    tainted,
                    func_summaries,
                    visited,
                    global_graph=global_graph,
                    caller_file=caller_file,
                    caller_name=caller_name,
                    call_string=call_string,
                    call_string_k=call_string_k,
                )
                if info:
                    tainted_arg_indexes.add(idx)
                    if info[5]:
                        nested_call_strings.append(info[5])

        incoming_call_string = max(nested_call_strings, key=len, default=call_string)

        try:
            sink_hit, sink_trace, ret_hit, return_trace = global_graph.propagate_call_facts(
                caller_file=caller_file or "<stdin>",
                caller_name=caller_name or "<module>",
                callee_file=callee_file,
                callee_name=callee,
                tainted_arg_indexes=tainted_arg_indexes,
                call_line=getattr(node, "lineno", None),
                call_string=incoming_call_string,
                call_string_k=call_string_k,
            )
            if ret_hit:
                src = "interprocedural return taint (global IFDS)"
                trace = return_trace or sink_trace
                trace = _append_trace(trace, "helper", f"through `{callee}()`", node)
                return (f"{callee}()", src, getattr(node, "lineno", 0), set(), trace, next_call_string)
        except Exception:
            pass

    if not summary:
        return None
    if summary.source:
        trace: tuple[TraceFrame, ...] = ()
        if summary.source_line:
            trace = _append_trace(trace, "source", summary.source, line=summary.source_line)
        trace = _append_trace(trace, "helper", f"through `{callee}()`", node)
        return (f"{callee}()", summary.source, getattr(node, "lineno", 0), set(), trace, next_call_string)

    arg_map = _map_call_arguments(node, summary.parameters)
    for param_name in summary.tainted_params:
        arg_node = arg_map.get(param_name)
        if arg_node is None:
            continue
        info = _find_tainted_expr_info(
            arg_node,
            tainted,
            func_summaries,
            visited,
            global_graph=global_graph,
            caller_file=caller_file,
            caller_name=caller_name,
            call_string=call_string,
            call_string_k=call_string_k,
        )
        if info:
            label, src, line, san, trace, nested_call_string = info
            trace = _append_trace(trace, "helper", f"through `{callee}()`", node)
            effective_call_string = nested_call_string or next_call_string
            return (f"{callee}() via `{label}`", src, line, san, trace, effective_call_string)
    return None


def _find_tainted_expr_info(
    node: ast.AST,
    tainted: dict[str, _TaintInfo],
    func_summaries: dict[str, _FunctionTaintSummary],
    visited: set[int] | None = None,
    *,
    global_graph: object | None = None,
    caller_file: str = "",
    caller_name: str = "",
    call_string: tuple[str, ...] = (),
    call_string_k: int = DEFAULT_IFDS_CALL_STRING_K,
) -> _ExprTaintInfo | None:
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
        return (node.id, src, line, san, trace, call_string)

    # Collection element taint: x = tainted_list[i] → x is tainted
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
        if node.value.id in tainted:
            src, line, san, trace = tainted[node.value.id]
            return (node.value.id, src, line, san, trace, call_string)

    # List/tuple literal: [tainted, clean] → result is tainted
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for elt in node.elts:
            info = _find_tainted_expr_info(
                elt,
                tainted,
                func_summaries,
                visited,
                global_graph=global_graph,
                caller_file=caller_file,
                caller_name=caller_name,
                call_string=call_string,
                call_string_k=call_string_k,
            )
            if info:
                return info

    if isinstance(node, ast.expr):
        src = _get_taint_source(node)
        if src:
            label = _safe_unparse(node)[:80] or "untrusted input"
            trace = (_make_trace_frame("source", label, node),)
            return (label, src, getattr(node, "lineno", 0), set(), trace, call_string)

    if isinstance(node, ast.Call):
        summary_info = _call_taint_from_summary(
            node,
            tainted,
            func_summaries,
            visited,
            global_graph=global_graph,
            caller_file=caller_file,
            caller_name=caller_name,
            call_string=call_string,
            call_string_k=call_string_k,
        )
        sanitized_cwes = _get_sanitized_cwes(node)
        if summary_info:
            label, src, line, san, trace, nested_call_string = summary_info
            if sanitized_cwes:
                trace = _append_trace(
                    trace,
                    "sanitizer",
                    f"sanitize via `{_get_call_name(node) or 'call'}`",
                    node,
                )
            return (label, src, line, san | sanitized_cwes, trace, nested_call_string)
        if sanitized_cwes:
            for arg in node.args:
                info = _find_tainted_expr_info(
                    arg,
                    tainted,
                    func_summaries,
                    visited,
                    global_graph=global_graph,
                    caller_file=caller_file,
                    caller_name=caller_name,
                    call_string=call_string,
                    call_string_k=call_string_k,
                )
                if info:
                    trace = _append_trace(
                        info[4],
                        "sanitizer",
                        f"sanitize via `{_get_call_name(node) or 'call'}`",
                        node,
                    )
                    return (info[0], info[1], info[2], info[3] | sanitized_cwes, trace, info[5])
            for kw in node.keywords:
                info = _find_tainted_expr_info(
                    kw.value,
                    tainted,
                    func_summaries,
                    visited,
                    global_graph=global_graph,
                    caller_file=caller_file,
                    caller_name=caller_name,
                    call_string=call_string,
                    call_string_k=call_string_k,
                )
                if info:
                    trace = _append_trace(
                        info[4],
                        "sanitizer",
                        f"sanitize via `{_get_call_name(node) or 'call'}`",
                        node,
                    )
                    return (info[0], info[1], info[2], info[3] | sanitized_cwes, trace, info[5])

    for child in ast.iter_child_nodes(node):
        info = _find_tainted_expr_info(
            child,
            tainted,
            func_summaries,
            visited,
            global_graph=global_graph,
            caller_file=caller_file,
            caller_name=caller_name,
            call_string=call_string,
            call_string_k=call_string_k,
        )
        if info:
            return info
    return None


def _record_function_summaries_in_global_graph(
    global_graph: object,
    *,
    filename: str,
    func_summaries: dict[str, _FunctionTaintSummary],
    summary_dependencies: dict[str, tuple[str, ...]],
) -> None:
    """Publish local Python summaries into the shared GlobalGraph IFDS store."""
    from ansede_static.ir.global_graph import FunctionSummary, IDETaintLevel

    for function_name, summary in func_summaries.items():
        parameters = list(summary.parameters)
        tainted_params = set(summary.tainted_params)
        arg_indexes = tuple(
            idx for idx, param in enumerate(parameters)
            if param in tainted_params
        )
        global_graph.record_function_summary(FunctionSummary(
            file_path=filename or "<stdin>",
            function_name=function_name,
            args_to_sink=arg_indexes,
            args_to_return=arg_indexes,
            return_from_source=bool(summary.source),
            side_effect_symbols=(),
            depends_on=summary_dependencies.get(function_name, ()),
        ))
        # Record IDE lattice facts: functions that return a tainted source value
        # are marked TAINTED so callers can have their confidence adjusted.
        if summary.source and hasattr(global_graph, "set_taint_with_access_path"):
            try:
                global_graph.set_taint_with_access_path(
                    file_path=filename or "<stdin>",
                    function_name=function_name,
                    value_label="$ret",
                    level=IDETaintLevel.TAINTED,
                    sources=(summary.source,),
                )
            except Exception:
                pass
    global_graph.save_summaries()


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


def _code_sans_strings_and_comments(code: str) -> list[str]:
    """
    Return a copy of *code* split into lines with string and comment tokens
    replaced by spaces, preserving line/column positions.

    Used by regex-based heuristic rules that should reason about executable code
    only, not examples, comments, or metadata embedded in the analyzer source.
    """
    rows: list[list[str]] = [list(line) for line in code.splitlines()]
    try:
        for tok in _tokenize.generate_tokens(io.StringIO(code).readline):
            if tok.type not in {_tokenize.STRING, _tokenize.COMMENT}:
                continue
            sr, sc = tok.start
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
        pass
    return ["".join(chars) for chars in rows]


# ──────────────────────────────────────────────────────────────────────────────
# Main detection engine — all 28 rule categories
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class FrameworkFingerprint:
    """Detect which web frameworks a Python source file uses.

    Used to scope route-specific and auth-specific rules to files
    that actually contain framework route definitions, reducing FP
    rate on pure-utility modules.
    """

    flask: bool = False
    fastapi: bool = False
    django: bool = False
    aiohttp: bool = False
    tornado: bool = False
    starlette: bool = False

    # Enhanced fields per Phase 2.3 hardening spec
    detected_framework: str | None = None
    security_decorators: set[str] = field(default_factory=set)

    @property
    def is_web_app(self) -> bool:
        """True if any web framework is detected."""
        return any([self.flask, self.fastapi, self.django,
                    self.aiohttp, self.tornado, self.starlette])

    @classmethod
    def from_source(cls, source: str) -> "FrameworkFingerprint":
        """Scan the first 200 lines for framework import patterns."""
        head = "\n".join(source.splitlines()[:200]).lower()
        return cls(
            flask="from flask" in head or "import flask" in head,
            fastapi="from fastapi" in head or "import fastapi" in head,
            django=(
                "from django" in head or "import django" in head
                or "django.db" in head or "models.model" in head
            ),
            aiohttp="from aiohttp" in head or "import aiohttp" in head,
            tornado="from tornado" in head or "import tornado" in head,
            starlette="from starlette" in head or "import starlette" in head,
        )

    def inspect_ast_node(self, node: ast.AST) -> None:
        """Inspect an AST node for framework import patterns.

        Called during the AST walk to detect framework usage and
        set detected_framework accordingly.
        """
        if isinstance(node, ast.ImportFrom):
            if node.module and "fastapi" in node.module:
                self.detected_framework = "FastAPI"
            elif node.module and "django" in node.module:
                self.detected_framework = "Django"
            elif node.module and "flask" in node.module:
                self.detected_framework = "Flask"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if "fastapi" in alias.name:
                    self.detected_framework = "FastAPI"
                elif "django" in alias.name:
                    self.detected_framework = "Django"
                elif "flask" in alias.name:
                    self.detected_framework = "Flask"

    def verify_endpoint_protection(self, node: ast.FunctionDef) -> bool:
        """Check if a route handler function has authentication protection.

        Returns True if the endpoint has proper auth decorators or
        dependency injection patterns.
        """
        if self.detected_framework == "FastAPI":
            # Check if signature relies on security parameters or Depends tokens
            # Either as annotations (Annotated[str, Depends(...)]) or defaults
            for arg in node.args.args:
                if arg.annotation and "Depends" in ast.dump(arg.annotation):
                    return True
            # Also check kw_defaults and defaults for Depends() calls
            all_defaults = list(node.args.defaults) + list(node.args.kw_defaults)
            for default in all_defaults:
                if default is not None and "Depends" in ast.dump(default):
                    return True
        elif self.detected_framework == "Django":
            # Look up active authentication decorators or mixin class configs
            for decorator in node.decorator_list:
                if "login_required" in ast.dump(decorator):
                    return True
                if "permission_required" in ast.dump(decorator):
                    return True
        elif self.detected_framework == "Flask":
            # Check for @login_required or similar auth decorators
            for decorator in node.decorator_list:
                dumped = ast.dump(decorator)
                if "login_required" in dumped:
                    return True
                if "jwt_required" in dumped:
                    return True
        return False


@dataclass
class _Ctx:
    """Shared context passed to every detection-rule function."""
    lines: list[str]
    sans: list[str]
    sans_comments: list[str]
    func_defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef]
    func_summaries: dict[str, _FunctionTaintSummary]
    _tree: ast.Module = None  # type: ignore[assignment]
    filename: str = ""
    global_graph: object = None
    class_defs: dict[str, ast.ClassDef] = None  # type: ignore[assignment]
    # Maps function object identity → enclosing ClassDef.
    func_to_class: dict[int, ast.ClassDef] = None  # type: ignore[assignment]
    # FastAPI/APIRouter receiver names configured with auth dependencies.
    fastapi_guarded_receivers: set[str] = None  # type: ignore[assignment]
    # FastAPI auth alias names (oauth2_scheme, get_current_user, etc.).
    fastapi_auth_aliases: set[str] = None  # type: ignore[assignment]
    # Framework fingerprint for scope-narrowing route/auth rules.
    framework: FrameworkFingerprint = None  # type: ignore[assignment]


_FRAMEWORK_INTERNAL_PY_MARKERS: tuple[str, ...] = (
    # Benchmark-specific clone paths
    "/django__django/django/",
    "/pallets__flask/src/flask/",
    "/tiangolo__fastapi/fastapi/",
    # Installed site-packages
    "/site-packages/django/",
    "/site-packages/flask/",
    "/site-packages/fastapi/",
    "/site-packages/starlette/",
    # Generic clone patterns — catches campaign repos like py-flask/, js-express/, etc.
    # Match any directory named after the framework containing its source.
    # Broader repo-level patterns catch test files inside framework clones too.
    "/flask/src/flask/",
    "/py-flask/",          # catches tests/, examples/, and src/flask/
    "/django/django/",
    "/py-django/",         # catches tests/, django/, docs/
    "/fastapi/fastapi/",
    "/py-fastapi/",
    "/starlette/starlette/",
    "/py-starlette/",
    "/aiohttp/aiohttp/",
    "/py-aiohttp/",
    "/tornado/tornado/",
    "/py-tornado/",
    "/sanic/sanic/",
    "/py-sanic/",
    "/bottle/bottle/",
    "/py-bottle/",
    "/celery/celery/",
    "/py-celery/",
    "/sqlalchemy/sqlalchemy/",
    "/sqlalchemy/lib/sqlalchemy/",
    "/py-sqlalchemy/",
    "/pydantic/pydantic/",
    "/py-pydantic/",
    "/marshmallow/src/marshmallow/",
    "/py-marshmallow/",
    "/requests/requests/",
    "/py-requests/",
    "/httpx/httpx/",
    "/py-httpx/",
    "/rich/rich/",
    "/py-rich/",
    "/loguru/loguru/",
    "/py-loguru/",
    "/apscheduler/apscheduler/",
    "/py-apscheduler/",
    "/dramatiq/dramatiq/",
    "/py-dramatiq/",
    "/peewee/peewee/",
    "/py-peewee/",
    "/scrapy/scrapy/",
    "/py-scrapy/",
    # JavaScript frameworks
    "/express/lib/",
    "/js-express/",
    "/fastify/lib/",
    "/js-fastify/",
    "/koa/lib/",
    "/js-koa/",
    "/hono/src/",
    "/js-hono/",
    "/axios/lib/",
    "/js-axios/",
    "/lodash/lodash.js",
    "/js-lodash/",
    "/moment/src/",
    "/js-moment/",
    "/socket.io/lib/",
    "/js-socketio/",
    "/cheerio/lib/",
    "/js-cheerio/",
    "/nestjs/core/",
    "/js-nest/",
    # Installed packages
    "/node_modules/express/",
    "/node_modules/fastify/",
    "/node_modules/koa/",
    "/node_modules/axios/",
    "/node_modules/lodash/",
    "/node_modules/moment/",
)

_FRAMEWORK_INTERNAL_PY_NOISE_RULES: frozenset[str] = frozenset({
    "PY-001",  # silent exception swallowing in framework/library internals
    "PY-012",  # pickle.loads in cache/session backends
    "PY-011",  # dangerous defaults (secure=False, httponly=False) in framework plumbing
    "PY-013",  # legacy hash algorithms for backward compatibility
    "PY-022",  # SSRF heuristic
    "PY-023",  # path traversal via join heuristic
    "PY-028",  # CBV missing auth mixin — framework base views intentionally unauthenticated
    "PY-029",  # path traversal via open heuristic
    "PY-030",  # open redirect heuristic
    "PY-035",  # mass assignment in form processing internals
    "PY-045",  # path traversal via open() taint — framework I/O helpers use controlled paths
})

# Rules that are expected noise in test/example/doc files (not framework-specific)
_TEST_FILE_NOISE_RULES: frozenset[str] = frozenset({
    "PY-003",  # CWE-798: hardcoded secrets in test fixtures are expected
    "PY-007",  # CWE-798: hardcoded API keys in test mocks
    "PY-010",  # CWE-327: weak crypto in test vectors is intentional
    "PY-017",  # CWE-338: weak PRNG in test fixtures
})

# Patterns that indicate a file is a test/example/fixture, not production code
_TEST_FILE_PATH_PATTERNS: tuple[str, ...] = (
    "/test/", "/tests/", "/testing/",
    "/test_", "_test.py", "_test.go", "_test.js", "_test.ts",
    "/spec/", "/specs/",
    "/fixture/", "/fixtures/",
    "/mock/", "/mocks/", "/stub/", "/stubs/",
    "/example/", "/examples/", "/demo/", "/demos/",
    "/sample/", "/samples/",
    "/conftest.py", "/conftest.go",
    "/__test__/", "/__tests__/",
    "/testdata/", "/test_data/",
    "/benchmark/", "/benchmarks/",
    "test_util", "test_helper",
)

_FRAMEWORK_INTERNAL_PY_RULE_EXEMPT_PATHS: dict[str, tuple[str, ...]] = {
    # Django cache backends use pickle.loads by design and ARE genuinely vulnerable
    # when cache storage is attacker-controlled; keep CWE-502 at full severity.
    "PY-012": (
        "/django/core/cache/backends/",
    ),
    # Django admin view helpers redirect to request-derived URLs without full
    # allowlist validation; keep CWE-601 at full severity for those files.
    "PY-030": (
        "/django/contrib/admin/options.py",
        "/django/contrib/admin/sites.py",
    ),
}

_FRAMEWORK_INTERNAL_PY_RULE_DOWNGRADE_PATHS: dict[str, tuple[str, ...]] = {
    # Autoreload and similar re-exec helpers intentionally respawn the current
    # process with interpreter-managed argv/environment state; treat these as
    # framework/runtime mechanics rather than app-level command injection.
    "PY-005": (
        "/django/utils/autoreload.py",
        "/django/db/backends/",              # database cloning/cli internals
        "/django/core/management/commands/", # django-admin shell commands
    ),
    # Django auth admin's user_change_password() redirects to request.get_full_path()
    # which is a redirect-to-self for form validation, not an attacker-controllable target.
    "PY-046": (
        "/django/contrib/auth/admin.py",
    ),
    # Flask CLI shell_command() uses eval/compile in developer tooling, not web paths.
    "PY-006": (
        "/flask/cli.py",
    ),
    # Flask CLI open() from PYTHONSTARTUP env var in shell_command().
    "PY-004": (
        "/flask/cli.py",
    ),
    # Django CSRF middleware sets session data — framework session handling, not app.
    "PY-016": (
        "/django/middleware/csrf.py",
    ),
    # Django generic dispatch() uses getattr for HTTP method routing — framework dispatch.
    "PY-036": (
        "/django/views/generic/base.py",
    ),
    # Django DB backend files use raw SQL for schema introspection and database
    # creation — these are not application-level SQL injection vectors.
    "PY-037": (
        "/django/db/backends/",
    ),
    # Django test database creation scripts hardcode test passwords.
    "PY-010": (
        "/django/db/backends/oracle/creation.py",
        "/django/db/backends/mysql/creation.py",
        "/django/contrib/auth/views.py",
    ),
}

_ANSEDE_INTERNAL_PY_MARKERS: tuple[str, ...] = (
    "src/ansede_static/",
    "/src/ansede_static/",
    "site-packages/ansede_static/",
    "/site-packages/ansede_static/",
)

_ANSEDE_INTERNAL_PY_NOISE_RULES: frozenset[str] = frozenset({
    "PY-001",  # deliberate broad-catch containment in scanner/engine internals
    "PY-011",  # rule metadata / examples can mention insecure defaults inline
    "PY-040",  # remediation/examples can mention verify=False inline
    "PY-044",  # analyzer/CLI orchestrators are intentionally branch-heavy
})

_ANSEDE_INTERNAL_PY_RULE_DOWNGRADE_PATHS: dict[str, tuple[str, ...]] = {
    # CLI file operations work on local user-selected artifact paths rather than
    # request-controlled web inputs; keep the heuristic from blocking self-scan.
    "PY-045": (
        "src/ansede_static/cli.py",
        "/src/ansede_static/cli.py",
        "site-packages/ansede_static/cli.py",
        "/site-packages/ansede_static/cli.py",
    ),
}


def _is_framework_internal_python_path(filename: str) -> bool:
    path_norm = filename.replace("\\", "/").lower()
    return any(marker in path_norm for marker in _FRAMEWORK_INTERNAL_PY_MARKERS)


# ── Phase 2.3+ audit fix: auto-detect framework repos at scan time ──────
# Cache of detected framework roots to avoid repeated filesystem checks.
_framework_root_cache: dict[str, bool] = {}


def _detect_framework_root(file_path: str) -> bool:
    """Detect if a file belongs to a known framework/library repository.

    Walks up from the file path looking for framework package metadata
    (setup.py, setup.cfg, pyproject.toml with framework metadata, or
    package.json for JS frameworks). Caches results per directory root.
    """
    import os as _os
    from pathlib import Path as _Path

    try:
        p = _Path(file_path).resolve()
    except (OSError, RuntimeError):
        return False

    # Walk up to find the project root (where setup.py/pyproject.toml/package.json lives)
    for parent in [p.parent, *list(p.parents)[:5]]:
        cache_key = str(parent)
        if cache_key in _framework_root_cache:
            return _framework_root_cache[cache_key]

        # Check for Python framework markers
        setup_py = parent / "setup.py"
        pyproject = parent / "pyproject.toml"

        is_python_framework = False
        if setup_py.exists() or (pyproject.exists() and not (parent / "tests").exists()):
            # Check if the package metadata declares itself as a framework
            try:
                if pyproject.exists():
                    content = pyproject.read_text(encoding="utf-8", errors="replace")[:2000]
                    framework_keywords = [
                        "framework", "web framework", "asgi framework", "wsgi framework",
                        "http server", "routing", "middleware",
                    ]
                    if any(kw in content.lower() for kw in framework_keywords):
                        is_python_framework = True
            except Exception:
                pass

        # Check for JS framework markers
        package_json = parent / "package.json"
        is_js_framework = False
        if package_json.exists():
            try:
                content = package_json.read_text(encoding="utf-8", errors="replace")[:2000]
                framework_keywords = [
                    "framework", "web framework", "router", "middleware",
                    "express", "fastify", "koa", "hono", "connect",
                ]
                if any(kw in content.lower() for kw in framework_keywords):
                    is_js_framework = True
            except Exception:
                pass

        if is_python_framework or is_js_framework:
            _framework_root_cache[cache_key] = True
            return True

    # Not detected as a framework
    for parent in [p.parent, *list(p.parents)[:5]]:
        cache_key = str(parent)
        if cache_key not in _framework_root_cache:
            _framework_root_cache[cache_key] = False

    return False


def _is_test_file(filename: str) -> bool:
    """Return True if the file path indicates test/example/fixture code."""
    path_norm = filename.replace("\\", "/").lower()
    return any(pattern in path_norm for pattern in _TEST_FILE_PATH_PATTERNS)


def _is_ansede_internal_python_path(filename: str) -> bool:
    path_norm = filename.replace("\\", "/").lower()
    return any(marker in path_norm for marker in _ANSEDE_INTERNAL_PY_MARKERS)


def _is_framework_internal_python_noise_exempt(rule_id: str, filename: str) -> bool:
    path_norm = filename.replace("\\", "/").lower()
    return any(fragment in path_norm for fragment in _FRAMEWORK_INTERNAL_PY_RULE_EXEMPT_PATHS.get(rule_id, ()))


def _is_framework_internal_python_noise_path(rule_id: str, filename: str) -> bool:
    path_norm = filename.replace("\\", "/").lower()
    return any(fragment in path_norm for fragment in _FRAMEWORK_INTERNAL_PY_RULE_DOWNGRADE_PATHS.get(rule_id, ()))


def _is_ansede_internal_python_noise_path(rule_id: str, filename: str) -> bool:
    path_norm = filename.replace("\\", "/").lower()
    return any(fragment in path_norm for fragment in _ANSEDE_INTERNAL_PY_RULE_DOWNGRADE_PATHS.get(rule_id, ()))


def _apply_python_noise_policy(findings: list[Finding], filename: str) -> list[Finding]:
    if not filename:
        return findings
    is_framework_internal = _is_framework_internal_python_path(filename)
    # Also check runtime framework detection (Phase 2.3 audit fix)
    if not is_framework_internal:
        is_framework_internal = _detect_framework_root(filename)
    is_ansede_internal = _is_ansede_internal_python_path(filename)
    is_test = _is_test_file(filename)

    if not is_framework_internal and not is_ansede_internal and not is_test:
        return findings

    for finding in findings:
        reason = ""
        # ── Framework-internal noise ────────────────────────────────────
        if is_framework_internal:
            if finding.rule_id in _FRAMEWORK_INTERNAL_PY_NOISE_RULES or _is_framework_internal_python_noise_path(finding.rule_id, filename):
                if _is_framework_internal_python_noise_exempt(finding.rule_id, filename):
                    continue
                reason = "framework-internal implementation heuristic downgraded"
            # Lower confidence on ALL framework-internal findings unless they're
            # in exempt paths (e.g., Django cache backends with real pickle risk)
            elif finding.confidence > 0.5:
                finding.confidence = 0.5

        # ── Test/example/fixture noise ──────────────────────────────────
        if not reason and is_test:
            if finding.rule_id in _TEST_FILE_NOISE_RULES:
                reason = "test-fixture heuristic downgraded"
            elif finding.confidence > 0.6:
                finding.confidence = 0.6  # Test files get lower default confidence

        # ── Ansede internal noise ───────────────────────────────────────
        if not reason and is_ansede_internal:
            if finding.rule_id in _ANSEDE_INTERNAL_PY_NOISE_RULES or _is_ansede_internal_python_noise_path(finding.rule_id, filename):
                reason = "tool-internal implementation heuristic downgraded"

        if not reason:
            continue
        if finding.severity.sort_key < Severity.LOW.sort_key:
            finding.severity = Severity.LOW
        finding.confidence = min(finding.confidence, 0.25)
        if reason not in finding.description:
            finding.description = f"{finding.description} ({reason})"
    return findings


_PY_TAINT_RULE_IDS: dict[str, str] = {
    "CWE-89": "PY-004",
    "CWE-78": "PY-005",
    "CWE-95": "PY-006",
    "CWE-94": "PY-006",
    "CWE-502": "PY-007",
    "CWE-918": "PY-008",
    "CWE-79": "PY-009",
}

_PY_BROKEN_AUTH_RULE_IDS: dict[str, str] = {
    "CWE-287": "PY-014",
    "CWE-345": "PY-015",
    "CWE-347": "PY-015",
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
    # Function-name prefixes/suffixes that imply deliberate exception containment.
    _SAFE_FUNC_PARTS = frozenset({
        "safe_", "try_", "attempt_", "maybe_", "best_effort",
        "_or_none", "_or_default", "_or_else", "_safely", "_silently",
        # Framework internals that legitimately catch broadly
        "_handler", "_callback", "_worker", "_listener",
        "dispatch", "full_dispatch", "wsgi_app", "finalize",
        "make_response", "process_response", "handle_exception",
        "run_wsgi", "run_app", "serve_", "__call__",
        "_get_response", "_handle_", "on_", "event_",
        "middleware", "interceptor", "plugin_",
        "test_", "_test", "mock_", "fixture_",
    })

    for fname, fnode in func_defs.items():
        fname_lower = fname.lower()
        # Skip intentionally-forgiving helpers named with safe prefixes/suffixes.
        if any(part in fname_lower for part in _SAFE_FUNC_PARTS):
            continue

        for child in ast.walk(fnode):
            if not isinstance(child, ast.ExceptHandler):
                continue
            is_broad = child.type is None or (
                isinstance(child.type, ast.Name) and
                child.type.id in ("Exception", "BaseException")
            )
            is_swallowed = all(isinstance(s, (ast.Pass, ast.Continue)) for s in child.body)
            has_raise = any(isinstance(s, ast.Raise) for s in child.body)
            # Handler that logs (even without re-raise) is acceptable — it surfaces the error.
            has_log = any(
                isinstance(s, ast.Expr) and isinstance(s.value, ast.Call) and (
                    (isinstance(s.value.func, ast.Attribute) and
                     s.value.func.attr in ("exception", "error", "warning", "critical", "debug", "info"))
                    or (isinstance(s.value.func, ast.Name) and
                        s.value.func.id in ("print",))
                )
                for s in child.body
            )
            # Handler that returns a fallback constant/None is a deliberate default pattern.
            has_fallback_return = any(
                isinstance(s, ast.Return) and (
                    s.value is None
                    or isinstance(s.value, (ast.Constant, ast.Name, ast.List, ast.Dict, ast.Tuple))
                )
                for s in child.body
            )

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
            elif is_broad and not has_raise and not has_log and not has_fallback_return:
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
                cwe="CWE-252",
            ))

    return _assign_rule_ids(findings, "PY-003")


def _rule_03(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    func_summaries = ctx.func_summaries
    # ── Rule 3: Intra-function taint analysis ────────────────────────────
    # Scoped symbol table: tainted_vars now tracks per-scope entries so that
    # same-name rebinding in nested scopes (comprehensions, inner functions,
    # with-blocks) does not conflate taint across scopes.
    for fname, fnode in func_defs.items():
        tainted_vars: dict[str, _TaintInfo] = {}
        _scope_stack: list[dict[str, _TaintInfo]] = []  # pushed on scope entry, popped on exit
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

        # ── Pre-pass: collect comprehension-scoped variable names ──────────
        # In Python 3, comprehension iteration variables (the `x` in `[x for x in ...]`)
        # are scoped to the comprehension and don't leak to the outer scope.
        # We collect these so the taint tracker skips them (they're fresh bindings).
        _comprehension_scoped: set[str] = set()
        for _node in ast.walk(fnode):
            for _comp in ast.iter_child_nodes(_node):
                if isinstance(_comp, ast.comprehension):
                    if isinstance(_comp.target, ast.Name):
                        _comprehension_scoped.add(_comp.target.id)
                    elif isinstance(_comp.target, (ast.Tuple, ast.List)):
                        for _elt in _comp.target.elts:
                            if isinstance(_elt, ast.Name):
                                _comprehension_scoped.add(_elt.id)

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
                    # Skip comprehension-scoped variables — they're fresh bindings
                    if target.id in _comprehension_scoped and not any(
                        isinstance(p, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                        for p in ast.walk(fnode) if hasattr(p, 'name') and getattr(p, 'name', None) == fname
                    ):
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
                                lam_info = _find_tainted_expr_info(
                                    lam_call_arg,
                                    tainted_vars,
                                    func_summaries,
                                    global_graph=ctx.global_graph,
                                    caller_file=ctx.filename,
                                    caller_name=fname,
                                )
                                if lam_info:
                                    _, lsrc, lline, lsan, ltrace, _ = lam_info
                                    lam_tainted[lam_arg.arg] = (lsrc, lline, lsan, ltrace)
                        lam_result = _find_tainted_expr_info(
                            lam.body,
                            lam_tainted,
                            func_summaries,
                            global_graph=ctx.global_graph,
                            caller_file=ctx.filename,
                            caller_name=fname,
                        )
                        if lam_result:
                            lbl, lsrc2, lline2, lsan2, ltrace2, _ = lam_result
                            tainted_vars[target.id] = (
                                f"lambda result from `{lbl}` ({lsrc2})",
                                lline2,
                                lsan2,
                                _append_trace(ltrace2, "propagator", f"lambda assign to `{target.id}`", line=node.lineno),
                            )
                        continue

                    taint_info = _find_tainted_expr_info(
                        node.value,
                        tainted_vars,
                        func_summaries,
                        global_graph=ctx.global_graph,
                        caller_file=ctx.filename,
                        caller_name=fname,
                    )
                    if not taint_info:
                        # Explicit clean-return / clean-assignment propagation:
                        # if a function return is provably not tainted, overwrite any prior taint
                        # on the target variable instead of leaving stale taint behind.
                        if isinstance(node.value, ast.Call):
                            callee = _get_local_callee_name(node.value)
                            summary = func_summaries.get(callee) if callee else None
                            if summary is not None:
                                arg_map = _map_call_arguments(node.value, summary.parameters)
                                tainted_arg_indexes: set[int] = set()
                                for idx, param in enumerate(summary.parameters):
                                    arg_node = arg_map.get(param)
                                    if arg_node is None:
                                        continue
                                    arg_hit = _find_tainted_expr_info(
                                        arg_node,
                                        tainted_vars,
                                        func_summaries,
                                        global_graph=ctx.global_graph,
                                        caller_file=ctx.filename,
                                        caller_name=fname,
                                    )
                                    if arg_hit:
                                        tainted_arg_indexes.add(idx)

                                return_is_tainted = bool(summary.source)
                                if not return_is_tainted and tainted_arg_indexes:
                                    return_taint_params = {
                                        idx
                                        for idx, param_name in enumerate(summary.parameters)
                                        if param_name in set(summary.tainted_params)
                                    }
                                    return_is_tainted = bool(return_taint_params & tainted_arg_indexes)

                                if not return_is_tainted:
                                    tainted_vars.pop(target.id, None)
                                    continue

                        # Non-tainted assignment should clear previously tainted variable state.
                        tainted_vars.pop(target.id, None)
                        continue
                    label, source_desc, source_line, inherited_san, inherited_trace, _ = taint_info
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
                taint_info = _find_tainted_expr_info(
                    node.value,
                    tainted_vars,
                    func_summaries,
                    global_graph=ctx.global_graph,
                    caller_file=ctx.filename,
                    caller_name=fname,
                )
                if taint_info:
                    label, source_desc, source_line, inherited_san, inherited_trace, _ = taint_info
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
                    if sink == "yaml.load" and _call_uses_safe_yaml_loader(node):
                        continue
                    # ORM query guard: broad "execute" sink often catches
                    # db.session.execute(db.select(...)) which is a safe ORM
                    # expression, not raw SQL. Skip if the first argument
                    # is an ast.Call (likely an ORM expression object).
                    if sink == "execute" and node.args and isinstance(node.args[0], ast.Call):
                        continue
                    # Safe subprocess guard: subprocess.run(["cmd","arg"]) with
                    # list-form args and no shell=True is the safe API form.
                    # Only flag if shell=True is present or args are a string.
                    if sink in ("subprocess.call", "subprocess.run", "subprocess.Popen",
                                 "subprocess.check_call", "subprocess.check_output"):
                        has_shell_true = any(
                            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                            for kw in node.keywords
                        )
                        has_list_args = node.args and isinstance(node.args[0], ast.List)
                        if not has_shell_true and has_list_args:
                            continue  # Safe: list-form args without shell=True
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
                        # Deep-audit improvement: if the SQL string itself uses
                        # ? or %s placeholders and there are parameter args,
                        # the query IS parameterized — mark the first arg safe too.
                        if node.args and len(node.args) > 1:
                            first_arg = node.args[0]
                            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                                sql_text = first_arg.value
                                if "?" in sql_text or "%s" in sql_text:
                                    safe_params.add(first_arg)

                    all_args = node.args + [kw.value for kw in node.keywords]
                    for arg_node in all_args:
                        hit = _find_tainted_expr_info(
                            arg_node,
                            tainted_vars,
                            func_summaries,
                            global_graph=ctx.global_graph,
                            caller_file=ctx.filename,
                            caller_name=fname,
                        )
                        if not hit:
                            continue
                        if arg_node in safe_params:
                            continue
                        
                        vname, vsrc, vline, san_cwes, trace, _ = hit
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
        if re.search(r'config\.|\.get\s*\(\s*["\']', line_text):
            continue  # skip config lookups (not hardcoded)
        if re.search(r'\{[^}]*\}', line_text) and re.search(r'(?:api_key|token|secret|password)\s*[:=]', line_text, re.IGNORECASE):
            continue  # skip template/f-string interpolations (variable reference, not hardcoded)
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
    sans = ctx.sans_comments
    lines = ctx.lines
    # ── Rule 5: Dangerous defaults ───────────────────────────────────────
    # Track whether we're inside an `if __name__ == "__main__":` block
    in_main_block = False
    main_indent = -1
    for lineno, line_text in enumerate(sans, 1):  # use string-blanked lines
        raw_line = lines[lineno - 1] if lineno <= len(lines) else ""
        stripped = raw_line.strip()
        # Track entry/exit of __main__ blocks
        if re.match(r'if\s+__name__\s*==\s*["\']__main__["\']\s*:', stripped):
            in_main_block = True
            main_indent = len(raw_line) - len(raw_line.lstrip())
            continue
        if in_main_block and stripped and not stripped.startswith("#"):
            current_indent = len(raw_line) - len(raw_line.lstrip())
            if current_indent <= main_indent:
                in_main_block = False
        if line_text.strip().startswith("#"):
            continue
        for pattern, label, desc in DANGEROUS_DEFAULTS:
            if re.search(pattern, line_text, re.IGNORECASE):
                # Skip debug=True inside if __name__ == "__main__" — legitimate for local dev
                if label == "debug=True" and in_main_block:
                    continue
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
    # ── Rule 6: Unsafe deserialization + code execution ──────────────────
    for lineno, line_text in enumerate(sans, 1):  # use string-blanked lines
        if line_text.strip().startswith("#"):
            continue
        for pattern, desc, cwe, sev in [
            (r'pickle\.loads?\(', "pickle deserialization", "CWE-502", Severity.CRITICAL),
            (r'marshal\.loads?\(', "marshal deserialization", "CWE-502", Severity.CRITICAL),
            (r'yaml\.load\((?!.*Loader\s*=\s*(?:yaml\.)?(?:C?SafeLoader))', "yaml.load without SafeLoader", "CWE-502", Severity.CRITICAL),
            (r'\bexec\s*\(', "exec() code execution", "CWE-94", Severity.CRITICAL),
        ]:
            if re.search(pattern, line_text):
                title = f"{cwe}: Unsafe {desc} at line {lineno}" if "deserialization" in desc else f"{cwe}: Unsafe {desc} at line {lineno}"
                findings.append(Finding(
                    category="security", severity=sev,
                    title=title,
                    description=(
                        f"Unsafe {desc} at L{lineno}: `{line_text.strip()[:80]}`. "
                        "If the data comes from an untrusted source, this can lead to code execution."
                    ),
                    line=lineno,
                    suggestion="Avoid using this pattern with untrusted data. Use safer alternatives.",
                    cwe=cwe, agent="python-analyzer",
                ))
                break

    return _assign_rule_ids(findings, "PY-012")


def _rule_07(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    lines = ctx.lines
    sans = ctx.sans
    # ── Rule 7: Weak cryptographic hashing ─────────────────────────────
    for lineno, line_text in enumerate(sans, 1):  # string-blanked
        if line_text.strip().startswith("#"):
            continue
        m = re.search(r'hashlib\.(md5|sha1|sha224)\(', line_text)
        if m:
            ctx_start = max(0, lineno - 5)
            context = "\n".join(lines[ctx_start:lineno])
            algo = m.group(1).upper()
            # Fire CRITICAL near password/credential context
            if re.search(r'password|passwd|pwd|credential|secret|token', context, re.IGNORECASE):
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
            else:
                # Fire MEDIUM for standalone weak crypto use
                findings.append(Finding(
                    category="security", severity=Severity.MEDIUM,
                    title=f"CWE-327: Weak cryptographic hash ({algo}) at line {lineno}",
                    description=(
                        f"`{algo}` is cryptographically broken at L{lineno}. "
                        f"Use SHA-256 or SHA-3 instead for any security-sensitive hashing."
                    ),
                    line=lineno,
                    suggestion="Replace with `hashlib.sha256()` or `hashlib.sha3_256()`. For passwords, use bcrypt/argon2.",
                    cwe="CWE-327", agent="python-analyzer",
                ))

    return _assign_rule_ids(findings, "PY-013")


def _rule_08(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    raw_lines = ctx.lines
    # ── Rule 8: Broken authentication patterns ────────────────────────────
    # Use raw lines (not string-blanked) so patterns like algorithms=["none"] are visible
    for lineno, line_text in enumerate(raw_lines, 1):
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

# Unambiguous ORM / IO mutation method names — always a mutation regardless of receiver.
_MUTATION_CALLS_UNAMBIGUOUS: frozenset[str] = frozenset({
    "commit", "add", "save", "delete", "insert", "execute",
    "bulk_create", "bulk_update", "create",
    # File / IO
    "write", "send", "send_message", "publish",
    # Session/auth
    "set_cookie", "delete_cookie",
})

# Ambiguous method names that are only ORM mutations when called on ORM-like receivers
# (e.g. session.update(...) is a mutation; results.update({}) is a plain dict op).
_MUTATION_CALLS_AMBIGUOUS: frozenset[str] = frozenset({"update"})

# Deprecated alias kept for backwards-compat with external callers (union of both sets).
_MUTATION_CALLS: frozenset[str] = _MUTATION_CALLS_UNAMBIGUOUS | _MUTATION_CALLS_AMBIGUOUS

# Receiver names that indicate an ORM / DB / session object (for ambiguous mutation check).
_ORM_RECEIVER_RE: re.Pattern[str] = re.compile(
    r'^(?:session|db|database|orm|queryset|objects|cursor|conn|connection|engine|'
    r'manager|repo|repository|store|storage|tx|transaction|client)$',
    re.IGNORECASE,
)

_MUTATION_ATTR_PAT: re.Pattern[str] = re.compile(
    r'session\[|redirect\(|abort\(|flash\(', re.IGNORECASE,
)


def _body_has_mutation(fnode: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if the function body contains state-mutating calls.

    Walks only the function *body* statements (not default-value expressions) to
    avoid false positives from FastAPI Path()/Query() parameter defaults that are
    unrelated to actual state mutation in the handler.
    """
    for stmt in fnode.body:
        for node in ast.walk(stmt):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Attribute):
                attr = node.func.attr
                if attr in _MUTATION_CALLS_UNAMBIGUOUS:
                    return True
                if attr in _MUTATION_CALLS_AMBIGUOUS:
                    # Only treat as mutation when called on an ORM-like receiver.
                    recv = node.func.value
                    recv_name = (
                        recv.id if isinstance(recv, ast.Name)
                        else recv.attr if isinstance(recv, ast.Attribute)
                        else ""
                    )
                    if recv_name and _ORM_RECEIVER_RE.search(recv_name):
                        return True
            elif isinstance(node.func, ast.Name):
                if node.func.id in _MUTATION_CALLS_UNAMBIGUOUS:
                    return True
    # Also check the legacy pattern-based signals (redirect, session[...], etc.)
    for stmt in fnode.body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call_src = _safe_unparse(node.value)
                if _MUTATION_ATTR_PAT.search(call_src):
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


def _call_uses_safe_yaml_loader(node: ast.Call) -> bool:
    """Return True when yaml.load(...) explicitly uses a safe YAML loader."""
    call_src = _safe_unparse(node)
    if not call_src or "yaml.load" not in call_src:
        return False
    return bool(re.search(r"Loader\s*=\s*(?:yaml\.)?(?:C?SafeLoader)\b", call_src))


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


def _idor_resource_names(
    fnode: ast.FunctionDef | ast.AsyncFunctionDef,
    func_summaries: dict[str, _FunctionTaintSummary] | None = None,
) -> set[str]:
    """Return ID-like names that can identify a resource in IDOR-style lookups."""
    names = set(_route_resource_names(fnode))
    summaries = func_summaries or {}
    source_vars: dict[str, str] = {}
    ordered_assignments: list[ast.Assign | ast.AnnAssign] = []

    for node in ast.walk(fnode):
        if isinstance(node, ast.Assign) and node.value is not None:
            ordered_assignments.append(node)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            ordered_assignments.append(node)

    ordered_assignments.sort(key=lambda node: getattr(node, "lineno", 0))

    for node in ordered_assignments:
        if isinstance(node, ast.Assign):
            targets = [target for target in node.targets if isinstance(target, ast.Name)]
            value = node.value
        else:
            targets = [node.target] if isinstance(node.target, ast.Name) else []
            value = node.value

        if value is None or not targets:
            continue

        src = _get_taint_source(value) or _expr_has_direct_source(value, source_vars, summaries)
        if src is None and isinstance(value, ast.Call):
            callee = _get_local_callee_name(value)
            summary = summaries.get(callee)
            if summary is not None and summary.source:
                src = summary.source

        if src is None:
            continue

        for target in targets:
            source_vars[target.id] = src
            if _ID_LIKE_NAME_RE.search(target.id):
                names.add(target.id)

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
    """Return True when a route/function looks administrative or privileged.
    
    Checks function/path names, route decorators, and explicit privilege decorators.
    """
    # Check function name
    if _PRIVILEGED_ENDPOINT_PAT.search(fnode.name):
        return True
    
    # Check route path patterns
    if any(_PRIVILEGED_ENDPOINT_PAT.search(path) for path in _route_paths(fnode)):
        return True
    
    # Check for explicit privilege decorators like @admin_required, @require_admin, @requires_role('admin'), etc.
    for deco in fnode.decorator_list:
        deco_name = _decorator_name(deco)
        if deco_name and _PRIVILEGE_CHECK_PAT.search(deco_name):
            return True
        deco_text = _safe_unparse(deco)
        # Check for @require_role('admin'), @requires_permission('admin'), etc.
        if re.search(r'@(?:require|requires)(?:_role|_permission|_admin)', deco_text, re.IGNORECASE):
            return True
        if re.search(r'\badmin(?:_required)?\b', deco_text, re.IGNORECASE):
            return True
    
    return False


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


def _fastapi_route_methods(fnode: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Return the declared HTTP methods for a FastAPI-style route function."""
    methods: set[str] = set()
    for deco in _iter_route_decorators(fnode):
        if isinstance(deco.func, ast.Attribute) and deco.func.attr != "route":
            methods.add(deco.func.attr.lower())
        for kw in deco.keywords:
            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                for elt in kw.value.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        methods.add(elt.value.lower())
    return methods


def _fastapi_route_receivers(fnode: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Return the receiver names used by route decorators (e.g. `app`, `router`)."""
    receivers: set[str] = set()
    for deco in _iter_route_decorators(fnode):
        func = deco.func
        if not isinstance(func, ast.Attribute):
            continue
        receiver = func.value
        if isinstance(receiver, ast.Name):
            receivers.add(receiver.id)
        elif isinstance(receiver, ast.Attribute):
            receivers.add(receiver.attr)
    return receivers


def _fastapi_route_is_receiver_guarded(
    fnode: ast.FunctionDef | ast.AsyncFunctionDef,
    guarded_receivers: set[str],
) -> bool:
    """Return True when the route receiver is configured with auth dependencies."""
    return bool(_fastapi_route_receivers(fnode) & guarded_receivers)


def _annotation_fastapi_dependency_calls(annotation: ast.AST | None) -> tuple[ast.Call, ...]:
    """Return Depends/Security calls nested inside annotations like Annotated[..., Depends(dep)]."""
    if annotation is None:
        return ()
    dep_calls: list[ast.Call] = []
    for node in ast.walk(annotation):
        if isinstance(node, ast.Call) and _decorator_name(node.func) in _FASTAPI_DEPENDENCY_CALLEES:
            dep_calls.append(node)
    return tuple(dep_calls)


def _iter_fastapi_dependency_calls(
    fnode: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[ast.Call, ...]:
    """Return Depends/Security calls attached to a FastAPI-style route."""
    dep_calls: list[ast.Call] = []
    for default in [*fnode.args.defaults, *fnode.args.kw_defaults]:
        if isinstance(default, ast.Call) and _decorator_name(default.func) in _FASTAPI_DEPENDENCY_CALLEES:
            dep_calls.append(default)
    for arg in (
        *fnode.args.args,
        *fnode.args.kwonlyargs,
        *([] if fnode.args.vararg is None else [fnode.args.vararg]),
        *([] if fnode.args.kwarg is None else [fnode.args.kwarg]),
    ):
        dep_calls.extend(_annotation_fastapi_dependency_calls(arg.annotation))
    for deco in _iter_route_decorators(fnode):
        for kw in deco.keywords:
            if kw.arg != "dependencies" or not isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                continue
            for dep in kw.value.elts:
                if isinstance(dep, ast.Call) and _decorator_name(dep.func) in _FASTAPI_DEPENDENCY_CALLEES:
                    dep_calls.append(dep)
    return tuple(dep_calls)


def _fastapi_dependency_callback_labels(dep_call: ast.Call) -> tuple[str, ...]:
    """Return human-readable callback labels referenced by a Depends/Security call."""
    labels: list[str] = []
    for value in [*dep_call.args, *(kw.value for kw in dep_call.keywords)]:
        text = _safe_unparse(value)
        if text and text not in labels:
            labels.append(text)
    return tuple(labels)


def _fastapi_dependency_call_has_auth_provider(
    dep_call: ast.Call,
    func_defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    auth_aliases: set[str],
) -> bool:
    """Return True when a Depends/Security call ultimately resolves to an auth provider."""
    if _fastapi_dep_call_has_auth_signal(dep_call, auth_aliases):
        return True

    for label in _fastapi_dependency_callback_labels(dep_call):
        short = label.rsplit('.', 1)[-1]
        if short in auth_aliases or _FASTAPI_AUTH_DEPENDS_RE.search(short):
            return True
        provider = func_defs.get(short)
        if provider is None:
            continue
        if _FASTAPI_AUTH_DEPENDS_RE.search(_safe_unparse(provider)):
            return True
        for child in ast.walk(provider):
            if isinstance(child, ast.Call):
                if _fastapi_dep_call_has_auth_signal(child, auth_aliases):
                    return True
                if _FASTAPI_AUTH_DEPENDS_RE.search(_safe_unparse(child)):
                    return True
    return False


def _fastapi_route_has_only_non_auth_dependencies(
    fnode: ast.FunctionDef | ast.AsyncFunctionDef,
    func_defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    auth_aliases: set[str],
    guarded_receivers: set[str],
) -> bool:
    """Return True when a FastAPI route uses Depends/Security but none of them look auth-related."""
    if _fastapi_route_is_receiver_guarded(fnode, guarded_receivers):
        return False
    dep_calls = _iter_fastapi_dependency_calls(fnode)
    if not dep_calls:
        return False
    return not any(
        _fastapi_dependency_call_has_auth_provider(dep, func_defs, auth_aliases)
        for dep in dep_calls
    )


def _fastapi_mutating_route_missing_dependencies(
    fnode: ast.FunctionDef | ast.AsyncFunctionDef,
    guarded_receivers: set[str],
) -> bool:
    """Return True when a FastAPI PUT/DELETE route has no Depends/Security hooks at all."""
    if _fastapi_route_is_receiver_guarded(fnode, guarded_receivers):
        return False
    methods = _fastapi_route_methods(fnode)
    if not methods.intersection(_FASTAPI_MUTATING_METHODS):
        return False
    return not _iter_fastapi_dependency_calls(fnode)


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
        resource_names = _idor_resource_names(fnode, ctx.func_summaries)
        route_methods: set[str] = set()
        route_path = ""
        for deco in fnode.decorator_list:
            if isinstance(deco, ast.Call) and isinstance(deco.func, ast.Attribute):
                attr = deco.func.attr
                if attr in _FLASK_ROUTE_ATTRS:
                    has_route = True
                    receiver_name = deco.func.value.id if isinstance(deco.func.value, ast.Name) else ""
                    if (
                        not has_auth
                        and receiver_name
                        and ctx.fastapi_guarded_receivers is not None
                        and receiver_name in ctx.fastapi_guarded_receivers
                    ):
                        has_auth = True
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
                        if (
                            kw.arg == "dependencies"
                            and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set))
                            and any(
                                _fastapi_dep_call_has_auth_signal(dep, ctx.fastapi_auth_aliases or set())
                                for dep in kw.value.elts
                            )
                        ):
                            has_auth = True
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

        # FastAPI Depends() / Security() dependency injection as auth signal
        if not has_auth and _fastapi_route_has_auth_dependency(fnode, ctx.fastapi_auth_aliases or set()):
            has_auth = True

        # Django REST Framework permission_classes decorator
        if not has_auth and _drf_viewfunc_has_auth(fnode):
            has_auth = True

        # Django class-based view: auth mixin on enclosing class
        if not has_auth and ctx.func_to_class is not None:
            enclosing = ctx.func_to_class.get(id(fnode))
            if enclosing is not None and (
                _class_has_auth_mixin(enclosing, ctx.class_defs)
                or _class_has_drf_auth_permission(enclosing)
            ):
                has_auth = True

        # FastAPI-style resource ID: {item_id} or {id} in path string
        if not has_resource_id and route_path:
            if re.search(r'\{[^}]*(?:id|uid|pk|slug)[^}]*\}', route_path, re.IGNORECASE):
                has_resource_id = True

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
                + (" It is on an `/admin` path — critical privilege-escalation risk." if is_admin else "")
                + " Missing: `@login_required` or equivalent."
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
        r'^(?:requests?|session|client|http|aiohttp|httpx|api_?client|conn|transport|agent)$',
        re.IGNORECASE,
    )
    _ssrf_sus_names = {
        "url","callback_url","webhook_url","endpoint","target","redirect_url",
        "next","dest","destination","host","location","callback","return_url",
    }
    for fname, fnode in func_defs.items():
        # Skip SSRF detection in test functions — test clients (client.get(url))
        # are not exploitable server-side
        if fname.startswith("test_"):
            continue
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
                        else:
                            tainted_ssrf.discard(t.id)
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
                    is_tainted = url_arg.id in tainted_ssrf
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
    func_summaries = ctx.func_summaries
    global_graph = getattr(ctx, "global_graph", None)
    filename = getattr(ctx, "filename", "")
    call_string_k = getattr(ctx, "call_string_k", DEFAULT_IFDS_CALL_STRING_K)
    # ── Rule 15: Path traversal — os.path.join with unsanitized variable ──
    for fname, fnode in func_defs.items():
        if fname.lower() == "safe_join" or _function_has_explicit_path_guard(fnode):
            continue
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
            for arg in node.args:
                var_name = None
                if isinstance(arg, ast.Constant):
                    continue
                info = _find_tainted_expr_info(
                    arg,
                    {},
                    func_summaries,
                    global_graph=global_graph,
                    caller_file=filename,
                    caller_name=fname,
                    call_string=(fname,),
                    call_string_k=call_string_k,
                )
                if isinstance(arg, ast.Name):
                    var_name = arg.id
                elif isinstance(arg, ast.Attribute):
                    var_name = arg.attr
                elif isinstance(arg, ast.Subscript):
                    var_name = "subscript"
                elif isinstance(arg, ast.Call):
                    var_name = _get_call_name(arg).rsplit('.', 1)[-1] or "call result"
                elif isinstance(arg, ast.BinOp):
                    var_name = "composed path"
                elif isinstance(arg, ast.Starred):
                    inner = arg.value
                    if isinstance(inner, ast.Name):
                        var_name = inner.id
                    else:
                        var_name = "starred path parts"
                is_risky = False
                if info and "CWE-22" not in info[3]:
                    var_name = var_name or info[0] or "tainted path input"
                    is_risky = True
                if var_name and var_name not in sanitized_paths:
                    is_risky = is_risky or var_name in tainted_paths or _expr_looks_path_like(arg)
                if is_risky:
                    findings.append(Finding(
                        category="security", severity=Severity.HIGH,
                        title=f"CWE-22: Path traversal in {fname}() via os.path.join()",
                        description=(
                            f"`{fname}()` passes `{var_name}` (dynamic/path-like input) "
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
        resource_names = _idor_resource_names(fnode, ctx.func_summaries)
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
                cwe="CWE-1120",
            ))

    return _assign_rule_ids(findings, "PY-044")


# ──────────────────────────────────────────────────────────────────────────────
# P0: Rule 21 — CWE-22: Path traversal via open()/Path.read_text() with tainted arg
# ──────────────────────────────────────────────────────────────────────────────

def _rule_21(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    func_summaries = ctx.func_summaries
    global_graph = getattr(ctx, "global_graph", None)
    filename = getattr(ctx, "filename", "")
    call_string_k = getattr(ctx, "call_string_k", DEFAULT_IFDS_CALL_STRING_K)
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
                info = _find_tainted_expr_info(
                    arg,
                    {},
                    func_summaries,
                    global_graph=global_graph,
                    caller_file=filename,
                    caller_name=fname,
                    call_string=(fname,),
                    call_string_k=call_string_k,
                )
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
                elif isinstance(arg, ast.Call):
                    callee = _get_call_name(arg)
                    short = callee.rsplit('.', 1)[-1] if callee else 'helper result'
                    if _expr_looks_path_like(arg):
                        is_tainted = True
                        var_name = short or "path helper"
                elif isinstance(arg, ast.Attribute):
                    if _expr_looks_path_like(arg):
                        is_tainted = True
                        var_name = arg.attr

                if info and "CWE-22" not in info[3]:
                    is_tainted = True
                    var_name = info[0] or var_name

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

    return _assign_rule_ids(findings, "PY-045")


# ──────────────────────────────────────────────────────────────────────────────
# P0: Rule 22 — CWE-601: Open Redirect via redirect() with user-controlled URL
# ──────────────────────────────────────────────────────────────────────────────

def _rule_22(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    _redirect_fns = {"redirect", "HttpResponseRedirect"}
    _safe_redirect_fns = {"url_for", "safe_redirect", "is_safe_url", "url_has_allowed_host_and_scheme", "reverse"}
    # Framework self-referential redirects: redirect(request.path) and
    # HttpResponseRedirect(request.get_full_path()) are redirect-to-self after
    # form validation — not attacker-controllable targets.
    _SELF_REDIRECT_VARS: frozenset[str] = frozenset({
        "request.path", "request.get_full_path", "request.build_absolute_uri",
    })
    _SELF_REDIRECT_RE = re.compile(
        r'(?:request\.path|request\.get_full_path\s*\(|request\.build_absolute_uri\s*\()',
        re.IGNORECASE,
    )
    for fname, fnode in func_defs.items():
        tainted_vars: set[str] = set()
        validated_vars: set[str] = set()
        canonical_redirect_vars: set[str] = set()
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
                            if cn and "get_absolute_url" in cn:
                                canonical_redirect_vars.add(t.id)
                                continue
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
                if url_arg.id in canonical_redirect_vars:
                    continue
                is_tainted = url_arg.id in tainted_vars and url_arg.id not in validated_vars
            elif isinstance(url_arg, ast.Call):
                cn = _get_call_name(url_arg)
                if cn and "get_absolute_url" in cn:
                    continue
                if cn and any(sf in cn for sf in _safe_redirect_fns):
                    continue  # redirect(url_for(...)) is safe
                is_tainted = _is_tainted_expr(url_arg, {v: None for v in tainted_vars})
                var_name = "expression"
            elif isinstance(url_arg, (ast.JoinedStr, ast.BinOp)):
                expr = ast.unparse(url_arg) if hasattr(ast, "unparse") else ""
                if "get_absolute_url" in expr or ("object_domain" in expr and "absurl" in expr):
                    continue
                is_tainted = _is_tainted_expr(url_arg, {v: None for v in tainted_vars})
                var_name = "interpolated URL"
            elif isinstance(url_arg, ast.Subscript):
                is_tainted = _is_tainted_expr(url_arg, {v: None for v in tainted_vars})
                var_name = "subscript"
            if not is_tainted:
                continue
            # ── Framework semantic: redirect-to-self is safe ──────────
            # redirect(request.path) after form validation is NOT an open redirect.
            # The user is sent back to the page they came from, which is always
            # the same application.
            if isinstance(url_arg, ast.Call) and _SELF_REDIRECT_RE.search(ast.unparse(url_arg) if hasattr(ast, "unparse") else ""):
                continue
            if isinstance(url_arg, ast.Attribute):
                attr_chain = _get_call_name(url_arg)
                if attr_chain and any(sv in attr_chain for sv in _SELF_REDIRECT_VARS):
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

    return _assign_rule_ids(findings, "PY-046")


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

    return _assign_rule_ids(findings, "PY-047")


# ──────────────────────────────────────────────────────────────────────────────
# P1: Rule 24 — CWE-798: JWT signing with hardcoded short secret
# ──────────────────────────────────────────────────────────────────────────────

def _rule_24(ctx: _Ctx) -> list[Finding]:
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    _jwt_sign_fns = {"encode", "sign"}
    _jwt_obj_names = {"jwt", "pyjwt", "jose", "jwk"}

    # ── Pre-compute module-level hardcoded vars ONCE ─────────────────
    module_hardcoded: dict[str, tuple[str, int]] = {}
    for node in ast.walk(ctx._tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and isinstance(node.value, ast.Constant):
                    if isinstance(node.value.value, str) and 2 <= len(node.value.value) <= 64:
                        module_hardcoded[t.id] = (node.value.value, node.lineno)

    for fname, fnode in func_defs.items():
        # Collect variables that hold short hardcoded string values
        hardcoded_vars: dict[str, tuple[str, int]] = dict(module_hardcoded)
        for node in ast.walk(fnode):
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

    return _assign_rule_ids(findings, "PY-048")


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


def _rule_36(ctx: _Ctx) -> list[Finding]:
    """CWE-862: Django CBV get/post methods without auth-enforcing mixins or decorators."""
    if not (ctx.framework and ctx.framework.django):
        return []
    findings: list[Finding] = []

    for cls in (ctx.class_defs or {}).values():
        if not _class_inherits_any_base(cls, ctx.class_defs, _DJANGO_CBV_BASES):
            continue
        if _class_inherits_any_base(cls, ctx.class_defs, _DJANGO_IDOR_CBV_BASES):
            continue
        method_names = _cbv_http_method_names(cls) & {"get", "post"}
        if not method_names:
            continue
        if (
            _class_has_auth_mixin(cls, ctx.class_defs)
            or _class_has_drf_auth_permission(cls)
            or _node_has_auth_decorator_signal(cls)
        ):
            continue
        if any(
            method is not None and _node_has_auth_decorator_signal(method)
            for method in (_class_method_named(cls, name) for name in method_names)
        ):
            continue

        method_list = ", ".join(sorted(method_names))
        trace: tuple[TraceFrame, ...] = ()
        trace = _append_trace(trace, "source", f"class-based view `{cls.name}`", line=cls.lineno)
        trace = _append_trace(trace, "gap", "no LoginRequiredMixin/PermissionRequiredMixin or auth method_decorator", line=cls.lineno)
        trace = _append_trace(trace, "sink", f"CBV methods `{method_list}` exposed without auth", line=cls.lineno)
        findings.append(Finding(
            category="security", severity=Severity.HIGH,
            title=f"CWE-862: Django CBV `{cls.name}` exposes {method_list} with no auth mixin",
            description=(
                f"`{cls.name}` implements `{method_list}` but does not inherit an auth-enforcing mixin "
                f"and has no `@method_decorator(login_required)` / permission decorator. "
                f"Class-based view methods can be reached without authentication."
            ),
            line=cls.lineno,
            suggestion=(
                "Add `LoginRequiredMixin` / `PermissionRequiredMixin`, or protect dispatch/methods with "
                "`@method_decorator(login_required, name='dispatch')`."
            ),
            cwe="CWE-862", agent="python-analyzer",
            confidence=0.91,
            analysis_kind="decorator-heuristic",
            trace=trace,
        ))

    return _assign_rule_ids(findings, "PY-028")


def _rule_37(ctx: _Ctx) -> list[Finding]:
    """CWE-639: Django Detail/Update/Delete CBVs missing user-scoped get_queryset()."""
    if not (ctx.framework and ctx.framework.django):
        return []
    findings: list[Finding] = []

    for cls in (ctx.class_defs or {}).values():
        if not _class_inherits_any_base(cls, ctx.class_defs, _DJANGO_IDOR_CBV_BASES):
            continue
        queryset_method = _cbv_get_queryset_method(cls)
        if queryset_method is not None:
            continue

        trace: tuple[TraceFrame, ...] = ()
        trace = _append_trace(trace, "source", f"class-based view `{cls.name}`", line=cls.lineno)
        trace = _append_trace(trace, "gap", "no get_queryset override detected", line=cls.lineno)
        trace = _append_trace(trace, "sink", "CBV resolves objects without visible user scoping", line=cls.lineno)
        findings.append(Finding(
            category="security", severity=Severity.HIGH,
            title=f"CWE-639: Django CBV `{cls.name}` has no user-scoped get_queryset()",
            description=(
                f"`{cls.name}` inherits from a detail/update/delete class-based view but does not override "
                f"`get_queryset()` to scope objects to `self.request.user`. This can expose other users' records."
            ),
            line=cls.lineno,
            suggestion=(
                "Override `get_queryset()` and filter by the current user, for example: "
                "`return Order.objects.filter(owner=self.request.user)`."
            ),
            cwe="CWE-639", agent="python-analyzer",
            confidence=0.9,
            analysis_kind="route-heuristic",
            trace=trace,
        ))

    return _assign_rule_ids(findings, "PY-029")


def _rule_38(ctx: _Ctx) -> list[Finding]:
    """CWE-285: Django Update/Delete CBVs whose get_queryset() lacks ownership scope."""
    if not (ctx.framework and ctx.framework.django):
        return []
    findings: list[Finding] = []

    for cls in (ctx.class_defs or {}).values():
        if not _class_inherits_any_base(cls, ctx.class_defs, _DJANGO_MUTATING_CBVS):
            continue
        queryset_method = _cbv_get_queryset_method(cls)
        if queryset_method is None or _queryset_method_has_user_scope(queryset_method):
            continue

        trace: tuple[TraceFrame, ...] = ()
        trace = _append_trace(trace, "source", f"class-based view `{cls.name}`", line=cls.lineno)
        trace = _append_trace(trace, "check", "custom get_queryset override detected", line=queryset_method.lineno)
        trace = _append_trace(trace, "gap", "get_queryset lacks owner/user scope", line=queryset_method.lineno)
        trace = _append_trace(trace, "sink", "update/delete view can act on another user's object", line=cls.lineno)
        findings.append(Finding(
            category="security", severity=Severity.HIGH,
            title=f"CWE-285: Django CBV `{cls.name}` get_queryset() lacks ownership filter",
            description=(
                f"`{cls.name}` overrides `get_queryset()` but the queryset body never scopes results to "
                f"`self.request.user` or another current-user identity. Update/delete actions may operate on "
                f"another user's object."
            ),
            line=queryset_method.lineno,
            suggestion=(
                "Scope the queryset to the current user, for example: "
                "`return Post.objects.filter(owner=self.request.user)`."
            ),
            cwe="CWE-285", agent="python-analyzer",
            confidence=0.9,
            analysis_kind="route-heuristic",
            trace=trace,
        ))

    return _assign_rule_ids(findings, "PY-030")


def _rule_39(ctx: _Ctx) -> list[Finding]:
    """CWE-287: FastAPI routes with Depends/Security hooks that do not perform auth."""
    if not (ctx.framework and ctx.framework.fastapi):
        return []
    findings: list[Finding] = []
    auth_aliases = ctx.fastapi_auth_aliases or set()
    guarded_receivers = ctx.fastapi_guarded_receivers or set()

    for fname, fnode in ctx.func_defs.items():
        if _node_has_auth_decorator_signal(fnode):
            continue
        dep_calls = _iter_fastapi_dependency_calls(fnode)
        if not dep_calls:
            continue
        if _fastapi_route_is_receiver_guarded(fnode, guarded_receivers):
            continue
        if any(_fastapi_dependency_call_has_auth_provider(dep, ctx.func_defs, auth_aliases) for dep in dep_calls):
            continue

        dep_labels = sorted({label for dep in dep_calls for label in _fastapi_dependency_callback_labels(dep)})
        dep_display = ", ".join(f"`{label}`" for label in dep_labels) or "`Depends(...)`"
        trace = _route_trace_frames(fnode)
        trace = _append_trace(trace, "gap", f"dependency hooks {dep_display} have no auth signal", line=fnode.lineno)
        trace = _append_trace(trace, "sink", f"FastAPI route `{fname}()` trusts non-auth dependency injection", line=fnode.lineno)
        findings.append(Finding(
            category="security", severity=Severity.CRITICAL,
            title=f"CWE-287: FastAPI route `{fname}()` uses Depends without auth verification",
            description=(
                f"`{fname}()` uses FastAPI dependency injection via {dep_display}, but none of those providers "
                f"call `get_current_user`, `verify_token`, `oauth2_scheme`, or another known auth dependency. "
                f"The route may look protected while still allowing an auth bypass."
            ),
            line=fnode.lineno,
            suggestion=(
                "Use an auth dependency such as `Depends(get_current_user)` / `Security(oauth2_scheme)`, or "
                "call token verification inside the dependency provider before returning."
            ),
            cwe="CWE-287", agent="python-analyzer",
            confidence=0.89,
            analysis_kind="decorator-heuristic",
            trace=trace,
        ))

    return _assign_rule_ids(findings, "PY-031")


def _rule_40(ctx: _Ctx) -> list[Finding]:
    """CWE-862: FastAPI PUT/DELETE routes with no dependency-based auth at all."""
    if not (ctx.framework and ctx.framework.fastapi):
        return []
    findings: list[Finding] = []
    guarded_receivers = ctx.fastapi_guarded_receivers or set()

    for fname, fnode in ctx.func_defs.items():
        if _node_has_auth_decorator_signal(fnode):
            continue
        if not _fastapi_mutating_route_missing_dependencies(fnode, guarded_receivers):
            continue

        methods = sorted(_fastapi_route_methods(fnode).intersection(_FASTAPI_MUTATING_METHODS))
        method_display = "/".join(m.upper() for m in methods) if methods else "PUT/DELETE"
        trace = _route_trace_frames(fnode)
        trace = _append_trace(trace, "gap", "no Depends/Security auth dependency detected", line=fnode.lineno)
        trace = _append_trace(trace, "sink", f"mutating FastAPI route `{fname}()` reachable without auth dependency", line=fnode.lineno)
        findings.append(Finding(
            category="security", severity=Severity.HIGH,
            title=f"CWE-862: FastAPI {method_display} route `{fname}()` has no auth dependency",
            description=(
                f"`{fname}()` is a FastAPI {method_display} endpoint but declares no `Depends()` / `Security()` "
                f"authentication dependency. Mutating routes should require an authenticated principal."
            ),
            line=fnode.lineno,
            suggestion=(
                "Add an auth dependency such as `current_user=Depends(get_current_user)` or configure "
                "router-level authenticated dependencies for the endpoint."
            ),
            cwe="CWE-862", agent="python-analyzer",
            confidence=0.9,
            analysis_kind="decorator-heuristic",
            trace=trace,
        ))

    return _assign_rule_ids(findings, "PY-032")


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
                    else:
                        info = _find_tainted_expr_info(
                            node.value, tainted_vars, func_summaries,
                            global_graph=ctx.global_graph, caller_file=ctx.filename, caller_name=fname,
                        )
                        if info:
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
                # ── Framework semantic: Django CBV dispatch ──────────
                # getattr(self, request.method.lower()) in View.dispatch()
                # is framework HTTP-method routing, not attacker-controlled reflection.
                if isinstance(attr_arg, ast.Call):
                    dispatch_call = _get_call_name(attr_arg)
                    if dispatch_call and "method" in dispatch_call and "lower" in dispatch_call:
                        continue
                attr_info = _find_tainted_expr_info(
                    attr_arg, tainted_vars, func_summaries,
                    global_graph=ctx.global_graph, caller_file=ctx.filename, caller_name=fname,
                )
                if attr_info:
                    vname, vsrc, vline, san_cwes, trace, _ = attr_info
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
                arg_info = _find_tainted_expr_info(
                    node.args[0], tainted_vars, func_summaries,
                    global_graph=ctx.global_graph, caller_file=ctx.filename, caller_name=fname,
                )
                if arg_info:
                    vname, vsrc, vline, san_cwes, trace, _ = arg_info
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
                arg_info = _find_tainted_expr_info(
                    node.args[0], tainted_vars, func_summaries,
                    global_graph=ctx.global_graph, caller_file=ctx.filename, caller_name=fname,
                )
                if arg_info:
                    vname, vsrc, vline, san_cwes, trace, _ = arg_info
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
                "CWE-unknown",
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


# ──────────────────────────────────────────────────────────────────────────────
# Rate-limiting patterns for Python frameworks
# ──────────────────────────────────────────────────────────────────────────────

_PY_RATE_LIMIT_RE: re.Pattern[str] = re.compile(
    r'flask_limiter|slowapi|fastapi_limiter|limits|'
    r'@limiter\.|@app\.limiter|Limiter\s*\(|RateLimiter\s*\(|'
    r'rate_limit|ratelimit|throttle|SlowAPI|redis.*limit',
    re.IGNORECASE,
)

_PY_AUTH_ROUTE_PAT: re.Pattern[str] = re.compile(
    r'@(?:app|router|api|blueprint)\.\s*(?:post|get|route)\s*\(\s*["\']'
    r'[^"\']*(?:login|signin|sign.?in|authenticate|auth[^"\']*|'
    r'forgot.?password|reset.?password|password.?reset|'
    r'mfa|2fa|totp|otp|verify.?otp|token|refresh.?token|'
    r'register|signup|sign.?up)[^"\']*["\']',
    re.IGNORECASE,
)


def _rule_30(ctx: _Ctx) -> list[Finding]:
    """CWE-307: Missing rate limiting on Python authentication/sensitive endpoints."""
    findings: list[Finding] = []
    code_text = "\n".join(ctx.lines)
    if _PY_RATE_LIMIT_RE.search(code_text):
        return findings  # rate limiting present globally

    for lineno, line in enumerate(ctx.lines, 1):
        if not _PY_AUTH_ROUTE_PAT.search(line):
            continue
        # Determine endpoint kind for the message
        line_lower = line.lower()
        if any(k in line_lower for k in ("mfa", "2fa", "totp", "otp")):
            kind = "multi-factor authentication"
        elif any(k in line_lower for k in ("forgot", "reset")):
            kind = "password reset"
        elif any(k in line_lower for k in ("token", "refresh")):
            kind = "token/refresh"
        elif any(k in line_lower for k in ("register", "signup", "sign-up", "sign_up")):
            kind = "registration"
        else:
            kind = "authentication"
        findings.append(Finding(
            category="security",
            severity=Severity.MEDIUM,
            title=f"CWE-307: No rate limiting on {kind} route at line {lineno}",
            description=(
                f"{kind.capitalize()} route at L{lineno} has no rate-limiting decorator or "
                f"middleware in scope: `{line.strip()[:80]}`. "
                f"An attacker can brute-force credentials, OTPs, or tokens."
            ),
            line=lineno,
            suggestion=(
                "Add rate limiting: `flask-limiter` for Flask (`@limiter.limit('5/minute')`), "
                "`slowapi` for FastAPI, or a middleware-level rate limiter."
            ),
            rule_id="PY-038",
            cwe="CWE-307",
            agent="python-analyzer",
        ))
    return findings


def _rule_31(ctx: _Ctx) -> list[Finding]:
    """CWE-200: Sensitive information exposed through error/debug output."""
    findings: list[Finding] = []
    lines = ctx.lines
    _DEBUG_ENABLE_RE = re.compile(
        r'(?:\bdebug\s*=\s*True\b|(?:app|application)\.config\[\s*["\']DEBUG["\']\s*\]\s*=\s*True\b)',
        re.IGNORECASE,
    )
    _TRACEBACK_EXPOSE_RE = re.compile(
        r'\b(?:traceback\.print_exc|traceback\.format_exc|sys\.exc_info)\s*\(',
        re.IGNORECASE,
    )
    _ERROR_RESPONSE_RE = re.compile(
        r'return\s+(?:f["\']|["\']).*(?:traceback|stack\s*trace|exception|sys\.exc_info)',
        re.IGNORECASE,
    )
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if _DEBUG_ENABLE_RE.search(stripped):
            findings.append(Finding(
                category="security", severity=Severity.HIGH,
                title=f"CWE-200: debug=True may expose tracebacks at line {lineno}",
                description=f"Debug mode enabled at L{lineno}; production errors can leak stack traces, configuration details, and other internal information.",
                line=lineno,
                suggestion="Disable debug mode in production and serve generic error pages to clients.",
                rule_id="PY-039", cwe="CWE-200", agent="python-analyzer",
            ))
        elif _TRACEBACK_EXPOSE_RE.search(stripped):
            findings.append(Finding(
                category="security", severity=Severity.MEDIUM,
                title=f"CWE-200: Traceback/error details exposed to users at line {lineno}",
                description=f"`traceback.print_exc()` or equivalent at L{lineno} may leak internal paths, versions, and logic to end users.",
                line=lineno,
                suggestion="Use `logger.exception()` server-side and return a generic error message to clients.",
                rule_id="PY-039", cwe="CWE-200", agent="python-analyzer",
            ))
        elif _ERROR_RESPONSE_RE.search(stripped):
            findings.append(Finding(
                category="security", severity=Severity.MEDIUM,
                title=f"CWE-200: Error details embedded in HTTP response at line {lineno}",
                description=f"Response at L{lineno} appears to include raw error or traceback data visible to clients.",
                line=lineno,
                suggestion="Strip internal details before returning; use generic HTTP error codes and log internally.",
                rule_id="PY-039", cwe="CWE-200", agent="python-analyzer",
            ))
    return findings


def _rule_32(ctx: _Ctx) -> list[Finding]:
    """CWE-295: TLS certificate verification disabled in HTTP clients."""
    findings: list[Finding] = []
    _TLS_DISABLE_RE = re.compile(
        r'\bverify\s*=\s*False\b|ssl\._create_unverified_context\s*\(|check_hostname\s*=\s*False',
        re.IGNORECASE,
    )
    _HTTP_CLIENT_RE = re.compile(
        r'\b(?:requests\.(?:get|post|put|patch|delete|request|head)|httpx\.(?:get|post|Client)|'
        r'aiohttp\.(?:ClientSession|request)|urllib\.request\.urlopen)\s*\(',
        re.IGNORECASE,
    )
    lines = ctx.sans_comments
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if _TLS_DISABLE_RE.search(stripped):
            ctx_start = max(0, lineno - 3)
            ctx_end = min(len(lines), lineno + 2)
            context = "\n".join(lines[ctx_start:ctx_end])
            # ssl._create_unverified_context() is always a TLS issue — no HTTP client context needed
            if "ssl._create_unverified_context" not in stripped and not _HTTP_CLIENT_RE.search(context):
                continue
            findings.append(Finding(
                    category="security", severity=Severity.HIGH,
                    title=f"CWE-295: TLS certificate verification disabled at line {lineno}",
                    description=f"HTTP client call near L{lineno} has `verify=False` or equivalent, enabling MITM attacks.",
                    line=lineno,
                    suggestion="Remove verify=False and use a custom CA bundle path if needed: `requests.get(url, verify='/path/to/ca-bundle.crt')`.",
                    rule_id="PY-040", cwe="CWE-295", agent="python-analyzer",
                ))
    return findings


def _rule_33(ctx: _Ctx) -> list[Finding]:
    """CWE-319: Cleartext HTTP URLs in authentication/sensitive contexts."""
    findings: list[Finding] = []
    _HTTP_URL_RE = re.compile(r'["\']http://[^"\']+["\']', re.IGNORECASE)
    _SENSITIVE_CTX_RE = re.compile(
        r'\b(?:auth|login|token|password|secret|credential|api[_-]?key|oauth)\b',
        re.IGNORECASE,
    )
    lines = ctx.lines
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or "localhost" in stripped or "127.0.0.1" in stripped:
            continue
        http_match = _HTTP_URL_RE.search(stripped)
        if not http_match:
            continue
        ctx_start = max(0, lineno - 2)
        ctx_end = min(len(lines), lineno + 2)
        context = "\n".join(lines[ctx_start:ctx_end])
        if _SENSITIVE_CTX_RE.search(context):
            findings.append(Finding(
                category="security", severity=Severity.HIGH,
                title=f"CWE-319: HTTP URL in authentication context at line {lineno}",
                description=f"Line L{lineno} uses `http://` for what appears to be an authentication or credential endpoint.",
                line=lineno,
                suggestion="Always use `https://` for authentication, token, and credential endpoints.",
                rule_id="PY-041", cwe="CWE-319", agent="python-analyzer",
            ))
    return findings


def _rule_34(ctx: _Ctx) -> list[Finding]:
    """CWE-400: Unbounded resource consumption from user input."""
    findings: list[Finding] = []
    _UNBOUNDED_INT_RE = re.compile(
        r'\bint\s*\(\s*(?:request\.(?:args|form|json)|req\.(?:query|body|params))',
        re.IGNORECASE,
    )
    _ALLOCATION_SINK_RE = re.compile(
        r'(?:^|\s|=|\()(?:range\s*\(|\[[^\]]*\]\s*\*\s*|bytes\s*\(|bytearray\s*\(|re\.(?:compile|search|match)|\w+\.read\s*\()',
        re.IGNORECASE,
    )
    _ZIPFILE_RE = re.compile(r'\b(?:zipfile\.ZipFile|ZipFile)\s*\(', re.IGNORECASE)
    _ZIP_EXTRACT_RE = re.compile(r'\.extractall\s*\(', re.IGNORECASE)
    _ZIP_GUARD_RE = re.compile(
        r'(?:infolist\s*\(|namelist\s*\(|file_size|compress_size|total_size|max_(?:files|size)|zipinfo)',
        re.IGNORECASE,
    )
    lines = ctx.lines
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if _UNBOUNDED_INT_RE.search(stripped):
            ctx_start = max(0, lineno - 2)
            ctx_end = min(len(lines), lineno + 3)
            context = "\n".join(lines[ctx_start:ctx_end])
            if _ALLOCATION_SINK_RE.search(context):
                findings.append(Finding(
                    category="security", severity=Severity.MEDIUM,
                    title=f"CWE-400: Unbounded user input used in resource allocation near line {lineno}",
                    description=f"`int(request.args.get(...))` at L{lineno} flows into a resource-consuming operation without an upper bound.",
                    line=lineno,
                    suggestion="Clamp user-controlled numeric values: `size = min(int(request.args.get('size', 100)), 10000)`.",
                    rule_id="PY-042", cwe="CWE-400", agent="python-analyzer",
                ))
    for fname, fnode in ctx.func_defs.items():
        code_block = ctx.lines[fnode.lineno - 1:fnode.end_lineno] if fnode.end_lineno else []
        block_text = "\n".join(code_block)
        if not (_ZIPFILE_RE.search(block_text) and _ZIP_EXTRACT_RE.search(block_text)):
            continue
        if _ZIP_GUARD_RE.search(block_text):
            continue
        findings.append(Finding(
            category="security", severity=Severity.MEDIUM,
            title=f"CWE-400: Zip extraction in `{fname}()` may allow zip-bomb resource exhaustion",
            description=(
                f"`{fname}()` extracts an archive with `extractall()` and no visible size, entry-count, or compression-ratio guard. "
                "A crafted zip bomb can exhaust disk, CPU, or memory resources."
            ),
            line=fnode.lineno,
            suggestion="Validate archive entry counts and total uncompressed size before calling `extractall()`.",
            rule_id="PY-042", cwe="CWE-400", agent="python-analyzer",
        ))
    return findings


def _rule_35(ctx: _Ctx) -> list[Finding]:
    """CWE-614: Sensitive cookie without secure flag."""
    findings: list[Finding] = []
    _COOKIE_SET_RE = re.compile(
        r'(?:set_cookie|response\.set_cookie|response\.headers\[["\']Set-Cookie["\']\])\s*\(',
        re.IGNORECASE,
    )
    _SECURE_FALSE_RE = re.compile(r'secure\s*=\s*False', re.IGNORECASE)
    _SESSION_COOKIE_RE = re.compile(
        r'SESSION_COOKIE_SECURE\s*=\s*False|SESSION_COOKIE_SECURE\s*=\s*(?:0|None)', re.IGNORECASE,
    )
    _SESSION_COOKIE_TRUE_RE = re.compile(
        r'SESSION_COOKIE_SECURE\s*=\s*True|SESSION_COOKIE_SECURE\s*=\s*1', re.IGNORECASE,
    )
    lines = ctx.lines
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if _SECURE_FALSE_RE.search(stripped) and _COOKIE_SET_RE.search(stripped):
            findings.append(Finding(
                category="security", severity=Severity.MEDIUM,
                title=f"CWE-614: Cookie set without secure flag at line {lineno}",
                description=f"`set_cookie()` at L{lineno} has `secure=False`, allowing transmission over unencrypted HTTP.",
                line=lineno,
                suggestion="Set `secure=True` on all session and authentication cookies.",
                rule_id="PY-043", cwe="CWE-614", agent="python-analyzer",
            ))
        elif _SESSION_COOKIE_RE.search(stripped):
            findings.append(Finding(
                category="security", severity=Severity.MEDIUM,
                title=f"CWE-614: SESSION_COOKIE_SECURE disabled at line {lineno}",
                description=f"Session cookie secure flag disabled at L{lineno}. Session cookies can be sent over HTTP.",
                line=lineno,
                suggestion="Set `SESSION_COOKIE_SECURE = True` in Django/Flask configuration.",
                rule_id="PY-043", cwe="CWE-614", agent="python-analyzer",
            ))
    code_text = "\n".join(lines)
    if (
        ("from flask import" in code_text or "Flask(" in code_text)
        and re.search(r'\bsession\s*\[', code_text)
        and ("SECRET_KEY" in code_text or "secret_key" in code_text)
        and not _SESSION_COOKIE_TRUE_RE.search(code_text)
        and not _SESSION_COOKIE_RE.search(code_text)
    ):
        session_line = next((idx for idx, line in enumerate(lines, 1) if re.search(r'\bsession\s*\[', line)), 1)
        findings.append(Finding(
            category="security", severity=Severity.MEDIUM,
            title=f"CWE-614: Flask session cookie may be sent without Secure flag at line {session_line}",
            description=(
                "Flask session state is used, but `SESSION_COOKIE_SECURE` is not enabled in configuration. "
                "Session cookies may be transmitted over cleartext HTTP if TLS is not enforced."
            ),
            line=session_line,
            suggestion="Set `app.config['SESSION_COOKIE_SECURE'] = True` for session-bearing Flask apps.",
            rule_id="PY-043", cwe="CWE-614", agent="python-analyzer",
        ))
    return findings


def _rule_41(ctx: _Ctx) -> list[Finding]:
    """CWE-611: XML parsers without external-entity protection (XXE)."""
    findings: list[Finding] = []
    _XXE_UNSAFE_PARSER_RE = re.compile(
        r'\b(?:etree\.(?:parse|fromstring|iterparse|XMLParser)\s*\(|'
        r'xml\.(?:dom|sax|etree\.ElementTree)\s*\(|'
        r'lxml\.(?:etree\.parse|etree\.fromstring|html\.parse|objectify\.parse)\s*\()',
        re.IGNORECASE,
    )
    _XXE_SAFE_RE = re.compile(
        r'(?:resolve_entities\s*=\s*False|XMLParser\s*\([^)]*load_dtd\s*=\s*False|'
        r'defusedxml|SafeXMLParser|RestrictedElement)',
        re.IGNORECASE,
    )
    _XXE_DISABLE_DTD_RE = re.compile(
        r'parser\.(?:entity|forbid_dtd|forbid_entities)\s*=',
        re.IGNORECASE,
    )
    lines = ctx.lines
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        m = _XXE_UNSAFE_PARSER_RE.search(stripped)
        if not m:
            continue
        # Check nearby context for safety guards
        ctx_start = max(0, lineno - 2)
        ctx_end = min(len(lines), lineno + 3)
        context = "\n".join(lines[ctx_start:ctx_end])
        if _XXE_SAFE_RE.search(context) or _XXE_DISABLE_DTD_RE.search(context):
            continue
        findings.append(Finding(
            category="security", severity=Severity.HIGH,
            title=f"CWE-611: XML parser without XXE protection at line {lineno}",
            description=f"XML parser `{m.group(0)[:50]}` at L{lineno} may be vulnerable to XML External Entity (XXE) injection.",
            line=lineno,
            suggestion=(
                "Use defusedxml or disable external entities: "
                "`parser = etree.XMLParser(resolve_entities=False)` or "
                "`from defusedxml import ElementTree`."
            ),
            rule_id="PY-049", cwe="CWE-611", agent="python-analyzer",
        ))
    return findings


def _rule_42(ctx: _Ctx) -> list[Finding]:
    """CWE-639: Insecure Direct Object Reference — auth then object access without ownership check."""
    findings: list[Finding] = []
    _IDOR_AUTH_RE = re.compile(
        r'(?:@login_required|@permission_required|request\.user\.is_authenticated|'
        r'current_user\.is_authenticated|user\s*=\s*get_current_user|Depends\s*\(\s*get_current)',
        re.IGNORECASE,
    )
    _IDOR_ACCESS_RE = re.compile(
        r'\b(?:\.get\s*\(\s*(?:pk|id|object_id|item_id|user_id)\s*=|'
        r'\.objects\.(?:get|filter)\s*\(\s*(?:pk|id)\s*=|'
        r'\.filter_by\s*\(\s*(?:id|user_id)\s*=)',
        re.IGNORECASE,
    )
    _IDOR_OWNER_CHECK_RE = re.compile(
        r'(?:owner|user|created_by|author|self\.request\.user|current_user)\s*=|'
        r'\.filter\s*\([^)]*request\.user|\.filter\s*\([^)]*current_user',
        re.IGNORECASE,
    )
    func_defs = ctx.func_defs
    for fname, fnode in func_defs.items():
        code_block = ctx.lines[fnode.lineno - 1:fnode.end_lineno] if fnode.end_lineno else []
        block_text = "\n".join(code_block)
        if not _IDOR_AUTH_RE.search(block_text):
            continue
        if not _IDOR_ACCESS_RE.search(block_text):
            continue
        if _IDOR_OWNER_CHECK_RE.search(block_text):
            continue
        findings.append(Finding(
            category="security", severity=Severity.HIGH,
            title=f"CWE-639: Possible IDOR in `{fname}()` — authenticated object access without ownership check",
            description=(
                f"`{fname}()` performs authentication and direct object access but "
                "lacks an ownership filter (owner=request.user). Attackers may access "
                "other users' objects by enumerating IDs."
            ),
            line=fnode.lineno,
            suggestion=(
                "Filter queried objects by the current user: "
                "`obj = Model.objects.get(pk=pk, owner=request.user)`."
            ),
            cwe="CWE-639", agent="python-analyzer",
            confidence=0.85,
            analysis_kind="pattern-heuristic",
            trace=(
                TraceFrame(kind="source", label=f"function `{fname}()`", line=fnode.lineno),
            ),
        ))
    return _assign_rule_ids(findings, "PY-050")


def _rule_43(ctx: _Ctx) -> list[Finding]:
    """CWE-352: State-changing endpoints without CSRF protection."""
    findings: list[Finding] = []
    _CSRF_MUTATING_DECORATOR_RE = re.compile(
        r'(?:app|bp|blueprint)\.(?:post|put|patch|delete)\s*\(',
        re.IGNORECASE,
    )
    _CSRF_ROUTE_METHOD_RE = re.compile(
        r'(?:app|bp|blueprint)\.route\s*\([^\)]*methods\s*=\s*\[[^\]]*(?:POST|PUT|PATCH|DELETE)',
        re.IGNORECASE,
    )
    _CSRF_FASTAPI_METHOD_RE = re.compile(
        r'(?:app|router)\.(?:post|put|patch|delete)\s*\(',
        re.IGNORECASE,
    )
    _CSRF_PROTECTION_RE = re.compile(
        r'(?:@csrf_exempt|csrf_protect|CSRF_ENABLED|WTF_CSRF_ENABLED|'
        r'csrf_token|CsrfViewMiddleware|CSRF_COOKIE|X-CSRFToken|'
        r'@requires_csrf_token|csrf\.get_token|Depends\([^)]*csrf)',
        re.IGNORECASE,
    )
    _CSRF_DJANGO_SAFE_RE = re.compile(
        r'(?:django\.views\.decorators\.csrf|method_decorator.*csrf|'
        r'ensure_csrf_cookie|csrf_exempt\s*=\s*False)',
        re.IGNORECASE,
    )
    func_defs = ctx.func_defs
    for fname, fnode in func_defs.items():
        # Check decorators on function
        has_mutating_decorator = False
        for deco in fnode.decorator_list:
            deco_str = ast.unparse(deco) if hasattr(ast, "unparse") else ""
            if (
                _CSRF_MUTATING_DECORATOR_RE.search(deco_str)
                or _CSRF_FASTAPI_METHOD_RE.search(deco_str)
                or _CSRF_ROUTE_METHOD_RE.search(deco_str)
            ):
                has_mutating_decorator = True
                break
        if not has_mutating_decorator:
            continue
        # Check body for CSRF protection
        code_block = ctx.lines[fnode.lineno - 1:fnode.end_lineno] if fnode.end_lineno else []
        block_text = "\n".join(code_block)
        if _CSRF_PROTECTION_RE.search(block_text) or _CSRF_DJANGO_SAFE_RE.search(block_text):
            continue
        findings.append(Finding(
            category="security", severity=Severity.HIGH,
            title=f"CWE-352: State-changing route `{fname}()` may lack CSRF protection",
            description=(
                f"`{fname}()` handles POST/PUT/DELETE but no CSRF token validation "
                "was detected. Cross-Site Request Forgery can force authenticated "
                "users to perform unintended actions."
            ),
            line=fnode.lineno,
            suggestion=(
                "Enable CSRF protection: use Flask-WTF `CSRFProtect`, Django's "
                "CsrfViewMiddleware, or FastAPI's CSRF dependency."
            ),
            cwe="CWE-352", agent="python-analyzer",
            confidence=0.80,
            analysis_kind="pattern-heuristic",
            trace=(
                TraceFrame(kind="source", label=f"route `{fname}()`", line=fnode.lineno),
            ),
        ))
    return _assign_rule_ids(findings, "PY-051")


def _rule_45(ctx: _Ctx) -> list[Finding]:
    """CWE-90/CWE-470 supplemental Python framework heuristics."""
    findings: list[Finding] = []
    route_param_re = re.compile(r'<(?:[^:>]+:)?([A-Za-z_]\w*)>')
    code_text = "\n".join(ctx.lines)
    if (
        ("request.args.get" in code_text or "request.form.get" in code_text or "request.values.get" in code_text)
        and "ldap" in code_text.lower()
        and re.search(r'\.(?:search|search_s|search_ext)\s*\(', code_text)
        and (
            re.search(r'f["\'][^\n]*\{[^\}]+\}', code_text)
            or "%" in code_text
            or ".format(" in code_text
        )
    ):
        ldap_line = next(
            (idx for idx, line in enumerate(ctx.lines, 1) if re.search(r'\.(?:search|search_s|search_ext)\s*\(', line)),
            1,
        )
        findings.append(Finding(
            category="security", severity=Severity.HIGH,
            title=f"CWE-90: LDAP injection via user-controlled filter at line {ldap_line}",
            description=(
                "LDAP search filter appears to be built from request-derived data without escaping LDAP metacharacters. "
                "Attackers can manipulate or broaden the directory query."
            ),
            line=ldap_line,
            suggestion="Escape LDAP filter metacharacters before embedding user input into LDAP search filters.",
            rule_id="PY-053", cwe="CWE-90", agent="python-analyzer",
        ))
    for fname, fnode in ctx.func_defs.items():
        code_block = ctx.lines[fnode.lineno - 1:fnode.end_lineno] if fnode.end_lineno else []
        block_text = "\n".join(code_block)

        if (
            ("request.args.get" in block_text or "request.form.get" in block_text or "request.values.get" in block_text)
            and re.search(r'\.(?:search|search_s|search_ext)\s*\(', block_text)
            and (
                re.search(r'f["\'][^\n]*\{[^\}]+\}', block_text)
                or "%" in block_text
                or ".format(" in block_text
            )
        ):
            findings.append(Finding(
                category="security", severity=Severity.HIGH,
                title=f"CWE-90: LDAP injection via user-controlled filter in `{fname}()`",
                description=(
                    f"`{fname}()` builds an LDAP search filter from request-derived data without escaping LDAP metacharacters. "
                    "Attackers can broaden or manipulate the directory query."
                ),
                line=fnode.lineno,
                suggestion="Escape LDAP filter metacharacters before embedding user input into LDAP search filters.",
                rule_id="PY-053", cwe="CWE-90", agent="python-analyzer",
            ))

        route_params: set[str] = set()
        for deco in fnode.decorator_list:
            deco_str = ast.unparse(deco) if hasattr(ast, "unparse") else ""
            route_params.update(route_param_re.findall(deco_str))
        if not route_params:
            continue
        if not re.search(r'\bgetattr\s*\(', block_text):
            continue
        if re.search(r'ALLOWED_|allowlist|allowed_actions|permitted_actions', block_text, re.IGNORECASE):
            continue
        for param in route_params:
            if re.search(rf'\bgetattr\s*\([^\n]*\b{re.escape(param)}\b', block_text):
                findings.append(Finding(
                    category="security", severity=Severity.HIGH,
                    title=f"CWE-470: Unsafe reflection via route parameter in `{fname}()`",
                    description=(
                        f"Route parameter `{param}` flows into `getattr()` in `{fname}()` without an explicit allowlist. "
                        "An attacker can trigger arbitrary method dispatch or sensitive introspection paths."
                    ),
                    line=fnode.lineno,
                    suggestion="Validate route-driven action names against a fixed allowlist before calling `getattr()`.",
                    rule_id="PY-054", cwe="CWE-470", agent="python-analyzer",
                ))
                break
    return findings


def _rule_46(ctx: _Ctx) -> list[Finding]:
    """Supplemental CVE heuristics for supply-chain, TOCTOU, and cloud ACL misconfigurations."""
    findings: list[Finding] = []
    lines = ctx.lines
    code_text = "\n".join(lines)

    _S3_PUBLIC_ACL_RE = re.compile(r'\b(?:ACL|acl)\s*=\s*["\']public-(?:read|read-write)["\']', re.IGNORECASE)
    _MKTEMP_RE = re.compile(r'\btempfile\.mktemp\s*\(', re.IGNORECASE)
    _EXISTS_OPEN_RE = re.compile(r'if\s+os\.path\.exists\s*\(([^\)]+)\)\s*:\s*[\s\S]{0,220}?open\s*\(\s*\1\s*,', re.IGNORECASE)
    _SETUP_SHELL_RE = re.compile(r'\b(?:os\.system|subprocess\.(?:run|Popen|call|check_call|check_output))\s*\(', re.IGNORECASE)
    # LDAP filter string concatenation — CWE-90
    _LDAP_FILTER_CONCAT_RE = re.compile(
        r'(?:search_filter|filter_str|ldap_filter|dn_filter)\s*=\s*["\'][^"\']*["\'\)]\s*\+\s*\w+|'
        r'["\'][^"\']*(?:uid=|cn=|sAMAccountName=|mail=)["\'\)]\s*\+\s*\w+|'
        r'f["\'][^"\']*(?:uid=|cn=|sAMAccountName=|mail=)\{',
        re.IGNORECASE,
    )
    _LDAP_SEARCH_RE = re.compile(r'\b(?:conn|ldap_conn|c|connection)\s*\.\s*search_s?\b', re.IGNORECASE)

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        if _S3_PUBLIC_ACL_RE.search(stripped):
            findings.append(Finding(
                category="security", severity=Severity.HIGH,
                title=f"CWE-732: S3 bucket/object ACL set to public at line {lineno}",
                description="S3 ACL is configured as public-read/public-read-write, which can expose sensitive bucket contents to unauthenticated users.",
                line=lineno,
                suggestion="Use private ACLs and explicit IAM policies; avoid public ACLs unless explicitly required.",
                rule_id="PY-055", cwe="CWE-732", agent="python-analyzer",
            ))

        if _MKTEMP_RE.search(stripped):
            findings.append(Finding(
                category="security", severity=Severity.HIGH,
                title=f"CWE-377: tempfile.mktemp() race-prone temporary file creation at line {lineno}",
                description="`tempfile.mktemp()` returns a filename without atomically creating the file, enabling symlink race attacks.",
                line=lineno,
                suggestion="Use `tempfile.NamedTemporaryFile(delete=False)` or `tempfile.mkstemp()` instead of `mktemp()`.",
                rule_id="PY-056", cwe="CWE-377", agent="python-analyzer",
            ))

        is_setup_script = (
            "setup.py" in (ctx.filename or "").lower()
            or "from setuptools import" in code_text
            or "import setuptools" in code_text
        )
        if is_setup_script and _SETUP_SHELL_RE.search(stripped):
            findings.append(Finding(
                category="security", severity=Severity.HIGH,
                title=f"CWE-494: setup.py executes shell command at line {lineno}",
                description="Package setup script executes a shell command during install/build, which can enable supply-chain code execution.",
                line=lineno,
                suggestion="Remove install-time shell execution from setup scripts; keep build metadata side-effect free.",
                rule_id="PY-057", cwe="CWE-494", agent="python-analyzer",
            ))

    # LDAP filter string-concat injection (function-param taint not tracked by engine)
    if _LDAP_FILTER_CONCAT_RE.search(code_text) and _LDAP_SEARCH_RE.search(code_text):
        # Find the line with the filter concatenation
        for lidx, ltext in enumerate(lines, 1):
            if _LDAP_FILTER_CONCAT_RE.search(ltext):
                findings.append(Finding(
                    category="security", severity=Severity.HIGH,
                    title=f"CWE-90: LDAP filter built via string concatenation at line {lidx}",
                    description=(
                        f"LDAP search filter constructed by string concatenation with an unescaped variable at L{lidx}. "
                        "An attacker can inject LDAP metacharacters (e.g. `*)(uid=*`) to bypass authentication or dump the directory."
                    ),
                    line=lidx,
                    suggestion="Use an LDAP escaping helper (e.g. `ldap.filter.escape_filter_chars()`) on all user-supplied values before incorporating them in filter strings.",
                    rule_id="PY-059", cwe="CWE-90", agent="python-analyzer",
                ))
                break

    for match in _EXISTS_OPEN_RE.finditer(code_text):
        line = code_text.count("\n", 0, match.start()) + 1
        findings.append(Finding(
            category="security", severity=Severity.HIGH,
            title=f"CWE-362: TOCTOU race via exists() check before open() at line {line}",
            description="Code checks `os.path.exists()` and then opens the same path, allowing a race window for attacker-controlled file substitution.",
            line=line,
            suggestion="Use atomic file operations and avoid check-then-open patterns on attacker-influenced paths.",
            rule_id="PY-058", cwe="CWE-362", agent="python-analyzer",
        ))

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# P0: Rule 47 — CWE-453: Mutable default argument in function signature
# ──────────────────────────────────────────────────────────────────────────────

def _rule_47(ctx: _Ctx) -> list[Finding]:
    """Detect mutable default arguments (x=[], x={}, x=set()) that share state across calls."""
    findings: list[Finding] = []
    for fname, fnode in ctx.func_defs.items():
        for default_node in [*fnode.args.defaults, *fnode.args.kw_defaults]:
            if default_node is None:
                continue
            is_mutable = False
            mut_type = ""
            if isinstance(default_node, ast.List):
                is_mutable = True
                mut_type = "[] (empty list)"
            elif isinstance(default_node, ast.Dict):
                is_mutable = True
                mut_type = "{} (empty dict)"
            elif isinstance(default_node, ast.Set):
                is_mutable = True
                mut_type = "set()"
            elif isinstance(default_node, ast.Call):
                if isinstance(default_node.func, ast.Name):
                    if default_node.func.id in {"list", "dict", "set", "OrderedDict", "defaultdict"}:
                        is_mutable = True
                        mut_type = f"{default_node.func.id}()"
            if not is_mutable:
                continue
            findings.append(Finding(
                category="bug", severity=Severity.MEDIUM,
                title=f"CWE-453: Mutable default argument `{mut_type}` in {fname}()",
                description=(
                    f"`{fname}()` at L{default_node.lineno} uses `{mut_type}` as a default argument value. "
                    "This shared mutable object persists across calls — mutations in one call leak to subsequent calls. "
                    "This is a common source of subtle, hard-to-reproduce bugs."
                ),
                line=default_node.lineno,
                suggestion="Use `None` as default and assign inside the function: `def fn(x=None): if x is None: x = []`",
                cwe="CWE-453", agent="python-analyzer",
            ))
    return _assign_rule_ids(findings, "PY-060")


# ──────────────────────────────────────────────────────────────────────────────
# P0: Rule 48 — CWE-617: Assert used for security check  (disabled in -O mode)
# ──────────────────────────────────────────────────────────────────────────────

def _rule_48(ctx: _Ctx) -> list[Finding]:
    """Detect `assert` statements used for security validation — disabled with python -O."""
    findings: list[Finding] = []
    # Keywords that suggest a security/intrusion/intent check rather than a debug invariant
    _SECURITY_ASSERT_RE = re.compile(
        r'(?:role|permission|auth|login|admin|owner|user_id|'
        r'is_(?:admin|staff|owner|authenticated|superuser)|'
        r'has_(?:role|permission|access)|can_(?:edit|delete|admin)|'
        r'allowed|authorized|is_owner|owns|verify|validate|check|'
        r'secure|secret|token|session|csrf|access|privilege|scope|'
        r'not\s+None|is\s+not\s+None)',
        re.IGNORECASE,
    )
    _ASSERT_STMT_RE = re.compile(r'assert\s+', re.IGNORECASE)
    for fname, fnode in ctx.func_defs.items():
        # Get function body text for regex search
        for node in ast.walk(fnode):
            if not isinstance(node, ast.Assert):
                continue
            node_text = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
            if not node_text:
                continue
            # Only flag if the assert condition looks security-related
            if not _SECURITY_ASSERT_RE.search(node_text):
                continue
            findings.append(Finding(
                category="security", severity=Severity.HIGH,
                title=f"CWE-617: Security check via `assert` in {fname}() at line {node.lineno}",
                description=(
                    f"`{fname}()` uses `assert {node_text[:100]}` at L{node.lineno} for a "
                    "security-relevant check. Python disables all `assert` statements when "
                    "running with `-O` (optimized mode). Production deployments often use `-O`."
                ),
                line=node.lineno,
                suggestion="Replace `assert` with an explicit `if` guard that raises an appropriate exception: "
                           "`if condition: raise PermissionError()`",
                cwe="CWE-617", agent="python-analyzer",
            ))
    return _assign_rule_ids(findings, "PY-061")


# ──────────────────────────────────────────────────────────────────────────────
# P0: Rule 49 — CWE-117: Log injection via f-string/logging with user data
# ──────────────────────────────────────────────────────────────────────────────

def _rule_49(ctx: _Ctx) -> list[Finding]:
    """Detect log injection patterns not caught by taint engine — f-string and %-format logging."""
    findings: list[Finding] = []
    _LOG_METHODS_RE = re.compile(
        r'(?:logger|log|logging)\.(?:info|warning|error|debug|critical|warn|exception)\s*\(',
        re.IGNORECASE,
    )
    # Variables that commonly hold user-controlled data
    _USER_VAR_RE = re.compile(
        r'\b(?:request|req|input|data|body|payload|'
        r'user_input|username|email|name|query|search|'
        r'param|argument|value|content|message|text|url|'
        r'ip|address|host|agent|referer|cookie|token|'
        r'headers|form|args|params|session)\b',
        re.IGNORECASE,
    )
    _LOGGED_CONTENT_RE = re.compile(
        r'f[\"\'].*?\{(\w+)\}.*?[\"\']',
        re.IGNORECASE,
    )
    for fname, fnode in ctx.func_defs.items():
        # Collect function parameter names that look user-controlled
        user_params: set[str] = set()
        for arg in fnode.args.args:
            if _USER_VAR_RE.search(arg.arg):
                user_params.add(arg.arg)
        # Track user-data variable assignments
        user_vars: set[str] = set(user_params)
        for node in ast.walk(fnode):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        if isinstance(node.value, ast.Name) and node.value.id in user_vars:
                            user_vars.add(t.id)

        for node in ast.walk(fnode):
            if not isinstance(node, ast.Call):
                continue
            call_text = ast.unparse(node) if hasattr(ast, "unparse") else ""
            if not _LOG_METHODS_RE.search(call_text):
                continue
            # Check all args for user-controlled variables
            has_user_data = False
            for arg in node.args:
                for child in ast.walk(arg):
                    if isinstance(child, ast.Name) and child.id in user_vars:
                        has_user_data = True
                        break
                    if isinstance(child, ast.FormattedValue):
                        if isinstance(child.value, ast.Name) and child.value.id in user_vars:
                            has_user_data = True
                            break
                if has_user_data:
                    break
            if has_user_data:
                findings.append(Finding(
                    category="security", severity=Severity.MEDIUM,
                    title=f"CWE-117: Log injection in {fname}() at line {node.lineno}",
                    description=(
                        f"`{fname}()` logs user-controlled data at L{node.lineno}. "
                        "An attacker can inject fake log entries via CRLF sequences, "
                        "compromising audit trails and SIEM-based detection."
                    ),
                    line=node.lineno,
                    suggestion="Sanitize: `safe = str(val).replace(chr(10), '').replace(chr(13), '')[:200]`",
                    cwe="CWE-117", agent="python-analyzer",
                ))

    # ── Module-level log injection (not inside any function) ─────────────
    _PCT_LOG_RE = re.compile(
        r"(?:logger|log|logging)\.(?:info|warning|error|debug|critical|warn|exception)\s*\(\s*[\"'].*?%[srd].*?[\"']\s*,\s*(\w+)",
        re.IGNORECASE,
    )
    for lineno, line in enumerate(ctx.lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        m = _PCT_LOG_RE.search(stripped)
        if m:
            var_name = m.group(1)
            # Check it's not a literal constant
            if not var_name.startswith(("'", '"')) and not var_name.isdigit():
                findings.append(Finding(
                    category="security", severity=Severity.MEDIUM,
                    title=f"CWE-117: Log injection at module level at line {lineno}",
                    description=(
                        f"Module-level log call at L{lineno} passes variable `{var_name}` via %-format. "
                        "An attacker can inject fake log entries via CRLF sequences."
                    ),
                    line=lineno,
                    suggestion="Sanitize: `safe = str(val).replace(chr(10), '').replace(chr(13), '')[:200]`",
                    cwe="CWE-117", agent="python-analyzer",
                ))

    return _assign_rule_ids(findings, "PY-062")


def _rule_44(ctx: _Ctx) -> list[Finding]:
    """CWE-434: File upload without type/content validation."""
    findings: list[Finding] = []
    _UPLOAD_RECEIVE_RE = re.compile(
        r'\b(?:request\.files\[|request\.files\.get\s*\(|'
        r'UploadFile|File\s*\(\s*\.\.\.|fastapi\.UploadFile|'
        r'werkzeug\.datastructures\.FileStorage)',
        re.IGNORECASE,
    )
    _UPLOAD_VALIDATION_RE = re.compile(
        r'(?:allowed_extensions|ALLOWED_EXTENSIONS|content_type|mimetype|'
        r'magic\b|filetype|imghdr\.what|python-magic|mimetypes\.guess|'
        r'\.endswith\s*\(|\.suffix\s*in\b)',
        re.IGNORECASE,
    )
    _UPLOAD_SAVE_RE = re.compile(
        r'(?:\.save\s*\(|shutil\.(?:copy|move)\s*\(|open\s*\([^)]*[\'"]w|'
        r'\.write\s*\(|\.upload_file\s*\()',
        re.IGNORECASE,
    )
    func_defs = ctx.func_defs
    for fname, fnode in func_defs.items():
        code_block = ctx.lines[fnode.lineno - 1:fnode.end_lineno] if fnode.end_lineno else []
        block_text = "\n".join(code_block)
        if not _UPLOAD_RECEIVE_RE.search(block_text):
            continue
        if not _UPLOAD_SAVE_RE.search(block_text):
            continue
        if _UPLOAD_VALIDATION_RE.search(block_text):
            continue
        m = _UPLOAD_RECEIVE_RE.search(block_text)
        line_offset = block_text[:m.start()].count("\n") + fnode.lineno if m else fnode.lineno
        findings.append(Finding(
            category="security", severity=Severity.HIGH,
            title=f"CWE-434: File upload in `{fname}()` without content-type validation",
            description=(
                f"`{fname}()` receives a file upload and writes it to disk without "
                "validating the file type or content. Attackers can upload executable "
                "files (webshells, scripts) to gain RCE."
            ),
            line=line_offset,
            suggestion=(
                "Validate uploaded files: check extension against an allowlist, verify "
                "MIME type, and use magic bytes (python-magic). Never serve uploaded "
                "files from executable directories."
            ),
            cwe="CWE-434", agent="python-analyzer",
            confidence=0.85,
            analysis_kind="pattern-heuristic",
            trace=(
                TraceFrame(kind="source", label=f"function `{fname}()`", line=fnode.lineno),
            ),
        ))
    return _assign_rule_ids(findings, "PY-052")


def _rule_50(ctx: _Ctx) -> list[Finding]:
    """CWE-942: CORS wildcard origin (flask-cors)."""
    findings: list[Finding] = []
    _CORS_RE = re.compile(r'CORS\s*\([^)]*origins\s*=\s*["\']\*["\']', re.IGNORECASE)
    for lineno, line in enumerate(ctx.lines, 1):
        if _CORS_RE.search(line):
            findings.append(Finding(
                category="security", severity=Severity.HIGH,
                title=f"CWE-942: CORS wildcard origin at line {lineno}",
                description=f"CORS configured with origins='*' at L{lineno}.",
                line=lineno,
                suggestion="Restrict CORS origins to specific trusted domains.",
                cwe="CWE-942", agent="python-analyzer",
            ))
    return _assign_rule_ids(findings, "PY-063")


def _rule_51(ctx: _Ctx) -> list[Finding]:
    """CWE-94: Jinja2 SSTI via from_string with user input."""
    findings: list[Finding] = []
    _SSTI_RE = re.compile(
        r'\.(?:from_string|Template)\s*\(\s*(?:request\.|args\.|form\.|params\.|input|data)',
        re.IGNORECASE,
    )
    for lineno, line in enumerate(ctx.lines, 1):
        if _SSTI_RE.search(line):
            findings.append(Finding(
                category="security", severity=Severity.CRITICAL,
                title=f"CWE-94: SSTI via Jinja2 from_string with user input at line {lineno}",
                description=f"Jinja2 template compiled from user-controlled source at L{lineno}.",
                line=lineno,
                suggestion="Never pass user input to Jinja2 from_string or Template. Use precompiled templates.",
                cwe="CWE-94", agent="python-analyzer",
            ))
    return _assign_rule_ids(findings, "PY-064")


def _rule_52(ctx: _Ctx) -> list[Finding]:
    """CWE-362: TOCTOU race condition (os.path.exists then open)."""
    findings: list[Finding] = []
    func_defs = ctx.func_defs
    for fname, fnode in func_defs.items():
        code_block = ctx.lines[fnode.lineno - 1:fnode.end_lineno] if fnode.end_lineno else []
        block_text = "\n".join(code_block)
        if re.search(r'os\.path\.exists\s*\(', block_text) and re.search(r'(?:open|with open)\s*\(', block_text):
            findings.append(Finding(
                category="security", severity=Severity.MEDIUM,
                title=f"CWE-362: TOCTOU race condition in {fname}() at line {fnode.lineno}",
                description=f"os.path.exists() check followed by open() in `{fname}()` at L{fnode.lineno}.",
                line=fnode.lineno,
                suggestion="Use try/except FileNotFoundError around open() instead of pre-checking with exists().",
                cwe="CWE-362", agent="python-analyzer",
            ))
    return _assign_rule_ids(findings, "PY-065")


def _detect(code: str, filename: str = "", global_graph: object = None) -> list[Finding]:
    """Run all deterministic detection rules. Returns findings sorted by severity."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(code)
    except (SyntaxError, ValueError, UnicodeEncodeError):
        return []

    lines = code.splitlines()
    sans = _code_sans_strings(code)
    sans_comments = _code_sans_strings_and_comments(code)
    func_defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_defs[node.name] = node
    func_summaries = _load_cached_function_summaries(code, filename or "<stdin>")
    if func_summaries is None:
        func_summaries = _build_function_taint_summaries(tree, func_defs)
        _store_cached_function_summaries(code, filename or "<stdin>", func_summaries)
    summary_dependencies = _collect_function_dependencies(func_defs, filename or "<stdin>")

    if global_graph is not None:
        try:
            _record_function_summaries_in_global_graph(
                global_graph,
                filename=filename,
                func_summaries=func_summaries,
                summary_dependencies=summary_dependencies,
            )
        except Exception:
            pass

    # Build class-level context for Django CBV mixin detection.
    class_defs: dict[str, ast.ClassDef] = {}
    func_to_class: dict[int, ast.ClassDef] = {}
    fastapi_auth_aliases = _collect_fastapi_auth_aliases(tree)
    fastapi_guarded_receivers = _collect_fastapi_guarded_receivers(tree, fastapi_auth_aliases)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            class_defs[node.name] = node
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_to_class[id(item)] = node
    ctx = _Ctx(
        lines=lines, sans=sans, sans_comments=sans_comments, func_defs=func_defs, func_summaries=func_summaries,
        _tree=tree, filename=filename, global_graph=global_graph,
        class_defs=class_defs, func_to_class=func_to_class,
        fastapi_guarded_receivers=fastapi_guarded_receivers,
        fastapi_auth_aliases=fastapi_auth_aliases,
        framework=FrameworkFingerprint.from_source(code),
    )
    findings: list[Finding] = []
    # ── AST walk cache: pre-compute node lists per function ────
    _walk_cache: dict[int, list] = {}
    _orig_walk = ast.walk
    def _cached_walk(node):
        nid = id(node)
        if nid in _walk_cache:
            return iter(_walk_cache[nid])
        result = list(_orig_walk(node))
        _walk_cache[nid] = result
        return iter(result)
    ast.walk = _cached_walk
    for fnode in func_defs.values():
        _walk_cache[id(fnode)] = list(_orig_walk(fnode))

    for rule_fn in (
        _rule_01, _rule_02, _rule_03, _rule_04, _rule_05,
        _rule_06, _rule_07, _rule_08, _rule_09, _rule_10,
        _rule_11, _rule_12, _rule_13, _rule_14, _rule_15,
        _rule_16, _rule_17, _rule_18, _rule_19, _rule_20,
        _rule_21, _rule_22, _rule_23, _rule_24, _rule_25,
        _rule_26, _rule_27, _rule_28, _rule_29, _rule_30,
        _rule_31, _rule_32, _rule_33, _rule_34, _rule_35,
        _rule_36, _rule_37, _rule_38, _rule_39, _rule_40,
        _rule_41, _rule_42, _rule_43, _rule_44, _rule_45,
        _rule_46, _rule_47, _rule_48, _rule_49,
        _rule_50, _rule_51, _rule_52,
    ):
        findings.extend(rule_fn(ctx))

    # ── Restore original ast.walk ──────────────────────────────────────
    ast.walk = _orig_walk

    # ── Data science ruleset ───────────────────────────────────────────────
    _HAS_DS_IMPORTS = bool(re.search(r'import\s+(?:pandas|numpy|sklearn|tensorflow|torch|keras|matplotlib|scipy|seaborn|plotly)', code))
    if _HAS_DS_IMPORTS:
        try:
            from ansede_static.rulesets.datascience import analyze_datascience
            findings.extend(analyze_datascience(code, filename))
        except Exception:  # pragma: no cover
            pass

    # ── Entropy-based secret detection ────────────────────────────────────
    try:
        from ansede_static.entropy import scan_for_secrets
        # Only run if the file is not too large (avoid false positives in data files)
        # and not in a vendored dependency directory (Unicode data, minified JS etc.)
        if len(code) < 500_000 and not _is_vendored_path(filename):
            findings.extend(scan_for_secrets(code, filename))
    except Exception:  # pragma: no cover
        pass

    # ── Fast bail: skip rescore/guards/clustering if no findings ───────
    if not findings:
        return findings

    # ── Rescore confidence before guard analysis (guards get final say) ──
    findings = rescore_findings(findings)

    # ── Symbolic guard analysis ───────────────────────────────────────────
    if findings and ('if ' in code or 'assert ' in code):
        try:
            from ansede_static.engine.symbolic_guards import analyze_guards_python
            findings = analyze_guards_python(code, findings, filename=filename)
        except Exception:
            pass

    # ── Deduplicate by (title.lower(), line) then cluster by CWE+region+sink ──
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
    # Third: cluster by CWE family, region, and sink identity
    deduped = cluster_findings(deduped)

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

    # ── Finalize confidence defaults and generate auto-fixes ───────────────
    for f in filtered:
        if f.confidence <= 0.0:
            f.confidence = 1.0
        if not f.auto_fix:
            f.auto_fix = _generate_auto_fix(f, lines)

    filtered = _apply_python_noise_policy(filtered, filename)
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
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(code, filename=filename)
    except (SyntaxError, ValueError, UnicodeEncodeError):
        return

    func_defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_defs[node.name] = node

    if func_defs:
        try:
            func_summaries = _build_function_taint_summaries(tree, func_defs)
            summary_dependencies = _collect_function_dependencies(func_defs, filename or "<stdin>")
            _record_function_summaries_in_global_graph(
                global_graph,
                filename=filename,
                func_summaries=func_summaries,
                summary_dependencies=summary_dependencies,
            )
        except Exception:
            pass
        
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


# ── Vendored-path guard ─────────────────────────────────────────────────────


_VENDOR_RE = re.compile(r'(?:^|[/\\])(?:vendor|_vendor|node_modules|bower_components|third_party)(?:[/\\]|$)')


def _is_vendored_path(filename: str) -> bool:
    """Return True if *filename* is inside a vendored-dependency directory."""
    return bool(_VENDOR_RE.search(str(filename).replace("\\", "/")))


# ── Phase 3.5: High-resilience graceful failure subsystem ──────────────

def safe_parse_target(file_path: str) -> ast.AST | None:
    """Attempt to parse a Python source file with multiple encoding fallbacks.

    Invalid file encodings or syntax issues are logged as individual skipped
    tasks without crashing the active runner process.

    Returns:
        Parsed AST on success, None if all encoding attempts fail.
    """
    import sys as _sys
    encodings = ["utf-8", "latin-1", "cp1252"]
    for encoding in encodings:
        try:
            with open(file_path, "r", encoding=encoding) as f:
                return ast.parse(f.read(), filename=file_path)
        except (UnicodeDecodeError, SyntaxError):
            continue
    # Log parsing anomaly cleanly to standard error without crashing execution
    print(
        f"[WARN] Skipping corrupted parsing node location: {file_path}",
        file=_sys.stderr,
    )
    return None


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

    # ── Rust fast-path: skip analysis for trivially clean files ────────
    try:
        from ansede_static.engine.rust_parser import HAS_RUST_CORE, fast_parse  # noqa: PLC0415
    except ImportError:
        HAS_RUST_CORE = False  # noqa: F811
    if HAS_RUST_CORE:
        try:
            raw = fast_parse(code, "python", filename)
            if raw and raw.get("nodes"):
                nodes = raw["nodes"]
                # Quick heuristic: no call expressions, no imports, no
                # function or class definitions → trivially clean
                has_calls = any(n.get("kind") in ("call", "call_expression") for n in nodes)
                has_imports = any(n.get("kind") == "import_statement" for n in nodes)
                has_defs = any(n.get("kind") in ("function_definition", "class_definition", "decorated_definition") for n in nodes)
                has_assignments = any(n.get("kind") == "assignment" for n in nodes)
                if not has_calls and not has_imports and not has_assignments and not has_defs:
                    return result
        except Exception:
            pass

    try:
        findings = _detect(code, filename=filename, global_graph=global_graph)
    except (SyntaxError, ValueError, RecursionError, TypeError) as exc:
        result.parse_error = f"Internal analyzer error: {exc}"
        return result

    # Universal template engine pass (Jinja2 / Handlebars SSTI)
    try:
        for tpl in TemplateEngineDetector.detect_all_ssti(code, filename):
            findings.append(Finding(
                category="security",
                severity=Severity.CRITICAL if tpl.severity.upper() == "CRITICAL" else Severity.HIGH,
                title=f"{tpl.cwe}: Potential server-side template injection in {tpl.context}",
                description=(
                    f"Template sink `{tpl.sink_function}` receives potentially tainted template expression at "
                    f"line {tpl.line}. Dynamic template rendering can allow template-expression execution."
                ),
                line=tpl.line,
                suggestion="Avoid rendering user-controlled template fragments directly; pass data as context variables and keep template source static.",
                rule_id="PY-038",
                cwe=tpl.cwe,
                agent="python-analyzer",
                confidence=0.9,
                analysis_kind="template-ast",
                trace=(
                    TraceFrame(kind="source", label=f"template expression `{tpl.tainted_expr[:80]}`", line=tpl.line),
                    TraceFrame(kind="sink", label=f"sink `{tpl.sink_function}`", line=tpl.line),
                ),
            ))
    except Exception:
        pass

    # Template AST transpilation pass: find tainted template expressions.
    try:
        for node in template_taint_nodes(code, filename=filename):
            findings.append(Finding(
                category="security",
                severity=Severity.HIGH,
                title=f"CWE-1336: Tainted template expression in {node.engine} template at line {node.line}",
                description=(
                    f"Template AST node `{node.expression[:90]}` in {node.engine} {node.kind} contains request/user-controlled markers. "
                    "Treat this as executable template context unless values are strictly escaped or sandboxed."
                ),
                line=node.line,
                suggestion="Avoid concatenating user-controlled template expressions; keep templates static and pass data as context values.",
                rule_id="PY-038",
                cwe="CWE-1336",
                agent="python-analyzer",
                confidence=0.9,
                analysis_kind="template-ast",
                trace=(
                    TraceFrame(kind="source", label=f"template expression `{node.expression[:80]}`", line=node.line, start_column=node.column),
                    TraceFrame(kind="sink", label=f"template AST {node.kind}", line=node.line, start_column=node.column),
                ),
            ))
    except Exception:
        pass

    # ── IDE lattice confidence adjustment (mirrors the JS taint_checks path) ──
    # Functions whose return value is tracked as TAINTED in the GlobalGraph IDE
    # lattice have their findings' confidence boosted; CLEAN facts suppress it.
    if global_graph is not None and hasattr(global_graph, "adjust_confidence_from_ide"):
        adjusted_findings: list[Finding] = []
        for finding in findings:
            try:
                adjusted = global_graph.adjust_confidence_from_ide(
                    file_path=filename or "<stdin>",
                    function_name="<module>",
                    value_label="$ret",
                    base_confidence=finding.confidence,
                )
                if adjusted != finding.confidence:
                    finding = Finding(
                        category=finding.category,
                        severity=finding.severity,
                        title=finding.title,
                        description=finding.description,
                        line=finding.line,
                        suggestion=finding.suggestion,
                        rule_id=finding.rule_id,
                        cwe=finding.cwe,
                        agent=finding.agent,
                        confidence=adjusted,
                        auto_fix=finding.auto_fix,
                        explanation=finding.explanation,
                        trace=finding.trace,
                        analysis_kind=finding.analysis_kind,
                        triggering_code=finding.triggering_code,
                    )
            except Exception:
                pass
            adjusted_findings.append(finding)
        findings = adjusted_findings

    # ── STIR emission ─────────────────────────────────────────────────────
    # Populate the Shared Taint IR with sources and sinks from findings
    # so the IFDS solver can operate on a language-agnostic fact graph.
    try:
        from ansede_static.ir.stir import emit_python_stir

        stir_sources: list[tuple[str, str, int]] = []
        stir_sinks: list[tuple[str, str, int, str]] = []
        for f in findings:
            line = f.line or 1
            if f.trace:
                for frame in f.trace:
                    if frame.kind == "source":
                        stir_sources.append(("http_request" if "request" in frame.label.lower() else "user_input", frame.label[:60], line))
                    elif frame.kind == "sink":
                        stir_sinks.append(("code_exec" if "exec" in frame.label.lower() else "sql_query" if "sql" in frame.label.lower() else "sink", frame.label[:60], line, f.cwe or "CWE-unknown"))
            if f.cwe:
                stir_sinks.append(("pattern_match", f.title[:60], line, f.cwe))

        if stir_sources or stir_sinks:
            stir_model = emit_python_stir(
                code, filename,
                sources=stir_sources if stir_sources else None,
                sinks=stir_sinks if stir_sinks else None,
            )
            if global_graph is not None and hasattr(global_graph, "absorb_stir"):
                global_graph.absorb_stir(stir_model)
    except Exception:
        pass  # STIR emission is best-effort

    # ── Taint-aware confidence adjustment ────────────────────────────────
    # Demote HIGH/CRITICAL findings where no user input is visible reaching
    # the sink.  Pure pattern matches without taint evidence are demoted to
    # MEDIUM at most.  This is the single biggest precision improvement.
    _lines_cache = code.splitlines()

    def _has_user_input_nearby(lineno: int, window: int = 5) -> bool:
        start = max(0, lineno - 1 - window)
        end = min(len(_lines_cache), lineno + window)
        ctx = "\n".join(_lines_cache[start:end])
        return bool(_USER_INPUT_RE.search(ctx))

    _USER_INPUT_RE = re.compile(
        r'(?:request\.(?:args|form|json|data|values|get_json|get_data)|'
        r'request\.(?:GET|POST|FILES|COOKIES|headers)|'
        r'self\.request\.|'
        r'\.get\s*\(\s*["\']\w+|'
        r'request_body|body\s*=\s*request|'
        r'@app\.route|@bp\.route|'
        r'def\s+\w+\s*\(\s*(?:self,\s*)?(?:request|req)\b|'
        r'\+.*(?:user|input|param|query|search|data|body|name|id|key)|'
        r'f["\'].*\{|'
        r'\.format\s*\(|'
        r'%\s*[sd]\b|'
        r'sys\.argv|'
        r'os\.environ\b|'
        r'open\s*\([^)]*\+|'
        r'input\s*\(\s*\)|'
        r'read\s*\(\s*\))',
        re.IGNORECASE,
    )

    _HARDCODED_SQL_RE = re.compile(
        r'\.execute\s*\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE|PRAGMA|CREATE|ALTER|DROP|SET)\b',
        re.IGNORECASE,
    )
    _HARDCODED_CMD_RE = re.compile(
        r'subprocess\.(?:run|call|Popen|check_output)\s*\(\s*\[',
    )

    adjusted: list[Any] = []
    for f in findings:
        sev = str(f.severity.value) if hasattr(f.severity, 'value') else str(f.severity)
        cwe = (f.cwe or "").upper()
        line = f.line or 1
        title = (f.title or "").lower()

        if cwe == "CWE-117" or "log" in title or "Log Injection" in str(f.title or ""):
            # Log injection: only real if user data reaches the log call
            if not _has_user_input_nearby(line):
                if sev in ("critical", "high"):
                    f = Finding(
                        category=f.category, severity=Severity.LOW,
                        title=f.title, description=f.description, line=f.line,
                        suggestion=f.suggestion, rule_id=f.rule_id, cwe=f.cwe,
                        agent=f.agent, confidence=0.25, auto_fix=f.auto_fix,
                        explanation=f.explanation, trace=f.trace,
                        analysis_kind=f.analysis_kind, triggering_code=f.triggering_code,
                    )
        elif cwe == "CWE-89" or "sql" in title:
            # SQL injection: only real if user input is concatenated/interpolated
            ctx_lines = "\n".join(_lines_cache[max(0,line-3):min(len(_lines_cache),line+1)])
            is_hardcoded = bool(_HARDCODED_SQL_RE.search(ctx_lines))
            has_format = bool(re.search(r'[+%]|\bf\s*["\']|\bformat\s*\(', ctx_lines))
            if is_hardcoded and not has_format:
                if sev in ("critical", "high"):
                    f = Finding(
                        category=f.category, severity=Severity.MEDIUM,
                        title=f.title, description=f.description, line=f.line,
                        suggestion=f.suggestion, rule_id=f.rule_id, cwe=f.cwe,
                        agent=f.agent, confidence=0.35, auto_fix=f.auto_fix,
                        explanation=f.explanation, trace=f.trace,
                        analysis_kind=f.analysis_kind, triggering_code=f.triggering_code,
                    )
        elif cwe == "CWE-78" or "command" in title or "os.system" in title:
            # Command injection: only real if args are user-controlled
            ctx_lines = "\n".join(_lines_cache[max(0,line-3):min(len(_lines_cache),line+1)])
            is_hardcoded_cmd = bool(_HARDCODED_CMD_RE.search(ctx_lines))
            if is_hardcoded_cmd and not _has_user_input_nearby(line):
                if sev in ("critical", "high"):
                    f = Finding(
                        category=f.category, severity=Severity.MEDIUM,
                        title=f.title, description=f.description, line=f.line,
                        suggestion=f.suggestion, rule_id=f.rule_id, cwe=f.cwe,
                        agent=f.agent, confidence=0.35, auto_fix=f.auto_fix,
                        explanation=f.explanation, trace=f.trace,
                        analysis_kind=f.analysis_kind, triggering_code=f.triggering_code,
                    )
        elif cwe == "CWE-1188" or "SSTI" in title or "template" in title:
            # SSTI/template injection: Flask auto-escapes, demote unless |safe used
            ctx = "\n".join(_lines_cache[max(0,line-2):min(len(_lines_cache),line+2)])
            if "|safe" not in ctx and "Markup" not in ctx:
                f = Finding(
                    category=f.category, severity=Severity.LOW,
                    title=f.title, description=f.description, line=f.line,
                    suggestion=f.suggestion, rule_id=f.rule_id, cwe=f.cwe,
                    agent=f.agent, confidence=0.20, auto_fix=f.auto_fix,
                    explanation=f.explanation, trace=f.trace,
                    analysis_kind=f.analysis_kind, triggering_code=f.triggering_code,
                )
        elif cwe == "CWE-352" or "CSRF" in title:
            # CSRF: can't detect middleware, always uncertain
            f = Finding(
                category=f.category, severity=Severity.MEDIUM if sev in ("critical","high") else f.severity,
                title=f.title, description=f.description, line=f.line,
                suggestion=f.suggestion, rule_id=f.rule_id, cwe=f.cwe,
                agent=f.agent, confidence=0.30, auto_fix=f.auto_fix,
                explanation=f.explanation, trace=f.trace,
                analysis_kind=f.analysis_kind, triggering_code=f.triggering_code,
            )
        adjusted.append(f)

    findings = adjusted

    result.findings = findings
    return result


def analyze_file(path: str | Path, *, global_graph: object | None = None) -> AnalysisResult:
    """Convenience wrapper that reads a file then calls analyze_python."""
    p = Path(path)
    code = p.read_text(encoding="utf-8", errors="replace")
    return analyze_python(code, filename=str(p), global_graph=global_graph)
