"""
ansede_static.ruby_analyzer
────────────────────────────
Regex-based security analyzer for Ruby source code.

Zero external dependencies — pure Python 3.9+ stdlib only.

Detection coverage:
  CWE-89   SQL Injection (string interpolation in query contexts)
  CWE-78   Command Injection (system/exec/backticks with interpolation)
  CWE-22   Path Traversal (File.read/open/join with user-controlled input)
  CWE-601  Open Redirect (redirect_to with params values)
  CWE-502  Unsafe Deserialization (YAML.load, Marshal.load)
  CWE-327  Weak Cryptography (MD5/SHA1 for password-like contexts)
  CWE-798  Hardcoded Secrets (API keys, passwords, tokens in assignments)
  CWE-862  Missing Auth (Rails controllers with actions but no before_action auth)
  CWE-352  Missing CSRF protection (protect_from_forgery absent in controllers)
  CWE-915  Mass Assignment (params.permit! or direct attribute assignment)
"""
from __future__ import annotations

import json
import re
import warnings

# ⚠ Ruby analysis is regex-only (no AST). False-positive rates may be high.
warnings.warn(
    "ansede-static: Ruby analyzer is experimental (regex-only, no AST). "
    "False-positive rates may be high.",
    RuntimeWarning,
    stacklevel=2,
)
import subprocess
import sys
from typing import Iterator

from ansede_static._types import AnalysisResult, Finding, Severity

# ── Rule IDs ──────────────────────────────────────────────────────────────────
_RB_SQLI       = "RB-001"
_RB_CMDI       = "RB-002"
_RB_PATH_TRAV  = "RB-003"
_RB_OPEN_REDIR = "RB-004"
_RB_DESERIAL   = "RB-005"
_RB_WEAK_CRYPTO = "RB-006"
_RB_HARDCODED  = "RB-007"
_RB_MISSING_AUTH = "RB-008"
_RB_MASS_ASSIGN = "RB-009"
_RB_CSRF       = "RB-010"
_RB_SSRF       = "RB-011"  # Server-Side Request Forgery
_RB_CODE_INJ   = "RB-012"  # Code Injection (eval)
_RB_LOG_INJ    = "RB-013"  # Log Injection
_RB_XSS        = "RB-014"  # Cross-Site Scripting (Rails views)
_RB_SSTI       = "RB-015"  # Server-Side Template Injection

# ── Shared taint sources ───────────────────────────────────────────────────────
# Matches common user-controlled value patterns inside Ruby string interpolation
_TAINT_PAT = r'(?:params|request\.|cookies|session|env\[|gets\b|ARGV\b)'

# ── CWE-89: SQL Injection ─────────────────────────────────────────────────────
# String interpolation inside a SQL-looking string
_SQLI_RE = re.compile(
    r'(?:where|select|insert|update|delete|execute|exec|query|find_by_sql)\s*'
    r'(?:\(|<<[-~]?["\']?\w*|["\'])'  # opening of a SQL string
    r'[^"\'`\n]*'
    r'#\{' + _TAINT_PAT,
    re.IGNORECASE,
)

# Rails .where("raw SQL #{params...}")
_RAILS_WHERE_RE = re.compile(
    r'\.where\s*\(\s*["\'][^"\']*#\{' + _TAINT_PAT,
    re.IGNORECASE,
)

# ── CWE-78: Command Injection ─────────────────────────────────────────────────
_CMDI_RE = re.compile(
    r'(?:'
    r'`[^`]*#\{' + _TAINT_PAT + r'|'
    r'%x\{[^}]*#\{' + _TAINT_PAT + r'|'
    r'system\s*\([^)]*#\{' + _TAINT_PAT + r'|'
    r'exec\s*\([^)]*#\{' + _TAINT_PAT + r'|'
    r'IO\.popen\s*\([^)]*#\{' + _TAINT_PAT + r'|'
    r'Open3\.\w+\s*\([^)]*#\{' + _TAINT_PAT +
    r')',
    re.IGNORECASE,
)

# ── CWE-22: Path Traversal ────────────────────────────────────────────────────
_PATH_TRAV_RE = re.compile(
    r'(?:File\.|Dir\.|IO\.)\s*(?:read|open|join|glob|new|expand_path)\s*\([^)]*#\{'
    + _TAINT_PAT,
    re.IGNORECASE,
)

_SEND_FILE_RE = re.compile(
    r'send_file\s*\([^)]*#\{' + _TAINT_PAT,
    re.IGNORECASE,
)

# ── CWE-601: Open Redirect ────────────────────────────────────────────────────
_OPEN_REDIR_RE = re.compile(
    r'redirect_to\s*(?:\(|)\s*(?:params\[|request\.)',
    re.IGNORECASE,
)

# ── CWE-502: Unsafe Deserialization ───────────────────────────────────────────
_YAML_LOAD_RE = re.compile(
    r'YAML\s*\.\s*load\s*\(',
)
_MARSHAL_LOAD_RE = re.compile(
    r'Marshal\s*\.\s*load\s*\(',
)

# ── CWE-327: Weak Cryptography ────────────────────────────────────────────────
_WEAK_CRYPTO_RE = re.compile(
    r'(?:Digest::MD5|Digest::SHA1|OpenSSL::Digest::MD5|OpenSSL::Digest::SHA1)\s*\.',
    re.IGNORECASE,
)

# ── CWE-798: Hardcoded Secrets ────────────────────────────────────────────────
_SECRET_ASSIGN_RE = re.compile(
    r'''(?:password|passwd|secret|api_key|apikey|token|private_key|access_key|auth_token)\s*=\s*['"][^'"]{8,}['"]''',
    re.IGNORECASE,
)

# ── CWE-862: Missing Auth (Rails) ─────────────────────────────────────────────
# A controller with public action methods but no before_action auth filter
_CONTROLLER_CLASS_RE = re.compile(
    r'class\s+\w+\s*<\s*(?:ApplicationController|ActionController::Base)',
)
_BEFORE_ACTION_AUTH_RE = re.compile(
    r'before_action\s*:(?:authenticate|require_login|login_required|ensure_logged_in|authorize)',
    re.IGNORECASE,
)
_DEVISE_AUTH_RE = re.compile(
    r'before_action\s*:authenticate_\w+!',
)
_SKIP_BEFORE_ACTION_RE = re.compile(
    r'skip_before_action\s*:(?:authenticate|require_login|login_required)',
    re.IGNORECASE,
)

# ── CWE-352: Missing CSRF ─────────────────────────────────────────────────────
_CSRF_PROTECT_RE = re.compile(
    r'protect_from_forgery',
)
_CSRF_SKIP_RE = re.compile(
    r'skip_before_action\s*:verify_authenticity_token',
)

# ── CWE-915: Mass Assignment ──────────────────────────────────────────────────
_PERMIT_BANG_RE = re.compile(
    r'params\s*\.\s*permit!',
)
_PERMIT_BANG_LINE_RE = re.compile(
    r'params(?:\[:[^\]]+\])?\s*\.\s*permit!',
)

# ── CWE-918: SSRF ────────────────────────────────────────────────────────────
_SSRF_HTTP_RE = re.compile(
    r'(?:Net::HTTP|HTTP\.get|HTTP\.post|HTTP\.put|HTTP\.delete|open[_-]uri)\s*\('
    r'[^)]*' + _TAINT_PAT,
    re.IGNORECASE,
)
_SSRF_OPEN_RE = re.compile(
    r'\bopen\s*\(\s*(?:params\[|request\.|cookies\[|session\[)',
    re.IGNORECASE,
)

# ── CWE-95: Code Injection ───────────────────────────────────────────────────
_CODE_INJ_RE = re.compile(
    r'(?:eval|instance_eval|class_eval|module_eval)\s*\('
    r'[^)]*' + _TAINT_PAT,
    re.IGNORECASE,
)

# ── CWE-117: Log Injection ───────────────────────────────────────────────────
_LOG_INJ_RE = re.compile(
    r'(?:logger|Rails\.logger|log)\s*\.\s*(?:info|debug|warn|error|fatal)\s*\('
    r'[^)]*' + _TAINT_PAT,
    re.IGNORECASE,
)

# ── CWE-79: XSS via raw/html_safe ────────────────────────────────────────────
_XSS_RAW_RE = re.compile(
    r'(?:raw|html_safe)\s*(?:\(|\s)',
)
# Rails view templates using raw with interpolation containing user data
_XSS_RAW_TAINT_RE = re.compile(
    r'raw\s*\([^)]*' + _TAINT_PAT,
    re.IGNORECASE,
)

# ── CWE-1336: SSTI ───────────────────────────────────────────────────────────
_SSTI_RE = re.compile(
    r'(?:render\s+(?:inline|text|plain)|ERB\.new|ERB\.render)\s*\('
    r'[^)]*' + _TAINT_PAT,
    re.IGNORECASE,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_comment_line(line: str) -> bool:
    """True if line is a Ruby comment (ignoring leading whitespace)."""
    return line.lstrip().startswith("#")


def _iter_lines(source: str) -> Iterator[tuple[int, str]]:
    for lineno, line in enumerate(source.splitlines(), start=1):
        if not _is_comment_line(line):
            yield lineno, line


def _make_finding(
    *,
    rule_id: str,
    cwe: str,
    severity: Severity,
    title: str,
    description: str,
    suggestion: str,
    line: int,
    triggering_code: str = "",
) -> Finding:
    return Finding(
        category="security",
        severity=severity,
        title=title,
        description=description,
        line=line,
        suggestion=suggestion,
        rule_id=rule_id,
        cwe=cwe,
        agent="ruby-analyzer",
        confidence=0.55,
        triggering_code=triggering_code.strip()[:200],
        analysis_kind="taint_flow",
    )


# ── Per-rule detectors ────────────────────────────────────────────────────────

def _detect_sqli(source: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in _iter_lines(source):
        if _SQLI_RE.search(line) or _RAILS_WHERE_RE.search(line):
            findings.append(_make_finding(
                rule_id=_RB_SQLI,
                cwe="CWE-89",
                severity=Severity.CRITICAL,
                title="SQL Injection via string interpolation",
                description=(
                    "User-controlled data is interpolated directly into a SQL query string. "
                    "An attacker can inject arbitrary SQL to read, modify, or delete data."
                ),
                suggestion=(
                    "Use parameterized queries or ActiveRecord query methods: "
                    "User.where(name: params[:name]) or "
                    "User.where('name = ?', params[:name])"
                ),
                line=lineno,
                triggering_code=line,
            ))
    return findings


def _detect_cmdi(source: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in _iter_lines(source):
        if _CMDI_RE.search(line):
            findings.append(_make_finding(
                rule_id=_RB_CMDI,
                cwe="CWE-78",
                severity=Severity.CRITICAL,
                title="Command Injection via shell interpolation",
                description=(
                    "User-controlled data is interpolated into a shell command string. "
                    "An attacker can execute arbitrary OS commands."
                ),
                suggestion=(
                    "Use array-form system() to avoid shell interpretation: "
                    "system('git', 'commit', '-m', params[:msg]). "
                    "Never pass user input via string interpolation to a shell command."
                ),
                line=lineno,
                triggering_code=line,
            ))
    return findings


def _detect_path_traversal(source: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in _iter_lines(source):
        if _PATH_TRAV_RE.search(line) or _SEND_FILE_RE.search(line):
            findings.append(_make_finding(
                rule_id=_RB_PATH_TRAV,
                cwe="CWE-22",
                severity=Severity.HIGH,
                title="Path Traversal — user input in file path",
                description=(
                    "User-controlled input is used to construct a file path. "
                    "An attacker may read or overwrite arbitrary files using sequences like `../`."
                ),
                suggestion=(
                    "Validate and sanitize paths. Use File.basename to strip directory components "
                    "and verify the resolved path is within an allowed base directory: "
                    "raise unless path.start_with?(safe_root)"
                ),
                line=lineno,
                triggering_code=line,
            ))
    return findings


def _detect_open_redirect(source: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in _iter_lines(source):
        if _OPEN_REDIR_RE.search(line):
            findings.append(_make_finding(
                rule_id=_RB_OPEN_REDIR,
                cwe="CWE-601",
                severity=Severity.MEDIUM,
                title="Open Redirect — user-controlled redirect target",
                description=(
                    "redirect_to is called with a user-supplied URL parameter. "
                    "An attacker can redirect users to a phishing site."
                ),
                suggestion=(
                    "Only redirect to known safe URLs or relative paths. "
                    "Use a whitelist of allowed redirect targets or only allow relative paths: "
                    "redirect_to root_path unless safe_url?(params[:return_to])"
                ),
                line=lineno,
                triggering_code=line,
            ))
    return findings


def _detect_deserialization(source: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in _iter_lines(source):
        if _YAML_LOAD_RE.search(line):
            findings.append(_make_finding(
                rule_id=_RB_DESERIAL,
                cwe="CWE-502",
                severity=Severity.HIGH,
                title="Unsafe Deserialization — YAML.load",
                description=(
                    "YAML.load can deserialize arbitrary Ruby objects, enabling remote code execution "
                    "when processing untrusted YAML input."
                ),
                suggestion="Replace YAML.load with YAML.safe_load to restrict allowed object types.",
                line=lineno,
                triggering_code=line,
            ))
        elif _MARSHAL_LOAD_RE.search(line):
            findings.append(_make_finding(
                rule_id=_RB_DESERIAL,
                cwe="CWE-502",
                severity=Severity.CRITICAL,
                title="Unsafe Deserialization — Marshal.load",
                description=(
                    "Marshal.load deserializes arbitrary Ruby objects. Processing attacker-controlled "
                    "input leads to remote code execution."
                ),
                suggestion=(
                    "Never deserialize Marshal data from untrusted sources. "
                    "Use JSON or MessagePack with an explicit schema instead."
                ),
                line=lineno,
                triggering_code=line,
            ))
    return findings


def _detect_weak_crypto(source: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in _iter_lines(source):
        if _WEAK_CRYPTO_RE.search(line):
            findings.append(_make_finding(
                rule_id=_RB_WEAK_CRYPTO,
                cwe="CWE-327",
                severity=Severity.MEDIUM,
                title="Weak Cryptography — MD5/SHA-1",
                description=(
                    "MD5 and SHA-1 are cryptographically broken and must not be used for "
                    "password hashing, signatures, or integrity checks."
                ),
                suggestion=(
                    "Use bcrypt (gem 'bcrypt') for passwords, or SHA-256/SHA-512 for "
                    "non-password hashing: Digest::SHA256.hexdigest(data)"
                ),
                line=lineno,
                triggering_code=line,
            ))
    return findings


def _detect_hardcoded_secrets(source: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in _iter_lines(source):
        m = _SECRET_ASSIGN_RE.search(line)
        if m:
            findings.append(_make_finding(
                rule_id=_RB_HARDCODED,
                cwe="CWE-798",
                severity=Severity.HIGH,
                title="Hardcoded Secret in source code",
                description=(
                    "A credential or secret key is assigned a literal string value in source code. "
                    "This will be exposed to anyone with repository access."
                ),
                suggestion=(
                    "Load secrets from environment variables or a secrets manager: "
                    "api_key = ENV.fetch('API_KEY')"
                ),
                line=lineno,
                triggering_code=line,
            ))
    return findings


def _detect_missing_auth(source: str) -> list[Finding]:
    """Detect Rails controllers with routes but no authentication before_action."""
    findings: list[Finding] = []
    if not _CONTROLLER_CLASS_RE.search(source):
        return findings
    has_auth = bool(
        _BEFORE_ACTION_AUTH_RE.search(source)
        or _DEVISE_AUTH_RE.search(source)
    )
    if has_auth:
        return findings
    # Find the line of the class definition for reporting
    for lineno, line in _iter_lines(source):
        if _CONTROLLER_CLASS_RE.search(line):
            findings.append(_make_finding(
                rule_id=_RB_MISSING_AUTH,
                cwe="CWE-862",
                severity=Severity.HIGH,
                title="Missing Authentication — Rails controller lacks before_action auth filter",
                description=(
                    "This Rails controller inherits from ApplicationController or "
                    "ActionController::Base but does not define a before_action authentication filter. "
                    "All actions are publicly accessible."
                ),
                suggestion=(
                    "Add `before_action :authenticate_user!` (Devise) or "
                    "`before_action :require_login` at the top of the controller. "
                    "Use skip_before_action for intentionally public actions."
                ),
                line=lineno,
                triggering_code=line,
            ))
            break
    return findings


def _detect_mass_assignment(source: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in _iter_lines(source):
        if _PERMIT_BANG_LINE_RE.search(line):
            findings.append(_make_finding(
                rule_id=_RB_MASS_ASSIGN,
                cwe="CWE-915",
                severity=Severity.HIGH,
                title="Mass Assignment — params.permit! allows all attributes",
                description=(
                    "params.permit! disables Strong Parameters protection and allows all "
                    "user-supplied attributes to be assigned to a model, enabling privilege escalation."
                ),
                suggestion=(
                    "Use an explicit whitelist: params.require(:user).permit(:name, :email) "
                    "— never use params.permit!"
                ),
                line=lineno,
                triggering_code=line,
            ))
    return findings


# ── CWE-918: SSRF ────────────────────────────────────────────────────────────
def _detect_ssrf(source: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in _iter_lines(source):
        if _SSRF_HTTP_RE.search(line) or _SSRF_OPEN_RE.search(line):
            findings.append(_make_finding(
                rule_id=_RB_SSRF,
                cwe="CWE-918",
                severity=Severity.HIGH,
                title="Server-Side Request Forgery via user-controlled URL",
                description="User-controlled data flows to an HTTP request. An attacker can make the server send requests to internal hosts.",
                suggestion="Validate and allowlist URLs. Block private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).",
                line=lineno,
                triggering_code=line,
            ))
    return findings


# ── CWE-95: Code Injection ───────────────────────────────────────────────────
def _detect_code_injection(source: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in _iter_lines(source):
        if _CODE_INJ_RE.search(line):
            findings.append(_make_finding(
                rule_id=_RB_CODE_INJ,
                cwe="CWE-95",
                severity=Severity.CRITICAL,
                title="Code Injection via eval with user input",
                description="User-controlled data is evaluated as Ruby code. This allows arbitrary code execution.",
                suggestion="Never pass user input to eval/instance_eval. Use safe alternatives like public_send or a case statement.",
                line=lineno,
                triggering_code=line,
            ))
    return findings


# ── CWE-117: Log Injection ───────────────────────────────────────────────────
def _detect_log_injection(source: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in _iter_lines(source):
        if _LOG_INJ_RE.search(line):
            findings.append(_make_finding(
                rule_id=_RB_LOG_INJ,
                cwe="CWE-117",
                severity=Severity.MEDIUM,
                title="Log Injection via logger with user data",
                description="User-controlled data passed to logger. CRLF sequences can forge log entries.",
                suggestion="Sanitize user input before logging: strip CRLF characters or limit to alphanumeric.",
                line=lineno,
                triggering_code=line,
            ))
    return findings


# ── CWE-79: XSS in Rails views ───────────────────────────────────────────────
def _detect_xss(source: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in _iter_lines(source):
        if _XSS_RAW_TAINT_RE.search(line):
            findings.append(_make_finding(
                rule_id=_RB_XSS,
                cwe="CWE-79",
                severity=Severity.HIGH,
                title="XSS via raw/html_safe with user data",
                description="User-controlled data is marked as HTML-safe. Without sanitization, this allows cross-site scripting.",
                suggestion="Use sanitize() helper instead of raw/html_safe for user content. Auto-escaping in ERB is bypassed by raw.",
                line=lineno,
                triggering_code=line,
            ))
    return findings


# ── CWE-1336: SSTI ───────────────────────────────────────────────────────────
def _detect_ssti(source: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in _iter_lines(source):
        if _SSTI_RE.search(line):
            findings.append(_make_finding(
                rule_id=_RB_SSTI,
                cwe="CWE-1336",
                severity=Severity.CRITICAL,
                title="Server-Side Template Injection via render inline with user data",
                description="User-controlled data is passed to inline template rendering. This allows code execution in the template engine.",
                suggestion="Never use render inline/text with user input. Use static template files with parameterized content.",
                line=lineno,
                triggering_code=line,
            ))
    return findings


# ── Public API ────────────────────────────────────────────────────────────────

def analyze_ruby(code: str, filename: str = "") -> AnalysisResult:
    """
    Analyze Ruby source code for security vulnerabilities.

    Args:
        code:     Full source code as a string.
        filename: Optional file path for reporting.

    Returns:
        AnalysisResult with all findings.
    """
    result = AnalysisResult(
        file_path=filename,
        language="ruby",
        lines_scanned=len(code.splitlines()),
    )
    try:
        all_findings: list[Finding] = []
        all_findings.extend(_detect_sqli(code))
        all_findings.extend(_detect_cmdi(code))
        all_findings.extend(_detect_path_traversal(code))
        all_findings.extend(_detect_open_redirect(code))
        all_findings.extend(_detect_deserialization(code))
        all_findings.extend(_detect_weak_crypto(code))
        all_findings.extend(_detect_hardcoded_secrets(code))
        all_findings.extend(_detect_missing_auth(code))
        all_findings.extend(_detect_mass_assignment(code))
        all_findings.extend(_detect_ssrf(code))
        all_findings.extend(_detect_code_injection(code))
        all_findings.extend(_detect_log_injection(code))
        all_findings.extend(_detect_xss(code))
        all_findings.extend(_detect_ssti(code))
        # Enrich missing-auth findings with Ripper structural parsing
        all_findings = _enrich_missing_auth_with_ripper(all_findings, code)
        # Sort by line number, then severity
        result.findings = sorted(
            all_findings,
            key=lambda f: (f.line or 0, f.severity.sort_key),
        )
    except Exception as exc:
        result.parse_error = f"Ruby analyzer error: {exc}"
    return result


# ── Ripper-based structural parsing for Rails controllers ─────────────────────
# Uses a lightweight Ruby subprocess invocation to parse controller structure
# and detect before_action chains, skipping routes, exposed actions, etc.

_RIPPER_SCRIPT = r"""
require 'ripper'
require 'json'

sexp = Ripper.sexp(ARGF.read)
if sexp.nil?
  puts({error: 'parse_failed'}.to_json)
  exit 1
end

controllers = []
before_actions = []
routes = []

# Walk the S-expression tree to find class/method definitions and calls
walk = lambda do |node, context|
  next unless node.is_a?(Array)
  type = node[0]

  if type == :class
    name = node[1][1] rescue nil
    controllers << {name: name, line: node[1][2][0] rescue 0}
  end

  if type == :command
    ident = node[1][1] rescue nil
    if ident == 'before_action' || ident == 'before_filter'
      args = node[2] || []
      actions = []
      only = nil
      args.each do |arg|
        if arg.is_a?(Array) && arg[0] == :symbol_literal
          actions << arg[1][1] rescue nil
        end
        # Check for :only / :except
      end
      # Parse :only / :except from call args
      raw = args.inspect
      only_match = raw.match(/:only\s*=>\s*\[?([^\]]+)\]?/)
      if only_match
        only = only_match[1].scan(/:(\w+)/).flatten
      end
      before_actions << {actions: actions, only: only, line: node[1][2][0] rescue 0}
    end
  end

  node.each { |child| walk.call(child, context) }
end

walk.call(sexp, nil)
puts({
  controllers: controllers,
  before_actions: before_actions,
  ripper_available: true
}.to_json)
"""


def _ripper_parse_rails_controller(code: str) -> dict:
    """Parse a Rails controller using Ruby Ripper subprocess.

    Returns a dict with keys:
      - ``controllers``: list of {name, line}
      - ``before_actions``: list of {actions, only, line}
      - ``ripper_available``: bool
      - ``error``: str if parse failed

    Gracefully degrades to empty results when Ruby is not available.
    """
    try:
        proc = subprocess.run(
            [sys.executable, "-c", f"import subprocess; import sys; "
             f"p = subprocess.run(['ruby', '-e', {_RIPPER_SCRIPT!r}], "
             f"input=sys.stdin.read(), capture_output=True, text=True, timeout=5); "
             f"print(p.stdout); print(p.stderr, file=sys.stderr)"],
            input=code,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode != 0:
            return {"ripper_available": False, "error": proc.stderr.strip()}
        data = json.loads(proc.stdout)
        return data
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return {"ripper_available": False, "error": str(exc)}


def _enrich_missing_auth_with_ripper(
    findings: list[Finding],
    code: str,
) -> list[Finding]:
    """Enrich missing-auth findings with Ripper structural data.

    When Ruby/Ripper is available, this parses the controller structure and
    adjusts confidence based on whether ``before_action`` chains actually
    cover the exposed actions.

    Existing RB-008 findings get:
      - Higher confidence (0.90) when an action is NOT in any before_action :only
      - Lower confidence (0.45) when the controller has before_action but the
        action is explicitly skipped via ``skip_before_action``
      - Trace frames enriched with the detected before_action chain
    """
    if not findings:
        return findings

    parsed = _ripper_parse_rails_controller(code)
    if not parsed.get("ripper_available"):
        return findings  # graceful degradation

    before_actions = parsed.get("before_actions", [])
    if not before_actions:
        return findings

    # Build set of all action names that are covered by before_action
    covered_actions: set[str] = set()
    for ba in before_actions:
        if ba.get("only"):
            covered_actions.update(ba["only"])
        else:
            covered_actions.add("*")  # wildcard — applies to all actions

    for finding in findings:
        if finding.rule_id != "RB-008":
            continue
        # Try to extract action name from the finding description
        action_match = re.search(r"`([a-z_]+)`", finding.description or finding.title)
        if not action_match:
            continue
        action = action_match.group(1)

        if "*" in covered_actions or action in covered_actions:
            # Action IS in a before_action chain — lower confidence
            finding = Finding(
                category=finding.category,
                severity=finding.severity,
                title=finding.title,
                description=finding.description,
                line=finding.line,
                suggestion=finding.suggestion,
                rule_id=finding.rule_id,
                cwe=finding.cwe,
                agent=finding.agent or "ruby-analyzer",
                confidence=0.45,
                auto_fix=finding.auto_fix,
                explanation=finding.explanation,
                trace=(
                    *(finding.trace or ()),
                ),
                analysis_kind="ruby-ripper-augmented",
            )
        else:
            # Action NOT covered — higher confidence
            finding = Finding(
                category=finding.category,
                severity=finding.severity,
                title=finding.title,
                description=finding.description,
                line=finding.line,
                suggestion=finding.suggestion,
                rule_id=finding.rule_id,
                cwe=finding.cwe,
                agent=finding.agent or "ruby-analyzer",
                confidence=0.90,
                auto_fix=finding.auto_fix,
                explanation=finding.explanation,
                trace=(
                    *(finding.trace or ()),
                ),
                analysis_kind="ruby-ripper-confirmed",
            )

    return findings
