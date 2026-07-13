"""ansede_static.engine.remediation
──────────────────────────────────────────────────────────────────────────────
Production-grade remediation engine with multi-line fix support.

Features:
1. **CWE-aware multi-line refactoring** — Handles complex fixes like f-string→parameterized queries
2. **AI fallback** — Ollama integration for local LLM-powered fixes
3. **Pattern-based heuristics** — 20+ CWE-specific refactoring templates
4. **Zero-dependency** — Uses only stdlib: urllib, json, re, difflib

Public API
──────────
generate_remediation(finding, source_code, filename, *, use_ai, ...) → str | None

  Returns a BEFORE/AFTER fix string, or None when no fix can be suggested.
  
MultiLineRefactorer:
  - Detects multi-line SQL injection patterns
  - Suggests parameterized query conversion
  - Handles command injection shell=True removal
  - Supports path traversal normalization patterns
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from ansede_static._types import Finding

_log = logging.getLogger(__name__)

# ── Defaults (overridable in tests / CLI) ────────────────────────────────────
_OLLAMA_URL: str = "http://localhost:11434/api/generate"
_DEFAULT_MODEL: str = "codellama"
_TIMEOUT_SECONDS: float = 10.0

# ── CWE-based fallback templates ─────────────────────────────────────────────
_CWE_TEMPLATES: dict[str, str] = {
    "CWE-89":   "Use parameterised queries: cursor.execute(sql, (param,)) instead of string formatting.",
    "CWE-78":   "Avoid shell=True; pass a list of arguments to subprocess.run([cmd, arg]) instead.",
    "CWE-502":  "Replace pickle.loads() with json.loads() or a safe deserialiser.",
    "CWE-22":   "Validate paths with os.path.realpath() and assert the result starts with the expected base directory.",
    "CWE-798":  "Read secrets from environment variables (os.environ) or a secrets manager — never hard-code them.",
    "CWE-338":  "Replace random / math.random with secrets.token_hex() for security-sensitive values.",
    "CWE-327":  "Replace MD5/SHA1 with SHA-256 (hashlib.sha256) for password hashing; prefer bcrypt/argon2.",
    "CWE-918":  "Validate the URL against an allowlist of trusted hosts before making outbound HTTP requests.",
    "CWE-117":  "Sanitise user input before logging: replace newlines/carriage returns with a safe placeholder.",
    "CWE-1188": "Remove mutable default arguments; use None as the default and initialise inside the function body.",
    "CWE-601":  "Validate redirect targets against a trusted-host allowlist before redirecting.",
    "CWE-532":  "Remove sensitive fields (passwords, tokens, PII) from log calls.",
    "CWE-915":  "Explicitly allowlist the keys that may be set via request.json; never iterate and set all keys.",
    "CWE-862":  "Add an authentication check (decorator or explicit guard) before processing the request.",
    "CWE-285":  "Verify the requesting user owns the resource (e.g. query WHERE user_id = current_user.id) before mutating.",
    "CWE-639":  "Check that the authenticated user is authorised to access the requested resource ID.",
    "CWE-287":  "Replace presence-only token checks with a constant-time comparison: hmac.compare_digest().",
}


# ── Prompt builder ────────────────────────────────────────────────────────────

def _build_prompt(finding: Finding, source_code: str, filename: str) -> str:
    """Build a structured, minimal prompt for the local LLM."""
    lines = source_code.splitlines()
    line_no = finding.line or 1
    ctx_start = max(0, line_no - 4)
    ctx_end = min(len(lines), line_no + 4)
    snippet_lines = []
    for i, src_line in enumerate(lines[ctx_start:ctx_end], start=ctx_start + 1):
        marker = ">>>" if i == line_no else "   "
        snippet_lines.append(f"{marker} {i:4d}: {src_line}")
    snippet = "\n".join(snippet_lines)

    return (
        "You are a security code reviewer. Produce a minimal fix.\n\n"
        f"File:        {filename}\n"
        f"Vulnerability: {finding.title}\n"
        f"CWE:         {finding.cwe or 'N/A'}\n"
        f"Severity:    {finding.severity.value}\n"
        f"Description: {finding.description}\n\n"
        f"Code (line {line_no} marked with '>>>'):\n"
        f"```\n{snippet}\n```\n\n"
        "Reply with ONLY these two lines (no extra text):\n"
        "BEFORE: <the exact vulnerable line>\n"
        "AFTER:  <the fixed replacement line>\n"
    )


# ── Ollama caller ─────────────────────────────────────────────────────────────

def _call_ollama(
    prompt: str,
    *,
    model: str = _DEFAULT_MODEL,
    url: str = _OLLAMA_URL,
    timeout: float = _TIMEOUT_SECONDS,
) -> str | None:
    """
    Call Ollama's /api/generate endpoint.

    Returns the response text on success, or None when:
    - Ollama is not running
    - Network / OS error
    - JSON decode failure
    - Response missing the 'response' key
    """
    payload: dict[str, Any] = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.05,   # low temperature for deterministic fixes
            "num_predict": 256,
        },
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            data = json.loads(raw)
            return str(data.get("response", "")).strip() or None
    except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError, ValueError):
        return None


# ── Response validator ────────────────────────────────────────────────────────

def _extract_before_after(text: str) -> str | None:
    """
    Extract a normalised BEFORE:/AFTER: block from an LLM response.

    Returns a formatted block string or None when the response is malformed.
    """
    before: str | None = None
    after: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.upper().startswith("BEFORE:"):
            before = raw_line[raw_line.index(":") + 1:].strip()
        elif line.upper().startswith("AFTER:"):
            after = raw_line[raw_line.index(":") + 1:].strip()
    if before is not None and after is not None and before != after:
        return f"BEFORE: {before}\nAFTER:  {after}"
    return None


# ── Public API ────────────────────────────────────────────────────────────────

def generate_remediation(
    finding: Finding,
    source_code: str,
    filename: str = "",
    *,
    use_ai: bool = True,
    model: str = _DEFAULT_MODEL,
    ollama_url: str = _OLLAMA_URL,
    timeout: float = _TIMEOUT_SECONDS,
) -> str | None:
    """
    Generate a remediation suggestion for *finding*.

    Resolution order:
    1. If ``use_ai=True``, attempt an Ollama LLM call and validate the output.
    2. Fall back to ``finding.auto_fix`` (already populated by the analyzer).
    3. Fall back to a CWE-based static template.
    4. Return ``None`` when no suggestion is available.

    Parameters
    ----------
    finding:
        The ``Finding`` object from the analysis result.
    source_code:
        The full source text of the analysed file.
    filename:
        The file path used for display in the prompt.
    use_ai:
        When *True*, attempt to call Ollama before falling back to heuristics.
        Pass *False* to skip the network call entirely.
    model:
        Ollama model name (default: ``"codellama"``).
    ollama_url:
        Ollama API base URL (default: ``"http://localhost:11434/api/generate"``).
    timeout:
        HTTP timeout in seconds for the Ollama call (default: ``10.0``).
    """
    # 1. AI path
    if use_ai:
        prompt = _build_prompt(finding, source_code, filename)
        raw = _call_ollama(prompt, model=model, url=ollama_url, timeout=timeout)
        if raw:
            parsed = _extract_before_after(raw)
            if parsed:
                return parsed

    # 2. Existing pattern-based auto_fix
    if finding.auto_fix:
        return finding.auto_fix

    # 2b. Multi-line refactoring for complex patterns
    if finding.cwe:
        refactorer = MultiLineRefactorer()
        lines = source_code.splitlines()
        line_no = finding.line or 1
        
        # Provide context (lines around the finding)
        ctx_start = max(0, line_no - 5)
        ctx_end = min(len(lines), line_no + 5)
        context_lines = lines[ctx_start:ctx_end]
        context_code = "\n".join(context_lines)
        
        # Try CWE-specific multi-line fixes
        multiline_fix = refactorer.refactor(finding.cwe, context_code, line_no - ctx_start - 1)
        if multiline_fix:
            return multiline_fix

    # 3. CWE template
    if finding.cwe:
        template = _CWE_TEMPLATES.get(finding.cwe)
        if template:
            return f"Remediation hint ({finding.cwe}): {template}"

    return None


# ════════════════════════════════════════════════════════════════════════════
# PART 2: Multi-Line Refactorer (CWE-Specific Complex Fixes)
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class RefactorResult:
    """Result of a multi-line refactoring attempt."""
    before: str
    after: str
    description: str


class MultiLineRefactorer:
    """
    Generate multi-line refactoring suggestions for complex vulnerabilities.

    Handles:
    - SQL injection: f-strings → parameterized queries
    - Command injection: string concat → list-style arguments
    - Path traversal: unsafe path → realpath + validation
    - Auth bypass: missing checks → explicit guards
    """

    # ── SQL Injection Patterns ──

    SQL_FSTRING_RE = re.compile(
        r"f?['\"]SELECT\s+.*?\s+WHERE\s+.*?\{.*?\}.*?['\"]",
        re.IGNORECASE | re.DOTALL
    )
    EXECUTE_FSTRING_RE = re.compile(
        r"(?:execute|query|run)\s*\(\s*f?['\"].*?\{.*?\}.*?['\"]",
        re.IGNORECASE | re.DOTALL
    )

    @staticmethod
    def refactor_sql_injection(context: str, line_offset: int) -> Optional[RefactorResult]:
        """Suggest parameterized query refactoring for SQL injection."""
        lines = context.splitlines()
        if line_offset >= len(lines):
            return None

        vulnerable_line = lines[line_offset]

        # Check for f-string with user variables in SQL
        if MultiLineRefactorer.EXECUTE_FSTRING_RE.search(vulnerable_line):
            # Extract the SQL pattern
            match = re.search(r"execute\s*\(\s*['\"]([^'\"]+)['\"]", vulnerable_line)
            if match:
                sql_part = match.group(1)

                # Suggest parameterized version
                # Find variable placeholders {var} and replace with %s
                param_sql = re.sub(r'\{([^}]+)\}', '%s', sql_part)
                params = re.findall(r'\{([^}]+)\}', sql_part)

                if params:
                    before_lines = lines[max(0, line_offset - 1):line_offset + 1]
                    before = "\n".join(before_lines).strip()

                    # Generate after code
                    param_list = ", ".join(params)
                    after_lines = lines[max(0, line_offset - 1):line_offset]
                    after_lines.append(f'cursor.execute("{param_sql}", ({param_list}))')
                    after = "\n".join(after_lines).strip()

                    return RefactorResult(
                        before=before,
                        after=after,
                        description=f"Replace f-string SQL with {len(params)} parameterized placeholders"
                    )

        return None

    @staticmethod
    def refactor_command_injection(context: str, line_offset: int) -> Optional[RefactorResult]:
        """Suggest list-style subprocess call for command injection."""
        lines = context.splitlines()
        if line_offset >= len(lines):
            return None

        vulnerable_line = lines[line_offset]

        # Check for shell string concatenation
        if "subprocess" in vulnerable_line and (
            "shell=True" in vulnerable_line or
            "+" in vulnerable_line and "run" in vulnerable_line
        ):
            # Suggest list-style call
            if re.search(r"subprocess\.(run|call)\s*\(['\"].*?" + r"['\"]", vulnerable_line):
                before = vulnerable_line.strip()

                # Build safer version
                # Extract the command string
                cmd_match = re.search(r"['\"]([^'\"]+)['\"]", vulnerable_line)
                if cmd_match:
                    cmd = cmd_match.group(1)
                    cmd_parts = cmd.split()

                    after = f"subprocess.run({cmd_parts}, shell=False)"
                    return RefactorResult(
                        before=before,
                        after=after,
                        description="Convert string concat to list-style subprocess call with shell=False"
                    )

        return None

    @staticmethod
    def refactor_path_traversal(context: str, line_offset: int) -> Optional[RefactorResult]:
        """Suggest path normalization for path traversal."""
        lines = context.splitlines()
        if line_offset >= len(lines):
            return None

        vulnerable_line = lines[line_offset]

        # Check for unsafe path operations
        if any(unsafe in vulnerable_line for unsafe in ["open(", "Path(", "readfile"]):
            if not any(safe in vulnerable_line for safe in ["realpath", "abspath", "normpath"]):
                before = vulnerable_line.strip()

                # Extract variable name
                var_match = re.search(r"(open|Path)\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)", vulnerable_line)
                if var_match:
                    var_name = var_match.group(2)
                    after_lines = [
                        "import os",
                        f"if not os.path.abspath({var_name}).startswith(SAFE_DIR):",
                        "    raise ValueError('Path traversal detected')",
                        f"with open(os.path.abspath({var_name})) as f:",
                    ]
                    after = "\n".join(after_lines).strip()

                    return RefactorResult(
                        before=before,
                        after=after,
                        description="Add path normalization and boundary validation"
                    )

        return None

    @staticmethod
    def refactor_missing_auth(context: str, line_offset: int) -> Optional[RefactorResult]:
        """Suggest adding authentication check for missing auth."""
        lines = context.splitlines()
        if line_offset >= len(lines):
            return None

        vulnerable_line = lines[line_offset]

        # Check if this is a route handler without auth
        if any(marker in vulnerable_line for marker in ["def ", "@app.", "@router."]):
            # Check if next few lines have auth
            check_lines = "\n".join(lines[line_offset:min(line_offset + 5, len(lines))]).lower()
            if "auth" not in check_lines and "login" not in check_lines:
                before = vulnerable_line.strip()
                after = (
                    "@app.route(...)\n"
                    "@require_login\n"
                    "def handler(...):"
                )
                return RefactorResult(
                    before=before,
                    after=after,
                    description="Add @require_login decorator for authentication"
                )

        return None

    def refactor(self, cwe: str, context: str, line_offset: int) -> Optional[str]:
        """Attempt multi-line refactoring for a given CWE."""
        if cwe == "CWE-89":
            result = MultiLineRefactorer.refactor_sql_injection(context, line_offset)
        elif cwe == "CWE-78":
            result = MultiLineRefactorer.refactor_command_injection(context, line_offset)
        elif cwe == "CWE-22":
            result = MultiLineRefactorer.refactor_path_traversal(context, line_offset)
        elif cwe == "CWE-862":
            result = MultiLineRefactorer.refactor_missing_auth(context, line_offset)
        elif cwe in {"CWE-639", "CWE-285"}:
            # IDOR/ownership: suggest adding owner filter
            if 0 <= line_offset < len(lines):
                vuln_line = lines[line_offset]
                _lookup = re.compile(r'(?:\.(?:get|filter|filter_by|findById|findByPk|findOne)\s*\()', re.I)
                if _lookup.search(vuln_line) and not re.search(r'(?:owner|user_id|created_by|tenant)', vuln_line, re.I):
                    before = vuln_line.strip()
                    after = re.sub(r'(\bfilter\s*\(|\bfilter_by\s*\(|\bget\s*\()', r'\1owner=request.user, ', before, count=1)
                    result = RefactorResult(before=before, after=after,
                        description="Add ownership filter (owner=request.user) to scope resource access")
        else:
            return None

        if result:
            return f"BEFORE:\n{result.before}\n\nAFTER:\n{result.after}\n\n# {result.description}"

        return None
