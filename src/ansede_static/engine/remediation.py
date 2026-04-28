"""ansede_static.engine.remediation
──────────────────────────────────────────────────────────────────────────────
AI-powered remediation engine for ansede-static.

Primary:  Ollama (http://localhost:11434) — local LLM, zero cloud dependency.
Fallback: Pattern-based heuristics from the built-in auto_fix field on
          Finding (already populated by python_analyzer._generate_auto_fix).

The module is intentionally zero-dependency: it uses only urllib.request for
HTTP and json / difflib from stdlib.

Public API
──────────
generate_remediation(finding, source_code, filename, *, use_ai, ...) → str | None

  Returns a BEFORE/AFTER fix string, or None when no fix can be suggested.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ansede_static._types import Finding

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

    # 3. CWE template
    if finding.cwe:
        template = _CWE_TEMPLATES.get(finding.cwe)
        if template:
            return f"Remediation hint ({finding.cwe}): {template}"

    return None
