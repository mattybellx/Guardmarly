"""
ansede_static.entropy
──────────────────────
Shannon entropy-based secret and credential detection.

This module scans Python source code (and arbitrary text files) for
high-entropy string literals that may be hardcoded secrets such as:
  - API keys / tokens
  - Private keys (PEM blobs)
  - Database passwords
  - OAuth secrets
  - AWS / Azure / GCP credentials

Algorithm
─────────
For each string literal or variable-assignment string value found in the
source, compute the Shannon entropy::

    H = -∑ p_i × log₂(p_i)

where p_i is the probability of character i in the string.

Strings with entropy above a configurable threshold (default: 4.5 bits)
and above a minimum length (default: 20 characters) are flagged.

Keyword heuristic
─────────────────
Variable/parameter names or dictionary keys near a high-entropy string are
checked against a list of secret-related keywords (``secret``, ``key``,
``token``, ``password``, ``credential``, etc.).  Findings with a matching
keyword are upgraded to HIGH severity; others remain LOW (informational).

Exclusions
──────────
The following are excluded to avoid false positives:
  - Hash digests that look like known fixed patterns (all-hex 40 or 64 chars)
  - Common test / placeholder values (``changeme``, ``test``, ``example``)
  - Strings that are clearly paths (start with ``/`` or ``./``)
  - Base64-encoded UUIDs and similar structured tokens are allowed through
    (they tend to be high-entropy but are not secrets)

Zero external dependencies.  Python 3.9+.
"""
from __future__ import annotations

import ast
import math
import re
from typing import List, Optional, Tuple

from ansede_static._types import Finding, Severity

# ── Constants ─────────────────────────────────────────────────────────────────

DEFAULT_MIN_ENTROPY: float = 4.5
# No-secret-context findings use a higher bar to limit noise on framework code.
_NON_SECRET_MIN_ENTROPY: float = 5.0
DEFAULT_MIN_LENGTH: int = 20

_SECRET_KEYWORDS: frozenset = frozenset({
    "secret", "api_key", "apikey", "token", "password", "passwd", "pwd",
    "credential", "credentials", "auth", "authorization", "private_key",
    "privatekey", "access_key", "accesskey", "client_secret", "client_id",
    "aws_secret", "aws_access", "azure_secret", "gcp_key", "database_url",
    "db_password", "db_pass", "db_pwd", "jwt_secret", "jwt_key",
    "signing_key", "encryption_key", "master_key", "service_account",
    "refresh_token", "bearer", "session_key", "secret_key",
})

# Strings matching these patterns are almost certainly not secrets.
_EXCLUDE_PATTERNS: tuple = (
    re.compile(r"^[0-9a-f]{40}$", re.I),   # SHA-1 hex digest
    re.compile(r"^[0-9a-f]{64}$", re.I),   # SHA-256 hex digest
    re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I),  # UUID
    re.compile(r"^[\./~]"),                  # file paths
    re.compile(r"^https?://"),               # URLs
    # Real secrets don't contain spaces; format strings, error messages, and i18n
    # strings all do.  This single check eliminates the vast majority of framework
    # source FPs without touching any real credential pattern.
    re.compile(r" "),
    # Format-string markers  (%s, %(x)s, {0}, {name})
    re.compile(r"%[\(\w]|\{\w*\}"),
    # HTML tags / CSS fragments / SVG — common in template/widget code
    re.compile(r"<[a-z]+[ />]|style=|class=", re.I),
    # Regex-flavoured strings (anchors, character classes, quantifiers)
    re.compile(r"\^\S|\\[dDwWsSnrtu]|\[\^?[\w-]{2,}\]"),
)

_PLACEHOLDER_VALUES: frozenset = frozenset({
    "changeme", "password", "secret", "test", "example", "dummy",
    "placeholder", "your_secret_here", "your_api_key_here",
    "replace_me", "insert_here", "xxx", "yyy", "zzz",
    "12345678901234567890", "abcdefghijklmnopqrstu",
})


# ── Core entropy function ─────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    """
    Compute the Shannon entropy (in bits) of the string *s*.

    Returns ``0.0`` for an empty string.
    """
    if not s:
        return 0.0
    length = len(s)
    freq: dict = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


# ── Extraction helpers ────────────────────────────────────────────────────────

def _is_excluded(value: str) -> bool:
    lower = value.lower()
    if lower in _PLACEHOLDER_VALUES:
        return True
    for pattern in _EXCLUDE_PATTERNS:
        if pattern.search(value):
            return True
    return False


def _context_keyword(node: ast.AST, parent_map: dict) -> Optional[str]:
    """
    Look up the variable name, dict key, or keyword argument name that
    immediately contains *node*, if any.
    Returns the name in lower-case, or None.
    """
    parent = parent_map.get(id(node))
    if parent is None:
        return None
    # x = "secret_value"  →  parent is Assign, target is Name
    if isinstance(parent, ast.Assign):
        for target in parent.targets:
            if isinstance(target, ast.Name):
                return target.id.lower()
            if isinstance(target, ast.Attribute):
                return target.attr.lower()
    # x: str = "secret_value"  →  parent is AnnAssign
    if isinstance(parent, ast.AnnAssign) and isinstance(parent.target, ast.Name):
        return parent.target.id.lower()
    # {"api_key": "secret_value"}  →  parent is Dict; find key index
    if isinstance(parent, ast.Dict):
        for key, val in zip(parent.keys, parent.values):
            if val is node and isinstance(key, ast.Constant):
                return str(key.value).lower()
    # keyword(arg="api_key", value=...)
    if isinstance(parent, ast.keyword) and parent.arg:
        return parent.arg.lower()
    return None


def _build_parent_map(tree: ast.AST) -> dict:
    parent_map: dict = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent_map[id(child)] = node
    return parent_map


# ── High-entropy string finder ────────────────────────────────────────────────

def find_high_entropy_strings(
    text: str,
    min_entropy: float = DEFAULT_MIN_ENTROPY,
    min_length: int = DEFAULT_MIN_LENGTH,
) -> List[Tuple[int, str, float]]:
    """
    Scan *text* (plain text, not necessarily Python) for high-entropy strings.

    Uses a simple regex to extract candidate strings from the text, then
    filters by entropy and length.

    Returns a list of ``(line_number, string_value, entropy)`` tuples.
    """
    # Pattern: anything between matching quotes
    _STRING_RE = re.compile(
        r"""(?:\"\"\".*?\"\"\"|\'\'\'.*?\'\'\'|\"([^\"\\]*(?:\\.[^\"\\]*)*)\"|\
'([^'\\]*(?:\\.[^'\\]*)*)')""",
        re.DOTALL,
    )
    results: list = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for m in _STRING_RE.finditer(line):
            candidate = m.group(1) or m.group(2) or ""
            if len(candidate) < min_length:
                continue
            if _is_excluded(candidate):
                continue
            ent = shannon_entropy(candidate)
            if ent >= min_entropy:
                results.append((lineno, candidate, ent))
    return results


# ── AST-based scanner for Python source ──────────────────────────────────────

def scan_for_secrets(
    source: str,
    filename: str,
    min_entropy: float = DEFAULT_MIN_ENTROPY,
    min_length: int = DEFAULT_MIN_LENGTH,
) -> List[Finding]:
    """
    Scan *source* (Python code) for high-entropy string literals that may be
    hardcoded secrets.

    Returns a list of :class:`~ansede_static._types.Finding` objects.
    Variable / key names near the secret are checked against keyword list
    to determine severity (HIGH vs LOW).
    """
    findings: list = []
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError:
        # Fallback: text-based scan
        return _scan_text_fallback(source, filename, min_entropy, min_length)

    parent_map = _build_parent_map(tree)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant):
            continue
        if not isinstance(node.value, str):
            continue

        value = node.value
        if len(value) < min_length:
            continue
        if _is_excluded(value):
            continue

        ent = shannon_entropy(value)
        if ent < min_entropy:
            continue

        lineno = getattr(node, "lineno", 0)
        kw = _context_keyword(node, parent_map)
        is_secret_context = _keyword_matches_secret(kw) if kw else False

        # Non-secret-context strings need a higher entropy bar to reduce noise
        # from framework internals (i18n keys, SQL templates, etc.).
        if not is_secret_context and ent < _NON_SECRET_MIN_ENTROPY:
            continue

        severity = Severity.HIGH if is_secret_context else Severity.LOW
        rule_id = "PY-ENTROPY-001" if is_secret_context else "PY-ENTROPY-002"
        cwe = "CWE-798"  # Use of Hard-coded Credentials

        context_note = (
            " Variable name '" + kw + "' suggests this may be a secret."
            if is_secret_context else ""
        )

        findings.append(
            Finding(
                category="security",
                severity=severity,
                title="Hardcoded high-entropy string (potential secret/credential)",
                description=(
                    "A string literal with Shannon entropy {:.2f} bits was detected. "
                    "High-entropy strings embedded in source code are often credentials, "
                    "API keys, or tokens.{}".format(ent, context_note)
                ),
                line=lineno,
                suggestion=(
                    "Move secrets to environment variables or a secrets manager "
                    "(e.g., os.environ['API_KEY'], HashiCorp Vault, AWS Secrets Manager)."
                ),
                rule_id=rule_id,
                cwe=cwe,
                agent="entropy-scanner",
                confidence=0.75 if not is_secret_context else 0.90,
                triggering_code=repr(value[:40] + "…" if len(value) > 40 else value),
                analysis_kind="entropy",
            )
        )

    return findings


def _keyword_matches_secret(kw: Optional[str]) -> bool:
    if kw is None:
        return False
    lower = kw.lower()
    for secret_kw in _SECRET_KEYWORDS:
        if secret_kw in lower:
            return True
    return False


# ── Text fallback ─────────────────────────────────────────────────────────────

def _scan_text_fallback(
    text: str,
    filename: str,
    min_entropy: float,
    min_length: int,
) -> List[Finding]:
    """Fallback scanner for non-Python files (JS, env, text)."""
    results: list = []
    for lineno, candidate, ent in find_high_entropy_strings(text, min_entropy, min_length):
        results.append(
            Finding(
                category="security",
                severity=Severity.LOW,
                title="High-entropy string detected in non-Python file",
                description=(
                    "String with entropy {:.2f} bits found at line {}. "
                    "May be a hardcoded credential.".format(ent, lineno)
                ),
                line=lineno,
                suggestion="Move secrets to a secrets manager or environment variable.",
                rule_id="ENTROPY-001",
                cwe="CWE-798",
                agent="entropy-scanner",
                confidence=0.6,
                triggering_code=repr(candidate[:40] + "…" if len(candidate) > 40 else candidate),
                analysis_kind="entropy",
            )
        )
    return results
