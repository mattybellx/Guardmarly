"""
Minified JS Regex Pre-Scanner
──────────────────────────────
Lightweight regex-based security scanner for minified/bundled JavaScript files
where the structural AST parser cannot recover meaningful patterns.

This runs BEFORE structural analysis on files flagged as minified and produces
findings at confidence=0.70 with analysis_kind="minified-heuristic".

Findings are deduplicated against structural findings, so any signal the AST
parser manages to extract takes precedence.
"""

from __future__ import annotations

import re
from ansede_static._types import Finding, Severity, TraceFrame

# ── Detection regexes ────────────────────────────────────────────────────
# CWE-95: eval with non-literal argument
_EVAL_DYNAMIC_RE = re.compile(
    r'(?<![\w.])eval\s*\(\s*(?![\'"]\s*[\'"])',
    re.IGNORECASE,
)

# CWE-95: new Function() — always code-injection surface
_NEW_FUNCTION_RE = re.compile(
    r'new\s+Function\s*\(',
    re.IGNORECASE,
)

# CWE-79: innerHTML assignment with non-literal RHS
_INNERHTML_DYNAMIC_RE = re.compile(
    r'\.innerHTML\s*=\s*(?![\'"])',
    re.IGNORECASE,
)

# CWE-79: document.write with dynamic arg
_DOCUMENT_WRITE_DYNAMIC_RE = re.compile(
    r'document\.write\s*\(\s*(?![\'"])',
    re.IGNORECASE,
)

# CWE-22: path join / open with dynamic arg
_PATH_JOIN_DYNAMIC_RE = re.compile(
    r'os\.path\.join\s*\(|path\.join\s*\(|path\.resolve\s*\(',
    re.IGNORECASE,
)

# CWE-98: dynamic require with non-literal path
_DYNAMIC_REQUIRE_RE = re.compile(
    r'\brequire\s*\(\s*(?![\'"])',
    re.IGNORECASE,
)

# CWE-78: subprocess/exec with shell=True or dynamic cmd
_SHELL_EXEC_RE = re.compile(
    r'(?:child_process\.exec|subprocess\.(?:call|run|Popen)|exec|spawn)\s*\(',
    re.IGNORECASE,
)

# CWE-89: SQL query with string concatenation in minified code
_SQL_DYNAMIC_RE = re.compile(
    r'(?:SELECT|INSERT|UPDATE|DELETE)\b[\s\S]{0,80}\+',
    re.IGNORECASE,
)

# CWE-918: fetch/request with dynamic URL
_SSRF_DYNAMIC_RE = re.compile(
    r'(?:fetch|axios\.(?:get|post|put)|requests\.(?:get|post|put))\s*\(\s*(?![\'"])',
    re.IGNORECASE,
)

# CWE-601: redirect with dynamic target
_OPEN_REDIRECT_RE = re.compile(
    r'(?:redirect|\.redirect)\s*\(\s*(?![\'"])',
    re.IGNORECASE,
)


def _line_for_offset(code: str, offset: int) -> int:
    """Return 1-based line number for a character offset."""
    return code[:offset].count("\n") + 1


def _snippet(code: str, offset: int, max_len: int = 80) -> str:
    """Extract a short code snippet around an offset."""
    start = max(0, offset - 10)
    end = min(len(code), offset + max_len)
    snippet = code[start:end].replace("\n", " ").strip()
    if len(snippet) > max_len:
        snippet = snippet[:max_len - 3] + "..."
    return snippet


def _make_minified_finding(
    cwe: str,
    title: str,
    description: str,
    suggestion: str,
    *,
    line: int,
    rule_id: str,
    offset: int,
    code: str,
) -> Finding:
    """Create a minified-heuristic finding at confidence=0.70."""
    snip = _snippet(code, offset)
    return Finding(
        category="security",
        severity=Severity.HIGH,
        title=title,
        description=description,
        line=line,
        suggestion=suggestion,
        rule_id=rule_id,
        cwe=cwe,
        agent="js-minified-scanner",
        confidence=0.70,
        analysis_kind="minified-heuristic",
        trace=(
            TraceFrame(
                kind="source",
                label=f"minified regex match at offset {offset}: `{snip}`",
                line=line,
            ),
        ),
        triggering_code=snip[:120],
    )


# ── Rule functions ───────────────────────────────────────────────────────

def _scan_cwe_95(code: str) -> list[Finding]:
    """Detect eval()/new Function() in minified code."""
    findings: list[Finding] = []
    seen_lines: set[int] = set()

    for pat, desc in [
        (_EVAL_DYNAMIC_RE, "eval()"),
        (_NEW_FUNCTION_RE, "new Function()"),
    ]:
        for m in pat.finditer(code):
            line = _line_for_offset(code, m.start())
            if line in seen_lines:
                continue
            seen_lines.add(line)
            findings.append(_make_minified_finding(
                cwe="CWE-95",
                title=f"CWE-95: {desc} with dynamic argument in minified code at line {line}",
                description=(
                    f"`{desc}` detected with non-literal argument at L{line} in minified JS. "
                    "Dynamic code execution in minified bundles may indicate obfuscated "
                    "eval abuse or naive template compilation."
                ),
                suggestion="Avoid dynamic code execution. Use static functions or safe template engines.",
                line=line,
                rule_id="JS-044",
                offset=m.start(),
                code=code,
            ))
    return findings


def _scan_cwe_79(code: str) -> list[Finding]:
    """Detect innerHTML/document.write with dynamic args in minified code."""
    findings: list[Finding] = []
    seen_lines: set[int] = set()

    for pat, sink in [
        (_INNERHTML_DYNAMIC_RE, "innerHTML"),
        (_DOCUMENT_WRITE_DYNAMIC_RE, "document.write()"),
    ]:
        for m in pat.finditer(code):
            line = _line_for_offset(code, m.start())
            if line in seen_lines:
                continue
            seen_lines.add(line)
            findings.append(_make_minified_finding(
                cwe="CWE-79",
                title=f"CWE-79: {sink} with dynamic content in minified code at line {line}",
                description=(
                    f"`{sink}` assignment with non-literal argument at L{line} in minified JS. "
                    "Dynamic DOM insertion in minified bundles may indicate XSS sinks without "
                    "visible escaping."
                ),
                suggestion="Use safe DOM APIs (textContent, createElement) or sanitize with DOMPurify.",
                line=line,
                rule_id="JS-045",
                offset=m.start(),
                code=code,
            ))
    return findings


def _scan_cwe_22(code: str) -> list[Finding]:
    """Detect path join/open with dynamic args in minified code."""
    findings: list[Finding] = []
    seen_lines: set[int] = set()

    for m in _PATH_JOIN_DYNAMIC_RE.finditer(code):
        line = _line_for_offset(code, m.start())
        if line in seen_lines:
            continue
        seen_lines.add(line)
        findings.append(_make_minified_finding(
            cwe="CWE-22",
            title=f"CWE-22: Path manipulation with dynamic input in minified code at line {line}",
            description=(
                f"`{m.group(0)[:50]}` path construction detected at L{line} in minified JS. "
                "Dynamic file path construction in minified bundles may indicate "
                "path traversal sinks."
            ),
            suggestion="Validate and sanitize file paths against an allowlist. Use path.resolve() with a safe base.",
            line=line,
            rule_id="JS-046",
            offset=m.start(),
            code=code,
        ))
    return findings


def _scan_cwe_98(code: str) -> list[Finding]:
    """Detect dynamic require() in minified code."""
    findings: list[Finding] = []
    seen_lines: set[int] = set()

    for m in _DYNAMIC_REQUIRE_RE.finditer(code):
        line = _line_for_offset(code, m.start())
        if line in seen_lines:
            continue
        seen_lines.add(line)
        findings.append(_make_minified_finding(
            cwe="CWE-98",
            title=f"CWE-98: Dynamic require() in minified code at line {line}",
            description=(
                f"`require()` with non-literal argument at L{line} in minified JS. "
                "Dynamic module loading in minified bundles may indicate AMD loader "
                "patterns that can load attacker-controlled modules."
            ),
            suggestion="Use static module paths in require() calls.",
            line=line,
            rule_id="JS-047",
            offset=m.start(),
            code=code,
        ))
    return findings


def _scan_cwe_78(code: str) -> list[Finding]:
    """Detect shell/process execution in minified code."""
    findings: list[Finding] = []
    seen_lines: set[int] = set()

    for m in _SHELL_EXEC_RE.finditer(code):
        line = _line_for_offset(code, m.start())
        if line in seen_lines:
            continue
        seen_lines.add(line)
        _snippet(code, m.start(), 120)
        findings.append(_make_minified_finding(
            cwe="CWE-78",
            title=f"CWE-78: OS command execution in minified code at line {line}",
            description=(
                f"Shell/process execution primitive `{m.group(0)[:60]}` at L{line} in minified JS. "
                "Command execution in bundled code may allow injection if input is not sanitized."
            ),
            suggestion="Use execFile() with separate arguments instead of string-based shell execution.",
            line=line,
            rule_id="JS-048",
            offset=m.start(),
            code=code,
        ))
    return findings


def _scan_cwe_89(code: str) -> list[Finding]:
    """Detect SQL query construction with concatenation in minified code."""
    findings: list[Finding] = []
    seen_lines: set[int] = set()

    for m in _SQL_DYNAMIC_RE.finditer(code):
        line = _line_for_offset(code, m.start())
        if line in seen_lines:
            continue
        seen_lines.add(line)
        findings.append(_make_minified_finding(
            cwe="CWE-89",
            title=f"CWE-89: Dynamic SQL query in minified code at line {line}",
            description=(
                f"SQL keyword with string concatenation at L{line} in minified JS. "
                "Dynamic query construction in bundled code bypasses structural "
                "parameterization checks."
            ),
            suggestion="Use parameterized queries or an ORM with bound parameters.",
            line=line,
            rule_id="JS-049",
            offset=m.start(),
            code=code,
        ))
    return findings


def _scan_cwe_918(code: str) -> list[Finding]:
    """Detect SSRF-like dynamic HTTP requests in minified code."""
    findings: list[Finding] = []
    seen_lines: set[int] = set()

    for m in _SSRF_DYNAMIC_RE.finditer(code):
        line = _line_for_offset(code, m.start())
        if line in seen_lines:
            continue
        seen_lines.add(line)
        findings.append(_make_minified_finding(
            cwe="CWE-918",
            title=f"CWE-918: Dynamic HTTP request in minified code at line {line}",
            description=(
                f"Outbound HTTP request with non-literal URL at L{line} in minified JS. "
                "Dynamic outbound requests from server-side bundles may indicate SSRF vectors."
            ),
            suggestion="Validate and allowlist outbound URLs. Never pass user-controlled URLs directly to HTTP clients.",
            line=line,
            rule_id="JS-050",
            offset=m.start(),
            code=code,
        ))
    return findings


def _scan_cwe_601(code: str) -> list[Finding]:
    """Detect open redirect patterns in minified code."""
    findings: list[Finding] = []
    seen_lines: set[int] = set()

    for m in _OPEN_REDIRECT_RE.finditer(code):
        line = _line_for_offset(code, m.start())
        if line in seen_lines:
            continue
        seen_lines.add(line)
        findings.append(_make_minified_finding(
            cwe="CWE-601",
            title=f"CWE-601: Open redirect in minified code at line {line}",
            description=(
                f"`redirect()` with non-literal argument at L{line} in minified JS. "
                "Open redirects in bundled code may expose users to phishing attacks."
            ),
            suggestion="Validate redirect targets against an allowlist of safe URLs.",
            line=line,
            rule_id="JS-051",
            offset=m.start(),
            code=code,
        ))
    return findings


# ── Main entry point ─────────────────────────────────────────────────────

def scan_minified_js(
    code: str,
    *,
    filename: str = "",
) -> list[Finding]:
    """
    Run regex-based security heuristics on minified JavaScript.

    Returns findings at confidence=0.70. These should be deduplicated
    against structural findings (structural wins where they overlap).

    Skip if the code looks like it has meaningful structure (e.g., > 100
    lines and function keywords present), since the structural parser
    can handle those.
    """
    lines = code.splitlines()
    # If the file has reasonable structure, skip minified heuristics —
    # the structural parser can handle it.
    if len(lines) > 100 and code.count("function ") > 5:
        return []

    findings: list[Finding] = []

    # Run each category scanner and aggregate
    for scanner in (
        _scan_cwe_95,
        _scan_cwe_79,
        _scan_cwe_22,
        _scan_cwe_98,
        _scan_cwe_78,
        _scan_cwe_89,
        _scan_cwe_918,
        _scan_cwe_601,
    ):
        try:
            findings.extend(scanner(code))
        except Exception:
            pass

    # Deduplicate by (cwe, line)
    seen: set[tuple[str, int]] = set()
    deduped: list[Finding] = []
    for f in findings:
        key = (f.cwe or "", f.line or 0)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return deduped
