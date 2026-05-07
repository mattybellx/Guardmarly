"""
Lightweight Symbolic Guard Analysis
────────────────────────────────────
Path-sensitive reasoning about security guards (if-conditions, decorators,
middleware) that precede taint sinks.

Instead of full symbolic execution, we analyze AST-level guard patterns
to determine if a security check mathematically covers a sink.

If the engine sees:
    if user.is_authenticated:
        obj = Model.objects.get(pk=request.GET['id'])  # ← NOT IDOR
    else:
        return 403

…it downgrades CWE-639 to confidence=0 because the auth guard protects the sink.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from ansede_static._types import Finding


@dataclass
class GuardInfo:
    """Information about a security guard (if-condition, decorator, middleware)."""
    kind: str                     # "auth_check", "csrf_check", "rate_limit", "input_validation", "ownership_check"
    line: int
    protects_lines: set[int] = field(default_factory=set)
    is_else_guard: bool = False   # True if this is an else/elif branch
    metadata: dict[str, str] = field(default_factory=dict)


# ── Guard pattern recognizers ──────────────────────────────────────────

_AUTH_GUARD_RE = re.compile(
    r'(?:\.is_authenticated\b|\.is_anonymous\b|@login_required|'
    r'@permission_required|@user_passes_test|login_required\s*\()',
    re.IGNORECASE,
)

_CSRF_GUARD_RE = re.compile(
    r'(?:csrf_token|csrf_exempt\s*=\s*False|CsrfViewMiddleware|'
    r'@csrf_protect|csrf\.get_token|wtforms\.csrf)',
    re.IGNORECASE,
)

_RATE_LIMIT_GUARD_RE = re.compile(
    r'(?:rate[_-]?limit|RateLimiter|limiter\.limit|throttle|'
    r'@ratelimit|TooManyRequests)',
    re.IGNORECASE,
)

_OWNERSHIP_GUARD_RE = re.compile(
    r'(?:\bowner\s*=\s*request\.user\b|\bfilter\s*\([^)]*request\.user\b|'
    r'\buser\s*=\s*request\.user\b|\bcreated_by\s*=\s*request\.user\b|'
    r'\.objects\.filter\s*\([^)]*\bowner\b)',
    re.IGNORECASE,
)

_INPUT_VALIDATION_GUARD_RE = re.compile(
    r'(?:\.isdigit\s*\(|\.isalnum\s*\(|isinstance\s*\(|'
    r'allowed_extensions|ALLOWED_EXTENSIONS|content_type\s*==)',
    re.IGNORECASE,
)


def _extract_python_guards(tree: ast.AST, source_lines: list[str]) -> list[GuardInfo]:
    """Extract security guard information from Python AST."""
    guards: list[GuardInfo] = []

    class GuardVisitor(ast.NodeVisitor):
        def visit_If(self, node: ast.If) -> None:
            test_text = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
            if _AUTH_GUARD_RE.search(test_text):
                body_lines = set(range(node.lineno, node.end_lineno + 1)) if node.end_lineno else set()
                guards.append(GuardInfo(
                    kind="auth_check", line=node.lineno,
                    protects_lines=body_lines,
                ))
                if node.orelse:
                    orelse_start = node.orelse[0].lineno if node.orelse else node.lineno
                    orelse_end = node.orelse[-1].end_lineno if node.orelse and hasattr(node.orelse[-1], "end_lineno") else orelse_start + 5
                    guards.append(GuardInfo(
                        kind="auth_check", line=orelse_start,
                        protects_lines=set(range(orelse_start, orelse_end + 1)),
                        is_else_guard=True,
                    ))
            if _OWNERSHIP_GUARD_RE.search(test_text):
                body_lines = set(range(node.lineno, node.end_lineno + 1)) if node.end_lineno else set()
                guards.append(GuardInfo(
                    kind="ownership_check", line=node.lineno,
                    protects_lines=body_lines,
                ))
            if _INPUT_VALIDATION_GUARD_RE.search(test_text):
                body_lines = set(range(node.lineno, node.end_lineno + 1)) if node.end_lineno else set()
                guards.append(GuardInfo(
                    kind="input_validation", line=node.lineno,
                    protects_lines=body_lines,
                ))
            self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            for deco in node.decorator_list:
                deco_text = ast.unparse(deco) if hasattr(ast, "unparse") else ""
                if _AUTH_GUARD_RE.search(deco_text):
                    body = set(range(node.lineno, node.end_lineno + 1)) if node.end_lineno else set()
                    guards.append(GuardInfo(
                        kind="auth_check", line=deco.lineno,
                        protects_lines=body,
                        metadata={"decorator": deco_text},
                    ))
                if _CSRF_GUARD_RE.search(deco_text):
                    body = set(range(node.lineno, node.end_lineno + 1)) if node.end_lineno else set()
                    guards.append(GuardInfo(
                        kind="csrf_check", line=deco.lineno,
                        protects_lines=body,
                    ))
                if _RATE_LIMIT_GUARD_RE.search(deco_text):
                    body = set(range(node.lineno, node.end_lineno + 1)) if node.end_lineno else set()
                    guards.append(GuardInfo(
                        kind="rate_limit", line=deco.lineno,
                        protects_lines=body,
                    ))
            self.generic_visit(node)

    GuardVisitor().visit(tree)
    return guards


def _extract_js_guards(code: str, filename: str) -> list[GuardInfo]:
    """Extract security guard information from JavaScript source."""
    guards: list[GuardInfo] = []
    lines = code.splitlines()

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        if _AUTH_GUARD_RE.search(stripped):
            guards.append(GuardInfo(
                kind="auth_check", line=i,
                protects_lines=set(range(i, min(i + 10, len(lines) + 1))),
            ))

        if _CSRF_GUARD_RE.search(stripped):
            guards.append(GuardInfo(
                kind="csrf_check", line=i,
                protects_lines=set(range(i, min(i + 10, len(lines) + 1))),
            ))

        if _RATE_LIMIT_GUARD_RE.search(stripped):
            guards.append(GuardInfo(
                kind="rate_limit", line=i,
                protects_lines=set(range(i, min(i + 10, len(lines) + 1))),
            ))

        if _OWNERSHIP_GUARD_RE.search(stripped):
            guards.append(GuardInfo(
                kind="ownership_check", line=i,
                protects_lines=set(range(i, min(i + 10, len(lines) + 1))),
            ))

        if _INPUT_VALIDATION_GUARD_RE.search(stripped):
            guards.append(GuardInfo(
                kind="input_validation", line=i,
                protects_lines=set(range(i, min(i + 10, len(lines) + 1))),
            ))

    return guards


# ── Guard-aware finding adjustment ─────────────────────────────────────

_GUARD_CWE_DOWNGRADE_MAP: dict[str, dict[str, float]] = {
    # (guard_kind, cwe) → new_confidence
    "auth_check": {
        "CWE-639": 0.0,   # IDOR — auth check means it's protected
        "CWE-862": 0.0,   # Missing auth — auth check proves it's there
        "CWE-287": 0.0,   # Auth bypass — auth guard present
        "CWE-285": 0.15,  # Improper auth — guard present but may be insufficient
    },
    "csrf_check": {
        "CWE-352": 0.0,   # CSRF — token check present
    },
    "rate_limit": {
        "CWE-307": 0.0,   # Brute force — rate limiting present
        "CWE-400": 0.0,   # Resource exhaustion — rate limiting present
    },
    "ownership_check": {
        "CWE-639": 0.0,   # IDOR — ownership filter present
    },
    "input_validation": {
        "CWE-434": 0.0,   # File upload — validation present
        "CWE-22": 0.10,   # Path traversal — input validated
        "CWE-89": 0.10,   # SQLi — input validated
    },
}


def adjust_findings_from_guards(
    findings: list[Finding],
    guards: list[GuardInfo],
) -> list[Finding]:
    """
    Downgrade findings that are protected by security guards.

    If a finding's line is inside a guard's protects_lines range and the
    guard kind matches the finding's CWE, reduce confidence/severity.
    """
    adjusted: list[Finding] = []
    for finding in findings:
        cwe = finding.cwe or ""
        line = finding.line or 0
        downgraded = False

        for guard in guards:
            if guard.is_else_guard:
                # Guards in else branches don't protect — they indicate
                # the UNauthenticated path. Don't downgrade.
                continue
            if line in guard.protects_lines:
                cwe_map = _GUARD_CWE_DOWNGRADE_MAP.get(guard.kind, {})
                if cwe in cwe_map:
                    new_conf = cwe_map[cwe]
                    if new_conf <= 0.01:
                        # Fully protected — drop finding entirely
                        downgraded = True
                        break
                    else:
                        finding.confidence = min(finding.confidence, new_conf)
                        finding.description = (
                            f"{finding.description} "
                            f"(guarded by {guard.kind} at L{guard.line}; confidence adjusted)"
                        )
                        downgraded = True

        if not downgraded:
            adjusted.append(finding)

    return adjusted


def analyze_guards_python(
    code: str,
    findings: list[Finding],
    *,
    filename: str = "",
) -> list[Finding]:
    """Python entry point: extract guards, adjust findings."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return findings
    guards = _extract_python_guards(tree, code.splitlines())
    if not guards:
        return findings
    return adjust_findings_from_guards(findings, guards)


def analyze_guards_js(
    code: str,
    findings: list[Finding],
    *,
    filename: str = "",
) -> list[Finding]:
    """JS entry point: extract guards, adjust findings."""
    guards = _extract_js_guards(code, filename)
    if not guards:
        return findings
    return adjust_findings_from_guards(findings, guards)
