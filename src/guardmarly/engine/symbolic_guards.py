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
from guardmarly._types import Finding, Severity


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
    r'@permission_required|@user_passes_test|login_required\s*\('
    r'|hmac\.compare_digest\s*\(|hmac\.new\s*\(|X-Hub-Signature)',
    re.IGNORECASE,
)

_CSRF_GUARD_RE = re.compile(
    r'(?:csrf_token|csrf_exempt\s*=\s*False|CsrfViewMiddleware|'
    r'@csrf_protect|csrf\.get_token|wtforms\.csrf|'
    r'hmac\.compare_digest|hmac\.new\s*\([^)]*key\b|X-Hub-Signature)',
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

_PATH_BOUNDARY_GUARD_RE = re.compile(
    r'(?:startswith\s*\(|startsWith\s*\(|commonpath\s*\(|is_relative_to\s*\()',
    re.IGNORECASE,
)

_EXPLICIT_AUTH_TEST_RE = re.compile(
    r'(?:\buser\.is_authenticated\b|\brequest\.user\.is_authenticated\b|'
    r'\bcurrent_user\.is_authenticated\b|\btoken\s+is\s+not\s+None\b|'
    r'\bauth(?:entication|orized?)?_check\s*\(|\bpermission_check\s*\(|'
    r'\bhas_permission\s*\(|\brequire_auth\s*\(|\bensure_auth\s*\(|'
    r'\bhmac\.(?:compare_digest|new)\s*\(|X-Hub-Signature|'
    r'\bwebhook\.verify\s*\(|\bsignature.*verify\b)',
    re.IGNORECASE,
)

_GUARD_POSITIVE_SIGNAL_RE = re.compile(
    r'\bis_authenticated\b|\bis not None\b|\bpermission\b|\bauthoriz|\bauth\b',
    re.IGNORECASE,
)

_NULL_GUARD_RE = re.compile(
    r'(?:\buser\s+is\s+None\b|\buser\s+is\s+not\s+None\b|'
    r'\brequest\.user\s+is\s+None\b|\bcurrent_user\s+is\s+None\b|'
    r'\bg\.user\s+is\s+None\b|\bsession\.get\([^)]+\)\s+is\s+None|'
    r'\bnot\s+(?:g\.)?user\b)',
    re.IGNORECASE,
)

_TYPE_GUARD_RE = re.compile(
    r'\bisinstance\s*\([^,]+,\s*(?:int|float|str|bool|dict|list|bytes)\b',
    re.IGNORECASE,
)

_COMPOUND_CONDITION_SPLIT_RE = re.compile(r'\band\b|\bor\b')

_JS_INLINE_AUTH_GUARD_RE = re.compile(
    r'(?:req\.user|ctx\.state\.user|request\.user|currentUser|current_user|'
    r'isAuthenticated\s*\(|hasPermission\s*\(|permissionCheck\s*\()',
    re.IGNORECASE,
)

_JS_RATE_LIMIT_BIND_RE = re.compile(
    r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:\w+\.)?rateLimit\s*\(',
    re.IGNORECASE,
)

_JS_ROUTE_APPLY_RE = re.compile(
    r'\b(?:app|router|server|fastify)\.(?:use|get|post|put|patch|delete|all|route)\s*\(',
    re.IGNORECASE,
)

_DENY_ACCESS_RE = re.compile(
    r'(?:abort\s*\(\s*(?:40[13]|403)\s*\)|return\s+(?:40[13]|403)\b|'
    r'return\s+.*,\s*(?:40[13]|403)\s*\)|return\s+.*,\s*(?:40[13]|403)\b|'
    r'raise\s+PermissionDenied\b|forbidden\s*\(|deny\s*\(|unauthorized\s*\()',
    re.IGNORECASE,
)


def _extract_python_guards(tree: ast.AST, source_lines: list[str]) -> list[GuardInfo]:
    """Extract security guard information from Python AST."""
    guards: list[GuardInfo] = []

    class GuardVisitor(ast.NodeVisitor):
        def visit_If(self, node: ast.If) -> None:
            test_text = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
            body_lines = set(range(node.lineno, node.end_lineno + 1)) if node.end_lineno else set()
            orelse_start = node.orelse[0].lineno if node.orelse else node.lineno
            orelse_end = (node.orelse[-1].end_lineno
                          if node.orelse and hasattr(node.orelse[-1], "end_lineno")
                          else orelse_start + 5)

            # Compound condition splitting: if auth() and ownership():
            sub_conditions = _COMPOUND_CONDITION_SPLIT_RE.split(test_text)

            for sub in sub_conditions:
                sub = sub.strip()

                if _AUTH_GUARD_RE.search(sub) or _NULL_GUARD_RE.search(sub):
                    guards.append(GuardInfo(
                        kind="auth_check", line=node.lineno,
                        protects_lines=body_lines,
                    ))
                    if node.orelse:
                        guards.append(GuardInfo(
                            kind="auth_check", line=orelse_start,
                            protects_lines=set(range(orelse_start, orelse_end + 1)),
                            is_else_guard=True,
                        ))
                if _OWNERSHIP_GUARD_RE.search(sub):
                    guards.append(GuardInfo(
                        kind="ownership_check", line=node.lineno,
                        protects_lines=body_lines,
                    ))
                if _INPUT_VALIDATION_GUARD_RE.search(sub) or _TYPE_GUARD_RE.search(sub):
                    guards.append(GuardInfo(
                        kind="input_validation", line=node.lineno,
                        protects_lines=body_lines,
                    ))
                if _PATH_BOUNDARY_GUARD_RE.search(sub):
                    guards.append(GuardInfo(
                        kind="path_boundary", line=node.lineno,
                        protects_lines=body_lines,
                    ))
                if _CSRF_GUARD_RE.search(sub):
                    guards.append(GuardInfo(
                        kind="csrf_check", line=node.lineno,
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


def _build_parent_map(tree: ast.AST) -> dict[int, ast.AST]:
    parents: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[id(child)] = parent
    return parents


def _is_positive_guard_condition(test_text: str) -> bool:
    if not test_text:
        return False
    if not _EXPLICIT_AUTH_TEST_RE.search(test_text):
        return False
    stripped = test_text.strip()
    if stripped.startswith("not "):
        return False
    if re.search(r'!=\s*None\b|==\s*None\b', stripped):
        return False
    return bool(_GUARD_POSITIVE_SIGNAL_RE.search(stripped))


def _local_node_has_auth_decorator_signal(node: ast.AST) -> bool:
    for deco in getattr(node, "decorator_list", ()):
        deco_text = ast.unparse(deco) if hasattr(ast, "unparse") else ""
        if _AUTH_GUARD_RE.search(deco_text) or _EXPLICIT_AUTH_TEST_RE.search(deco_text):
            return True
    return False


def _collect_python_guard_kinds_for_line(tree: ast.AST, line: int) -> set[str]:
    try:
        parents = _build_parent_map(tree)
    except Exception:
        return set()

    guarded: set[str] = set()
    candidate_nodes = [
        node for node in ast.walk(tree)
        if getattr(node, "lineno", None) == line
    ]
    for node in candidate_nodes:
        current = node
        while id(current) in parents:
            parent = parents[id(current)]
            if isinstance(parent, ast.If):
                test_text = ast.unparse(parent.test) if hasattr(ast, "unparse") else ""
                sub_conditions = _COMPOUND_CONDITION_SPLIT_RE.split(test_text)
                for sub in sub_conditions:
                    sub = sub.strip()
                    if _is_positive_guard_condition(sub) or _NULL_GUARD_RE.search(sub):
                        guarded.add("auth_check")
                    if _OWNERSHIP_GUARD_RE.search(sub):
                        guarded.add("ownership_check")
                    if _INPUT_VALIDATION_GUARD_RE.search(sub) or _TYPE_GUARD_RE.search(sub):
                        guarded.add("input_validation")
                    if _PATH_BOUNDARY_GUARD_RE.search(sub):
                        guarded.add("path_boundary")
            elif isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for deco in parent.decorator_list:
                    deco_text = ast.unparse(deco) if hasattr(ast, "unparse") else ""
                    if _AUTH_GUARD_RE.search(deco_text):
                        guarded.add("auth_check")
            current = parent
    return guarded


def _statements_deny_access(statements: list[ast.stmt]) -> bool:
    for statement in statements:
        text = ast.unparse(statement) if hasattr(ast, "unparse") else ""
        if _DENY_ACCESS_RE.search(text):
            return True
    return False


def _function_scope_guard_kinds(tree: ast.AST, line: int) -> set[str]:
    guarded: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        start = getattr(node, "lineno", None)
        end = getattr(node, "end_lineno", None)
        if start is None or end is None or not (start <= line <= end):
            continue
        statements = list(getattr(node, "body", ()))
        for idx, stmt in enumerate(statements):
            if not isinstance(stmt, ast.If):
                continue
            test_text = ast.unparse(stmt.test) if hasattr(ast, "unparse") else ""
            sub_conditions = _COMPOUND_CONDITION_SPLIT_RE.split(test_text)
            has_auth_signal = any(
                _EXPLICIT_AUTH_TEST_RE.search(sub)
                for sub in sub_conditions
            )
            has_null_guard = any(
                _NULL_GUARD_RE.search(sub)
                for sub in sub_conditions
            )
            has_ownership_signal = any(_OWNERSHIP_GUARD_RE.search(sub) for sub in sub_conditions)
            has_input_signal = any(
                _INPUT_VALIDATION_GUARD_RE.search(sub) or _TYPE_GUARD_RE.search(sub)
                for sub in sub_conditions
            )
            has_path_boundary_signal = any(_PATH_BOUNDARY_GUARD_RE.search(sub) for sub in sub_conditions)
            has_negative_guard = bool(re.search(r'\bnot\b|!=|is not|not in', test_text))
            following_statements = statements[idx + 1:]
            if has_auth_signal:
                if has_negative_guard and _statements_deny_access(stmt.body):
                    guarded.add("auth_check")
                elif not has_negative_guard and (
                    _statements_deny_access(stmt.orelse)
                    or _statements_deny_access(following_statements)
                ):
                    guarded.add("auth_check")
                elif _is_positive_guard_condition(test_text):
                    guarded.add("auth_check")
            # Null guard: `if user is None: return 403` protects the rest
            if has_null_guard:
                if has_negative_guard:
                    # `if user is not None:` → body is the protected path
                    guarded.add("auth_check")
                else:
                    # `if user is None:` → body denies access, rest is protected
                    if _statements_deny_access(stmt.body):
                        guarded.add("auth_check")
            if has_ownership_signal:
                guarded.add("ownership_check")
            if has_input_signal:
                guarded.add("input_validation")
            if has_path_boundary_signal:
                guarded.add("path_boundary")
        if _local_node_has_auth_decorator_signal(node):
            guarded.add("auth_check")
        break
    return guarded


def _severity_downgrade(severity: Severity) -> Severity:
    if severity == Severity.CRITICAL:
        return Severity.HIGH
    if severity == Severity.HIGH:
        return Severity.MEDIUM
    if severity == Severity.MEDIUM:
        return Severity.LOW
    return severity


def _extract_js_guards(code: str, filename: str) -> list[GuardInfo]:
    """Extract security guard information from JavaScript source."""
    guards: list[GuardInfo] = []
    lines = code.splitlines()
    rate_limit_aliases: set[str] = set()

    def _route_scope(start_line: int) -> set[int]:
        text = lines[start_line - 1]
        if ".use(" in text and "=>" not in text and "function" not in text:
            return set(range(start_line, min(start_line + 20, len(lines) + 1)))

        protected = {start_line}
        balance = text.count("{") - text.count("}")
        saw_block = balance > 0
        for current in range(start_line + 1, len(lines) + 1):
            protected.add(current)
            line_text = lines[current - 1]
            balance += line_text.count("{") - line_text.count("}")
            saw_block = saw_block or (line_text.count("{") > 0)
            if saw_block and balance <= 0:
                break
        return protected

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        alias_match = _JS_RATE_LIMIT_BIND_RE.search(stripped)
        if alias_match:
            rate_limit_aliases.add(alias_match.group(1))

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

        direct_rate_limit_use = "@ratelimit" in stripped.lower() or (
            _JS_ROUTE_APPLY_RE.search(stripped)
            and (
                "rateLimit(" in stripped
                or any(re.search(rf'\b{re.escape(alias)}\b', stripped) for alias in rate_limit_aliases)
                or "throttle" in stripped.lower()
            )
        )

        if direct_rate_limit_use:
            guards.append(GuardInfo(
                kind="rate_limit", line=i,
                protects_lines=_route_scope(i),
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

        if _PATH_BOUNDARY_GUARD_RE.search(stripped):
            guards.append(GuardInfo(
                kind="path_boundary", line=i,
                protects_lines=set(range(i, min(i + 10, len(lines) + 1))),
            ))

    return guards


def _collect_js_guard_kinds_for_line(code: str, line: int) -> set[str]:
    lines = code.splitlines()
    guarded: set[str] = set()
    if line <= 0 or line > len(lines):
        return guarded

    open_blocks = 0
    for idx in range(line - 1, -1, -1):
        text = lines[idx].strip()
        open_blocks += lines[idx].count("{") - lines[idx].count("}")
        if not text:
            continue
        if text.startswith("if") or text.startswith("if ") or text.startswith("if("):
            if _JS_INLINE_AUTH_GUARD_RE.search(text):
                guarded.add("auth_check")
            if _OWNERSHIP_GUARD_RE.search(text):
                guarded.add("ownership_check")
            if _INPUT_VALIDATION_GUARD_RE.search(text):
                guarded.add("input_validation")
            if _PATH_BOUNDARY_GUARD_RE.search(text):
                guarded.add("path_boundary")
            if open_blocks <= 0:
                break
    return guarded


# ── Guard-aware finding adjustment ─────────────────────────────────────

_GUARD_CWE_DOWNGRADE_MAP: dict[str, dict[str, float]] = {
    # (guard_kind, cwe) → new_confidence
    "auth_check": {
        "CWE-639": 0.0,   # IDOR — auth check means it's protected
        "CWE-862": 0.0,   # Missing auth — auth check proves it's there
        "CWE-287": 0.0,   # Auth bypass — auth guard present
        "CWE-285": 0.15,  # Improper auth — guard present but may be insufficient
        "CWE-306": 0.0,   # Missing authentication — guard present
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
        "CWE-78": 0.15,   # Command injection — input validated
        "CWE-79": 0.15,   # XSS — input validated
    },
    "path_boundary": {
        "CWE-22": 0.0,    # Path traversal — resolved path checked against base dir
    },
    "null_guard": {
        "CWE-862": 0.0,   # Missing auth — None check before access means auth gate
        "CWE-287": 0.0,   # Auth bypass — None gate present
        "CWE-639": 0.0,   # IDOR in gated context
    },
    "type_guard": {
        "CWE-502": 0.10,  # Unsafe deserialization — type guard present
        "CWE-434": 0.10,  # File upload — type guard present
        "CWE-89": 0.15,   # SQLi — type-constrained input
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
    adjusted = adjust_findings_from_guards(findings, guards) if guards else list(findings)
    final: list[Finding] = []
    for finding in adjusted:
        if not finding.line:
            final.append(finding)
            continue
        guard_kinds = _collect_python_guard_kinds_for_line(tree, finding.line) | _function_scope_guard_kinds(tree, finding.line)
        if finding.cwe == "CWE-862" and "auth_check" in guard_kinds:
            continue
        if finding.cwe == "CWE-639" and "ownership_check" in guard_kinds:
            continue
        if finding.cwe == "CWE-22" and "path_boundary" in guard_kinds:
            continue
        if finding.cwe in {"CWE-285", "CWE-287"} and "auth_check" in guard_kinds:
            finding.confidence = min(finding.confidence, 0.15)
            finding.severity = _severity_downgrade(finding.severity)
            if "AST guard ancestry" not in finding.description:
                finding.description = f"{finding.description} (AST guard ancestry indicates an inline auth check before the sink)"
        final.append(finding)
    return final


def analyze_guards_js(
    code: str,
    findings: list[Finding],
    *,
    filename: str = "",
) -> list[Finding]:
    """JS entry point: extract guards, adjust findings."""
    guards = _extract_js_guards(code, filename)
    adjusted = adjust_findings_from_guards(findings, guards) if guards else list(findings)
    final: list[Finding] = []
    for finding in adjusted:
        if not finding.line:
            final.append(finding)
            continue
        guard_kinds = _collect_js_guard_kinds_for_line(code, finding.line)
        if finding.cwe == "CWE-862" and "auth_check" in guard_kinds:
            continue
        if finding.cwe == "CWE-639" and "ownership_check" in guard_kinds:
            continue
        if finding.cwe == "CWE-22" and "path_boundary" in guard_kinds:
            continue
        final.append(finding)
    return final
