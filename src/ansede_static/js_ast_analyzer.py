from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Callable

from ansede_static._types import AnalysisResult, Finding, Severity, TraceFrame
from ansede_static.js_analyzer import analyze_js
from ansede_static.hardening import detect_minified
from ansede_static.js_engine import (
    JsCall,
    JsPropertyWrite,
    append_trace,
    collect_calls,
    collect_property_writes,
    dedup_findings,
    extract_taint_traces,
    filter_inline_suppressions,
    trace_for_expr,
    trace_has_sanitizer,
)
from ansede_static.js_engine.constants import (
    DOCUMENT_WRITE_CALLEES,
    TIMER_CALLEES,
    COMMAND_EXEC_CALLEES,
    SHELL_TRUE_CALLEES,
    SQL_CALLEES,
    SSRF_CALLEES,
    PATH_CALLEE_PARTS,
    callee_matches,
)
from ansede_static.js_engine.source_map_resolver import (
    load_sourcemap_path,
    remap_findings_to_source_map,
)
from ansede_static.js_engine.sourcemap_rescanner import rescore_via_source_map

from ansede_static.js_engine.project import build_js_project_index, propagate_helper_return_traces
from ansede_static.js_engine.project_context import (
    ProjectContext,
    Runtime,
    classify_runtime,
    is_fs_callee,
)
from ansede_static.js_engine.react import run_react_checks
from ansede_static.js_engine.routes import run_route_checks
from ansede_static.js_engine.taint_checks import run_taint_flow_checks
from ansede_static.js_engine.minified_scanner import scan_minified_js
from ansede_static.engine.clustering import cluster_findings
from ansede_static.engine.confidence import rescore_findings

_log = logging.getLogger(__name__)

_STATIC_SINGLE_RE = re.compile(r"^\s*'([^'\\]|\\.)*'\s*$", re.S)
_STATIC_DOUBLE_RE = re.compile(r'^\s*"([^"\\]|\\.)*"\s*$', re.S)
_STATIC_TEMPLATE_RE = re.compile(r'^\s*`([^`\\]|\\.)*`\s*$', re.S)
_SANITIZE_HTML_RE = re.compile(r'DOMPurify\.sanitize|sanitizeHtml|escapeHtml', re.IGNORECASE)
_DYNAMIC_CONCAT_RE = re.compile(r'(?:\+\s*[A-Za-z_$`"\'])|(?:[A-Za-z_$)\]`"\']\s*\+)', re.IGNORECASE)
_SHELL_TRUE_RE = re.compile(r'\bshell\s*:\s*true\b', re.IGNORECASE)
_SIMPLE_IDENTIFIER_RE = re.compile(r'^\s*[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\s*$')
_VENDOR_JS_PATH_RE = re.compile(r'(?:^|[/\\])(?:vendor|vendors|node_modules|third_party|third-party|bower_components)(?:[/\\]|$)', re.IGNORECASE)
_MINIFIED_JS_PATH_RE = re.compile(r'(?:\.min\.(?:js|css)$|(?:bundle|chunk)\.js$)', re.IGNORECASE)
# Matches innerHTML assignment with a plain string literal (no interpolation/concatenation)
_HARDCODED_INNERHTML_RE = re.compile(
    r"""innerHTML\s*=\s*['\"][^'\"\n]{5,}['\"]""",
    re.IGNORECASE | re.DOTALL,
)
# DOCUMENT_WRITE_CALLEES, TIMER_CALLEES, COMMAND_EXEC_CALLEES, SHELL_TRUE_CALLEES,
# SQL_CALLEES, SSRF_CALLEES, PATH_CALLEE_PARTS, callee_matches
# are all imported from js_engine.constants

_FRAMEWORK_INTERNAL_JS_MARKERS: tuple[str, ...] = (
    "/expressjs__express/lib/",
    "/pallets__flask/src/flask/",
    "/django__django/django/",
    "/tiangolo__fastapi/fastapi/",
    "/site-packages/express/",
    "/site-packages/flask/",
    "/site-packages/django/",
    "/site-packages/fastapi/",
    "/site-packages/starlette/",
)

_VENDOR_NOISE_CWES: frozenset[str] = frozenset({
    "CWE-22", "CWE-79", "CWE-1321", "CWE-1333", "CWE-601", "CWE-862", "CWE-918",
})

# CWEs that are noise in test files (test routes don't need auth, etc.)
_TEST_NOISE_CWES: frozenset[str] = frozenset({
    "CWE-862", "CWE-352", "CWE-209", "CWE-918", "CWE-1188",
    "CWE-98",  # Dynamic require() in test files — pattern not security
})

_FRAMEWORK_INTERNAL_NOISE_CWES: frozenset[str] = frozenset({
    "CWE-22", "CWE-1333", "CWE-601", "CWE-918",
})

# Backward-compatible wrapper — extracts .callee from JsCall and delegates to
# the canonical callee_matches from js_engine.constants.
def _callee_matches(call: JsCall, targets: frozenset[str]) -> bool:
    return callee_matches(call.callee, targets)


def _downgrade_findings_for_missing_sourcemap(
    findings: list[Finding],
    *,
    confidence: float = 0.35,
) -> list[Finding]:
    downgraded: list[Finding] = []
    for finding in findings:
        downgraded.append(Finding(
            category=finding.category,
            severity=finding.severity,
            title=finding.title,
            description=(
                f"{finding.description} (minified bundle without source map; "
                "confidence downgraded to low)"
            ),
            line=finding.line,
            suggestion=finding.suggestion,
            rule_id=finding.rule_id,
            cwe=finding.cwe,
            agent=finding.agent,
            confidence=min(finding.confidence, confidence),
            auto_fix=finding.auto_fix,
            explanation=finding.explanation,
            trace=finding.trace,
            analysis_kind=finding.analysis_kind,
            triggering_code=finding.triggering_code,
        ))
    return downgraded


def _normalized_path(filename: str) -> str:
    return filename.replace("\\", "/").lower()


def _is_vendor_or_minified_js_path(filename: str) -> bool:
    path_norm = _normalized_path(filename)
    return bool(_VENDOR_JS_PATH_RE.search(path_norm) or _MINIFIED_JS_PATH_RE.search(path_norm))


def _is_framework_internal_js_path(filename: str) -> bool:
    path_norm = _normalized_path(filename)
    return any(marker in path_norm for marker in _FRAMEWORK_INTERNAL_JS_MARKERS)


def _is_test_js_path(filename: str) -> bool:
    """Check if the file path suggests a test file."""
    path_norm = _normalized_path(filename)
    return any(m in path_norm for m in (
        "/test/", "/tests/", "/__tests__/", "/spec/", "/e2e/",
        "/perf/", "/bench/", "/benchmarks/", "/examples/",
    ))


def _downgrade_noise_findings(
    findings: list[Finding],
    *,
    reason: str,
    cwes: frozenset[str],
    confidence: float = 0.2,
    severity: Severity = Severity.LOW,
) -> list[Finding]:
    for finding in findings:
        if finding.cwe not in cwes:
            continue
        if finding.severity.sort_key < severity.sort_key:
            finding.severity = severity
        finding.confidence = min(finding.confidence, confidence)
        if reason not in finding.description:
            finding.description = f"{finding.description} ({reason})"
    return findings


def _apply_js_noise_policy(
    findings: list[Finding],
    *,
    filename: str,
    minified: object,
    source_map_path: str | Path | None,
    project_context: ProjectContext | None = None,
) -> list[Finding]:
    if not filename:
        return findings

    vendor_like = _is_vendor_or_minified_js_path(filename) or bool(getattr(minified, "is_minified", False) and source_map_path is None)
    framework_internal = _is_framework_internal_js_path(filename)

    if vendor_like:
        findings = _downgrade_noise_findings(
            findings,
            reason="vendor/minified asset heuristic downgraded",
            cwes=_VENDOR_NOISE_CWES,
            confidence=0.15,
            severity=Severity.LOW,
        )
    if framework_internal:
        findings = _downgrade_noise_findings(
            findings,
            reason="framework-internal implementation heuristic downgraded",
            cwes=_FRAMEWORK_INTERNAL_NOISE_CWES,
            confidence=0.25,
            severity=Severity.LOW,
        )
    # Gap 2: Downgrade CWE-862/352/209 findings in test files
    # Check via project_context OR via filename heuristic (for fallback findings)
    is_test = (
        (project_context and project_context.is_test)
        or _is_test_js_path(filename)
    )
    if is_test:
        findings = _downgrade_noise_findings(
            findings,
            reason="test file heuristic downgraded",
            cwes=_TEST_NOISE_CWES,
            confidence=0.25,
            severity=Severity.LOW,
        )
    # Gap 1: Downgrade innerHTML findings where the description shows a hardcoded string
    for finding in findings:
        if finding.cwe == "CWE-79" and _HARDCODED_INNERHTML_RE.search(finding.description or ""):
            finding.confidence = min(finding.confidence, 0.3)
            if "hardcoded string" not in finding.description:
                finding.description = f"{finding.description} (hardcoded string — likely FP)"
    return findings



def _expr_is_static_string(expr: str) -> bool:
    text = expr.strip()
    if not text:
        return False
    if _STATIC_SINGLE_RE.match(text) or _STATIC_DOUBLE_RE.match(text):
        return True
    return bool(_STATIC_TEMPLATE_RE.match(text) and "${" not in text)



def _expr_has_template_interpolation(expr: str) -> bool:
    return "${" in expr



def _expr_has_concat(expr: str) -> bool:
    return bool(_DYNAMIC_CONCAT_RE.search(expr))



def _expr_is_sanitized_html(expr: str) -> bool:
    return bool(_SANITIZE_HTML_RE.search(expr))



def _expr_looks_like_function_reference(expr: str) -> bool:
    text = expr.strip()
    if not text:
        return False
    if text.startswith("function") or "=>" in text:
        return True
    return bool(_SIMPLE_IDENTIFIER_RE.match(text))



def _generic_dynamic_trace(expr: str, *, line: int) -> tuple[TraceFrame, ...]:
    snippet = " ".join(expr.strip().split())[:80]
    return (TraceFrame(kind="source", label=f"dynamic expression `{snippet}`", line=line),)



def _flow_trace(
    expr: str,
    taint_traces: dict[str, tuple[TraceFrame, ...]],
    *,
    line: int,
    allow_generic_dynamic: bool,
) -> tuple[TraceFrame, ...]:
    trace = trace_for_expr(expr, taint_traces, line=line)
    if trace:
        return trace
    if allow_generic_dynamic and (
        _expr_has_template_interpolation(expr)
        or _expr_has_concat(expr)
        or (not _expr_is_static_string(expr) and not _expr_looks_like_function_reference(expr))
    ):
        return _generic_dynamic_trace(expr, line=line)
    return ()



def _make_finding(
    *,
    line: int,
    title: str,
    description: str,
    suggestion: str,
    severity: Severity,
    rule_id: str,
    cwe: str,
    trace: tuple[TraceFrame, ...],
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
        agent="js-ast-analyzer",
        confidence=0.96,
        analysis_kind="syntax-ast",
        trace=trace,
    )



def _check_property_xss(
    writes: list[JsPropertyWrite],
    taint_traces: dict[str, tuple[TraceFrame, ...]],
) -> list[Finding]:
    findings: list[Finding] = []
    for write in writes:
        expr = write.expression
        if _expr_is_sanitized_html(expr):
            continue
        if _expr_is_static_string(expr) and not _expr_has_template_interpolation(expr):
            continue

        if _expr_has_template_interpolation(expr):
            trace = _flow_trace(expr, taint_traces, line=write.line, allow_generic_dynamic=True)
            if trace_has_sanitizer(trace, "html"):
                continue
            trace = append_trace(trace, "sink", f"sink `.{write.property_name}`", line=write.line)
            findings.append(_make_finding(
                line=write.line,
                title=f"CWE-79: XSS via unencoded template literal inserted into HTML at line {write.line}",
                description=(
                    f"Template literal with user-controlled content is written to `.{write.property_name}` at L{write.line}: "
                    f"`{write.raw[:90]}`."
                ),
                suggestion="Encode or sanitize HTML before inserting it, or switch to `textContent` for plain text.",
                severity=Severity.HIGH,
                rule_id="JS-059",
                cwe="CWE-79",
                trace=trace,
            ))
            continue

        trace = _flow_trace(expr, taint_traces, line=write.line, allow_generic_dynamic=True)
        if not trace:
            continue
        if trace_has_sanitizer(trace, "html"):
            continue
        trace = append_trace(trace, "sink", f"sink `.{write.property_name}` assignment", line=write.line)
        findings.append(_make_finding(
            line=write.line,
            title=f"CWE-79: XSS via innerHTML assignment at line {write.line}",
            description=(
                f"Unsanitized content is assigned to `.{write.property_name}` at L{write.line}: `{write.raw[:90]}`. "
                f"An attacker can inject active HTML or script into the page."
            ),
            suggestion="Use `textContent` for plain text or sanitize with DOMPurify before writing HTML.",
            severity=Severity.CRITICAL,
            rule_id="JS-001",
            cwe="CWE-79",
            trace=trace,
        ))
    return findings



def _check_document_write(
    calls: list[JsCall],
    taint_traces: dict[str, tuple[TraceFrame, ...]],
) -> list[Finding]:
    findings: list[Finding] = []
    for call in calls:
        if not _callee_matches(call, DOCUMENT_WRITE_CALLEES) or not call.arguments:
            continue
        expr = call.arguments[0]
        if _expr_is_static_string(expr):
            continue
        trace = _flow_trace(expr, taint_traces, line=call.line, allow_generic_dynamic=True)
        if not trace:
            continue
        if trace_has_sanitizer(trace, "html"):
            continue
        trace = append_trace(trace, "sink", "sink `document.write()`", line=call.line)
        findings.append(_make_finding(
            line=call.line,
            title=f"CWE-79: XSS via document.write() at line {call.line}",
            description=(
                f"`document.write()` receives dynamic content at L{call.line}: `{call.raw[:90]}`. "
                f"Any user-controlled string passed here is rendered as raw HTML."
            ),
            suggestion="Replace `document.write()` with safe DOM APIs and `textContent`, or sanitize before rendering HTML.",
            severity=Severity.CRITICAL,
            rule_id="JS-002",
            cwe="CWE-79",
            trace=trace,
        ))
    return findings



def _check_eval(
    calls: list[JsCall],
    taint_traces: dict[str, tuple[TraceFrame, ...]],
) -> list[Finding]:
    findings: list[Finding] = []
    for call in calls:
        if call.callee.split(".")[-1] != "eval" or not call.arguments:
            continue
        expr = call.arguments[0]
        if _expr_is_static_string(expr):
            continue
        trace = _flow_trace(expr, taint_traces, line=call.line, allow_generic_dynamic=True)
        if not trace:
            continue
        trace = append_trace(trace, "sink", "sink `eval()`", line=call.line)
        findings.append(_make_finding(
            line=call.line,
            title=f"CWE-95: Code injection via eval() at line {call.line}",
            description=(
                f"`eval()` is called with dynamic content at L{call.line}: `{call.raw[:90]}`. "
                f"If the argument is attacker-influenced, arbitrary JavaScript can execute."
            ),
            suggestion="Remove `eval()`. Parse data with `JSON.parse()` or use a safe expression interpreter.",
            severity=Severity.CRITICAL,
            rule_id="JS-004",
            cwe="CWE-95",
            trace=trace,
        ))
    return findings



def _check_function_constructor(calls: list[JsCall]) -> list[Finding]:
    findings: list[Finding] = []
    for call in calls:
        if call.callee != "new Function":
            continue
        trace = append_trace((), "sink", "sink `new Function()`", line=call.line)
        findings.append(_make_finding(
            line=call.line,
            title=f"CWE-95: Code injection via new Function() at line {call.line}",
            description=(
                f"`new Function(...)` is used at L{call.line}: `{call.raw[:90]}`. "
                f"This is equivalent to `eval()` and turns strings into executable code."
            ),
            suggestion="Avoid `new Function()`. Use explicit code paths or a safe DSL/interpreter instead.",
            severity=Severity.CRITICAL,
            rule_id="JS-005",
            cwe="CWE-95",
            trace=trace,
        ))
    return findings



def _check_timer_string_eval(
    calls: list[JsCall],
    taint_traces: dict[str, tuple[TraceFrame, ...]],
) -> list[Finding]:
    findings: list[Finding] = []
    for call in calls:
        if not _callee_matches(call, TIMER_CALLEES) or not call.arguments:
            continue
        expr = call.arguments[0]
        if _expr_looks_like_function_reference(expr):
            continue
        if not (_expr_is_static_string(expr) or _expr_has_template_interpolation(expr) or _expr_has_concat(expr) or trace_for_expr(expr, taint_traces, line=call.line)):
            continue
        trace = _flow_trace(expr, taint_traces, line=call.line, allow_generic_dynamic=True)
        trace = append_trace(trace, "sink", f"sink `{call.callee}()`", line=call.line)
        findings.append(_make_finding(
            line=call.line,
            title=f"CWE-95: setTimeout/setInterval with string argument at line {call.line}",
            description=(
                f"`{call.callee}` is called with a string-like argument at L{call.line}: `{call.raw[:90]}`. "
                f"String arguments are evaluated like `eval()`."
            ),
            suggestion="Pass a function reference or closure to the timer instead of a string.",
            severity=Severity.HIGH,
            rule_id="JS-006",
            cwe="CWE-95",
            trace=trace,
        ))
    return findings



def _check_command_exec(
    calls: list[JsCall],
    taint_traces: dict[str, tuple[TraceFrame, ...]],
    *,
    project_context: ProjectContext | None = None,
) -> list[Finding]:
    # Skip command injection checks in browser-side code
    if project_context and project_context.skip_node_rules:
        return []
    findings: list[Finding] = []
    for call in calls:
        if not _callee_matches(call, COMMAND_EXEC_CALLEES) or not call.arguments:
            continue
        expr = call.arguments[0]
        trace = _flow_trace(expr, taint_traces, line=call.line, allow_generic_dynamic=False)
        if not trace and not (_expr_has_template_interpolation(expr) or _expr_has_concat(expr)):
            continue
        if not trace:
            trace = _generic_dynamic_trace(expr, line=call.line)
        trace = append_trace(trace, "sink", f"sink `{call.callee}()`", line=call.line)
        findings.append(_make_finding(
            line=call.line,
            title=f"CWE-78: Command injection via exec() at line {call.line}",
            description=(
                f"Shell command construction at L{call.line} is dynamic: `{call.raw[:90]}`. "
                f"Metacharacters in user input can execute arbitrary OS commands."
            ),
            suggestion="Use `execFile()` or `spawn()` with an argument array and strict validation instead of a shell command string.",
            severity=Severity.CRITICAL,
            rule_id="JS-007",
            cwe="CWE-78",
            trace=trace,
        ))
    return findings



def _check_shell_true(calls: list[JsCall]) -> list[Finding]:
    findings: list[Finding] = []
    for call in calls:
        if not _callee_matches(call, SHELL_TRUE_CALLEES):
            continue
        if not any(_SHELL_TRUE_RE.search(argument) for argument in call.arguments[1:]):
            continue
        trace = append_trace((), "sink", f"sink `{call.callee}` with `shell: true`", line=call.line)
        findings.append(_make_finding(
            line=call.line,
            title=f"CWE-78: Command injection via spawn with shell:true at line {call.line}",
            description=(
                f"`{call.callee}` is invoked with `shell: true` at L{call.line}: `{call.raw[:90]}`. "
                f"This routes execution through the shell and enables metacharacter injection."
            ),
            suggestion="Remove `shell: true` and pass command arguments as a list instead.",
            severity=Severity.CRITICAL,
            rule_id="JS-008",
            cwe="CWE-78",
            trace=trace,
        ))
    return findings



def _check_sql_injection(
    calls: list[JsCall],
    taint_traces: dict[str, tuple[TraceFrame, ...]],
) -> list[Finding]:
    findings: list[Finding] = []
    for call in calls:
        if not _callee_matches(call, SQL_CALLEES) or not call.arguments:
            continue
        expr = call.arguments[0]
        trace = _flow_trace(expr, taint_traces, line=call.line, allow_generic_dynamic=False)
        has_template = _expr_has_template_interpolation(expr)
        has_concat = _expr_has_concat(expr)
        if not trace and not (has_template or has_concat):
            continue
        if _expr_is_static_string(expr) and len(call.arguments) >= 2 and not has_template:
            continue
        if not trace:
            trace = _generic_dynamic_trace(expr, line=call.line)
        trace = append_trace(trace, "sink", f"sink `{call.callee}()`", line=call.line)
        if has_template:
            title = f"CWE-89: SQL injection via template literal query at line {call.line}"
            description = (
                f"SQL execution at L{call.line} uses a template literal with interpolation: `{call.raw[:90]}`. "
                f"This is equivalent to building SQL with string concatenation."
            )
            rule_id = "JS-010"
        else:
            title = f"CWE-89: SQL injection via string concatenation at line {call.line}"
            description = (
                f"SQL execution at L{call.line} assembles the query dynamically: `{call.raw[:90]}`. "
                f"An attacker can alter the query structure if input is not parameterized."
            )
            rule_id = "JS-009"
        findings.append(_make_finding(
            line=call.line,
            title=title,
            description=description,
            suggestion="Use parameterized queries with placeholders instead of interpolating data into SQL text.",
            severity=Severity.CRITICAL,
            rule_id=rule_id,
            cwe="CWE-89",
            trace=trace,
        ))
    return findings



def _check_dynamic_require(
    calls: list[JsCall],
    *,
    project_context: ProjectContext | None = None,
) -> list[Finding]:
    # Skip dynamic require checks in browser-side code
    if project_context and project_context.skip_node_rules:
        return []
    findings: list[Finding] = []
    for call in calls:
        # Only match the Node.js global `require()` — not custom object methods like
        # `handlers.require(name)` or `loader.require(mod)`.  A dot-qualified callee
        # such as `foo.require` is an object method, not module loading.
        if "." in call.callee or call.callee.split(".")[-1] != "require":
            continue
        if not call.arguments:
            continue
        expr = call.arguments[0]
        if _expr_is_static_string(expr):
            continue
        trace = _generic_dynamic_trace(expr, line=call.line)
        trace = append_trace(trace, "sink", "sink `require()`", line=call.line)
        findings.append(_make_finding(
            line=call.line,
            title=f"CWE-98: Dynamic require() with variable path at line {call.line}",
            description=(
                f"`require()` is called with a non-literal argument at L{call.line}: `{call.raw[:90]}`. "
                f"If the path is attacker-controlled, arbitrary modules can be loaded."
            ),
            suggestion="Use only static module paths in `require()` and never pass user-controlled values.",
            severity=Severity.HIGH,
            rule_id="JS-023",
            cwe="CWE-98",
            trace=trace,
        ))
    return findings



# ── URL-route patterns to exclude from path traversal detection ────────────
# These are URL route fragments, not file-system paths
_URL_ROUTE_RE = re.compile(
    r"^\s*['\"`]/|/\(?::\w+|\?\w+=|#\w+",
)


def _check_path_traversal(
    calls: list[JsCall],
    taint_traces: dict[str, tuple[TraceFrame, ...]],
    *,
    code: str = "",
    project_context: ProjectContext | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for call in calls:
        short = call.callee.split(".")[-1]
        if short not in PATH_CALLEE_PARTS or not call.arguments:
            continue

        # ── Ambiguous callee guard ────────────────────────────────────
        # `open` / `openSync` match XMLHttpRequest.open(), modals.open(),
        # window.open(), etc. — none of which are filesystem operations.
        # Only flag these when we can confirm they are fs operations.
        if short in {"open", "openSync", "resolve", "join"}:
            if not is_fs_callee(call.callee, code=code):
                continue

        # ── Runtime context guard ─────────────────────────────────────
        # If the file is browser-side, skip all path-traversal rules —
        # there is no filesystem in a browser.
        if project_context and project_context.skip_node_rules:
            continue

        expr = call.arguments[0]
        # Skip URL route patterns (e.g., '/install/step/' + step) — these are not file paths
        raw_arg = call.raw[call.raw.find(call.arguments[0]):] if call.arguments else ""
        if _URL_ROUTE_RE.match(raw_arg):
            continue
        trace = _flow_trace(expr, taint_traces, line=call.line, allow_generic_dynamic=False)
        if not trace:
            continue
        trace = append_trace(trace, "sink", "sink `fs/path operation`", line=call.line)
        findings.append(_make_finding(
            line=call.line,
            title=f"CWE-22: Path traversal via tainted variable at line {call.line}",
            description=(
                f"A file-system or path operation at L{call.line} uses a user-influenced value: `{call.raw[:90]}`. "
                f"Attackers can use `../` sequences to escape the intended directory."
            ),
            suggestion="Normalize with `path.basename()` or a strict allowlist and verify the resolved path stays under the expected base directory.",
            severity=Severity.HIGH,
            rule_id="JS-038",
            cwe="CWE-22",
            trace=trace,
        ))
    return findings



def _check_open_redirect(
    calls: list[JsCall],
    taint_traces: dict[str, tuple[TraceFrame, ...]],
    property_writes: list[JsPropertyWrite] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    # Server-side: res.redirect(url) or res.redirect(status, url)
    for call in calls:
        if call.callee not in ("res.redirect", "reply.redirect") or not call.arguments:
            continue
        # If first arg is a number (status code), the URL is the second arg
        expr = call.arguments[0]
        if len(call.arguments) >= 2 and call.arguments[0].isdigit():
            expr = call.arguments[1]
        trace = _flow_trace(expr, taint_traces, line=call.line, allow_generic_dynamic=False)
        if not trace:
            continue
        trace = append_trace(trace, "sink", f"sink `{call.callee}()`", line=call.line)
        findings.append(_make_finding(
            line=call.line,
            title=f"CWE-601: Open redirect via tainted variable at line {call.line}",
            description=(
                f"`{call.callee}()` at L{call.line} uses a user-influenced destination: `{call.raw[:90]}`. "
                f"Attackers can redirect victims to untrusted sites."
            ),
            suggestion="Validate redirect targets against an allowlist of permitted relative paths or trusted hosts.",
            severity=Severity.HIGH,
            rule_id="JS-039",
            cwe="CWE-601",
            trace=trace,
        ))
    # Client-side: window.location / location.href = userInput
    if property_writes:
        for write in property_writes:
            if write.property_name not in ("href", "search", "hash", "pathname"):
                continue
            expr = write.expression
            if _expr_is_static_string(expr):
                continue
            trace = _flow_trace(expr, taint_traces, line=write.line, allow_generic_dynamic=True)
            if not trace:
                continue
            trace = append_trace(trace, "sink", f"sink `location.{write.property_name}`", line=write.line)
            findings.append(_make_finding(
                line=write.line,
                title=f"CWE-601: Client-side open redirect via location.{write.property_name} at line {write.line}",
                description=(
                    f"`location.{write.property_name}` at L{write.line} is assigned user-influenced content: "
                    f"`{write.raw[:90]}`. Attackers can redirect victims to phishing pages."
                ),
                suggestion="Validate redirect URLs against an allowlist of trusted domains before assigning to location.",
                severity=Severity.MEDIUM,
                rule_id="JS-039",
                cwe="CWE-601",
                trace=trace,
            ))
    return findings



def _check_ssrf(
    calls: list[JsCall],
    taint_traces: dict[str, tuple[TraceFrame, ...]],
    *,
    project_context: ProjectContext | None = None,
) -> list[Finding]:
    # Skip SSRF checks in browser-side code — browser fetch() is standard,
    # not a server-side outbound request to internal infrastructure.
    if project_context and project_context.skip_node_rules:
        return []
    findings: list[Finding] = []
    for call in calls:
        if not _callee_matches(call, SSRF_CALLEES) or not call.arguments:
            continue
        expr = call.arguments[0]
        trace = _flow_trace(expr, taint_traces, line=call.line, allow_generic_dynamic=False)
        if not trace:
            continue
        trace = append_trace(trace, "sink", "sink `HTTP client call`", line=call.line)
        findings.append(_make_finding(
            line=call.line,
            title=f"CWE-918: SSRF via tainted variable at line {call.line}",
            description=(
                f"HTTP client code at L{call.line} uses a user-influenced URL: `{call.raw[:90]}`. "
                f"Attackers can target internal services or cloud metadata endpoints."
            ),
            suggestion="Parse and validate the URL against an explicit host allowlist and block private IP ranges.",
            severity=Severity.HIGH,
            rule_id="JS-040",
            cwe="CWE-918",
            trace=trace,
        ))
    return findings


def _check_csrf_js(code: str) -> list[Finding]:
    """CWE-352: State-changing Express routes without CSRF token validation."""
    findings: list[Finding] = []
    _MUTATING_METHOD_RE = re.compile(
        r'(?:app|router)\.(?:post|put|patch|delete|del)\s*\(\s*[\'"]',
        re.IGNORECASE,
    )
    _CSRF_TOKEN_RE = re.compile(
        r'(?:csrf|csrfToken|_csrf|xsrf|XSRF-TOKEN|csrftoken|'
        r'csrfProtection|csurf|req\.csrfToken|lusca)',
        re.IGNORECASE,
    )
    # ── Global CSRF middleware pre-scan ───────────────────────────────
    # If the app applies CSRF middleware globally (app.use(csurf()),
    # server.use(csrf()), etc.), ALL routes are protected — skip checking.
    _GLOBAL_CSRF_RE = re.compile(
        r'(?:app|server|router|express)\.use\s*\(\s*'
        r'(?:csurf|csrf|lusca\.csrf|helmet|csrfProtection)\b',
        re.IGNORECASE,
    )
    if _GLOBAL_CSRF_RE.search(code):
        return findings  # Global middleware present — all routes protected
    # ──────────────────────────────────────────────────────────────────
    for lineno, line in enumerate(code.splitlines(), 1):
        if not _MUTATING_METHOD_RE.search(line):
            continue
        # Look ahead a few lines for CSRF protection
        lookahead = "\n".join(code.splitlines()[lineno:lineno + 5])
        if _CSRF_TOKEN_RE.search(lookahead):
            continue
        findings.append(_make_finding(
            line=lineno,
            title=f"CWE-352: State-changing route may lack CSRF protection at line {lineno}",
            description=(
                f"POST/PUT/DELETE route defined at L{lineno} without detectable CSRF "
                "token validation. Cross-site request forgery can force authenticated "
                "users to perform unintended actions."
            ),
            suggestion="Use csurf middleware or implement CSRF token validation for all mutating routes.",
            severity=Severity.HIGH,
            rule_id="JS-041",
            cwe="CWE-352",
            trace=(TraceFrame(kind="source", label=f"route handler at L{lineno}", line=lineno),),
        ))
    # Reduce confidence for heuristic detection
    for f in findings:
        f.confidence = 0.80
        f.analysis_kind = "pattern-heuristic"
    return findings


def _check_file_upload_js(code: str, calls: list[JsCall]) -> list[Finding]:
    """CWE-434: File upload handling without content-type validation."""
    findings: list[Finding] = []
    _UPLOAD_RECEIVE_RE = re.compile(
        r'(?:req\.files|req\.file|multer|busboy|formidable|'
        r'express-fileupload|\.single\s*\(|\.array\s*\(|\.fields\s*\()',
        re.IGNORECASE,
    )
    _UPLOAD_VALIDATION_RE = re.compile(
        r'(?:mimetype|filetype|allowedTypes|fileFilter|'
        r'magic|\.endsWith|\.match\s*\(\s*[\'"]\.(?:jpg|png)',
        re.IGNORECASE,
    )
    _UPLOAD_SAVE_RE = re.compile(
        r'(?:\.mv\s*\(|fs\.(?:writeFile|createWriteStream|rename)|'
        r'\.pipe\s*\(|\.save\s*\()',
        re.IGNORECASE,
    )
    lines = code.splitlines()
    has_upload = any(_UPLOAD_RECEIVE_RE.search(ln) for ln in lines)
    has_save = any(_UPLOAD_SAVE_RE.search(ln) for ln in lines)
    has_validation = any(_UPLOAD_VALIDATION_RE.search(ln) for ln in lines)
    if not (has_upload and has_save) or has_validation:
        return findings
    line = next((i + 1 for i, ln in enumerate(lines) if _UPLOAD_RECEIVE_RE.search(ln)), 1)
    findings.append(_make_finding(
        line=line,
        title=f"CWE-434: File upload at line {line} lacks content-type validation",
        description=(
            f"File upload handler at L{line} receives files and writes them to disk "
            "without validating content type. Attackers can upload executable files."
        ),
        suggestion="Validate file MIME type with file-type or magic-bytes, and use an extension allowlist.",
        severity=Severity.HIGH,
        rule_id="JS-042",
        cwe="CWE-434",
        trace=(TraceFrame(kind="source", label=f"upload handler near L{line}", line=line),),
    ))
    for f in findings:
        f.confidence = 0.85
        f.analysis_kind = "pattern-heuristic"
    return findings


def _check_idor_js(code: str) -> list[Finding]:
    """CWE-639: Auth middleware + direct object access without ownership filter."""
    findings: list[Finding] = []
    _AUTH_MIDDLEWARE_RE = re.compile(
        r'(?:req\.isAuthenticated\(\)|req\.user|passport\.authenticate|'
        r'ensureAuthenticated|requireAuth|authMiddleware|'
        r'\.use\s*\(\s*(?:auth|requireAuth|ensureAuth))',
        re.IGNORECASE,
    )
    _DIRECT_OBJECT_ACCESS_RE = re.compile(
        r'(?:\b(?:findById|findOne|findByPk|get)\s*\(\s*req\.(?:params|query|body)\.'
        r'|\bModel\.(?:findById|findOne)\s*\(\s*req\.)',
        re.IGNORECASE,
    )
    _OWNER_FILTER_RE = re.compile(
        r'(?:\bowner\b|\buserId\b|\bcreatedBy\b|\bauthor\b|'
        r'where\s*:\s*\{[^}]*req\.user\.)',
        re.IGNORECASE,
    )
    lines = code.splitlines()
    has_auth = any(_AUTH_MIDDLEWARE_RE.search(ln) for ln in lines)
    has_direct_access = any(_DIRECT_OBJECT_ACCESS_RE.search(ln) for ln in lines)
    has_owner_filter = any(_OWNER_FILTER_RE.search(ln) for ln in lines)
    if not (has_auth and has_direct_access) or has_owner_filter:
        return findings
    line = next((i + 1 for i, ln in enumerate(lines) if _DIRECT_OBJECT_ACCESS_RE.search(ln)), 1)
    findings.append(_make_finding(
        line=line,
        title=f"CWE-639: Possible IDOR — authenticated object access without ownership check at line {line}",
        description=(
            f"Authenticated route at L{line} performs direct object lookup by "
            "request parameter without filtering by the current user. Attackers "
            "can enumerate IDs to access other users' data."
        ),
        suggestion="Filter database queries by the authenticated user: `Model.findOne({ _id: id, owner: req.user.id })`.",
        severity=Severity.HIGH,
        rule_id="JS-043",
        cwe="CWE-639",
        trace=(TraceFrame(kind="source", label=f"object access near L{line}", line=line),),
    ))
    for f in findings:
        f.confidence = 0.85
        f.analysis_kind = "pattern-heuristic"
    return findings



def _build_checker_list(
    calls: list[JsCall],
    property_writes: list[JsPropertyWrite],
    taint_traces,  # type: ignore[arg-type]
    project_ctx: ProjectContext,
    code: str,
    filename: str,
    project,  # type: ignore[arg-type]
    global_graph: object | None,
) -> list[Callable[[], list[Finding]]]:
    """Build the list of structural checker lambdas."""
    return [
        lambda: _check_property_xss(property_writes, taint_traces),
        lambda: _check_document_write(calls, taint_traces),
        lambda: _check_eval(calls, taint_traces),
        lambda: _check_function_constructor(calls),
        lambda: _check_timer_string_eval(calls, taint_traces),
        lambda: _check_command_exec(calls, taint_traces, project_context=project_ctx),
        lambda: _check_shell_true(calls),
        lambda: _check_sql_injection(calls, taint_traces),
        lambda: _check_dynamic_require(calls, project_context=project_ctx),
        lambda: _check_path_traversal(calls, taint_traces, code=code, project_context=project_ctx),
        lambda: _check_open_redirect(calls, taint_traces, property_writes=property_writes),
        lambda: _check_ssrf(calls, taint_traces, project_context=project_ctx),
        lambda: _check_csrf_js(code),
        lambda: _check_file_upload_js(code, calls),
        lambda: _check_idor_js(code),
        lambda: run_taint_flow_checks(
            code, agent="js-ast-analyzer", analysis_kind="syntax-ast",
            filename=filename, project=project, global_graph=global_graph,
            project_context=project_ctx,
        ),
        lambda: run_react_checks(
            code, calls, taint_traces,
            agent="js-ast-analyzer", analysis_kind="syntax-ast",
        ),
        lambda: run_route_checks(
            code, agent="js-ast-analyzer", analysis_kind="syntax-ast",
            filename=filename, project=project,
        ),
    ]


def _run_structural_checkers(
    code: str, filename: str, global_graph: object | None,
) -> tuple[list[Finding], ProjectContext, object, Any]:
    """Run all structural JS checkers. Returns (findings, project_ctx, project)."""
    structural_findings: list[Finding] = []
    minified = detect_minified(filename or "<memory>", code)
    project_ctx = ProjectContext()
    project = None

    try:
        if filename and not minified.is_minified:
            project = build_js_project_index(filename, code)
        calls = collect_calls(code)
        property_writes = collect_property_writes(code)
        taint_traces = extract_taint_traces(code)
        if project and filename:
            taint_traces = propagate_helper_return_traces(
                project, filename, code, taint_traces, global_graph=global_graph,
            )
        project_ctx = classify_runtime(code, file_path=filename)

        checkers = _build_checker_list(
            calls, property_writes, taint_traces, project_ctx,
            code, filename, project, global_graph,
        )
        for checker in checkers:
            structural_findings.extend(checker())
    except (ValueError, TypeError, RecursionError, re.error) as exc:
        _log.debug("ansede-static: syntax-aware JS analysis failed on %r: %s", filename, exc, exc_info=True)

    return structural_findings, project_ctx, project, minified


def _dedup_and_merge(
    merged: list[Finding], new_findings: list[Finding], key_attr: str = "cwe",
) -> list[Finding]:
    """Merge new findings into merged list, deduplicating by (cwe, line)."""
    existing: set[tuple[str, int]] = set()
    for f in merged:
        existing.add((f.cwe or "", f.line or 0))
    for sf in new_findings:
        if (sf.cwe or "", sf.line or 0) not in existing:
            merged.append(sf)
            existing.add((sf.cwe or "", sf.line or 0))
    return merged


def _rust_fast_path(code: str, filename: str) -> AnalysisResult | None:
    """Use Rust Tree-sitter for a fast pre-check.
    Returns an empty AnalysisResult if the file is trivially clean
    (no function calls, no taint sources). Returns None to fall through
    to the full analyzer."""
    try:
        from ansede_static.engine.rust_parser import HAS_RUST_CORE, fast_parse
    except ImportError:
        return None
    if not HAS_RUST_CORE:
        return None

    lang = "javascript"
    raw = fast_parse(code, lang, filename)
    if not raw or not raw.get("nodes"):
        return None

    # Fast-path short-circuit disabled: pattern rules and other
    # non-call-based detectors (e.g. open redirect, prototype pollution)
    # can trigger even when no call expressions are present.
    # Always fall through to full analysis.
    return None


def analyze_js_ast(code: str, filename: str = "", global_graph: object | None = None) -> AnalysisResult:
    # Rust fast-path: skip analysis for trivially clean files
    fast = _rust_fast_path(code, filename)
    if fast is not None:
        return fast

    result = AnalysisResult(
        file_path=filename,
        language="javascript",
        lines_scanned=len(code.splitlines()),
    )

    structural_findings, project_ctx, project, minified = _run_structural_checkers(
        code, filename, global_graph,
    )
    source_map_path = load_sourcemap_path(filename) if filename else None

    fallback = analyze_js(code, filename, global_graph=global_graph, project=project)
    merged = cluster_findings(structural_findings + fallback.findings)
    merged = rescore_findings(merged)
    merged = remap_findings_to_source_map(merged, filename)

    # Source-map-aware rescan
    if minified.is_minified and filename:
        try:
            sourcemap_findings = rescore_via_source_map(
                code, filename,
                scan_fn=lambda c, f: analyze_js_ast(c, f).findings,
            )
            merged = _dedup_and_merge(merged, sourcemap_findings)
        except Exception:
            _log.exception("Source-map rescan failed for %s", filename)

    # Minified JS regex pre-scanner
    if minified.is_minified and not _is_vendor_or_minified_js_path(filename):
        try:
            minified_findings = scan_minified_js(code, filename=filename)
            merged = _dedup_and_merge(merged, minified_findings)
        except Exception:
            _log.exception("Minified JS pre-scanner failed for %s", filename)

    if minified.is_minified and source_map_path is None:
        merged = _downgrade_findings_for_missing_sourcemap(merged)
    merged = _apply_js_noise_policy(
        merged,
        filename=filename,
        minified=minified,
        source_map_path=source_map_path,
        project_context=project_ctx,
    )
    result.findings = filter_inline_suppressions(merged, code)

    # Symbolic guard analysis
    try:
        from ansede_static.engine.symbolic_guards import analyze_guards_js
        result.findings = analyze_guards_js(code, result.findings, filename=filename)
    except Exception:
        _log.exception("Symbolic guard analysis failed for %s", filename)

    return result
