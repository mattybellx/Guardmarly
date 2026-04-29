from __future__ import annotations

import logging
import re
import warnings as _warnings
from pathlib import Path

from ansede_static._types import AnalysisResult, Finding, Severity, TraceFrame
from ansede_static.js_analyzer import analyze_js
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

_warnings.warn(
    "ansede_static.js_ast_analyzer is deprecated and will be removed in a future release. "
    "Use ansede_static.v2.engine with the v2 JS rule pack instead. "
    "The v2 engine provides tree-sitter-backed normalization, structured taint tracking, "
    "and the full rule protocol. See docs/writing-rules.md for migration guidance.",
    DeprecationWarning,
    stacklevel=2,
)
from ansede_static.js_engine.project import build_js_project_index, propagate_helper_return_traces
from ansede_static.js_engine.react import run_react_checks
from ansede_static.js_engine.routes import run_route_checks
from ansede_static.js_engine.taint_checks import run_taint_flow_checks

_log = logging.getLogger(__name__)

_STATIC_SINGLE_RE = re.compile(r"^\s*'([^'\\]|\\.)*'\s*$", re.S)
_STATIC_DOUBLE_RE = re.compile(r'^\s*"([^"\\]|\\.)*"\s*$', re.S)
_STATIC_TEMPLATE_RE = re.compile(r'^\s*`([^`\\]|\\.)*`\s*$', re.S)
_SANITIZE_HTML_RE = re.compile(r'DOMPurify\.sanitize|sanitizeHtml|escapeHtml', re.IGNORECASE)
_DYNAMIC_CONCAT_RE = re.compile(r'(?:\+\s*[A-Za-z_$`"\'])|(?:[A-Za-z_$)\]`"\']\s*\+)', re.IGNORECASE)
_SHELL_TRUE_RE = re.compile(r'\bshell\s*:\s*true\b', re.IGNORECASE)
_SIMPLE_IDENTIFIER_RE = re.compile(r'^\s*[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\s*$')

_DOCUMENT_WRITE_CALLEES = {"document.write", "document.writeln"}
_TIMER_CALLEES = {"setTimeout", "setInterval"}
_COMMAND_EXEC_CALLEES = {"exec", "execSync", "child_process.exec", "child_process.execSync"}
_SHELL_TRUE_CALLEES = {"spawn", "execFile", "child_process.spawn", "child_process.execFile"}
_SQL_CALLEES = {
    "query",
    "execute",
    "raw",
    "db.query",
    "db.execute",
    "sequelize.query",
    "knex.raw",
}
_SSRF_CALLEES = {
    "fetch",
    "axios.get",
    "axios.post",
    "request",
    "got",
    "needle",
    "http.get",
    "https.get",
}
_PATH_CALLEE_PARTS = {
    "readFile",
    "readFileSync",
    "writeFile",
    "writeFileSync",
    "open",
    "openSync",
    "unlink",
    "unlinkSync",
    "stat",
    "statSync",
    "access",
    "accessSync",
    "createReadStream",
    "createWriteStream",
    "resolve",
    "join",
}


def _callee_matches(call: JsCall, targets: set[str]) -> bool:
    if call.callee in targets:
        return True
    short = call.callee.split(".")[-1]
    return short in targets



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
                rule_id="JS-027",
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
        if not _callee_matches(call, _DOCUMENT_WRITE_CALLEES) or not call.arguments:
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
        if not _callee_matches(call, _TIMER_CALLEES) or not call.arguments:
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
) -> list[Finding]:
    findings: list[Finding] = []
    for call in calls:
        if not _callee_matches(call, _COMMAND_EXEC_CALLEES) or not call.arguments:
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
        if not _callee_matches(call, _SHELL_TRUE_CALLEES):
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
        if not _callee_matches(call, _SQL_CALLEES) or not call.arguments:
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



def _check_dynamic_require(calls: list[JsCall]) -> list[Finding]:
    findings: list[Finding] = []
    for call in calls:
        if call.callee.split(".")[-1] != "require" or not call.arguments:
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



def _check_path_traversal(
    calls: list[JsCall],
    taint_traces: dict[str, tuple[TraceFrame, ...]],
) -> list[Finding]:
    findings: list[Finding] = []
    for call in calls:
        short = call.callee.split(".")[-1]
        if short not in _PATH_CALLEE_PARTS or not call.arguments:
            continue
        expr = call.arguments[0]
        trace = _flow_trace(expr, taint_traces, line=call.line, allow_generic_dynamic=False)
        if not trace:
            continue
        trace = append_trace(trace, "sink", "sink `fs/path operation`", line=call.line)
        findings.append(_make_finding(
            line=call.line,
            title=f"CWE-22: Path traversal via tainted variable at line {call.line}",
            description=(
                f"A file-system or path operation at L{call.line} uses a user-influenced path: `{call.raw[:90]}`. "
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
) -> list[Finding]:
    findings: list[Finding] = []
    for call in calls:
        if call.callee != "res.redirect" or not call.arguments:
            continue
        expr = call.arguments[0]
        trace = _flow_trace(expr, taint_traces, line=call.line, allow_generic_dynamic=False)
        if not trace:
            continue
        trace = append_trace(trace, "sink", "sink `res.redirect()`", line=call.line)
        findings.append(_make_finding(
            line=call.line,
            title=f"CWE-601: Open redirect via tainted variable at line {call.line}",
            description=(
                f"`res.redirect()` at L{call.line} uses a user-influenced destination: `{call.raw[:90]}`. "
                f"Attackers can redirect victims to untrusted sites."
            ),
            suggestion="Validate redirect targets against an allowlist of permitted relative paths or trusted hosts.",
            severity=Severity.HIGH,
            rule_id="JS-039",
            cwe="CWE-601",
            trace=trace,
        ))
    return findings



def _check_ssrf(
    calls: list[JsCall],
    taint_traces: dict[str, tuple[TraceFrame, ...]],
) -> list[Finding]:
    findings: list[Finding] = []
    for call in calls:
        if not _callee_matches(call, _SSRF_CALLEES) or not call.arguments:
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



def analyze_js_ast(code: str, filename: str = "") -> AnalysisResult:
    result = AnalysisResult(
        file_path=filename,
        language="javascript",
        lines_scanned=len(code.splitlines()),
    )

    structural_findings: list[Finding] = []
    try:
        project = build_js_project_index(filename, code) if filename else None
        calls = collect_calls(code)
        property_writes = collect_property_writes(code)
        taint_traces = extract_taint_traces(code)
        if project and filename:
            taint_traces = propagate_helper_return_traces(project, filename, code, taint_traces)

        for checker in (
            lambda: _check_property_xss(property_writes, taint_traces),
            lambda: _check_document_write(calls, taint_traces),
            lambda: _check_eval(calls, taint_traces),
            lambda: _check_function_constructor(calls),
            lambda: _check_timer_string_eval(calls, taint_traces),
            lambda: _check_command_exec(calls, taint_traces),
            lambda: _check_shell_true(calls),
            lambda: _check_sql_injection(calls, taint_traces),
            lambda: _check_dynamic_require(calls),
            lambda: _check_path_traversal(calls, taint_traces),
            lambda: _check_open_redirect(calls, taint_traces),
            lambda: _check_ssrf(calls, taint_traces),
            lambda: run_taint_flow_checks(
                code,
                agent="js-ast-analyzer",
                analysis_kind="syntax-ast",
                filename=filename,
                project=project,
            ),
            lambda: run_react_checks(
                code,
                calls,
                taint_traces,
                agent="js-ast-analyzer",
                analysis_kind="syntax-ast",
            ),
            lambda: run_route_checks(
                code,
                agent="js-ast-analyzer",
                analysis_kind="syntax-ast",
                filename=filename,
                project=project,
            ),
        ):
            structural_findings.extend(checker())
    except (ValueError, TypeError, RecursionError, re.error) as exc:  # noqa: BLE001
        _log.debug("ansede-static: syntax-aware JS analysis failed on %r: %s", filename, exc, exc_info=True)

    fallback = analyze_js(code, filename)
    merged = dedup_findings(structural_findings + fallback.findings)
    result.findings = filter_inline_suppressions(merged, code)
    return result



def analyze_file(path: str | Path) -> AnalysisResult:
    source_path = Path(path)
    code = source_path.read_text(encoding="utf-8", errors="replace")
    return analyze_js_ast(code, filename=str(source_path))
