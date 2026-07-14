from __future__ import annotations

import re

from ansede_static._types import Finding, Severity, TraceFrame
from ansede_static.ir.global_graph import GlobalGraph
from ansede_static.js_engine.common import COMMENT_LINE_RE
from ansede_static.js_engine.constants import (
    PATH_CALLEE_PARTS,
    SSRF_CALLEES,
    callee_matches,
)
from ansede_static.js_engine.project_context import ProjectContext, is_fs_callee
from ansede_static.js_engine.project import (
    _trace_helper_return_expression,
    build_js_project_index,
    propagate_helper_return_traces,
    request_object_trace,
    resolve_js_function,
    summarize_js_function,
)
from ansede_static.js_engine.structure import collect_calls
from ansede_static.js_engine.taint import append_trace, extract_taint_traces, merge_traces, trace_for_expr, trace_has_sanitizer


_DEFAULT_IFDS_CALL_STRING_K = GlobalGraph.DEFAULT_CALL_STRING_K


def _trace_sink_argument(
    argument: str,
    taint_traces: dict[str, tuple[TraceFrame, ...]],
    *,
    line: int,
    filename: str,
    project,
    global_graph: object | None,
) -> tuple[TraceFrame, ...]:
    trace = trace_for_expr(argument, taint_traces, line=line)
    if not trace:
        trace = request_object_trace(argument, line=line)
    helper_trace: tuple[TraceFrame, ...] = ()
    if project and filename:
        helper_trace = _trace_helper_return_expression(
            project,
            filename,
            argument,
            taint_traces,
            line=line,
            global_graph=global_graph,
        )
    return merge_traces(trace, helper_trace)



def _make_taint_call_finding(
    lineno: int,
    line: str,
    rule_id: str,
    cwe: str,
    title_prefix: str,
    description: str,
    suggestion: str,
    severity: Severity,
    *,
    agent: str,
    analysis_kind: str,
    trace: tuple[TraceFrame, ...] = (),
) -> Finding:
    return Finding(
        category="security",
        severity=severity,
        title=f"{title_prefix} at line {lineno}",
        description=description.format(line=lineno, snippet=line.strip()[:90]),
        line=lineno,
        suggestion=suggestion,
        rule_id=rule_id,
        cwe=cwe,
        agent=agent,
        confidence=0.93,
        analysis_kind=analysis_kind,
        trace=trace,
    )



def _check_taint_path_traversal(
    code: str,
    taint_traces: dict[str, tuple[TraceFrame, ...]],
    *,
    filename: str,
    project,
    global_graph: object | None,
    agent: str,
    analysis_kind: str,
) -> list[Finding]:
    if not taint_traces and not (project and filename):
        return []
    findings: list[Finding] = []
    for call in collect_calls(code):
        short = call.callee.split(".")[-1]
        # ── Ambiguous callee guard ──────────────────────────────
        # `open` / `openSync` match XMLHttpRequest.open(), modals.open(),
        # window.open(), etc. — none of which are filesystem operations.
        if short in {"open", "openSync", "resolve", "join"}:
            if not is_fs_callee(call.callee, code=code):
                continue
        if not callee_matches(call.callee, PATH_CALLEE_PARTS):
            continue
        trace: tuple[TraceFrame, ...] = ()
        for argument in call.arguments:
            trace = _trace_sink_argument(
                argument,
                taint_traces,
                line=call.line,
                filename=filename,
                project=project,
                global_graph=global_graph,
            )
            if trace:
                break
        if not trace:
            continue
        if trace_has_sanitizer(trace, "path"):
            continue
        trace = append_trace(trace, "sink", "sink `fs/path operation`", line=call.line)
        findings.append(_make_taint_call_finding(
            call.line,
            call.raw,
            "JS-038",
            "CWE-22",
            "CWE-22: Path traversal via tainted variable",
            "File-system operation uses `{snippet}` (L{line}) with a variable that came from user-controlled input. An attacker can use `../` sequences.",
            "Sanitize with `path.basename()` and verify the resolved path stays inside the allowed base directory.",
            Severity.HIGH,
            agent=agent,
            analysis_kind=analysis_kind,
            trace=trace,
        ))
    return findings



def _check_taint_redirect(
    code: str,
    taint_traces: dict[str, tuple[TraceFrame, ...]],
    *,
    filename: str,
    project,
    global_graph: object | None,
    agent: str,
    analysis_kind: str,
) -> list[Finding]:
    if not taint_traces and not (project and filename):
        return []
    findings: list[Finding] = []
    for call in collect_calls(code):
        if call.callee not in {"res.redirect", "reply.redirect"}:
            continue
        if not call.arguments:
            continue
        trace = _trace_sink_argument(
            call.arguments[0],
            taint_traces,
            line=call.line,
            filename=filename,
            project=project,
            global_graph=global_graph,
        )
        if not trace:
            continue
        if trace_has_sanitizer(trace, "redirect"):
            continue
        sink_label = "sink `reply.redirect()`" if call.callee == "reply.redirect" else "sink `res.redirect()`"
        trace = append_trace(trace, "sink", sink_label, line=call.line)
        findings.append(_make_taint_call_finding(
            call.line,
            call.raw,
            "JS-039",
            "CWE-601",
            "CWE-601: Open redirect via tainted variable",
            "Redirect logic at L{line} uses a variable sourced from user-controlled input: `{snippet}`. An attacker can redirect victims to a phishing site.",
            "Validate redirect targets against an allowlist of permitted relative paths or trusted hosts.",
            Severity.HIGH,
            agent=agent,
            analysis_kind=analysis_kind,
            trace=trace,
        ))
    return findings



def _check_taint_ssrf(
    code: str,
    taint_traces: dict[str, tuple[TraceFrame, ...]],
    *,
    filename: str,
    project,
    global_graph: object | None,
    agent: str,
    analysis_kind: str,
) -> list[Finding]:
    if not taint_traces and not (project and filename):
        return []
    findings: list[Finding] = []
    for call in collect_calls(code):
        if not callee_matches(call.callee, SSRF_CALLEES):
            continue
        if not call.arguments:
            continue
        trace = _trace_sink_argument(
            call.arguments[0],
            taint_traces,
            line=call.line,
            filename=filename,
            project=project,
            global_graph=global_graph,
        )
        if not trace:
            continue
        if trace_has_sanitizer(trace, "ssrf"):
            continue
        trace = append_trace(trace, "sink", "sink `HTTP client call`", line=call.line)
        findings.append(_make_taint_call_finding(
            call.line,
            call.raw,
            "JS-040",
            "CWE-918",
            "CWE-918: SSRF via tainted variable",
            "HTTP client call at L{line} uses a URL from user-controlled input: `{snippet}`. An attacker can target internal services or cloud metadata endpoints.",
            "Validate URL hostname against an explicit allowlist and block private IP ranges.",
            Severity.HIGH,
            agent=agent,
            analysis_kind=analysis_kind,
            trace=trace,
        ))
    return findings



def _helper_taint_findings(
    code: str,
    taint_traces: dict[str, tuple[TraceFrame, ...]],
    *,
    filename: str,
    project,
    global_graph: object | None,
    agent: str,
    analysis_kind: str,
) -> list[Finding]:
    if not project:
        return []

    findings: list[Finding] = []
    for call in collect_calls(code):
        resolved = resolve_js_function(project, filename, call.callee)
        if not resolved:
            continue
        resolved_file, function_def = resolved
        summary = summarize_js_function(
            project,
            resolved_file,
            function_def.lookup_key or function_def.name,
            global_graph=global_graph,
        )
        if global_graph is not None and hasattr(global_graph, "propagate_js_call_facts"):
            tainted_arg_indexes: set[int] = set()
            for idx, argument in enumerate(call.arguments):
                if trace_for_expr(argument, taint_traces, line=call.line) or request_object_trace(argument, line=call.line):
                    tainted_arg_indexes.add(idx)
            try:
                sink_hit, _, _, _ = global_graph.propagate_js_call_facts(
                    caller_file=filename or "<memory>",
                    callee_file=resolved_file,
                    callee_name=function_def.lookup_key or function_def.name,
                    tainted_arg_indexes=tainted_arg_indexes,
                    call_line=call.line,
                    call_string=(),
                    call_string_k=_DEFAULT_IFDS_CALL_STRING_K,
                )
                if not sink_hit:
                    continue
            except Exception:
                pass
        for effect in summary.effects:
            if effect.kind not in {"path", "redirect", "ssrf"}:
                continue
            if effect.param_index >= len(call.arguments):
                continue
            argument = call.arguments[effect.param_index]
            trace = trace_for_expr(argument, taint_traces, line=call.line)
            if not trace:
                trace = request_object_trace(argument, line=call.line)
            if not trace:
                continue
            if trace_has_sanitizer(trace, effect.kind):
                continue

            trace = append_trace(trace, "helper", f"through `{call.callee}()`", line=call.line)
            for helper_label in effect.helper_chain:
                trace = append_trace(trace, "helper", helper_label, line=call.line)
            trace = append_trace(trace, "sink", effect.sink_label, line=call.line)

            if effect.kind == "path":
                findings.append(_make_taint_call_finding(
                    call.line,
                    call.raw,
                    "JS-038",
                    "CWE-22",
                    "CWE-22: Path traversal via tainted variable",
                    "File-system helper call at L{line} forwards user-controlled input into a path operation: `{snippet}`. An attacker can use `../` sequences.",
                    "Sanitize with `path.basename()` and verify the resolved path stays inside the allowed base directory.",
                    Severity.HIGH,
                    agent=agent,
                    analysis_kind=analysis_kind,
                    trace=trace,
                ))
            elif effect.kind == "redirect":
                findings.append(_make_taint_call_finding(
                    call.line,
                    call.raw,
                    "JS-039",
                    "CWE-601",
                    "CWE-601: Open redirect via tainted variable",
                    "Redirect helper call at L{line} forwards user-controlled input into redirect logic: `{snippet}`. An attacker can redirect victims to a phishing site.",
                    "Validate redirect targets against an allowlist of permitted relative paths or trusted hosts.",
                    Severity.HIGH,
                    agent=agent,
                    analysis_kind=analysis_kind,
                    trace=trace,
                ))
            elif effect.kind == "ssrf":
                findings.append(_make_taint_call_finding(
                    call.line,
                    call.raw,
                    "JS-040",
                    "CWE-918",
                    "CWE-918: SSRF via tainted variable",
                    "HTTP helper call at L{line} forwards user-controlled input into an outbound request: `{snippet}`. An attacker can target internal services or metadata endpoints.",
                    "Validate URL hostname against an explicit allowlist and block private IP ranges.",
                    Severity.HIGH,
                    agent=agent,
                    analysis_kind=analysis_kind,
                    trace=trace,
                ))

    # ── Apply IDE lattice confidence adjustment where available ──────────
    if global_graph is not None and hasattr(global_graph, "adjust_confidence_from_ide"):
        for i, finding in enumerate(findings):
            try:
                adjusted = global_graph.adjust_confidence_from_ide(
                    file_path=filename or "<memory>",
                    function_name="<js-scope>",
                    value_label="$ret",
                    base_confidence=finding.confidence,
                    call_string=(),
                    call_string_k=_DEFAULT_IFDS_CALL_STRING_K,
                )
                if adjusted != finding.confidence:
                    findings[i] = Finding(
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

    return findings


def _check_timer_indirection_redirect(
    code: str,
    taint_traces: dict[str, tuple[TraceFrame, ...]],
    *,
    agent: str,
    analysis_kind: str,
) -> list[Finding]:
    """Detect tainted redirects nested inside timer callbacks like setTimeout(() => res.redirect(next))."""
    if not taint_traces:
        return []
    findings: list[Finding] = []
    lines = code.splitlines()
    timer_re = re.compile(r'\b(?:setTimeout|setInterval)\s*\(', re.IGNORECASE)
    for lineno, line in enumerate(lines, 1):
        if COMMENT_LINE_RE.match(line.strip()) or not timer_re.search(line):
            continue
        window_parts = [line]
        balance = line.count("(") - line.count(")")
        next_idx = lineno
        while balance > 0 and next_idx < len(lines):
            next_idx += 1
            window_parts.append(lines[next_idx - 1])
            balance += lines[next_idx - 1].count("(") - lines[next_idx - 1].count(")")
            if len(window_parts) >= 12:
                break
        window = "\n".join(window_parts)
        if "redirect" not in window:
            continue
        matched_var = None
        matched_trace: tuple[TraceFrame, ...] = ()
        for name, trace in taint_traces.items():
            if re.search(rf'\b(?:res|reply)\.redirect\s*\([^\n)]*\b{re.escape(name)}\b', window):
                matched_var = name
                matched_trace = trace
                break
        if not matched_var:
            continue
        if trace_has_sanitizer(matched_trace, "redirect"):
            continue
        trace = append_trace(matched_trace, "helper", "through timer callback", line=lineno)
        trace = append_trace(trace, "sink", "sink `res.redirect()`", line=lineno)
        findings.append(_make_taint_call_finding(
            lineno,
            window_parts[0],
            "JS-039",
            "CWE-601",
            "CWE-601: Open redirect via timer-indirected tainted variable",
            "Timer callback at L{line} forwards user-controlled input into redirect logic: `{snippet}`. Indirection through setTimeout/setInterval still reaches a redirect sink.",
            "Validate redirect targets before scheduling the callback, or close over only a validated relative path.",
            Severity.HIGH,
            agent=agent,
            analysis_kind=analysis_kind,
            trace=trace,
        ))
    return findings



def run_taint_flow_checks(
    code: str,
    *,
    agent: str = "js-analyzer",
    analysis_kind: str = "taint-flow",
    filename: str = "",
    project=None,
    global_graph: object | None = None,
    project_context: ProjectContext | None = None,
) -> list[Finding]:
    # Gap 4: Skip taint flow checks entirely in browser-side code
    if project_context and project_context.skip_node_rules:
        return []

    active_project = project or (build_js_project_index(filename, code, fast=True) if filename else None)
    taint_traces = extract_taint_traces(code)
    if active_project and filename:
        taint_traces = propagate_helper_return_traces(
            active_project,
            filename,
            code,
            taint_traces,
            global_graph=global_graph,
        )
    findings: list[Finding] = []
    for checker in (
        _check_taint_path_traversal,
        _check_taint_redirect,
        _check_taint_ssrf,
        _check_timer_indirection_redirect,
    ):
        if checker is _check_timer_indirection_redirect:
            findings.extend(checker(code, taint_traces, agent=agent, analysis_kind=analysis_kind))
            continue
        findings.extend(checker(
            code,
            taint_traces,
            filename=filename,
            project=active_project,
            global_graph=global_graph,
            agent=agent,
            analysis_kind=analysis_kind,
        ))
    findings.extend(
        _helper_taint_findings(
            code,
            taint_traces,
            filename=filename,
            project=active_project,
            global_graph=global_graph,
            agent=agent,
            analysis_kind=analysis_kind,
        )
    )
    return findings
