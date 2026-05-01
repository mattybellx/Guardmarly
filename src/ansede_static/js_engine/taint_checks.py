from __future__ import annotations

import re

from ansede_static._types import Finding, Severity, TraceFrame
from ansede_static.js_engine.common import COMMENT_LINE_RE, consume_balanced
from ansede_static.js_engine.constants import (
    PATH_CALLEE_PARTS,
    SSRF_CALLEES,
    callee_matches,
)
from ansede_static.js_engine.project import (
    build_js_project_index,
    propagate_helper_return_traces,
    request_object_trace,
    resolve_js_function,
    summarize_js_function,
)
from ansede_static.js_engine.structure import collect_calls
from ansede_static.js_engine.taint import append_trace, extract_taint_traces, first_referenced_taint_name, trace_for_expr, trace_has_sanitizer



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
    agent: str,
    analysis_kind: str,
) -> list[Finding]:
    if not taint_traces:
        return []
    var_pattern = "|".join(re.escape(name) for name in taint_traces)
    pattern = re.compile(rf'(?:fs\.|path\.resolve|path\.join)\w*\s*\([^)]*(?:{var_pattern})', re.IGNORECASE)
    findings: list[Finding] = []
    for lineno, line in enumerate(code.splitlines(), 1):
        if COMMENT_LINE_RE.match(line.strip()):
            continue
        if not pattern.search(line):
            continue
        var_name = first_referenced_taint_name(line, taint_traces)
        trace = taint_traces.get(var_name or "", ())
        if trace_has_sanitizer(trace, "path"):
            continue
        trace = append_trace(trace, "sink", "sink `fs/path operation`", line=lineno)
        findings.append(_make_taint_call_finding(
            lineno,
            line,
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
    agent: str,
    analysis_kind: str,
) -> list[Finding]:
    if not taint_traces:
        return []
    var_pattern = "|".join(re.escape(name) for name in taint_traces)
    pattern = re.compile(rf'(?:res|reply)\.redirect\s*\([^)]*(?:{var_pattern})', re.IGNORECASE)
    findings: list[Finding] = []
    for lineno, line in enumerate(code.splitlines(), 1):
        if COMMENT_LINE_RE.match(line.strip()):
            continue
        if not pattern.search(line):
            continue
        var_name = first_referenced_taint_name(line, taint_traces)
        trace = taint_traces.get(var_name or "", ())
        if trace_has_sanitizer(trace, "redirect"):
            continue
        sink_label = "sink `reply.redirect()`" if "reply.redirect" in line else "sink `res.redirect()`"
        trace = append_trace(trace, "sink", sink_label, line=lineno)
        findings.append(_make_taint_call_finding(
            lineno,
            line,
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
    agent: str,
    analysis_kind: str,
) -> list[Finding]:
    if not taint_traces:
        return []
    var_pattern = "|".join(re.escape(name) for name in taint_traces)
    pattern = re.compile(
        rf'(?:fetch|axios\.(?:get|post|put|delete|request)|request|got(?:\.(?:get|post|stream))?|needle(?:\.(?:get|post|put|delete|request))?|superagent(?:\.(?:get|post))?|http\.get|https\.get)\s*\([^)]*(?:{var_pattern})',
        re.IGNORECASE,
    )
    findings: list[Finding] = []
    for lineno, line in enumerate(code.splitlines(), 1):
        if COMMENT_LINE_RE.match(line.strip()):
            continue
        if not pattern.search(line):
            continue
        var_name = first_referenced_taint_name(line, taint_traces)
        trace = taint_traces.get(var_name or "", ())
        if trace_has_sanitizer(trace, "ssrf"):
            continue
        trace = append_trace(trace, "sink", "sink `HTTP client call`", line=lineno)
        findings.append(_make_taint_call_finding(
            lineno,
            line,
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
        if global_graph is not None and hasattr(global_graph, "propagate_call_facts"):
            tainted_arg_indexes: set[int] = set()
            for idx, argument in enumerate(call.arguments):
                if trace_for_expr(argument, taint_traces, line=call.line) or request_object_trace(argument, line=call.line):
                    tainted_arg_indexes.add(idx)
            try:
                sink_hit, _, _, _ = global_graph.propagate_call_facts(
                    caller_file=filename or "<memory>",
                    caller_name="<js-scope>",
                    callee_file=resolved_file,
                    callee_name=function_def.lookup_key or function_def.name,
                    tainted_arg_indexes=tainted_arg_indexes,
                    call_line=call.line,
                    call_string=(),
                    call_string_k=2,
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
                    call_string_k=2,
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



def run_taint_flow_checks(
    code: str,
    *,
    agent: str = "js-analyzer",
    analysis_kind: str = "taint-flow",
    filename: str = "",
    project=None,
    global_graph: object | None = None,
) -> list[Finding]:
    active_project = project or (build_js_project_index(filename, code) if filename else None)
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
    ):
        findings.extend(checker(code, taint_traces, agent=agent, analysis_kind=analysis_kind))
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
