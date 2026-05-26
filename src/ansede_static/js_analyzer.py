"""
ansede_static.js_analyzer
──────────────────────────
JavaScript / TypeScript security analyzer.

The classic analyzer orchestrates regex rules, context heuristics, route/auth
checks, and taint-flow checks from the shared `js_engine` modules.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ansede_static._types import AnalysisResult, Finding, Severity, TraceFrame
from ansede_static.hardening import TemplateEngineDetector
from ansede_static.template_transpiler import template_taint_nodes
from ansede_static.js_engine.common import dedup_findings, filter_inline_suppressions
from ansede_static.js_engine.context_checks import run_context_checks
from ansede_static.js_engine.pattern_rules import run_pattern_rules
from ansede_static.js_engine.project import build_js_project_index, propagate_helper_return_traces
from ansede_static.js_engine.routes import run_route_checks
from ansede_static.js_engine.structure import collect_calls, collect_property_writes
from ansede_static.js_engine.taint import extract_taint_traces, trace_for_expr, trace_has_sanitizer
from ansede_static.js_engine.taint_checks import run_taint_flow_checks
from ansede_static.engine.symbolic_guards import analyze_guards_js

_log = logging.getLogger(__name__)


def _filter_sanitized_xss_findings(all_findings, code: str, *, filename: str, project, global_graph: object | None = None):
    xss_rule_ids = {"JS-001", "JS-002", "JS-059"}
    if not any(finding.rule_id in xss_rule_ids for finding in all_findings):
        return all_findings

    taint_traces = extract_taint_traces(code)
    if project and filename:
        taint_traces = propagate_helper_return_traces(project, filename, code, taint_traces, global_graph=global_graph)

    safe_lines: set[int] = set()
    for write in collect_property_writes(code):
        trace = trace_for_expr(write.expression, taint_traces, line=write.line)
        if trace and trace_has_sanitizer(trace, "html"):
            safe_lines.add(write.line)

    for call in collect_calls(code):
        if call.callee not in {"document.write", "document.writeln"} or not call.arguments:
            continue
        trace = trace_for_expr(call.arguments[0], taint_traces, line=call.line)
        if trace and trace_has_sanitizer(trace, "html"):
            safe_lines.add(call.line)

    if not safe_lines:
        return all_findings
    return [
        finding
        for finding in all_findings
        if not (finding.rule_id in xss_rule_ids and finding.line in safe_lines)
    ]



def analyze_js(
    code: str,
    filename: str = "",
    global_graph: object | None = None,
    *,
    project=None,
) -> AnalysisResult:
    result = AnalysisResult(
        file_path=filename,
        language="javascript",
        lines_scanned=len(code.splitlines()),
    )
    all_findings = []
    if project is None and filename:
        project = build_js_project_index(filename, code)

    for runner, label in (
        (lambda: run_pattern_rules(code, agent="js-analyzer"), "pattern rules"),
        (lambda: run_context_checks(code, agent="js-analyzer"), "context checks"),
        (
            lambda: run_route_checks(
                code,
                agent="js-analyzer",
                analysis_kind="route-heuristic",
                filename=filename,
                project=project,
            ),
            "route checks",
        ),
        (
            lambda: run_taint_flow_checks(
                code,
                agent="js-analyzer",
                analysis_kind="taint-flow",
                filename=filename,
                project=project,
                global_graph=global_graph,
            ),
            "taint checks",
        ),
    ):
        try:
            all_findings.extend(runner())
        except (ValueError, TypeError, RecursionError, re.error) as exc:  # noqa: BLE001
            _log.debug("ansede-static: JS %s failed on %r: %s", label, filename, exc, exc_info=True)

    all_findings = _filter_sanitized_xss_findings(
        all_findings,
        code,
        filename=filename,
        project=project,
        global_graph=global_graph,
    )

    try:
        for tpl in TemplateEngineDetector.detect_all_ssti(code, filename):
            all_findings.append(Finding(
                category="security",
                severity=Severity.CRITICAL if tpl.severity.upper() == "CRITICAL" else Severity.HIGH,
                title=f"{tpl.cwe}: Potential server-side template injection in {tpl.context}",
                description=(
                    f"Template sink `{tpl.sink_function}` receives potentially tainted template expression at "
                    f"line {tpl.line}. Dynamic template rendering can allow template-expression execution."
                ),
                line=tpl.line,
                suggestion="Avoid compiling or rendering user-controlled template source; keep templates static and pass user input only as escaped data context.",
                rule_id="JS-041",
                cwe=tpl.cwe,
                agent="js-analyzer",
                confidence=0.9,
                analysis_kind="template-ast",
                trace=(
                    TraceFrame(kind="source", label=f"template expression `{tpl.tainted_expr[:80]}`", line=tpl.line),
                    TraceFrame(kind="sink", label=f"sink `{tpl.sink_function}`", line=tpl.line),
                ),
            ))
    except Exception:
        pass

    try:
        for node in template_taint_nodes(code, filename=filename):
            all_findings.append(Finding(
                category="security",
                severity=Severity.HIGH,
                title=f"CWE-1336: Tainted template expression in {node.engine} template at line {node.line}",
                description=(
                    f"Template AST node `{node.expression[:90]}` in {node.engine} {node.kind} includes request/user-controlled markers. "
                    "Compiling or rendering this expression can enable template injection."
                ),
                line=node.line,
                suggestion="Keep template sources static and pass untrusted values as escaped data context only.",
                rule_id="JS-041",
                cwe="CWE-1336",
                agent="js-analyzer",
                confidence=0.9,
                analysis_kind="template-ast",
                trace=(
                    TraceFrame(kind="source", label=f"template expression `{node.expression[:80]}`", line=node.line, start_column=node.column),
                    TraceFrame(kind="sink", label=f"template AST {node.kind}", line=node.line, start_column=node.column),
                ),
            ))
    except Exception:
        pass

    try:
        all_findings = analyze_guards_js(code, all_findings, filename=filename)
    except Exception:
        pass

    deduped = dedup_findings(all_findings)
    result.findings = filter_inline_suppressions(deduped, code)
    return result



def analyze_file(path: str | Path) -> AnalysisResult:
    source_path = Path(path)
    code = source_path.read_text(encoding="utf-8", errors="replace")
    return analyze_js(code, filename=str(source_path))
