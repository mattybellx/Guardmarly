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
            _log.warning("ansede-static: JS %s failed on %r: %s — results may be incomplete", label, filename, exc)
            result.analysis_degraded = True
            if not result.degradation_reason:
                result.degradation_reason = f"JS {label} crashed on {filename}: {exc}"

    # ── Fallback: direct pattern detection for blind-spot CWEs ──────────
    # Catches XSS, CmdInj, PathTrav when AST flow analysis misses them.
    # Lower confidence but ensures coverage of known vulnerable patterns.
    all_findings.extend(_fallback_xss_detect(code, filename))
    all_findings.extend(_fallback_cmd_inj_detect(code, filename))
    all_findings.extend(_fallback_path_trav_detect(code, filename))
    all_findings.extend(_fallback_code_inj_detect(code, filename))
    all_findings.extend(_fallback_nosql_detect(code, filename))
    all_findings.extend(_fallback_idor_detect(code, filename))

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
        _log.exception("Template engine detection failed for %s", filename)

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
        _log.exception("Template taint analysis failed for %s", filename)

    try:
        all_findings = analyze_guards_js(code, all_findings, filename=filename)
    except Exception:
        _log.exception("Symbolic guard analysis failed for %s", filename)

    deduped = dedup_findings(all_findings)
    result.findings = filter_inline_suppressions(deduped, code)
    return result


# ── Fallback direct-pattern detectors for blind-spot CWEs ────────────────
# These catch patterns that the AST flow analysis may miss, at lower confidence.

# Variable assignment that propagates taint: const x = req.query.y
_VAR_PROPAGATION_RE = re.compile(
    r'(?:const|let|var)\s+([A-Za-z_$]\w*)\s*=\s*(?:req|request|ctx)\.(?:params|query|body|headers|cookies)\b',
    re.IGNORECASE,
)
_VAR_CHAIN_RE = re.compile(
    r'(?:const|let|var)\s+([A-Za-z_$]\w*)\s*=\s*([A-Za-z_$]\w*)\b',
    re.IGNORECASE,
)


def _get_propagated_taint(code: str) -> set[str]:
    """Find variables that receive tainted values through assignments."""
    tainted: set[str] = set()
    for m in _VAR_PROPAGATION_RE.finditer(code):
        tainted.add(m.group(1))
    # Chain propagation: const y = x where x is already tainted
    for _ in range(3):
        new = False
        for m in _VAR_CHAIN_RE.finditer(code):
            vname = m.group(1)
            src = m.group(2)
            if src in tainted and vname not in tainted:
                tainted.add(vname)
                new = True
        if not new:
            break
    return tainted

_XSS_SINK_PATTERN = re.compile(
    r'(?:innerHTML|outerHTML)\s*=|document\.write\s*\(|document\.writeln\s*\(|'
    r'\.insertAdjacentHTML\s*\(|\.html\s*\(|dangerouslySetInnerHTML|'
    r'res\.send\s*\(|res\.write\s*\(|res\.end\s*\(|res\.render\s*\(',
    re.IGNORECASE,
)
_HAS_TAINT_SOURCE_JS = re.compile(
    r'req\.(?:params|query|body|headers|cookies)|request\.(?:params|query|body)|'
    r'ctx\.(?:params|query|body)|\.getParameter\s*\(|\.getHeader\s*\(|'
    r'\.getQueryString\s*\(|window\.location|document\.location|location\.(?:href|search)',
    re.IGNORECASE,
)
_CMD_INJ_SINK_PATTERN = re.compile(
    r'(?:child_process|require\s*\(\s*[\"\']child_process[\"\']\s*\)|'
    r'require\s*\(\s*[\"\']child_process[\"\']\s*\)\.exec)\s*(?:\.\s*(?:exec|execSync|spawn|spawnSync|execFile))?\s*\(|'
    r'\bexec\s*\(\s*["\'].*["\']\s*\+|\bexec\s*\(\s*\w+\s*\+|\bexec\s*\(\s*\w+\s*\[|'
    r'\bspawn\s*\(\s*\w+\s*\[|\bexecSync\s*\(|'
    r'\bexec\s*\(\s*`[^`]*\$\{',
    re.IGNORECASE,
)
_CODE_INJ_PATTERN = re.compile(
    r'\beval\s*\(|new\s+Function\s*\(|Function\s*\(\s*"[^"]*"\s*,\s*"[^"]*"\s*\)\s*\(|'
    r'setTimeout\s*\(\s*[\"\']|setInterval\s*\(\s*[\"\']',
    re.IGNORECASE,
)
_NOSQL_INJ_PATTERN = re.compile(
    r'\.find\s*\(\s*\{[^}]*req\.(?:body|query|params)|'
    r'\$where\s*:|\.findOne\s*\(\s*\{[^}]*req\.',
    re.IGNORECASE,
)
_PATH_TRAV_SINK_PATTERN = re.compile(
    r'fs\.(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|'
    r'unlink|unlinkSync|rmdir|rmdirSync|mkdir|mkdirSync|open|openSync|'
    r'appendFile|appendFileSync|access|accessSync|stat|statSync|exists|existsSync|'
    r'readdir|readdirSync)\s*\(',
    re.IGNORECASE,
)
_PATH_JOIN_PATTERN = re.compile(
    r'path\.join\s*\([^)]*\+|path\.resolve\s*\([^)]*\+',
    re.IGNORECASE,
)

# CWE-639 IDOR: route param used in DB query without session ownership check
_IDOR_ROUTE_PARAM = re.compile(
    r'req\.params\.(\w+)|req\.query\.(\w+)|req\.body\.(\w+)|'
    r'\{[^}]*(\w+)[^}]*\}\s*=\s*req\.(?:params|query|body)',
    re.IGNORECASE,
)
_IDOR_DB_QUERY = re.compile(
    r'\.(?:find|findById|findOne|findOneAndUpdate|findByIdAndUpdate|'
    r'findByIdAndRemove|findOneAndDelete|remove|deleteOne|deleteMany|'
    r'updateOne|updateMany|get\w*\s*\(|fetch|query|search|'
    r'read|lookup|retrieve)\s*\(',
    re.IGNORECASE,
)
_IDOR_SESSION_CHECK = re.compile(
    r'req\.session\.\w+|req\.user\.\w+|session\.\w+|\.userId\s*===?\s*req\.|'
    r'\.id\s*===?\s*req\.|req\.session|ownsDocument|authorize|isOwner',
    re.IGNORECASE,
)


def _fallback_xss_detect(code: str, filename: str) -> list[Finding]:
    """Catch XSS patterns that AST flow analysis may miss."""
    findings: list[Finding] = []
    if not _HAS_TAINT_SOURCE_JS.search(code):
        return findings
    for m in _XSS_SINK_PATTERN.finditer(code):
        line = code[:m.start()].count('\n') + 1
        findings.append(Finding(
            category="security", severity=Severity.HIGH,
            title=f"CWE-79: XSS via {m.group()[:60]} at line {line}",
            description=f"Direct XSS sink detected at L{line}. Verify input is sanitized.",
            line=line,
            suggestion="HTML-encode user input before inserting into DOM. Use textContent instead of innerHTML.",
            rule_id="JS-001F", cwe="CWE-79", agent="js-fallback",
            confidence=0.85, analysis_kind="direct_sink",
        ))
    return findings[:5]  # Cap at 5 to avoid flooding


def _fallback_cmd_inj_detect(code: str, filename: str) -> list[Finding]:
    """Catch command injection patterns that AST flow analysis may miss."""
    findings: list[Finding] = []
    if not _HAS_TAINT_SOURCE_JS.search(code):
        return findings
    propagated = _get_propagated_taint(code)
    for m in _CMD_INJ_SINK_PATTERN.finditer(code):
        line = code[:m.start()].count('\n') + 1
        # Get arguments of the exec/spawn call
        # Find the ( that starts the call arguments
        matched = m.group()
        paren_idx = matched.find('(')
        if paren_idx == -1:
            continue
        sink_start = m.start() + paren_idx
        depth = 0
        arg_start = None
        arg_text = ""
        for i in range(sink_start, min(sink_start + 300, len(code))):
            c = code[i]
            if c == '(' and depth == 0:
                arg_start = i + 1
                depth = 1
            elif c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    arg_text = code[arg_start:i] if arg_start else ""
                    break
        arg_vars = set(re.findall(r'\b([A-Za-z_$]\w*)\b', arg_text)) if arg_text else set()
        has_tainted_arg = bool(arg_vars & propagated) if propagated else False

        # Also check the sink itself for inline taint or concatenation
        matched_has_concat = '+' in matched or '${' in matched
        if not has_tainted_arg and not matched_has_concat and '+' not in arg_text and '${' not in arg_text:
            continue
        findings.append(Finding(
            category="security", severity=Severity.CRITICAL,
            title=f"CWE-78: Command injection via {matched[:60]} at line {line}",
            description=f"Command execution sink with dynamic input at L{line}."
                + (f" Variable(s) {sorted(arg_vars & propagated)} traced to user input." if arg_vars & propagated else ""),
            line=line,
            suggestion="Use execFile with explicit argument arrays. Never pass user input to shell commands.",
            rule_id="JS-007F", cwe="CWE-78", agent="js-fallback",
            confidence=0.85 if has_tainted_arg else 0.82, analysis_kind="direct_sink",
        ))
    return findings[:5]  # Increased cap


def _fallback_path_trav_detect(code: str, filename: str) -> list[Finding]:
    """Catch path traversal patterns that AST flow analysis may miss."""
    findings: list[Finding] = []
    if not _HAS_TAINT_SOURCE_JS.search(code):
        return findings
    propagated = _get_propagated_taint(code)
    for m in _PATH_TRAV_SINK_PATTERN.finditer(code):
        line = code[:m.start()].count('\n') + 1
        matched = m.group()
        paren_idx = matched.find('(')
        if paren_idx == -1:
            continue
        sink_start = m.start() + paren_idx
        depth = 0
        arg_start = None
        arg_text = ""
        for i in range(sink_start, min(sink_start + 300, len(code))):
            c = code[i]
            if c == '(' and depth == 0:
                arg_start = i + 1
                depth = 1
            elif c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    arg_text = code[arg_start:i] if arg_start else ""
                    break
        arg_vars = set(re.findall(r'\b([A-Za-z_$]\w*)\b', arg_text)) if arg_text else set()
        has_tainted_arg = bool(arg_vars & propagated) if propagated else False

        if not has_tainted_arg:
            context = code[max(0, m.start()-100):m.end()+100]
            if '+' not in context and '${' not in context:
                continue
        findings.append(Finding(
            category="security", severity=Severity.HIGH,
            title=f"CWE-22: Path traversal via {matched[:60]} at line {line}",
            description=f"File operation with tainted path at L{line}."
                + (f" Variable(s) {sorted(arg_vars & propagated)} traced to user input." if arg_vars & propagated else ""),
            line=line,
            suggestion="Sanitize file paths with path.resolve and validate against a base directory.",
            rule_id="JS-013F", cwe="CWE-22", agent="js-fallback",
            confidence=0.85 if has_tainted_arg else 0.82, analysis_kind="direct_sink",
        ))
    return findings[:5]


def _fallback_code_inj_detect(code: str, filename: str) -> list[Finding]:
    """Catch eval/Function code injection patterns."""
    findings: list[Finding] = []
    if not _HAS_TAINT_SOURCE_JS.search(code):
        return findings
    for m in _CODE_INJ_PATTERN.finditer(code):
        line = code[:m.start()].count('\n') + 1
        context = code[max(0,m.start()-80):m.end()+80]
        if 'req.' not in context.lower() and 'param' not in context.lower():
            continue
        findings.append(Finding(
            category="security", severity=Severity.CRITICAL,
            title=f"CWE-94/CWE-95: Code injection via {m.group()[:60]} at line {line}",
            description=f"Dynamic code execution with potentially tainted input at L{line}.",
            line=line, suggestion="Never pass user input to eval(), Function(), setTimeout(), or setInterval().",
            rule_id="JS-004F", cwe="CWE-95", agent="js-fallback",
            confidence=0.85, analysis_kind="direct_sink",
        ))
    return findings[:3]


def _fallback_nosql_detect(code: str, filename: str) -> list[Finding]:
    """Catch NoSQL injection patterns in MongoDB queries."""
    findings: list[Finding] = []
    if not _HAS_TAINT_SOURCE_JS.search(code):
        return findings
    for m in _NOSQL_INJ_PATTERN.finditer(code):
        line = code[:m.start()].count('\n') + 1
        findings.append(Finding(
            category="security", severity=Severity.CRITICAL,
            title=f"CWE-943: NoSQL injection via {m.group()[:60]} at line {line}",
            description=f"MongoDB query with user-controlled input at L{line}.",
            line=line, suggestion="Sanitize and validate all user input before passing to MongoDB queries. Use $eq operator for exact matching.",
            rule_id="JS-051F", cwe="CWE-943", agent="js-fallback",
            confidence=0.85, analysis_kind="direct_sink",
        ))
    return findings[:5]


def _fallback_idor_detect(code: str, filename: str) -> list[Finding]:
    """Catch CWE-639 IDOR: route param → DAO query without session ownership check.
    
    Targeted heuristic: only fires when req.params/query is destructured AND
    a DAO/Service/Repository object method is called within the same function
    without a req.session ownership check. Narrow scope minimizes false positives.
    """
    findings: list[Finding] = []
    # Must have route params
    if not re.search(r'req\.(?:params|query)\b', code, re.IGNORECASE):
        return findings
    # Must have a DAO-like object method call
    dao_calls = list(re.finditer(
        r'(\w*(?:DAO|Service|Repository|DataAccess|Store))\s*\.\s*(\w+)\s*\(',
        code, re.IGNORECASE,
    ))
    if not dao_calls:
        return findings

    lines = code.splitlines()

    for m in dao_calls:
        dao_obj = m.group(1)
        dao_method = m.group(2)
        line = code[:m.start()].count('\n') + 1

        # Find enclosing function boundaries
        func_start = line
        for i in range(line - 1, max(0, line - 25), -1):
            if re.search(r'(?:function\s+\w+|=>\s*\{|:\s*function|^\s*\w+\s*=\s*\()', lines[i]):
                func_start = i
                break

        # Check for session/auth guard in the function context
        func_ctx = '\n'.join(lines[max(0, func_start - 1):min(len(lines), line + 5)])
        if re.search(
            r'req\.session\.\w+|session\.\w+\s*===?\s*req\.|'
            r'\.userId\s*===?\s*req\.session|req\.user\b|'
            r'isAuthenticated\s*\(|authorize\s*\(|isOwner\s*\(',
            func_ctx, re.IGNORECASE,
        ):
            continue

        findings.append(Finding(
            category="security", severity=Severity.HIGH,
            title=f"CWE-639: IDOR — {dao_obj}.{dao_method}() at line {line} uses route param without session check",
            description=(
                f"DAO method {dao_obj}.{dao_method}() at L{line} is called in a route handler "
                "with req.params/query but no visible req.session ownership verification."
            ),
            line=line,
            suggestion="Verify req.session.userId matches the requested resource before querying. Use session-based IDs, not route params.",
            rule_id="JS-052F", cwe="CWE-639", agent="js-fallback",
            confidence=0.70, analysis_kind="direct_sink",
        ))
    return findings[:2]  # Strict cap — IDOR is easy to false-positive


def analyze_file(path: str | Path) -> AnalysisResult:
    source_path = Path(path)
    code = source_path.read_text(encoding="utf-8", errors="replace")
    return analyze_js(code, filename=str(source_path))
