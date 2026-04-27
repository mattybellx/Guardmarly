from __future__ import annotations

import re

from ansede_static._types import Finding, Severity, TraceFrame
from ansede_static.js_engine.structure import JsCall, parse_object_literal
from ansede_static.js_engine.taint import append_trace, merge_traces, trace_for_expr, trace_has_sanitizer

_SANITIZE_HTML_RE = re.compile(r'DOMPurify\.sanitize|sanitizeHtml|escapeHtml', re.IGNORECASE)
_JSX_DANGEROUS_HTML_RE = re.compile(
    r'dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([\s\S]*?)\}\s*\}',
    re.IGNORECASE,
)
_JSX_PROP_BAG_RE = re.compile(
    r'dangerouslySetInnerHTML\s*=\s*\{\s*([A-Za-z_$][\w$]*)\s*\}',
    re.IGNORECASE,
)
_DIRECT_PROPS_RE = re.compile(r'(?:this\.)?props\.([A-Za-z_$][\w$]*)', re.IGNORECASE)
_DESTRUCTURED_FUNC_RE = re.compile(r'function\s+\w+\s*\(\s*\{([^}]*)\}\s*\)', re.IGNORECASE)
_DESTRUCTURED_ARROW_RE = re.compile(
    r'(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?\(\s*\{([^}]*)\}\s*\)\s*=>',
    re.IGNORECASE,
)
_DESTRUCTURED_ASSIGN_RE = re.compile(
    r'(?:const|let|var)\s+\{([^}]*)\}\s*=\s*(?:this\.)?props\s*;',
    re.IGNORECASE,
)
_PROP_ASSIGN_RE = re.compile(
    r'(?:const|let|var)\s+([A-Za-z_$]\w*)\s*=\s*(?:this\.)?props\.([A-Za-z_$]\w*)',
    re.IGNORECASE,
)
_OBJECT_ASSIGN_RE = re.compile(r'(?:const|let|var)\s+([A-Za-z_$]\w*)\s*=\s*', re.IGNORECASE)



def _balanced_object_end(text: str, start_index: int) -> int | None:
    depth = 0
    state = 'default'
    i = start_index
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ''
        if state == 'line_comment':
            if ch == '\n':
                state = 'default'
            i += 1
            continue
        if state == 'block_comment':
            if ch == '*' and nxt == '/':
                i += 2
                state = 'default'
                continue
            i += 1
            continue
        if state in {'single', 'double', 'template'}:
            if ch == '\\' and i + 1 < len(text):
                i += 2
                continue
            if state == 'single' and ch == "'":
                state = 'default'
            elif state == 'double' and ch == '"':
                state = 'default'
            elif state == 'template' and ch == '`':
                state = 'default'
            i += 1
            continue
        if ch == '/' and nxt == '/':
            state = 'line_comment'
            i += 2
            continue
        if ch == '/' and nxt == '*':
            state = 'block_comment'
            i += 2
            continue
        if ch == "'":
            state = 'single'
            i += 1
            continue
        if ch == '"':
            state = 'double'
            i += 1
            continue
        if ch == '`':
            state = 'template'
            i += 1
            continue
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None



def _normalize_prop_entry(entry: str) -> tuple[str, str] | None:
    text = entry.strip()
    if not text or text.startswith('...'):
        return None
    text = text.split('=', 1)[0].strip()
    if ':' in text:
        original, alias = text.split(':', 1)
        return original.strip(), alias.strip()
    return text, text



def extract_react_prop_traces(code: str) -> dict[str, tuple[TraceFrame, ...]]:
    traces: dict[str, tuple[TraceFrame, ...]] = {}
    for pattern in (_DESTRUCTURED_FUNC_RE, _DESTRUCTURED_ARROW_RE, _DESTRUCTURED_ASSIGN_RE):
        for match in pattern.finditer(code):
            line = code.count('\n', 0, match.start()) + 1
            for entry in match.group(1).split(','):
                parsed = _normalize_prop_entry(entry)
                if not parsed:
                    continue
                original, alias = parsed
                if alias in traces:
                    continue
                traces[alias] = (
                    TraceFrame(kind='source', label=f"react prop `props.{original}`", line=line),
                    TraceFrame(kind='propagator', label=f"assign to `{alias}`", line=line),
                )
    for match in _PROP_ASSIGN_RE.finditer(code):
        alias, original = match.groups()
        line = code.count('\n', 0, match.start()) + 1
        if alias in traces:
            continue
        traces[alias] = (
            TraceFrame(kind='source', label=f"react prop `props.{original}`", line=line),
            TraceFrame(kind='propagator', label=f"assign to `{alias}`", line=line),
        )
    return traces



def _extract_object_literal_assignments(code: str) -> dict[str, tuple[dict[str, str], int]]:
    assignments: dict[str, tuple[dict[str, str], int]] = {}
    for match in _OBJECT_ASSIGN_RE.finditer(code):
        name = match.group(1)
        index = match.end()
        while index < len(code) and code[index].isspace():
            index += 1
        if index >= len(code) or code[index] != '{':
            continue
        end = _balanced_object_end(code, index)
        if end is None:
            continue
        object_text = code[index:end + 1]
        try:
            props = parse_object_literal(object_text)
        except Exception:  # noqa: BLE001
            continue
        assignments[name] = (props, code.count('\n', 0, match.start()) + 1)
    return assignments



def _expr_trace(
    expr: str,
    *,
    line: int,
    taint_traces: dict[str, tuple[TraceFrame, ...]],
    react_prop_traces: dict[str, tuple[TraceFrame, ...]],
) -> tuple[TraceFrame, ...]:
    trace = trace_for_expr(expr, taint_traces, line=line)
    if trace:
        return trace
    direct_prop = _DIRECT_PROPS_RE.search(expr)
    if direct_prop:
        return (TraceFrame(kind='source', label=f"react prop `{direct_prop.group(0)}`", line=line),)
    referenced = [
        prop_trace
        for name, prop_trace in react_prop_traces.items()
        if re.search(rf'\b{re.escape(name)}\b', expr)
    ]
    if referenced:
        return merge_traces(*referenced)
    snippet = ' '.join(expr.strip().split())[:80]
    return (TraceFrame(kind='source', label=f"dynamic react expression `{snippet}`", line=line),)



def _extract_html_expr(value: str, object_assignments: dict[str, tuple[dict[str, str], int]]) -> tuple[str | None, tuple[TraceFrame, ...]]:
    text = value.strip()
    if text.startswith('{') and text.endswith('}'):
        try:
            props = parse_object_literal(text)
        except Exception:  # noqa: BLE001
            return None, ()
        expr = props.get('__html')
        return expr, ()
    if re.fullmatch(r'[A-Za-z_$][\w$]*', text):
        assignment = object_assignments.get(text)
        if not assignment:
            return None, ()
        props, line = assignment
        expr = props.get('__html')
        if not expr:
            return None, ()
        return expr, (TraceFrame(kind='helper', label=f"through prop bag `{text}`", line=line),)
    return None, ()



def _react_finding(
    *,
    line: int,
    description: str,
    trace: tuple[TraceFrame, ...],
    agent: str,
    analysis_kind: str,
) -> Finding:
    return Finding(
        category='security',
        severity=Severity.HIGH,
        title=f'CWE-79: XSS via dangerouslySetInnerHTML at line {line}',
        description=description,
        line=line,
        suggestion=(
            'Sanitize with DOMPurify.sanitize() before setting dangerouslySetInnerHTML, or render plain text instead when HTML is not required.'
        ),
        rule_id='JS-003',
        cwe='CWE-79',
        agent=agent,
        confidence=0.95,
        analysis_kind=analysis_kind,
        trace=trace,
    )



def run_react_checks(
    code: str,
    calls: list[JsCall],
    taint_traces: dict[str, tuple[TraceFrame, ...]],
    *,
    agent: str = 'js-ast-analyzer',
    analysis_kind: str = 'syntax-ast',
) -> list[Finding]:
    findings: list[Finding] = []
    react_prop_traces = extract_react_prop_traces(code)
    object_assignments = _extract_object_literal_assignments(code)

    for match in _JSX_DANGEROUS_HTML_RE.finditer(code):
        expr = match.group(1).strip()
        if not expr or _SANITIZE_HTML_RE.search(expr):
            continue
        line = code.count('\n', 0, match.start()) + 1
        trace = _expr_trace(expr, line=line, taint_traces=taint_traces, react_prop_traces=react_prop_traces)
        if trace_has_sanitizer(trace, 'html'):
            continue
        trace = append_trace(trace, 'sink', 'sink `dangerouslySetInnerHTML`', line=line)
        findings.append(_react_finding(
            line=line,
            description=(
                f'React `dangerouslySetInnerHTML` receives dynamic HTML at L{line}: `dangerouslySetInnerHTML={{ __html: {expr[:60]} }}`. '
                f'Unsanitized content here bypasses React\'s normal XSS protections.'
            ),
            trace=trace,
            agent=agent,
            analysis_kind=analysis_kind,
        ))

    for match in _JSX_PROP_BAG_RE.finditer(code):
        prop_bag = match.group(1)
        assignment = object_assignments.get(prop_bag)
        if not assignment:
            continue
        props, helper_line = assignment
        expr = props.get('__html')
        if not expr or _SANITIZE_HTML_RE.search(expr):
            continue
        line = code.count('\n', 0, match.start()) + 1
        trace = _expr_trace(expr, line=line, taint_traces=taint_traces, react_prop_traces=react_prop_traces)
        if trace_has_sanitizer(trace, 'html'):
            continue
        trace = append_trace(trace, 'helper', f"through prop bag `{prop_bag}`", line=helper_line)
        trace = append_trace(trace, 'sink', 'sink `dangerouslySetInnerHTML`', line=line)
        findings.append(_react_finding(
            line=line,
            description=(
                f'React `dangerouslySetInnerHTML` uses prop bag `{prop_bag}` at L{line}. The embedded `__html` value is dynamic and bypasses React\'s XSS protections.'
            ),
            trace=trace,
            agent=agent,
            analysis_kind=analysis_kind,
        ))

    for call in calls:
        if call.callee not in {'React.createElement', 'createElement'} or len(call.arguments) < 2:
            continue
        props_arg = call.arguments[1].strip()
        helper_trace: tuple[TraceFrame, ...] = ()
        if props_arg.startswith('{') and props_arg.endswith('}'):
            props = parse_object_literal(props_arg)
        elif re.fullmatch(r'[A-Za-z_$][\w$]*', props_arg) and props_arg in object_assignments:
            props, helper_line = object_assignments[props_arg]
            helper_trace = (TraceFrame(kind='helper', label=f"through props object `{props_arg}`", line=helper_line),)
        else:
            continue
        value = props.get('dangerouslySetInnerHTML')
        if not value:
            continue
        expr, nested_helper = _extract_html_expr(value, object_assignments)
        if not expr or _SANITIZE_HTML_RE.search(expr):
            continue
        trace = _expr_trace(expr, line=call.line, taint_traces=taint_traces, react_prop_traces=react_prop_traces)
        if trace_has_sanitizer(trace, 'html'):
            continue
        trace = merge_traces(trace, helper_trace, nested_helper)
        trace = append_trace(trace, 'sink', 'sink `React.createElement dangerouslySetInnerHTML`', line=call.line)
        findings.append(_react_finding(
            line=call.line,
            description=(
                f'React `createElement` builds props with `dangerouslySetInnerHTML` at L{call.line}: `{call.raw[:90]}`. '
                f'Unsanitized HTML here bypasses React\'s XSS protections.'
            ),
            trace=trace,
            agent=agent,
            analysis_kind=analysis_kind,
        ))

    return findings
