from __future__ import annotations

import re
from collections.abc import Iterable

from ansede_static._types import TraceFrame
from ansede_static.js_engine.common import COMMENT_LINE_RE, strip_comments
from ansede_static.js_engine.structure import collect_calls

_ASSIGNMENT_RE = re.compile(
    r'(?:(?:const|let|var)\s+)?([A-Za-z_$]\w*)\s*=\s*(.+?);?\s*$',
)
DIRECT_TAINT_SOURCE_RE = re.compile(
    r'\b(?:'
    r'req\.(?:params|query|body|headers|cookies|ip|hostname|protocol|originalUrl|url|path|method)(?:\.[A-Za-z_$][\w$]*)?'
    r'|request\.(?:params|query|body|headers|cookies|ip|hostname|protocol|originalUrl|url)(?:\.[A-Za-z_$][\w$]*)?'
    r'|params\.[A-Za-z_$][\w$]*'
    r'|ctx\.(?:params|query|body)(?:\.[A-Za-z_$][\w$]*)?'
    r'|ctx\.request\.(?:body|headers)(?:\.[A-Za-z_$][\w$]*)?'
    r'|context\.(?:params|query|body)(?:\.[A-Za-z_$][\w$]*)?'
    r'|window\.location(?:\.[A-Za-z_$][\w$]*)?'
    r'|document\.location(?:\.[A-Za-z_$][\w$]*)?'
    r'|location\.(?:href|search|hash)'
    r'|document\.cookie'
    r'|request\.headers\.get\s*\([^)]*\)'
    r')\b',
    re.IGNORECASE,
)
_SANITIZER_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    'path': (
        re.compile(r'^(?:path\.)?basename$', re.IGNORECASE),
        re.compile(r'(?:safe|secure|clean)\w*path', re.IGNORECASE),
        re.compile(r'(?:safe|secure)Join$', re.IGNORECASE),
    ),
    'redirect': (
        re.compile(r'(?:safe|allow(?:list|listed)|trusted|validate)\w*redirect', re.IGNORECASE),
        re.compile(r'(?:redirect|next|return)\w*(?:allow(?:list|listed)|safe|trusted|validate)', re.IGNORECASE),
    ),
    'ssrf': (
        re.compile(r'(?:safe|allow(?:list|listed)|trusted|validate)\w*(?:url|uri|host|hostname|endpoint|target)', re.IGNORECASE),
        re.compile(r'(?:assert|ensure)(?:Trusted|Safe)(?:Host|Url|Endpoint)', re.IGNORECASE),
    ),
    'html': (
        re.compile(r'^DOMPurify\.sanitize$', re.IGNORECASE),
        re.compile(r'sanitize(?:Html|Markup|Content)?$', re.IGNORECASE),
        re.compile(r'escapeHtml$', re.IGNORECASE),
        re.compile(r'^he\.encode$', re.IGNORECASE),
        re.compile(r'^xssFilters?\.', re.IGNORECASE),
    ),
}


def append_trace(
    trace: tuple[TraceFrame, ...],
    kind: str,
    label: str,
    *,
    line: int | None = None,
) -> tuple[TraceFrame, ...]:
    frame = TraceFrame(kind=kind, label=label, line=line)
    if trace and trace[-1] == frame:
        return trace
    return trace + (frame,)



def merge_traces(*traces: tuple[TraceFrame, ...]) -> tuple[TraceFrame, ...]:
    merged: tuple[TraceFrame, ...] = ()
    for trace in traces:
        for frame in trace:
            if merged and merged[-1] == frame:
                continue
            merged += (frame,)
    return merged



def expr_references_taint(expr: str, taint_names: Iterable[str]) -> bool:
    return any(re.search(rf'\b{re.escape(name)}\b', expr) for name in taint_names)



def first_referenced_taint_name(
    expr: str,
    taint_traces: dict[str, tuple[TraceFrame, ...]],
) -> str | None:
    for name in taint_traces:
        if re.search(rf'\b{re.escape(name)}\b', expr):
            return name
    return None



def _direct_source_trace(expr: str, *, line: int) -> tuple[TraceFrame, ...]:
    return _direct_source_trace_with_regex(expr, line=line, direct_source_re=DIRECT_TAINT_SOURCE_RE)



def _direct_source_trace_with_regex(
    expr: str,
    *,
    line: int,
    direct_source_re: re.Pattern[str],
) -> tuple[TraceFrame, ...]:
    match = direct_source_re.search(expr)
    if not match:
        return ()
    return (TraceFrame(kind="source", label=f"source `{match.group(0)[:80]}`", line=line),)


def _callee_sanitizer_kinds(callee: str) -> tuple[str, ...]:
    candidate = callee.strip()
    short_name = candidate.split('.')[-1]
    kinds: list[str] = []
    for kind, patterns in _SANITIZER_PATTERNS.items():
        if any(pattern.search(candidate) or pattern.search(short_name) for pattern in patterns):
            kinds.append(kind)
    return tuple(dict.fromkeys(kinds))


def sanitizer_frames_for_expr(expr: str, *, line: int) -> tuple[TraceFrame, ...]:
    frames: tuple[TraceFrame, ...] = ()
    seen: set[str] = set()
    for call in collect_calls(expr):
        for kind in _callee_sanitizer_kinds(call.callee):
            label = f"sanitize {kind} via `{call.callee}()`"
            if label in seen:
                continue
            seen.add(label)
            frames = append_trace(frames, 'sanitizer', label, line=line)
    return frames


def trace_has_sanitizer(trace: tuple[TraceFrame, ...], kind: str) -> bool:
    prefix = f"sanitize {kind} "
    return any(frame.kind == 'sanitizer' and frame.label.startswith(prefix) for frame in trace)



def trace_for_expr(
    expr: str,
    taint_traces: dict[str, tuple[TraceFrame, ...]],
    *,
    line: int,
    direct_source_re: re.Pattern[str] | None = None,
) -> tuple[TraceFrame, ...]:
    direct = _direct_source_trace_with_regex(
        expr,
        line=line,
        direct_source_re=direct_source_re or DIRECT_TAINT_SOURCE_RE,
    )
    referenced = [
        trace
        for name, trace in taint_traces.items()
        if re.search(rf'\b{re.escape(name)}\b', expr)
    ]
    base = direct or merge_traces(*referenced)
    if not base:
        return ()
    return merge_traces(base, sanitizer_frames_for_expr(expr, line=line))



def extract_taint_traces(
    code: str,
    *,
    line_offset: int = 0,
    initial_traces: dict[str, tuple[TraceFrame, ...]] | None = None,
    direct_source_re: re.Pattern[str] | None = None,
) -> dict[str, tuple[TraceFrame, ...]]:
    taint_traces: dict[str, tuple[TraceFrame, ...]] = dict(initial_traces or {})
    lines = code.splitlines()
    active_direct_source_re = direct_source_re or DIRECT_TAINT_SOURCE_RE

    MAX_PASSES = 24  # Run to fixpoint, not a fixed small count
    for _ in range(MAX_PASSES):
        changed = False
        for lineno, line in enumerate(lines, 1 + line_offset):
            stripped = strip_comments(line).strip()
            if not stripped or COMMENT_LINE_RE.match(stripped):
                continue
            match = _ASSIGNMENT_RE.match(stripped)
            if not match:
                continue
            target, expr = match.groups()
            if target in taint_traces:
                continue

            direct = _direct_source_trace_with_regex(expr, line=lineno, direct_source_re=active_direct_source_re)
            if direct:
                trace = merge_traces(direct, sanitizer_frames_for_expr(expr, line=lineno))
                trace = append_trace(trace, "propagator", f"assign to `{target}`", line=lineno)
                taint_traces[target] = trace
                changed = True
                continue

            referenced = [
                trace
                for name, trace in taint_traces.items()
                if re.search(rf'\b{re.escape(name)}\b', expr)
            ]
            if not referenced:
                continue

            trace = merge_traces(merge_traces(*referenced), sanitizer_frames_for_expr(expr, line=lineno))
            if re.search(r'\b\w+\s*\(', expr):
                trace = append_trace(trace, "helper", f"through `{expr[:80]}`", line=lineno)
            else:
                trace = append_trace(trace, "propagator", f"via `{expr[:80]}`", line=lineno)
            trace = append_trace(trace, "propagator", f"assign to `{target}`", line=lineno)
            taint_traces[target] = trace
            changed = True
        if not changed:
            break

    return taint_traces
