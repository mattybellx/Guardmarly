from __future__ import annotations

import re
from collections.abc import Iterable

from guardmarly._types import TraceFrame
from guardmarly.js_engine.common import COMMENT_LINE_RE, strip_comments
from guardmarly.js_engine.structure import collect_calls

_ASSIGNMENT_RE = re.compile(
    r'(?:(?:const|let|var)\s+)?([A-Za-z_$]\w*)\s*=\s*(.+?);?\s*$',
)

# ── Destructuring-aware taint patterns (v6.3+) ───────────────────────────
# Object destructuring: const { name, email: e } = req.query
_DESTRUCTURE_OBJECT_RE = re.compile(
    r'(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*=\s*(.+?);?\s*$',
)
# Array destructuring: const [first, second] = taintedArray  
_DESTRUCTURE_ARRAY_RE = re.compile(
    r'(?:const|let|var)\s*\[\s*([^\]]+)\s*\]\s*=\s*(.+?);?\s*$',
)
# Object.assign(target, source) — target becomes tainted
_OBJECT_ASSIGN_RE = re.compile(
    r'Object\.assign\s*\(\s*([A-Za-z_$]\w*(?:\.[A-Za-z_$]\w*)*)\s*,',
    re.IGNORECASE,
)
# Spread in object literal: const obj = {...taintedSource, extra: 1}
_SPREAD_OBJECT_RE = re.compile(
    r'(?:const|let|var)\s+([A-Za-z_$]\w*)\s*=\s*\{[^}]*\.\.\.([A-Za-z_$]\w*)',
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
    r'|event\.queryStringParameters(?:\.[A-Za-z_$][\w$]*)?'
    r'|event\.body'
    r'|getQuery\([^)]*\)(?:\.[A-Za-z_$][\w$]*)?'
    r'|url\.searchParams\.get\s*\([^)]*\)'
    # Additional taint sources for broader coverage (v6.3+)
    r'|process\.env(?:\.[A-Za-z_$][\w$]*)?'
    r'|req\.(?:file|files)(?:\.[A-Za-z_$][\w$]*)?'
    r'|req\.(?:route|originalUrl|baseUrl)(?:\.[A-Za-z_$][\w$]*)?'
    r'|c\.(?:req|request)\.(?:params|query|body|headers)(?:\.[A-Za-z_$][\w$]*)?'
    r'|req\.param\s*\([^)]*\)'
    r'|req\.get\s*\([^)]*\)'
    r'|\.split\s*\(\s*["\'\`][^"\'\`]*["\'\`]\s*\)\['
    r')\b',
    re.IGNORECASE,
)
_SANITIZER_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    'path': (
        re.compile(r'^(?:path\.)?basename$', re.IGNORECASE),
        re.compile(r'(?:safe|secure|clean)\w*path', re.IGNORECASE),
        re.compile(r'(?:safe|secure)Join$', re.IGNORECASE),
        re.compile(r'^TextDecoder\.decode$', re.IGNORECASE),
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


_DESTRUCTURE_PROP_RE = re.compile(r'([A-Za-z_$]\w*)\s*(?::\s*([A-Za-z_$]\w*))?')


def _parse_destructure_props(props_str: str) -> list[str]:
    """Parse destructured property names from '{ a, b: c, d }' → ['a', 'c', 'd'].
    
    For each property:
    - `a` (shorthand) → captured name is 'a'
    - `b: c` (renamed) → captured name is 'c' (the target variable)
    """
    names: list[str] = []
    # Split on commas, but be careful with nested destructuring — keep it simple
    for part in props_str.split(","):
        part = part.strip()
        if not part:
            continue
        # Skip rest elements like ...rest
        if part.startswith("..."):
            rest_name = part[3:].strip()
            if rest_name and rest_name[0].isalpha():
                names.append(rest_name)
            continue
        # Skip nested destructuring like { a: { b, c } } — too complex for regex
        if "{" in part or "[" in part:
            continue
        match = _DESTRUCTURE_PROP_RE.match(part)
        if match:
            shorthand = match.group(1)
            renamed = match.group(2)
            # If renamed (b: c), use 'c'; otherwise use 'a'
            names.append(renamed if renamed else shorthand)
    return names



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


# ── Variable-level taint propagation (v6.4+) ─────────────────────────────
# Tracks taint through local variable assignments: const x = req.query.y → x is tainted

# Matches: const/let/var x = req.query.y or const x = req.params.id
_VAR_TAINT_ASSIGN_RE = re.compile(
    r'(?:const|let|var)\s+([A-Za-z_$]\w*)\s*=\s*(.+)',
    re.IGNORECASE,
)


def _propagate_taint_variables(
    code: str,
    taint_names: set[str],
    *,
    source_re: re.Pattern[str],
) -> set[str]:
    """Propagate taint through simple variable assignments.
    
    Example: const cmd = req.query.cmd → adds 'cmd' to taint_names
    """
    new_tainted: set[str] = set()
    lines = code.splitlines()
    
    for line in lines:
        stripped = strip_comments(line).strip()
        if not stripped:
            continue
        
        m = _VAR_TAINT_ASSIGN_RE.match(stripped)
        if not m:
            continue
        
        var_name = m.group(1)
        expr = m.group(2).rstrip(';').strip()
        
        # Check if RHS references a known taint source
        if source_re.search(expr):
            new_tainted.add(var_name)
            continue
        
        # Check if RHS references an already tainted variable
        for tainted in taint_names | new_tainted:
            if re.search(rf'\b{re.escape(tainted)}\b', expr):
                new_tainted.add(var_name)
                break
    
    return new_tainted


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
                # ── Destructuring-aware taint (v6.3+) ──────────────────────
                _handled_destructure = False
                
                # Object destructuring: const { a, b: c } = source
                dest_match = _DESTRUCTURE_OBJECT_RE.match(stripped)
                if dest_match:
                    props_str, expr = dest_match.groups()
                    # Parse property names from "{ a, b: c, d }" → ["a", "c", "d"]
                    prop_names = _parse_destructure_props(props_str)
                    direct = _direct_source_trace_with_regex(expr, line=lineno, direct_source_re=active_direct_source_re)
                    taint_base = direct
                    if not taint_base:
                        referenced = [
                            trace for name, trace in taint_traces.items()
                            if re.search(rf'\b{re.escape(name)}\b', expr)
                        ]
                        taint_base = merge_traces(*referenced) if referenced else ()
                    if taint_base:
                        trace = merge_traces(taint_base, sanitizer_frames_for_expr(expr, line=lineno))
                        for prop in prop_names:
                            if prop and prop not in taint_traces:
                                taint_traces[prop] = append_trace(
                                    trace, "propagator", f"destructure `{prop}` from `{expr[:60]}`", line=lineno
                                )
                                changed = True
                    _handled_destructure = True
                
                # Array destructuring: const [x, y] = source
                arr_match = _DESTRUCTURE_ARRAY_RE.match(stripped)
                if arr_match:
                    elems_str, expr = arr_match.groups()
                    elem_names = [e.strip() for e in elems_str.split(",") if e.strip() and not e.strip().startswith("...")]
                    direct = _direct_source_trace_with_regex(expr, line=lineno, direct_source_re=active_direct_source_re)
                    taint_base = direct
                    if not taint_base:
                        referenced = [
                            trace for name, trace in taint_traces.items()
                            if re.search(rf'\b{re.escape(name)}\b', expr)
                        ]
                        taint_base = merge_traces(*referenced) if referenced else ()
                    if taint_base:
                        trace = merge_traces(taint_base, sanitizer_frames_for_expr(expr, line=lineno))
                        for elem in elem_names:
                            if elem and elem not in taint_traces:
                                taint_traces[elem] = append_trace(
                                    trace, "propagator", f"destructure `{elem}` from `{expr[:60]}`", line=lineno
                                )
                                changed = True
                    _handled_destructure = True
                
                # Spread in object: const obj = {...tainted}
                spread_match = _SPREAD_OBJECT_RE.match(stripped)
                if spread_match:
                    target, spread_src = spread_match.groups()
                    if spread_src in taint_traces and target not in taint_traces:
                        trace = append_trace(
                            taint_traces[spread_src], "propagator",
                            f"spread `{spread_src}` into `{target}`", line=lineno
                        )
                        taint_traces[target] = trace
                        changed = True
                    _handled_destructure = True
                
                # Object.assign(target, source) — if source is tainted, target becomes tainted
                oa_match = _OBJECT_ASSIGN_RE.search(stripped)
                if oa_match:
                    target_name = oa_match.group(1)
                    # Check if any of the source args reference tainted variables
                    for taint_name, trace in list(taint_traces.items()):
                        if re.search(rf'\b{re.escape(taint_name)}\b', stripped.replace(target_name, "", 1)):
                            if target_name not in taint_traces:
                                taint_traces[target_name] = append_trace(
                                    trace, "propagator",
                                    f"Object.assign via `{taint_name}` → `{target_name}`", line=lineno
                                )
                                changed = True
                            break
                    _handled_destructure = True
                
                if _handled_destructure:
                    continue
                # ── End destructuring-aware taint ──────────────────────────
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

    # ── Variable-level taint propagation (v6.4+) ──
    # Propagate taint through assignments: const x = req.query.y → x is tainted
    _tainted_names = set(taint_traces.keys())
    _propagated = _propagate_taint_variables(code, _tainted_names,
                                              source_re=active_direct_source_re)
    for var_name in _propagated:
        if var_name not in taint_traces:
            taint_traces[var_name] = (
                TraceFrame(kind="source", label=f"tainted via assignment to `{var_name}`", line=0),
            )

    return taint_traces
