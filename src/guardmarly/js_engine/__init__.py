from guardmarly.js_engine.common import (
    COMMENT_LINE_RE,
    SUPPRESSION_RE,
    dedup_findings,
    filter_inline_suppressions,
    strip_comments,
)
from guardmarly.js_engine.structure import (
    JsCall,
    JsPropertyWrite,
    collect_calls,
    collect_property_writes,
    parse_object_literal,
)
from guardmarly.js_engine.taint import (
    DIRECT_TAINT_SOURCE_RE,
    append_trace,
    expr_references_taint,
    extract_taint_traces,
    first_referenced_taint_name,
    merge_traces,
    trace_for_expr,
    trace_has_sanitizer,
)
from guardmarly.js_engine.source_map_resolver import (
    load_sourcemap_path,
    parse_sourcemap_segments,
    remap_findings_to_source_map,
)

__all__ = [
    "COMMENT_LINE_RE",
    "SUPPRESSION_RE",
    "DIRECT_TAINT_SOURCE_RE",
    "JsCall",
    "JsPropertyWrite",
    "append_trace",
    "collect_calls",
    "collect_property_writes",
    "dedup_findings",
    "expr_references_taint",
    "extract_taint_traces",
    "filter_inline_suppressions",
    "first_referenced_taint_name",
    "merge_traces",
    "parse_object_literal",
    "parse_sourcemap_segments",
    "load_sourcemap_path",
    "remap_findings_to_source_map",
    "strip_comments",
    "trace_for_expr",
    "trace_has_sanitizer",
]
