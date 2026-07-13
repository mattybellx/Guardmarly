"""Java call-graph construction via tree-sitter AST.

Extracts methods, call sites, and builds caller→callee edges for
interprocedural taint propagation via GlobalGraph FunctionSummary.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from tree_sitter import Language, Parser, Node
import tree_sitter_java as tsjava

_log = logging.getLogger(__name__)

JAVA_LANGUAGE = Language(tsjava.language())
_JAVA_PARSER = Parser(JAVA_LANGUAGE)


# ── Data classes ────────────────────────────────────────────────────────────


@dataclass
class JavaCallSite:
    """A method invocation with argument info for taint propagation."""
    callee_name: str       # e.g., "processQuery"
    receiver: str          # e.g., "this", "service", ""
    arguments: list[str]   # argument text
    line: int
    raw: str


@dataclass
class JavaMethodSummary:
    """Per-method summary for callgraph + taint analysis."""
    name: str
    class_name: str
    file_path: str
    params: list[str]
    return_type: str
    start_line: int
    end_line: int
    calls: list[JavaCallSite] = field(default_factory=list)
    is_public: bool = False
    annotations: list[str] = field(default_factory=list)
    # Taint summary fields (populated during analysis)
    has_direct_source: bool = False   # body calls request.getParameter etc.
    sinks: list[str] = field(default_factory=list)  # cwe categories hit


# ── AST helpers ─────────────────────────────────────────────────────────────


def _node_text(node: Node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _find_all(node: Node, type_name: str) -> list[Node]:
    result: list[Node] = []
    if node.type == type_name:
        result.append(node)
    for child in node.children:
        result.extend(_find_all(child, type_name))
    return result


def _find_child(node: Node, type_name: str) -> Node | None:
    for child in node.children:
        if child.type == type_name:
            return child
    return None


def _find_descendant(node: Node, type_name: str) -> Node | None:
    if node.type == type_name:
        return node
    for child in node.children:
        result = _find_descendant(child, type_name)
        if result is not None:
            return result
    return None


# ── Method extraction ───────────────────────────────────────────────────────


def _extract_method_name(node: Node, source: bytes) -> str:
    """Get method name from method_declaration or constructor_declaration."""
    for child in node.children:
        if child.type == "identifier":
            return _node_text(child, source)
    return "<unknown>"


def _extract_params(node: Node, source: bytes) -> list[str]:
    """Extract parameter names and their types from formal_parameters."""
    params: list[str] = []
    fp = _find_child(node, "formal_parameters")
    if fp is None:
        return params
    for child in fp.children:
        if child.type == "formal_parameter":
            # Collect identifier children (last one is the param name)
            ids = [c for c in child.children if c.type == "identifier"]
            if ids:
                params.append(_node_text(ids[-1], source))
    return params


def _extract_param_types_and_names(node: Node, source: bytes) -> list[tuple[str, str]]:
    """Extract (type, name) pairs from formal_parameters for annotation taint."""
    result: list[tuple[str, str]] = []
    fp = _find_child(node, "formal_parameters")
    if fp is None:
        return result
    for child in fp.children:
        if child.type == "formal_parameter":
            param_text = _node_text(child, source)
            ids = [c for c in child.children if c.type == "identifier"]
            param_name = _node_text(ids[-1], source) if ids else ""
            # Extract type: everything before the last identifier
            if ids:
                type_part = param_text[:param_text.rfind(param_name)].strip()
                result.append((type_part, param_name))
            else:
                result.append(("", param_name))
    return result


def _extract_annotations(node: Node, source: bytes) -> list[str]:
    """Extract annotation names from modifiers."""
    annotations: list[str] = []
    mods = _find_child(node, "modifiers")
    if mods is not None:
        for child in mods.children:
            if child.type in ("marker_annotation", "annotation"):
                annotations.append(_node_text(child, source))
    return annotations


def _extract_calls(node: Node, source: bytes) -> list[JavaCallSite]:
    """Extract all method invocations from a subtree."""
    calls: list[JavaCallSite] = []
    for mi_node in _find_all(node, "method_invocation"):
        callee = ""
        receiver = ""
        identifiers: list[str] = []
        for child in mi_node.children:
            if child.type == "identifier":
                identifiers.append(_node_text(child, source))

        if identifiers:
            callee = identifiers[-1]
            if len(identifiers) >= 2:
                receiver = identifiers[-2]

        arguments: list[str] = []
        args_node = _find_child(mi_node, "argument_list")
        if args_node is not None:
            for child in args_node.children:
                if child.type not in ("(", ")", ","):
                    arguments.append(_node_text(child, source).strip())

        calls.append(JavaCallSite(
            callee_name=callee,
            receiver=receiver,
            arguments=arguments,
            line=mi_node.start_point[0] + 1,
            raw=_node_text(mi_node, source),
        ))
    return calls


def _extract_return_type(node: Node, source: bytes) -> str:
    """Extract the return type from a method_declaration."""
    # For constructors there's no return type
    if node.type == "constructor_declaration":
        return ""
    for child in node.children:
        if child.type in ("type_identifier", "void_type", "primitive_type",
                          "generic_type", "array_type", "scoped_type_identifier"):
            return _node_text(child, source)
    return ""


# ── Sink / source detection ─────────────────────────────────────────────────


# Method names that indicate a sink (used for args_to_sink summary)
_SINK_METHODS: frozenset[str] = frozenset({
    # SQLi
    "createQuery", "executeQuery", "executeUpdate", "createNativeQuery",
    "prepareCall", "prepareStatement", "createStatement",
    # CMDi
    "exec",
    # XSS
    "write", "print", "println",
    # Redirect
    "sendRedirect",
    # Path traversal
    "get",  # Paths.get
})

# Methods that indicate a source (taint enters)
_SOURCE_METHODS: frozenset[str] = frozenset({
    "getParameter", "getQueryString", "getHeader", "getCookies",
    "getCookie", "getInputStream", "getReader", "getRequestBody",
    "getPathParameter", "getFormParam", "getQueryParam", "getMatrixParam",
})

# Sink classes for context
_SINK_CLASSES: frozenset[str] = frozenset({
    "JdbcTemplate", "Runtime", "ProcessBuilder",
    "FileInputStream", "FileOutputStream", "FileReader", "FileWriter",
    "RandomAccessFile", "File", "URL", "HttpURLConnection",
})


def _detect_sinks(calls: list[JavaCallSite]) -> list[str]:
    """Detect CWE categories from call sites."""
    cwes: set[str] = set()
    for call in calls:
        if call.callee_name in {"createQuery", "executeQuery", "executeUpdate",
                                 "createNativeQuery", "prepareCall",
                                 "prepareStatement", "createStatement"}:
            cwes.add("CWE-89")
        if call.callee_name == "exec" and call.receiver in ("Runtime", "runtime", "rt"):
            cwes.add("CWE-78")
        if call.callee_name in ("write", "print", "println"):
            cwes.add("CWE-79")
        if call.callee_name == "sendRedirect":
            cwes.add("CWE-601")
        if call.callee_name == "get" and call.receiver == "Paths":
            cwes.add("CWE-22")
        if call.receiver in ("request", "req") and call.callee_name in _SOURCE_METHODS:
            cwes.add("SOURCE")
    return sorted(cwes)


def _detect_direct_sources(calls: list[JavaCallSite]) -> bool:
    """Return True if method body directly calls request.getXxx()."""
    for call in calls:
        if call.receiver in ("request", "req") and call.callee_name in _SOURCE_METHODS:
            return True
    return False


# ── Class name extraction ───────────────────────────────────────────────────


def _extract_class_name(source: bytes, method_node: Node) -> str:
    """Walk up to find the enclosing class name."""
    current = method_node.parent
    while current is not None:
        if current.type == "class_declaration":
            for child in current.children:
                if child.type == "identifier":
                    return _node_text(child, source)
            break
        current = current.parent
    return "<top-level>"


# ── Main extraction ─────────────────────────────────────────────────────────


def extract_java_callgraph(code: str, file_path: str = "") -> list[JavaMethodSummary]:
    """Parse Java source and extract method summaries with call graphs.

    Args:
        code: Java source code
        file_path: Path to the source file (for recording in summaries)

    Returns:
        List of JavaMethodSummary, one per method/constructor.
    """
    source_bytes = code.encode("utf-8")
    try:
        tree = _JAVA_PARSER.parse(source_bytes)
    except Exception as exc:
        _log.debug("Java callgraph parse failed for %r: %s", file_path, exc)
        return []

    summaries: list[JavaMethodSummary] = []
    root = tree.root_node

    # Find all class bodies
    for class_node in _find_all(root, "class_declaration"):
        class_name = ""
        for child in class_node.children:
            if child.type == "identifier":
                class_name = _node_text(child, source_bytes)
                break

        class_body = _find_child(class_node, "class_body")
        if class_body is None:
            continue

        # Process methods and constructors
        for child in class_body.children:
            if child.type not in ("method_declaration", "constructor_declaration"):
                continue

            name = _extract_method_name(child, source_bytes)
            params = _extract_params(child, source_bytes)
            annotations = _extract_annotations(child, source_bytes)
            return_type = _extract_return_type(child, source_bytes)
            calls = _extract_calls(child, source_bytes)

            is_public = any(
                c.type == "modifiers" and "public" in _node_text(c, source_bytes)
                for c in child.children
            )

            body_node = _find_child(child, "block")
            start_line = child.start_point[0] + 1
            end_line = (body_node.end_point[0] + 1) if body_node else start_line

            # Compute IFDS summary fields
            has_source = _detect_direct_sources(calls)
            sinks = _detect_sinks(calls)
            _ = _extract_param_types_and_names(child, source_bytes)  # reserved for annotation taint

            summaries.append(JavaMethodSummary(
                name=name,
                class_name=class_name,
                file_path=file_path,
                params=params,
                return_type=return_type,
                start_line=start_line,
                end_line=end_line,
                calls=calls,
                is_public=is_public,
                annotations=annotations,
                has_direct_source=has_source,
                sinks=sinks,
            ))

    return summaries


# ── Call graph edge building ────────────────────────────────────────────────


@dataclass
class JavaCallEdge:
    """A directed edge: caller → callee."""
    caller_file: str
    caller_class: str
    caller_method: str
    callee_name: str       # simple name (used for resolution)
    callee_file: str = ""  # resolved later if in same file or via imports
    call_line: int = 0


def build_call_edges(summaries: list[JavaMethodSummary]) -> list[JavaCallEdge]:
    """Build caller→callee edges from method summaries.

    Resolution: callee is assumed to be in the same file (or a known dependency).
    External/library calls are not resolved.
    """
    edges: list[JavaCallEdge] = []
    for summary in summaries:
        for call in summary.calls:
            # Skip external library calls (dot-prefixed receivers, common libs)
            if call.receiver and "." in call.receiver:
                continue
            if call.receiver in ("System", "Arrays", "Collections", "Objects",
                                  "String", "Integer", "Long", "Boolean",
                                  "Math", "Thread", "Class"):
                continue
            edges.append(JavaCallEdge(
                caller_file=summary.file_path,
                caller_class=summary.class_name,
                caller_method=summary.name,
                callee_name=call.callee_name,
                callee_file="",  # resolve later
                call_line=call.line,
            ))
    return edges


def resolve_edges_within_file(edges: list[JavaCallEdge],
                               summaries: list[JavaMethodSummary]) -> list[JavaCallEdge]:
    """Resolve callee_file for edges where the callee is in the same file."""
    method_names = {s.name for s in summaries}
    for edge in edges:
        if edge.callee_name in method_names:
            edge.callee_file = edge.caller_file
    return edges


# ── GlobalGraph integration ─────────────────────────────────────────────────


def record_to_global_graph(
    global_graph: object,
    summaries: list[JavaMethodSummary],
    file_path: str = "",
) -> None:
    """Publish Java method summaries into the shared GlobalGraph IFDS store.

    For each method that has direct taint sources or calls other methods,
    records a FunctionSummary so callees can propagate taint through the call chain.
    """
    from ansede_static.ir.global_graph import FunctionSummary, IDETaintLevel

    for summary in summaries:
        # Determine which argument positions reach sinks
        args_to_sink: list[int] = []
        args_to_return: list[int] = []

        if summary.sinks or summary.has_direct_source:
            # If the method body directly reaches a sink, any tainted arg
            # index contributes. We track this by checking which params
            # appear in sink call arguments.
            for call in summary.calls:
                for arg_text in call.arguments:
                    for idx, param in enumerate(summary.params):
                        if param and param in arg_text:
                            args_to_sink.append(idx)
                            args_to_return.append(idx)

        # Deduplicate
        args_to_sink = sorted(set(args_to_sink))
        args_to_return = sorted(set(args_to_return))

        full_name = f"{summary.class_name}.{summary.name}" if summary.class_name else summary.name

        global_graph.record_function_summary(FunctionSummary(
            file_path=file_path or summary.file_path,
            function_name=full_name,
            args_to_sink=tuple(args_to_sink),
            args_to_return=tuple(args_to_return),
            return_from_source=summary.has_direct_source,
            side_effect_symbols=(),
            depends_on=tuple(
                call.callee_name for call in summary.calls
            ),
        ))

        # Record IDE lattice fact for methods that are direct sources
        if summary.has_direct_source and hasattr(global_graph, "set_taint_with_access_path"):
            try:
                global_graph.set_taint_with_access_path(
                    file_path=file_path or summary.file_path,
                    function_name=full_name,
                    value_label="$ret",
                    level=IDETaintLevel.TAINTED,
                    sources=("request.getParameter",),
                )
            except Exception:
                pass

    global_graph.save_summaries()
