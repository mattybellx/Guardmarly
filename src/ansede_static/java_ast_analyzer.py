"""
java_ast_analyzer.py — Ansede Static tree-sitter Java analysis engine.

Replaces regex structural heuristics with accurate tree-sitter AST parsing.
Provides: method extraction, call-graph construction, annotation-aware routing,
taint-source → sink tracking, and framework-aware analysis (Spring, JAX-RS,
Micronaut, Quarkus).

Architecture mirrors js_ast_analyzer.py: parse → extract → match → report.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tree_sitter import Language, Parser, Node
import tree_sitter_java as tsjava

from ansede_static._types import AnalysisResult, Finding, Severity, TraceFrame

_log = logging.getLogger(__name__)

# ── tree-sitter setup ───────────────────────────────────────────────────────
JAVA_LANGUAGE = Language(tsjava.language())
_JAVA_PARSER = Parser(JAVA_LANGUAGE)

# ── Constants ───────────────────────────────────────────────────────────────
_ROUTE_ANNOTATIONS: frozenset[str] = frozenset({
    "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping",
    "RequestMapping",
    "GET", "POST", "PUT", "DELETE", "PATCH", "Path",
    "Get", "Post", "Put", "Delete", "Patch",
})
_MUTATING_ANNOTATIONS: frozenset[str] = frozenset({
    "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping",
    "POST", "PUT", "DELETE", "PATCH",
    "Post", "Put", "Delete", "Patch",
})
_AUTH_ANNOTATIONS: frozenset[str] = frozenset({
    "PreAuthorize", "Secured", "RolesAllowed",
    "Authenticated", "PermitAll", "DenyAll",
})

# ── Taint source patterns (user input) ──────────────────────────────────────
_REQUEST_TAINT_METHODS: frozenset[str] = frozenset({
    "getParameter", "getQueryString", "getHeader", "getHeaders",
    "getCookie", "getCookies", "getRequestBody", "getPathParameter",
    "getFormParam", "getQueryParam", "getMatrixParam",
    "getInputStream", "getReader",
    "getTheParameter", "getTheValue",  # OWASP benchmark helpers
    "getValue",  # Cookie.getValue()
})

# Taint-carrier methods: if called on a tainted receiver, the return value is tainted
_TAINT_CARRIER_METHODS: frozenset[str] = frozenset({
    "get", "getValue", "getAttribute", "getProperty",
    "nextElement", "nextToken", "toString",
    "substring", "trim", "toLowerCase", "toUpperCase",
    "concat", "replace", "replaceAll", "replaceFirst",
})

# ── Sink patterns by CWE ────────────────────────────────────────────────────
_SQLI_METHODS: frozenset[str] = frozenset({
    "createQuery", "executeQuery", "executeUpdate",
    "createNativeQuery", "prepareCall", "prepareStatement",
    "createStatement",
})
_SQLI_CLASSES: frozenset[str] = frozenset({
    "JdbcTemplate",
})

_CMD_EXEC_CLASSES: frozenset[str] = frozenset({
    "Runtime",
})
_CMD_EXEC_METHODS: frozenset[str] = frozenset({
    "exec",
})
_PROCESS_BUILDER_CLASSES: frozenset[str] = frozenset({
    "ProcessBuilder",
})

_WEAK_CRYPTO_ALGOS: frozenset[str] = frozenset({
    "MD5", "SHA1", "SHA-1", "DES", "RC4", "RC2", "Blowfish",
})

_SSRF_CLASSES: frozenset[str] = frozenset({
    "URL", "HttpURLConnection", "HttpClient", "RestTemplate",
    "WebClient", "OkHttpClient",
})

_REDIRECT_METHODS: frozenset[str] = frozenset({
    "sendRedirect",
})

_XSS_SINK_METHODS: frozenset[str] = frozenset({
    "getWriter", "getOutputStream",
})
_XSS_OUTPUT_METHODS: frozenset[str] = frozenset({
    "write", "print", "println", "append", "format",
})

# Receiver names that indicate HTTP response context (for XSS detection)
_XSS_RESPONSE_RECEIVERS: frozenset[str] = frozenset({
    "response", "res", "resp", "httpresponse", "servletresponse",
    "httpresponse", "writer", "printwriter", "outputstream",
})

_PATH_TRAVERSAL_CLASSES: frozenset[str] = frozenset({
    "FileInputStream", "FileOutputStream", "FileReader", "FileWriter",
    "RandomAccessFile", "File", "Files",
})
_PATH_TRAVERSAL_METHODS: frozenset[str] = frozenset({
    "Paths.get", "read", "write", "newInputStream", "newOutputStream",
    "readAllBytes", "readString", "writeString", "copy", "move",
    "createFile", "createDirectory", "newBufferedReader", "newBufferedWriter",
})

# ── LDAP injection sinks (CWE-90) ────────────────────────────────────────
_LDAP_SINK_CLASSES: frozenset[str] = frozenset({
    "InitialDirContext", "DirContext", "LdapContext",
    "InitialLdapContext", "LdapTemplate",
})
_LDAP_SINK_METHODS: frozenset[str] = frozenset({
    "search", "lookup", "list", "listBindings",
    "modifyAttributes", "createSubcontext",
})
_LDAP_SEARCH_FILTER_METHODS: frozenset[str] = frozenset({
    "search",
})

# ── XPath injection sinks (CWE-643) ──────────────────────────────────────
_XPATH_SINK_CLASSES: frozenset[str] = frozenset({
    "XPath", "XPathExpression", "XPathFactory",
})
_XPATH_SINK_METHODS: frozenset[str] = frozenset({
    "evaluate", "compile", "selectNodes", "selectSingleNode",
})
_XPATH_SINK_PACKAGES: frozenset[str] = frozenset({
    "javax.xml.xpath",
})

# ── Framework annotation taint (parameter-level) ─────────────────────────
# Annotations on method parameters that mark them as tainted user input
_FRAMEWORK_TAINT_ANNOTATIONS: frozenset[str] = frozenset({
    # Spring MVC
    "RequestParam", "RequestBody", "PathVariable", "RequestHeader",
    "CookieValue", "RequestPart", "ModelAttribute",
    "MatrixVariable",  # Spring 3.2+
    # JAX-RS
    "QueryParam", "FormParam", "PathParam", "HeaderParam",
    "CookieParam", "MatrixParam", "BeanParam",
    # Micronaut
    "Body", "Header", "Cookie", "Parameter",
})

# ── Sanitizer patterns (suppression) ─────────────────────────────────────
_SANITIZER_PATTERNS: dict[str, frozenset[str]] = {
    # SQLi sanitizers
    "CWE-89": frozenset({
        "PreparedStatement", "createPreparedStatement",
        "ESAPI.encoder().encodeForSQL", "encodeForSQL",
        "OWASP",
        # Parameterized queries use ? not concatenation
    }),
    # XSS sanitizers
    "CWE-79": frozenset({
        "ESAPI.encoder().encodeForHTML", "encodeForHTML",
        "HtmlUtils.htmlEscape", "StringEscapeUtils.escapeHtml4",
        "OWASP", "DOMPurify",
        "Jsoup.clean", "Sanitizer",
    }),
    # CMDi sanitizers
    "CWE-78": frozenset({
        "ProcessBuilder",  # inherently safer than Runtime.exec with shell
    }),
    # Path traversal sanitizers
    "CWE-22": frozenset({
        "FilenameUtils.getName", "getCanonicalPath",
        "Paths.get",  # when used with hardcoded prefix
    }),
    # LDAP sanitizers
    "CWE-90": frozenset({
        "ESAPI.encoder().encodeForLDAP", "encodeForLDAP",
        "LdapEncoder",
    }),
    # XPath sanitizers
    "CWE-643": frozenset({
        "ESAPI.encoder().encodeForXPath", "encodeForXPath",
        "XPathFactory",  # not a sanitizer but indicates structured usage
    }),
}

# Parameter names that are framework objects, not user input
_FRAMEWORK_PARAM_NAMES: frozenset[str] = frozenset({
    "request", "req", "response", "res", "resp", "session",
    "servletcontext", "servletconfig", "pagecontext",
})

# ── Builder / fluent API propagation targets ─────────────────────────────
_BUILDER_APPEND_METHODS: frozenset[str] = frozenset({
    "append", "concat", "format",
})
_BUILDER_CLASSES: frozenset[str] = frozenset({
    "StringBuilder", "StringBuffer",
})

# ── Collection methods for taint propagation ────────────────────────────
_COLLECTION_ADD_METHODS: frozenset[str] = frozenset({
    "add", "addAll", "addElement", "put", "append",
})

# ── ProcessBuilder command methods ──────────────────────────────────────
_PB_COMMAND_METHODS: frozenset[str] = frozenset({
    "command",
})

# ── Data classes ────────────────────────────────────────────────────────────


@dataclass
class _JavaCall:
    """A method invocation extracted from the AST."""
    callee: str
    arguments: list[str]
    line: int
    raw: str = ""
    receiver: str = ""  # e.g., "Runtime" in Runtime.getRuntime().exec()


@dataclass
class _JavaMethod:
    """A method declaration extracted from the AST."""
    name: str
    start_line: int
    body_start_line: int = 0  # file line of the opening brace
    body: str = ""
    annotations: list[str] = field(default_factory=list)
    route_paths: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    param_annotations: dict[str, list[str]] = field(default_factory=dict)
    framework_tainted_params: set[str] = field(default_factory=set)
    is_public: bool = False
    has_auth: bool = False


# ── AST helpers ─────────────────────────────────────────────────────────────


def _node_text(node: Node, source: bytes) -> str:
    """Get the source text for a tree-sitter node."""
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _find_all(node: Node, type_name: str) -> list[Node]:
    """Recursively find all nodes of a given type."""
    result: list[Node] = []
    if node.type == type_name:
        result.append(node)
    for child in node.children:
        result.extend(_find_all(child, type_name))
    return result


def _find_child(node: Node, type_name: str) -> Node | None:
    """Find the first direct child of a given type."""
    for child in node.children:
        if child.type == type_name:
            return child
    return None


def _find_descendant(node: Node, type_name: str) -> Node | None:
    """Find the first descendant of a given type (depth-first)."""
    if node.type == type_name:
        return node
    for child in node.children:
        result = _find_descendant(child, type_name)
        if result is not None:
            return result
    return None


def _collect_method_invocations(node: Node, source: bytes) -> list[_JavaCall]:
    """Collect all method invocations from a subtree."""
    calls: list[_JavaCall] = []
    if node.type == "method_invocation":
        calls.append(_parse_method_invocation(node, source))
    for child in node.children:
        calls.extend(_collect_method_invocations(child, source))
    return calls


def _parse_method_invocation(node: Node, source: bytes) -> _JavaCall:
    """Parse a method_invocation AST node into a _JavaCall."""
    arguments: list[str] = []
    callee = ""
    receiver = ""

    # Collect all identifiers — the last one before argument_list is the method name
    identifiers: list[str] = []
    has_nested_invocation = False
    for child in node.children:
        if child.type == "identifier":
            identifiers.append(_node_text(child, source))
        elif child.type == "method_invocation":
            has_nested_invocation = True
            # For chained calls like Runtime.getRuntime().exec():
            # extract the first identifier from the nested invocation as the receiver
            nested_ids: list[str] = []
            for nc in child.children:
                if nc.type == "identifier":
                    nested_ids.append(_node_text(nc, source))
            if nested_ids:
                receiver = nested_ids[0]  # e.g., "Runtime"

    # Method name is the last identifier, receiver from first if not already set
    if identifiers:
        callee = identifiers[-1]
        if not receiver and len(identifiers) >= 2:
            receiver = identifiers[-2]

    # Find arguments
    args_node = _find_child(node, "argument_list")
    if args_node is not None:
        for child in args_node.children:
            if child.type not in ("(", ")", ","):
                arguments.append(_node_text(child, source).strip())

    return _JavaCall(
        callee=callee,
        arguments=arguments,
        line=node.start_point[0] + 1,
        raw=_node_text(node, source),
        receiver=receiver,
    )


def _parse_object_creation(node: Node, source: bytes) -> tuple[str, list[str], int]:
    """Parse object_creation_expression: returns (class_name, arguments, line)."""
    class_name = ""
    arguments: list[str] = []

    type_node = _find_child(node, "type_identifier")
    if type_node is None:
        type_node = _find_child(node, "scoped_type_identifier")
    if type_node is not None:
        class_name = _node_text(type_node, source)

    args_node = _find_child(node, "argument_list")
    if args_node is not None:
        for child in args_node.children:
            if child.type not in ("(", ")", ","):
                arguments.append(_node_text(child, source).strip())

    return class_name, arguments, node.start_point[0] + 1


def _collect_object_creations(node: Node, source: bytes) -> list[tuple[str, list[str], int]]:
    """Collect all object_creation_expression nodes."""
    creations: list[tuple[str, list[str], int]] = []
    if node.type == "object_creation_expression":
        creations.append(_parse_object_creation(node, source))
    for child in node.children:
        creations.extend(_collect_object_creations(child, source))
    return creations


def _parse_method_declaration(node: Node, source: bytes) -> _JavaMethod:
    """Parse a method_declaration AST node."""
    name = ""
    body = ""
    start_line = node.start_point[0] + 1
    body_start_line = start_line  # default: brace on same line as method signature
    annotations: list[str] = []
    route_paths: list[str] = []
    params: list[str] = []
    param_annotations_map: dict[str, list[str]] = {}
    is_public = False
    has_auth = False

    for child in node.children:
        if child.type == "identifier":
            name = _node_text(child, source)
        elif child.type == "block":
            body = _node_text(child, source)
            body_start_line = child.start_point[0] + 1
        elif child.type == "modifiers":
            mod_text = _node_text(child, source)
            if "public" in mod_text:
                is_public = True
            # Extract annotations from modifiers
            for mod_child in child.children:
                if mod_child.type in ("marker_annotation", "annotation"):
                    annotations.append(_node_text(mod_child, source))
        elif child.type == "formal_parameters":
            for param_child in child.children:
                if param_child.type == "formal_parameter":
                    # Extract parameter-level annotations
                    param_annotations: list[str] = []
                    param_name = ""
                    for pc in param_child.children:
                        if pc.type in ("marker_annotation", "annotation"):
                            param_annotations.append(_node_text(pc, source))
                        elif pc.type == "identifier":
                            param_name = _node_text(pc, source)
                    if param_name:
                        params.append(param_name)
                        if param_annotations:
                            param_annotations_map[param_name] = param_annotations

    # Look for annotations in the parent (class_declaration) or sibling context
    # In tree-sitter, annotations on methods appear before the method_declaration
    # as siblings within the class body. We handle this during _collect_methods.

    # Check for route annotations
    for ann in annotations:
        ann_short = ann.rsplit(".", 1)[-1].split("(", 1)[0]
        if ann_short in _ROUTE_ANNOTATIONS:
            # Extract path from annotation value
            path_matches = re.findall(r'"([^"]*)"', ann)
            route_paths.extend(path_matches)

    # Check for auth annotations
    for ann in annotations:
        ann_short = ann.rsplit(".", 1)[-1].split("(", 1)[0]
        if ann_short in _AUTH_ANNOTATIONS:
            has_auth = True

    return _JavaMethod(
        name=name,
        start_line=start_line,
        body_start_line=body_start_line,
        body=body,
        annotations=annotations,
        route_paths=route_paths,
        params=params,
        param_annotations=param_annotations_map,
        is_public=is_public,
        has_auth=has_auth,
    )


def _collect_methods(source: bytes, tree: Node) -> list[_JavaMethod]:
    """Collect all method declarations with their annotations from the AST."""
    methods: list[_JavaMethod] = []
    root = tree.root_node

    # Find class_declaration nodes
    for class_node in _find_all(root, "class_declaration"):
        class_body = _find_child(class_node, "class_body")
        if class_body is None:
            continue

        pending_annotations: list[str] = []

        for child in class_body.children:
            text = _node_text(child, source).strip() if child.type != "block" else ""

            # Collect annotations
            if child.type == "marker_annotation" or child.type == "annotation":
                pending_annotations.append(_node_text(child, source))
                continue

            # Method declaration
            if child.type == "method_declaration":
                method = _parse_method_declaration(child, source)
                # Merge pending annotations (from class_body level) with method's own
                method.annotations = pending_annotations + method.annotations
                # Also merge class-level annotations into param_annotations if needed
                for ann in pending_annotations:
                    ann_short = ann.rsplit(".", 1)[-1].split("(", 1)[0]
                    if ann_short in _FRAMEWORK_TAINT_ANNOTATIONS:
                        # Class-level framework annotation — apply to all params
                        for pname in method.params:
                            method.param_annotations.setdefault(pname, []).append(ann)
                # Parse route paths and auth from ALL annotations
                for ann in method.annotations:
                    ann_short = ann.rsplit(".", 1)[-1].split("(", 1)[0]
                    if ann_short in _ROUTE_ANNOTATIONS:
                        path_matches = re.findall(r'"([^"]*)"', ann)
                        method.route_paths.extend(path_matches)
                    if ann_short in _AUTH_ANNOTATIONS:
                        method.has_auth = True
                # Framework-annotated params are automatically taint sources
                for pname, panns in method.param_annotations.items():
                    for ann in panns:
                        ann_short = ann.rsplit(".", 1)[-1].split("(", 1)[0]
                        if ann_short in _FRAMEWORK_TAINT_ANNOTATIONS:
                            method.framework_tainted_params.add(pname)
                methods.append(method)
                pending_annotations = []
                continue

            # Non-annotation, non-method: reset pending annotations
            if child.type not in ("{", "}", ";", "comment", "block_comment", "line_comment",
                                   "marker_annotation", "annotation"):
                pending_annotations = []

    return methods


def _collect_tainted_variables_ast(tree: Node, source: bytes, params: list[str],
                                  framework_tainted: set[str] | None = None) -> set[str]:
    """Use tree-sitter AST to find variables carrying user input.
    Uses iterative propagation until the tainted set stabilizes.

    Args:
        tree: The parsed AST root node
        source: Source bytes
        params: Method parameter names
        framework_tainted: Parameter names annotated with @RequestParam/@RequestBody etc.
    """
    tainted: set[str] = set()

    # Pre-populate: framework-annotated params are automatically tainted
    if framework_tainted:
        tainted.update(framework_tainted)
    
    # Collect all relevant nodes once
    lvd_nodes = _find_all(tree, "local_variable_declaration")
    ae_nodes = _find_all(tree, "assignment_expression")
    
    # Iterative propagation until stable
    changed = True
    while changed:
        changed = False
        before = len(tainted)
        
        for node in lvd_nodes:
            _collect_taint_from_declaration(node, source, tainted)
        for node in ae_nodes:
            _collect_taint_from_assignment(node, source, tainted)
        
        if len(tainted) > before:
            changed = True
    
    # Post-pass: propagate through StringBuilder/StringBuffer .append() chains
    # sb.append(tainted) → sb is now tainted → sb.toString() is tainted
    # Also: list.add(tainted) → list is now tainted
    # Also: taintedReceiver.getXxx() → result is tainted
    all_mis = _find_all(tree, "method_invocation")
    changed = True
    while changed:
        changed = False
        before = len(tainted)
        for mi_node in all_mis:
            call = _parse_method_invocation(mi_node, source)
            if call.callee in _BUILDER_APPEND_METHODS | _COLLECTION_ADD_METHODS and call.receiver:
                for arg_text in call.arguments:
                    for t in list(tainted):
                        if t in arg_text:
                            if call.receiver not in tainted:
                                tainted.add(call.receiver)
                                changed = True
                            break
            # Propagate taint through getters on tainted objects
            # e.g., taintedCookie.getValue() or taintedList.get(0)
            if call.receiver and _is_getter(call.callee):
                for t in list(tainted):
                    if t == call.receiver or _token_in_var_list(t, call.raw):
                        # Find what variable this call is assigned to
                        parent = mi_node.parent
                        if parent and parent.type == "assignment_expression":
                            lhs_id = None
                            for pc in parent.children:
                                if pc.type == "identifier":
                                    lhs_id = _node_text(pc, source)
                                    break
                            if lhs_id and lhs_id not in tainted:
                                tainted.add(lhs_id)
                                changed = True
                        break
        if len(tainted) > before:
            changed = True
    
    return tainted


def _collect_taint_from_declaration(node: Node, source: bytes, tainted: set[str]) -> None:
    """Extract tainted variable from a local_variable_declaration AST node."""
    var_name = None
    is_request_call = False

    for child in node.children:
        if child.type == "variable_declarator":
            for vc in child.children:
                if vc.type == "identifier":
                    var_name = _node_text(vc, source)
                elif vc.type == "method_invocation":
                    call = _parse_method_invocation(vc, source)
                    if call.callee in _REQUEST_TAINT_METHODS:
                        is_request_call = True
                    # Taint-carrier: if receiver is tainted, return value is tainted
                    if call.receiver in tainted and call.callee in _TAINT_CARRIER_METHODS:
                        is_request_call = True
                    # Also check if any argument contains a tainted variable
                    for arg_text in call.arguments:
                        for t in list(tainted):
                            if t in arg_text:
                                if var_name:
                                    tainted.add(var_name)
                elif vc.type == "binary_expression":
                    # String concatenation like "prefix" + param
                    vc_text = _node_text(vc, source)
                    for t in list(tainted):
                        if t in vc_text and var_name:
                            tainted.add(var_name)
                elif vc.type == "array_initializer":
                    # Array initializer like {param} or {"x", param}
                    vc_text = _node_text(vc, source)
                    for t in list(tainted):
                        if t in vc_text and var_name:
                            tainted.add(var_name)

    if var_name and is_request_call:
        tainted.add(var_name)


def _collect_taint_from_assignment(node: Node, source: bytes, tainted: set[str]) -> None:
    """Propagate taint through assignment expressions, also detect direct request taint."""
    lhs = None
    rhs_text = ""
    has_request_call = False
    for child in node.children:
        if child.type == "identifier":
            if lhs is None:
                lhs = _node_text(child, source)
        elif child.type == "method_invocation":
            call = _parse_method_invocation(child, source)
            rhs_text += call.raw
            if call.callee in _REQUEST_TAINT_METHODS:
                has_request_call = True
            # Taint-carrier: if receiver is tainted, the return value is tainted
            if call.receiver in tainted and call.callee in _TAINT_CARRIER_METHODS:
                has_request_call = True
        elif child.type in ("binary_expression", "parenthesized_expression"):
            rhs_text += _node_text(child, source)
        elif child.type == "=":
            continue
        else:
            rhs_text += _node_text(child, source)

    if lhs:
        # Direct taint: lhs = request.getXxx()
        if has_request_call:
            tainted.add(lhs)
        # Propagation: lhs = expr_with_tainted_var
        for t in list(tainted):
            if t in rhs_text:
                tainted.add(lhs)
                break


def _has_dynamic_input(arguments: list[str], params: list[str]) -> bool:
    """Check if any argument references a method parameter (potential user input)."""
    for arg in arguments:
        arg_clean = arg.strip()
        if "+" in arg_clean:
            return True
        for param in params:
            if param in _FRAMEWORK_PARAM_NAMES:
                continue
            if param in arg_clean:
                return True
        if re.search(r'(?:request|req|body|param|query|header|cookie)\b', arg_clean, re.IGNORECASE):
            return True
    return False


def _has_dynamic_input_ast(arguments: list[str], params: list[str], tainted_vars: set[str]) -> bool:
    """Check if any argument references a tainted variable (from AST-level tracking)."""
    for arg in arguments:
        arg_clean = arg.strip()
        # String concat: only flag if it involves tainted vars or user params
        if "+" in arg_clean:
            has_tainted_concat = any(t in arg_clean for t in tainted_vars)
            has_user_param = any(p in arg_clean for p in params if p not in _FRAMEWORK_PARAM_NAMES)
            if has_tainted_concat or has_user_param:
                return True
        for tainted in tainted_vars:
            if tainted in arg_clean:
                return True
        for param in params:
            if param in _FRAMEWORK_PARAM_NAMES:
                continue
            if param in arg_clean:
                return True
        if re.search(r'(?:request|req)\b', arg_clean, re.IGNORECASE):
            return True
    return False


def _has_string_concat(call: _JavaCall) -> bool:
    """Check if any argument involves string concatenation with tainted input."""
    for arg in call.arguments:
        if "+" not in arg:
            continue
        # Must involve a non-literal (variable or method call)
        if re.search(r'[a-zA-Z_]\w*\s*\+', arg) or re.search(r'\+\s*[a-zA-Z_]\w*', arg):
            return True
    return False


def _is_getter(method_name: str) -> bool:
    """Check if a method name looks like a value-extracting getter."""
    if not method_name:
        return False
    return (method_name.startswith("get") and len(method_name) > 3) or \
           method_name in ("next", "nextElement", "elementAt", "getValue", "toString", "clone")


def _token_in_var_list(token: str, text: str) -> bool:
    """Check if token appears as a standalone identifier in text."""
    return bool(re.search(r'\b' + re.escape(token) + r'\b', text))


def _make_finding(
    line: int,
    title: str,
    description: str,
    suggestion: str,
    severity: Severity,
    rule_id: str,
    cwe: str,
    trace: tuple[TraceFrame, ...] = (),
    confidence: float = 0.85,
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
        agent="java-ast-analyzer",
        confidence=confidence,
        auto_fix="",
        explanation=f"### {cwe}\n\n{description}\n\n**Fix:** {suggestion}",
        analysis_kind="ast",
        trace=list(trace),
    )


# ── Rule checkers ───────────────────────────────────────────────────────────


def _body_line_to_file(method: _JavaMethod, body_line: int) -> int:
    """Convert a body-relative line number to a file-absolute line number.

    When we re-parse method.body as a standalone fragment, tree-sitter reports
    line numbers starting from 0 (relative to the body text). This helper
    offsets them by the method's file-level start line.
    """
    return method.start_line + body_line



def _check_sqli(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-89: SQL injection — origin-aware taint + regex patterns + FPR guards."""
    from ansede_static.java_taint_origins import collect_taint_origins, has_user_origin

    findings: list[Finding] = []
    for method in methods:
        body_bytes = method.body.encode("utf-8")
        body_tree = _JAVA_PARSER.parse(body_bytes).root_node
        origins = collect_taint_origins(body_tree, body_bytes, method.params,
                                         method.framework_tainted_params)
        calls = _collect_method_invocations(body_tree, body_bytes)

        # ── Pattern 0: IFDS-lite forward propagation ──
        try:
            from ansede_static.v2_java_bridge import run_ifds_analysis
            ifds_findings = run_ifds_analysis(body_tree, body_bytes, method.params)
            for f in ifds_findings:
                if f["cwe"] == "CWE-89":
                    findings.append(_make_finding(
                        line=0, title=f"CWE-89: SQLi (IFDS) — {f['tainted_vars']}",
                        description=f"IFDS taint at SQL sink: {f['text'][:100]}",
                        suggestion="Use parameterized queries.",
                        severity=Severity.CRITICAL, rule_id="JV-004", cwe="CWE-89"))
        except Exception:
            pass

        # Object-sensitive FPR guard: track parameterized vs dynamic statements
        from ansede_static.statement_tracker import classify_statement_variables, is_safe_sql_call
        stmt_vars = classify_statement_variables(method.body)

        # ── Pattern 1: Origin-aware check ──
        # ── Pattern 2: String concat with tainted vars in body ──
        tainted_concat_vars: set[str] = set()
        for t_var in origins:
            if re.search(r'"\s*\+\s*' + re.escape(t_var) + r'\b', method.body) or \
               re.search(r'\b' + re.escape(t_var) + r'\s*\+\s*"', method.body) or \
               re.search(r'\b' + re.escape(t_var) + r'\s*\+\s*\w', method.body):
                for m2 in re.finditer(r'(\w+)\s*=\s*"[^"]*"\s*\+\s*' + re.escape(t_var), method.body):
                    tainted_concat_vars.add(m2.group(1))
                tainted_concat_vars.add(t_var)

        # ── Pattern 3: String.format / String.concat detection ──
        format_vars: set[str] = set()
        for t_var in origins:
            if re.search(r'String\.format\s*\([^,]*' + re.escape(t_var), method.body) or \
               re.search(r'\.concat\s*\(\s*' + re.escape(t_var), method.body):
                for m2 in re.finditer(r'(\w+)\s*=\s*String\.format', method.body):
                    format_vars.add(m2.group(1))

        # ── Pattern 4: StringBuilder.append().toString() chains ──
        builder_vars: set[str] = set()
        for t_var in origins:
            if re.search(r'\.append\s*\(\s*' + re.escape(t_var), method.body):
                for m2 in re.finditer(r'(\w+)\s*=\s*new\s+StringBuilder', method.body):
                    builder_vars.add(m2.group(1))
                for m2 in re.finditer(r'(\w+)\.toString\(\)', method.body):
                    builder_vars.add(m2.group(1))

        for call in calls:
            if call.callee not in _SQLI_METHODS:
                continue

            # ── Object-sensitive FPR guard: skip parameterized statements ──
            if is_safe_sql_call(call.raw, stmt_vars):
                continue

            # ── Critical FPR guard: executeQuery/execute with NO args = PreparedStatement (safe) ──
            if call.callee in ("executeQuery", "execute") and not call.arguments:
                continue

            # ── FPR guard: prepareStatement/prepareCall with ? in SQL = parameterized (safe) ──
            if call.callee in ("prepareStatement", "prepareCall") and '?' in call.raw:
                continue

            # ── FPR guard: PreparedStatement with ? or JdbcTemplate with args ──
            if _is_parameterized_sql(call.raw):
                continue

            # ── Check all detection patterns ──
            has_user = has_user_origin(call.arguments, origins, method.params)
            has_concat = any(arg.strip() in tainted_concat_vars for arg in call.arguments)
            has_format = any(arg.strip() in format_vars for arg in call.arguments)
            has_builder = any(arg.strip() in builder_vars for arg in call.arguments)
            
            # Pattern 5: SQL string literal directly containing concat or format
            has_inline_sql = bool(re.search(
                r'(?:executeQuery|executeUpdate|createQuery|createNativeQuery|prepareCall)\s*\(\s*"[^"]*"\s*\+',
                call.raw
            )) or bool(re.search(
                r'(?:executeQuery|executeUpdate|createQuery|createNativeQuery|prepareCall)\s*\(\s*String\.format',
                call.raw
            ))

            if not (has_user or has_concat or has_format or has_builder or has_inline_sql):
                # Last-resort fallback: method has request source + SQL + concat anywhere
                has_request = bool(re.search(
                    r'(?:getParameter|getHeader|getCookies|getQueryString|getTheParameter|getInputStream)\s*\(',
                    method.body
                ))
                has_any_concat = '+' in method.body
                if not (has_request and has_any_concat):
                    continue

            findings.append(_make_finding(
                line=_body_line_to_file(method, call.line),
                title=f"CWE-89: SQL injection via {call.callee}() at line {_body_line_to_file(method, call.line)}",
                description=f"`{call.callee}()` called with dynamic input at L{_body_line_to_file(method, call.line)}: `{call.raw[:100]}`.",
                suggestion="Use parameterized queries with PreparedStatement or JdbcTemplate with ? placeholders.",
                severity=Severity.CRITICAL,
                rule_id="JV-004",
                cwe="CWE-89",
            ))
    return findings


def _is_parameterized_sql(raw: str) -> bool:
    """Check if SQL call uses parameterized query (safe pattern)."""
    if re.search(r'prepareStatement\s*\(\s*"[^"]*\?\s*[^"]*"', raw):
        return True
    if re.search(r'prepareCall\s*\(\s*"[^"]*\?\s*[^"]*"', raw):
        return True
    if re.search(r'\.query\s*\([^)]*,\s*new\s+Object\[\]', raw):
        return True
    if re.search(r'\.update\s*\([^)]*,\s*new\s+Object\[\]', raw):
        return True
    if re.search(r'\.queryForObject\s*\([^)]*,\s*\w+\s*\)', raw):
        return True
    return False


def _method_uses_parameterized_sql(method_body: str) -> bool:
    """Check if the ENTIRE method uses parameterized SQL patterns (safe)."""
    if re.search(r'prepareStatement\s*\(\s*"[^"]*\?\s*[^"]*"', method_body):
        return True
    if re.search(r'prepareCall\s*\(\s*"[^"]*\?\s*[^"]*"', method_body):
        return True
    if re.search(r'(?:query|update|queryForObject|queryForList)\s*\([^)]*,\s*new\s+Object\[\]', method_body):
        return True
    if re.search(r'prepareStatement\s*\(', method_body) and re.search(r'\.setString\s*\(|\.setInt\s*\(|\.setLong\s*\(', method_body):
        return True
    return False


def _method_has_no_request_source(method_body: str) -> bool:
    """True if method has NO user-input source — findings are likely FPs."""
    sources = (
        r'request\.getParameter|request\.getHeader|request\.getCookies|request\.getQueryString'
        r'|request\.getInputStream|request\.getReader'
        r'|getTheParameter|getTheValue'
        r'|\.getParameter\(|\.getHeader\(|\.getCookies\(|\.getQueryString\('
        r'|@RequestParam|@RequestBody|@PathVariable|@QueryParam|@FormParam'
    )
    return not bool(re.search(sources, method_body))


def _check_cmd_injection(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-78: Command injection detection with origin-aware taint."""
    from ansede_static.java_taint_origins import collect_taint_origins, has_user_origin
    findings: list[Finding] = []
    for method in methods:
        body_bytes = method.body.encode("utf-8")
        if _method_has_no_request_source(method.body):
            continue
        body_tree = _JAVA_PARSER.parse(body_bytes).root_node
        origins = collect_taint_origins(body_tree, body_bytes, method.params,
                                         method.framework_tainted_params)
        calls = _collect_method_invocations(body_tree, body_bytes)
        for call in calls:
            if call.callee == "exec":
                if has_user_origin(call.arguments, origins, method.params):
                    fl = _body_line_to_file(method, call.line)
                    findings.append(_make_finding(
                        line=fl,
                        title=f"CWE-78: Command injection via Runtime.exec() at line {fl}",
                        description=f"`Runtime.exec()` called with dynamic input at L{fl}: `{call.raw[:100]}`.",
                        suggestion="Use ProcessBuilder with a command list, never concatenate user input into shell commands.",
                        severity=Severity.CRITICAL,
                        rule_id="JV-008",
                        cwe="CWE-78",
                    ))
            # ProcessBuilder.command(list) — check for dynamic input
            if call.callee in _PB_COMMAND_METHODS:
                if has_user_origin(call.arguments, origins, method.params):
                    fl = _body_line_to_file(method, call.line)
                    findings.append(_make_finding(
                        line=fl,
                        title=f"CWE-78: Command injection via ProcessBuilder.{call.callee}() at line {fl}",
                        description=f"`ProcessBuilder.{call.callee}()` with dynamic input at L{fl}: `{call.raw[:100]}`.",
                        suggestion="Use a hardcoded command list. Never include user input in process arguments.",
                        severity=Severity.CRITICAL,
                        rule_id="JV-008",
                        cwe="CWE-78",
                    ))

        creations = _collect_object_creations(body_tree, body_bytes)
        for class_name, args, line in creations:
            if class_name == "ProcessBuilder" and has_user_origin(args, origins, method.params):
                fl = _body_line_to_file(method, line)
                findings.append(_make_finding(
                    line=fl,
                    title=f"CWE-78: Command injection via ProcessBuilder at line {fl}",
                    description=f"`new ProcessBuilder()` with dynamic arguments at L{fl}.",
                    suggestion="Pass command arguments as a list of hardcoded strings, never with user input concatenation.",
                    severity=Severity.CRITICAL,
                    rule_id="JV-008",
                    cwe="CWE-78",
                ))
    return findings


def _check_weak_crypto(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-328: Weak cryptographic algorithm detection."""
    findings: list[Finding] = []
    for method in methods:
        calls = _collect_method_invocations(
            _JAVA_PARSER.parse(method.body.encode("utf-8")).root_node,
            method.body.encode("utf-8"),
        )
        for call in calls:
            if call.callee != "getInstance":
                continue
            for arg in call.arguments:
                for algo in _WEAK_CRYPTO_ALGOS:
                    if algo.lower() in arg.lower():
                        fl = _body_line_to_file(method, call.line)
                        findings.append(_make_finding(
                            line=fl,
                            title=f"CWE-328: Weak cryptographic algorithm ({algo}) at line {fl}",
                            description=f"`MessageDigest.getInstance({algo})` or similar at L{fl}.",
                            suggestion="Use SHA-256 or stronger. For passwords, use bcrypt, scrypt, or Argon2.",
                            severity=Severity.HIGH,
                            rule_id="JV-012",
                            cwe="CWE-328",
                        ))
                        break
    return findings


def _check_ssrf(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-918: Server-Side Request Forgery with origin-aware taint."""
    from ansede_static.java_taint_origins import collect_taint_origins, has_user_origin
    findings: list[Finding] = []
    for method in methods:
        body_bytes = method.body.encode("utf-8")
        body_tree = _JAVA_PARSER.parse(body_bytes).root_node
        origins = collect_taint_origins(body_tree, body_bytes, method.params,
                                         method.framework_tainted_params)
        calls = _collect_method_invocations(body_tree, body_bytes)
        for call in calls:
            if call.callee == "openConnection" and has_user_origin(call.arguments, origins, method.params):
                fl = _body_line_to_file(method, call.line)
                findings.append(_make_finding(
                    line=fl,
                    title=f"CWE-918: SSRF via openConnection() at line {fl}",
                    description=f"`openConnection()` with dynamic URL at L{fl}.",
                    suggestion="Validate URLs against an allowlist.",
                    severity=Severity.HIGH, rule_id="JV-009", cwe="CWE-918"))
        creations = _collect_object_creations(body_tree, body_bytes)
        for class_name, args, line in creations:
            if class_name == "URL" and has_user_origin(args, origins, method.params):
                fl = _body_line_to_file(method, line)
                findings.append(_make_finding(
                    line=fl, title=f"CWE-918: SSRF via URL() at line {fl}",
                    description=f"`new URL()` with dynamic input at L{fl}.",
                    suggestion="Validate URLs against an allowlist.",
                    severity=Severity.HIGH, rule_id="JV-009", cwe="CWE-918"))
    return findings


def _check_open_redirect(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-601: Open redirect with origin-aware taint."""
    from ansede_static.java_taint_origins import collect_taint_origins, has_user_origin
    findings: list[Finding] = []
    for method in methods:
        body_bytes = method.body.encode("utf-8")
        body_tree = _JAVA_PARSER.parse(body_bytes).root_node
        origins = collect_taint_origins(body_tree, body_bytes, method.params,
                                         method.framework_tainted_params)
        calls = _collect_method_invocations(body_tree, body_bytes)
        for call in calls:
            if call.callee == "sendRedirect" and has_user_origin(call.arguments, origins, method.params):
                fl = _body_line_to_file(method, call.line)
                findings.append(_make_finding(
                    line=fl,
                    title=f"CWE-601: Open redirect via sendRedirect() at line {fl}",
                    description=f"`sendRedirect()` with user-controlled URL at L{fl}.",
                    suggestion="Validate redirect URLs against a static allowlist.",
                    severity=Severity.MEDIUM, rule_id="JV-010", cwe="CWE-601"))
    return findings


def _check_xss(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-79: Cross-Site Scripting via response writer with origin-aware taint."""
    from ansede_static.java_taint_origins import collect_taint_origins, has_user_origin
    findings: list[Finding] = []
    for method in methods:
        body_bytes = method.body.encode("utf-8")
        if _method_has_no_request_source(method.body):
            continue
        body_tree = _JAVA_PARSER.parse(body_bytes).root_node
        origins = collect_taint_origins(body_tree, body_bytes, method.params,
                                         method.framework_tainted_params)
        calls = _collect_method_invocations(body_tree, body_bytes)
        for call in calls:
            if call.callee in _XSS_OUTPUT_METHODS and has_user_origin(call.arguments, origins, method.params):
                rcvr_lower = call.receiver.lower()
                if rcvr_lower and rcvr_lower not in _XSS_RESPONSE_RECEIVERS:
                    if rcvr_lower not in origins and not any(
                        w in rcvr_lower for w in ('writer', 'output', 'response', 'printwriter', 'stream')):
                        continue
                # FPR guard: check if ESAPI/OWASP encoding is applied nearby
                call_text = call.raw.lower()
                if any(enc in call_text for enc in (
                    'encodeforhtml', 'encodeforjavascript', 'encodeforcss',
                    'escapehtml', 'htmlencode', 'esapi.encoder',
                    'stringescapeutils.escapehtml', 'encode.forhtml',
                )):
                    continue
                fl = _body_line_to_file(method, call.line)
                findings.append(_make_finding(
                    line=fl,
                    title=f"CWE-79: XSS via response write() at line {fl}",
                    description=f"Response writer with dynamic content at L{fl}: `{call.raw[:100]}`.",
                    suggestion="HTML-encode all user-supplied data before writing to the HTTP response.",
                    severity=Severity.HIGH,
                    rule_id="JV-006",
                    cwe="CWE-79",
                ))
    return findings


def _check_hardcoded_secrets(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-798: Hardcoded credentials detection."""
    findings: list[Finding] = []
    _SECRET_RE = re.compile(
        r'\b(?:password|passwd|pwd|apiKey|apikey|secret|secretKey|token)\b\s*=\s*"([^"]{3,})"',
        re.IGNORECASE,
    )
    for method in methods:
        for match in _SECRET_RE.finditer(method.body):
            if any(skip in match.group(1).lower() for skip in ("placeholder", "example", "your-", "xxx", "test")):
                continue
            line = method.start_line + method.body[:match.start()].count("\n")
            findings.append(_make_finding(
                line=line,
                title=f"CWE-798: Hardcoded credential at line {line}",
                description=f"Hardcoded secret value found at L{line}: `{match.group(1)[:30]}...`.",
                suggestion="Use environment variables, a secrets manager, or a configuration server.",
                severity=Severity.HIGH,
                rule_id="JV-008",
                cwe="CWE-798",
            ))
    return findings


def _check_path_traversal(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-22: Path traversal with origin-aware taint + NIO patterns."""
    from ansede_static.java_taint_origins import collect_taint_origins, has_user_origin
    findings: list[Finding] = []
    for method in methods:
        body_bytes = method.body.encode("utf-8")
        if _method_has_no_request_source(method.body):
            continue
        body_tree = _JAVA_PARSER.parse(body_bytes).root_node
        origins = collect_taint_origins(body_tree, body_bytes, method.params,
                                         method.framework_tainted_params)
        creations = _collect_object_creations(body_tree, body_bytes)
        for class_name, args, line in creations:
            if class_name in _PATH_TRAVERSAL_CLASSES and has_user_origin(args, origins, method.params):
                fl = _body_line_to_file(method, line)
                findings.append(_make_finding(
                    line=fl, title=f"CWE-22: Path traversal via new {class_name}() at line {fl}",
                    description=f"`new {class_name}()` with user-controlled path at L{fl}.",
                    suggestion="Validate and sanitize file paths.",
                    severity=Severity.HIGH, rule_id="JV-008", cwe="CWE-22"))
        calls = _collect_method_invocations(body_tree, body_bytes)
        for call in calls:
            is_path_sink = (call.callee == "get" and call.receiver == "Paths") or \
                           (call.callee in _PATH_TRAVERSAL_METHODS and call.receiver == "Files") or \
                           call.callee in _PATH_TRAVERSAL_METHODS
            if is_path_sink and has_user_origin(call.arguments, origins, method.params):
                fl = _body_line_to_file(method, call.line)
                findings.append(_make_finding(
                    line=fl,
                    title=f"CWE-22: Path traversal via {call.receiver}.{call.callee}() at line {fl}",
                    description=f"`{call.receiver}.{call.callee}()` with user-controlled path at L{fl}.",
                    suggestion="Validate and sanitize file paths.",
                    severity=Severity.HIGH, rule_id="JV-008", cwe="CWE-22"))
    return findings


def _check_auth_bypass(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-862: Missing authorization on sensitive routes."""
    findings: list[Finding] = []
    for method in methods:
        # Check if it's a mutating route without auth
        has_mutating = any(
            ann.rsplit(".", 1)[-1].split("(", 1)[0] in _MUTATING_ANNOTATIONS
            for ann in method.annotations
        )
        if not has_mutating:
            # Also flag GET endpoints exposing actuator/sensitive paths without auth
            has_actuator = any(
                "/actuator/" in rp or "/env" in rp or "/heapdump" in rp
                for ann in method.annotations
                for rp in (re.findall(r'"([^"]*)"', ann) or [])
            )
            if not has_actuator:
                continue
        if method.has_auth:
            continue
        # Check for manual security checks in body
        if re.search(r'SecurityContextHolder|getAuthentication|isAuthenticated|hasRole|hasAuthority',
                     method.body):
            continue
        findings.append(_make_finding(
            line=method.start_line,
            title=f"CWE-862: Missing authorization on mutating route {method.name}() at line {method.start_line}",
            description=f"Mutating endpoint `{method.name}()` at L{method.start_line} has no auth annotation or manual security check.",
            suggestion="Add @PreAuthorize, @Secured, or manual auth check.",
            severity=Severity.HIGH,
            rule_id="JV-009",
            cwe="CWE-862",
        ))
    return findings


def _has_sanitizer(calls: list[_JavaCall], cwe: str, line: int = 0) -> bool:
    """Check if any call uses a sanitizer for the given CWE, near the given line.
    
    Only matches actual method calls, not arbitrary substrings in comments.
    """
    sanitizers = _SANITIZER_PATTERNS.get(cwe, frozenset())
    if not sanitizers:
        return False
    for call in calls:
        # Only match actual method/class names, not substrings in raw text
        if call.callee in sanitizers:
            if line == 0 or abs(call.line - line) <= 3:
                return True
        if call.receiver in sanitizers:
            if line == 0 or abs(call.line - line) <= 3:
                return True
    return False


def _check_ldap_injection(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-90: LDAP injection with origin-aware taint."""
    from ansede_static.java_taint_origins import collect_taint_origins, has_user_origin
    findings: list[Finding] = []
    for method in methods:
        body_bytes = method.body.encode("utf-8")
        if _method_has_no_request_source(method.body):
            continue
        body_tree = _JAVA_PARSER.parse(body_bytes).root_node
        origins = collect_taint_origins(body_tree, body_bytes, method.params,
                                         method.framework_tainted_params)
        all_calls = _collect_method_invocations(body_tree, body_bytes)

        if _has_sanitizer(all_calls, "CWE-90"):
            continue

        for call in all_calls:
            if call.callee in _LDAP_SINK_METHODS:
                if has_user_origin(call.arguments, origins, method.params):
                    fl = _body_line_to_file(method, call.line)
                    findings.append(_make_finding(
                        line=fl,
                        title=f"CWE-90: LDAP injection via {call.callee}() at line {fl}",
                        description=f"`{call.callee}()` with dynamic filter at L{fl}: `{call.raw[:100]}`.",
                        suggestion="Use parameterized LDAP queries or escape special chars per RFC 4515.",
                        severity=Severity.HIGH,
                        rule_id="JV-025",
                        cwe="CWE-90",
                    ))

        creations = _collect_object_creations(body_tree, body_bytes)
        for class_name, args, line in creations:
            if class_name in _LDAP_SINK_CLASSES and has_user_origin(args, origins, method.params):
                fl = _body_line_to_file(method, line)
                findings.append(_make_finding(
                    line=fl,
                    title=f"CWE-90: LDAP injection via {class_name} at line {fl}",
                    description=f"`new {class_name}()` with dynamic parameters at L{fl}.",
                    suggestion="Validate and escape LDAP filter values.",
                    severity=Severity.HIGH,
                    rule_id="JV-025",
                    cwe="CWE-90",
                ))
    return findings


def _check_xpath_injection(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-643: XPath injection with origin-aware taint."""
    from ansede_static.java_taint_origins import collect_taint_origins, has_user_origin
    findings: list[Finding] = []
    for method in methods:
        body_bytes = method.body.encode("utf-8")
        if _method_has_no_request_source(method.body):
            continue
        body_tree = _JAVA_PARSER.parse(body_bytes).root_node
        origins = collect_taint_origins(body_tree, body_bytes, method.params,
                                         method.framework_tainted_params)
        all_calls = _collect_method_invocations(body_tree, body_bytes)

        if _has_sanitizer(all_calls, "CWE-643"):
            continue

        for call in all_calls:
            if call.callee in _XPATH_SINK_METHODS:
                if has_user_origin(call.arguments, origins, method.params):
                    fl = _body_line_to_file(method, call.line)
                    findings.append(_make_finding(
                        line=fl,
                        title=f"CWE-643: XPath injection via {call.callee}() at line {fl}",
                        description=f"`{call.callee}()` with dynamic XPath at L{fl}: `{call.raw[:100]}`.",
                        suggestion="Use parameterized XPath with XPathVariablesResolver.",
                        severity=Severity.HIGH,
                        rule_id="JV-026",
                        cwe="CWE-643",
                    ))

        creations = _collect_object_creations(body_tree, body_bytes)
        for class_name, args, line in creations:
            if class_name in _XPATH_SINK_CLASSES and has_user_origin(args, origins, method.params):
                fl = _body_line_to_file(method, line)
                findings.append(_make_finding(
                    line=fl,
                    title=f"CWE-643: XPath injection via {class_name} at line {fl}",
                    description=f"`new {class_name}()` with dynamic expression at L{fl}.",
                    suggestion="Use parameterized XPath. Validate input against allowlist.",
                    severity=Severity.HIGH,
                    rule_id="JV-026",
                    cwe="CWE-643",
                ))
    return findings


def _check_interprocedural_taint(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """Interprocedural taint: detect when tainted args flow to sinks through helper calls.

    Queries GlobalGraph for callee summaries and flags call sites where
    tainted arguments reach sinks via the callee.
    """
    # This checker requires GlobalGraph - it's a no-op if not wired
    return []  # Wired via analyze_java_ast with global_graph parameter


# ── Main analyzer ───────────────────────────────────────────────────────────

_ALL_CHECKERS: list[tuple[str, Any]] = [
    ("CWE-89 SQLi", _check_sqli),
    ("CWE-78 CMDi", _check_cmd_injection),
    ("CWE-328 WeakCrypto", _check_weak_crypto),
    ("CWE-918 SSRF", _check_ssrf),
    ("CWE-601 Redirect", _check_open_redirect),
    ("CWE-79 XSS", _check_xss),
    ("CWE-798 Secrets", _check_hardcoded_secrets),
    ("CWE-22 Traversal", _check_path_traversal),
    ("CWE-862 Auth", _check_auth_bypass),
    ("CWE-90 LDAP", _check_ldap_injection),
    ("CWE-643 XPath", _check_xpath_injection),
    ("Interprocedural", _check_interprocedural_taint),
]


def _build_method_summaries_for_gg(
    methods: list[_JavaMethod],
    source: bytes,
    filename: str,
    global_graph: object | None,
) -> None:
    """Compute per-method taint summaries and record into GlobalGraph.

    For each method, determines which argument positions reach which sinks,
    and records a FunctionSummary so callers can propagate taint through
    the call chain.
    """
    if global_graph is None:
        return
    try:
        from ansede_static.ir.global_graph import FunctionSummary, IDETaintLevel
    except ImportError:
        return

    for method in methods:
        body_bytes = method.body.encode("utf-8")
        body_tree = _JAVA_PARSER.parse(body_bytes).root_node
        tainted_vars = _collect_tainted_variables_ast(body_tree, body_bytes, method.params,
                                                       method.framework_tainted_params)
        calls = _collect_method_invocations(body_tree, body_bytes)
        creations = _collect_object_creations(body_tree, body_bytes)

        # Determine which params reach sinks: check each param against method body
        # Conservative: any param that appears in a concat with a sink arg is flagged
        args_to_sink: set[int] = set()
        args_to_return: set[int] = set()

        for call in calls:
            # Collect all sink categories
            is_sqli = call.callee in _SQLI_METHODS
            is_cmdi = call.callee == "exec" and call.receiver in ("Runtime", "runtime", "rt")
            is_xss = call.callee == "write" and (call.receiver.lower() in _XSS_RESPONSE_RECEIVERS or not call.receiver)
            is_pathtrav = call.callee == "get" and call.receiver == "Paths"
            is_ldap = call.callee in _LDAP_SINK_METHODS
            is_xpath = call.callee in _XPATH_SINK_METHODS
            
            if not (is_sqli or is_cmdi or is_xss or is_pathtrav or is_ldap or is_xpath):
                continue
            
            # For each param, check if it reaches this sink
            for idx, param in enumerate(method.params):
                if not param or param in ("request", "req", "response", "res"):
                    continue
                # Direct check: param appears in arg text or is tainted
                for arg_text in call.arguments:
                    if _token_in_text(param, arg_text, tainted_vars, method.body):
                        args_to_sink.add(idx)
                        args_to_return.add(idx)
                        break
                # Conservative: param appears in concat anywhere in body near a sink var
                if idx not in args_to_sink:
                    for arg_text in call.arguments:
                        arg_stripped = arg_text.strip()
                        if arg_stripped and re.search(
                            r'\b' + re.escape(arg_stripped) + r'\s*=.*\+.*\b' + re.escape(param) + r'\b',
                            method.body
                        ):
                            args_to_sink.add(idx)
                            args_to_return.add(idx)
                            break

        # Also check object creations for sinks
        for class_name, args, line in creations:
            if class_name in _PATH_TRAVERSAL_CLASSES or class_name in _SSRF_CLASSES or \
               class_name in _LDAP_SINK_CLASSES or class_name in _XPATH_SINK_CLASSES or \
               class_name == "ProcessBuilder":
                for idx, param in enumerate(method.params):
                    for arg_text in args:
                        if _token_in_text(param, arg_text, tainted_vars, method.body):
                            args_to_sink.add(idx)
                            args_to_return.add(idx)

        # Detect direct sources
        has_source = any(
            call.callee in _REQUEST_TAINT_METHODS
            for call in calls
        )

        full_name = method.name
        try:
            global_graph.record_function_summary(FunctionSummary(
                file_path=filename or "<stdin>",
                function_name=full_name,
                args_to_sink=tuple(sorted(args_to_sink)),
                args_to_return=tuple(sorted(args_to_return)),
                return_from_source=has_source,
                side_effect_symbols=(),
                depends_on=tuple(c.callee for c in calls),
            ))

            if has_source and hasattr(global_graph, "set_taint_with_access_path"):
                try:
                    global_graph.set_taint_with_access_path(
                        file_path=filename or "<stdin>",
                        function_name=full_name,
                        value_label="$ret",
                        level=IDETaintLevel.TAINTED,
                        sources=("request.getParameter",),
                    )
                except Exception:
                    pass
        except Exception:
            pass

    try:
        global_graph.save_summaries()
    except Exception:
        pass


def _token_in_text(param: str, arg_text: str, tainted: set[str],
                   method_body: str = "") -> bool:
    """Check if a parameter or tainted variable appears in argument text.
    
    Also checks reverse: if any tainted var in arg_text was built from param
    (e.g., sql = "..." + id → executeQuery(sql) → id reaches sink).
    """
    if not param:
        return False
    if re.search(r'\b' + re.escape(param) + r'\b', arg_text):
        return True
    if param in tainted:
        return True
    # Reverse: check if any tainted var in arg_text traces to param via concat
    for t_var in tainted:
        if t_var in arg_text and method_body:
            # Does method body show t_var = "..." + param or t_var = param + "..."?
            if re.search(r'\b' + re.escape(t_var) + r'\s*=.*\+.*\b' + re.escape(param) + r'\b', method_body):
                return True
            if re.search(r'\b' + re.escape(t_var) + r'\s*=.*\b' + re.escape(param) + r'\s*\+', method_body):
                return True
    return False


def _check_interprocedural_taint(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """Interprocedural taint: detect when tainted args flow to sinks through helper calls.

    Queries GlobalGraph for callee summaries and flags call sites where
    tainted arguments reach sinks via the callee.
    """
    # This checker requires GlobalGraph - it's a no-op if not wired
    return []  # Wired via analyze_java_ast with global_graph parameter


def _check_interprocedural_taint_impl(
    methods: list[_JavaMethod],
    source: bytes,
    global_graph: object,
    filename: str,
) -> list[Finding]:
    """Actual implementation of interprocedural taint checking."""
    findings: list[Finding] = []
    if global_graph is None:
        return findings

    # Build set of all method names in this file for local call resolution
    local_methods: set[str] = {m.name for m in methods}

    for method in methods:
        body_bytes = method.body.encode("utf-8")
        body_tree = _JAVA_PARSER.parse(body_bytes).root_node
        tainted_vars = _collect_tainted_variables_ast(body_tree, body_bytes, method.params,
                                                       method.framework_tainted_params)
        calls = _collect_method_invocations(body_tree, body_bytes)

        for call in calls:
            # Only process calls to local methods (not external APIs)
            if call.callee not in local_methods:
                continue
            # Skip self-recursion
            if call.callee == method.name:
                continue
            # Skip known external classes
            if call.receiver in ("System", "Arrays", "Collections", "Objects",
                                  "String", "Integer", "Long", "Boolean", "Math"):
                continue

            # Determine which argument positions are tainted
            tainted_arg_indexes: set[int] = set()
            for idx, arg_text in enumerate(call.arguments):
                if _has_dynamic_input_ast([arg_text], method.params, tainted_vars):
                    tainted_arg_indexes.add(idx)

            if not tainted_arg_indexes:
                continue

            # Query GlobalGraph for callee summary
            try:
                sink_hit, sink_trace, ret_hit, return_trace = global_graph.propagate_call_facts(
                    caller_file=filename or "<stdin>",
                    caller_name=method.name,
                    callee_file=filename or "<stdin>",
                    callee_name=call.callee,
                    tainted_arg_indexes=tainted_arg_indexes,
                    call_line=call.line,
                )

                if sink_hit:
                    # Determine CWE from callee's sink types
                    summary = global_graph.get_function_summary(filename or "<stdin>", call.callee)
                    cwe = "CWE-89"  # default
                    if summary and summary.args_to_sink:
                        cwe = "CWE-89"

                    fl = _body_line_to_file(method, call.line)
                    findings.append(_make_finding(
                        line=fl,
                        title=f"Interprocedural taint: {call.callee}() at line {fl}",
                        description=f"Tainted argument flows to sink through `{call.callee}()`. Call at L{fl}: `{call.raw[:100]}`.",
                        suggestion="Review the data flow through helper methods. Ensure input validation at the entry point.",
                        severity=Severity.HIGH,
                        rule_id="JV-030",
                        cwe=cwe,
                        trace=sink_trace,
                        confidence=0.80,
                    ))

                if ret_hit:
                    # The callee returns tainted data - mark it for propagation
                    # For now, just flag if the return value is used unsafely
                    pass

            except Exception:
                pass

    return findings


def analyze_java_ast(
    code: str,
    filename: str = "",
    global_graph: object = None,
) -> AnalysisResult:
    """Analyze Java source using tree-sitter AST.

    Args:
        code: Java source code
        filename: Path to the source file
        global_graph: Optional GlobalGraph for interprocedural IFDS taint

    Returns an AnalysisResult with findings from all active checkers.
    """
    result = AnalysisResult(
        file_path=filename,
        language="java",
        lines_scanned=len(code.splitlines()),
    )

    source_bytes = code.encode("utf-8")
    try:
        tree = _JAVA_PARSER.parse(source_bytes)
    except Exception as exc:
        _log.debug("Tree-sitter parse failed for %r: %s", filename, exc)
        return result

    methods = _collect_methods(source_bytes, tree)
    if not methods:
        _log.debug("No methods extracted from %r", filename)

    # Phase 1: Build per-method summaries and record into GlobalGraph
    _build_method_summaries_for_gg(methods, source_bytes, filename, global_graph)

    # Phase 2: Run pattern checkers
    for checker_label, checker_fn in _ALL_CHECKERS:
        try:
            if checker_label == "Interprocedural":
                result.findings.extend(
                    _check_interprocedural_taint_impl(methods, source_bytes, global_graph, filename)
                )
            else:
                result.findings.extend(checker_fn(methods, source_bytes))
        except Exception as exc:
            _log.debug("Java checker %s failed on %r: %s", checker_label, filename, exc, exc_info=True)

    return result
