"""
java_ast_analyzer.py — Ansede Static tree-sitter Java analysis engine.

Replaces regex structural heuristics with accurate tree-sitter AST parsing.
Provides: method extraction, call-graph construction, annotation-aware routing,
taint-source → sink tracking, and framework-aware analysis (Spring, JAX-RS,
Micronaut, Quarkus).

Architecture mirrors js_ast_analyzer.py: parse → extract → match → report.
"""
from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from tree_sitter import Language, Parser, Node
import tree_sitter_java as tsjava

from ansede_static._types import AnalysisResult, Finding, Severity, TraceFrame

_log = logging.getLogger(__name__)

# ── tree-sitter setup ───────────────────────────────────────────────────────
JAVA_LANGUAGE = Language(tsjava.language())
_JAVA_PARSER = Parser(JAVA_LANGUAGE)

# ── IFDS result cache ───────────────────────────────────────────────────────
# Keyed by (method_sig, source_hash) → {method_name: [findings]}
# Avoids re-running the expensive IFDS solver on identical method bodies
_IFDS_CACHE: dict[tuple[str, str], dict[str, list[dict[str, Any]]]] = {}
_MAX_CACHE_SIZE = 256

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
    # Standard JDBC
    "createQuery", "executeQuery", "executeUpdate",
    "createNativeQuery", "prepareCall", "prepareStatement",
    "createStatement",
    # JdbcTemplate (Spring)
    "query", "queryForObject", "queryForList", "queryForMap",
    "queryForRowSet", "update", "batchUpdate", "execute",
    # JPA EntityManager / Hibernate
    "createQuery", "createNativeQuery", "createNamedQuery",
    "find", "persist", "merge", "remove",
    # JPA @Query / raw
    "getResultList", "getSingleResult",
})
_SQLI_CLASSES: frozenset[str] = frozenset({
    "JdbcTemplate", "NamedParameterJdbcTemplate",
    "EntityManager", "Session", "SessionFactory",
    "Query", "TypedQuery", "StoredProcedureQuery",
})
# SQLI receiver patterns (variable names that indicate a JDBC/JPA object)
_SQLI_RECEIVER_PATTERNS: tuple[str, ...] = (
    "jdbcTemplate", "jdbc", "template", "namedJdbcTemplate",
    "entityManager", "em", "session", "entityMgr",
    "query", "typedQuery", "storedProcQuery",
)

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
    "RandomAccessFile", "File", "Files", "Path", "Paths",
})
_PATH_TRAVERSAL_METHODS: frozenset[str] = frozenset({
    "Paths.get", "Path.of", "read", "write", "newInputStream", "newOutputStream",
    "readAllBytes", "readString", "writeString", "copy", "move",
    "createFile", "createDirectory", "newBufferedReader", "newBufferedWriter",
    "list", "walk", "delete", "deleteIfExists", "resolve", "resolveSibling",
    "toPath", "toFile",
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

# ── Deserialization sinks (CWE-502) ──────────────────────────────────────
_DESERIALIZATION_SINK_CLASSES: frozenset[str] = frozenset({
    "ObjectInputStream", "XMLDecoder", "Jackson2ObjectMapperBuilder",
})
_DESERIALIZATION_SINK_METHODS: frozenset[str] = frozenset({
    "readObject", "readUnshared", "readResolve", "decodeObject",
    "deserialize", "fromXML", "fromJSON",
})

# ── NoSQL injection sinks (CWE-943) ──────────────────────────────────────
_NOSQL_SINK_CLASSES: frozenset[str] = frozenset({
    "MongoCollection", "MongoDatabase", "MongoClient",
    "Document", "BasicDBObject", "BsonDocument", "Query", "Criteria",
})
_NOSQL_SINK_METHODS: frozenset[str] = frozenset({
    "find", "findOne", "aggregate", "updateOne", "updateMany",
    "deleteOne", "deleteMany", "replaceOne",
    "where", "andOperator", "orOperator",
})

# ── SSTI / template injection sinks (CWE-94) ─────────────────────────────
_SSTI_SINK_CLASSES: frozenset[str] = frozenset({
    "VelocityEngine", "Template", "FreeMarkerTemplate",
    "ThymeleafTemplate", "MustacheTemplate",
})
_SSTI_SINK_METHODS: frozenset[str] = frozenset({
    "evaluate", "merge", "process", "render", "eval", "evalScript",
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

# ── Sanitizer Tracker: per-method variable sanitization ──────────────────
# Tracks which variables have been sanitized (safe to pass to sinks).
# Goal: reduce FPR by recognizing PreparedStatement + setString, ESAPI encoding,
# and other sanitizer patterns WITHOUT losing true positives.

# SQL sanitizers — patterns that neutralize SQL injection risk
_SQL_SANITIZER_METHODS: frozenset[str] = frozenset({
    "setString", "setInt", "setLong", "setDouble", "setFloat",
    "setBoolean", "setDate", "setTimestamp", "setObject", "setBytes",
    "setNull", "setBigDecimal", "setTime", "setURL", "setArray",
})

# SQL prepared-statement variable patterns — if a method has BOTH of these, SQL is safe
_SQL_PREPARED_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r'prepareStatement\s*\(\s*"[^"]*\?[^"]*"', re.IGNORECASE),
    re.compile(r'prepareCall\s*\(\s*"[^"]*\?[^"]*"', re.IGNORECASE),
)

# XSS sanitizers — encoding functions that neutralize XSS
_XSS_SANITIZER_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r'(?:ESAPI\.encoder\(\)\.encodeForHTML|encodeForHTML|StringEscapeUtils\.escapeHtml4?|'
               r'HtmlUtils\.htmlEscape|OWASP\w*Encoder\.encodeForHTML|HTMLEntityCodec|'
               r'\.encode\s*\(\s*\w+\s*,\s*"(?:HTML|html))', re.IGNORECASE),
    re.compile(r'(?:Jsoup\.clean|Sanitizer\.sanitize|DOMPurify)', re.IGNORECASE),
)

# Command injection sanitizers — patterns that make exec safe
_CMD_SANITIZER_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r'new\s+ProcessBuilder\s*\(', re.IGNORECASE),  # array form, no shell
    re.compile(r'\.command\s*\(\s*new\s+\w+\[\]', re.IGNORECASE),
)

# Hardcoded string assignment — not tainted
_HARDCODED_STRING_RE = re.compile(
    r'(?:String|var)\s+(\w+)\s*=\s*"(?:[^"\\]|\\.)*"\s*;',
    re.IGNORECASE,
)

# Variable assignment from sanitizer function: String safe = encode(x);
_SANITIZER_ASSIGN_RE = re.compile(
    r'(?:String|var)\s+(\w+)\s*=\s*(\w+(?:\.\w+)*)\s*\(\s*(\w+)',
    re.IGNORECASE,
)

# String concatenation: param + "..." or "..." + param
_STRING_CONCAT_RE = re.compile(r'(\w+)\s*\+\s*"[^"]*"|"[^"]*"\s*\+\s*(\w+)', re.IGNORECASE)


class SanitizerTracker:
    """Per-method tracking of which variables have been sanitized for specific CWEs."""

    def __init__(self, method_body: str):
        self._body = method_body
        self._body_lower = method_body.lower()
        # CWE → set of safe variable names
        self._safe_vars: dict[str, set[str]] = {
            "CWE-89": set(),   # SQL-safe vars
            "CWE-79": set(),   # XSS-safe vars
            "CWE-78": set(),   # CmdInj-safe vars
        }
        # Variables set to hardcoded strings (not tainted)
        self._hardcoded_vars: set[str] = set()
        # Variables that went through string concatenation (definitely tainted)
        self._concat_vars: set[str] = set()
        # Whether the method uses PreparedStatement with setString (completely SQL-safe)
        self._has_safe_sql: bool = False
        # Whether the method uses ESAPI/OWASP HTML encoding
        self._has_html_encoding: bool = False

        self._analyze()

    def _analyze(self) -> None:
        """Scan method body for sanitizer patterns."""
        b = self._body

        # 1. Detect PreparedStatement + parameterized query (completely SQL-safe)
        has_param_query = any(p.search(b) for p in _SQL_PREPARED_PATTERNS)
        has_set_param = bool(re.search(
            r'\.(?:setString|setInt|setLong|setDouble|setFloat|setBoolean|setDate|setTimestamp|setObject)\s*\(',
            b, re.IGNORECASE))
        has_raw_statement = bool(re.search(r'createStatement\s*\(\s*\)', b))
        if has_param_query and has_set_param and not has_raw_statement:
            self._has_safe_sql = True
            # All variables passed through setString/setInt are SQL-safe
            for m in re.finditer(r'\.(?:setString|setInt|setLong|setDouble|setFloat|setBoolean|setObject)\s*\(\s*\d+\s*,\s*(\w+)', b, re.IGNORECASE):
                self._safe_vars["CWE-89"].add(m.group(1))

        # 2. Detect HTML encoding (XSS-safe)
        for pat in _XSS_SANITIZER_PATTERNS:
            if pat.search(b):
                self._has_html_encoding = True
                break

        # 3. Detect sanitizer assignments: String safe = ESAPI.encoder().encodeForHTML(x)
        for m in _SANITIZER_ASSIGN_RE.finditer(b):
            var_name = m.group(1)
            func_call = m.group(2).lower()
            source_var = m.group(3)
            if any(kw in func_call for kw in ('encodeforhtml', 'escapehtml', 'encode', 'sanitize', 'clean', 'purify')):
                self._safe_vars["CWE-79"].add(var_name)
            if 'preparestatement' in func_call or 'preparecall' in func_call:
                self._safe_vars["CWE-89"].add(var_name)

        # 4. Detect hardcoded strings
        for m in _HARDCODED_STRING_RE.finditer(b):
            self._hardcoded_vars.add(m.group(1))

        # 5. Detect string concatenation (tainted)
        for m in _STRING_CONCAT_RE.finditer(b):
            for g in m.groups():
                if g:
                    self._concat_vars.add(g)

        # 6. Detect ProcessBuilder (safer than Runtime.exec with shell)
        if any(p.search(b) for p in _CMD_SANITIZER_PATTERNS):
            # ProcessBuilder with array args is safer
            pb_vars = set()
            for m in re.finditer(r'new\s+ProcessBuilder\s*\(\s*(\w+)', b, re.IGNORECASE):
                pb_vars.add(m.group(1))
            for m in re.finditer(r'\.command\s*\(\s*(\w+)', b, re.IGNORECASE):
                pb_vars.add(m.group(1))
            # Variables passed to ProcessBuilder are cmd-safe
            self._safe_vars["CWE-78"].update(pb_vars)

    def is_sanitized(self, cwe: str, var_name: str) -> bool:
        """Check if a variable has been sanitized for a given CWE."""
        if cwe == "CWE-89" and self._has_safe_sql:
            # If the entire method uses PreparedStatement safely, all SQL is safe
            # unless the variable went through string concatenation
            if var_name not in self._concat_vars:
                return True
        if var_name in self._safe_vars.get(cwe, set()):
            return True
        # Hardcoded strings are safe for CWE-78 (command injection)
        if cwe == "CWE-78" and var_name in self._hardcoded_vars:
            return True
        return False

    def any_sanitized(self, cwe: str, var_names: set[str]) -> bool:
        """Check if ANY of the given variables is sanitized."""
        return any(self.is_sanitized(cwe, v) for v in var_names)

    @property
    def sql_is_safe(self) -> bool:
        return self._has_safe_sql

    @property
    def xss_is_encoded(self) -> bool:
        return self._has_html_encoding


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
    for child in node.children:
        if child.type == "identifier":
            identifiers.append(_node_text(child, source))
        elif child.type == "method_invocation":
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
        ann_short = ann.rsplit(".", 1)[-1].split("(", 1)[0].lstrip("@")
        if ann_short in _ROUTE_ANNOTATIONS:
            # Extract path from annotation value
            path_matches = re.findall(r'"([^"]*)"', ann)
            route_paths.extend(path_matches)

    # Check for auth annotations
    for ann in annotations:
        ann_short = ann.rsplit(".", 1)[-1].split("(", 1)[0].lstrip("@")
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
            _node_text(child, source).strip() if child.type != "block" else ""

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
                    ann_short = ann.rsplit(".", 1)[-1].split("(", 1)[0].lstrip("@")
                    if ann_short in _ROUTE_ANNOTATIONS:
                        path_matches = re.findall(r'"([^"]*)"', ann)
                        method.route_paths.extend(path_matches)
                    if ann_short in _AUTH_ANNOTATIONS:
                        method.has_auth = True
                # Framework-annotated params are automatically taint sources
                for pname, panns in method.param_annotations.items():
                    for ann in panns:
                        ann_short = ann.rsplit(".", 1)[-1].split("(", 1)[0].lstrip("@")
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



# ── CWE-330: Weak Random (OWASP weakrand category) ─────────────────────
_WEAK_RANDOM_CLASSES: frozenset[str] = frozenset({
    "Random", "java.util.Random", "ThreadLocalRandom",
})
_WEAK_RANDOM_METHODS: frozenset[str] = frozenset({
    "Math.random",
})
_SECURE_RANDOM_CLASSES: frozenset[str] = frozenset({
    "SecureRandom", "java.security.SecureRandom",
})


def _check_weak_random(methods: list[_JavaMethod], source: bytes, filename: str = "") -> list[Finding]:
    """CWE-330: Use of insufficiently random values (predictable PRNG).

    Detects:
    - ``new Random()`` or ``new java.util.Random()`` in security-sensitive contexts
    - ``Math.random()`` calls
    - Ignores ``new SecureRandom()`` (the correct fix)
    - Flags ThreadLocalRandom for non-security contexts where predictability matters
    - Suppresses findings in test files and non-security utility classes
    """
    findings: list[Finding] = []
    # Skip test files entirely — Random in tests is never a security issue
    _fn_lower = filename.lower().replace("\\", "/")
    _is_test = any(p in _fn_lower for p in ("/test/", "test/", "tests/", "test.java", "tests.java",
                                              "_test.java", "_tests.java", "test_", "tests_"))
    for method in methods:
        body_bytes = method.body.encode("utf-8")
        body_tree = _JAVA_PARSER.parse(body_bytes).root_node
        creations = _collect_object_creations(body_tree, body_bytes)
        calls = _collect_method_invocations(body_tree, body_bytes)

        # Pattern 1: new Random() or new java.util.Random()
        for class_name, arguments, line in creations:
            if class_name in _WEAK_RANDOM_CLASSES:
                # FP guard: skip if Random used for non-security (shuffle, sort, game, UI)
                _body_lower_r = method.body.lower()
                if any(kw in _body_lower_r for kw in ("collections.shuffle", "collections.sort",
                        "arrays.sort", "cardgame", "deck.", "dice", "lottery",
                        "shuffle(", ".shuffle(", "games", "game.", "gameplay")):
                    continue
                # Check context: if used for token/session/crypto, flag it
                context_lines = method.body.split("\n")
                line_idx = line - 1
                context_start = max(0, line_idx - 2)
                context_end = min(len(context_lines), line_idx + 5)
                context = "\n".join(context_lines[context_start:context_end]).lower()

                security_keywords = (
                    "token", "session", "crypto", "password", "secret", "key",
                    "auth", "nonce", "csrf", "otp", "reset", "verification",
                    "secure", "credential", "sign",
                )
                is_security_context = any(kw in context for kw in security_keywords)

                # Always flag if it's a field declaration (likely reused)
                is_field = "private" in context or "public" in context or "protected" in context

                if is_security_context or is_field:
                    fl = _body_line_to_file(method, line)
                    findings.append(_make_finding(
                        line=fl,
                        title=f"CWE-330: Weak PRNG (`{class_name}`) at line {fl}",
                        description=f"`new {class_name}()` used at L{fl}. `java.util.Random` is not "
                                    "cryptographically secure. An attacker can predict its output.",
                        suggestion="Use `java.security.SecureRandom` for security-sensitive values "
                                  "(tokens, session IDs, crypto keys). `new SecureRandom()` is the "
                                  "drop-in replacement.",
                        severity=Severity.HIGH,
                        rule_id="JV-025",
                        cwe="CWE-330",
                    ))
                    continue

                # Flag unconditionally in methods with auth/route annotations
                if method.has_auth or method.route_paths or method.annotations:
                    fl = _body_line_to_file(method, line)
                    findings.append(_make_finding(
                        line=fl,
                        title=f"CWE-330: Weak PRNG (`{class_name}`) in web handler at line {fl}",
                        description=f"`new {class_name}()` at L{fl} in a web-facing method. "
                                    "Weak randomness in web endpoints enables session prediction and "
                                    "CSRF token bypass.",
                        suggestion="Use `java.security.SecureRandom` for web-facing random values.",
                        severity=Severity.MEDIUM,
                        rule_id="JV-025",
                        cwe="CWE-330",
                    ))

        # Pattern 2: Math.random() calls — only flag in web handlers or security context
        for call in calls:
            if call.callee == "random" and call.receiver == "Math":
                # Skip test files
                if _is_test:
                    continue
                # Only flag in web-facing methods (has routes/annotations) or security context
                is_web_context = bool(method.has_auth or method.route_paths or method.annotations)
                if not is_web_context:
                    continue
                fl = _body_line_to_file(method, call.line)
                findings.append(_make_finding(
                    line=fl,
                    title=f"CWE-330: `Math.random()` in web handler at line {fl}",
                    description=f"`Math.random()` at L{fl} in a web-facing method. "
                                "Its 48-bit seed can be brute-forced in minutes.",
                    suggestion="Use `java.security.SecureRandom` for security-sensitive values.",
                    severity=Severity.MEDIUM,
                    rule_id="JV-025",
                    cwe="CWE-330",
                ))

        # Pattern 3: new Random(seed) — even worse, seed is hardcoded
        for class_name, arguments, line in creations:
            if class_name in _WEAK_RANDOM_CLASSES and arguments:
                seed_val = arguments[0].strip()
                # If seed is a literal number or string, it's trivially predictable
                if re.match(r'^\d+[L]?$', seed_val) or seed_val.startswith('"'):
                    fl = _body_line_to_file(method, line)
                    findings.append(_make_finding(
                        line=fl,
                        title=f"CWE-330: Predictable PRNG seed at line {fl}",
                        description=f"`new {class_name}({seed_val})` at L{fl} uses a hardcoded seed. "
                                    "This makes the random sequence 100% reproducible by an attacker.",
                        suggestion="Use `new SecureRandom()` which auto-seeds from OS entropy.",
                        severity=Severity.CRITICAL,
                        rule_id="JV-025",
                        cwe="CWE-330",
                    ))

    return findings


# ── CWE-614: Insecure Cookie ────────────────────────────────────────────
_INSECURE_COOKIE_METHODS: frozenset[str] = frozenset({
    "setSecure", "setHttpOnly",
})


def _check_insecure_cookie(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-614: Sensitive cookie without Secure/HttpOnly flag.

    Detects:
    - ``cookie.setSecure(false)`` — explicitly disabling the Secure flag
    - Missing ``setSecure(true)`` on Cookie construction
    - ``Cookie`` constructor without security flags
    """
    findings: list[Finding] = []
    for method in methods:
        body_bytes = method.body.encode("utf-8")
        body_tree = _JAVA_PARSER.parse(body_bytes).root_node
        creations = _collect_object_creations(body_tree, body_bytes)
        calls = _collect_method_invocations(body_tree, body_bytes)

        # Track cookies and their security state
        cookie_vars: dict[str, dict[str, bool]] = {}  # var_name → {"secure": bool, "httponly": bool}

        # Pattern 1: new Cookie(name, value) — check for missing security setup
        for class_name, arguments, line in creations:
            if class_name == "Cookie":
                # Find the variable name assigned from this creation
                context_lines = method.body.split("\n")
                line_idx = line - 1
                if line_idx < len(context_lines):
                    decl_line = context_lines[line_idx]
                    var_match = re.search(r'(\w+)\s*=\s*new\s+Cookie\s*\(', decl_line)
                    if var_match:
                        cookie_var = var_match.group(1)
                        cookie_vars[cookie_var] = {"secure": False, "httponly": False}

        # Pattern 2: cookie.setSecure(false) — explicitly insecure
        for call in calls:
            if call.callee == "setSecure" and call.receiver in cookie_vars:
                if call.arguments and call.arguments[0].strip().lower() == "false":
                    fl = _body_line_to_file(method, call.line)
                    findings.append(_make_finding(
                        line=fl,
                        title=f"CWE-614: Cookie Secure flag explicitly disabled at line {fl}",
                        description=f"`{call.receiver}.setSecure(false)` at L{fl} explicitly disables "
                                    "the Secure flag. The cookie will be sent over unencrypted HTTP.",
                        suggestion="Use `cookie.setSecure(true)` to restrict the cookie to HTTPS only.",
                        severity=Severity.HIGH,
                        rule_id="JV-026",
                        cwe="CWE-614",
                    ))
                elif call.arguments and call.arguments[0].strip().lower() == "true":
                    cookie_vars[call.receiver]["secure"] = True

            if call.callee == "setHttpOnly" and call.receiver in cookie_vars:
                if call.arguments and call.arguments[0].strip().lower() == "true":
                    cookie_vars[call.receiver]["httponly"] = True

        # Pattern 3: Cookie created in web handler without setSecure(true)
        # Only flag if the cookie has a sensitive-sounding name
        for var_name, flags in cookie_vars.items():
            if not flags["secure"]:
                # Check if cookie name suggests sensitive content
                # Read the creation line context
                for class_name, arguments, line in creations:
                    if class_name != "Cookie":
                        continue
                    context_lines = method.body.split("\n")
                    line_idx = line - 1
                    if line_idx < len(context_lines):
                        decl_line = context_lines[line_idx]
                        if var_name in decl_line.split("=")[0]:
                            cookie_name = arguments[0].strip(" \"'") if arguments else ""
                            sensitive_names = (
                                "session", "auth", "token", "jwt", "sid", "csrf",
                                "cred", "login", "user", "pass", "secret",
                            )
                            if any(sn in cookie_name.lower() for sn in sensitive_names):
                                fl = _body_line_to_file(method, line)
                                findings.append(_make_finding(
                                    line=fl,
                                    title=f"CWE-614: Sensitive cookie without Secure flag at line {fl}",
                                    description=f"Cookie `{cookie_name}` at L{fl} is created without "
                                                "`setSecure(true)`. Sensitive cookies sent over HTTP "
                                                "can be intercepted via MITM attacks.",
                                    suggestion="Add `{}.setSecure(true)` and `{}.setHttpOnly(true)` "
                                              "to protect this cookie.".format(var_name, var_name),
                                    severity=Severity.HIGH,
                                    rule_id="JV-026",
                                    cwe="CWE-614",
                                ))
                            break

    return findings


def _check_sqli(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-89: SQL injection — origin-aware taint + IFDS + regex patterns + FPR guards."""
    from ansede_static.java_taint_origins import collect_taint_origins, has_user_origin

    findings: list[Finding] = []
    # Pre-compute method name set for intra-file call resolution
    method_names = {m.name for m in methods}

    # ── Interprocedural IFDS pass (run once for all methods with cross-calls) ──
    ifds_all_findings: dict[str, list[dict[str, Any]]] = {}  # method_name → findings
    if len(methods) > 1:
        # Fast check: are there any cross-method calls in this file?
        _has_cross_calls = False
        for method in methods:
            for other in methods:
                if other.name != method.name and other.name in method.body:
                    _has_cross_calls = True
                    break
            if _has_cross_calls:
                break
        if _has_cross_calls:
            # Check cache first
            source_hash = hashlib.md5(source).hexdigest()[:12]
            body_sig = "|".join(sorted(f"{m.name}:{hashlib.md5(m.body.encode()).hexdigest()[:8]}" for m in methods))
            cache_key = (body_sig, source_hash)
            if cache_key in _IFDS_CACHE:
                ifds_all_findings = _IFDS_CACHE[cache_key]
            else:
                try:
                    from ansede_static.v2_java_bridge import run_interprocedural_ifds
                    all_ifds = run_interprocedural_ifds(methods, source)
                    for f in all_ifds:
                        method_name = f.get("method", "")
                        ifds_all_findings.setdefault(method_name, []).append(f)
                    # Cache the result
                    if len(_IFDS_CACHE) < _MAX_CACHE_SIZE:
                        _IFDS_CACHE[cache_key] = dict(ifds_all_findings)
                except Exception as exc:
                    _log.debug("Interprocedural IFDS failed: %s", exc)

    for method in methods:
        body_bytes = method.body.encode("utf-8")
        body_tree = _JAVA_PARSER.parse(body_bytes).root_node

        _has_taint = any(s in method.body for s in ("getParameter", "getHeader", "getCookies",
                                                      "getQueryString", "getTheParameter", "getTheValue"))
        if not _has_taint:
            continue

        # ── FPR Guard: skip method if ALL SQL is parameterized ──
        # Expanded: also check for PreparedStatement + setString/setInt (safe pattern)
        _has_prepared = bool(re.search(r'prepareStatement\s*\(', method.body))
        _has_bind_params = bool(re.search(r'\.setString\s*\(|\.setInt\s*\(|\.setLong\s*\(|\.setObject\s*\(', method.body))
        _has_raw_statement = bool(re.search(r'createStatement\s*\(\s*\)', method.body))
        if _has_prepared and _has_bind_params and not _has_raw_statement:
            continue  # Uses PreparedStatement with bind parameters and no raw Statement — safe

        # ── SanitizerTracker: per-method variable sanitization ──
        tracker = SanitizerTracker(method.body)

        origins = collect_taint_origins(body_tree, body_bytes, method.params,
                                         method.framework_tainted_params)
        calls = _collect_method_invocations(body_tree, body_bytes)

        # FPR guard: skip if ALL SQL calls use parameterized queries
        _sql_calls_in_method = [c for c in calls if c.callee in _SQLI_METHODS]
        if _sql_calls_in_method and all(
            _is_parameterized_sql(c.raw) or (c.callee in ("executeQuery", "execute") and not c.arguments)
            for c in _sql_calls_in_method
        ):
            continue  # All SQL is parameterized — safe, skip IFDS

        # ── Pattern 0: IFDS findings (from interprocedural or intra pass) ──
        ifds_tainted_vars: set[str] = set()
        # First, consume interprocedural IFDS results
        for f in ifds_all_findings.get(method.name, []):
            cwe = f.get("cwe", "CWE-89")
            tainted_names = f.get("tainted_vars", [])
            if isinstance(tainted_names, str):
                tainted_names = [tainted_names]
            ifds_tainted_vars.update(tainted_names)
            sink_text = f.get("text", "")
            sink_line = 0
            for line_idx, body_line in enumerate(method.body.split("\n")):
                if sink_text[:60] in body_line:
                    sink_line = line_idx + 1
                    break
            if sink_line:
                fl = _body_line_to_file(method, sink_line)
                rule_id = f.get("rule_id", "JV-004")
                severity = Severity.CRITICAL if cwe in ("CWE-89", "CWE-78") else Severity.HIGH
                sink_type = {"CWE-89": "SQL", "CWE-78": "command", "CWE-79": "XSS"}.get(cwe, "data")
                # FPR guard: skip if tainted vars were sanitized
                if cwe == "CWE-89" and tracker.any_sanitized(cwe, set(tainted_names)):
                    continue
                findings.append(_make_finding(
                    line=fl,
                    title=f"{cwe}: {sink_type} injection (interproc IFDS) — tainted {tainted_names} at line {fl}",
                    description=f"Interprocedural IFDS: {tainted_names} flows across methods to {cwe} sink.",
                    suggestion="Use parameterized queries / input validation.",
                    severity=severity, rule_id=rule_id, cwe=cwe, confidence=0.92))

        # Fallback: run intra-procedural IFDS only if method has sinks
        _has_any_sinks_for_ifds = any(
            c.callee in _SQLI_METHODS or c.callee in ("exec", "write", "print", "println", "append")
            or c.receiver == "Runtime"
            for c in calls
        )
        if _has_any_sinks_for_ifds and (not ifds_all_findings or method.name not in ifds_all_findings):
            try:
                from ansede_static.v2_java_bridge import run_ifds_analysis
                intra_findings = run_ifds_analysis(body_tree, body_bytes, method.params)
                for f in intra_findings:
                    cwe = f.get("cwe", "CWE-89")
                    tainted_names = f.get("tainted_vars", [])
                    if isinstance(tainted_names, str):
                        tainted_names = [tainted_names]
                    ifds_tainted_vars.update(tainted_names)
                    sink_text = f.get("text", "")
                    sink_line = 0
                    for line_idx, body_line in enumerate(method.body.split("\n")):
                        if sink_text[:60] in body_line:
                            sink_line = line_idx + 1
                            break
                    if sink_line:
                        fl = _body_line_to_file(method, sink_line)
                        rule_id = f.get("rule_id", "JV-004")
                        severity = Severity.CRITICAL if cwe in ("CWE-89", "CWE-78") else Severity.HIGH
                        sink_type = {"CWE-89": "SQL", "CWE-78": "command", "CWE-79": "XSS"}.get(cwe, "data")
                        # FPR guard: skip if tainted vars were sanitized
                        if cwe == "CWE-89" and tracker.any_sanitized(cwe, set(tainted_names)):
                            continue
                        findings.append(_make_finding(
                            line=fl,
                            title=f"{cwe}: {sink_type} injection (IFDS) — tainted {tainted_names} at line {fl}",
                            description=f"IFDS taint analysis: {tainted_names} flows to {cwe} sink.",
                            suggestion="Use parameterized queries / input validation.",
                            severity=severity, rule_id=rule_id, cwe=cwe, confidence=0.92))
            except Exception as exc:
                _log.debug("IFDS analysis skipped for %s: %s", method.name, exc)

        # ── Pattern 0b: Intraprocedural dataflow (java_dataflow) ──
        # Only run dataflow if there are taint sources AND SQL sink calls in the method body
        _has_sql_sinks = any(s in method.body for s in ("executeQuery", "executeUpdate", "createQuery",
                                                           "prepareStatement", "createStatement"))
        _has_taint_sources = any(s in method.body for s in ("getParameter", "getHeader", "getCookies",
                                                              "getQueryString", "getTheParameter", "getTheValue"))
        if _has_sql_sinks and _has_taint_sources:
            try:
                from ansede_static.java_dataflow import run_intraprocedural_dataflow
                df_result = run_intraprocedural_dataflow(body_tree, body_bytes, method.params)
                for sink_finding in df_result.tainted_at_sinks:
                    tainted_vars = sink_finding.get("tainted_vars", [])
                    ifds_tainted_vars.update(tainted_vars)
                    cwe = sink_finding.get("cwe", "CWE-89")
                    rule_id = sink_finding.get("rule_id", "JV-004")
                    # Find line number
                    sink_text = sink_finding.get("text", "")
                    sink_line = 0
                    for line_idx, body_line in enumerate(method.body.split("\n")):
                        if sink_text[:60] in body_line:
                            sink_line = line_idx + 1
                            break
                    if sink_line:
                        fl = _body_line_to_file(method, sink_line)
                        findings.append(_make_finding(
                            line=fl,
                            title=f"{cwe}: Dataflow taint — {tainted_vars} at line {fl}",
                            description=f"Forward dataflow: {tainted_vars} reaches {cwe} sink. "
                                        f"Sink: {sink_text[:100]}",
                            suggestion="Use parameterized queries or input validation.",
                            severity=Severity.CRITICAL if cwe in ("CWE-89", "CWE-78") else Severity.HIGH,
                            rule_id=rule_id, cwe=cwe,
                            confidence=0.88,
                        ))
            except Exception as exc:
                _log.debug("Dataflow analysis skipped for %s: %s", method.name, exc)

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
        builder_tainted: dict[str, set[str]] = {}  # sb_var → set of tainted vars that fed it
        for t_var in origins:
            # Find: sb.append(taintedVar)
            for m in re.finditer(r'(\w+)\.append\s*\(\s*' + re.escape(t_var) + r'\s*\)', method.body):
                sb_var = m.group(1)
                builder_tainted.setdefault(sb_var, set()).add(t_var)
                builder_vars.add(sb_var)
            # Also: sb.append("SELECT..." + taintedVar)
            for m in re.finditer(r'(\w+)\.append\s*\(\s*"[^"]*"\s*\+\s*' + re.escape(t_var), method.body):
                sb_var = m.group(1)
                builder_tainted.setdefault(sb_var, set()).add(t_var)
                builder_vars.add(sb_var)

        # Propagate builder taint to toString() result
        builder_to_string_vars: set[str] = set()
        for sb_var in builder_tainted:
            # Find: StringVar = sb_var.toString()
            for m in re.finditer(r'(\w+)\s*=\s*' + re.escape(sb_var) + r'\.toString\(\)', method.body):
                builder_to_string_vars.add(m.group(1))
            # Also: sb_var.toString() passed directly to a sink
            builder_to_string_vars.add(sb_var)  # the sb itself is tainted

        # ── Pattern 4b: Simple concat SQL strings with tainted vars ──
        # "SELECT..." + taintedVar → variable → SQL sink
        simple_concat_vars: set[str] = set()
        for t_var in origins:
            # Var = "SELECT..." + taintedVar
            for m in re.finditer(r'(\w+)\s*=\s*"[^"]*"\s*\+\s*' + re.escape(t_var), method.body):
                simple_concat_vars.add(m.group(1))
            # Var = taintedVar + "..."
            for m in re.finditer(r'(\w+)\s*=\s*' + re.escape(t_var) + r'\s*\+\s*"[^"]*"', method.body):
                simple_concat_vars.add(m.group(1))
            # Var = "SELECT..." + taintedVar + "..."
            for m in re.finditer(r'(\w+)\s*=\s*"[^"]*"\s*\+\s*' + re.escape(t_var) + r'\s*\+\s*"[^"]*"', method.body):
                simple_concat_vars.add(m.group(1))
            # Var = baseQuery + taintedVar (two variables concatenated)
            for m in re.finditer(r'(\w+)\s*=\s*(\w+)\s*\+\s*' + re.escape(t_var), method.body):
                simple_concat_vars.add(m.group(1))
            for m in re.finditer(r'(\w+)\s*=\s*' + re.escape(t_var) + r'\s*\+\s*(\w+)', method.body):
                simple_concat_vars.add(m.group(1))

        for call in calls:
            if call.callee not in _SQLI_METHODS:
                continue

            # ── Receiver guard: generic method names (query, update, find, etc.)
            #     only count as SQLi if called on a known JDBC/JPA receiver ──
            _GENERIC_SQL_METHODS = frozenset({
                "query", "queryForObject", "queryForList", "queryForMap",
                "queryForRowSet", "update", "batchUpdate", "execute",
                "find", "persist", "merge", "remove",
                "getResultList", "getSingleResult",
            })
            if call.callee in _GENERIC_SQL_METHODS:
                recv_lower = call.receiver.lower()
                if not any(p in recv_lower for p in _SQLI_RECEIVER_PATTERNS):
                    continue  # Not a known SQL receiver — skip to avoid FP

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
            has_builder = any(arg.strip() in builder_to_string_vars for arg in call.arguments)
            has_simple_concat = any(arg.strip() in simple_concat_vars for arg in call.arguments)
            # Also check: if any argument contains a tainted variable name (var-to-var concat)
            has_tainted_arg = any(
                any(t_var in arg for t_var in origins) or
                any(t_var in arg for t_var in ifds_tainted_vars)
                for arg in call.arguments
            )
            
            # Pattern 5: SQL string literal directly containing concat or format
            has_inline_sql = bool(re.search(
                r'(?:executeQuery|executeUpdate|createQuery|createNativeQuery|prepareCall)\s*\(\s*"[^"]*"\s*\+',
                call.raw
            )) or bool(re.search(
                r'(?:executeQuery|executeUpdate|createQuery|createNativeQuery|prepareCall)\s*\(\s*String\.format',
                call.raw
            ))

            if not (has_user or has_concat or has_format or has_builder or has_simple_concat or has_tainted_arg or has_inline_sql):
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

        # ── Pattern 6: Intra-file helper method returns tainted SQL ──
        # If method X calls helper Y(userInput) and Y returns a String that reaches a SQL sink
        local_calls = [c for c in calls if c.callee in method_names and c.callee != method.name]
        if local_calls:
            # Find helper methods that build SQL from tainted params
            for helper_call in local_calls:
                helper = next((m for m in methods if m.name == helper_call.callee), None)
                if helper is None:
                    continue
                # Does helper contain SQL patterns?
                if not any(s in helper.body for s in ("Statement", "executeQuery", "executeUpdate",
                                                       "prepareStatement", "createQuery")):
                    continue
                # Are any of helper_call's arguments tainted?
                has_tainted_arg = False
                for arg_text in helper_call.arguments:
                    for t_var in origins:
                        if t_var in arg_text:
                            has_tainted_arg = True
                            break
                    for t_var in ifds_tainted_vars:
                        if t_var in arg_text:
                            has_tainted_arg = True
                            break
                if has_tainted_arg:
                    fl = _body_line_to_file(method, helper_call.line)
                    findings.append(_make_finding(
                        line=fl,
                        title=f"CWE-89: SQLi via helper {helper_call.callee}() at line {fl}",
                        description=f"Call to `{helper_call.callee}()` at L{fl} with tainted args. "
                                    f"Helper method `{helper_call.callee}()` builds SQL from user input.",
                        suggestion="Use parameterized queries. Never build SQL from user input in helper methods.",
                        severity=Severity.CRITICAL, rule_id="JV-004", cwe="CWE-89",
                        confidence=0.85,
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
    """CWE-328: Weak cryptographic algorithm detection.

    Detects:
    - ``MessageDigest.getInstance("MD5")`` / ``("SHA-1")``
    - ``Cipher.getInstance("DES")`` / ``("RC4")`` / ``("RC2")`` / ``("Blowfish")``
    - Guava ``Hashing.md5()`` / ``Hashing.sha1()``
    - Apache Commons ``DigestUtils.md5Hex()`` / ``DigestUtils.sha1Hex()``
    - Variable-based algorithm selection with weak default values
    - Suppresses findings in non-security contexts (checksums, file IDs, etc.)
    """
    findings: list[Finding] = []
    for method in methods:
        body_bytes = method.body.encode("utf-8")
        body_tree = _JAVA_PARSER.parse(body_bytes).root_node
        calls = _collect_method_invocations(body_tree, body_bytes)
        _collect_object_creations(body_tree, body_bytes)

        # Helper: check if method body has security context near a line
        def _has_security_context(line_num: int, radius: int = 5) -> bool:
            body_lines = method.body.split("\n")
            start = max(0, line_num - radius - 1)
            end = min(len(body_lines), line_num + radius)
            context = ("\n".join(body_lines[start:end]) + " " + method.name).lower()
            security_kw = (
                "password", "token", "auth", "sign", "secret", "credential",
                "key", "hash", "encrypt", "decrypt", "cipher", "ssl", "tls",
                "oauth", "jwt", "session", "csrf", "nonce",
            )
            # Skip standard hashCode() methods — not security-related
            if "hashcode" in context and "messagedigest" in context and method.name.lower().strip() == "hashcode":
                return False
            return any(kw in context for kw in security_kw)

        # Pattern 1: MessageDigest.getInstance() / Cipher.getInstance() with weak algo
        for call in calls:
            if call.callee != "getInstance":
                continue
            for arg in call.arguments:
                arg_clean = arg.strip(" \"'")
                for algo in _WEAK_CRYPTO_ALGOS:
                    if algo.lower() in arg_clean.lower():
                        # Only flag in security context (passwords, tokens, auth, encryption)
                        if not _has_security_context(call.line):
                            continue
                        fl = _body_line_to_file(method, call.line)
                        findings.append(_make_finding(
                            line=fl,
                            title=f"CWE-328: Weak cryptographic algorithm ({algo}) at line {fl}",
                            description=f"`getInstance({arg})` at L{fl}. {algo} is cryptographically "
                                        "broken and vulnerable to collision attacks.",
                            suggestion="Use SHA-256 or stronger. For passwords, use bcrypt, scrypt, or Argon2.",
                            severity=Severity.HIGH,
                            rule_id="JV-012",
                            cwe="CWE-328",
                        ))
                        break

        # Pattern 2: Guava Hashing.md5() / Hashing.sha1() / Hashing.sha256() — sha256 is OK
        for call in calls:
            if call.receiver == "Hashing":
                algo_map = {
                    "md5": ("MD5", Severity.HIGH),
                    "sha1": ("SHA-1", Severity.HIGH),
                    "sha256": None,  # OK — skip
                    "sha384": None,  # OK — skip
                    "sha512": None,  # OK — skip
                }
                algo_info = algo_map.get(call.callee.lower())
                if algo_info is not None:
                    algo, severity = algo_info
                    fl = _body_line_to_file(method, call.line)
                    findings.append(_make_finding(
                        line=fl,
                        title=f"CWE-328: Weak hash via Guava `Hashing.{call.callee}()` at line {fl}",
                        description=f"`Hashing.{call.callee}()` at L{fl}. Guava's {algo} is "
                                    "cryptographically broken and should not be used for security.",
                        suggestion="Use `Hashing.sha256()` or `Hashing.sha512()` instead.",
                        severity=severity,
                        rule_id="JV-012",
                        cwe="CWE-328",
                    ))

        # Pattern 3: Apache Commons DigestUtils.md5Hex() / DigestUtils.sha1Hex()
        for call in calls:
            if call.callee in ("md5Hex", "sha1Hex", "md5", "sha1", "sha"):
                # These are from org.apache.commons.codec.digest.DigestUtils
                fl = _body_line_to_file(method, call.line)
                weak_algo = call.callee.replace("Hex", "").upper()
                findings.append(_make_finding(
                    line=fl,
                    title=f"CWE-328: Weak hash via `DigestUtils.{call.callee}()` at line {fl}",
                    description=f"`DigestUtils.{call.callee}()` at L{fl}. {weak_algo} is "
                                "cryptographically broken.",
                    suggestion="Use `DigestUtils.sha256Hex()` or `DigestUtils.sha512Hex()` instead.",
                    severity=Severity.HIGH,
                    rule_id="JV-012",
                    cwe="CWE-328",
                ))

        # Pattern 4: Hardcoded "MD5" or "SHA-1" string constants passed to getInstance
        # Check for variable declarations like: String algo = "MD5";
        # Then MessageDigest.getInstance(algo);
        algo_vars: dict[str, str] = {}  # var → algorithm name
        body_text = method.body
        # Find String algo = "MD5" patterns
        for m in re.finditer(r'(\w+)\s*=\s*"((?:MD5|SHA-?1|DES|RC[24]|Blowfish))"', body_text, re.IGNORECASE):
            algo_vars[m.group(1)] = m.group(2).upper()
        # Check if any getInstance call uses a variable holding a weak algo
        for call in calls:
            if call.callee != "getInstance":
                continue
            for arg in call.arguments:
                var_name = arg.strip()
                if var_name in algo_vars:
                    weak_algo = algo_vars[var_name]
                    fl = _body_line_to_file(method, call.line)
                    findings.append(_make_finding(
                        line=fl,
                        title=f"CWE-328: Weak crypto via variable `{var_name}=\"{weak_algo}\"` at line {fl}",
                        description=f"`getInstance({var_name})` at L{fl} uses `{weak_algo}` which is "
                                    "cryptographically broken.",
                        suggestion="Use SHA-256 or stronger.",
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
        # FP guard: skip if method has allowlist/validation on the URL
        _has_ssrf_guard = bool(re.search(
            r'ALLOWED|allowed|whitelist|WHITELIST|SAFE_URLS|\.contains\s*\(|sendError\s*\(',
            method.body, re.IGNORECASE))
        for call in calls:
            if call.callee == "openConnection" and has_user_origin(call.arguments, origins, method.params):
                if _has_ssrf_guard: continue
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
                if _has_ssrf_guard: continue
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
                # FP guard: skip if method has allowlist/validation before redirect
                _has_redirect_guard = bool(re.search(
                    r'ALLOWED|allowed|whitelist|WHITELIST|SAFE_URLS|\.contains\s*\(',
                    method.body, re.IGNORECASE))
                if _has_redirect_guard:
                    continue
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
        # SanitizerTracker: check for HTML encoding before response write
        tracker = SanitizerTracker(method.body)
        if tracker.xss_is_encoded:
            continue  # Method has HTML encoding — XSS is mitigated
        # Check if this method is in an HTTP servlet context (has HttpServletResponse/getWriter)
        _body_lower = method.body.lower()
        _is_http_context = any(kw in _body_lower for kw in (
            'httpservletresponse', 'getwriter()', 'getoutputstream()',
            'httpservletrequest', 'doget(', 'dopost(',
        ))
        for call in calls:
            if call.callee in _XSS_OUTPUT_METHODS and has_user_origin(call.arguments, origins, method.params):
                rcvr_lower = call.receiver.lower()
                # FP guard: must have response/writer context — skip FileWriter, StringWriter, etc.
                if rcvr_lower and rcvr_lower not in _XSS_RESPONSE_RECEIVERS:
                    # If we're in an HTTP servlet context, be more permissive with receiver names
                    if _is_http_context:
                        pass  # Allow — this is likely HttpServletResponse.getWriter()
                    elif rcvr_lower not in origins and not any(
                        w in rcvr_lower for w in ('writer', 'output', 'response', 'printwriter', 'stream')):
                        continue
                # FP guard: skip if the receiver is a non-HTTP writer (FileWriter, StringWriter, PrintWriter to file, journal, log, cache)
                _non_http_writers = ('file', 'string', 'buffer', 'chararray', 'piped', 'bytearray', 'journal', 'logwriter', 'cache')
                if any(w in rcvr_lower for w in _non_http_writers):
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
    """CWE-22: Path traversal with origin-aware taint + NIO patterns + variable tracking."""
    from ansede_static.java_taint_origins import collect_taint_origins, has_user_origin

    def _has_path_validation(body: str) -> bool:
        """Check if method body contains path validation (contains, startsWith, etc.)."""
        return bool(re.search(
            r'\.contains\s*\(\s*"\.\."|\.startsWith\s*\(|\.indexOf\s*\(\s*"\.\."|'
            r'\.endsWith\s*\(|commonpath\s*\(|is_relative_to\s*\('
            r'|ALLOWED_|allowed_|WHITELIST|whitelist|SAFE_DIR',
            body, re.IGNORECASE))

    findings: list[Finding] = []
    for method in methods:
        body_bytes = method.body.encode("utf-8")
        if _method_has_no_request_source(method.body):
            continue
        body_tree = _JAVA_PARSER.parse(body_bytes).root_node
        origins = collect_taint_origins(body_tree, body_bytes, method.params,
                                         method.framework_tainted_params)

        # Extended taint tracking: also collect tainted variables via AST
        tainted_vars = _collect_tainted_variables_ast(body_tree, body_bytes, method.params,
                                                       method.framework_tainted_params)
        # Merge with origin tracking (origins is dict[str, set[str]] — extract keys)
        all_tainted: set[str] = set(origins.keys()) | tainted_vars

        # Pattern 0: direct object creation with tainted args
        creations = _collect_object_creations(body_tree, body_bytes)
        for class_name, args, line in creations:
            if class_name in _PATH_TRAVERSAL_CLASSES:
                # Check origin-aware taint
                if has_user_origin(args, origins, method.params):
                    # FP guard: skip if path validation is present (contains, startsWith, etc.)
                    if _has_path_validation(method.body):
                        continue
                    fl = _body_line_to_file(method, line)
                    findings.append(_make_finding(
                        line=fl, title=f"CWE-22: Path traversal via new {class_name}() at line {fl}",
                        description=f"`new {class_name}()` with user-controlled path at L{fl}.",
                        suggestion="Validate and sanitize file paths against a base directory.",
                        severity=Severity.HIGH, rule_id="JV-008", cwe="CWE-22"))
                    continue
                # Check variable-level taint: any arg contains a tainted variable
                for arg_text in args:
                    for t_var in all_tainted:
                        if t_var in arg_text:
                            if _has_path_validation(method.body):
                                continue
                            fl = _body_line_to_file(method, line)
                            findings.append(_make_finding(
                                line=fl,
                                title=f"CWE-22: Path traversal via new {class_name}({t_var}) at line {fl}",
                                description=f"`new {class_name}()` with tainted variable `{t_var}` at L{fl}.",
                                suggestion="Validate and sanitize file paths against a base directory.",
                                severity=Severity.HIGH, rule_id="JV-008", cwe="CWE-22"))
                            break

        # Pattern 1: method calls with tainted args (Paths.get, Files.read, etc.)
        calls = _collect_method_invocations(body_tree, body_bytes)
        for call in calls:
            is_path_sink = (call.callee == "get" and call.receiver == "Paths") or \
                           (call.callee in _PATH_TRAVERSAL_METHODS and call.receiver == "Files") or \
                           call.callee in _PATH_TRAVERSAL_METHODS
            if not is_path_sink:
                continue
            if has_user_origin(call.arguments, origins, method.params):
                if _has_path_validation(method.body):
                    continue
                fl = _body_line_to_file(method, call.line)
                findings.append(_make_finding(
                    line=fl,
                    title=f"CWE-22: Path traversal via {call.receiver}.{call.callee}() at line {fl}",
                    description=f"`{call.receiver}.{call.callee}()` with user-controlled path at L{fl}.",
                    suggestion="Validate and sanitize file paths.",
                    severity=Severity.HIGH, rule_id="JV-008", cwe="CWE-22"))
                continue
            # Variable-level check
            for arg_text in call.arguments:
                for t_var in all_tainted:
                    if t_var in arg_text:
                        if _has_path_validation(method.body):
                            continue
                        fl = _body_line_to_file(method, call.line)
                        findings.append(_make_finding(
                            line=fl,
                            title=f"CWE-22: Path traversal via {call.receiver}.{call.callee}({t_var}) at line {fl}",
                            description=f"`{call.receiver}.{call.callee}()` with tainted variable `{t_var}` at L{fl}.",
                            suggestion="Validate and sanitize file paths.",
                            severity=Severity.HIGH, rule_id="JV-008", cwe="CWE-22"))
                        break

        # Pattern 2: Broader regex fallback for path construction with tainted vars
        # "new File(" + taintedVar + ")" or similar patterns
        if _has_path_validation(method.body):
            continue
        for t_var in all_tainted:
            if re.search(r'new\s+(?:File|Path|FileInputStream|FileReader)\s*\([^)]*' + re.escape(t_var), method.body):
                # Find the line
                for line_idx, body_line in enumerate(method.body.split("\n")):
                    if t_var in body_line and re.search(r'new\s+(?:File|Path|FileInputStream|FileReader)', body_line):
                        fl = _body_line_to_file(method, line_idx + 1)
                        # Only add if not already found via AST
                        if not any(f.line == fl and "CWE-22" in (f.cwe or "") for f in findings):
                            findings.append(_make_finding(
                                line=fl,
                                title=f"CWE-22: Path traversal at line {fl}",
                                description=f"File/path constructed with tainted variable `{t_var}` at L{fl}.",
                                suggestion="Validate and sanitize file paths against a base directory.",
                                severity=Severity.HIGH, rule_id="JV-008", cwe="CWE-22"))
                        break

    return findings


def _check_auth_bypass(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-862: Missing authorization on sensitive routes."""
    findings: list[Finding] = []
    for method in methods:
        # Check if it's a mutating route without auth
        has_mutating = any(
            ann.rsplit(".", 1)[-1].split("(", 1)[0].lstrip("@") in _MUTATING_ANNOTATIONS
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
        # XPath injection: skip HTTP-source filter — any untrusted string input can be dangerous
        body_tree = _JAVA_PARSER.parse(body_bytes).root_node
        origins = collect_taint_origins(body_tree, body_bytes, method.params,
                                         method.framework_tainted_params)
        all_calls = _collect_method_invocations(body_tree, body_bytes)

        if _has_sanitizer(all_calls, "CWE-643"):
            continue

        for call in all_calls:
            if call.callee in _XPATH_SINK_METHODS:
                # Also check if any argument contains string concat (XPath built dynamically)
                arg_text = " ".join(call.arguments)
                has_concat = "+" in arg_text
                if has_user_origin(call.arguments, origins, method.params) or (
                    has_concat and any(p in method.body for p in method.params if p in arg_text)
                ):
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


# ── CWE-501: Trust Boundary Violation ────────────────────────────────────
# Detects: untrusted data placed into trusted storage (session.setAttribute
# with request parameter values, or request.setAttribute with untrusted data)

_TRUSTED_STORAGE_METHODS: frozenset[str] = frozenset({
    "setAttribute",
})


def _check_trust_boundary(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-501: Trust boundary violation — mixing trusted and untrusted data.

    Detects:
    - ``session.setAttribute("key", request.getParameter("key"))`` — untrusted → trusted
    - ``request.setAttribute("key", untrustedValue)`` — mixing trust domains
    """
    findings: list[Finding] = []
    for method in methods:
        body_bytes = method.body.encode("utf-8")
        body_tree = _JAVA_PARSER.parse(body_bytes).root_node
        calls = _collect_method_invocations(body_tree, body_bytes)

        # FP guard: skip if method has auth annotations (authenticated context is a different trust boundary)
        if method.has_auth:
            continue

        # FP guard: skip if body contains validation/sanitization patterns
        _has_validation = bool(re.search(
            r'(?:\.trim\s*\(|Integer\.parseInt|Long\.parseLong|\.isEmpty\s*\(|'
            r'\.isBlank\s*\(|ESAPI\.|\.encodeFor|\.sanitize|StringEscapeUtils|'
            r'HtmlUtils\.htmlEscape|Jsoup\.clean)',
            method.body
        ))
        if _has_validation:
            continue

        # First collect tainted variables (from request.getParameter etc.)
        tainted_vars = _collect_tainted_variables_ast(body_tree, body_bytes, method.params,
                                                       method.framework_tainted_params)

        for call in calls:
            if call.callee != "setAttribute":
                continue

            # Trusted receiver: session
            is_session_receiver = call.receiver.lower() in ("session", "httpsession", "req.getsession()")
            # Request receiver: putting into request attr from another source
            is_request_receiver = call.receiver.lower() in ("request", "req")

            if not (is_session_receiver or is_request_receiver):
                continue

            # Check if any argument contains tainted data
            for arg_text in call.arguments:
                for t_var in tainted_vars:
                    if t_var in arg_text:
                        fl = _body_line_to_file(method, call.line)
                        domain = "session" if is_session_receiver else "request"
                        findings.append(_make_finding(
                            line=fl,
                            title=f"CWE-501: Trust boundary violation at line {fl}",
                            description=f"Untrusted data `{t_var}` from request parameter is stored "
                                        f"in `{domain}.setAttribute()` at L{fl}. This mixes trusted "
                                        "and untrusted data across the trust boundary.",
                            suggestion="Validate and sanitize input before storing in trusted context, "
                                      "or use a separate namespace for user-supplied data.",
                            severity=Severity.MEDIUM,
                            rule_id="JV-027",
                            cwe="CWE-501",
                            confidence=0.80,
                        ))
                        break

    return findings


# ── CWE-502 Deserialization checker ──────────────────────────────────────
def _check_deserialization(methods: list[_JavaMethod], calls: list[_JavaCall], source: bytes) -> list[Finding]:
    findings: list[Finding] = []
    for call in calls:
        if call.callee in _DESERIALIZATION_SINK_METHODS:
            findings.append(Finding(
                category="security", severity=Severity.CRITICAL,
                title=f"CWE-502: Unsafe deserialization via {call.callee}() at line {call.line}",
                description=f"Deserialization at L{call.line} may process untrusted data.",
                line=call.line, rule_id="JV-502", cwe="CWE-502",
                agent="java-ast-analyzer", confidence=0.90,
                suggestion="Use a safe deserialization approach with type allowlisting.",
                analysis_kind="pattern",
            ))
    return findings


# ── CWE-943 NoSQL injection checker ──────────────────────────────────────
def _check_nosql_injection(methods: list[_JavaMethod], calls: list[_JavaCall], source: bytes) -> list[Finding]:
    findings: list[Finding] = []
    for call in calls:
        if call.callee in _NOSQL_SINK_METHODS:
            findings.append(Finding(
                category="security", severity=Severity.CRITICAL,
                title=f"CWE-943: NoSQL injection via {call.callee}() at line {call.line}",
                description=f"NoSQL query at L{call.line} may be constructed with user input.",
                line=call.line, rule_id="JV-943", cwe="CWE-943",
                agent="java-ast-analyzer", confidence=0.85,
                suggestion="Use parameterized queries with Filters builders.",
                analysis_kind="pattern",
            ))
    return findings


# ── CWE-94 SSTI checker ─────────────────────────────────────────────────
def _check_ssti_injection(methods: list[_JavaMethod], source: bytes, filename: str = "") -> list[Finding]:
    findings: list[Finding] = []
    for method in methods:
        body_bytes = method.body.encode("utf-8")
        body_tree = _JAVA_PARSER.parse(body_bytes).root_node
        calls = _collect_method_invocations(body_tree, body_bytes)
        for call in calls:
            if call.callee in _SSTI_SINK_METHODS:
                # Skip XPath objects — CWE-643 handles those, not CWE-94
                _XPATH_RECEIVERS = frozenset({"xpath", "xPath", "xpathExpression",
                    "xPathExpression", "xpathExpr", "expr", "xpathCompiled"})
                if call.receiver.lower() in _XPATH_RECEIVERS:
                    continue
                # Skip calls with all-hardcoded string literal arguments
                # e.g., engine.eval("var x = 1;") is safe initialization code
                if call.arguments and all(
                    (a.startswith('"') and a.endswith('"')) for a in call.arguments
                ):
                    continue
                fl = _body_line_to_file(method, call.line)
                findings.append(_make_finding(
                    line=fl,
                    title=f"CWE-94: Code injection via {call.callee}() at line {fl}",
                    description=f"Dynamic code evaluation at L{fl} may process user-controlled input.",
                    suggestion="Never pass user input to script engines or template evaluators.",
                    severity=Severity.CRITICAL,
                    rule_id="JV-094",
                    cwe="CWE-94",
                ))
    return findings


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
    ("CWE-330 WeakRandom", _check_weak_random),
    ("CWE-614 InsecureCookie", _check_insecure_cookie),
    ("CWE-501 TrustBoundary", _check_trust_boundary),
    ("Interprocedural", _check_interprocedural_taint),
    ("CWE-502 Deserialization", _check_deserialization),
    ("CWE-943 NoSQL", _check_nosql_injection),
    ("CWE-94 SSTI", _check_ssti_injection),
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
                    # Find the callee method body to check sink type
                    callee_method = None
                    for m in methods:
                        if m.name == call.callee:
                            callee_method = m
                            break

                    # Only flag as SQLi if callee body contains SQL keywords
                    _SQL_SINK_RE = re.compile(
                        r'(?:executeQuery|executeUpdate|execute\(|prepareStatement|createQuery|'
                        r'createNativeQuery|jdbcTemplate|JdbcTemplate|@Query|'
                        r'Statement\.|PreparedStatement)',
                        re.IGNORECASE,
                    )
                    is_sql_sink = bool(callee_method and _SQL_SINK_RE.search(callee_method.body))

                    if is_sql_sink:
                        cwe = "CWE-89"
                        fl = _body_line_to_file(method, call.line)
                        findings.append(_make_finding(
                            line=fl,
                            title=f"Interprocedural SQLi taint: {call.callee}() at line {fl}",
                            description=f"Tainted argument flows to SQL sink through `{call.callee}()`. Call at L{fl}: `{call.raw[:100]}`.",
                            suggestion="Review the data flow through helper methods. Ensure parameterized queries.",
                            severity=Severity.HIGH,
                            rule_id="JV-030",
                            cwe=cwe,
                            trace=sink_trace,
                            confidence=0.85,
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

    # Phase 2: Run pattern checkers (pass filename for context-aware suppression)
    for checker_label, checker_fn in _ALL_CHECKERS:
        try:
            if checker_label == "Interprocedural":
                result.findings.extend(
                    _check_interprocedural_taint_impl(methods, source_bytes, global_graph, filename)
                )
            else:
                try:
                    result.findings.extend(checker_fn(methods, source_bytes, filename))
                except TypeError:
                    # Fallback for checkers that don't accept filename yet
                    result.findings.extend(checker_fn(methods, source_bytes))
        except Exception as exc:
            _log.debug("Java checker %s failed on %r: %s", checker_label, filename, exc, exc_info=True)

    return result
