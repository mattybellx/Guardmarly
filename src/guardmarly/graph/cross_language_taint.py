"""Cross-language traversal helpers over the Unified Source Graph."""

from __future__ import annotations

from collections import deque
from pathlib import Path
import re
from urllib.parse import urlparse

from guardmarly.graph.go_callgraph import build_go_callgraph
from guardmarly.graph.import_graph import _load_tsconfig_aliases, _resolve_js_module, resolve_go_imports, resolve_js_imports, resolve_python_imports
from guardmarly.graph.js_callgraph import build_js_callgraph
from guardmarly.graph.python_callgraph import build_python_callgraph
from guardmarly.graph.unified_source_graph import SourceEdge, SourceNode, UnifiedSourceGraph

_PY_ROUTE_RE = re.compile(
    r"@(?:[A-Za-z_][\w]*\.)?(?P<method>get|post|put|delete|patch|route)\(\s*(['\"])(?P<path>[^'\"]+)\2[^\n]*\)\s*\n\s*(?:async\s+def|def)\s+(?P<handler>[A-Za-z_][\w]*)\s*\(",
    re.MULTILINE,
)
_JS_ROUTE_RE = re.compile(
    r"(?:app|router)\.(?P<method>get|post|put|delete|patch)\(\s*(['\"`])(?P<path>[^'\"`]+)\2\s*,\s*(?P<handler>[A-Za-z_$][\w$]*)",
    re.MULTILINE,
)
_GO_ROUTE_RE = re.compile(
    r"http\.HandleFunc\(\s*\"(?P<path>[^\"]+)\"\s*,\s*(?P<handler>[A-Za-z_][A-Za-z0-9_]*)\s*\)",
    re.MULTILINE,
)
_JS_PATH_TOKEN = r"(?:[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*|['\"`][^'\"`]+['\"`]|`[^`]+`)"
_JS_PATH_EXPR = rf"{_JS_PATH_TOKEN}(?:\s*\+\s*{_JS_PATH_TOKEN})*"
_JS_IDENTIFIER_RE = re.compile(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*")
_JS_CONST_ASSIGN_RE = re.compile(
    rf"(?P<export>export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?P<expr>{_JS_PATH_EXPR})\s*(?:;|$)",
    re.MULTILINE,
)
_EXPORT_DEFAULT_EXPR_RE = re.compile(
    rf"export\s+default\s+(?P<expr>{_JS_PATH_EXPR})\s*(?:;|$)",
    re.MULTILINE,
)
_JS_OBJECT_ASSIGN_START_RE = re.compile(
    r"(?P<export>export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*\{",
    re.MULTILINE,
)
_EXPORT_DEFAULT_OBJECT_START_RE = re.compile(
    r"export\s+default\s*\{",
    re.MULTILINE,
)
_COMMONJS_EXPORT_ASSIGN_RE = re.compile(
    rf"(?:module\.exports|exports)\.(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?P<expr>{_JS_PATH_EXPR})\s*(?:;|$)",
    re.MULTILINE,
)
_COMMONJS_OBJECT_EXPORT_START_RE = re.compile(
    r"(?:module\.exports|exports)\.(?P<name>[A-Za-z_$][\w$]*)\s*=\s*\{",
    re.MULTILINE,
)
_COMMONJS_MODULE_EXPORT_OBJECT_START_RE = re.compile(
    r"module\.exports\s*=\s*\{",
    re.MULTILINE,
)
_IMPORT_NAMED_RE = re.compile(r"import\s*\{([^}]+)\}\s*from\s*['\"]([^'\"]+)['\"]")
_IMPORT_DEFAULT_RE = re.compile(r"import\s+(?P<alias>[A-Za-z_$][\w$]*)\s+from\s*['\"](?P<module>[^'\"]+)['\"]")
_IMPORT_NAMESPACE_RE = re.compile(r"import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s*['\"]([^'\"]+)['\"]")
_REQUIRE_OBJECT_RE = re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['\"]([^'\"]+)['\"]\s*\)")
_REQUIRE_DESTRUCTURED_RE = re.compile(r"(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\(\s*['\"]([^'\"]+)['\"]\s*\)")
_AXIOS_CREATE_RE = re.compile(
    rf"(?:const|let|var)\s+(?P<client>[A-Za-z_$][\w$]*)\s*=\s*axios\.create\(\s*\{{[\s\S]*?\bbaseURL\s*:\s*(?P<expr>{_JS_PATH_EXPR})",
    re.MULTILINE,
)
_FETCH_RE = re.compile(r"\bfetch\(\s*(['\"`])(?P<path>[^'\"`]+)\1", re.MULTILINE)
_AXIOS_RE = re.compile(r"\baxios\.(?:get|post|put|delete|patch|request)\(\s*(['\"`])(?P<path>[^'\"`]+)\1", re.MULTILINE)
_AXIOS_CONFIG_RE = re.compile(
    r"\baxios(?:\.request)?\(\s*\{[\s\S]*?\burl\s*:\s*(['\"`])(?P<path>[^'\"`]+)\1",
    re.MULTILINE,
)
_XHR_OPEN_RE = re.compile(
    r"\.open\(\s*(['\"`])(?:GET|POST|PUT|DELETE|PATCH)\1\s*,\s*(['\"`])(?P<path>[^'\"`]+)\2",
    re.IGNORECASE | re.MULTILINE,
)
_FETCH_EXPR_RE = re.compile(rf"\bfetch\(\s*(?P<expr>{_JS_PATH_EXPR})", re.MULTILINE)
_AXIOS_EXPR_RE = re.compile(rf"\baxios\.(?:get|post|put|delete|patch)\(\s*(?P<expr>{_JS_PATH_EXPR})", re.MULTILINE)
_AXIOS_CONFIG_EXPR_RE = re.compile(
    rf"\baxios(?:\.request)?\(\s*\{{[\s\S]*?\burl\s*:\s*(?P<expr>{_JS_PATH_EXPR})",
    re.MULTILINE,
)
_XHR_OPEN_EXPR_RE = re.compile(
    rf"\.open\(\s*(['\"`])(?:GET|POST|PUT|DELETE|PATCH)\1\s*,\s*(?P<expr>{_JS_PATH_EXPR})",
    re.IGNORECASE | re.MULTILINE,
)
_AXIOS_CLIENT_CALL_RE = re.compile(
    rf"\b(?P<client>[A-Za-z_$][\w$]*)\.(?:get|post|put|delete|patch)\(\s*(?P<expr>{_JS_PATH_EXPR})",
    re.MULTILINE,
)
_AXIOS_CLIENT_CONFIG_RE = re.compile(
    rf"\b(?P<client>[A-Za-z_$][\w$]*)\.request\(\s*\{{[\s\S]*?\burl\s*:\s*(?P<expr>{_JS_PATH_EXPR})",
    re.MULTILINE,
)
_JS_SINK_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("innerHTML", "dom_xss", re.compile(r"\.[A-Za-z_$][\w$]*\s*\.\s*innerHTML\s*=|\.innerHTML\s*=", re.MULTILINE)),
    ("outerHTML", "dom_xss", re.compile(r"\.[A-Za-z_$][\w$]*\s*\.\s*outerHTML\s*=|\.outerHTML\s*=", re.MULTILINE)),
    ("document.write", "dom_xss", re.compile(r"\bdocument\.write\s*\(", re.MULTILINE)),
    ("insertAdjacentHTML", "dom_xss", re.compile(r"\b[A-Za-z_$][\w$]*\.insertAdjacentHTML\s*\(", re.MULTILINE)),
    ("dangerouslySetInnerHTML", "dom_xss", re.compile(r"\bdangerouslySetInnerHTML\b", re.MULTILINE)),
    ("srcdoc", "dom_xss", re.compile(r"\.[A-Za-z_$][\w$]*\s*\.\s*srcdoc\s*=|\.srcdoc\s*=", re.MULTILINE)),
    ("eval", "code_execution", re.compile(r"\beval\s*\(", re.MULTILINE)),
    ("Function", "code_execution", re.compile(r"\b(?:new\s+)?Function\s*\(", re.MULTILINE)),
)


def _special_node_id(path: Path, kind: str, suffix: str) -> str:
    return f"file://{path.resolve().as_posix()}#{kind}:{suffix}"


def _line_number(content: str, offset: int) -> int:
    return content[:offset].count("\n") + 1


def _normalize_path(raw_path: str) -> str:
    value = raw_path.strip()
    if not value:
        return "/"
    if "://" in value:
        parsed = urlparse(value)
        value = parsed.path or "/"
    value = value.split("?", 1)[0].split("#", 1)[0]
    value = re.sub(r"\$\{[^}]+\}", "{param}", value)
    value = re.sub(r":([A-Za-z_][\w-]*)", "{param}", value)
    value = re.sub(r"\{[^}]+\}", "{param}", value)
    value = re.sub(r"//+", "/", value)
    if not value.startswith("/"):
        value = "/" + value
    if len(value) > 1:
        value = value.rstrip("/")
    return value or "/"


def _ensure_node(usg: UnifiedSourceGraph, node: SourceNode) -> None:
    if node.id not in usg.nodes:
        usg.add_node(node)


def _sink_node_kind(sink_family: str) -> str:
    if sink_family == "code_execution":
        return "exec_sink"
    return "dom_sink"


def _sink_family_for_node(node: SourceNode) -> str:
    if node.kind == "exec_sink":
        return "code_execution"
    return "dom_xss"


def _split_js_concat(expr: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(expr):
        char = expr[i]
        if quote is not None:
            current.append(char)
            if char == quote and (i == 0 or expr[i - 1] != "\\"):
                quote = None
            i += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            current.append(char)
        elif char == "+":
            token = "".join(current).strip()
            if token:
                parts.append(token)
            current = []
        else:
            current.append(char)
        i += 1
    token = "".join(current).strip()
    if token:
        parts.append(token)
    return parts


def _find_matching_brace(content: str, open_index: int) -> int:
    depth = 0
    in_string: str | None = None
    escape = False
    for index in range(open_index, len(content)):
        char = content[index]
        if in_string is not None:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == in_string:
                in_string = None
            continue
        if char in {"'", '"', "`"}:
            in_string = char
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return len(content) - 1


def _split_js_top_level(text: str, delimiter: str = ",") -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    in_string: str | None = None
    escape = False
    brace_depth = 0
    bracket_depth = 0
    paren_depth = 0
    for char in text:
        if in_string is not None:
            current.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == in_string:
                in_string = None
            continue
        if char in {"'", '"', "`"}:
            in_string = char
            current.append(char)
            continue
        if char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth -= 1
        elif char == "[":
            bracket_depth += 1
        elif char == "]":
            bracket_depth -= 1
        elif char == "(":
            paren_depth += 1
        elif char == ")":
            paren_depth -= 1
        if char == delimiter and brace_depth == 0 and bracket_depth == 0 and paren_depth == 0:
            token = "".join(current).strip()
            if token:
                parts.append(token)
            current = []
            continue
        current.append(char)
    token = "".join(current).strip()
    if token:
        parts.append(token)
    return parts


def _split_js_property(entry: str) -> tuple[str, str] | None:
    in_string: str | None = None
    escape = False
    brace_depth = 0
    bracket_depth = 0
    paren_depth = 0
    for index, char in enumerate(entry):
        if in_string is not None:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == in_string:
                in_string = None
            continue
        if char in {"'", '"', "`"}:
            in_string = char
            continue
        if char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth -= 1
        elif char == "[":
            bracket_depth += 1
        elif char == "]":
            bracket_depth -= 1
        elif char == "(":
            paren_depth += 1
        elif char == ")":
            paren_depth -= 1
        elif char == ":" and brace_depth == 0 and bracket_depth == 0 and paren_depth == 0:
            return entry[:index].strip(), entry[index + 1:].strip()
    return None


def _normalize_js_object_key(raw_key: str) -> str | None:
    key = raw_key.strip()
    if len(key) >= 2 and key[0] == key[-1] and key[0] in {"'", '"', "`"}:
        key = key[1:-1]
    return key if re.fullmatch(r"[A-Za-z_$][\w$]*", key) else None


def _resolve_js_path_expression(expr: str, constants: dict[str, str]) -> str | None:
    value = expr.strip()
    if not value:
        return None
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"', "`"}:
        return value[1:-1]
    if _JS_IDENTIFIER_RE.fullmatch(value):
        return constants.get(value)
    if "+" in value:
        resolved_parts: list[str] = []
        for part in _split_js_concat(value):
            resolved = _resolve_js_path_expression(part, constants)
            if resolved is None:
                return None
            resolved_parts.append(resolved)
        return "".join(resolved_parts)
    return None


def _collect_js_raw_string_assignments(content: str) -> dict[str, str]:
    raw_assignments = {match.group("name"): match.group("expr") for match in _JS_CONST_ASSIGN_RE.finditer(content)}
    raw_assignments.update({match.group("name"): match.group("expr") for match in _COMMONJS_EXPORT_ASSIGN_RE.finditer(content)})
    for match in _EXPORT_DEFAULT_EXPR_RE.finditer(content):
        raw_assignments["default"] = match.group("expr")
    return raw_assignments


def _collect_js_string_constants(content: str, initial_constants: dict[str, str] | None = None) -> dict[str, str]:
    raw_assignments = _collect_js_raw_string_assignments(content)
    resolved: dict[str, str] = {}
    available_constants = dict(initial_constants or {})
    changed = True
    while changed:
        changed = False
        for name, expr in raw_assignments.items():
            if name in resolved:
                continue
            value = _resolve_js_path_expression(expr, {**available_constants, **resolved})
            if value is None:
                continue
            resolved[name] = value
            changed = True
    return resolved


def _collect_js_object_alias_constants(content: str, constants: dict[str, str]) -> dict[str, str]:
    raw_assignments = _collect_js_raw_string_assignments(content)
    resolved: dict[str, str] = {}
    changed = True
    while changed:
        changed = False
        available = {**constants, **resolved}
        for alias_name, expr in raw_assignments.items():
            target_prefix = expr.strip()
            if not _JS_IDENTIFIER_RE.fullmatch(target_prefix):
                continue
            prefix = f"{target_prefix}."
            for key, value in available.items():
                if not key.startswith(prefix):
                    continue
                alias_key = f"{alias_name}{key[len(target_prefix):]}"
                if resolved.get(alias_key) == value:
                    continue
                resolved[alias_key] = value
                changed = True
    return resolved


def _parse_js_object_literal(object_text: str, constants: dict[str, str]) -> dict[str, str]:
    stripped = object_text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        body = stripped[1:-1]
    else:
        body = stripped

    resolved: dict[str, str] = {}
    for entry in _split_js_top_level(body):
        prop = _split_js_property(entry)
        if prop is None:
            continue
        raw_key, raw_value = prop
        key = _normalize_js_object_key(raw_key)
        if not key:
            continue
        value = raw_value.strip()
        if value.startswith("{") and value.endswith("}"):
            nested = _parse_js_object_literal(value, {**constants, **resolved})
            for nested_key, nested_value in nested.items():
                resolved[f"{key}.{nested_key}"] = nested_value
            continue
        scalar_value = _resolve_js_path_expression(value, {**constants, **resolved})
        if scalar_value is not None:
            resolved[key] = scalar_value
    return resolved


def _collect_js_object_constants(content: str, constants: dict[str, str]) -> dict[str, str]:
    named_objects: dict[str, str] = {}
    root_objects: list[str] = []
    default_objects: list[str] = []

    for pattern in (_JS_OBJECT_ASSIGN_START_RE, _COMMONJS_OBJECT_EXPORT_START_RE):
        for match in pattern.finditer(content):
            open_index = content.find("{", match.start())
            if open_index < 0:
                continue
            close_index = _find_matching_brace(content, open_index)
            named_objects[match.group("name")] = content[open_index:close_index + 1]

    for match in _COMMONJS_MODULE_EXPORT_OBJECT_START_RE.finditer(content):
        open_index = content.find("{", match.start())
        if open_index < 0:
            continue
        close_index = _find_matching_brace(content, open_index)
        root_objects.append(content[open_index:close_index + 1])

    for match in _EXPORT_DEFAULT_OBJECT_START_RE.finditer(content):
        open_index = content.find("{", match.start())
        if open_index < 0:
            continue
        close_index = _find_matching_brace(content, open_index)
        default_objects.append(content[open_index:close_index + 1])

    resolved: dict[str, str] = {}
    changed = True
    while changed:
        changed = False
        available = {**constants, **resolved}
        for name, object_text in named_objects.items():
            parsed = _parse_js_object_literal(object_text, available)
            for key, value in parsed.items():
                qualified_key = f"{name}.{key}"
                if resolved.get(qualified_key) == value:
                    continue
                resolved[qualified_key] = value
                changed = True
        for object_text in root_objects:
            parsed = _parse_js_object_literal(object_text, available)
            for key, value in parsed.items():
                if resolved.get(key) == value:
                    continue
                resolved[key] = value
                changed = True
        for object_text in default_objects:
            parsed = _parse_js_object_literal(object_text, available)
            for key, value in parsed.items():
                qualified_key = f"default.{key}"
                if resolved.get(qualified_key) == value:
                    continue
                resolved[qualified_key] = value
                changed = True
    return resolved


def _resolve_js_module_file(module_name: str, importer: Path, root_dir: Path) -> Path | None:
    base_url, alias_map = _load_tsconfig_aliases(root_dir)
    return _resolve_js_module(module_name, importer.resolve(), root_dir.resolve(), base_url, alias_map)


def _parse_js_import_bindings(file_path: Path, content: str, root_dir: Path) -> tuple[dict[str, tuple[Path, str]], dict[str, Path], dict[str, Path]]:
    named_bindings: dict[str, tuple[Path, str]] = {}
    module_bindings: dict[str, Path] = {}
    default_bindings: dict[str, Path] = {}

    for match in _IMPORT_DEFAULT_RE.finditer(content):
        alias = match.group("alias")
        module_name = match.group("module")
        target = _resolve_js_module_file(module_name, file_path, root_dir)
        if target is not None:
            default_bindings[alias] = target

    for match in _IMPORT_NAMED_RE.finditer(content):
        module_name = match.group(2)
        target = _resolve_js_module_file(module_name, file_path, root_dir)
        if target is None:
            continue
        for chunk in match.group(1).split(","):
            token = chunk.strip()
            if not token:
                continue
            if " as " in token:
                original, alias = [part.strip() for part in token.split(" as ", 1)]
            else:
                original = alias = token
            named_bindings[alias] = (target, original)

    for match in _IMPORT_NAMESPACE_RE.finditer(content):
        alias = match.group(1)
        module_name = match.group(2)
        target = _resolve_js_module_file(module_name, file_path, root_dir)
        if target is not None:
            module_bindings[alias] = target

    for match in _REQUIRE_OBJECT_RE.finditer(content):
        alias = match.group(1)
        module_name = match.group(2)
        target = _resolve_js_module_file(module_name, file_path, root_dir)
        if target is not None:
            module_bindings[alias] = target

    for match in _REQUIRE_DESTRUCTURED_RE.finditer(content):
        module_name = match.group(2)
        target = _resolve_js_module_file(module_name, file_path, root_dir)
        if target is None:
            continue
        for chunk in match.group(1).split(","):
            token = chunk.strip()
            if not token:
                continue
            if ":" in token:
                original, alias = [part.strip() for part in token.split(":", 1)]
            else:
                original = alias = token
            named_bindings[alias] = (target, original)

    return named_bindings, module_bindings, default_bindings


def _collect_js_module_constants(
    file_path: Path,
    root_dir: Path,
    cache: dict[str, dict[str, str]],
    visiting: set[str] | None = None,
) -> dict[str, str]:
    file_key = str(file_path.resolve())
    if file_key in cache:
        return cache[file_key]
    if visiting is None:
        visiting = set()
    if file_key in visiting:
        return {}
    visiting.add(file_key)
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        visiting.discard(file_key)
        cache[file_key] = {}
        return {}

    scalar_constants = _collect_js_string_constants(content)
    object_constants = _collect_js_object_constants(content, scalar_constants)
    alias_constants = _collect_js_object_alias_constants(content, {**scalar_constants, **object_constants})
    constants = {**scalar_constants, **object_constants, **alias_constants}
    named_bindings, module_bindings, default_bindings = _parse_js_import_bindings(file_path, content, root_dir)

    for alias, target_file in default_bindings.items():
        target_constants = _collect_js_module_constants(target_file, root_dir, cache, visiting)
        default_value = target_constants.get("default")
        if default_value is not None:
            constants.setdefault(alias, default_value)
        for key, value in target_constants.items():
            if not key.startswith("default."):
                continue
            constants.setdefault(f"{alias}{key[len('default'):]}", value)

    for alias, (target_file, exported_name) in named_bindings.items():
        target_constants = _collect_js_module_constants(target_file, root_dir, cache, visiting)
        value = target_constants.get(exported_name)
        if value is not None:
            constants.setdefault(alias, value)
        nested_prefix = f"{exported_name}."
        for key, nested_value in target_constants.items():
            if not key.startswith(nested_prefix):
                continue
            constants.setdefault(f"{alias}{key[len(exported_name):]}", nested_value)

    for alias, target_file in module_bindings.items():
        target_constants = _collect_js_module_constants(target_file, root_dir, cache, visiting)
        for export_name, value in target_constants.items():
            constants.setdefault(f"{alias}.{export_name}", value)

    changed = True
    while changed:
        changed = False
        refreshed_scalars = _collect_js_string_constants(content, constants)
        refreshed_objects = _collect_js_object_constants(content, {**constants, **refreshed_scalars})
        refreshed_aliases = _collect_js_object_alias_constants(content, {**constants, **refreshed_scalars, **refreshed_objects})
        for resolved_group in (refreshed_scalars, refreshed_objects, refreshed_aliases):
            for key, value in resolved_group.items():
                if constants.get(key) == value:
                    continue
                constants[key] = value
                changed = True

    visiting.discard(file_key)
    cache[file_key] = constants
    return constants


def _join_route_paths(base_path: str, route_path: str) -> str:
    if route_path.startswith("http://") or route_path.startswith("https://"):
        return route_path
    if not route_path:
        return base_path or "/"
    if route_path.startswith("/"):
        return f"{base_path.rstrip('/')}{route_path}" if base_path else route_path
    return f"{base_path.rstrip('/')}/{route_path.lstrip('/')}" if base_path else f"/{route_path.lstrip('/')}"


def _collect_js_axios_clients(content: str, constants: dict[str, str]) -> dict[str, str]:
    clients: dict[str, str] = {}
    for match in _AXIOS_CREATE_RE.finditer(content):
        base_url = _resolve_js_path_expression(match.group("expr"), constants)
        if not base_url:
            continue
        clients[match.group("client")] = base_url
    return clients


def _add_edge(usg: UnifiedSourceGraph, edge: SourceEdge) -> None:
    if edge.source_id in usg.nodes and edge.target_id in usg.nodes:
        if any(
            existing.source_id == edge.source_id
            and existing.target_id == edge.target_id
            and existing.kind == edge.kind
            for existing in usg.edges
        ):
            return
        usg.add_edge(edge)


def _function_nodes_for_file(usg: UnifiedSourceGraph, file_path: Path, language: str) -> list[SourceNode]:
    resolved = str(file_path.resolve())
    nodes = [
        node for node in usg.nodes.values()
        if node.kind == "function" and node.language == language and node.file_path == resolved
    ]
    return sorted(nodes, key=lambda node: (node.start_line, node.end_line or 0))


def _find_function_node(functions: list[SourceNode], line: int, name: str | None = None) -> SourceNode | None:
    if name is not None:
        for node in functions:
            if node.name.split(".")[-1] == name:
                return node
    containing = [
        node for node in functions
        if node.start_line <= line <= (node.end_line or node.start_line)
    ]
    if not containing:
        return None
    containing.sort(key=lambda node: ((node.end_line or node.start_line) - node.start_line, node.start_line))
    return containing[0]


def _collect_route_nodes(root: Path, usg: UnifiedSourceGraph) -> None:
    for file_path in sorted(root.rglob("*.py")):
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        functions = _function_nodes_for_file(usg, file_path, "python")
        for match in _PY_ROUTE_RE.finditer(content):
            method = match.group("method").upper()
            route_path = _normalize_path(match.group("path"))
            handler_name = match.group("handler")
            line = _line_number(content, match.start())
            route_id = _special_node_id(file_path, "route", f"{method}:{route_path}")
            _ensure_node(usg, SourceNode(
                id=route_id,
                kind="route",
                name=f"{method} {route_path}",
                file_path=str(file_path.resolve()),
                language="python",
                start_line=line,
                end_line=line,
            ))
            function_node = _find_function_node(functions, line, name=handler_name)
            if function_node is not None:
                _add_edge(usg, SourceEdge(route_id, function_node.id, "handles", confidence=0.95))

    for file_path in sorted(path for path in root.rglob("*") if path.is_file() and path.suffix.lower() in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".mts", ".cjs", ".cts"}):
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        functions = _function_nodes_for_file(usg, file_path, "typescript" if file_path.suffix.lower() in {".ts", ".tsx", ".mts", ".cts"} else "javascript")
        for match in _JS_ROUTE_RE.finditer(content):
            method = match.group("method").upper()
            route_path = _normalize_path(match.group("path"))
            handler_name = match.group("handler")
            line = _line_number(content, match.start())
            route_id = _special_node_id(file_path, "route", f"{method}:{route_path}")
            _ensure_node(usg, SourceNode(
                id=route_id,
                kind="route",
                name=f"{method} {route_path}",
                file_path=str(file_path.resolve()),
                language="typescript" if file_path.suffix.lower() in {".ts", ".tsx", ".mts", ".cts"} else "javascript",
                start_line=line,
                end_line=line,
            ))
            function_node = _find_function_node(functions, line, name=handler_name)
            if function_node is not None:
                _add_edge(usg, SourceEdge(route_id, function_node.id, "handles", confidence=0.94))

    for file_path in sorted(root.rglob("*.go")):
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        functions = _function_nodes_for_file(usg, file_path, "go")
        for match in _GO_ROUTE_RE.finditer(content):
            route_path = _normalize_path(match.group("path"))
            handler_name = match.group("handler")
            line = _line_number(content, match.start())
            route_id = _special_node_id(file_path, "route", f"GET:{route_path}")
            _ensure_node(usg, SourceNode(
                id=route_id,
                kind="route",
                name=f"GET {route_path}",
                file_path=str(file_path.resolve()),
                language="go",
                start_line=line,
                end_line=line,
            ))
            function_node = _find_function_node(functions, line, name=handler_name)
            if function_node is not None:
                _add_edge(usg, SourceEdge(route_id, function_node.id, "handles", confidence=0.93))


def _collect_js_client_flows(root: Path, usg: UnifiedSourceGraph) -> None:
    js_suffixes = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".mts", ".cjs", ".cts"}
    constant_cache: dict[str, dict[str, str]] = {}
    for file_path in sorted(path for path in root.rglob("*") if path.is_file() and path.suffix.lower() in js_suffixes):
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        language = "typescript" if file_path.suffix.lower() in {".ts", ".tsx", ".mts", ".cts"} else "javascript"
        functions = _function_nodes_for_file(usg, file_path, language)
        constants = _collect_js_module_constants(file_path, root, constant_cache)
        axios_clients = _collect_js_axios_clients(content, constants)
        http_calls_by_function: dict[str, list[SourceNode]] = {}
        sinks_by_function: dict[str, list[SourceNode]] = {}

        for pattern in (_FETCH_RE, _AXIOS_RE, _AXIOS_CONFIG_RE, _XHR_OPEN_RE):
            for match in pattern.finditer(content):
                route_path = _normalize_path(match.group("path"))
                line = _line_number(content, match.start())
                node_id = _special_node_id(file_path, "http", f"{line}:{route_path}")
                node = SourceNode(
                    id=node_id,
                    kind="http_call",
                    name=route_path,
                    file_path=str(file_path.resolve()),
                    language=language,
                    start_line=line,
                    end_line=line,
                )
                _ensure_node(usg, node)
                function_node = _find_function_node(functions, line)
                if function_node is not None:
                    http_calls_by_function.setdefault(function_node.id, []).append(node)
                    _add_edge(usg, SourceEdge(function_node.id, node.id, "calls_http", confidence=0.90))

        for pattern in (_FETCH_EXPR_RE, _AXIOS_EXPR_RE, _AXIOS_CONFIG_EXPR_RE, _XHR_OPEN_EXPR_RE):
            for match in pattern.finditer(content):
                resolved_path = _resolve_js_path_expression(match.group("expr"), constants)
                if not resolved_path:
                    continue
                route_path = _normalize_path(resolved_path)
                line = _line_number(content, match.start())
                node_id = _special_node_id(file_path, "http", f"{line}:{route_path}")
                node = SourceNode(
                    id=node_id,
                    kind="http_call",
                    name=route_path,
                    file_path=str(file_path.resolve()),
                    language=language,
                    start_line=line,
                    end_line=line,
                )
                _ensure_node(usg, node)
                function_node = _find_function_node(functions, line)
                if function_node is not None:
                    http_calls_by_function.setdefault(function_node.id, []).append(node)
                    _add_edge(usg, SourceEdge(function_node.id, node.id, "calls_http", confidence=0.90))

        for pattern in (_AXIOS_CLIENT_CALL_RE, _AXIOS_CLIENT_CONFIG_RE):
            for match in pattern.finditer(content):
                base_url = axios_clients.get(match.group("client"))
                if not base_url:
                    continue
                resolved_path = _resolve_js_path_expression(match.group("expr"), constants)
                if not resolved_path:
                    continue
                route_path = _normalize_path(_join_route_paths(base_url, resolved_path))
                line = _line_number(content, match.start())
                node_id = _special_node_id(file_path, "http", f"{line}:{route_path}")
                node = SourceNode(
                    id=node_id,
                    kind="http_call",
                    name=route_path,
                    file_path=str(file_path.resolve()),
                    language=language,
                    start_line=line,
                    end_line=line,
                )
                _ensure_node(usg, node)
                function_node = _find_function_node(functions, line)
                if function_node is not None:
                    http_calls_by_function.setdefault(function_node.id, []).append(node)
                    _add_edge(usg, SourceEdge(function_node.id, node.id, "calls_http", confidence=0.9))

        for sink_name, sink_family, pattern in _JS_SINK_PATTERNS:
            for match in pattern.finditer(content):
                line = _line_number(content, match.start())
                node_id = _special_node_id(file_path, "sink", f"{line}:{sink_name}")
                node = SourceNode(
                    id=node_id,
                    kind=_sink_node_kind(sink_family),
                    name=sink_name,
                    file_path=str(file_path.resolve()),
                    language=language,
                    start_line=line,
                    end_line=line,
                )
                _ensure_node(usg, node)
                function_node = _find_function_node(functions, line)
                if function_node is not None:
                    sinks_by_function.setdefault(function_node.id, []).append(node)
                    _add_edge(usg, SourceEdge(function_node.id, node.id, "writes_dom", confidence=0.92))

        for function_id, http_nodes in http_calls_by_function.items():
            for sink in sinks_by_function.get(function_id, []):
                for http_node in http_nodes:
                    _add_edge(usg, SourceEdge(http_node.id, sink.id, "data_flow", confidence=0.84))


def _reachable_js_functions(usg: UnifiedSourceGraph, start_id: str, max_depth: int = 2) -> set[str]:
    reachable: set[str] = {start_id}
    queue: deque[tuple[str, int]] = deque([(start_id, 0)])
    while queue:
        current, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for edge in usg.edges:
            if edge.kind != "calls":
                continue
            neighbor_id: str | None = None
            if edge.source_id == current:
                neighbor_id = edge.target_id
            elif edge.target_id == current:
                neighbor_id = edge.source_id
            if neighbor_id is None or neighbor_id in reachable:
                continue
            neighbor = usg.nodes.get(neighbor_id)
            if neighbor is None or neighbor.kind != "function" or neighbor.language not in {"javascript", "typescript"}:
                continue
            reachable.add(neighbor_id)
            queue.append((neighbor_id, depth + 1))
    return reachable


def _add_js_propagation_edges(usg: UnifiedSourceGraph, max_depth: int = 2) -> None:
    function_to_http: dict[str, list[str]] = {}
    function_to_sinks: dict[str, list[str]] = {}
    for edge in usg.edges:
        if edge.kind == "calls_http":
            function_to_http.setdefault(edge.source_id, []).append(edge.target_id)
        elif edge.kind == "writes_dom":
            function_to_sinks.setdefault(edge.source_id, []).append(edge.target_id)

    for function_id, http_node_ids in function_to_http.items():
        for reachable_function_id in _reachable_js_functions(usg, function_id, max_depth=max_depth):
            for sink_id in function_to_sinks.get(reachable_function_id, []):
                confidence = 0.84 if reachable_function_id == function_id else 0.72
                for http_node_id in http_node_ids:
                    _add_edge(usg, SourceEdge(http_node_id, sink_id, "data_flow", confidence=confidence))


def _route_to_pattern(route_path: str) -> re.Pattern | None:
    """Convert a Flask/FastAPI/Express-style route path to a regex pattern.
    Handles <param>, <type:param>, :param, and ${param} style placeholders.
    Enables parameterized routes like /api/users/<id> to match /api/users/123.
    """
    if not route_path:
        return None
    # Replace ALL placeholders with a wildcard BEFORE re.escape
    normalized = route_path
    normalized = re.sub(r"\$\{(\w+)\}", "___PARAM___", normalized)
    normalized = re.sub(r"<(?:\w+:)?\w+>", "___PARAM___", normalized)
    normalized = re.sub(r":\w+", "___PARAM___", normalized)
    pattern = re.escape(normalized)
    pattern = pattern.replace("___PARAM___", r"[^/]+")
    return re.compile(f"^{pattern}$")


def _route_path(node: SourceNode) -> str | None:
    if node.kind == "route" and " " in node.name:
        return node.name.split(" ", 1)[1]
    if node.kind == "http_call":
        return node.name
    return None


def _add_route_bridge_edges(usg: UnifiedSourceGraph) -> None:
    routes = [node for node in usg.nodes.values() if node.kind == "route"]
    http_calls = [node for node in usg.nodes.values() if node.kind == "http_call"]
    # Pre-build route patterns for parameterized matching
    route_patterns = []
    for route in routes:
        rp = _route_path(route)
        if rp is None:
            continue
        pat = _route_to_pattern(rp)
        route_patterns.append((route, rp, pat))

    for http_call in http_calls:
        call_path = _route_path(http_call)
        if call_path is None:
            continue
        for route, rp, pat in route_patterns:
            # Fast path: exact string match
            if rp == call_path:
                _add_edge(usg, SourceEdge(route.id, http_call.id, "http_bridge", confidence=0.83))
            # Parameterized match: use regex
            elif pat and pat.match(call_path):
                _add_edge(usg, SourceEdge(route.id, http_call.id, "http_bridge", confidence=0.78))


def build_repository_graph(root_dir: str | Path) -> UnifiedSourceGraph:
    """Construct a repository graph across Python, JS/TS, and Go files."""
    root = Path(root_dir).resolve()
    graph = UnifiedSourceGraph()

    python_imports = resolve_python_imports(root, graph)
    js_imports = resolve_js_imports(root, graph)
    go_imports = resolve_go_imports(root, graph)

    build_python_callgraph(root, graph, python_imports)
    build_js_callgraph(root, graph, js_imports)
    build_go_callgraph(root, graph, go_imports)
    _collect_route_nodes(root, graph)
    _collect_js_client_flows(root, graph)
    _add_js_propagation_edges(graph)
    _add_route_bridge_edges(graph)
    return graph


def build_repository_graph_with_global_graph(
    root_dir: str | Path,
    global_graph: Any | None = None,
) -> tuple[UnifiedSourceGraph, Any, int]:
    """Build repository graph AND publish cross-language bridges into GlobalGraph (DIR-3.3).

    Returns (usg, global_graph, bridge_count).
    If global_graph is None, creates a new one.
    """
    from guardmarly.ir.global_graph import GlobalGraph

    usg = build_repository_graph(root_dir)
    if global_graph is None:
        global_graph = GlobalGraph()

    # Extract route→HTTP bridge edges from the USG, resolving to function names
    bridges: list[tuple[str, str, str, str]] = []
    for edge in usg.edges:
        if edge.kind != "http_bridge":
            continue
        src_node = usg.nodes.get(edge.source_id)
        tgt_node = usg.nodes.get(edge.target_id)
        if src_node is None or tgt_node is None:
            continue
        # Walk from route node to its handler function
        src_func = _find_related_function(usg, src_node)
        # Walk from http_call node to its caller function
        tgt_func = _find_related_function(usg, tgt_node)
        if src_func is None or tgt_func is None:
            continue
        bridges.append((
            src_func.file_path or "",
            src_func.name or "",
            tgt_func.file_path or "",
            tgt_func.name or "",
        ))

    bridge_count = global_graph.publish_cross_language_bridges(bridges)
    return usg, global_graph, bridge_count


def _find_related_function(usg: UnifiedSourceGraph, node: SourceNode) -> SourceNode | None:
    """Walk edges to find the function node associated with a route or http_call node."""
    if node.kind == "function":
        return node
    if node.kind in ("route", "http_call"):
        # Look for incoming edges that point to this node from a function
        for edge in usg.edges:
            if edge.target_id == node.id:
                src = usg.nodes.get(edge.source_id)
                if src and src.kind == "function":
                    return src
            if edge.source_id == node.id:
                tgt = usg.nodes.get(edge.target_id)
                if tgt and tgt.kind == "function":
                    return tgt
    return None


def _path_node_ids(path: list[SourceEdge]) -> list[str]:
    if not path:
        return []
    node_ids = [path[0].source_id]
    node_ids.extend(edge.target_id for edge in path)
    return node_ids


def path_languages(usg: UnifiedSourceGraph, path: list[SourceEdge]) -> list[str]:
    """Return ordered distinct languages traversed by a path."""
    languages: list[str] = []
    seen: set[str] = set()
    for node_id in _path_node_ids(path):
        node = usg.nodes.get(node_id)
        if node is None or node.language in seen:
            continue
        seen.add(node.language)
        languages.append(node.language)
    return languages


def _calculate_path_confidence(path: list[SourceEdge]) -> float:
    if not path:
        return 0.0
    return sum(edge.confidence for edge in path) / len(path)


def find_cross_language_taint(usg: UnifiedSourceGraph, max_depth: int = 12) -> list[dict[str, object]]:
    """Return route-to-sink taint paths that cross language boundaries."""
    sources = [node for node in usg.nodes.values() if node.kind == "route"]
    sinks = [node for node in usg.nodes.values() if node.kind in {"dom_sink", "exec_sink"}]
    results: list[dict[str, object]] = []
    seen: set[tuple[str, str, tuple[tuple[str, str, str], ...]]] = set()
    for source in sources:
        for sink in sinks:
            path = usg.find_path(source.id, sink.id, max_depth=max_depth)
            if not path:
                continue
            languages = path_languages(usg, path)
            if len(languages) < 2:
                continue
            fingerprint = tuple((edge.source_id, edge.target_id, edge.kind) for edge in path)
            dedupe_key = (source.id, sink.id, fingerprint)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            results.append({
                "source": source.id,
                "sink": sink.id,
                "source_file": source.file_path,
                "sink_file": sink.file_path,
                "source_line": source.start_line,
                "sink_line": sink.start_line,
                "sink_name": sink.name,
                "sink_family": _sink_family_for_node(sink),
                "languages": languages,
                "confidence": round(_calculate_path_confidence(path), 3),
                "path": [
                    {"from": edge.source_id, "to": edge.target_id, "kind": edge.kind}
                    for edge in path
                ],
            })
    return results


def find_cross_language_taint_paths(
    usg: UnifiedSourceGraph,
    source_pattern: str,
    sink_pattern: str,
    max_depth: int = 12,
    min_languages: int = 2,
) -> list[list[SourceEdge]]:
    """Return taint paths that actually cross at least *min_languages* languages."""
    all_paths = usg.find_taint_paths(source_pattern, sink_pattern, max_depth=max_depth)
    return [path for path in all_paths if len(path_languages(usg, path)) >= min_languages]