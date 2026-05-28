"""Basic JavaScript/TypeScript call-graph construction."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ansede_static.graph.import_graph import _ensure_file_node, _node_id_for_file, resolve_js_imports
from ansede_static.graph.unified_source_graph import SourceEdge, SourceNode, UnifiedSourceGraph

_JS_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".mts", ".cjs", ".cts"}

_FUNCTION_DEF_RE = re.compile(
    r"(?:^|\n)\s*(?:export\s+(?:default\s+)?)?function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{",
    re.MULTILINE,
)
_ARROW_DEF_RE = re.compile(
    r"(?:^|\n)\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>\s*\{",
    re.MULTILINE,
)
_IMPORT_DEFAULT_RE = re.compile(r"import\s+(?P<alias>[A-Za-z_$][\w$]*)\s*(?:,\s*\{[^}]+\})?\s*from\s*['\"](?P<module>[^'\"]+)['\"]")
_IMPORT_NAMED_RE = re.compile(r"import\s*\{([^}]+)\}\s*from\s*['\"]([^'\"]+)['\"]")
_IMPORT_NAMESPACE_RE = re.compile(r"import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s*['\"]([^'\"]+)['\"]")
_REQUIRE_OBJECT_RE = re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['\"]([^'\"]+)['\"]\s*\)")
_REQUIRE_DESTRUCTURED_RE = re.compile(r"(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\(\s*['\"]([^'\"]+)['\"]\s*\)")
_EXPORT_DEFAULT_ALIAS_RE = re.compile(r"export\s+default\s+([A-Za-z_$][\w$]*)\s*(?:;|$)")
_MODULE_EXPORT_ALIAS_RE = re.compile(r"module\.exports\s*=\s*([A-Za-z_$][\w$]*)\s*(?:;|$)")
_DIRECT_CALL_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\(")
_ATTRIBUTE_CALL_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*\(")
_KEYWORDS = {"if", "for", "while", "switch", "return", "catch", "function", "typeof", "await", "new"}


def _function_node_id(path: Path, name: str) -> str:
    return f"file://{path.resolve().as_posix()}#func:{name}"


@dataclass
class _JsFunction:
    name: str
    node_id: str
    start: int
    end: int


def _find_matching_brace(content: str, open_index: int) -> int:
    depth = 0
    in_string: str | None = None
    escape = False
    for index in range(open_index, len(content)):
        ch = content[index]
        if in_string is not None:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_string:
                in_string = None
            continue
        if ch in {'"', "'", "`"}:
            in_string = ch
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return index
    return len(content) - 1


def _collect_js_functions(file_path: Path, content: str, usg: UnifiedSourceGraph) -> dict[str, _JsFunction]:
    functions: dict[str, _JsFunction] = {}
    for pattern in (_FUNCTION_DEF_RE, _ARROW_DEF_RE):
        for match in pattern.finditer(content):
            name = match.group(1)
            body_start = content.find("{", match.start())
            if body_start < 0:
                continue
            body_end = _find_matching_brace(content, body_start)
            node_id = _function_node_id(file_path, name)
            if node_id not in usg.nodes:
                usg.add_node(SourceNode(
                    id=node_id,
                    kind="function",
                    name=name,
                    file_path=str(file_path.resolve()),
                    language="typescript" if file_path.suffix.lower() in {".ts", ".tsx", ".mts", ".cts"} else "javascript",
                    start_line=content[:match.start()].count("\n") + 1,
                    end_line=content[:body_end].count("\n") + 1,
                ))
            functions[name] = _JsFunction(name=name, node_id=node_id, start=body_start + 1, end=body_end)
    return functions


def _resolve_js_module_path(module_name: str, importer: Path, root_dir: Path) -> Path | None:
    temp_graph = UnifiedSourceGraph()
    edges = resolve_js_imports(root_dir, temp_graph)
    source_id = _node_id_for_file(importer)
    for edge in edges:
        if edge.source_id == source_id:
            candidate_path = Path(edge.target_id[len("file://"):].split("#", 1)[0])
            try:
                # Only keep the edge if the import text actually appears in the file mapping pass.
                if candidate_path.exists():
                    return candidate_path
            except OSError:
                continue
    return None


def _parse_import_bindings(file_path: Path, content: str, root_dir: Path) -> tuple[dict[str, tuple[Path, str]], dict[str, Path]]:
    named_bindings: dict[str, tuple[Path, str]] = {}
    module_bindings: dict[str, Path] = {}
    default_bindings: dict[str, Path] = {}

    def _resolve(module_name: str) -> Path | None:
        from ansede_static.graph.import_graph import _load_tsconfig_aliases, _resolve_js_module

        base_url, alias_map = _load_tsconfig_aliases(root_dir)
        return _resolve_js_module(module_name, file_path.resolve(), root_dir.resolve(), base_url, alias_map)

    for match in _IMPORT_DEFAULT_RE.finditer(content):
        alias = match.group("alias")
        module_name = match.group("module")
        target = _resolve(module_name)
        if target is not None:
            default_bindings[alias] = target

    for match in _IMPORT_NAMED_RE.finditer(content):
        module_name = match.group(2)
        target = _resolve(module_name)
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
        target = _resolve(module_name)
        if target is not None:
            module_bindings[alias] = target

    for match in _REQUIRE_OBJECT_RE.finditer(content):
        alias = match.group(1)
        module_name = match.group(2)
        target = _resolve(module_name)
        if target is not None:
            module_bindings[alias] = target

    for match in _REQUIRE_DESTRUCTURED_RE.finditer(content):
        module_name = match.group(2)
        target = _resolve(module_name)
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

    for match in _REQUIRE_OBJECT_RE.finditer(content):
        alias = match.group(1)
        module_name = match.group(2)
        target = _resolve(module_name)
        if target is not None:
            module_bindings[alias] = target
            default_bindings.setdefault(alias, target)

    return named_bindings, module_bindings, default_bindings


def _default_export_name(content: str, functions: dict[str, _JsFunction]) -> str | None:
    for match in _EXPORT_DEFAULT_ALIAS_RE.finditer(content):
        name = match.group(1)
        if name in functions:
            return name
    for match in _MODULE_EXPORT_ALIAS_RE.finditer(content):
        name = match.group(1)
        if name in functions:
            return name
    if "export default function " in content:
        for name in functions:
            if re.search(rf"export\s+default\s+function\s+{re.escape(name)}\s*\(", content):
                return name
    return None


def build_js_callgraph(
    root_dir: str | Path,
    usg: UnifiedSourceGraph,
    import_edges: list[SourceEdge],
) -> list[SourceEdge]:
    """Build a lightweight JS/TS call graph over top-level functions."""
    root = Path(root_dir).resolve()
    files = sorted(path for path in root.rglob("*") if path.is_file() and path.suffix.lower() in _JS_SUFFIXES)

    imported_targets_by_file: dict[str, set[str]] = {}
    for edge in import_edges:
        source_path = edge.source_id[len("file://"):].split("#", 1)[0]
        target_path = edge.target_id[len("file://"):].split("#", 1)[0]
        imported_targets_by_file.setdefault(str(Path(source_path).resolve()), set()).add(str(Path(target_path).resolve()))

    file_functions: dict[str, dict[str, _JsFunction]] = {}
    file_contents: dict[str, str] = {}
    default_exports: dict[str, str] = {}
    for file_path in files:
        _ensure_file_node(usg, file_path)
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        file_contents[str(file_path.resolve())] = content
        functions = _collect_js_functions(file_path, content, usg)
        file_functions[str(file_path.resolve())] = functions
        default_name = _default_export_name(content, functions)
        if default_name is not None:
            default_exports[str(file_path.resolve())] = default_name

    edges: list[SourceEdge] = []
    seen: set[tuple[str, str, str]] = set()
    for file_path in files:
        file_key = str(file_path.resolve())
        content = file_contents.get(file_key, "")
        functions = file_functions.get(file_key, {})
        named_bindings, module_bindings, default_bindings = _parse_import_bindings(file_path, content, root)
        allowed_targets = imported_targets_by_file.get(file_key, set())

        for function in functions.values():
            body = content[function.start:function.end]

            for match in _DIRECT_CALL_RE.finditer(body):
                callee = match.group(1)
                if callee in _KEYWORDS:
                    continue
                target_id: str | None = None
                if callee in functions:
                    target_id = functions[callee].node_id
                elif callee in named_bindings:
                    target_file, exported_name = named_bindings[callee]
                    if allowed_targets and str(target_file.resolve()) not in allowed_targets:
                        continue
                    target_functions = file_functions.get(str(target_file.resolve()), {})
                    if exported_name in target_functions:
                        target_id = target_functions[exported_name].node_id
                elif callee in default_bindings:
                    target_file = default_bindings[callee]
                    if allowed_targets and str(target_file.resolve()) not in allowed_targets:
                        continue
                    exported_name = default_exports.get(str(target_file.resolve()))
                    target_functions = file_functions.get(str(target_file.resolve()), {})
                    if exported_name and exported_name in target_functions:
                        target_id = target_functions[exported_name].node_id
                if target_id is None or target_id == function.node_id:
                    continue
                fingerprint = (function.node_id, target_id, "calls")
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                edge = SourceEdge(source_id=function.node_id, target_id=target_id, kind="calls", confidence=0.88)
                usg.add_edge(edge)
                edges.append(edge)

            for match in _ATTRIBUTE_CALL_RE.finditer(body):
                base, attr = match.groups()
                target_file = module_bindings.get(base)
                if target_file is None:
                    continue
                if allowed_targets and str(target_file.resolve()) not in allowed_targets:
                    continue
                target_functions = file_functions.get(str(target_file.resolve()), {})
                if attr not in target_functions:
                    continue
                target_id = target_functions[attr].node_id
                fingerprint = (function.node_id, target_id, "calls")
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                edge = SourceEdge(source_id=function.node_id, target_id=target_id, kind="calls", confidence=0.86)
                usg.add_edge(edge)
                edges.append(edge)

    return edges