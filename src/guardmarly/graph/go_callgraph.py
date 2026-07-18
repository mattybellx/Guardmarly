"""Basic Go call-graph construction."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from guardmarly.graph.import_graph import _build_go_package_index, _ensure_file_node, _go_module_name
from guardmarly.graph.unified_source_graph import SourceEdge, SourceNode, UnifiedSourceGraph

_FUNC_RE = re.compile(
    r"func\s*(?:\(([^)]*)\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*(?:\([^\{]*\)|[^\{()]*)?\{",
    re.MULTILINE,
)
_IMPORT_SINGLE_RE = re.compile(r'^\s*import\s+(?:(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s+)?"(?P<path>[^"]+)"', re.MULTILINE)
_IMPORT_BLOCK_RE = re.compile(r'import\s*\((.*?)\)', re.DOTALL | re.MULTILINE)
_IMPORT_ENTRY_RE = re.compile(r'(?:(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s+)?"(?P<path>[^"]+)"')
_DIRECT_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_ATTRIBUTE_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_KEYWORDS = {"if", "for", "switch", "return", "go", "defer", "func", "make", "new"}


def _function_node_id(path: Path, name: str) -> str:
    return f"file://{path.resolve().as_posix()}#func:{name}"


@dataclass
class _GoFunction:
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


def _receiver_type(receiver: str | None) -> str | None:
    if not receiver:
        return None
    parts = receiver.strip().split()
    if not parts:
        return None
    receiver_type = parts[-1].lstrip("*")
    return receiver_type or None


def _collect_go_functions(file_path: Path, content: str, usg: UnifiedSourceGraph) -> dict[str, _GoFunction]:
    functions: dict[str, _GoFunction] = {}
    for match in _FUNC_RE.finditer(content):
        receiver = _receiver_type(match.group(1))
        name = match.group(2)
        qualname = f"{receiver}.{name}" if receiver else name
        body_start = content.find("{", match.start())
        if body_start < 0:
            continue
        body_end = _find_matching_brace(content, body_start)
        node_id = _function_node_id(file_path, qualname)
        if node_id not in usg.nodes:
            usg.add_node(SourceNode(
                id=node_id,
                kind="function",
                name=qualname,
                file_path=str(file_path.resolve()),
                language="go",
                start_line=content[:match.start()].count("\n") + 1,
                end_line=content[:body_end].count("\n") + 1,
            ))
        functions[qualname] = _GoFunction(name=qualname, node_id=node_id, start=body_start + 1, end=body_end)
        if receiver:
            functions[name] = functions[qualname]
    return functions


def _parse_import_aliases(content: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for match in _IMPORT_SINGLE_RE.finditer(content):
        import_path = match.group("path")
        alias = match.group("alias") or import_path.rsplit("/", 1)[-1]
        aliases[alias] = import_path
    for block in _IMPORT_BLOCK_RE.finditer(content):
        for entry in _IMPORT_ENTRY_RE.finditer(block.group(1)):
            import_path = entry.group("path")
            alias = entry.group("alias") or import_path.rsplit("/", 1)[-1]
            aliases[alias] = import_path
    return aliases


def build_go_callgraph(
    root_dir: str | Path,
    usg: UnifiedSourceGraph,
    import_edges: list[SourceEdge],
) -> list[SourceEdge]:
    """Build a lightweight Go call graph over top-level functions and package calls."""
    root = Path(root_dir).resolve()
    module_name = _go_module_name(root)
    if not module_name:
        return []

    package_index = _build_go_package_index(root, module_name)
    imported_targets_by_file: dict[str, set[str]] = {}
    for edge in import_edges:
        source_path = edge.source_id[len("file://"):].split("#", 1)[0]
        target_path = edge.target_id[len("file://"):].split("#", 1)[0]
        imported_targets_by_file.setdefault(str(Path(source_path).resolve()), set()).add(str(Path(target_path).resolve()))

    go_files = sorted(path for path in root.rglob("*.go") if path.is_file())
    file_functions: dict[str, dict[str, _GoFunction]] = {}
    file_contents: dict[str, str] = {}
    for file_path in go_files:
        _ensure_file_node(usg, file_path)
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        file_contents[str(file_path.resolve())] = content
        file_functions[str(file_path.resolve())] = _collect_go_functions(file_path, content, usg)

    edges: list[SourceEdge] = []
    seen: set[tuple[str, str, str]] = set()
    for file_path in go_files:
        file_key = str(file_path.resolve())
        content = file_contents.get(file_key, "")
        functions = file_functions.get(file_key, {})
        allowed_targets = imported_targets_by_file.get(file_key, set())
        aliases = _parse_import_aliases(content)

        for function in list({v.node_id: v for v in functions.values()}.values()):
            body = content[function.start:function.end]

            for match in _DIRECT_CALL_RE.finditer(body):
                callee = match.group(1)
                if callee in _KEYWORDS:
                    continue
                target = functions.get(callee)
                if target is None or target.node_id == function.node_id:
                    continue
                fingerprint = (function.node_id, target.node_id, "calls")
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                edge = SourceEdge(source_id=function.node_id, target_id=target.node_id, kind="calls", confidence=0.89)
                usg.add_edge(edge)
                edges.append(edge)

            for match in _ATTRIBUTE_CALL_RE.finditer(body):
                alias, callee = match.groups()
                import_path = aliases.get(alias)
                if import_path is None:
                    continue
                target_file = package_index.get(import_path)
                if target_file is None:
                    continue
                if allowed_targets and str(target_file.resolve()) not in allowed_targets:
                    continue
                target_functions = file_functions.get(str(target_file.resolve()), {})
                target = target_functions.get(callee)
                if target is None:
                    continue
                fingerprint = (function.node_id, target.node_id, "calls")
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                edge = SourceEdge(source_id=function.node_id, target_id=target.node_id, kind="calls", confidence=0.87)
                usg.add_edge(edge)
                edges.append(edge)

    return edges