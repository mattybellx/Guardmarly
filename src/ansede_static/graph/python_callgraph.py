"""Basic Python call-graph construction over the Unified Source Graph."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from ansede_static.graph.import_graph import _build_python_module_index, _ensure_file_node
from ansede_static.graph.unified_source_graph import SourceEdge, SourceNode, UnifiedSourceGraph


def _function_node_id(path: Path, qualname: str) -> str:
    return f"file://{path.resolve().as_posix()}#func:{qualname}"


def _class_node_id(path: Path, class_name: str) -> str:
    return f"file://{path.resolve().as_posix()}#class:{class_name}"


@dataclass
class _FileSymbols:
    file_path: Path
    module_name: str
    tree: ast.AST
    top_level_functions: dict[str, str] = field(default_factory=dict)
    class_methods: dict[str, dict[str, str]] = field(default_factory=dict)
    classes: dict[str, str] = field(default_factory=dict)


class _DefinitionCollector(ast.NodeVisitor):
    def __init__(self, file_path: Path, usg: UnifiedSourceGraph):
        self.file_path = file_path
        self.usg = usg
        self.symbols = _FileSymbols(file_path=file_path, module_name="", tree=ast.parse(""))
        self._scope: list[str] = []
        self._class_stack: list[str] = []

    def collect(self, tree: ast.AST, module_name: str) -> _FileSymbols:
        self.symbols.tree = tree
        self.symbols.module_name = module_name
        self.visit(tree)
        return self.symbols

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        class_name = ".".join([*self._scope, node.name]) if self._scope else node.name
        class_id = _class_node_id(self.file_path, class_name)
        self.symbols.classes[class_name] = class_id
        self.symbols.class_methods.setdefault(class_name, {})
        if class_id not in self.usg.nodes:
            self.usg.add_node(SourceNode(
                id=class_id,
                kind="class",
                name=class_name,
                file_path=str(self.file_path.resolve()),
                language="python",
                start_line=getattr(node, "lineno", 0),
                end_line=getattr(node, "end_lineno", getattr(node, "lineno", 0)),
            ))
        self._scope.append(node.name)
        self._class_stack.append(class_name)
        self.generic_visit(node)
        self._class_stack.pop()
        self._scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._register_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._register_function(node)

    def _register_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qualname = ".".join([*self._scope, node.name]) if self._scope else node.name
        node_id = _function_node_id(self.file_path, qualname)
        if node_id not in self.usg.nodes:
            self.usg.add_node(SourceNode(
                id=node_id,
                kind="function",
                name=qualname,
                file_path=str(self.file_path.resolve()),
                language="python",
                start_line=getattr(node, "lineno", 0),
                end_line=getattr(node, "end_lineno", getattr(node, "lineno", 0)),
            ))
        if self._class_stack:
            self.symbols.class_methods.setdefault(self._class_stack[-1], {})[node.name] = node_id
        elif len(self._scope) <= 1:
            self.symbols.top_level_functions[node.name] = node_id

        self._scope.append(node.name)
        self.generic_visit(node)
        self._scope.pop()


class _CallCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.calls: list[ast.Call] = []

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append(node)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return


def _attribute_chain(node: ast.AST) -> list[str]:
    chain: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        chain.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        chain.append(current.id)
    return list(reversed(chain))


def _file_path_from_node_id(node_id: str) -> Path:
    prefix = "file://"
    anchor = "#file"
    if node_id.endswith(anchor):
        raw = node_id[len(prefix):-len(anchor)]
    else:
        raw = node_id[len(prefix):].split("#", 1)[0]
    return Path(raw)


def _parse_import_bindings(file_path: Path, root: Path, module_index: dict[str, Path]) -> dict[str, tuple[Path, str | None]]:
    bindings: dict[str, tuple[Path, str | None]] = {}
    try:
        tree = ast.parse(file_path.read_text(encoding="utf-8", errors="replace"), filename=str(file_path))
    except (OSError, SyntaxError, ValueError):
        return bindings

    module_name = ".".join(file_path.relative_to(root).with_suffix("").parts)
    is_package = file_path.name == "__init__.py"
    current_parts = [part for part in module_name.split(".") if part]
    package_parts = current_parts if is_package else current_parts[:-1]

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                target = module_index.get(alias.name)
                if target is not None:
                    bindings[alias.asname or alias.name.split(".")[-1]] = (target, None)
        elif isinstance(node, ast.ImportFrom):
            base_parts = package_parts[:]
            if node.level > 0:
                trim = max(node.level - 1, 0)
                if trim:
                    base_parts = base_parts[:-trim] if trim <= len(base_parts) else []
            if node.module:
                base_module = ".".join([*base_parts, *node.module.split(".")])
            else:
                base_module = ".".join(base_parts)
            for alias in node.names:
                candidates: list[tuple[str, str | None]] = []
                if base_module:
                    candidates.append((f"{base_module}.{alias.name}", alias.name))
                    candidates.append((base_module, alias.name))
                else:
                    candidates.append((alias.name, alias.name))
                for candidate, imported_name in candidates:
                    target = module_index.get(candidate)
                    if target is not None:
                        bindings[alias.asname or alias.name] = (target, imported_name if candidate == base_module else None)
                        break
    return bindings


def build_python_callgraph(
    root_dir: str | Path,
    usg: UnifiedSourceGraph,
    import_edges: list[SourceEdge],
) -> list[SourceEdge]:
    """Build a simple Python call graph over top-level functions and class methods."""
    root = Path(root_dir).resolve()
    module_index = _build_python_module_index(root)
    imported_targets_by_file: dict[str, set[str]] = {}
    for edge in import_edges:
        source_path = str(_file_path_from_node_id(edge.source_id).resolve())
        target_path = str(_file_path_from_node_id(edge.target_id).resolve())
        imported_targets_by_file.setdefault(source_path, set()).add(target_path)

    file_symbols: dict[str, _FileSymbols] = {}
    for file_path in sorted(module_index.values()):
        _ensure_file_node(usg, file_path)
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(file_path))
        except (OSError, SyntaxError, ValueError):
            continue
        collector = _DefinitionCollector(file_path, usg)
        file_symbols[str(file_path.resolve())] = collector.collect(tree, module_name="")

    edges: list[SourceEdge] = []
    seen: set[tuple[str, str, str]] = set()

    for file_key, symbols in file_symbols.items():
        bindings = _parse_import_bindings(symbols.file_path, root, module_index)
        allowed_import_targets = imported_targets_by_file.get(file_key, set())
        for node in ast.walk(symbols.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if any(parent for parent in ast.iter_child_nodes(node) if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))):
                pass
            qualname_parts: list[str] = []
            parent_map: dict[ast.AST, ast.AST] = {}
            for parent in ast.walk(symbols.tree):
                for child in ast.iter_child_nodes(parent):
                    parent_map[child] = parent
            current: ast.AST | None = node
            while current is not None and not isinstance(current, ast.Module):
                if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    qualname_parts.append(current.name)
                current = parent_map.get(current)
            qualname = ".".join(reversed(qualname_parts))
            caller_id = _function_node_id(symbols.file_path, qualname)
            if caller_id not in usg.nodes:
                continue

            collector = _CallCollector()
            for statement in node.body:
                collector.visit(statement)

            for call in collector.calls:
                target_id: str | None = None
                if isinstance(call.func, ast.Name):
                    call_name = call.func.id
                    target_id = symbols.top_level_functions.get(call_name)
                    if target_id is None and call_name in bindings:
                        target_file, imported_name = bindings[call_name]
                        if allowed_import_targets and str(target_file.resolve()) not in allowed_import_targets:
                            continue
                        imported_symbols = file_symbols.get(str(target_file.resolve()))
                        if imported_symbols is not None:
                            target_id = imported_symbols.top_level_functions.get(imported_name or call_name)
                    if target_id is None and call_name in symbols.classes:
                        target_id = symbols.class_methods.get(call_name, {}).get("__init__")
                elif isinstance(call.func, ast.Attribute):
                    chain = _attribute_chain(call.func)
                    if len(chain) == 2:
                        base, attr = chain
                        if base in bindings:
                            target_file, imported_name = bindings[base]
                            if allowed_import_targets and str(target_file.resolve()) not in allowed_import_targets:
                                continue
                            imported_symbols = file_symbols.get(str(target_file.resolve()))
                            if imported_symbols is not None:
                                target_id = imported_symbols.top_level_functions.get(attr)
                                if imported_name is not None and target_id is None:
                                    target_id = imported_symbols.class_methods.get(imported_name, {}).get(attr)
                        if target_id is None and base in symbols.class_methods:
                            target_id = symbols.class_methods[base].get(attr)
                if target_id is None or target_id == caller_id:
                    continue
                fingerprint = (caller_id, target_id, "calls")
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                edge = SourceEdge(source_id=caller_id, target_id=target_id, kind="calls", confidence=0.90)
                usg.add_edge(edge)
                edges.append(edge)

    return edges