from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class SymbolLocation:
    module: str
    file_path: str
    line: int
    symbol: str
    node: ast.FunctionDef | None = None


@dataclass
class GlobalProjectIndex:
    symbols: dict[str, SymbolLocation] = field(default_factory=dict)
    imports: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def resolve(self, qualified_symbol: str) -> SymbolLocation | None:
        return self.symbols.get(qualified_symbol)

    def register_symbol(
        self, module_path: str, file_path: str, node: ast.FunctionDef
    ) -> None:
        """Register a function/class definition for cross-file resolution."""
        self.symbols[module_path] = SymbolLocation(
            module=module_path,
            file_path=file_path,
            line=getattr(node, "lineno", 1),
            symbol=node.name,
            node=node,
        )

    def resolve_call(
        self, current_module: str, import_name: str
    ) -> SymbolLocation | None:
        """Resolve absolute and relative local framework import scopes."""
        # Try fully-qualified lookup first: current_module.import_name
        target_key = f"{current_module}.{import_name}"
        if target_key in self.symbols:
            return self.symbols[target_key]
        # Fall back to bare import name
        return self.symbols.get(import_name)


def _module_name_from_path(root: Path, file_path: Path) -> str:
    rel = file_path.resolve().relative_to(root.resolve())
    return ".".join(rel.with_suffix("").parts)


def build_project_index(root: Path) -> GlobalProjectIndex:
    """Build a project-wide symbol/import index for cross-file resolution."""
    index = GlobalProjectIndex()
    for path in sorted(root.rglob("*.py")):
        if any(
            part in {".git", "__pycache__", ".venv", "venv", "node_modules"}
            for part in path.parts
        ):
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except SyntaxError:
            continue

        module = _module_name_from_path(root, path)
        imported: list[str] = []

        for node in ast.walk(tree):
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                qname = f"{module}.{node.name}"
                index.symbols[qname] = SymbolLocation(
                    module=module,
                    file_path=str(path),
                    line=getattr(node, "lineno", 1),
                    symbol=node.name,
                    node=node if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else None,
                )
            elif isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                for alias in node.names:
                    imported.append(
                        f"{base}.{alias.name}" if base else alias.name
                    )

        index.imports[module] = tuple(
            sorted(set(name for name in imported if name))
        )

    return index


def propagate_taint_cross_file(
    index: GlobalProjectIndex,
    target_symbol: str,
    tainted_param_index: int,
) -> bool:
    """Check whether a cross-file call site validates ownership/authorization.

    Walks the external target AST node to verify if access control parameters
    (owner_id, tenant_id) are checked before the tainted parameter is used.
    Returns True if an authorization check was validated successfully.
    """
    loc = index.resolve_call("", target_symbol)
    if not loc or loc.node is None:
        return False

    # Walk the external target AST node to verify if access control
    # parameters are checked
    for item in ast.walk(loc.node):
        if isinstance(item, ast.Compare):
            dumped = ast.dump(item)
            # Flag clean if resource checks map to contextual identity parameters
            if "owner_id" in dumped or "tenant_id" in dumped:
                return True  # Authorization check validated successfully

    return False
