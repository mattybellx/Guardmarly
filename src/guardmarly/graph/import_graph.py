"""Import graph resolution for Python, JS/TS, and Go source trees."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from guardmarly.graph.unified_source_graph import SourceEdge, SourceNode, UnifiedSourceGraph

_PYTHON_SUFFIXES = {".py"}
_JS_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".mts", ".cjs", ".cts"}
_GO_SUFFIXES = {".go"}

_JS_IMPORT_RE = re.compile(
    r"(?:import\s+(?:[^\n;]+?\s+from\s+)?|export\s+[^\n;]+?\s+from\s+|require\s*\(|import\s*\()\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)

_GO_SINGLE_IMPORT_RE = re.compile(r'^\s*import\s+(?:[a-zA-Z_][\w]*\s+)?"([^"]+)"', re.MULTILINE)
_GO_BLOCK_IMPORT_RE = re.compile(r'import\s*\((.*?)\)', re.DOTALL | re.MULTILINE)
_GO_IMPORT_ENTRY_RE = re.compile(r'(?:(?:[a-zA-Z_][\w]*)\s+)?"([^"]+)"')


def _node_id_for_file(path: Path) -> str:
    return f"file://{path.resolve().as_posix()}#file"


def _language_for_path(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".py":
        return "python"
    if suffix in {".ts", ".tsx", ".mts", ".cts"}:
        return "typescript"
    if suffix in {".js", ".jsx", ".mjs", ".cjs"}:
        return "javascript"
    if suffix == ".go":
        return "go"
    return "unknown"


def _ensure_file_node(usg: UnifiedSourceGraph | None, path: Path) -> None:
    if usg is None:
        return
    node_id = _node_id_for_file(path)
    if node_id not in usg.nodes:
        usg.add_node(SourceNode(
            id=node_id,
            kind="file",
            name=path.name,
            file_path=str(path.resolve()),
            language=_language_for_path(path),
            start_line=1,
            end_line=0,
        ))


def _add_import_edge(usg: UnifiedSourceGraph | None, source: Path, target: Path, confidence: float = 1.0) -> SourceEdge:
    edge = SourceEdge(
        source_id=_node_id_for_file(source),
        target_id=_node_id_for_file(target),
        kind="imports",
        confidence=confidence,
    )
    if usg is not None:
        _ensure_file_node(usg, source)
        _ensure_file_node(usg, target)
        usg.add_edge(edge)
    return edge


def _iter_files(root_dir: Path, suffixes: set[str]) -> list[Path]:
    return sorted(
        path for path in root_dir.rglob("*")
        if path.is_file() and path.suffix.lower() in suffixes
    )


def _python_module_name(root_dir: Path, file_path: Path) -> str:
    rel = file_path.relative_to(root_dir)
    if rel.name == "__init__.py":
        parts = rel.parts[:-1]
    else:
        parts = rel.with_suffix("").parts
    return ".".join(parts)


def _build_python_module_index(root_dir: Path) -> dict[str, Path]:
    index: dict[str, Path] = {}
    for file_path in _iter_files(root_dir, _PYTHON_SUFFIXES):
        module_name = _python_module_name(root_dir, file_path)
        if module_name:
            index[module_name] = file_path.resolve()
    return index


def _resolve_python_base_module(current_module: str, level: int, module_name: str, is_package: bool) -> str:
    current_parts = [part for part in current_module.split(".") if part]
    package_parts = current_parts if is_package else current_parts[:-1]
    if level > 0:
        trim = max(level - 1, 0)
        if trim:
            package_parts = package_parts[:-trim] if trim <= len(package_parts) else []
    if module_name:
        return ".".join([*package_parts, *module_name.split(".")])
    return ".".join(package_parts)


def resolve_python_imports(root_dir: str | Path, usg: UnifiedSourceGraph | None = None) -> list[SourceEdge]:
    """Build import edges for Python files in *root_dir*."""
    root = Path(root_dir).resolve()
    module_index = _build_python_module_index(root)
    edges: list[SourceEdge] = []
    seen: set[tuple[str, str]] = set()

    for file_path in _iter_files(root, _PYTHON_SUFFIXES):
        _ensure_file_node(usg, file_path)
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(file_path))
        except (OSError, SyntaxError, ValueError):
            continue

        current_module = _python_module_name(root, file_path)
        is_package = file_path.name == "__init__.py"
        for node in ast.walk(tree):
            resolved_targets: list[Path] = []
            if isinstance(node, ast.Import):
                for alias in node.names:
                    target = module_index.get(alias.name)
                    if target is not None:
                        resolved_targets.append(target)
            elif isinstance(node, ast.ImportFrom):
                base_module = _resolve_python_base_module(current_module, node.level, node.module or "", is_package)
                candidates: list[str] = []
                if base_module:
                    candidates.append(base_module)
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    if base_module:
                        candidates.append(f"{base_module}.{alias.name}")
                    else:
                        candidates.append(alias.name)
                for candidate in candidates:
                    target = module_index.get(candidate)
                    if target is not None:
                        resolved_targets.append(target)
                        break

            for target in resolved_targets:
                fingerprint = (str(file_path.resolve()), str(target))
                if fingerprint in seen or Path(target) == file_path.resolve():
                    continue
                seen.add(fingerprint)
                edges.append(_add_import_edge(usg, file_path.resolve(), Path(target)))

    return edges


def _load_tsconfig_aliases(root_dir: Path) -> tuple[str, dict[str, list[str]]]:
    tsconfig = root_dir / "tsconfig.json"
    if not tsconfig.exists():
        return ".", {}
    try:
        payload = json.loads(tsconfig.read_text(encoding="utf-8"))
        compiler = payload.get("compilerOptions", {}) if isinstance(payload, dict) else {}
        base_url = str(compiler.get("baseUrl", "."))
        paths = compiler.get("paths", {})
        if isinstance(paths, dict):
            alias_map = {str(key): [str(item) for item in value] for key, value in paths.items() if isinstance(value, list)}
            return base_url, alias_map
    except Exception:
        pass
    return ".", {}


def _resolve_js_candidate(base_path: Path) -> Path | None:
    candidates = [
        base_path,
        *[base_path.with_suffix(ext) for ext in [".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs"]],
        *[(base_path / f"index{ext}") for ext in [".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs"]],
    ]
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return candidate.resolve()
    return None


def _resolve_js_module(module_name: str, importer: Path, root_dir: Path, base_url: str, alias_map: dict[str, list[str]]) -> Path | None:
    if module_name.startswith("."):
        return _resolve_js_candidate((importer.parent / module_name).resolve())

    for pattern, targets in alias_map.items():
        if "*" in pattern:
            prefix, suffix = pattern.split("*", 1)
            if not module_name.startswith(prefix):
                continue
            if suffix and not module_name.endswith(suffix):
                continue
            middle = module_name[len(prefix): len(module_name) - len(suffix) if suffix else None]
            for target in targets:
                candidate_rel = target.replace("*", middle)
                resolved = _resolve_js_candidate((root_dir / base_url / candidate_rel).resolve())
                if resolved is not None:
                    return resolved
        elif module_name == pattern:
            for target in targets:
                resolved = _resolve_js_candidate((root_dir / base_url / target).resolve())
                if resolved is not None:
                    return resolved
    return None


def resolve_js_imports(root_dir: str | Path, usg: UnifiedSourceGraph | None = None) -> list[SourceEdge]:
    """Build import edges for JavaScript/TypeScript files in *root_dir*."""
    root = Path(root_dir).resolve()
    base_url, alias_map = _load_tsconfig_aliases(root)
    edges: list[SourceEdge] = []
    seen: set[tuple[str, str]] = set()

    for file_path in _iter_files(root, _JS_SUFFIXES):
        _ensure_file_node(usg, file_path)
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in _JS_IMPORT_RE.finditer(content):
            module_name = match.group(1)
            target = _resolve_js_module(module_name, file_path.resolve(), root, base_url, alias_map)
            if target is None or target == file_path.resolve():
                continue
            fingerprint = (str(file_path.resolve()), str(target))
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            confidence = 0.95 if not module_name.startswith(".") else 1.0
            edges.append(_add_import_edge(usg, file_path.resolve(), target, confidence=confidence))

    return edges


def _go_module_name(root_dir: Path) -> str:
    go_mod = root_dir / "go.mod"
    if not go_mod.exists():
        return ""
    try:
        for line in go_mod.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if stripped.startswith("module "):
                return stripped.split(None, 1)[1].strip()
    except OSError:
        pass
    return ""


def _build_go_package_index(root_dir: Path, module_name: str) -> dict[str, Path]:
    index: dict[str, Path] = {}
    package_dirs: dict[Path, list[Path]] = {}
    for file_path in _iter_files(root_dir, _GO_SUFFIXES):
        package_dirs.setdefault(file_path.parent.resolve(), []).append(file_path.resolve())
    for directory, files in package_dirs.items():
        rel = directory.relative_to(root_dir)
        import_path = module_name if str(rel) == "." else f"{module_name}/{rel.as_posix()}"
        index[import_path] = sorted(files)[0]
    return index


def _extract_go_imports(content: str) -> list[str]:
    imports = [match.group(1) for match in _GO_SINGLE_IMPORT_RE.finditer(content)]
    for block in _GO_BLOCK_IMPORT_RE.finditer(content):
        imports.extend(match.group(1) for match in _GO_IMPORT_ENTRY_RE.finditer(block.group(1)))
    return imports


def resolve_go_imports(root_dir: str | Path, usg: UnifiedSourceGraph | None = None) -> list[SourceEdge]:
    """Build import edges for local Go packages under *root_dir*."""
    root = Path(root_dir).resolve()
    module_name = _go_module_name(root)
    if not module_name:
        return []
    package_index = _build_go_package_index(root, module_name)
    edges: list[SourceEdge] = []
    seen: set[tuple[str, str]] = set()

    for file_path in _iter_files(root, _GO_SUFFIXES):
        _ensure_file_node(usg, file_path)
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for import_path in _extract_go_imports(content):
            target = package_index.get(import_path)
            if target is None or target == file_path.resolve():
                continue
            fingerprint = (str(file_path.resolve()), str(target))
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            edges.append(_add_import_edge(usg, file_path.resolve(), target))

    return edges
