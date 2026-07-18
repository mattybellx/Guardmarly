"""
guardmarly.v2.normalizer
────────────────────────────
Language-specific AST → normalized ASTNode conversion layer (Phase 1 §1.2).

This module maps raw Python ``ast`` nodes (and, when tree-sitter is
available, tree-sitter nodes for JS/TS) to the shared ASTNode vocabulary
defined in ``guardmarly.v2.nodes``.

Tree-sitter is an *optional* dependency.  When unavailable the JS/TS
normalizer falls back to a regex-assisted heuristic pass identical in
spirit to the existing ``js_ast_analyzer.py`` approach, but emitting
normalized nodes.

Design contract:
  - Input:  source text + file path
  - Output: SemanticModel (pre-indexed; raw AST discarded)
  - No tree-sitter types may appear in the returned SemanticModel.
"""
from __future__ import annotations

import ast as _ast
import gc
import logging
import re
from pathlib import Path
from typing import Optional

from guardmarly.v2.nodes import (
    ASTNode,
    AssignNode,
    AttributeAccessNode,
    CallNode,
    ClassDefNode,
    FormattedStringNode,
    FuncDefNode,
    ImportNode,
    ReturnNode,
    SourceLocation,
)
from guardmarly.v2.model import SemanticModel
from guardmarly.v2.suppression import parse_suppressions

_log = logging.getLogger(__name__)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _loc(file_path: str, node: _ast.AST) -> SourceLocation:
    return SourceLocation(
        file_path=file_path,
        line=getattr(node, "lineno", 0),
        column=getattr(node, "col_offset", 0),
    )


def _callee_name(node: _ast.expr) -> str:
    """Extract a dotted callee name from an ast.Call node's func field."""
    if isinstance(node, _ast.Name):
        return node.id
    if isinstance(node, _ast.Attribute):
        prefix = _callee_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _raw_text(node: _ast.AST, source_lines: list[str]) -> str:
    """Return the raw source text for *node* if line info is available."""
    lineno = getattr(node, "lineno", None)
    end_lineno = getattr(node, "end_lineno", lineno)
    if lineno is None:
        return ""
    try:
        if lineno == end_lineno:
            return source_lines[lineno - 1].strip()
        return " ".join(l.strip() for l in source_lines[lineno - 1 : end_lineno])
    except IndexError:
        return ""


def _assign_target_name(target: _ast.expr) -> str:
    if isinstance(target, _ast.Name):
        return target.id
    if isinstance(target, _ast.Attribute):
        return f"{_callee_name(target.value)}.{target.attr}"
    if isinstance(target, _ast.Subscript):
        return _assign_target_name(target.value)
    return ""


def _fstring_parts(node: _ast.JoinedStr) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Extract static text parts and expression repr-strings from an f-string."""
    texts: list[str] = []
    exprs: list[str] = []
    for val in node.values:
        if isinstance(val, _ast.Constant) and isinstance(val.value, str):
            texts.append(val.value)
        elif isinstance(val, _ast.FormattedValue):
            try:
                exprs.append(_ast.unparse(val.value))
            except Exception:
                exprs.append("<expr>")
    return tuple(texts), tuple(exprs)


# ── Python normalizer ──────────────────────────────────────────────────────────

class PythonNormalizer:
    """Walk a Python AST and emit normalized ASTNodes into a SemanticModel."""

    def normalize(self, source: str, file_path: str) -> SemanticModel:
        model = SemanticModel(file_path=file_path, language="python")
        suppressed = parse_suppressions(source, file_path)
        model.suppressed_lines = suppressed

        try:
            tree = _ast.parse(source, filename=file_path, type_comments=False)
        except SyntaxError as exc:
            model.parse_error = f"SyntaxError: {exc}"
            return model

        source_lines = source.splitlines()

        for node in _ast.walk(tree):
            self._visit(node, file_path, source_lines, model)

        del tree
        gc.collect()
        return model

    def _visit(
        self,
        node: _ast.AST,
        file_path: str,
        source_lines: list[str],
        model: SemanticModel,
    ) -> None:
        loc = _loc(file_path, node)
        raw = _raw_text(node, source_lines)

        # ── CALL ──────────────────────────────────────────────────────────────
        if isinstance(node, _ast.Call):
            callee = _callee_name(node.func)
            is_method = isinstance(node.func, _ast.Attribute)
            norm_args = tuple(
                self._expr_to_node(a, file_path, source_lines) for a in node.args
            )
            n = CallNode(
                node_type="CALL",
                location=loc,
                language="python",
                raw_text=raw,
                callee=callee,
                args=norm_args,
                is_method_call=is_method,
            )
            model.add_node(n)

        # ── ASSIGN ────────────────────────────────────────────────────────────
        elif isinstance(node, _ast.Assign):
            for target in node.targets:
                name = _assign_target_name(target)
                val_node = self._expr_to_node(node.value, file_path, source_lines)
                n = AssignNode(
                    node_type="ASSIGN",
                    location=loc,
                    language="python",
                    raw_text=raw,
                    target=name,
                    value=val_node,
                )
                model.add_node(n)
                if name:
                    model.scope_map.setdefault(name, []).append(n)

        elif isinstance(node, _ast.AnnAssign) and node.value is not None:
            name = _assign_target_name(node.target)
            val_node = self._expr_to_node(node.value, file_path, source_lines)
            n = AssignNode(
                node_type="ASSIGN",
                location=loc,
                language="python",
                raw_text=raw,
                target=name,
                value=val_node,
            )
            model.add_node(n)
            if name:
                model.scope_map.setdefault(name, []).append(n)

        # ── IMPORT ────────────────────────────────────────────────────────────
        elif isinstance(node, _ast.Import):
            for alias in node.names:
                n = ImportNode(
                    node_type="IMPORT",
                    location=loc,
                    language="python",
                    raw_text=raw,
                    module=alias.name,
                    names=(alias.name,),
                    alias_map=((alias.name, alias.asname or alias.name),),
                )
                model.add_node(n)
                model.imports.append(n)

        elif isinstance(node, _ast.ImportFrom):
            module = node.module or ""
            names = tuple(a.name for a in node.names)
            alias_map = tuple((a.name, a.asname or a.name) for a in node.names)
            n = ImportNode(
                node_type="IMPORT",
                location=loc,
                language="python",
                raw_text=raw,
                module=module,
                names=names,
                alias_map=alias_map,
            )
            model.add_node(n)
            model.imports.append(n)

        # ── RETURN ────────────────────────────────────────────────────────────
        elif isinstance(node, _ast.Return):
            val_node = (
                self._expr_to_node(node.value, file_path, source_lines)
                if node.value is not None
                else None
            )
            model.add_node(ReturnNode(
                node_type="RETURN",
                location=loc,
                language="python",
                raw_text=raw,
                value=val_node,
            ))

        # ── FORMATTED_STRING (f-string) ───────────────────────────────────────
        elif isinstance(node, _ast.JoinedStr):
            parts, exprs = _fstring_parts(node)
            model.add_node(FormattedStringNode(
                node_type="FORMATTED_STRING",
                location=loc,
                language="python",
                raw_text=raw,
                parts=parts,
                expressions=exprs,
            ))

        # ── ATTRIBUTE_ACCESS ──────────────────────────────────────────────────
        elif isinstance(node, _ast.Attribute):
            obj = _callee_name(node.value)
            model.add_node(AttributeAccessNode(
                node_type="ATTRIBUTE_ACCESS",
                location=loc,
                language="python",
                raw_text=raw,
                object_name=obj,
                attribute=node.attr,
            ))

        # ── FUNC_DEF ──────────────────────────────────────────────────────────
        elif isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
            params = tuple(a.arg for a in node.args.args)
            decorators = tuple(
                (_callee_name(d) if isinstance(d, (_ast.Name, _ast.Attribute)) else _ast.unparse(d))
                for d in node.decorator_list
            )
            fn = FuncDefNode(
                node_type="FUNC_DEF",
                location=loc,
                language="python",
                raw_text=raw,
                name=node.name,
                params=params,
                decorators=decorators,
                is_async=isinstance(node, _ast.AsyncFunctionDef),
            )
            model.add_node(fn)
            model.functions.append(fn)

        # ── CLASS_DEF ─────────────────────────────────────────────────────────
        elif isinstance(node, _ast.ClassDef):
            bases = tuple(
                _callee_name(b) if isinstance(b, (_ast.Name, _ast.Attribute)) else ""
                for b in node.bases
            )
            decorators = tuple(
                _callee_name(d) if isinstance(d, (_ast.Name, _ast.Attribute)) else ""
                for d in node.decorator_list
            )
            model.add_node(ClassDefNode(
                node_type="CLASS_DEF",
                location=loc,
                language="python",
                raw_text=raw,
                name=node.name,
                bases=bases,
                decorators=decorators,
            ))

    def _expr_to_node(
        self,
        expr: _ast.expr,
        file_path: str,
        source_lines: list[str],
    ) -> ASTNode:
        """Shallow conversion of an expression to an ASTNode for use as a child."""
        loc = _loc(file_path, expr)
        raw = _raw_text(expr, source_lines)
        if isinstance(expr, _ast.Call):
            callee = _callee_name(expr.func)
            return CallNode(
                node_type="CALL",
                location=loc,
                language="python",
                raw_text=raw,
                callee=callee,
                args=(),
                is_method_call=isinstance(expr.func, _ast.Attribute),
            )
        if isinstance(expr, _ast.Attribute):
            return AttributeAccessNode(
                node_type="ATTRIBUTE_ACCESS",
                location=loc,
                language="python",
                raw_text=raw,
                object_name=_callee_name(expr.value),
                attribute=expr.attr,
            )
        if isinstance(expr, _ast.JoinedStr):
            parts, exprs = _fstring_parts(expr)
            return FormattedStringNode(
                node_type="FORMATTED_STRING",
                location=loc,
                language="python",
                raw_text=raw,
                parts=parts,
                expressions=exprs,
            )
        return ASTNode(
            node_type="EXPR",
            location=loc,
            language="python",
            raw_text=raw,
        )


# ── JS/TS normalizer ───────────────────────────────────────────────────────────

# Attempt to import tree-sitter.  When missing, fall back to a lightweight
# regex-based heuristic pass.
try:
    import tree_sitter  # type: ignore[import-untyped]
    _HAS_TREE_SITTER = True
except ImportError:
    _HAS_TREE_SITTER = False
    _log.debug(
        "tree-sitter not installed; JS/TS normalization falls back to heuristic mode. "
        "Install with: pip install guardmarly[treesitter]"
    )

# Regex patterns for heuristic JS normalizer
_JS_CALL_RE = re.compile(
    r"""(?P<callee>[\w$][\w.$]*)\s*\(""",
    re.MULTILINE,
)
_JS_IMPORT_RE = re.compile(
    r"""(?:import\s+.*?\s+from\s+['"]([\w./\-@]+)['"]|require\s*\(\s*['"]([\w./\-@]+)['"]\s*\))""",
    re.MULTILINE,
)
_JS_ASSIGN_RE = re.compile(
    r"""(?:const|let|var)\s+([\w$]+)\s*=\s*(.+?)(?:;|$)""",
    re.MULTILINE,
)


class JsTsNormalizer:
    """
    Normalize JavaScript / TypeScript / JSX source to the shared ASTNode vocabulary.

    When tree-sitter is installed, raw parse trees are produced and then
    converted.  When unavailable, a best-effort regex heuristic is used.
    """

    def normalize(self, source: str, file_path: str) -> SemanticModel:
        ext = Path(file_path).suffix.lower()
        language = (
            "typescript" if ext in {".ts", ".tsx"}
            else "jsx" if ext == ".jsx"
            else "javascript"
        )
        model = SemanticModel(file_path=file_path, language=language)
        suppressed = parse_suppressions(source, file_path)
        model.suppressed_lines = suppressed

        if _HAS_TREE_SITTER:
            self._normalize_with_tree_sitter(source, file_path, language, model)
        else:
            self._normalize_heuristic(source, file_path, language, model)

        return model

    # ── tree-sitter path ──────────────────────────────────────────────────────

    def _normalize_with_tree_sitter(
        self,
        source: str,
        file_path: str,
        language: str,
        model: SemanticModel,
    ) -> None:
        """Full tree-sitter backed normalization."""
        try:
            self._ts_normalize(source, file_path, language, model)
        except Exception as exc:  # noqa: BLE001
            _log.warning("tree-sitter normalization failed for %s: %s", file_path, exc)
            self._normalize_heuristic(source, file_path, language, model)

    def _ts_normalize(
        self,
        source: str,
        file_path: str,
        language: str,
        model: SemanticModel,
    ) -> None:
        """Internal tree-sitter normalization.  Requires tree_sitter installed."""
        try:
            if language in ("typescript", "jsx"):
                from tree_sitter_languages import get_language, get_parser  # type: ignore
                ts_lang = "tsx" if language in ("typescript", "jsx") else "javascript"
                parser = get_parser(ts_lang)
            else:
                from tree_sitter_languages import get_parser  # type: ignore
                parser = get_parser("javascript")
        except ImportError:
            # tree_sitter_languages not available; try bare tree-sitter
            try:
                import tree_sitter as _ts
                # Build a minimal parser — language grammar may not be pre-compiled
                parser = _ts.Parser()
            except Exception:
                self._normalize_heuristic(source, file_path, language, model)
                return

        source_bytes = source.encode("utf-8", errors="replace")
        tree = parser.parse(source_bytes)
        source_lines = source.splitlines()

        self._walk_ts_node(tree.root_node, file_path, language, source_lines, source_bytes, model)

        del tree
        gc.collect()

    def _walk_ts_node(
        self,
        node,  # tree_sitter.Node
        file_path: str,
        language: str,
        source_lines: list[str],
        source_bytes: bytes,
        model: SemanticModel,
    ) -> None:
        """Recursively walk a tree-sitter node tree."""
        ntype = node.type

        loc = SourceLocation(
            file_path=file_path,
            line=node.start_point[0] + 1,
            column=node.start_point[1],
        )
        raw = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace").strip()[:200]

        if ntype in ("call_expression", "new_expression"):
            func_node = node.child_by_field_name("function") or node.child_by_field_name("constructor")
            callee = (
                source_bytes[func_node.start_byte:func_node.end_byte].decode("utf-8", errors="replace").strip()
                if func_node else ""
            )
            is_method = "." in callee
            model.add_node(CallNode(
                node_type="CALL",
                location=loc,
                language=language,
                raw_text=raw,
                callee=callee,
                args=(),
                is_method_call=is_method,
            ))

        elif ntype in ("variable_declarator", "assignment_expression", "lexical_declaration"):
            name_node = node.child_by_field_name("name") or node.child_by_field_name("left")
            name = (
                source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace").strip()
                if name_node else ""
            )
            if name:
                model.add_node(AssignNode(
                    node_type="ASSIGN",
                    location=loc,
                    language=language,
                    raw_text=raw,
                    target=name,
                ))
                model.scope_map.setdefault(name, []).append(
                    ASTNode(node_type="EXPR", location=loc, language=language, raw_text=raw)
                )

        elif ntype in ("import_statement", "import_declaration"):
            src_node = node.child_by_field_name("source")
            module = (
                source_bytes[src_node.start_byte:src_node.end_byte].decode("utf-8", errors="replace").strip().strip("'\"")
                if src_node else ""
            )
            n = ImportNode(
                node_type="IMPORT",
                location=loc,
                language=language,
                raw_text=raw,
                module=module,
                names=(),
            )
            model.add_node(n)
            model.imports.append(n)

        elif ntype in ("function_declaration", "arrow_function", "function_expression", "method_definition"):
            name_node = node.child_by_field_name("name")
            name = (
                source_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace").strip()
                if name_node else "<anonymous>"
            )
            fn = FuncDefNode(
                node_type="FUNC_DEF",
                location=loc,
                language=language,
                raw_text=raw,
                name=name,
                is_async="async" in raw[:20],
            )
            model.add_node(fn)
            model.functions.append(fn)

        elif ntype in ("member_expression", "subscript_expression"):
            parts = raw.split(".", 1)
            obj = parts[0].strip() if len(parts) > 1 else ""
            attr = parts[1].strip() if len(parts) > 1 else raw.strip()
            model.add_node(AttributeAccessNode(
                node_type="ATTRIBUTE_ACCESS",
                location=loc,
                language=language,
                raw_text=raw,
                object_name=obj,
                attribute=attr,
            ))

        elif ntype == "return_statement":
            model.add_node(ReturnNode(
                node_type="RETURN",
                location=loc,
                language=language,
                raw_text=raw,
            ))

        elif ntype == "template_string":
            model.add_node(FormattedStringNode(
                node_type="FORMATTED_STRING",
                location=loc,
                language=language,
                raw_text=raw,
                expressions=(),
            ))

        for child in node.children:
            self._walk_ts_node(child, file_path, language, source_lines, source_bytes, model)

    # ── Heuristic fallback ────────────────────────────────────────────────────

    def _normalize_heuristic(
        self,
        source: str,
        file_path: str,
        language: str,
        model: SemanticModel,
    ) -> None:
        """Regex-based JS normalization used when tree-sitter is absent."""
        source_lines = source.splitlines()

        for m in _JS_CALL_RE.finditer(source):
            start = source[:m.start()].count("\n") + 1
            loc = SourceLocation(file_path=file_path, line=start, column=m.start(0) - source.rfind("\n", 0, m.start(0)) - 1)
            callee = m.group("callee")
            raw = source_lines[start - 1].strip()[:200] if 0 < start <= len(source_lines) else ""
            model.add_node(CallNode(
                node_type="CALL",
                location=loc,
                language=language,
                raw_text=raw,
                callee=callee,
                is_method_call="." in callee,
            ))

        for m in _JS_IMPORT_RE.finditer(source):
            start = source[:m.start()].count("\n") + 1
            loc = SourceLocation(file_path=file_path, line=start, column=0)
            module = m.group(1) or m.group(2) or ""
            raw = source_lines[start - 1].strip()[:200] if 0 < start <= len(source_lines) else ""
            n = ImportNode(
                node_type="IMPORT",
                location=loc,
                language=language,
                raw_text=raw,
                module=module,
                names=(),
            )
            model.add_node(n)
            model.imports.append(n)

        for m in _JS_ASSIGN_RE.finditer(source):
            start = source[:m.start()].count("\n") + 1
            loc = SourceLocation(file_path=file_path, line=start, column=0)
            name = m.group(1)
            raw = source_lines[start - 1].strip()[:200] if 0 < start <= len(source_lines) else ""
            n = AssignNode(
                node_type="ASSIGN",
                location=loc,
                language=language,
                raw_text=raw,
                target=name,
            )
            model.add_node(n)
            model.scope_map.setdefault(name, []).append(n)


# ── Public normalizer factory ──────────────────────────────────────────────────

_python_normalizer = PythonNormalizer()
_js_normalizer = JsTsNormalizer()

_PYTHON_EXTS = frozenset({".py", ".pyw"})
_JS_EXTS = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})


def normalize_file(file_path: str, source: Optional[str] = None) -> SemanticModel:
    """
    Normalize a source file to a SemanticModel.

    If *source* is not supplied the file is read from disk.
    Returns a model with ``parse_error`` set when reading or parsing fails.
    """
    path = Path(file_path)
    ext = path.suffix.lower()

    if source is None:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            lang = "python" if ext in _PYTHON_EXTS else "javascript"
            return SemanticModel.error(file_path, lang, str(exc))

    if ext in _PYTHON_EXTS:
        return _python_normalizer.normalize(source, file_path)
    if ext in _JS_EXTS:
        return _js_normalizer.normalize(source, file_path)

    return SemanticModel.error(file_path, "unknown", f"Unsupported file type: {ext}")


def normalize_source(source: str, file_path: str, language: str) -> SemanticModel:
    """
    Normalize a string of source code using the given language hint.

    Useful for stdin analysis where the file extension is not available.
    """
    if language == "python":
        return _python_normalizer.normalize(source, file_path)
    if language in ("javascript", "typescript", "jsx"):
        return _js_normalizer.normalize(source, file_path)
    return SemanticModel.error(file_path, language, f"No normalizer for language: {language}")
