from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class TemplateASTNode:
    engine: str
    kind: str
    line: int
    column: int
    expression: str


_JINJA_EXPR_RE = re.compile(r"\{\{(?P<expr>.+?)\}\}")
_JINJA_STMT_RE = re.compile(r"\{%\s*(?P<stmt>.+?)\s*%\}")
_HBS_EXPR_RE = re.compile(r"\{\{\s*(?P<expr>[^#/{][^}]*)\s*\}\}")
_HBS_HELPER_RE = re.compile(r"\{\{#(?P<helper>[A-Za-z_$][\w$]*)\b(?P<args>[^}]*)\}\}")
_TAINT_MARKERS_RE = re.compile(
    r"request\.|req\.|params\.|query\.|body\.|cookies\.|headers\.|session\.|user_input|input|args\.",
    re.IGNORECASE,
)


def transpile_templates_to_ast(content: str, *, filename: str = "") -> list[TemplateASTNode]:
    """Extract lightweight template AST nodes from Jinja2/Handlebars syntax."""
    nodes: list[TemplateASTNode] = []
    lines = content.splitlines()
    ext = filename.lower()

    detect_jinja = ext.endswith((".py", ".jinja", ".jinja2", ".j2", ".html", ".htm"))
    detect_hbs = ext.endswith((".js", ".ts", ".jsx", ".tsx", ".hbs", ".handlebars", ".html", ".htm"))

    for line_no, line in enumerate(lines, start=1):
        if detect_jinja:
            for match in _JINJA_EXPR_RE.finditer(line):
                nodes.append(TemplateASTNode(
                    engine="jinja2",
                    kind="expression",
                    line=line_no,
                    column=match.start() + 1,
                    expression=(match.group("expr") or "").strip(),
                ))
            for match in _JINJA_STMT_RE.finditer(line):
                nodes.append(TemplateASTNode(
                    engine="jinja2",
                    kind="statement",
                    line=line_no,
                    column=match.start() + 1,
                    expression=(match.group("stmt") or "").strip(),
                ))

        if detect_hbs:
            for match in _HBS_EXPR_RE.finditer(line):
                nodes.append(TemplateASTNode(
                    engine="handlebars",
                    kind="expression",
                    line=line_no,
                    column=match.start() + 1,
                    expression=(match.group("expr") or "").strip(),
                ))
            for match in _HBS_HELPER_RE.finditer(line):
                args = (match.group("args") or "").strip()
                nodes.append(TemplateASTNode(
                    engine="handlebars",
                    kind="helper",
                    line=line_no,
                    column=match.start() + 1,
                    expression=f"{match.group('helper')} {args}".strip(),
                ))

    return nodes


def template_taint_nodes(content: str, *, filename: str = "") -> list[TemplateASTNode]:
    """Return template nodes with taint-like marker references."""
    return [
        node
        for node in transpile_templates_to_ast(content, filename=filename)
        if _TAINT_MARKERS_RE.search(node.expression)
    ]
