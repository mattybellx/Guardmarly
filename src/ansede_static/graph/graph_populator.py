"""Populate SQLite GraphStore from Rust/Tree-sitter parse output."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ansede_static.graph.sqlite_graph import GraphStore


def populate_from_flat_table(store: GraphStore, flat: dict[str, Any],
                             file_path: str) -> int:
    """Populate store from a flat table parse result.
    Returns the file_id.
    """
    nodes_list = flat.get("nodes", [])
    if not nodes_list:
        return 0

    file_id = store.add_file(file_path, flat.get("language", "unknown"),
                             lines=flat.get("lines_scanned", 0))
    if not file_id:
        return 0

    # Build lookup: flat node id -> db node id
    id_map: dict[int, int] = {}

    # First pass: insert all nodes (need IDs for parent references)
    for n in nodes_list:
        nid = n["id"]
        ntype = _infer_node_type(n)
        parent_nid = n.get("parent_id", 0)
        parent_dbid = id_map.get(parent_nid) if parent_nid else None
        db_id = store.add_node(
            file_id=file_id,
            node_type=ntype,
            name=_infer_name(n),
            kind=n.get("kind", ""),
            start_line=n.get("start_line", 1),
            end_line=n.get("end_line", 1),
            parent_id=parent_dbid,
            depth=n.get("depth", 0),
        )
        id_map[nid] = db_id

    # Second pass: create additional containment edges for non-direct-parent refs
    for n in nodes_list:
        nid = n["id"]
        parent_id = n.get("parent_id", 0)
        if parent_id and parent_id != nid and parent_id in id_map and nid in id_map:
            # Already handled via parent_id ref, but add explicit edge for querying
            if parent_id in id_map and nid in id_map:
                store.add_edge(
                    source_id=id_map[parent_id],
                    target_id=id_map[nid],
                    edge_type="contains",
                    confidence=1.0,
                )

    return file_id


def _infer_node_type(n: dict[str, Any]) -> str:
    """Infer the node_type from tree-sitter AST kind."""
    kind = n.get("kind", "")
    n.get("text", "")
    depth = n.get("depth", 0)

    # Deep leaves with literal values
    if depth > 1 and kind in ("identifier", "string", "number", "true", "false", "null"):
        return "literal"
    if kind in ("function_definition", "method_definition"):
        return "function"
    if kind in ("class_definition", "class_declaration"):
        return "class"
    if kind in ("call", "call_expression"):
        return "call"
    if kind in ("import_statement", "import_from_statement", "import_declaration"):
        return "import"
    if kind in ("assignment", "variable_declaration", "let_declaration", "const_declaration"):
        return "variable"
    if depth == 0:
        return "root"
    return "other"


def _infer_name(n: dict[str, Any]) -> str:
    """Try to extract a meaningful name from a node."""
    text = n.get("text", "")
    kind = n.get("kind", "")
    if kind in ("function_definition", "method_definition", "class_definition",
                "class_declaration"):
        # First child is usually the name identifier
        return text.split("(")[0].split()[1] if " " in text and "(" in text else text[:40]
    if kind in ("call", "call_expression"):
        return text.split("(")[0][:40]
    return text[:60]
