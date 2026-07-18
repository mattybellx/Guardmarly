"""guardmarly.graph.sqlite_graph — SQLite Relational Call Graph.

Replaces in-memory graph structures with SQLite B-Tree schemas, enabling
Recursive CTE queries for multi-hop taint-flow traces and fast delta scans.

Schema:
  - files:  tracked source files with metadata
  - nodes:  AST nodes (functions, calls, variables, etc.)
  - edges:  relationships between nodes (calls, data_flow, taint, imports)
  - taint_sources: known taint sources (user input functions)
  - taint_sinks:   known taint sinks (dangerous functions)
"""
from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

# ── Schema ───────────────────────────────────────────────────────────

SCHEMA_VERSION = 1

CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS _meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    path        TEXT UNIQUE NOT NULL,
    language    TEXT NOT NULL,
    lines       INTEGER NOT NULL DEFAULT 0,
    size_bytes  INTEGER NOT NULL DEFAULT 0,
    sha256      TEXT,
    scanned_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS nodes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id     INTEGER NOT NULL REFERENCES files(id),
    node_type   TEXT NOT NULL,       -- 'function', 'call', 'variable', 'class', 'import', 'literal'
    name        TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL DEFAULT '',  -- tree-sitter AST kind
    signature   TEXT NOT NULL DEFAULT '',
    start_line  INTEGER NOT NULL DEFAULT 0,
    end_line    INTEGER NOT NULL DEFAULT 0,
    parent_id   INTEGER REFERENCES nodes(id),
    depth       INTEGER NOT NULL DEFAULT 0,
    meta_json   TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_nodes_file ON nodes(file_id);
CREATE INDEX IF NOT EXISTS idx_nodes_name ON nodes(name);
CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(node_type);
CREATE INDEX IF NOT EXISTS idx_nodes_parent ON nodes(parent_id);

CREATE TABLE IF NOT EXISTS edges (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id   INTEGER NOT NULL REFERENCES nodes(id),
    target_id   INTEGER NOT NULL REFERENCES nodes(id),
    edge_type   TEXT NOT NULL,       -- 'calls', 'data_flow', 'taint', 'imports', 'defines', 'contains'
    confidence  REAL NOT NULL DEFAULT 1.0,
    meta_json   TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source_id);
CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target_id);
CREATE INDEX IF NOT EXISTS idx_edges_type ON edges(edge_type);

CREATE TABLE IF NOT EXISTS taint_flows (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_node_id INTEGER NOT NULL REFERENCES nodes(id),
    sink_node_id   INTEGER NOT NULL REFERENCES nodes(id),
    path_json   TEXT NOT NULL,       -- JSON array of edge IDs forming the path
    path_len    INTEGER NOT NULL,
    confidence  REAL NOT NULL DEFAULT 1.0,
    cwe         TEXT NOT NULL DEFAULT 'CWE-0',
    discovered_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_taint_source ON taint_flows(source_node_id);
CREATE INDEX IF NOT EXISTS idx_taint_sink ON taint_flows(sink_node_id);
"""


# ── GraphStore ───────────────────────────────────────────────────────

class GraphStore:
    """SQLite-backed relational call graph store.

    Usage:
        store = GraphStore(":memory:")  # or a file path
        store.migrate()
        file_id = store.add_file("src/main.py", "python", 100)
        node_id = store.add_node(file_id, "function", "get_user", ...)
        ...
        paths = store.find_taint_paths()
    """

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._db_path = str(db_path)
        self._conn: sqlite3.Connection | None = None
        self._batch_nodes: list[tuple] = []
        self._batch_edges: list[tuple] = []
        self._BATCH_SIZE = 1000

    # ── Connection ───────────────────────────────────────────────────

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self._db_path)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def close(self) -> None:
        self.flush_batch()
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> GraphStore:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # ── Migration ────────────────────────────────────────────────────

    def migrate(self) -> None:
        """Run schema migrations to bring the database up to date."""
        self.conn.executescript(CREATE_TABLES)
        self.conn.execute(
            "INSERT OR REPLACE INTO _meta (key, value) VALUES (?, ?)",
            ("schema_version", str(SCHEMA_VERSION)),
        )
        self.conn.commit()
        _log.debug("SQLite graph schema migrated to v%d", SCHEMA_VERSION)

    # ── File operations ──────────────────────────────────────────────

    def add_file(self, path: str, language: str, lines: int = 0,
                 size_bytes: int = 0, sha256: str | None = None) -> int:
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO files (path, language, lines, size_bytes, sha256) VALUES (?, ?, ?, ?, ?)",
            (path, language, lines, size_bytes, sha256),
        )
        if cur.lastrowid:
            return cur.lastrowid
        row = self.conn.execute("SELECT id FROM files WHERE path = ?", (path,)).fetchone()
        return row["id"] if row else 0

    def get_file(self, file_id: int) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
        return dict(row) if row else None

    def get_file_by_path(self, path: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM files WHERE path = ?", (path,)).fetchone()
        return dict(row) if row else None

    # ── Node operations ──────────────────────────────────────────────

    def add_node(self, file_id: int, node_type: str, name: str = "",
                 kind: str = "", signature: str = "",
                 start_line: int = 0, end_line: int = 0,
                 parent_id: int | None = None, depth: int = 0,
                 meta: dict[str, Any] | None = None) -> int:
        cur = self.conn.execute(
            """INSERT INTO nodes (file_id, node_type, name, kind, signature,
               start_line, end_line, parent_id, depth, meta_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (file_id, node_type, name, kind, signature,
             start_line, end_line, parent_id, depth,
             json.dumps(meta or {})),
        )
        return cur.lastrowid or 0

    def batch_add_node(self, file_id: int, node_type: str, name: str = "",
                       kind: str = "", signature: str = "",
                       start_line: int = 0, end_line: int = 0,
                       parent_id: int | None = None, depth: int = 0,
                       meta: dict[str, Any] | None = None) -> None:
        self._batch_nodes.append(
            (file_id, node_type, name, kind, signature,
             start_line, end_line, parent_id, depth,
             json.dumps(meta or {}))
        )
        if len(self._batch_nodes) >= self._BATCH_SIZE:
            self.flush_batch_nodes()

    def flush_batch_nodes(self) -> None:
        if not self._batch_nodes:
            return
        self.conn.executemany(
            """INSERT INTO nodes (file_id, node_type, name, kind, signature,
               start_line, end_line, parent_id, depth, meta_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            self._batch_nodes,
        )
        self._batch_nodes.clear()

    def flush_batch(self) -> None:
        self.flush_batch_nodes()
        self.flush_batch_edges()

    def get_node(self, node_id: int) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
        return dict(row) if row else None

    # ── Edge operations ──────────────────────────────────────────────

    def add_edge(self, source_id: int, target_id: int, edge_type: str,
                 confidence: float = 1.0, meta: dict[str, Any] | None = None) -> int:
        cur = self.conn.execute(
            "INSERT INTO edges (source_id, target_id, edge_type, confidence, meta_json) VALUES (?, ?, ?, ?, ?)",
            (source_id, target_id, edge_type, confidence, json.dumps(meta or {})),
        )
        return cur.lastrowid or 0

    def batch_add_edge(self, source_id: int, target_id: int, edge_type: str,
                       confidence: float = 1.0, meta: dict[str, Any] | None = None) -> None:
        self._batch_edges.append(
            (source_id, target_id, edge_type, confidence, json.dumps(meta or {}))
        )
        if len(self._batch_edges) >= self._BATCH_SIZE:
            self.flush_batch_edges()

    def flush_batch_edges(self) -> None:
        if not self._batch_edges:
            return
        self.conn.executemany(
            "INSERT INTO edges (source_id, target_id, edge_type, confidence, meta_json) VALUES (?, ?, ?, ?, ?)",
            self._batch_edges,
        )
        self._batch_edges.clear()

    # ── Taint flow recording ─────────────────────────────────────────

    def record_taint_flow(self, source_node_id: int, sink_node_id: int,
                          path: list[int], confidence: float = 1.0,
                          cwe: str = "CWE-0") -> int:
        cur = self.conn.execute(
            """INSERT INTO taint_flows (source_node_id, sink_node_id, path_json,
               path_len, confidence, cwe) VALUES (?, ?, ?, ?, ?, ?)""",
            (source_node_id, sink_node_id, json.dumps(path),
             len(path), confidence, cwe),
        )
        return cur.lastrowid or 0

    # ── Recursive CTE Queries ────────────────────────────────────────

    def find_taint_paths(self, max_depth: int = 10) -> list[dict[str, Any]]:
        """Use recursive CTE to find all taint flow paths up to max_depth.
        Returns list of {source, sink, path, confidence, cwe, edge_types}."""
        query = """
        WITH RECURSIVE taint_path(source_id, target_id, path_json, edge_types, depth) AS (
            -- Base: direct taint edges
            SELECT e.source_id, e.target_id,
                   '[' || e.id || ']',
                   '[' || '"' || e.edge_type || '"' || ']',
                   1
            FROM edges e
            WHERE e.edge_type = 'taint'
            AND e.source_id IN (SELECT id FROM nodes WHERE node_type = 'source')
            AND e.target_id IN (SELECT id FROM nodes WHERE node_type = 'sink')
            --
            UNION ALL
            -- Recursive: follow calls and data_flow edges
            SELECT tp.source_id, e.target_id,
                   substr(tp.path_json, 1, length(tp.path_json) - 1) || ',' || e.id || ']',
                   substr(tp.edge_types, 1, length(tp.edge_types) - 1) || ',' || '"' || e.edge_type || '"' || ']',
                   tp.depth + 1
            FROM taint_path tp
            JOIN edges e ON e.source_id = tp.target_id
            WHERE tp.depth < ?
            AND e.edge_type IN ('calls', 'data_flow', 'taint')
        )
        SELECT DISTINCT
            tp.source_id,
            tp.target_id,
            tp.path_json,
            tp.edge_types,
            tp.depth,
            sn.name AS source_name,
            sn.kind AS source_kind,
            sn.start_line AS source_line,
            tn.name AS sink_name,
            tn.kind AS sink_kind,
            tn.start_line AS sink_line,
            f.path AS file_path
        FROM taint_path tp
        JOIN nodes sn ON sn.id = tp.source_id
        JOIN nodes tn ON tn.id = tp.target_id
        JOIN files f ON f.id = sn.file_id
        WHERE tn.node_type = 'sink'
        ORDER BY tp.depth
        """
        rows = self.conn.execute(query, (max_depth,)).fetchall()
        return [dict(r) for r in rows]

    def find_callers(self, function_name: str) -> list[dict[str, Any]]:
        """Find all callers of a function."""
        query = """
        SELECT n.id, n.name, n.kind, n.start_line, f.path
        FROM edges e
        JOIN nodes n ON n.id = e.source_id
        JOIN files f ON f.id = n.file_id
        WHERE e.edge_type = 'calls'
        AND e.target_id IN (SELECT id FROM nodes WHERE name = ? AND node_type = 'function')
        """
        rows = self.conn.execute(query, (function_name,)).fetchall()
        return [dict(r) for r in rows]

    def find_callees(self, function_name: str) -> list[dict[str, Any]]:
        """Find all functions called by a given function."""
        query = """
        SELECT n.id, n.name, n.kind, n.start_line, f.path
        FROM edges e
        JOIN nodes n ON n.id = e.target_id
        JOIN files f ON f.id = n.file_id
        WHERE e.edge_type = 'calls'
        AND e.source_id IN (SELECT id FROM nodes WHERE name = ? AND node_type = 'function')
        """
        rows = self.conn.execute(query, (function_name,)).fetchall()
        return [dict(r) for r in rows]

    # ── Stats ────────────────────────────────────────────────────────

    def stats(self) -> dict[str, int]:
        return {
            "files": self.conn.execute("SELECT COUNT(*) FROM files").fetchone()[0],
            "nodes": self.conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0],
            "edges": self.conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0],
            "taint_flows": self.conn.execute("SELECT COUNT(*) FROM taint_flows").fetchone()[0],
        }

    def clear(self) -> None:
        """Clear all data (for testing)."""
        for table in ("taint_flows", "edges", "nodes", "files"):
            self.conn.execute(f"DELETE FROM {table}")
        self.conn.commit()

    @property
    def db_path(self) -> str:
        return self._db_path
