"""
ansede_static.cache.sqlite_store
────────────────────────────────
Tiny SQLite-backed JSON key-value store for incremental scan state.

Phase 4 upgrades (spec §4.3):
  - WAL journal mode + NORMAL synchronous mode for safe concurrent reads.
  - BLAKE2b-20 replaces SHA-256 in stable_hash() for faster fingerprinting.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any


def stable_hash(value: str | bytes) -> str:
    """Return a stable BLAKE2b-20 hex digest for content-addressing.

    BLAKE2b is ~3× faster than SHA-256 on modern hardware while retaining
    sufficient collision resistance for a cache key.  The digest_size=20
    (160-bit) matches the space requirements of typical file path hashing.
    """
    payload = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.blake2b(payload, digest_size=20).hexdigest()


class SQLiteStore:
    """Simple bucketed JSON store backed by sqlite3."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._connection: sqlite3.Connection | None = None

    def connect(self) -> sqlite3.Connection:
        """Open the backing database and initialise the schema if needed."""
        if self._connection is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._connection = sqlite3.connect(self.path)
            self._connection.row_factory = sqlite3.Row
            # Phase 4: WAL mode for concurrent-safe reads during parallel scans
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=NORMAL")
            self._initialise()
        return self._connection

    def close(self) -> None:
        """Close the database connection if one is open."""
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def _initialise(self) -> None:
        conn = self.connect_raw()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cache_entries (
                bucket TEXT NOT NULL,
                cache_key TEXT NOT NULL,
                value_json TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (bucket, cache_key)
            )
            """
        )
        conn.commit()

    def connect_raw(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("SQLiteStore is not connected")
        return self._connection

    def set_json(self, bucket: str, key: str, value: Any) -> None:
        """Store a JSON-serialisable value under ``bucket``/``key``."""
        payload = json.dumps(value, sort_keys=True)
        conn = self.connect()
        conn.execute(
            """
            INSERT INTO cache_entries(bucket, cache_key, value_json)
            VALUES(?, ?, ?)
            ON CONFLICT(bucket, cache_key)
            DO UPDATE SET value_json = excluded.value_json, updated_at = CURRENT_TIMESTAMP
            """,
            (bucket, key, payload),
        )
        conn.commit()

    def get_json(self, bucket: str, key: str) -> Any | None:
        """Load a stored JSON value, returning ``None`` when absent."""
        conn = self.connect()
        row = conn.execute(
            "SELECT value_json FROM cache_entries WHERE bucket = ? AND cache_key = ?",
            (bucket, key),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row[0])

    def delete(self, bucket: str, key: str) -> None:
        """Delete a cache entry if it exists."""
        conn = self.connect()
        conn.execute(
            "DELETE FROM cache_entries WHERE bucket = ? AND cache_key = ?",
            (bucket, key),
        )
        conn.commit()

    def keys(self, bucket: str) -> list[str]:
        """Return all keys stored in a bucket."""
        conn = self.connect()
        rows = conn.execute(
            "SELECT cache_key FROM cache_entries WHERE bucket = ? ORDER BY cache_key",
            (bucket,),
        ).fetchall()
        return [str(row[0]) for row in rows]

    def evict_older_than(self, bucket: str, days: int) -> int:
        """Delete entries in *bucket* not updated within the last *days* days.

        Returns the number of rows deleted.  Keeps the cache bounded on
        long-running incremental installations.
        """
        conn = self.connect()
        cursor = conn.execute(
            "DELETE FROM cache_entries WHERE bucket = ? AND updated_at < datetime('now', ? || ' days')",
            (bucket, f"-{days}"),
        )
        conn.commit()
        return cursor.rowcount

    # ── File-level result caching ────────────────────────────────────────────

    _RESULT_BUCKET = "file_results_v1"

    def get_cached_result(self, file_path: str, code: str) -> object | None:
        """Return a cached AnalysisResult if file content hasn't changed, else None."""
        from ansede_static._types import AnalysisResult, Finding, Severity, TraceFrame

        content_hash = stable_hash(code)
        cached = self.get_json(self._RESULT_BUCKET, f"{file_path}:{content_hash}")
        if cached is None:
            return None
        try:
            findings = []
            for fd in cached.get("findings", []):
                trace = tuple(
                    TraceFrame(
                        kind=t.get("kind", ""),
                        label=t.get("label", ""),
                        line=t.get("line"),
                        start_column=t.get("start_column", 1),
                    )
                    for t in fd.get("trace", [])
                )
                findings.append(Finding(
                    category=fd.get("category", "security"),
                    severity=Severity(fd.get("severity", "medium")),
                    title=fd.get("title", ""),
                    description=fd.get("description", ""),
                    line=fd.get("line"),
                    suggestion=fd.get("suggestion", ""),
                    rule_id=fd.get("rule_id", ""),
                    cwe=fd.get("cwe", ""),
                    agent=fd.get("agent", ""),
                    confidence=fd.get("confidence", 1.0),
                    auto_fix=fd.get("auto_fix", ""),
                    explanation=fd.get("explanation", ""),
                    trace=trace,
                    analysis_kind=fd.get("analysis_kind", "pattern"),
                    triggering_code=fd.get("triggering_code", ""),
                ))
            return AnalysisResult(
                file_path=cached.get("file_path", file_path),
                language=cached.get("language", ""),
                lines_scanned=cached.get("lines_scanned", 0),
                findings=findings,
                parse_error=cached.get("parse_error", ""),
            )
        except Exception:
            return None

    def put_cached_result(self, file_path: str, code: str, result: object) -> None:
        """Store an AnalysisResult keyed by file path + content hash."""
        content_hash = stable_hash(code)
        payload = {
            "file_path": getattr(result, "file_path", file_path),
            "language": getattr(result, "language", ""),
            "lines_scanned": getattr(result, "lines_scanned", 0),
            "parse_error": getattr(result, "parse_error", ""),
            "findings": [
                {
                    "category": f.category,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "line": f.line,
                    "suggestion": f.suggestion,
                    "rule_id": f.rule_id,
                    "cwe": f.cwe,
                    "agent": f.agent,
                    "confidence": f.confidence,
                    "auto_fix": f.auto_fix,
                    "explanation": f.explanation,
                    "analysis_kind": f.analysis_kind,
                    "triggering_code": f.triggering_code,
                    "trace": [
                        {"kind": t.kind, "label": t.label, "line": t.line, "start_column": t.start_column}
                        for t in (getattr(f, "trace", None) or ())
                    ],
                }
                for f in getattr(result, "findings", [])
            ],
        }
        self.set_json(self._RESULT_BUCKET, f"{file_path}:{content_hash}", payload)

    def __enter__(self) -> SQLiteStore:
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()