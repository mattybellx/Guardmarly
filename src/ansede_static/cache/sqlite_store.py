"""
ansede_static.cache.sqlite_store
────────────────────────────────
Tiny SQLite-backed JSON key-value store for incremental scan state.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any


def stable_hash(value: str | bytes) -> str:
    """Return a stable SHA-256 hex digest for content-addressing."""
    payload = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(payload).hexdigest()


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

    def __enter__(self) -> SQLiteStore:
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()