"""
ansede_static.cache.incremental
────────────────────────────────
SHA-256-based incremental scan cache.

Instead of relying on git-diff (which requires a git repo), this module
hashes every scanned file's content and compares it against the previous
hash stored in SQLite.  If the file hasn't changed, the cached findings
list is returned instead of re-running the analyser.

Usage
─────
    from ansede_static.cache.incremental import IncrementalCache

    cache = IncrementalCache()          # uses .ansede/cache.db by default
    # or:
    cache = IncrementalCache(".custom/cache.db")

    if not cache.file_changed("app.py"):
        findings = cache.get_cached_findings("app.py")
    else:
        findings = run_analysis("app.py")
        cache.update_hash("app.py")
        cache.store_findings("app.py", findings)

All paths are normalised to absolute strings before hashing so that
relative vs. absolute paths resolve to the same cache entry.

Zero external dependencies.  Python 3.9+.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, List, Optional

from ansede_static.cache.sqlite_store import SQLiteStore

_BUCKET_HASH = "file_hashes"
_BUCKET_FINDINGS = "file_findings"


def _hash_file(path: Path) -> str:
    """Return the SHA-256 hex digest of a file's contents."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


class IncrementalCache:
    """
    Manages incremental scan state using file-content SHA-256 hashes.

    Parameters
    ----------
    db_path
        Path to the SQLite database.  Defaults to ``.ansede/cache.db``
        relative to the current working directory.
    """

    def __init__(self, db_path: Optional[str | Path] = None) -> None:
        if db_path is None:
            db_path = Path(".ansede") / "cache.db"
        self._store = SQLiteStore(db_path)
        self._store.connect()

    # ------------------------------------------------------------------
    # Hash management
    # ------------------------------------------------------------------

    def _normalise(self, path: str | Path) -> str:
        """Return the absolute string path used as a cache key."""
        return str(Path(path).resolve())

    def file_changed(self, path: str | Path) -> bool:
        """
        Return ``True`` when the file's current SHA-256 differs from the
        stored hash (or no hash is stored yet).
        """
        key = self._normalise(path)
        current_hash = _hash_file(Path(path))
        if not current_hash:
            # File unreadable — treat as changed so analyser can report the error
            return True
        stored = self._store.get_json(_BUCKET_HASH, key)
        return stored != current_hash

    def update_hash(self, path: str | Path) -> None:
        """Store the current SHA-256 of *path* in the cache."""
        key = self._normalise(path)
        current_hash = _hash_file(Path(path))
        if current_hash:
            self._store.set_json(_BUCKET_HASH, key, current_hash)

    # ------------------------------------------------------------------
    # Findings management
    # ------------------------------------------------------------------

    def get_cached_findings(self, path: str | Path) -> Optional[List[Any]]:
        """
        Return the cached findings list for *path*, or ``None`` if not cached.

        The returned list contains raw dicts (as serialised by
        ``Finding.to_dict()`` / ``_types.py``); callers should deserialise
        if needed.
        """
        key = self._normalise(path)
        return self._store.get_json(_BUCKET_FINDINGS, key)

    def store_findings(self, path: str | Path, findings: List[Any]) -> None:
        """
        Persist *findings* for *path*.

        *findings* must be JSON-serialisable.  Pass a list of dicts
        (e.g. ``[f.__dict__ for f in findings]``) or the raw list of
        ``Finding`` objects converted to dicts.
        """
        key = self._normalise(path)
        # Serialise dataclasses/objects to plain dicts if needed
        serialisable = _serialise_findings(findings)
        self._store.set_json(_BUCKET_FINDINGS, key, serialisable)

    # ------------------------------------------------------------------
    # Bulk invalidation
    # ------------------------------------------------------------------

    def invalidate(self, path: str | Path) -> None:
        """Remove stored hash and findings for *path*."""
        key = self._normalise(path)
        # SQLiteStore doesn't expose delete; we overwrite with sentinel
        self._store.set_json(_BUCKET_HASH, key, None)
        self._store.set_json(_BUCKET_FINDINGS, key, None)

    def close(self) -> None:
        """Close the backing SQLite connection."""
        self._store.close()

    def __enter__(self) -> "IncrementalCache":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


# ── Serialisation helpers ─────────────────────────────────────────────────────

def _serialise_findings(findings: List[Any]) -> List[Any]:
    """Convert Finding objects (or plain dicts) to JSON-safe dicts."""
    result = []
    for f in findings:
        if isinstance(f, dict):
            result.append(f)
        elif hasattr(f, "__dict__"):
            result.append(_obj_to_dict(f))
        else:
            result.append(str(f))
    return result


def _obj_to_dict(obj: Any) -> Any:
    """Recursively convert dataclass / object to a plain dict."""
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    if isinstance(obj, (list, tuple)):
        return [_obj_to_dict(item) for item in obj]
    if isinstance(obj, dict):
        return {k: _obj_to_dict(v) for k, v in obj.items()}
    if hasattr(obj, "__dict__"):
        return {k: _obj_to_dict(v) for k, v in obj.__dict__.items()}
    return str(obj)
