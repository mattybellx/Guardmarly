from __future__ import annotations

import json

from guardmarly.cache import SQLiteStore, stable_hash
from guardmarly.python_analyzer import analyze_python


def test_sqlite_store_round_trip(tmp_path):
    store = SQLiteStore(tmp_path / "cache.db")
    store.set_json("scan", "doc.py", {"fingerprint": stable_hash("content"), "count": 2})

    assert store.get_json("scan", "doc.py") == {
        "fingerprint": stable_hash("content"),
        "count": 2,
    }
    assert store.keys("scan") == ["doc.py"]

    store.delete("scan", "doc.py")
    assert store.get_json("scan", "doc.py") is None
    store.close()


def test_sqlite_store_persists_between_instances(tmp_path):
    path = tmp_path / "cache.db"
    first = SQLiteStore(path)
    first.set_json("summary", "workspace", {"total": 4})
    first.close()

    second = SQLiteStore(path)
    assert second.get_json("summary", "workspace") == {"total": 4}
    second.close()


def test_sqlite_store_overwrite_updates_value(tmp_path):
    store = SQLiteStore(tmp_path / "cache.db")
    store.set_json("scan", "app.py", {"findings": 3})
    store.set_json("scan", "app.py", {"findings": 5})  # overwrite
    assert store.get_json("scan", "app.py") == {"findings": 5}
    store.close()


def test_sqlite_store_bucket_isolation(tmp_path):
    store = SQLiteStore(tmp_path / "cache.db")
    store.set_json("bucket_a", "key1", {"a": 1})
    store.set_json("bucket_b", "key1", {"b": 2})

    assert store.get_json("bucket_a", "key1") == {"a": 1}
    assert store.get_json("bucket_b", "key1") == {"b": 2}
    assert store.keys("bucket_a") == ["key1"]
    assert store.keys("bucket_b") == ["key1"]
    store.close()


def test_sqlite_store_missing_key_returns_none(tmp_path):
    store = SQLiteStore(tmp_path / "cache.db")
    assert store.get_json("scan", "nonexistent.py") is None
    store.close()


def test_incremental_cache_known_clean_tracking(tmp_path):
    from guardmarly.cache.incremental import IncrementalCache
    cache = IncrementalCache(tmp_path / "test_clean.db")
    test_file = tmp_path / "test.py"
    test_file.write_text("x = 1")

    assert cache.is_clean(test_file) is False

    cache.mark_clean(test_file)
    assert cache.is_clean(test_file) is False  # 1 < 3

    cache.mark_clean(test_file)
    assert cache.is_clean(test_file) is False  # 2 < 3

    cache.mark_clean(test_file)
    assert cache.is_clean(test_file) is True  # 3 >= 3

    cache.mark_dirty(test_file)
    assert cache.is_clean(test_file) is False  # reset to 0

    cache.close()


def test_incremental_cache_clean_count_survives_reopen(tmp_path):
    from guardmarly.cache.incremental import IncrementalCache
    db_path = tmp_path / "test_persist.db"
    test_file = tmp_path / "test.py"
    test_file.write_text("x = 1")

    cache = IncrementalCache(db_path)
    cache.mark_clean(test_file)
    cache.mark_clean(test_file)
    cache.mark_clean(test_file)
    assert cache.is_clean(test_file) is True
    cache.close()

    cache2 = IncrementalCache(db_path)
    assert cache2.is_clean(test_file) is True
    cache2.close()


def test_sqlite_store_context_manager(tmp_path):
    path = tmp_path / "cache.db"
    with SQLiteStore(path) as store:
        store.set_json("ctx", "x", {"v": 99})

    # Should be closed after the with block; re-opening should still see the data.
    with SQLiteStore(path) as store:
        assert store.get_json("ctx", "x") == {"v": 99}


def test_stable_hash_is_deterministic():
    assert stable_hash("hello") == stable_hash("hello")
    assert stable_hash("hello") != stable_hash("world")


def test_get_cached_result_round_trip(tmp_path):
    from guardmarly.cache.sqlite_store import SQLiteStore
    from pathlib import Path

    store = SQLiteStore(tmp_path / "result_cache.db")
    test_file = tmp_path / "test.py"
    test_file.write_text("x = 1")

    # First call: no cache hit
    code = test_file.read_text(encoding="utf-8")
    cached = store.get_cached_result(str(test_file), code)
    assert cached is None, "Should be None on first access"

    # Run analysis and cache it
    from guardmarly import scan_code
    result = scan_code(code, language="python", filename=str(test_file))

    # Store the result using the same bucket the CLI uses
    store.set_json("file_results_v1", f"{test_file}:{stable_hash(code)}", {
        "findings": [f.as_dict() for f in result.findings],
        "lines_scanned": result.lines_scanned,
        "language": result.language,
    })

    # Second call: should hit cache
    cached2 = store.get_cached_result(str(test_file), code)
    assert cached2 is not None, "Should return cached result"
    assert cached2.lines_scanned == result.lines_scanned
    assert cached2.language == result.language

    # Change file content: should miss cache
    test_file.write_text("y = 2")
    code2 = test_file.read_text(encoding="utf-8")
    cached3 = store.get_cached_result(str(test_file), code2)
    assert cached3 is None, "Should miss cache after content change"

    store.close()
    assert len(stable_hash("any string")) == 40  # BLAKE2b-20 hex (Phase 4 §4.3 upgrade from SHA-256)


def test_sqlite_store_evict_older_than(tmp_path):
    """evict_older_than(bucket, 0) removes all entries (updated_at < now)."""
    store = SQLiteStore(tmp_path / "cache.db")
    store.set_json("scan", "a.py", {"v": 1})
    store.set_json("scan", "b.py", {"v": 2})
    store.set_json("other", "c.py", {"v": 3})

    # Evicting with 0 days removes everything older than right now.
    # SQLite CURRENT_TIMESTAMP has 1-second granularity; we back-date the
    # entries by directly updating updated_at to force them to look old.
    store.connect().execute(
        "UPDATE cache_entries SET updated_at = datetime('now', '-2 days')"
    )
    store.connect().commit()

    deleted = store.evict_older_than("scan", 1)
    assert deleted == 2
    assert store.get_json("scan", "a.py") is None
    assert store.get_json("scan", "b.py") is None
    # Different bucket untouched
    assert store.get_json("other", "c.py") == {"v": 3}
    store.close()


def test_sqlite_store_evict_returns_zero_when_nothing_old(tmp_path):
    store = SQLiteStore(tmp_path / "cache.db")
    store.set_json("scan", "fresh.py", {"v": 1})
    # Entries are brand-new — evict with 30-day window should remove nothing.
    deleted = store.evict_older_than("scan", 30)
    assert deleted == 0
    assert store.get_json("scan", "fresh.py") == {"v": 1}
    store.close()


def test_python_analyzer_persists_function_summaries(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    code = """
from flask import request

def helper(user_id):
    return user_id

def handler():
    value = request.args.get('id')
    return helper(value)
"""

    result = analyze_python(code, filename="app.py")
    assert result.findings is not None

    store = SQLiteStore(tmp_path / ".guardmarly" / "cache.db")
    keys = store.keys("function_summaries_v1")
    assert len(keys) == 1
    payload = store.get_json("function_summaries_v1", keys[0])
    assert "helper" in payload
    assert "handler" in payload
    store.close()
