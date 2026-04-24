from __future__ import annotations

import json

from ansede_static.cache import SQLiteStore, stable_hash


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
    assert len(stable_hash("any string")) == 64  # SHA-256 hex
