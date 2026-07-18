"""Tests for the incremental scan cache (ROADMAP Section 13)."""
from __future__ import annotations

import json
from pathlib import Path

from guardmarly.cache.incremental import (
    IncrementalCache,
    _extract_js_imports,
    _extract_python_imports,
    _hash_file,
    _resolve_import_target,
)


class TestJsImportExtraction:
    def test_relative_js_imports_extracted(self, tmp_path):
        helper = tmp_path / "helpers.js"
        app = tmp_path / "app.js"
        helper.write_text("export const x = 1;")
        app.write_text("import { x } from './helpers';")

        imports = _extract_js_imports(app)
        assert len(imports) >= 1
        assert any("helpers" in imp for imp in imports)

    def test_deep_relative_import(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        app = tmp_path / "app.js"
        helper = sub / "utils.js"
        app.write_text("import utils from './sub/utils';")
        helper.write_text("export default {};")

        imports = _extract_js_imports(app)
        assert any("sub" in imp and "utils" in imp for imp in imports)

    def test_non_js_files_return_empty(self, tmp_path):
        py_file = tmp_path / "app.py"
        py_file.write_text("import os")
        imports = _extract_js_imports(py_file)
        assert imports == []


class TestIncrementalCache:
    def test_file_changed_detected(self, tmp_path):
        db = tmp_path / "cache.db"
        cache = IncrementalCache(db)
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1")

        assert cache.file_changed(test_file)  # No hash stored yet
        cache.update_hash(test_file)
        assert not cache.file_changed(test_file)  # Same content

        test_file.write_text("x = 2")
        assert cache.file_changed(test_file)  # Content changed

        cache.close()

    def test_python_imports_tracked(self, tmp_path):
        helper = tmp_path / "helper.py"
        app = tmp_path / "app.py"
        helper.write_text("def fn(): pass")
        app.write_text("from helper import fn")

        db = tmp_path / "cache.db"
        cache = IncrementalCache(db)
        cache.update_hash(app)

        imports = cache.get_imports(app)
        assert any("helper" in imp for imp in imports)

        cache.close()

    def test_affected_files_propagates(self, tmp_path):
        helper = tmp_path / "helper.py"
        app = tmp_path / "app.py"
        stand = tmp_path / "standalone.py"
        helper.write_text("def fn(): pass")
        app.write_text("from helper import fn")
        stand.write_text("print(1)")

        db = tmp_path / "cache.db"
        cache = IncrementalCache(db)
        cache.update_hash(app)
        cache.update_hash(stand)
        cache.update_hash(helper)

        affected = cache.affected_files(
            {helper},
            candidate_paths={app, stand, helper},
        )
        assert str(app.resolve()) in affected, "app imports helper, should be affected"
        assert str(stand.resolve()) not in affected, "standalone doesn't import helper"

        cache.close()

    def test_js_imports_tracked(self, tmp_path):
        helper = tmp_path / "utils.js"
        app = tmp_path / "app.js"
        helper.write_text("export const x = 1;")
        app.write_text("import { x } from './utils';")

        db = tmp_path / "cache.db"
        cache = IncrementalCache(db)
        cache.update_hash(app)

        imports = cache.get_imports(app)
        assert any("utils" in imp for imp in imports), f"JS imports not tracked: {imports}"

        cache.close()
