from pathlib import Path

import ansede_static.js_ast_analyzer as js_ast_analyzer
import ansede_static.js_analyzer as js_analyzer
import ansede_static.js_engine.project as js_project


def test_minified_bundle_skips_project_index(monkeypatch, tmp_path: Path):
    bundle_path = tmp_path / "bundle.min.js"
    code = "(()=>{" + "const a=1;" * 1200 + "})();"
    bundle_path.write_text(code, encoding="utf-8")

    def _unexpected_project_index(*args, **kwargs):
        raise AssertionError("minified bundles should skip JS project indexing")

    monkeypatch.setattr(js_ast_analyzer, "build_js_project_index", _unexpected_project_index)

    result = js_ast_analyzer.analyze_js_ast(code, filename=str(bundle_path))

    assert result.language == "javascript"


def test_build_js_project_index_short_circuits_minified_bundle(monkeypatch, tmp_path: Path):
    bundle_path = tmp_path / "bundle.min.js"
    code = "(()=>{" + "const a=1;" * 1200 + "})();"
    bundle_path.write_text(code, encoding="utf-8")

    def _unexpected_file_index(*args, **kwargs):
        raise AssertionError("minified bundles should not build file indexes")

    monkeypatch.setattr(js_project, "_build_file_index", _unexpected_file_index)

    assert js_project.build_js_project_index(str(bundle_path), code) is None


def test_ast_fallback_reuses_existing_project_index(monkeypatch, tmp_path: Path):
    source_path = tmp_path / "server.js"
    code = (
        "const app = express();\n"
        "app.get('/admin/users', (req, res) => {\n"
        "  res.json(User.findAll());\n"
        "});\n"
    )
    source_path.write_text(code, encoding="utf-8")

    def _unexpected_classic_project_index(*args, **kwargs):
        raise AssertionError("classic fallback should reuse the structural JS project index")

    monkeypatch.setattr(js_analyzer, "build_js_project_index", _unexpected_classic_project_index)

    result = js_ast_analyzer.analyze_js_ast(code, filename=str(source_path))

    assert result.language == "javascript"