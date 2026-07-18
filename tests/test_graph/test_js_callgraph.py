from __future__ import annotations

from guardmarly.graph.import_graph import resolve_js_imports
from guardmarly.graph.js_callgraph import build_js_callgraph
from guardmarly.graph.unified_source_graph import UnifiedSourceGraph


def test_build_js_callgraph_resolves_same_file_calls(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    file_path = root / "app.js"
    file_path.write_text(
        "function helper() { return 1; }\n"
        "function route() { return helper(); }\n",
        encoding="utf-8",
    )

    usg = UnifiedSourceGraph()
    import_edges = resolve_js_imports(root, usg)
    call_edges = build_js_callgraph(root, usg, import_edges)

    helper_id = f"file://{file_path.resolve().as_posix()}#func:helper"
    route_id = f"file://{file_path.resolve().as_posix()}#func:route"
    assert any(edge.source_id == route_id and edge.target_id == helper_id for edge in call_edges)


def test_build_js_callgraph_resolves_named_import_calls(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    service = root / "service.js"
    service.write_text("export function getUser() { return 1; }\n", encoding="utf-8")
    api = root / "api.js"
    api.write_text(
        "import { getUser } from './service';\n"
        "export function route() { return getUser(); }\n",
        encoding="utf-8",
    )

    usg = UnifiedSourceGraph()
    import_edges = resolve_js_imports(root, usg)
    call_edges = build_js_callgraph(root, usg, import_edges)

    route_id = f"file://{api.resolve().as_posix()}#func:route"
    get_user_id = f"file://{service.resolve().as_posix()}#func:getUser"
    assert any(edge.source_id == route_id and edge.target_id == get_user_id for edge in call_edges)


def test_build_js_callgraph_resolves_module_object_calls(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    service = root / "service.js"
    service.write_text("function getUser() { return 1; }\nmodule.exports = { getUser };\n", encoding="utf-8")
    api = root / "api.js"
    api.write_text(
        "const service = require('./service');\n"
        "function route() { return service.getUser(); }\n",
        encoding="utf-8",
    )

    usg = UnifiedSourceGraph()
    import_edges = resolve_js_imports(root, usg)
    call_edges = build_js_callgraph(root, usg, import_edges)

    route_id = f"file://{api.resolve().as_posix()}#func:route"
    get_user_id = f"file://{service.resolve().as_posix()}#func:getUser"
    assert any(edge.source_id == route_id and edge.target_id == get_user_id for edge in call_edges)


def test_build_js_callgraph_resolves_default_import_calls(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    service = root / "service.js"
    service.write_text("export default function getUser() { return 1; }\n", encoding="utf-8")
    api = root / "api.js"
    api.write_text(
        "import getUser from './service';\n"
        "export function route() { return getUser(); }\n",
        encoding="utf-8",
    )

    usg = UnifiedSourceGraph()
    import_edges = resolve_js_imports(root, usg)
    call_edges = build_js_callgraph(root, usg, import_edges)

    route_id = f"file://{api.resolve().as_posix()}#func:route"
    get_user_id = f"file://{service.resolve().as_posix()}#func:getUser"
    assert any(edge.source_id == route_id and edge.target_id == get_user_id for edge in call_edges)


def test_build_js_callgraph_resolves_commonjs_default_export_calls(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    service = root / "service.js"
    service.write_text("function getUser() { return 1; }\nmodule.exports = getUser;\n", encoding="utf-8")
    api = root / "api.js"
    api.write_text(
        "const getUser = require('./service');\n"
        "function route() { return getUser(); }\n",
        encoding="utf-8",
    )

    usg = UnifiedSourceGraph()
    import_edges = resolve_js_imports(root, usg)
    call_edges = build_js_callgraph(root, usg, import_edges)

    route_id = f"file://{api.resolve().as_posix()}#func:route"
    get_user_id = f"file://{service.resolve().as_posix()}#func:getUser"
    assert any(edge.source_id == route_id and edge.target_id == get_user_id for edge in call_edges)