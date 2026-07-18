from __future__ import annotations

from guardmarly.graph.go_callgraph import build_go_callgraph
from guardmarly.graph.import_graph import resolve_go_imports
from guardmarly.graph.unified_source_graph import UnifiedSourceGraph


def test_build_go_callgraph_resolves_same_file_calls(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "go.mod").write_text("module example.com/demo\n\ngo 1.22\n", encoding="utf-8")
    app = root / "main.go"
    app.write_text(
        "package main\n\n"
        "func helper() int { return 1 }\n\n"
        "func route() int { return helper() }\n",
        encoding="utf-8",
    )

    usg = UnifiedSourceGraph()
    import_edges = resolve_go_imports(root, usg)
    call_edges = build_go_callgraph(root, usg, import_edges)

    helper_id = f"file://{app.resolve().as_posix()}#func:helper"
    route_id = f"file://{app.resolve().as_posix()}#func:route"
    assert any(edge.source_id == route_id and edge.target_id == helper_id for edge in call_edges)


def test_build_go_callgraph_resolves_imported_package_calls(tmp_path):
    root = tmp_path / "repo"
    pkg = root / "internal" / "auth"
    pkg.mkdir(parents=True)
    (root / "go.mod").write_text("module example.com/demo\n\ngo 1.22\n", encoding="utf-8")
    service = pkg / "auth.go"
    service.write_text(
        "package auth\n\n"
        "func Check() bool { return true }\n",
        encoding="utf-8",
    )
    app = root / "main.go"
    app.write_text(
        "package main\n\n"
        "import \"example.com/demo/internal/auth\"\n\n"
        "func route() bool { return auth.Check() }\n",
        encoding="utf-8",
    )

    usg = UnifiedSourceGraph()
    import_edges = resolve_go_imports(root, usg)
    call_edges = build_go_callgraph(root, usg, import_edges)

    route_id = f"file://{app.resolve().as_posix()}#func:route"
    check_id = f"file://{service.resolve().as_posix()}#func:Check"
    assert any(edge.source_id == route_id and edge.target_id == check_id for edge in call_edges)