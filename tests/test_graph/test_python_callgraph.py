from __future__ import annotations

from guardmarly.graph.import_graph import resolve_python_imports
from guardmarly.graph.python_callgraph import build_python_callgraph
from guardmarly.graph.unified_source_graph import UnifiedSourceGraph


def test_build_python_callgraph_resolves_same_file_calls(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text(
        "def helper():\n    return 1\n\n"
        "def route():\n    return helper()\n",
        encoding="utf-8",
    )

    usg = UnifiedSourceGraph()
    import_edges = resolve_python_imports(root, usg)
    call_edges = build_python_callgraph(root, usg, import_edges)

    helper_id = f"file://{(root / 'app.py').resolve().as_posix()}#func:helper"
    route_id = f"file://{(root / 'app.py').resolve().as_posix()}#func:route"
    assert any(edge.source_id == route_id and edge.target_id == helper_id for edge in call_edges)


def test_build_python_callgraph_resolves_imported_calls(tmp_path):
    root = tmp_path / "repo"
    pkg = root / "pkg"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "services.py").write_text("def get_user():\n    return 1\n", encoding="utf-8")
    (pkg / "api.py").write_text(
        "from .services import get_user\n"
        "def route():\n    return get_user()\n",
        encoding="utf-8",
    )

    usg = UnifiedSourceGraph()
    import_edges = resolve_python_imports(root, usg)
    call_edges = build_python_callgraph(root, usg, import_edges)

    route_id = f"file://{(pkg / 'api.py').resolve().as_posix()}#func:route"
    get_user_id = f"file://{(pkg / 'services.py').resolve().as_posix()}#func:get_user"
    assert any(edge.source_id == route_id and edge.target_id == get_user_id for edge in call_edges)


def test_build_python_callgraph_resolves_module_attribute_calls(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "services.py").write_text("def get_user():\n    return 1\n", encoding="utf-8")
    (root / "api.py").write_text(
        "import services\n"
        "def route():\n    return services.get_user()\n",
        encoding="utf-8",
    )

    usg = UnifiedSourceGraph()
    import_edges = resolve_python_imports(root, usg)
    call_edges = build_python_callgraph(root, usg, import_edges)

    route_id = f"file://{(root / 'api.py').resolve().as_posix()}#func:route"
    get_user_id = f"file://{(root / 'services.py').resolve().as_posix()}#func:get_user"
    assert any(edge.source_id == route_id and edge.target_id == get_user_id for edge in call_edges)