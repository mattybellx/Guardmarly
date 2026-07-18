from __future__ import annotations

from guardmarly.graph.import_graph import resolve_go_imports, resolve_js_imports, resolve_python_imports
from guardmarly.graph.unified_source_graph import UnifiedSourceGraph


def test_resolve_python_imports_handles_relative_and_package_imports(tmp_path):
    root = tmp_path / "repo"
    pkg = root / "pkg"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("from .services import get_user\n", encoding="utf-8")
    (pkg / "services.py").write_text("def get_user():\n    return 1\n", encoding="utf-8")
    (pkg / "api.py").write_text("from .services import get_user\nimport pkg.services\n", encoding="utf-8")

    usg = UnifiedSourceGraph()
    edges = resolve_python_imports(root, usg)

    edge_targets = {(edge.source_id, edge.target_id) for edge in edges}
    services_node = f"file://{(pkg / 'services.py').resolve().as_posix()}#file"
    api_node = f"file://{(pkg / 'api.py').resolve().as_posix()}#file"
    init_node = f"file://{(pkg / '__init__.py').resolve().as_posix()}#file"

    assert (api_node, services_node) in edge_targets
    assert (init_node, services_node) in edge_targets
    assert services_node in usg.nodes


def test_resolve_js_imports_handles_relative_require_and_tsconfig_alias(tmp_path):
    root = tmp_path / "repo"
    src = root / "src"
    ui = src / "ui"
    ui.mkdir(parents=True)
    (root / "tsconfig.json").write_text(
        '{"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["src/*"]}}}',
        encoding="utf-8",
    )
    (src / "client.ts").write_text("export const fetchUser = () => 1\n", encoding="utf-8")
    (ui / "render.ts").write_text("export const renderUser = () => 1\n", encoding="utf-8")
    (src / "api.ts").write_text(
        "import { fetchUser } from './client'\n"
        "const render = require('@/ui/render')\n"
        "async function lazy() { return import('@/ui/render') }\n",
        encoding="utf-8",
    )

    usg = UnifiedSourceGraph()
    edges = resolve_js_imports(root, usg)

    targets = {(edge.source_id, edge.target_id) for edge in edges}
    api_node = f"file://{(src / 'api.ts').resolve().as_posix()}#file"
    client_node = f"file://{(src / 'client.ts').resolve().as_posix()}#file"
    render_node = f"file://{(ui / 'render.ts').resolve().as_posix()}#file"

    assert (api_node, client_node) in targets
    assert (api_node, render_node) in targets
    assert len([edge for edge in edges if edge.target_id == render_node]) == 1


def test_resolve_go_imports_uses_go_mod_module_path(tmp_path):
    root = tmp_path / "repo"
    cmd = root / "cmd"
    auth = root / "internal" / "auth"
    auth.mkdir(parents=True)
    cmd.mkdir(parents=True)
    (root / "go.mod").write_text("module example.com/app\n\ngo 1.22\n", encoding="utf-8")
    (auth / "auth.go").write_text("package auth\n\nfunc Check() bool { return true }\n", encoding="utf-8")
    (cmd / "main.go").write_text(
        'package main\n\nimport (\n    "example.com/app/internal/auth"\n)\n\nfunc main() { _ = auth.Check() }\n',
        encoding="utf-8",
    )

    usg = UnifiedSourceGraph()
    edges = resolve_go_imports(root, usg)

    main_node = f"file://{(cmd / 'main.go').resolve().as_posix()}#file"
    auth_node = f"file://{(auth / 'auth.go').resolve().as_posix()}#file"
    assert any(edge.source_id == main_node and edge.target_id == auth_node for edge in edges)
    assert auth_node in usg.nodes