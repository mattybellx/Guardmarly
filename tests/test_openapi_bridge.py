from __future__ import annotations

import json
from pathlib import Path

from guardmarly.graph.openapi_bridge import (
    _normalize_route_path,
    _extract_openapi_routes,
    _discover_openapi_files,
    _load_spec,
    build_openapi_bridges,
    bridge_stats,
)


def test_normalize_route_path_normalizes_param_styles():
    assert _normalize_route_path("/users/{id}") == "/users/{param}"
    assert _normalize_route_path("/users/:id") == "/users/{param}"
    assert _normalize_route_path("/api/v1/users/{userId}/posts") == "/api/v1/users/{param}/posts"
    assert _normalize_route_path("/") == "/"
    assert _normalize_route_path("") == "/"


def test_extract_openapi_routes_from_spec():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/users/{id}": {
                "get": {
                    "operationId": "getUser",
                    "summary": "Get a user by ID",
                    "tags": ["users"],
                    "parameters": [{"name": "id", "in": "path", "required": True}],
                },
                "post": {
                    "operationId": "createUser",
                    "summary": "Create a new user",
                },
            },
            "/health": {
                "get": {
                    "operationId": "healthCheck",
                },
            },
        },
    }

    routes = _extract_openapi_routes(spec)
    assert len(routes) == 3
    assert routes[0]["method"] == "GET"
    assert routes[0]["path"] == "/users/{id}"
    assert routes[0]["operation_id"] == "getUser"
    assert routes[0]["normalized_path"] == "/users/{param}"
    assert routes[1]["method"] == "POST"
    assert routes[2]["path"] == "/health"


def test_discover_openapi_files_finds_spec(tmp_path: Path):
    spec_file = tmp_path / "openapi.json"
    spec_file.write_text("{}", encoding="utf-8")

    found = _discover_openapi_files(tmp_path)
    assert len(found) == 1
    assert found[0].name == "openapi.json"


def test_load_spec_parses_json(tmp_path: Path):
    spec_file = tmp_path / "openapi.json"
    spec_file.write_text(json.dumps({"openapi": "3.0.0", "info": {"title": "Test"}}), encoding="utf-8")

    data = _load_spec(spec_file)
    assert data is not None
    assert data["openapi"] == "3.0.0"


def test_build_openapi_bridges_no_spec_returns_empty(tmp_path: Path):
    bridges = build_openapi_bridges(tmp_path)
    assert bridges == []


def test_bridge_stats_computes_match_rate():
    bridges = [
        {"match_type": "exact", "language": "python", "spec_path": "/a", "spec_method": "GET"},
        {"match_type": "unmatched", "language": "", "spec_path": "/b", "spec_method": "POST"},
        {"match_type": "wildcard", "language": "javascript", "spec_path": "/c", "method": "GET"},
    ]
    stats = bridge_stats(bridges)
    assert stats["total_routes"] == 3
    assert stats["matched_handlers"] == 2
    assert stats["match_rate_pct"] == 66.7


def test_build_openapi_bridges_with_spec_and_source(tmp_path: Path):
    # Create an OpenAPI spec
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/api/users": {
                "get": {"operationId": "listUsers"},
            },
        },
    }
    spec_file = tmp_path / "openapi.json"
    spec_file.write_text(json.dumps(spec), encoding="utf-8")

    # Create a backend source file matching the route
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    backend = source_dir / "routes.py"
    backend.write_text(
        'from flask import Flask\napp = Flask(__name__)\n\n@app.get("/api/users")\ndef list_users():\n    return []\n',
        encoding="utf-8",
    )

    bridges = build_openapi_bridges(tmp_path)
    assert len(bridges) >= 1
    matched = [b for b in bridges if b["match_type"] != "unmatched"]
    assert len(matched) >= 1
    assert matched[0]["language"] == "python"
