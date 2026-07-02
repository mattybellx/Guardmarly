"""
ansede_static.graph.openapi_bridge
───────────────────────────────────
Parse OpenAPI 3.0/3.1 specs and generate cross-language bridge edges
matching spec routes to backend route handlers (Python/Go/Java/C#/JS).

Bridge edges feed into the UnifiedSourceGraph for cross-language taint tracking.

Usage:
    from ansede_static.graph.openapi_bridge import build_openapi_bridges

    bridges = build_openapi_bridges("/path/to/openapi.json", root_dir=Path("."))
    for bridge in bridges:
        print(bridge["spec_path"], "→", bridge["handler"])
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

# Lazy imports: jsonschema/yaml are optional deps; we wrap them in try/except.

_OPENAPI_SPEC_FILES: tuple[str, ...] = (
    "openapi.json", "openapi.yaml", "openapi.yml",
    "swagger.json", "swagger.yaml", "swagger.yml",
    "api-docs.json", "api-docs.yaml",
)


def _dequote(value: str) -> str:
    """Strip surrounding quote chars from a string."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        return value[1:-1]
    return value


def _normalize_route_path(path: str) -> str:
    """Normalize a route path to a canonical form for matching.

    Converts OpenAPI {param} and Express :param to a common {param} placeholder.
    Strips trailing slashes, lowercases.
    """
    value = path.strip()
    if not value:
        return "/"
    value = re.sub(r":([A-Za-z_][\w-]*)", "{param}", value)
    value = re.sub(r"\{[^}]+\}", "{param}", value)
    value = re.sub(r"//+", "/", value)
    if not value.startswith("/"):
        value = "/" + value
    if len(value) > 1:
        value = value.rstrip("/")
    return value.lower()


def _discover_openapi_files(root_dir: Path, search_paths: list[Path] | None = None) -> list[Path]:
    """Discover OpenAPI spec files in the repository."""
    found: list[Path] = []
    targets = search_paths or [root_dir]

    for target in targets:
        target = target.resolve()
        if target.is_file():
            if target.name.lower() in _OPENAPI_SPEC_FILES or target.suffix.lower() in (".json", ".yaml", ".yml"):
                found.append(target)
            continue
        if target.is_dir():
            for name in _OPENAPI_SPEC_FILES:
                candidate = target / name
                if candidate.exists():
                    found.append(candidate)
            # Also check common subdirectories
            for sub in ("docs", "api", "spec", "openapi", "swagger"):
                subdir = target / sub
                if subdir.is_dir():
                    for name in _OPENAPI_SPEC_FILES:
                        candidate = subdir / name
                        if candidate.exists():
                            found.append(candidate)
    return sorted(set(found))


def _load_spec(path: Path) -> dict[str, Any] | None:
    """Load an OpenAPI spec from a JSON or YAML file."""
    ext = path.suffix.lower()
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    if ext in (".yaml", ".yml"):
        try:
            import yaml as _yaml  # type: ignore[import-untyped]
            data = _yaml.safe_load(raw)
            if isinstance(data, dict):
                return data
            return None
        except ImportError:
            # Fallback: try JSON parse (some .yaml files are actually JSON)
            pass
        except Exception:
            return None

    if ext == ".json":
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                return data
            return None
        except json.JSONDecodeError:
            return None

    # No extension — try JSON first, then YAML
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    try:
        import yaml as _yaml
        data = _yaml.safe_load(raw)
        if isinstance(data, dict):
            return data
    except ImportError:
        pass
    except Exception:
        pass
    return None


def _extract_openapi_routes(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract route definitions from an OpenAPI 3.0/3.1 or Swagger 2.0 spec."""
    routes: list[dict[str, Any]] = []

    # Determine spec version
    str(spec.get("swagger", "") or "")
    str(spec.get("openapi", "") or "")

    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        return routes

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method in ("get", "post", "put", "delete", "patch", "options", "head"):
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue

            operation_id = str(operation.get("operationId", "") or "").strip()
            summary = str(operation.get("summary", "") or "").strip()
            tags = operation.get("tags", [])
            if not isinstance(tags, list):
                tags = []

            # Extract parameters (path + query)
            parameters: list[dict[str, Any]] = []
            for param_list in (operation.get("parameters", []), path_item.get("parameters", [])):
                if isinstance(param_list, list):
                    for param in param_list:
                        if isinstance(param, dict):
                            parameters.append({
                                "name": str(param.get("name", "")),
                                "in": str(param.get("in", "")),
                                "required": bool(param.get("required", False)),
                            })

            routes.append({
                "path": path,
                "method": method.upper(),
                "operation_id": operation_id,
                "summary": summary,
                "tags": tags,
                "parameters": parameters,
                "normalized_path": _normalize_route_path(path),
            })

    return routes


def _find_backend_handler(
    normalized_spec_path: str,
    method: str,
    backend_routes: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Find the best-matching backend handler for a given OpenAPI route."""
    candidates: list[dict[str, Any]] = []
    for route in backend_routes:
        route_norm = route.get("normalized_path", "")
        route_method = route.get("method", "GET")

        if route_norm == normalized_spec_path and route_method == method:
            candidates.append(route)
        elif route_norm == normalized_spec_path and route_method == "ANY":
            candidates.append(route)

    if candidates:
        return candidates[0]

    # No exact match — try suffix match (for nested routes)
    for route in backend_routes:
        route_norm = route.get("normalized_path", "")
        route_method = route.get("method", "GET")
        spec_segments = normalized_spec_path.strip("/").split("/")
        route_segments = route_norm.strip("/").split("/")

        if len(spec_segments) != len(route_segments):
            continue

        # Allow {param} wildcard matching
        match = True
        for s, r in zip(spec_segments, route_segments):
            if r == "{param}" or s == r:
                continue
            match = False
            break

        if match and (route_method == method or route_method == "ANY"):
            candidates.append(route)

    if candidates:
        return candidates[0]
    return None


def _extract_backend_routes_from_source(root_dir: Path) -> list[dict[str, Any]]:
    """Extract backend route handlers from Python/JS/Go/Java/C# source code.

    Uses the same regex patterns as the cross-language taint module.
    """
    backend_routes: list[dict[str, Any]] = []
    supported_exts = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".cs"}

    _PY_ROUTE_RE = re.compile(
        r"@(?:[A-Za-z_][\w]*\.)?(?P<method>get|post|put|delete|patch|route)\(\s*(['\"])(?P<path>[^'\"]+)\2[^\n]*\)\s*\n\s*(?:async\s+def|def)\s+(?P<handler>[A-Za-z_][\w]*)\s*\(",
        re.MULTILINE,
    )
    _JS_ROUTE_RE = re.compile(
        r"(?:app|router)\.(?P<method>get|post|put|delete|patch)\(\s*(['\"`])(?P<path>[^'\"`]+)\2\s*,\s*(?P<handler>[A-Za-z_$][\w$]*)",
        re.MULTILINE,
    )
    _GO_ROUTE_RE = re.compile(
        r"http\.HandleFunc\(\s*\"(?P<path>[^\"]+)\"\s*,\s*(?P<handler>[A-Za-z_][A-Za-z0-9_]*)\s*\)",
        re.MULTILINE,
    )
    _JAVA_ROUTE_RE = re.compile(
        r"@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)\(\s*(['\"])(?P<path>[^'\"]+)\1",
        re.MULTILINE,
    )
    _CSHARP_ROUTE_RE = re.compile(
        r"\[Http(?:Get|Post|Put|Delete)\(\s*['\"](?P<cspath>[^'\"]+)['\"]\)\]|"
        r"\[Route\(\s*['\"](?P<csroute>[^'\"]+)['\"]\)\]",
        re.MULTILINE,
    )
    _CSHARP_TOPLEVEL_RE = re.compile(
        r"app\.Map(?:Get|Post|Put|Delete|Patch)\(\s*['\"](?P<path>[^'\"]+)['\"]",
        re.MULTILINE,
    )

    for file_path in sorted(root_dir.rglob("*")):
        if not file_path.is_file():
            continue
        if file_path.suffix.lower() not in supported_exts:
            continue
        if ".git" in file_path.parts:
            continue
        if "node_modules" in file_path.parts:
            continue

        try:
            code = file_path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            continue

        rel = file_path.relative_to(root_dir).as_posix()
        lang = "python" if file_path.suffix in (".py",) else \
               "javascript" if file_path.suffix in (".js", ".ts", ".jsx", ".tsx") else \
               "go" if file_path.suffix == ".go" else \
               "java" if file_path.suffix == ".java" else \
               "csharp" if file_path.suffix == ".cs" else "unknown"

        for pattern, method_extractor in [
            (_PY_ROUTE_RE, lambda m: m.group("method").upper()),
            (_JS_ROUTE_RE, lambda m: m.group("method").upper()),
            (_GO_ROUTE_RE, lambda _: "GET"),
            (_JAVA_ROUTE_RE, lambda m: m.group(0).replace("@", "").replace("Mapping", "").upper()),
            (_CSHARP_ROUTE_RE, lambda m: "GET" if "HttpGet" in m.group(0) else
                                          "POST" if "HttpPost" in m.group(0) else
                                          "PUT" if "HttpPut" in m.group(0) else
                                          "DELETE" if "HttpDelete" in m.group(0) else "GET"),
            (_CSHARP_TOPLEVEL_RE, lambda m: m.group(0).replace("app.Map", "").upper()),
        ]:
            for match in pattern.finditer(code):
                raw_path = match.group("path") if "path" in match.groupdict() else \
                           match.group("cspath") if "cspath" in match.groupdict() else \
                           match.group("csroute") if "csroute" in match.groupdict() else \
                           match.group("handler_path") if "handler_path" in match.groupdict() else ""
                http_method = method_extractor(match)
                handler = match.groupdict().get("handler", "")
                if not raw_path:
                    continue
                backend_routes.append({
                    "path": raw_path,
                    "method": http_method,
                    "normalized_path": _normalize_route_path(raw_path),
                    "handler": handler or f"{rel}:{match.start()}",
                    "file": rel,
                    "language": lang,
                })

    return backend_routes


def build_openapi_bridges(
    root_dir: Path,
    *,
    spec_paths: list[Path] | None = None,
) -> list[dict[str, Any]]:
    """Build bridge edges from OpenAPI specs to backend route handlers.

    Returns a list of bridge dicts, each with:
      - spec_file: Path to the OpenAPI spec file
      - spec_path: The route path from the spec
      - spec_method: HTTP method (GET, POST, etc.)
      - operation_id: operationId from the spec
      - handler_file: Matched backend source file
      - handler: Matched handler function/method name
      - handler_line: Approximate line number (0 if unknown)
      - match_type: "exact" or "wildcard"
      - language: Backend language
    """
    spec_files = _discover_openapi_files(root_dir, spec_paths)
    if not spec_files:
        return []

    # Load all specs
    spec_routes: list[dict[str, Any]] = []
    for spec_file in spec_files:
        spec_data = _load_spec(spec_file)
        if spec_data is None:
            continue
        routes = _extract_openapi_routes(spec_data)
        for route in routes:
            route["spec_file"] = str(spec_file.resolve())
        spec_routes.extend(routes)

    if not spec_routes:
        return []

    # Extract backend routes from source
    backend_routes = _extract_backend_routes_from_source(root_dir)
    if not backend_routes:
        # Return spec routes as unmatched bridges
        return [
            {
                "spec_file": r["spec_file"],
                "spec_path": r["path"],
                "spec_method": r["method"],
                "normalized_path": r["normalized_path"],
                "operation_id": r["operation_id"],
                "handler_file": "",
                "handler": "",
                "handler_line": 0,
                "match_type": "unmatched",
                "language": "",
            }
            for r in spec_routes
        ]

    # Match spec routes to backend handlers
    bridges: list[dict[str, Any]] = []
    for route in spec_routes:
        handler = _find_backend_handler(route["normalized_path"], route["method"], backend_routes)
        if handler is not None:
            match_type = "exact" if handler.get("normalized_path") == route["normalized_path"] else "wildcard"
            bridges.append({
                "spec_file": route["spec_file"],
                "spec_path": route["path"],
                "spec_method": route["method"],
                "normalized_path": route["normalized_path"],
                "operation_id": route["operation_id"],
                "handler_file": handler.get("file", ""),
                "handler": handler.get("handler", ""),
                "handler_line": 0,
                "match_type": match_type,
                "language": handler.get("language", ""),
            })
        else:
            bridges.append({
                "spec_file": route["spec_file"],
                "spec_path": route["path"],
                "spec_method": route["method"],
                "normalized_path": route["normalized_path"],
                "operation_id": route["operation_id"],
                "handler_file": "",
                "handler": "",
                "handler_line": 0,
                "match_type": "unmatched",
                "language": "",
            })

    return bridges


def bridge_stats(bridges: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute aggregate statistics from a list of bridge edges."""
    total = len(bridges)
    matched = sum(1 for b in bridges if b["match_type"] != "unmatched")
    unmatched = total - matched
    by_language: dict[str, int] = {}
    for b in bridges:
        lang = b.get("language", "") or "unknown"
        by_language[lang] = by_language.get(lang, 0) + 1
    return {
        "total_routes": total,
        "matched_handlers": matched,
        "unmatched_routes": unmatched,
        "match_rate_pct": round(matched / total * 100, 1) if total else 0.0,
        "by_language": dict(sorted(by_language.items(), key=lambda x: -x[1])),
    }


def cli_bridge_report(root_dir_str: str) -> str:
    """CLI-friendly report of OpenAPI bridge discovery results."""
    root = Path(root_dir_str).resolve()
    bridges = build_openapi_bridges(root)
    if not bridges:
        return f"No OpenAPI specs found in {root}"

    stats = bridge_stats(bridges)
    lines = [
        f"OpenAPI Bridge Report — {root}",
        "=" * 60,
        f"Spec routes found    : {stats['total_routes']}",
        f"Backend handlers     : {stats['matched_handlers']}",
        f"Unmatched            : {stats['unmatched_routes']}",
        f"Match rate           : {stats['match_rate_pct']}%",
        "",
        "By language:",
    ]
    for lang, count in stats["by_language"].items():
        lines.append(f"  {lang:<15} {count}")
    lines.append("")

    matched = [b for b in bridges if b["match_type"] != "unmatched"]
    if matched:
        lines.append(f"Matched bridges ({len(matched)}):")
        for b in matched[:20]:
            lines.append(f"  {b['spec_method']} {b['spec_path']:<35} {b['spec_file']}")
            lines.append(f"    → {b['handler_file']}:{b['handler']} ({b['language']})")

    unmatched_routes = [b for b in bridges if b["match_type"] == "unmatched"]
    if unmatched_routes:
        lines.append(f"\nUnmatched routes ({len(unmatched_routes)}):")
        for b in unmatched_routes[:10]:
            op = f" ({b['operation_id']})" if b.get("operation_id") else ""
            lines.append(f"  {b['spec_method']} {b['spec_path']}{op}")
    return "\n".join(lines)
