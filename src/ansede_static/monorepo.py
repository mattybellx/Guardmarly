"""
ansede_static.monorepo
──────────────────────
Monorepo topology detection and workspace boundary discovery.

Detects common monorepo configurations and returns the list of sub-package
roots so that diffed-file scanning can be scoped to only affected packages.

Supported workspace formats:
  - pnpm-workspace.yaml
  - nx.json (Nx monorepo)
  - lerna.json
  - rush.json
  - package.json with "workspaces" key (Yarn/npm workspaces)
  - pyproject.toml with [tool.poetry.packages] or namespace packages
  - Python namespace packages (implicit — src/ with multiple packages)

Zero external dependencies — pure stdlib only.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class MonorepoInfo:
    """Result of monorepo detection for a workspace root."""
    is_monorepo: bool = False
    kind: str = ""                     # "pnpm" | "nx" | "lerna" | "yarn" | "rush" | "python-namespace"
    workspace_root: Path = field(default_factory=Path)
    packages: list[Path] = field(default_factory=list)   # detected sub-package roots
    config_file: str = ""             # path to the config file that was detected

    def package_for_path(self, file_path: Path) -> Path | None:
        """Return the sub-package root that contains *file_path*, or None."""
        for pkg in self.packages:
            try:
                file_path.relative_to(pkg)
                return pkg
            except ValueError:
                continue
        return None

    def affected_packages(self, changed_files: list[Path]) -> list[Path]:
        """Return sub-packages that contain at least one file in *changed_files*."""
        affected: list[Path] = []
        seen: set[Path] = set()
        for fpath in changed_files:
            pkg = self.package_for_path(fpath)
            if pkg and pkg not in seen:
                seen.add(pkg)
                affected.append(pkg)
        return affected


def detect_monorepo(workspace_root: Path) -> MonorepoInfo:
    """Analyse *workspace_root* and return a :class:`MonorepoInfo`."""
    info = MonorepoInfo(workspace_root=workspace_root)

    # pnpm-workspace.yaml
    pnpm_file = workspace_root / "pnpm-workspace.yaml"
    if pnpm_file.is_file():
        info.is_monorepo = True
        info.kind = "pnpm"
        info.config_file = str(pnpm_file)
        info.packages = _resolve_glob_patterns(
            workspace_root, _parse_pnpm_workspace(pnpm_file)
        )
        return info

    # Nx monorepo
    nx_file = workspace_root / "nx.json"
    if nx_file.is_file():
        info.is_monorepo = True
        info.kind = "nx"
        info.config_file = str(nx_file)
        # Nx projects live under apps/ and libs/ by convention; also check nx.json
        info.packages = _discover_nx_packages(workspace_root, nx_file)
        return info

    # Lerna
    lerna_file = workspace_root / "lerna.json"
    if lerna_file.is_file():
        info.is_monorepo = True
        info.kind = "lerna"
        info.config_file = str(lerna_file)
        info.packages = _resolve_glob_patterns(
            workspace_root, _parse_lerna_packages(lerna_file)
        )
        return info

    # Rush
    rush_file = workspace_root / "rush.json"
    if rush_file.is_file():
        info.is_monorepo = True
        info.kind = "rush"
        info.config_file = str(rush_file)
        info.packages = _parse_rush_projects(workspace_root, rush_file)
        return info

    # Yarn / npm workspaces (package.json "workspaces" key)
    pkg_json = workspace_root / "package.json"
    if pkg_json.is_file():
        patterns = _parse_npm_workspaces(pkg_json)
        if patterns:
            info.is_monorepo = True
            info.kind = "yarn"
            info.config_file = str(pkg_json)
            info.packages = _resolve_glob_patterns(workspace_root, patterns)
            return info

    # Python namespace package detection (src/ with multiple top-level packages)
    python_ns = _detect_python_namespace(workspace_root)
    if python_ns:
        info.is_monorepo = True
        info.kind = "python-namespace"
        info.config_file = ""
        info.packages = python_ns
        return info

    return info


# ──────────────────────────────────────────────────────────────────────────────
# Per-format parsers
# ──────────────────────────────────────────────────────────────────────────────

def _parse_pnpm_workspace(path: Path) -> list[str]:
    """Return glob patterns from pnpm-workspace.yaml (regex, no yaml lib required)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    patterns: list[str] = []
    in_packages = False
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"^packages\s*:", stripped):
            in_packages = True
            continue
        if in_packages:
            if stripped and not stripped.startswith("-") and ":" in stripped:
                break
            m = re.match(r"^-\s+['\"]?([^'\"]+)['\"]?$", stripped)
            if m:
                patterns.append(m.group(1).strip())
    return patterns


def _parse_lerna_packages(path: Path) -> list[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return ["packages/*"]
    return data.get("packages", ["packages/*"])


def _parse_npm_workspaces(path: Path) -> list[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []
    ws = data.get("workspaces", [])
    if isinstance(ws, list):
        return [str(p) for p in ws if isinstance(p, str)]
    if isinstance(ws, dict):
        return [str(p) for p in ws.get("packages", []) if isinstance(p, str)]
    return []


def _parse_rush_projects(root: Path, path: Path) -> list[Path]:
    try:
        # Rush JSON may have C-style comments — strip them first
        text = path.read_text(encoding="utf-8", errors="replace")
        text = re.sub(r"//[^\n]*", "", text)
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
        data = json.loads(text)
    except (OSError, json.JSONDecodeError):
        return []
    paths: list[Path] = []
    for project in data.get("projects", []):
        folder = project.get("projectFolder", "")
        if folder:
            pkg_path = root / folder
            if pkg_path.is_dir():
                paths.append(pkg_path)
    return paths


def _discover_nx_packages(root: Path, nx_file: Path) -> list[Path]:
    """Return package roots from Nx's apps/ and libs/ convention, plus any
    explicitly listed in nx.json's 'projects' key."""
    paths: list[Path] = []
    seen: set[Path] = set()

    # Convention-based
    for sub in ("apps", "libs", "packages"):
        sub_dir = root / sub
        if sub_dir.is_dir():
            for child in sub_dir.iterdir():
                if child.is_dir() and child not in seen:
                    seen.add(child)
                    paths.append(child)

    # Explicit projects in nx.json
    try:
        data = json.loads(nx_file.read_text(encoding="utf-8", errors="replace"))
        projects = data.get("projects", {})
        if isinstance(projects, dict):
            for _name, proj_path in projects.items():
                if isinstance(proj_path, str):
                    p = root / proj_path
                    if p.is_dir() and p not in seen:
                        seen.add(p)
                        paths.append(p)
                elif isinstance(proj_path, dict):
                    root_str = proj_path.get("root", "")
                    if root_str:
                        p = root / root_str
                        if p.is_dir() and p not in seen:
                            seen.add(p)
                            paths.append(p)
    except (OSError, json.JSONDecodeError):
        pass

    return paths


def _detect_python_namespace(root: Path) -> list[Path]:
    """Detect Python namespace / multi-package layouts under src/."""
    candidates: list[Path] = []
    src = root / "src"
    if src.is_dir():
        # A namespace monorepo typically has multiple Python packages under src/
        for child in src.iterdir():
            if child.is_dir() and (child / "__init__.py").is_file():
                candidates.append(child)
        if len(candidates) >= 2:
            return candidates
    return []


# ──────────────────────────────────────────────────────────────────────────────
# Glob expander
# ──────────────────────────────────────────────────────────────────────────────

def _resolve_glob_patterns(root: Path, patterns: list[str]) -> list[Path]:
    """Expand simple glob patterns (supporting ** and *) relative to *root*."""
    resolved: list[Path] = []
    seen: set[Path] = set()
    for pattern in patterns:
        # Normalise: replace backslashes, strip leading ./
        pattern = pattern.replace("\\", "/").lstrip("./")
        # Use pathlib glob if pattern contains wildcards
        if "*" in pattern:
            for match in sorted(root.glob(pattern)):
                if match.is_dir() and match not in seen:
                    seen.add(match)
                    resolved.append(match)
        else:
            p = root / pattern
            if p.is_dir() and p not in seen:
                seen.add(p)
                resolved.append(p)
    return resolved
