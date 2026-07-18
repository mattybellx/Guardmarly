from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class FrameworkProfile:
    django: bool = False
    flask: bool = False
    fastapi: bool = False

    @property
    def detected(self) -> tuple[str, ...]:
        names: list[str] = []
        if self.django:
            names.append("django")
        if self.flask:
            names.append("flask")
        if self.fastapi:
            names.append("fastapi")
        return tuple(names)


def _update_from_import(node: ast.Import, state: dict[str, bool]) -> None:
    for alias in node.names:
        name = alias.name.lower()
        state["django"] = state["django"] or name.startswith("django")
        state["flask"] = state["flask"] or name.startswith("flask")
        state["fastapi"] = state["fastapi"] or name.startswith("fastapi")


def _update_from_import_from(node: ast.ImportFrom, state: dict[str, bool]) -> None:
    module = (node.module or "").lower()
    state["django"] = state["django"] or module.startswith("django")
    state["flask"] = state["flask"] or module.startswith("flask")
    state["fastapi"] = state["fastapi"] or module.startswith("fastapi")


def _update_from_function(node: ast.FunctionDef, state: dict[str, bool]) -> None:
    for deco in node.decorator_list:
        text = ast.unparse(deco) if hasattr(ast, "unparse") else ""
        if ".route(" in text and "router." not in text:
            state["flask"] = True
        if any(token in text for token in ("router.get", "router.post", "router.put", "router.patch", "router.delete")):
            state["fastapi"] = True


def _update_from_class(node: ast.ClassDef, state: dict[str, bool]) -> None:
    for base in node.bases:
        base_name = ast.unparse(base) if hasattr(ast, "unparse") else ""
        if "LoginRequiredMixin" in base_name:
            state["django"] = True


def detect_framework_profile(source: str) -> FrameworkProfile:
    """Return framework context signals used to tune route/auth heuristics."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        lowered = source.lower()
        return FrameworkProfile(
            django=("django" in lowered),
            flask=("flask" in lowered),
            fastapi=("fastapi" in lowered),
        )

    state = {"django": False, "flask": False, "fastapi": False}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            _update_from_import(node, state)
        elif isinstance(node, ast.ImportFrom):
            _update_from_import_from(node, state)
        elif isinstance(node, ast.FunctionDef):
            _update_from_function(node, state)
        elif isinstance(node, ast.ClassDef):
            _update_from_class(node, state)

    return FrameworkProfile(
        django=state["django"],
        flask=state["flask"],
        fastapi=state["fastapi"],
    )
