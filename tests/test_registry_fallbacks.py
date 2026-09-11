"""
tests.test_registry_fallbacks
─────────────────────────────
Regression tests for the registry pack loading fallbacks.

Both fallback paths referenced names that were never bound in their scope, so
they raised ``NameError`` instead of degrading gracefully:

* ``registry.loader.load_packs_for_source`` used ``normalised`` (defined only in
  ``load_packs_for_language``) when no framework marker matched the source.
* ``registry.sharded_loader.load_pack`` used ``_REGISTRY_DIR`` (defined only in
  ``registry.loader``) for the JSON pack fallback.
"""
from __future__ import annotations

from guardmarly.registry import sharded_loader
from guardmarly.registry.loader import (
    load_all_registry_packs,
    load_packs_for_language,
    load_packs_for_source,
)

FRAMEWORK_FREE_PYTHON = """
def add(a, b):
    return a + b
"""

FRAMEWORK_FREE_JS = """
function add(a, b) {
    return a + b;
}
"""


def test_framework_free_python_source_loads_generic_packs_only():
    rules = load_packs_for_source(FRAMEWORK_FREE_PYTHON, "python")

    assert isinstance(rules, list)


def test_framework_free_js_source_loads_generic_packs_only():
    rules = load_packs_for_source(FRAMEWORK_FREE_JS, "javascript")

    assert isinstance(rules, list)


def test_language_aliases_normalise_consistently():
    for alias in ("py", "python", "PYTHON"):
        assert isinstance(load_packs_for_language(alias), list)

    assert len(load_packs_for_language("js")) == len(load_packs_for_language("javascript"))


def test_json_pack_fallback_does_not_raise():
    """Unknown pack names must fall through to the JSON path, not crash."""
    for pack_name in ("definitely_not_a_pack", "django"):
        assert isinstance(sharded_loader.load_pack(pack_name), list)


def test_registry_catalogue_is_non_empty():
    assert load_all_registry_packs(), "registry packs should load for --list-rules"
