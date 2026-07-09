"""
ansede_static.engine_version
────────────────────────────
Shared engine and schema version helpers.
"""
from __future__ import annotations

from typing import Any

ENGINE_NAME = "ansede-static"
SCHEMA_VERSION = "1.0"

# Hardcoded fallback when importlib.metadata is unavailable (Nuitka, frozen builds)
_FALLBACK_VERSION = "6.1.1"


def get_engine_version() -> str:
    """Return the installed package version, or the fallback when unavailable."""
    try:
        from importlib.metadata import PackageNotFoundError
    except ImportError:
        PackageNotFoundError = Exception
    try:
        from importlib.metadata import version
        return version(ENGINE_NAME)
    except (ImportError, PackageNotFoundError):
        return _FALLBACK_VERSION


def get_engine_record() -> dict[str, Any]:
    """Return a compact engine metadata record for report envelopes."""
    from ansede_static.js_engine.backends import list_js_backends

    return {
        "name": ENGINE_NAME,
        "version": get_engine_version(),
        "schema_version": SCHEMA_VERSION,
        "js_backends": [backend.as_dict() for backend in list_js_backends()],
    }