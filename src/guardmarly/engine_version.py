"""
guardmarly.engine_version
────────────────────────────
Shared engine and schema version helpers.
"""
from __future__ import annotations

from typing import Any

ENGINE_NAME = "guardmarly"
SCHEMA_VERSION = "1.0"

# Sentinel used only when neither the source tree nor installed metadata can
# tell us the version. Never report a plausible-looking number here: a stale
# literal silently mislabels every report produced by a source checkout.
_UNKNOWN_VERSION = "0.0.0+unknown"


def get_engine_version() -> str:
    """Return the package version.

    Resolution order:

    1. ``guardmarly._version`` — shipped in the wheel/sdist and present in the
       source tree, so it is authoritative even for an editable install whose
       ``dist-info`` metadata predates the current source.
    2. Installed distribution metadata (covers frozen/Nuitka builds that strip
       the module).
    3. :data:`_UNKNOWN_VERSION` — an explicit sentinel rather than a stale
       version number.
    """
    try:
        from guardmarly._version import __version__ as source_version

        if source_version:
            return source_version
    except (ImportError, AttributeError):
        pass

    try:
        from importlib.metadata import PackageNotFoundError, version
    except ImportError:
        return _UNKNOWN_VERSION

    try:
        return version(ENGINE_NAME)
    except (ImportError, PackageNotFoundError, ValueError):
        return _UNKNOWN_VERSION


def get_engine_record() -> dict[str, Any]:
    """Return a compact engine metadata record for report envelopes."""
    from guardmarly.js_engine.backends import list_js_backends

    return {
        "name": ENGINE_NAME,
        "version": get_engine_version(),
        "schema_version": SCHEMA_VERSION,
        "js_backends": [backend.as_dict() for backend in list_js_backends()],
    }