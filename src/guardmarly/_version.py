"""
guardmarly._version
───────────────────
Single source of truth for the package version.

``pyproject.toml`` reads this file via ``[tool.hatch.version]`` and every
runtime consumer (CLI ``--version``, JSON/SARIF envelopes, ``--show-stats``)
reads it back through :func:`guardmarly.engine_version.get_engine_version`, so
the released artefact, the source tree and the reported version can never
drift apart. Bump this value when cutting a release.
"""

from __future__ import annotations

__version__ = "6.6.0"

__all__ = ["__version__"]
