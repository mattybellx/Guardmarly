"""
guardmarly_rust_core — Native Rust extraction engine.

Redirects to the python/ subdirectory where the actual package lives
(built via maturin). This prevents the namespace-package shadowing issue.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure the python/ subdirectory is on sys.path so the real
# guardmarly_rust_core package (with _core.pyd) is found first.
_python_dir = str(Path(__file__).resolve().parent / "python")
if _python_dir not in sys.path:
    sys.path.insert(0, _python_dir)

# Re-import the real package from python/guardmarly_rust_core/
import importlib
_real_pkg = importlib.import_module("guardmarly_rust_core")

# Copy all public attributes
__all__ = []
for _attr in dir(_real_pkg):
    if not _attr.startswith("_"):
        globals()[_attr] = getattr(_real_pkg, _attr)
        __all__.append(_attr)
