"""Analysis compatibility modules.

These lightweight adapters preserve blueprint paths while delegating to
existing production analyzers.
"""

from .framework_detector import FrameworkProfile, detect_framework_profile
from .interprocedural import GlobalProjectIndex, SymbolLocation, build_project_index

__all__ = [
    "FrameworkProfile",
    "detect_framework_profile",
    "GlobalProjectIndex",
    "SymbolLocation",
    "build_project_index",
]
