"""
Framework profiles — domain-specific knowledge for each major web framework.

Each profile defines:
  - GUARDS: patterns indicating a route/method is protected (auth, CSRF, etc.)
  - SINKS: security-sensitive sink patterns specific to the framework
  - SOURCES: patterns that introduce user-controlled data

These are consumed by language analyzers to improve precision (fewer FPs)
and recall (detect framework-specific vulnerability patterns).

YAML specs in ``rules/specs/`` provide the same information in a
declarative, language-agnostic format consumable by the shared engine.
Use ``get_framework_spec(language, framework)`` to load both.
"""

from __future__ import annotations

from guardmarly.frameworks.spring import SpringProfile  # noqa: F401
from guardmarly.frameworks.aspnet import AspNetProfile  # noqa: F401
from guardmarly.frameworks.django import DjangoProfile  # noqa: F401
from guardmarly.frameworks.express import ExpressProfile  # noqa: F401
from guardmarly.frameworks.gin import GinProfile  # noqa: F401
from guardmarly.frameworks.quarkus import QuarkusProfile  # noqa: F401


def get_framework_spec(language: str, framework: str | None = None):
    """Load a framework spec in the best available format.

    Returns a ``SecuritySpec`` (YAML spec) if available, otherwise falls
    back to the Python dataclass profile. This is the unified entry point
    for analyzers that want framework-specific security knowledge.
    """
    try:
        from guardmarly.engine.spec_loader import load_spec  # noqa: PLC0415
        spec = load_spec(language, framework)
        if spec is not None:
            return spec
    except (ImportError, OSError):
        pass

    # Fallback: Python dataclass profiles
    if framework is None:
        framework = ""

    fw_lower = framework.lower()
    lang_lower = language.lower()

    if lang_lower in ("python", "py"):
        if fw_lower in ("django", "drf", ""):
            return DjangoProfile()
    elif lang_lower in ("javascript", "js", "typescript", "ts"):
        if fw_lower in ("express", ""):
            return ExpressProfile()
    elif lang_lower == "java":
        if fw_lower in ("spring", ""):
            return SpringProfile()
    elif lang_lower in ("csharp", "cs", "c#"):
        if fw_lower in ("aspnet", "asp.net", "asp-net", ""):
            return AspNetProfile()
    elif lang_lower == "go":
        if fw_lower in ("gin", ""):
            return GinProfile()

    return None


# Map of language → known framework names (for discovery)
KNOWN_FRAMEWORKS: dict[str, list[str]] = {
    "python": ["django", "flask", "fastapi"],
    "javascript": ["express", "nestjs", "nextjs"],
    "java": ["spring", "quarkus"],
    "csharp": ["aspnet"],
    "go": ["gin", "echo"],
    "php": ["laravel", "symfony"],
    "ruby": ["rails"],
}

