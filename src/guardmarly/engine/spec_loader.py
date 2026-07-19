"""
Spec loader — Loads declarative YAML security specs for languages and frameworks.

Specs live in ``rules/specs/<language>/`` and define sources, sinks, sanitizers,
propagators, route extractors, auth checks, ownership checks, and middleware
patterns consumed by the shared taint engine.

Uses the zero-dependency YAML parser from ``guardmarly.yaml_rules``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from guardmarly.yaml_rules import _load_yaml_or_json

# ── Data classes for spec entries ──────────────────────────────────────────

@dataclass(frozen=True)
class SourceSpec:
    """A taint source — where user-controlled data enters the app."""
    id: str
    pattern: str = ""
    kind: str = ""  # http_param, http_header, route_param, file_upload, etc.
    description: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SourceSpec":
        return cls(
            id=d.get("id", ""),
            pattern=d.get("pattern", ""),
            kind=d.get("kind", ""),
            description=d.get("description", d.get("note", "")),
        )


@dataclass(frozen=True)
class SinkSpec:
    """A security sink — where tainted data causes harm."""
    id: str
    pattern: str
    cwe: str = ""
    severity: str = "medium"
    description: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SinkSpec":
        return cls(
            id=d.get("id", ""),
            pattern=d.get("pattern", ""),
            cwe=d.get("cwe", ""),
            severity=d.get("severity", "medium"),
            description=d.get("description", d.get("note", "")),
        )


@dataclass(frozen=True)
class SanitizerSpec:
    """A sanitizer — a pattern that neutralizes taint."""
    id: str
    pattern: str
    description: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SanitizerSpec":
        return cls(
            id=d.get("id", ""),
            pattern=d.get("pattern", ""),
            description=d.get("description", d.get("note", "")),
        )


@dataclass(frozen=True)
class PropagatorSpec:
    """A propagator — an operation that moves taint without neutralizing it."""
    id: str
    pattern: str
    description: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PropagatorSpec":
        return cls(
            id=d.get("id", ""),
            pattern=d.get("pattern", ""),
            description=d.get("description", d.get("note", "")),
        )


@dataclass(frozen=True)
class RouteExtractorSpec:
    """A route extractor — pattern that identifies route definitions."""
    id: str
    pattern: str
    captures: list[str] = field(default_factory=list)
    framework: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RouteExtractorSpec":
        captures = d.get("captures", [])
        if isinstance(captures, list):
            captures = [str(c) for c in captures]
        return cls(
            id=d.get("id", ""),
            pattern=d.get("pattern", ""),
            captures=captures,
            framework=d.get("framework", ""),
        )


@dataclass(frozen=True)
class AuthCheckSpec:
    """An auth check — presence means the handler IS protected."""
    id: str
    pattern: str
    effect: str = "protect"  # "protect" | "exempt"

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AuthCheckSpec":
        return cls(
            id=d.get("id", ""),
            pattern=d.get("pattern", ""),
            effect=d.get("effect", "protect"),
        )


@dataclass(frozen=True)
class OwnershipCheckSpec:
    """An ownership check — scoping queries to the current user."""
    id: str
    pattern: str

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "OwnershipCheckSpec":
        return cls(
            id=d.get("id", ""),
            pattern=d.get("pattern", ""),
        )


@dataclass(frozen=True)
class MiddlewareSpec:
    """Middleware — checked for auth coverage across the app."""
    id: str
    pattern: str

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "MiddlewareSpec":
        return cls(
            id=d.get("id", ""),
            pattern=d.get("pattern", ""),
        )


# ── Full spec for a language + optional framework ─────────────────────────

@dataclass(frozen=True)
class SecuritySpec:
    """Complete security spec for a language (and optionally a framework)."""
    spec_version: int
    language: str
    framework: str = ""
    description: str = ""
    sources: list[SourceSpec] = field(default_factory=list)
    sinks: list[SinkSpec] = field(default_factory=list)
    sanitizers: list[SanitizerSpec] = field(default_factory=list)
    propagators: list[PropagatorSpec] = field(default_factory=list)
    route_extractors: list[RouteExtractorSpec] = field(default_factory=list)
    auth_checks: list[AuthCheckSpec] = field(default_factory=list)
    ownership_checks: list[OwnershipCheckSpec] = field(default_factory=list)
    middleware: list[MiddlewareSpec] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SecuritySpec":
        return cls(
            spec_version=d.get("spec_version", 1),
            language=d.get("language", ""),
            framework=d.get("framework", ""),
            description=d.get("description", ""),
            sources=[SourceSpec.from_dict(s) for s in d.get("sources", [])],
            sinks=[SinkSpec.from_dict(s) for s in d.get("sinks", [])],
            sanitizers=[SanitizerSpec.from_dict(s) for s in d.get("sanitizers", [])],
            propagators=[PropagatorSpec.from_dict(p) for p in d.get("propagators", [])],
            route_extractors=[RouteExtractorSpec.from_dict(r) for r in d.get("route_extractors", [])],
            auth_checks=[AuthCheckSpec.from_dict(a) for a in d.get("auth_checks", [])],
            ownership_checks=[OwnershipCheckSpec.from_dict(o) for o in d.get("ownership_checks", [])],
            middleware=[MiddlewareSpec.from_dict(m) for m in d.get("middleware", [])],
        )

    def get_sources_by_kind(self, kind: str) -> list[SourceSpec]:
        """Get all sources of a specific kind (e.g., 'http_param')."""
        return [s for s in self.sources if s.kind == kind]

    def get_sinks_by_cwe(self, cwe: str) -> list[SinkSpec]:
        """Get all sinks for a specific CWE."""
        return [s for s in self.sinks if s.cwe.upper() == cwe.upper()]

    def get_sinks_by_severity(self, severity: str) -> list[SinkSpec]:
        """Get all sinks of a given minimum severity."""
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        threshold = severity_order.get(severity.lower(), 0)
        return [s for s in self.sinks if severity_order.get(s.severity.lower(), 0) >= threshold]

    def get_auth_checks(self, *, include_exempt: bool = False) -> list[AuthCheckSpec]:
        """Get auth checks. Pass include_exempt=True to also get AllowAny/csrf_exempt patterns."""
        if include_exempt:
            return list(self.auth_checks)
        return [a for a in self.auth_checks if a.effect != "exempt"]

    def is_empty(self) -> bool:
        """True if the spec has no meaningful content."""
        return not any([
            self.sources, self.sinks, self.sanitizers, self.propagators,
            self.route_extractors, self.auth_checks, self.ownership_checks, self.middleware,
        ])


# ── Spec loader ───────────────────────────────────────────────────────────

def _resolve_specs_dir() -> Path:
    """Resolve the rules/specs/ directory relative to the repo root."""
    # Try relative to this file first (for installed packages)
    this_dir = Path(__file__).resolve().parent.parent  # guardmarly/
    specs_dir = this_dir.parent / "rules" / "specs"
    if specs_dir.is_dir():
        return specs_dir

    # Try relative to cwd (for development)
    cwd_specs = Path("rules/specs")
    if cwd_specs.is_dir():
        return cwd_specs.resolve()

    # Try relative to the guardmarly package
    pkg_specs = this_dir / "rules" / "specs"
    if pkg_specs.is_dir():
        return pkg_specs

    return specs_dir  # Return the most likely path even if it doesn't exist


@lru_cache(maxsize=32)
def _load_spec_file(path: str) -> SecuritySpec | None:
    """Load a single spec YAML file, cached."""
    p = Path(path)
    if not p.is_file():
        return None
    try:
        data = _load_yaml_or_json(p)
        if not isinstance(data, dict):
            return None
        return SecuritySpec.from_dict(data)
    except (OSError, ValueError, KeyError) as e:
        import logging
        _log = logging.getLogger(__name__)
        _log.warning("Failed to load spec %s: %s", p, e)
        return None


def list_available_specs(specs_dir: Path | None = None) -> dict[str, list[str]]:
    """List all available spec files, grouped by language.

    Returns:
        dict mapping language → list of spec file stems (e.g., 'core', 'django')
    """
    if specs_dir is None:
        specs_dir = _resolve_specs_dir()

    result: dict[str, list[str]] = {}
    if not specs_dir.is_dir():
        return result

    for lang_dir in sorted(specs_dir.iterdir()):
        if not lang_dir.is_dir():
            continue
        yaml_files = sorted(
            f.stem for f in lang_dir.glob("*.yaml")
            if f.is_file()
        )
        if yaml_files:
            result[lang_dir.name] = yaml_files

    return result


def load_spec(
    language: str,
    framework: str | None = None,
    *,
    specs_dir: Path | None = None,
) -> SecuritySpec | None:
    """Load the security spec for a language and optional framework.

    Args:
        language: Language name (e.g., 'python', 'javascript')
        framework: Optional framework name (e.g., 'django', 'express')
        specs_dir: Override the specs directory

    Returns:
        Merged SecuritySpec or None if no spec files found.
    """
    if specs_dir is None:
        specs_dir = _resolve_specs_dir()

    lang_dir = specs_dir / language
    if not lang_dir.is_dir():
        return None

    # Load core spec first (always)
    core_spec = _load_spec_file(str(lang_dir / "core.yaml"))

    # Load framework spec if requested
    fw_spec = None
    if framework:
        fw_path = lang_dir / f"{framework}.yaml"
        fw_spec = _load_spec_file(str(fw_path))

    # Merge: framework spec extends core spec
    if core_spec is None and fw_spec is None:
        return None

    return _merge_specs(core_spec, fw_spec, language, framework or "")


def load_all_specs_for_language(
    language: str,
    *,
    specs_dir: Path | None = None,
) -> list[SecuritySpec]:
    """Load all specs for a language (core + all framework specs)."""
    if specs_dir is None:
        specs_dir = _resolve_specs_dir()

    lang_dir = specs_dir / language
    if not lang_dir.is_dir():
        return []

    specs: list[SecuritySpec] = []
    for yaml_file in sorted(lang_dir.glob("*.yaml")):
        spec = _load_spec_file(str(yaml_file))
        if spec is not None and not spec.is_empty():
            specs.append(spec)

    return specs


def _merge_specs(
    core: SecuritySpec | None,
    framework: SecuritySpec | None,
    language: str,
    framework_name: str,
) -> SecuritySpec:
    """Merge a core spec with a framework spec. Framework extends core."""
    if core is None and framework is None:
        return SecuritySpec(spec_version=1, language=language)

    if core is None:
        return framework  # type: ignore[return-value]

    if framework is None:
        return core

    # Framework specs add to core specs; framework entries take precedence
    # for deduplication by id
    core_source_ids = {s.id for s in core.sources}
    core_sink_ids = {s.id for s in core.sinks}
    core_sanitizer_ids = {s.id for s in core.sanitizers}
    core_propagator_ids = {s.id for s in core.propagators}

    return SecuritySpec(
        spec_version=core.spec_version,
        language=language,
        framework=framework_name,
        description=f"{core.description} + {framework.description}".strip(" +"),
        sources=core.sources + [s for s in framework.sources if s.id not in core_source_ids],
        sinks=core.sinks + [s for s in framework.sinks if s.id not in core_sink_ids],
        sanitizers=core.sanitizers + [s for s in framework.sanitizers if s.id not in core_sanitizer_ids],
        propagators=core.propagators + [s for s in framework.propagators if s.id not in core_propagator_ids],
        route_extractors=core.route_extractors + framework.route_extractors,
        auth_checks=core.auth_checks + framework.auth_checks,
        ownership_checks=core.ownership_checks + framework.ownership_checks,
        middleware=core.middleware + framework.middleware,
    )
