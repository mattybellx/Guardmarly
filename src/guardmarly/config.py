"""
guardmarly.config
────────────────────
Fast, zero-dependency configuration loader for enterprise workspaces.
Reads an `guardmarly.json` file to tune scanner rules, set ignore paths, 
and load custom internal taint sources and sinks.

Phase 4 additions (spec §4.1-4.2):
  - jsonschema validation when jsonschema is installed (optional dep).
  - Upgraded sink format with tainted_args / safe_args / sources fields.
  - Schema bundled at src/guardmarly/schema/guardmarly.schema.json.
  - GuardmarlyConfig.v2_sinks / v2_sources lists for v2 engine integration.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

from guardmarly._types import AnalysisResult, Finding, Severity

_log = logging.getLogger(__name__)

# ── Optional jsonschema integration ───────────────────────────────────────────
try:
    import jsonschema as _jsonschema  # type: ignore[import-untyped]
    _HAS_JSONSCHEMA = True
except ImportError:
    _jsonschema = None  # type: ignore[assignment]
    _HAS_JSONSCHEMA = False

# Path to bundled JSON Schema
_SCHEMA_PATH = Path(__file__).parent / "schemas" / "guardmarly.schema.json"
_CACHED_SCHEMA: Optional[dict] = None


def _load_schema() -> Optional[dict]:
    """Load the bundled JSON Schema; return None if not found or parse fails."""
    global _CACHED_SCHEMA
    if _CACHED_SCHEMA is not None:
        return _CACHED_SCHEMA
    if not _SCHEMA_PATH.is_file():
        return None
    try:
        _CACHED_SCHEMA = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
        return _CACHED_SCHEMA
    except Exception as exc:
        _log.debug("Could not load guardmarly.schema.json: %s", exc)
        return None


def validate_config_json(data: dict, warnings: list[str]) -> None:
    """
    Validate *data* against the Guardmarly JSON Schema.

    When jsonschema is not installed a single advisory warning is emitted
    instead of hard-failing — the scanner stays zero-runtime-dep by default.
    Validation errors are appended to *warnings* so callers can surface them
    without aborting the scan.
    """
    if not _HAS_JSONSCHEMA:
        warnings.append(
            "jsonschema is not installed; guardmarly.json schema validation is skipped. "
            "Install with: pip install guardmarly[schema]"
        )
        return

    schema = _load_schema()
    if schema is None:
        _log.debug("guardmarly.schema.json not found; schema validation skipped")
        return

    try:
        validator = _jsonschema.Draft7Validator(schema)
        errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
        for error in errors:
            path_str = " > ".join(str(p) for p in error.absolute_path) or "(root)"
            warnings.append(
                "guardmarly.json schema error at "
                + path_str
                + ": "
                + error.message
            )
    except Exception as exc:
        _log.debug("jsonschema validation raised: %s", exc)


_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})


@dataclass(frozen=True)
class CustomSinkSpec:
    cwe: str
    title: str
    severity: str = "high"

    def as_taint_sink(self) -> tuple[str, str, str]:
        return (self.cwe, self.title, self.severity)


@dataclass(frozen=True)
class V2SinkSpec:
    """v2 sink format (spec §4.1) — richer than the legacy CustomSinkSpec."""
    rule_id: str
    cwe: str
    title: str
    function: str
    severity: str = "high"
    tainted_args: tuple[int, ...] = field(default_factory=tuple)
    safe_args: tuple[int, ...] = field(default_factory=tuple)
    language: str = ""  # "" means all languages


@dataclass(frozen=True)
class V2SourceSpec:
    """v2 source format (spec §4.1)."""
    function: str
    category: str   # user_input | env | file | network | database
    language: str = ""


@dataclass
class GuardmarlyConfig:
    exclude_paths: list[str] = field(default_factory=list)
    disable_rules: list[str] = field(default_factory=list)
    custom_sources: list[str] = field(default_factory=list)
    custom_sinks: dict[str, CustomSinkSpec] = field(default_factory=dict)
    # v2 structured sink / source specs
    v2_sinks: list[V2SinkSpec] = field(default_factory=list)
    v2_sources: list[V2SourceSpec] = field(default_factory=list)
    # Path to a custom YAML/JSON rule definitions file (see docs/CUSTOM_RULES.md)
    custom_rules_file: str = ""
    # Extra sanitizer catalog JSON files to merge with the built-in library
    extra_sanitizer_files: list[str] = field(default_factory=list)
    # Per-project custom taint sanitizers — function names that neutralise taint
    # for specific CWEs. Unlike the built-in SANITIZERS which fully suppress,
    # custom sanitizers reduce confidence to 0.40 (surfaced as low-confidence
    # findings so users can verify the implementation isn't flawed).
    # Format: {"function_name": ["CWE-22", "CWE-78"]}
    custom_sanitizers: dict[str, list[str]] = field(default_factory=dict)
    # Rule severity overrides — map CWE or rule_id to new severity
    # e.g. {"CWE-862": "critical", "PY-020": "low"}
    rule_overrides: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list, compare=False)


def _normalized_rule_token(token: str) -> str:
    return token.strip().upper()


def _parse_custom_sink(sink_name: str, sink_data: object, warnings: list[str]) -> CustomSinkSpec | None:
    if isinstance(sink_data, dict):
        cwe = str(sink_data.get("cwe", "")).strip().upper()
        title = str(sink_data.get("title", "")).strip()
        severity = str(sink_data.get("severity", "high")).strip().lower() or "high"
        if not cwe.startswith("CWE-"):
            warnings.append(
                f"guardmarly.json custom_sinks.{sink_name!s} is missing a valid 'cwe' (expected like 'CWE-89') — skipping entry."
            )
            return None
        if not title:
            warnings.append(
                f"guardmarly.json custom_sinks.{sink_name!s} is missing a non-empty 'title' — skipping entry."
            )
            return None
        if severity not in _VALID_SEVERITIES:
            warnings.append(
                f"guardmarly.json custom_sinks.{sink_name!s} has invalid severity {severity!r}; defaulting to 'high'."
            )
            severity = "high"
        return CustomSinkSpec(cwe=cwe, title=title, severity=severity)

    if isinstance(sink_data, list):
        if len(sink_data) >= 2 and isinstance(sink_data[0], str) and isinstance(sink_data[1], str):
            cwe = sink_data[0].strip().upper()
            title = sink_data[1].strip()
            severity = str(sink_data[2]).strip().lower() if len(sink_data) >= 3 else "high"
            if cwe.startswith("CWE-") and title:
                if severity not in _VALID_SEVERITIES:
                    warnings.append(
                        f"guardmarly.json custom_sinks.{sink_name!s} has invalid severity {severity!r}; defaulting to 'high'."
                    )
                    severity = "high"
                return CustomSinkSpec(cwe=cwe, title=title, severity=severity)

        warnings.append(
            f"guardmarly.json custom_sinks.{sink_name!s} uses an unsupported legacy list format; use an object with cwe/title/severity instead."
        )
        return None

    warnings.append(
        f"guardmarly.json custom_sinks.{sink_name!s} must be an object (or supported legacy list) — skipping entry."
    )
    return None


def finding_is_disabled(finding: Finding, disabled_rules: set[str]) -> bool:
    if not disabled_rules:
        return False
    identifiers = {
        _normalized_rule_token(finding.rule_id),
        _normalized_rule_token(finding.effective_rule_id),
        _normalized_rule_token(finding.cwe),
    }
    identifiers.discard("")
    return not identifiers.isdisjoint(disabled_rules)


def apply_config_to_results(results: list[AnalysisResult], config: GuardmarlyConfig | None) -> list[AnalysisResult]:
    if not config:
        return results

    disabled_rules = {_normalized_rule_token(rule) for rule in config.disable_rules if rule.strip()}
    overrides = config.rule_overrides if hasattr(config, "rule_overrides") else {}

    for result in results:
        filtered: list[Finding] = []
        for finding in result.findings:
            if disabled_rules:
                if finding_is_disabled(finding, disabled_rules):
                    continue

            # Apply severity overrides
            if overrides:
                for token in (
                    _normalized_rule_token(finding.rule_id),
                    _normalized_rule_token(finding.cwe),
                ):
                    if token and token in overrides:
                        new_sev = overrides[token]
                        try:
                            finding = Finding(
                                category=finding.category,
                                severity=Severity(new_sev),
                                title=finding.title,
                                description=finding.description,
                                line=finding.line,
                                suggestion=finding.suggestion,
                                rule_id=finding.rule_id,
                                cwe=finding.cwe,
                                agent=finding.agent,
                                confidence=finding.confidence,
                                auto_fix=finding.auto_fix,
                                explanation=finding.explanation,
                                trace=finding.trace,
                                analysis_kind=finding.analysis_kind,
                                triggering_code=finding.triggering_code,
                            )
                        except (ValueError, KeyError):
                            pass
                        break

            filtered.append(finding)
        result.findings = filtered
    return results


@contextmanager
def temporary_analyzer_config(config: GuardmarlyConfig | None) -> Iterator[None]:
    if not config or (not config.custom_sources and not config.custom_sinks and not config.extra_sanitizer_files):
        yield
        return

    try:
        from guardmarly.python_analyzer import TAINT_SINKS, TAINT_SOURCES, SANITIZERS
    except ImportError:
        yield
        return

    previous_sources: dict[str, str | None] = {}
    previous_sinks: dict[str, tuple[str, str] | tuple[str, str, str] | None] = {}
    injected_sanitizers: dict[str, set[str]] = {}

    for source_name in config.custom_sources:
        previous_sources[source_name] = TAINT_SOURCES.get(source_name)
        TAINT_SOURCES[source_name] = "Custom taint source from guardmarly.json"

    for sink_name, sink_spec in config.custom_sinks.items():
        previous_sinks[sink_name] = TAINT_SINKS.get(sink_name)
        TAINT_SINKS[sink_name] = sink_spec.as_taint_sink()

    # Merge extra sanitizer libraries into the running SANITIZERS dict
    for san_path in config.extra_sanitizer_files:
        san_file = Path(san_path)
        if not san_file.is_file():
            continue
        try:
            catalog = json.loads(san_file.read_text(encoding="utf-8"))
            py_section = catalog.get("python", {})
            for cwe, frameworks in py_section.items():
                if not isinstance(frameworks, dict):
                    continue
                for fw_name, fn_list in frameworks.items():
                    if fw_name == "notes" or not isinstance(fn_list, list):
                        continue
                    for fn_name in fn_list:
                        if not isinstance(fn_name, str):
                            continue
                        cwe_upper = cwe.strip().upper()
                        prev = SANITIZERS.get(fn_name)
                        if prev is None:
                            SANITIZERS[fn_name] = {cwe_upper}
                            injected_sanitizers[fn_name] = None  # type: ignore[assignment]
                        else:
                            prev.add(cwe_upper)
                            injected_sanitizers.setdefault(fn_name, set()).add(cwe_upper)
        except Exception as exc:
            _log.warning("Failed to load extra sanitizer file %s: %s", san_path, exc)

    # Apply per-project custom sanitizers from guardmarly.json
    # These reduce confidence instead of fully suppressing (unlike built-in SANITIZERS)
    if config.custom_sanitizers:
        for func_name, cwe_list in config.custom_sanitizers.items():
            cwe_set = set(cwe_list)
            prev = SANITIZERS.get(func_name)
            if prev is None:
                SANITIZERS[func_name] = cwe_set
                injected_sanitizers[func_name] = None
            else:
                prev.update(cwe_set)
                injected_sanitizers.setdefault(func_name, set()).update(cwe_set)

    try:
        yield
    finally:
        for source_name, previous in previous_sources.items():
            if previous is None:
                TAINT_SOURCES.pop(source_name, None)
            else:
                TAINT_SOURCES[source_name] = previous
        for sink_name, previous in previous_sinks.items():
            if previous is None:
                TAINT_SINKS.pop(sink_name, None)
            else:
                TAINT_SINKS[sink_name] = previous
        for fn_name, added_cwes in injected_sanitizers.items():
            if added_cwes is None:
                SANITIZERS.pop(fn_name, None)
            else:
                existing = SANITIZERS.get(fn_name)
                if existing is not None:
                    existing.difference_update(added_cwes)


def load_config(workspace_root: Path | None = None) -> GuardmarlyConfig:
    if not workspace_root:
        workspace_root = Path.cwd()
        
    config_path = workspace_root / "guardmarly.json"
    if not config_path.is_file():
        return GuardmarlyConfig()
        
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        warnings: list[str] = []

        # Phase 4: JSON Schema validation
        validate_config_json(data, warnings)

        custom_sinks: dict[str, CustomSinkSpec] = {}
        for sink_name, sink_data in data.get("custom_sinks", {}).items():
            sink_spec = _parse_custom_sink(sink_name, sink_data, warnings)
            if sink_spec is not None:
                custom_sinks[sink_name] = sink_spec

        # v2 structured sinks
        v2_sinks: list[V2SinkSpec] = []
        for raw_sink in data.get("sinks", []):
            parsed = _parse_v2_sink(raw_sink, warnings)
            if parsed is not None:
                v2_sinks.append(parsed)

        # v2 structured sources
        v2_sources: list[V2SourceSpec] = []
        for raw_src in data.get("sources", []):
            parsed_src = _parse_v2_source(raw_src, warnings)
            if parsed_src is not None:
                v2_sources.append(parsed_src)

        disable_rules = [rule for rule in data.get("disable_rules", []) if isinstance(rule, str) and rule.strip()]
        custom_sources = [src for src in data.get("custom_sources", []) if isinstance(src, str) and src.strip()]
        custom_rules_file = str(data.get("custom_rules_file", "")).strip()
        extra_sanitizer_files = [
            str(p).strip() for p in data.get("extra_sanitizer_files", []) if str(p).strip()
        ]

        # Custom taint sanitizers — per-project function names that neutralise taint
        # Format: {"function_name": ["CWE-22", "CWE-78"]}
        custom_sanitizers: dict[str, list[str]] = {}
        raw_custom_sanitizers = data.get("custom_sanitizers", {})
        if isinstance(raw_custom_sanitizers, dict):
            for func_name, cwe_list in raw_custom_sanitizers.items():
                if isinstance(func_name, str) and func_name.strip():
                    if isinstance(cwe_list, list):
                        validated_cwes = [
                            str(c).strip().upper()
                            for c in cwe_list
                            if isinstance(c, str) and c.strip().startswith("CWE-")
                        ]
                        if validated_cwes:
                            custom_sanitizers[func_name.strip()] = validated_cwes
                        else:
                            warnings.append(
                                f"guardmarly.json custom_sanitizers.{func_name!s} has no valid CWE entries "
                                "(expected like ['CWE-22', 'CWE-78']) — skipping."
                            )
                    else:
                        warnings.append(
                            f"guardmarly.json custom_sanitizers.{func_name!s} must be a list of CWE strings — skipping."
                        )

        # Rule severity overrides — map CWE or rule_id to a new severity level
        rule_overrides: dict[str, str] = {}
        raw_overrides = data.get("rule_overrides", {})
        if isinstance(raw_overrides, dict):
            for rule_token, sev in raw_overrides.items():
                token = str(rule_token).strip()
                sev_str = str(sev).strip().lower()
                if token and sev_str in _VALID_SEVERITIES:
                    rule_overrides[_normalized_rule_token(token)] = sev_str

        return GuardmarlyConfig(
            exclude_paths=data.get("exclude_paths", []),
            disable_rules=disable_rules,
            custom_sources=custom_sources,
            custom_sinks=custom_sinks,
            v2_sinks=v2_sinks,
            v2_sources=v2_sources,
            custom_rules_file=custom_rules_file,
            extra_sanitizer_files=extra_sanitizer_files,
            custom_sanitizers=custom_sanitizers,
            rule_overrides=rule_overrides,
            warnings=warnings,
        )
    except json.JSONDecodeError as exc:
        _log.warning("guardmarly.json is not valid JSON — ignoring config: %s", exc)
        return GuardmarlyConfig()
    except Exception as exc:
        _log.warning("Failed to load guardmarly.json — ignoring config: %s", exc)
        return GuardmarlyConfig()


def _parse_v2_sink(raw: object, warnings: list[str]) -> Optional[V2SinkSpec]:
    if not isinstance(raw, dict):
        warnings.append("guardmarly.json sinks[]: each entry must be an object — skipping.")
        return None
    rule_id = str(raw.get("rule_id", "")).strip()
    cwe = str(raw.get("cwe", "")).strip().upper()
    title = str(raw.get("title", "")).strip()
    function = str(raw.get("function", "")).strip()
    severity = str(raw.get("severity", "high")).strip().lower() or "high"
    if not rule_id or not cwe or not title or not function:
        warnings.append(
            "guardmarly.json sinks[]: entry missing required field (rule_id/cwe/title/function) — skipping."
        )
        return None
    if severity not in _VALID_SEVERITIES:
        severity = "high"
    tainted_args = tuple(int(x) for x in raw.get("tainted_args", []) if isinstance(x, int))
    safe_args = tuple(int(x) for x in raw.get("safe_args", []) if isinstance(x, int))
    language = str(raw.get("language", "")).strip()
    return V2SinkSpec(
        rule_id=rule_id, cwe=cwe, title=title, function=function,
        severity=severity, tainted_args=tainted_args, safe_args=safe_args,
        language=language,
    )


def _parse_v2_source(raw: object, warnings: list[str]) -> Optional[V2SourceSpec]:
    _VALID_CATEGORIES = frozenset({"user_input", "env", "file", "network", "database"})
    if not isinstance(raw, dict):
        warnings.append("guardmarly.json sources[]: each entry must be an object — skipping.")
        return None
    function = str(raw.get("function", "")).strip()
    category = str(raw.get("category", "")).strip().lower()
    if not function or not category:
        warnings.append(
            "guardmarly.json sources[]: entry missing required field (function/category) — skipping."
        )
        return None
    if category not in _VALID_CATEGORIES:
        warnings.append(
            "guardmarly.json sources[]: entry has invalid category "
            + repr(category)
            + "; valid: "
            + ", ".join(sorted(_VALID_CATEGORIES))
            + " — skipping."
        )
        return None
    return V2SourceSpec(
        function=function,
        category=category,
        language=str(raw.get("language", "")).strip(),
    )
