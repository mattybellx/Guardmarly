"""
ansede_static.config
────────────────────
Fast, zero-dependency configuration loader for enterprise workspaces.
Reads an `ansede.json` file to tune scanner rules, set ignore paths, 
and load custom internal taint sources and sinks.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from ansede_static._types import AnalysisResult, Finding

_log = logging.getLogger(__name__)


_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})


@dataclass(frozen=True)
class CustomSinkSpec:
    cwe: str
    title: str
    severity: str = "high"

    def as_taint_sink(self) -> tuple[str, str, str]:
        return (self.cwe, self.title, self.severity)


@dataclass
class AnsedeConfig:
    exclude_paths: list[str] = field(default_factory=list)
    disable_rules: list[str] = field(default_factory=list)
    custom_sources: list[str] = field(default_factory=list)
    custom_sinks: dict[str, CustomSinkSpec] = field(default_factory=dict)
    # Path to a custom YAML/JSON rule definitions file (see docs/CUSTOM_RULES.md)
    custom_rules_file: str = ""
    # Extra sanitizer catalog JSON files to merge with the built-in library
    extra_sanitizer_files: list[str] = field(default_factory=list)
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
                f"ansede.json custom_sinks.{sink_name!s} is missing a valid 'cwe' (expected like 'CWE-89') — skipping entry."
            )
            return None
        if not title:
            warnings.append(
                f"ansede.json custom_sinks.{sink_name!s} is missing a non-empty 'title' — skipping entry."
            )
            return None
        if severity not in _VALID_SEVERITIES:
            warnings.append(
                f"ansede.json custom_sinks.{sink_name!s} has invalid severity {severity!r}; defaulting to 'high'."
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
                        f"ansede.json custom_sinks.{sink_name!s} has invalid severity {severity!r}; defaulting to 'high'."
                    )
                    severity = "high"
                return CustomSinkSpec(cwe=cwe, title=title, severity=severity)

        warnings.append(
            f"ansede.json custom_sinks.{sink_name!s} uses an unsupported legacy list format; use an object with cwe/title/severity instead."
        )
        return None

    warnings.append(
        f"ansede.json custom_sinks.{sink_name!s} must be an object (or supported legacy list) — skipping entry."
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


def apply_config_to_results(results: list[AnalysisResult], config: AnsedeConfig | None) -> list[AnalysisResult]:
    if not config or not config.disable_rules:
        return results

    disabled_rules = {_normalized_rule_token(rule) for rule in config.disable_rules if rule.strip()}
    for result in results:
        result.findings = [
            finding for finding in result.findings
            if not finding_is_disabled(finding, disabled_rules)
        ]
    return results


@contextmanager
def temporary_analyzer_config(config: AnsedeConfig | None) -> Iterator[None]:
    if not config or (not config.custom_sources and not config.custom_sinks and not config.extra_sanitizer_files):
        yield
        return

    try:
        from ansede_static.python_analyzer import TAINT_SINKS, TAINT_SOURCES, SANITIZERS
    except ImportError:
        yield
        return

    previous_sources: dict[str, str | None] = {}
    previous_sinks: dict[str, tuple[str, str] | tuple[str, str, str] | None] = {}
    injected_sanitizers: dict[str, set[str]] = {}

    for source_name in config.custom_sources:
        previous_sources[source_name] = TAINT_SOURCES.get(source_name)
        TAINT_SOURCES[source_name] = "Custom taint source from ansede.json"

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


def load_config(workspace_root: Path | None = None) -> AnsedeConfig:
    if not workspace_root:
        workspace_root = Path.cwd()
        
    config_path = workspace_root / "ansede.json"
    if not config_path.is_file():
        return AnsedeConfig()
        
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        warnings: list[str] = []
        custom_sinks: dict[str, CustomSinkSpec] = {}
        for sink_name, sink_data in data.get("custom_sinks", {}).items():
            sink_spec = _parse_custom_sink(sink_name, sink_data, warnings)
            if sink_spec is not None:
                custom_sinks[sink_name] = sink_spec

        disable_rules = [rule for rule in data.get("disable_rules", []) if isinstance(rule, str) and rule.strip()]
        custom_sources = [src for src in data.get("custom_sources", []) if isinstance(src, str) and src.strip()]
        custom_rules_file = str(data.get("custom_rules_file", "")).strip()
        extra_sanitizer_files = [
            str(p).strip() for p in data.get("extra_sanitizer_files", []) if str(p).strip()
        ]

        return AnsedeConfig(
            exclude_paths=data.get("exclude_paths", []),
            disable_rules=disable_rules,
            custom_sources=custom_sources,
            custom_sinks=custom_sinks,
            custom_rules_file=custom_rules_file,
            extra_sanitizer_files=extra_sanitizer_files,
            warnings=warnings,
        )
    except json.JSONDecodeError as exc:
        _log.warning("ansede.json is not valid JSON — ignoring config: %s", exc)
        return AnsedeConfig()
    except Exception as exc:
        _log.warning("Failed to load ansede.json — ignoring config: %s", exc)
        return AnsedeConfig()
