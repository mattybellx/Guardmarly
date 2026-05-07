"""
ansede_static.yaml_rules
─────────────────────────
Zero-dependency custom and community rule loading.

Classic custom-rule bundles still use a top-level ``rules`` array. Community
rules introduced in Task D are single-rule YAML files stored under
``~/.ansede/community_rules`` and parsed using a constrained YAML subset so the
feature remains dependency-free.
"""
from __future__ import annotations

import ast
import json
import logging
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from ansede_static._types import Finding, Severity

_log = logging.getLogger(__name__)

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_LANGUAGES = {
    "python", "py",
    "javascript", "js", "jsx",
    "typescript", "ts", "tsx",
    "go", "golang",
    "java",
    "csharp", "cs", "c#",
}


@dataclass(frozen=True)
class CustomRule:
    rule_id: str
    title: str
    description: str
    severity: Severity
    cwe: str
    category: str
    languages: tuple[str, ...]
    pattern_type: str = "regex"
    pattern: re.Pattern[str] | None = None
    raw_pattern: str = ""
    route_decorator: str = ""
    missing_decorators: tuple[str, ...] = field(default_factory=tuple)
    sink_names: tuple[str, ...] = field(default_factory=tuple)
    suggestion: str = ""
    auto_fix: str = ""
    maturity: str = "stable"
    tags: tuple[str, ...] = field(default_factory=tuple)
    test_positive: str = ""
    test_negative: str = ""
    source_path: str = ""
    is_community: bool = False

    def matches_language(self, language: str) -> bool:
        if not self.languages:
            return True
        return _normalise_language(language) in self.languages


def _normalise_language(lang: str) -> str:
    lang = lang.strip().lower()
    if lang in ("js", "javascript", "jsx", "ts", "typescript", "tsx"):
        return "javascript"
    if lang in ("py", "python"):
        return "python"
    if lang in ("go", "golang"):
        return "go"
    if lang == "java":
        return "java"
    if lang in ("c#", "cs", "csharp"):
        return "csharp"
    return lang


def default_community_rules_dir() -> Path:
    return Path.home() / ".ansede" / "community_rules"


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if not value:
        return ""
    if value.startswith(("'", '"')) and value.endswith(("'", '"')) and len(value) >= 2:
        try:
            return ast.literal_eval(value)
        except Exception:
            return value[1:-1]
    if value.startswith("[") and value.endswith("]"):
        try:
            return json.loads(value)
        except Exception:
            try:
                return ast.literal_eval(value)
            except Exception:
                return value
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in {"null", "none"}:
        return None
    if re.fullmatch(r"-?\d+", value):
        try:
            return int(value)
        except ValueError:
            return value
    return value


def _prepare_yaml_lines(text: str) -> list[tuple[int, str]]:
    prepared: list[tuple[int, str]] = []
    for raw_line in text.splitlines():
        expanded = raw_line.replace("\t", "    ")
        stripped = expanded.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        prepared.append((len(expanded) - len(stripped), stripped.rstrip()))
    return prepared


def _parse_yaml_block_scalar(
    lines: list[tuple[int, str]],
    index: int,
    *,
    parent_indent: int,
) -> tuple[str, int]:
    block_lines: list[str] = []
    while index < len(lines):
        indent, text = lines[index]
        if indent <= parent_indent:
            break
        relative = max(indent - (parent_indent + 2), 0)
        block_lines.append((" " * relative) + text)
        index += 1
    return "\n".join(block_lines), index


def _parse_yaml_list(
    lines: list[tuple[int, str]],
    index: int,
    *,
    indent: int,
) -> tuple[list[Any], int]:
    items: list[Any] = []
    while index < len(lines):
        line_indent, stripped = lines[index]
        if line_indent < indent or line_indent != indent or not stripped.startswith("- "):
            break
        remainder = stripped[2:].strip()
        if not remainder:
            index += 1
            if index < len(lines) and lines[index][0] > line_indent:
                value, index = _parse_yaml_node(lines, index, indent=lines[index][0])
            else:
                value = ""
            items.append(value)
            continue
        items.append(_parse_scalar(remainder))
        index += 1
    return items, index


def _parse_yaml_mapping(
    lines: list[tuple[int, str]],
    index: int,
    *,
    indent: int,
) -> tuple[dict[str, Any], int]:
    mapping: dict[str, Any] = {}
    while index < len(lines):
        line_indent, stripped = lines[index]
        if line_indent < indent:
            break
        if line_indent != indent or stripped.startswith("- "):
            break
        key, sep, remainder = stripped.partition(":")
        if not sep:
            raise ValueError(f"Invalid YAML line: {stripped!r}")
        key = key.strip()
        remainder = remainder.strip()
        if remainder == "|":
            value, index = _parse_yaml_block_scalar(lines, index + 1, parent_indent=line_indent)
            mapping[key] = value
            continue
        if remainder:
            mapping[key] = _parse_scalar(remainder)
            index += 1
            continue
        index += 1
        if index < len(lines) and lines[index][0] > line_indent:
            value, index = _parse_yaml_node(lines, index, indent=lines[index][0])
        else:
            value = {}
        mapping[key] = value
    return mapping, index


def _parse_yaml_node(
    lines: list[tuple[int, str]],
    index: int,
    *,
    indent: int,
) -> tuple[Any, int]:
    if index >= len(lines):
        return {}, index
    line_indent, stripped = lines[index]
    if line_indent < indent:
        return {}, index
    if stripped.startswith("- "):
        return _parse_yaml_list(lines, index, indent=line_indent)
    return _parse_yaml_mapping(lines, index, indent=line_indent)


def _load_yaml_text(text: str) -> Any:
    prepared = _prepare_yaml_lines(text)
    if not prepared:
        return {}
    parsed, index = _parse_yaml_node(prepared, 0, indent=prepared[0][0])
    if index < len(prepared):
        raise ValueError("Could not parse the full YAML document")
    return parsed


def _load_yaml_or_json_text(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return _load_yaml_text(text)


def _load_yaml_or_json(path: Path) -> Any:
    return _load_yaml_or_json_text(path.read_text(encoding="utf-8", errors="replace"))


def _is_valid_cwe(cwe: str) -> bool:
    return bool(re.fullmatch(r"CWE-\d+", cwe.strip().upper()))


def _compile_regex(rule_id: str, pattern_str: str) -> re.Pattern[str] | None:
    try:
        return re.compile(pattern_str)
    except re.error as exc:
        _log.warning("Rule %r: invalid regex pattern %r: %s — skipping", rule_id, pattern_str, exc)
        return None


def _normalise_languages(raw_langs: object, *, is_community: bool) -> tuple[str, ...]:
    if is_community and isinstance(raw_langs, str):
        values = [raw_langs]
    elif isinstance(raw_langs, list):
        values = [item for item in raw_langs if isinstance(item, str)]
    else:
        values = []
    normalized: list[str] = []
    for value in values:
        language = _normalise_language(value)
        if language in _VALID_LANGUAGES and language not in normalized:
            normalized.append(language)
    return tuple(normalized)


def _parse_rule_entry(
    entry: object,
    *,
    source_label: str,
    default_rule_id: str,
    is_community: bool,
) -> CustomRule | None:
    if not isinstance(entry, dict):
        _log.warning("Rule %r in %s is not a mapping — skipping", default_rule_id, source_label)
        return None

    rule_id = str(entry.get("id", default_rule_id)).strip()
    title = str(entry.get("title", "")).strip()
    description = str(entry.get("description", title)).strip()
    severity_str = str(entry.get("severity", "medium")).strip().lower() or "medium"
    cwe = str(entry.get("cwe", "")).strip().upper()
    category = str(entry.get("category", "security")).strip().lower() or "security"
    suggestion = str(entry.get("suggestion", "")).strip()
    auto_fix = str(entry.get("auto_fix", "")).strip()
    maturity = str(entry.get("maturity", "beta")).strip().lower() or "beta"
    raw_tags = entry.get("tags", [])
    tags = tuple(str(tag).strip() for tag in (raw_tags if isinstance(raw_tags, list) else []) if str(tag).strip())

    if not title:
        _log.warning("Rule %r in %s is missing 'title' — skipping", rule_id, source_label)
        return None
    if severity_str not in _VALID_SEVERITIES:
        _log.warning("Rule %r: invalid severity %r, defaulting to 'medium'", rule_id, severity_str)
        severity_str = "medium"
    if cwe and not _is_valid_cwe(cwe):
        _log.warning("Rule %r in %s has invalid CWE %r — skipping", rule_id, source_label, cwe)
        return None
    if is_community and not cwe:
        _log.warning("Community rule %r in %s is missing 'cwe' — skipping", rule_id, source_label)
        return None

    raw_languages = entry.get("language") if is_community else entry.get("languages", [])
    languages = _normalise_languages(raw_languages, is_community=is_community)
    if is_community and not languages:
        _log.warning("Community rule %r in %s is missing a valid 'language' — skipping", rule_id, source_label)
        return None

    test_block = entry.get("test", {}) if isinstance(entry.get("test", {}), dict) else {}
    test_positive = str(test_block.get("positive", "")).rstrip()
    test_negative = str(test_block.get("negative", "")).rstrip()

    if not is_community:
        pattern_str = str(entry.get("pattern", "")).strip()
        if not pattern_str:
            _log.warning("Rule %r in %s is missing 'pattern' — skipping", rule_id, source_label)
            return None
        compiled = _compile_regex(rule_id, pattern_str)
        if compiled is None:
            return None
        return CustomRule(
            rule_id=rule_id,
            title=title,
            description=description,
            severity=Severity(severity_str),
            cwe=cwe if cwe.startswith("CWE-") else "",
            category=category,
            languages=languages,
            pattern_type="regex",
            pattern=compiled,
            raw_pattern=pattern_str,
            suggestion=suggestion,
            auto_fix=auto_fix,
            maturity=maturity,
            tags=tags,
            source_path=source_label,
        )

    pattern_data = entry.get("pattern", {})
    if not isinstance(pattern_data, dict):
        _log.warning("Community rule %r in %s is missing a pattern object — skipping", rule_id, source_label)
        return None

    pattern_type = str(pattern_data.get("type", "regex")).strip().lower() or "regex"
    compiled: re.Pattern[str] | None = None
    raw_pattern = ""
    route_decorator = ""
    missing_decorators: tuple[str, ...] = ()
    sink_names: tuple[str, ...] = ()

    if pattern_type == "regex":
        raw_pattern = str(pattern_data.get("regex", pattern_data.get("pattern", ""))).strip()
        if not raw_pattern:
            _log.warning("Community rule %r in %s is missing pattern.regex — skipping", rule_id, source_label)
            return None
        compiled = _compile_regex(rule_id, raw_pattern)
        if compiled is None:
            return None
    elif pattern_type == "ast_structural":
        route_decorator = str(pattern_data.get("route_decorator", "")).strip()
        raw_missing = pattern_data.get("missing_decorator", [])
        missing_decorators = tuple(
            str(item).strip() for item in (raw_missing if isinstance(raw_missing, list) else []) if str(item).strip()
        )
        if not route_decorator or not missing_decorators:
            _log.warning(
                "Community rule %r in %s must define pattern.route_decorator and pattern.missing_decorator — skipping",
                rule_id,
                source_label,
            )
            return None
    elif pattern_type == "taint_sink":
        raw_sinks = pattern_data.get("sink", pattern_data.get("sinks", []))
        if isinstance(raw_sinks, str):
            sink_names = (raw_sinks.strip(),) if raw_sinks.strip() else ()
        elif isinstance(raw_sinks, list):
            sink_names = tuple(str(item).strip() for item in raw_sinks if str(item).strip())
        if not sink_names:
            _log.warning("Community rule %r in %s is missing pattern.sink — skipping", rule_id, source_label)
            return None
    else:
        _log.warning("Community rule %r in %s uses unsupported pattern type %r — skipping", rule_id, source_label, pattern_type)
        return None

    return CustomRule(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=Severity(severity_str),
        cwe=cwe,
        category=category,
        languages=languages,
        pattern_type=pattern_type,
        pattern=compiled,
        raw_pattern=raw_pattern,
        route_decorator=route_decorator,
        missing_decorators=missing_decorators,
        sink_names=sink_names,
        suggestion=suggestion,
        auto_fix=auto_fix,
        maturity=maturity,
        tags=tags,
        test_positive=test_positive,
        test_negative=test_negative,
        source_path=source_label,
        is_community=True,
    )


def _dedupe_rules(rules: list[CustomRule]) -> list[CustomRule]:
    deduped: dict[str, CustomRule] = {}
    for rule in rules:
        existing = deduped.get(rule.rule_id)
        if existing is not None:
            _log.warning(
                "Duplicate runtime rule id %r from %s overrides earlier definition from %s",
                rule.rule_id,
                rule.source_path or "<unknown>",
                existing.source_path or "<unknown>",
            )
        deduped[rule.rule_id] = rule
    return list(deduped.values())


def load_custom_rules(rules_file: str | Path) -> list[CustomRule]:
    path = Path(rules_file)
    if not path.is_file():
        _log.warning("Custom rules file not found: %s", path)
        return []

    try:
        data = _load_yaml_or_json(path)
    except Exception as exc:
        _log.warning("Failed to parse custom rules file %s: %s", path, exc)
        return []

    if not isinstance(data, dict):
        _log.warning("Custom rules file must be a YAML/JSON object with a 'rules' list: %s", path)
        return []

    if isinstance(data.get("rules"), list):
        rules_data = list(data.get("rules", []))
    elif "id" in data:
        rules_data = [data]
    else:
        _log.warning("'rules' key in %s must be a list", path)
        return []

    loaded: list[CustomRule] = []
    for idx, entry in enumerate(rules_data):
        parsed = _parse_rule_entry(
            entry,
            source_label=str(path),
            default_rule_id=f"CUSTOM-{idx + 1:03d}",
            is_community=False,
        )
        if parsed is not None:
            loaded.append(parsed)
    return _dedupe_rules(loaded)


def load_community_rule_file(rule_file: str | Path) -> CustomRule | None:
    path = Path(rule_file)
    if not path.is_file():
        _log.warning("Community rule file not found: %s", path)
        return None
    try:
        data = _load_yaml_or_json(path)
    except Exception as exc:
        _log.warning("Failed to parse community rule file %s: %s", path, exc)
        return None
    return _parse_rule_entry(data, source_label=str(path), default_rule_id=path.stem, is_community=True)


def load_community_rule_text(text: str, *, source_label: str = "<community-rule>") -> CustomRule | None:
    try:
        data = _load_yaml_or_json_text(text)
    except Exception as exc:
        _log.warning("Failed to parse community rule text from %s: %s", source_label, exc)
        return None
    return _parse_rule_entry(data, source_label=source_label, default_rule_id="community-rule", is_community=True)


@lru_cache(maxsize=32)
def _cached_community_rule_paths(directory: str) -> tuple[str, ...]:
    rule_dir = Path(directory)
    if not rule_dir.is_dir():
        return tuple()
    return tuple(
        str(path)
        for path in sorted(rule_dir.iterdir())
        if path.is_file() and path.suffix.lower() in {".yaml", ".yml", ".json"}
    )


def load_community_rules(directory: str | Path | None = None) -> list[CustomRule]:
    rule_dir = Path(directory) if directory is not None else default_community_rules_dir()
    loaded: list[CustomRule] = []
    for rule_path in _cached_community_rule_paths(str(rule_dir)):
        parsed = load_community_rule_file(rule_path)
        if parsed is not None:
            loaded.append(parsed)
    return _dedupe_rules(loaded)


def load_runtime_rules(
    *,
    config: object | None = None,
    workspace_root: str | Path | None = None,
    community_dir: str | Path | None = None,
) -> list[CustomRule]:
    rules: list[CustomRule] = []
    rules.extend(load_community_rules(community_dir))
    custom_rules_file = str(getattr(config, "custom_rules_file", "") or "").strip() if config else ""
    if custom_rules_file:
        base = Path(workspace_root) if workspace_root is not None else Path.cwd()
        custom_path = Path(custom_rules_file)
        if not custom_path.is_absolute():
            custom_path = (base / custom_path).resolve()
        rules.extend(load_custom_rules(custom_path))
    return _dedupe_rules(rules)


def load_registry_packs(language: str | None = None) -> list[CustomRule]:
    """Load all registry pack rules, optionally filtered by language."""
    try:
        from ansede_static.registry.loader import (
            load_packs_for_language,
            load_all_registry_packs,
        )
        if language:
            return list(load_packs_for_language(language))
        return list(load_all_registry_packs())
    except Exception:  # noqa: BLE001  # registry is optional
        return []


def _suppression_tokens_for_line(line: str) -> frozenset[str] | None:
    marker = re.search(r"#\s*ansede\s*:\s*ignore", line, re.IGNORECASE)
    if marker is None:
        return None
    tail = line[marker.end():].split("--", 1)[0].strip()
    if tail.startswith("["):
        closing = tail.find("]")
        token_text = tail[1:closing] if closing != -1 else tail[1:]
    else:
        token_text = tail
    return frozenset(token for token in re.findall(r"[A-Za-z][\w./-]+", token_text))


def _line_suppresses_rule(line: str, rule: CustomRule) -> bool:
    tokens = _suppression_tokens_for_line(line)
    if tokens is None:
        return False
    if not tokens:
        return True
    normalized = {rule.rule_id, rule.rule_id.upper(), rule.cwe, rule.cwe.upper()}
    normalized.discard("")
    for token in tokens:
        if token in normalized or token.upper() in normalized:
            return True
    return False


def _build_custom_finding(rule: CustomRule, *, line: int, line_text: str) -> Finding:
    return Finding(
        category=rule.category,
        severity=rule.severity,
        title=rule.title,
        description=rule.description,
        line=line,
        suggestion=rule.suggestion,
        rule_id=rule.rule_id,
        cwe=rule.cwe,
        agent="community-rules" if rule.is_community else "custom-rules",
        confidence=0.7,
        auto_fix=rule.auto_fix,
        analysis_kind="route_heuristic" if rule.pattern_type == "ast_structural" else "custom-pattern",
        triggering_code=line_text.strip(),
    )


def _apply_regex_rule(code_lines: list[str], rule: CustomRule) -> list[Finding]:
    findings: list[Finding] = []
    if rule.pattern is None:
        return findings
    for lineno, line_text in enumerate(code_lines, start=1):
        if rule.pattern.search(line_text):
            if _line_suppresses_rule(line_text, rule):
                continue
            findings.append(_build_custom_finding(rule, line=lineno, line_text=line_text))
    return findings


def _apply_ast_structural_rule(code_lines: list[str], rule: CustomRule) -> list[Finding]:
    findings: list[Finding] = []
    if not rule.route_decorator or not rule.missing_decorators:
        return findings
    for lineno, line_text in enumerate(code_lines, start=1):
        if rule.route_decorator not in line_text:
            continue
        upper_bound = min(len(code_lines), lineno + 8)
        window = code_lines[lineno - 1:upper_bound]
        if any(token in window_line for token in rule.missing_decorators for window_line in window):
            continue
        if _line_suppresses_rule(line_text, rule):
            continue
        findings.append(_build_custom_finding(rule, line=lineno, line_text=line_text))
    return findings


def _apply_taint_sink_rule(code_lines: list[str], rule: CustomRule) -> list[Finding]:
    findings: list[Finding] = []
    if not rule.sink_names:
        return findings
    for lineno, line_text in enumerate(code_lines, start=1):
        if any(sink in line_text for sink in rule.sink_names):
            if _line_suppresses_rule(line_text, rule):
                continue
            findings.append(_build_custom_finding(rule, line=lineno, line_text=line_text))
    return findings


def apply_custom_rules(
    code: str,
    filename: str,
    language: str,
    rules: list[CustomRule],
) -> list[Finding]:
    findings: list[Finding] = []
    if not rules:
        return findings

    code_lines = code.splitlines()
    for rule in rules:
        if not rule.matches_language(language):
            continue
        if rule.pattern_type == "regex":
            findings.extend(_apply_regex_rule(code_lines, rule))
        elif rule.pattern_type == "ast_structural":
            findings.extend(_apply_ast_structural_rule(code_lines, rule))
        elif rule.pattern_type == "taint_sink":
            findings.extend(_apply_taint_sink_rule(code_lines, rule))
    return findings
