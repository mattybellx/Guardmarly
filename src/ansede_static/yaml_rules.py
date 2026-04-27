"""
ansede_static.yaml_rules
─────────────────────────
Community-extensible YAML / JSON custom rule loader.

Rule file format (YAML or JSON):

    version: "1.0"
    rules:
      - id: "CUSTOM-001"
        title: "Dangerous function call"
        description: "Flags use of my_legacy_exec() which passes input to the shell."
        severity: "high"          # critical | high | medium | low | info
        cwe: "CWE-78"
        category: "security"
        languages: ["python"]     # python | javascript
        pattern: "my_legacy_exec"  # regex matched against source lines
        suggestion: "Replace my_legacy_exec() with subprocess.run(args, shell=False)."
        auto_fix: ""              # optional BEFORE:/AFTER: inline fix
        maturity: "beta"          # stable | beta | experimental
        tags: ["custom", "legacy"]

Rules are applied as additional pattern checks after the normal analyzers run.
They do NOT have access to AST or taint state — pattern-only matching.
Zero external dependencies.  PyYAML is used when available; falls back to JSON.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ansede_static._types import Finding, Severity

_log = logging.getLogger(__name__)

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_LANGUAGES = {"python", "javascript", "typescript", "js", "ts", "py"}


@dataclass(frozen=True)
class CustomRule:
    rule_id: str
    title: str
    description: str
    severity: Severity
    cwe: str
    category: str
    languages: tuple[str, ...]       # normalised to "python" / "javascript"
    pattern: re.Pattern[str]
    suggestion: str = ""
    auto_fix: str = ""
    maturity: str = "beta"
    tags: tuple[str, ...] = field(default_factory=tuple)

    def matches_language(self, language: str) -> bool:
        if not self.languages:
            return True
        return language.lower() in self.languages


def _normalise_language(lang: str) -> str:
    lang = lang.strip().lower()
    if lang in ("js", "javascript", "jsx", "ts", "typescript", "tsx"):
        return "javascript"
    if lang in ("py", "python"):
        return "python"
    return lang


def _load_yaml_or_json(path: Path) -> Any:
    """Load a YAML or JSON file; try PyYAML first, fall back to JSON."""
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        import yaml  # type: ignore[import]
        return yaml.safe_load(text)
    except ImportError:
        pass
    return json.loads(text)


def load_custom_rules(rules_file: str | Path) -> list[CustomRule]:
    """Load and validate custom rules from a YAML or JSON file.

    Returns a list of validated :class:`CustomRule` objects.  Invalid entries
    are skipped with a warning.
    """
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

    rules_data = data.get("rules", [])
    if not isinstance(rules_data, list):
        _log.warning("'rules' key in %s must be a list", path)
        return []

    loaded: list[CustomRule] = []
    for idx, entry in enumerate(rules_data):
        if not isinstance(entry, dict):
            _log.warning("Rule #%d in %s is not a mapping — skipping", idx + 1, path)
            continue

        rule_id = str(entry.get("id", f"CUSTOM-{idx+1:03d}")).strip()
        title = str(entry.get("title", "")).strip()
        description = str(entry.get("description", title)).strip()
        severity_str = str(entry.get("severity", "medium")).strip().lower()
        cwe = str(entry.get("cwe", "")).strip().upper()
        category = str(entry.get("category", "security")).strip().lower()
        pattern_str = str(entry.get("pattern", "")).strip()
        suggestion = str(entry.get("suggestion", "")).strip()
        auto_fix = str(entry.get("auto_fix", "")).strip()
        maturity = str(entry.get("maturity", "beta")).strip().lower()
        raw_langs = entry.get("languages", [])
        raw_tags = entry.get("tags", [])

        if not title:
            _log.warning("Rule %r in %s is missing 'title' — skipping", rule_id, path)
            continue
        if not pattern_str:
            _log.warning("Rule %r in %s is missing 'pattern' — skipping", rule_id, path)
            continue
        if severity_str not in _VALID_SEVERITIES:
            _log.warning("Rule %r: invalid severity %r, defaulting to 'medium'", rule_id, severity_str)
            severity_str = "medium"

        try:
            compiled = re.compile(pattern_str)
        except re.error as exc:
            _log.warning("Rule %r: invalid regex pattern %r: %s — skipping", rule_id, pattern_str, exc)
            continue

        languages = tuple(
            _normalise_language(lang)
            for lang in (raw_langs if isinstance(raw_langs, list) else [])
            if isinstance(lang, str)
        )
        tags = tuple(str(t).strip() for t in (raw_tags if isinstance(raw_tags, list) else []) if t)

        loaded.append(CustomRule(
            rule_id=rule_id,
            title=title,
            description=description,
            severity=Severity(severity_str),
            cwe=cwe if cwe.startswith("CWE-") else "",
            category=category,
            languages=languages,
            pattern=compiled,
            suggestion=suggestion,
            auto_fix=auto_fix,
            maturity=maturity,
            tags=tags,
        ))

    return loaded


def apply_custom_rules(
    code: str,
    filename: str,
    language: str,
    rules: list[CustomRule],
) -> list[Finding]:
    """Apply *rules* against *code* line-by-line and return a list of Findings."""
    findings: list[Finding] = []
    if not rules:
        return findings

    lines = code.splitlines()
    for rule in rules:
        if not rule.matches_language(language):
            continue
        for lineno, line_text in enumerate(lines, start=1):
            if rule.pattern.search(line_text):
                findings.append(Finding(
                    category=rule.category,
                    severity=rule.severity,
                    title=rule.title,
                    description=rule.description,
                    line=lineno,
                    suggestion=rule.suggestion,
                    rule_id=rule.rule_id,
                    cwe=rule.cwe,
                    agent="custom-rules",
                    confidence=0.7,
                    auto_fix=rule.auto_fix,
                    analysis_kind="custom-pattern",
                ))
    return findings
