"""
Sharded Rule Registry Loader
─────────────────────────────
Lazily loads framework-specific rule packs from the registry/ directory.
Only "thaws" packs when framework markers are detected in the target code.

See registry/__init__.py for the existing pack infrastructure.
"""

from __future__ import annotations

import logging
import re
from typing import Any

_log = logging.getLogger(__name__)

_FRAMEWORK_MARKERS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'import\s+django\b|from\s+django\b|INSTALLED_APPS|DJANGO_SETTINGS', re.IGNORECASE), "django"),
    (re.compile(r'from\s+flask\s+import|import\s+flask\b|Flask\s*\(|@app\.route', re.IGNORECASE), "flask"),
    (re.compile(r'from\s+fastapi\s+import|import\s+fastapi\b|FastAPI\s*\(|APIRouter', re.IGNORECASE), "fastapi"),
    (re.compile(r"require\s*\(\s*['\"]express['\"]|from\s+['\"]express['\"]|express\s*\(\s*\)", re.IGNORECASE), "express_js"),
    (re.compile(r"@nestjs/|@Module\s*\(|NestFactory|@Injectable\s*\(|@Controller\s*\(", re.IGNORECASE), "nestjs_framework"),
    (re.compile(r"from\s+['\"]react['\"]|import\s+React\b|useState|useEffect", re.IGNORECASE), "react_frontend"),
    (re.compile(r"import\s+boto3\b|from\s+boto3\b|boto3\.(?:client|resource|session)", re.IGNORECASE), "boto3_aws"),
    (re.compile(r"from\s+sqlalchemy\b|import\s+sqlalchemy\b", re.IGNORECASE), "sqlalchemy"),
    (re.compile(r"require\s*\(\s*['\"]mongoose['\"]", re.IGNORECASE), "mongoose_js"),
    (re.compile(r"require\s*\(\s*['\"]sequelize['\"]", re.IGNORECASE), "sequelize_orm"),
    (re.compile(r"require\s*\(\s*['\"]axios['\"]", re.IGNORECASE), "axios_js"),
    (re.compile(r"from\s+pydantic\b|import\s+pydantic\b|BaseModel", re.IGNORECASE), "pydantic"),
    (re.compile(r"from\s+celery\b|import\s+celery\b|@celery\.task", re.IGNORECASE), "celery"),
    (re.compile(r"yaml\.(?:load|safe_load|full_load)\s*\(", re.IGNORECASE), "yaml_load"),
    (re.compile(r"etree\.(?:parse|fromstring)|lxml\.etree|xml\.(?:dom|sax)", re.IGNORECASE), "xml_parsers"),
    (re.compile(r"subprocess\.(?:run|Popen|call|check_output)", re.IGNORECASE), "subprocess_lib"),
]

_PACK_LANGUAGE_HINTS: dict[str, str] = {
    "django": "python",
    "flask": "python",
    "fastapi": "python",
    "boto3_aws": "python",
    "sqlalchemy": "python",
    "pydantic": "python",
    "celery": "python",
    "yaml_load": "python",
    "xml_parsers": "python",
    "subprocess_lib": "python",
    "express_js": "javascript",
    "nestjs_framework": "javascript",
    "react_frontend": "javascript",
    "mongoose_js": "javascript",
    "sequelize_orm": "javascript",
    "axios_js": "javascript",
}

_loaded_packs: dict[str, list[dict]] = {}


def _normalize_language(language: str) -> str:
    text = language.strip().lower()
    if text in {"js", "jsx", "ts", "tsx", "typescript", "javascript"}:
        return "javascript"
    if text in {"py", "python"}:
        return "python"
    if text in {"cs", "c#", "csharp"}:
        return "csharp"
    if text in {"golang", "go"}:
        return "go"
    return text


def detect_frameworks(code: str) -> list[str]:
    """Detect frameworks used in source code."""
    detected: list[str] = []
    for marker_re, pack_name in _FRAMEWORK_MARKERS:
        if marker_re.search(code):
            if pack_name not in detected:
                detected.append(pack_name)
    return detected


def load_custom_rules_for_code(code: str, language: str) -> list[Any]:
    """Load registry custom-rule objects for a source/language pair.

    This is the canonical bridge used by runtime scanning paths.
    """
    try:
        from guardmarly.registry.loader import load_packs_for_source

        return list(load_packs_for_source(code, _normalize_language(language)))
    except Exception as exc:
        _log.debug("Sharded custom-rule load failed: %s", exc)
        return []


def load_pack(pack_name: str) -> list[dict]:
    """Load a rule pack, caching the result."""
    if pack_name in _loaded_packs:
        return _loaded_packs[pack_name]

    try:
        from guardmarly.registry.loader import load_packs_for_source
        from guardmarly.yaml_rules import CustomRule

        rules = load_packs_for_source(f"import {pack_name}\n", _PACK_LANGUAGE_HINTS.get(pack_name, "python"))
        normalized: list[dict] = []
        for rule in rules:
            if isinstance(rule, CustomRule):
                normalized.append({
                    "id": rule.rule_id,
                    "title": rule.title,
                    "cwe": rule.cwe,
                    "pattern_type": rule.pattern_type,
                    "languages": list(rule.languages),
                })
            elif isinstance(rule, dict):
                normalized.append(rule)
        _loaded_packs[pack_name] = normalized
        _log.debug("Loaded %d rules from %s pack", len(normalized), pack_name)
        return normalized
    except Exception:
        pass

    pack_path = _REGISTRY_DIR / f"{pack_name}.json"
    if not pack_path.exists():
        _loaded_packs[pack_name] = []
        return []
    try:
        import json
        data = json.loads(pack_path.read_text(encoding="utf-8"))
    except Exception:
        _loaded_packs[pack_name] = []
        return []

    rules = data.get("rules", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
    _loaded_packs[pack_name] = rules
    _log.debug("Loaded %d rules from %s pack", len(rules), pack_name)
    return rules


def load_rules_for_code(code: str, language: str | None = None) -> list[dict]:
    """Auto-detect frameworks and load matching normalized rule dicts.

    Backward-compatible adapter used by existing tests and diagnostics.
    """
    if language:
        rules = load_custom_rules_for_code(code, language)
        normalized: list[dict] = []
        try:
            from guardmarly.yaml_rules import CustomRule
        except Exception:
            CustomRule = None  # type: ignore[assignment]
        for rule in rules:
            if CustomRule is not None and isinstance(rule, CustomRule):
                normalized.append({
                    "id": rule.rule_id,
                    "title": rule.title,
                    "cwe": rule.cwe,
                    "pattern_type": rule.pattern_type,
                    "languages": list(rule.languages),
                })
            elif isinstance(rule, dict):
                normalized.append(rule)
        return normalized

    frameworks = detect_frameworks(code)
    all_rules: list[dict] = []
    for fw in frameworks:
        all_rules.extend(load_pack(fw))
    return all_rules
