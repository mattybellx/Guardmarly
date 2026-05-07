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
from pathlib import Path

_log = logging.getLogger(__name__)

_REGISTRY_DIR = Path(__file__).resolve().parent

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

_loaded_packs: dict[str, list[dict]] = {}


def detect_frameworks(code: str) -> list[str]:
    """Detect frameworks used in source code."""
    detected: list[str] = []
    for marker_re, pack_name in _FRAMEWORK_MARKERS:
        if marker_re.search(code):
            if pack_name not in detected:
                detected.append(pack_name)
    return detected


def load_pack(pack_name: str) -> list[dict]:
    """Load a rule pack, caching the result."""
    if pack_name in _loaded_packs:
        return _loaded_packs[pack_name]

    pack_path = _REGISTRY_DIR / f"{pack_name}.yaml"
    if not pack_path.exists():
        pack_path = _REGISTRY_DIR / f"{pack_name}.yml"
    if not pack_path.exists():
        _loaded_packs[pack_name] = []
        return []

    try:
        import yaml
        with open(pack_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception:
        try:
            import json
            json_path = _REGISTRY_DIR / f"{pack_name}.json"
            if json_path.exists():
                data = json.loads(json_path.read_text(encoding="utf-8"))
            else:
                _loaded_packs[pack_name] = []
                return []
        except Exception:
            _loaded_packs[pack_name] = []
            return []

    rules = data.get("rules", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
    _loaded_packs[pack_name] = rules
    _log.debug("Loaded %d rules from %s pack", len(rules), pack_name)
    return rules


def load_rules_for_code(code: str) -> list[dict]:
    """Auto-detect frameworks and load matching rule packs."""
    frameworks = detect_frameworks(code)
    all_rules: list[dict] = []
    for fw in frameworks:
        all_rules.extend(load_pack(fw))
    return all_rules
