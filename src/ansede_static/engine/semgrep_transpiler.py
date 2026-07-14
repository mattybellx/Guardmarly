"""
ansede_static.engine.semgrep_transpiler
────────────────────────────────────────
DIR-3.2: Rule-to-Semgrep transpiler.

Converts ansede-static rule contracts into Semgrep-compatible YAML rules
for external validation, comparison, and CI integration.

Zero-dependency (stdlib yaml-like output via dict → JSON mapping; YAML
is valid JSON so we output JSON-compatible YAML directly).

Usage:
    from ansede_static.engine.semgrep_transpiler import transpile_rule

    rule_yaml = transpile_rule("PY-004")  # SQL injection → Semgrep pattern
    print(rule_yaml)
"""
from __future__ import annotations

from typing import Any

from ansede_static.rules import get_rule_contract

# ── Pattern mapping: ansede rule IDs → Semgrep patterns ──────────────────
# These are hand-curated mappings for high-value rules where the ansede
# detection approach can be losslessly lowered to Semgrep's pattern syntax.
# The key is the rule_id, and the value is the Semgrep pattern configuration.

_SEMGREP_PATTERNS: dict[str, dict[str, Any]] = {
    "PY-004": {
        "languages": ["python"],
        "patterns": [
            {"pattern-either": [
                {"pattern": "cursor.execute(f\"...$VAR...\")"},
                {"pattern": "cursor.execute('...' + $VAR + '...')"},
                {"pattern": "cursor.execute(\"...\" + $VAR + \"...\")"},
            ]},
            {"pattern-not": "cursor.execute('...', $ARGS)"},
        ],
        "message": "Possible SQL injection via string formatting in cursor.execute()",
    },
    "PY-005": {
        "languages": ["python"],
        "patterns": [
            {"pattern-either": [
                {"pattern": "os.system($VAR)"},
                {"pattern": "os.popen($VAR)"},
                {"pattern": "subprocess.call($VAR, shell=True)"},
                {"pattern": "subprocess.Popen($VAR, shell=True)"},
            ]},
        ],
        "message": "OS command injection via subprocess or os module",
    },
    "PY-008": {
        "languages": ["python"],
        "patterns": [
            {"pattern-either": [
                {"pattern": "subprocess.call(..., shell=True)"},
                {"pattern": "subprocess.run(..., shell=True)"},
                {"pattern": "subprocess.Popen(..., shell=True)"},
                {"pattern": "os.system($VAR)"},
                {"pattern": "os.popen($VAR)"},
            ]},
        ],
        "message": "Shell injection via subprocess or os with shell=True",
    },
    "PY-020": {
        "languages": ["python"],
        "patterns": [
            {"pattern-either": [
                {"pattern": """
@app.route(...)
def $FUNC(...):
    ...
"""},
                {"pattern": """
@app.get(...)
def $FUNC(...):
    ...
"""},
            ]},
            {"pattern-not-regex": "@login_required|@auth|login_required|@permission|Depends\\(get_current"},
        ],
        "message": "Route without visible authentication guard may expose internal endpoints",
    },
    "PY-022": {
        "languages": ["python"],
        "patterns": [
            {"pattern-either": [
                {"pattern": "open($PATH).read()"},
                {"pattern": "Path($PATH).read_text()"},
            ]},
            {"pattern-not-regex": r"os\.path\.join\([^,]+,\s*[\"']"},
        ],
        "message": "Path traversal via user-controlled file path",
    },
    "PY-024": {
        "languages": ["python"],
        "patterns": [
            {"pattern-either": [
                {"pattern": "db.execute('SELECT ... WHERE id = ?', ($ID,)).fetchone()"},
                {"pattern": "$MODEL.query.get($ID)"},
                {"pattern": "$MODEL.query.filter_by(id=$ID).first()"},
            ]},
            {"pattern-not-regex": "owner_id|user_id|g\\.user"},
        ],
        "message": "Resource lookup by ID without ownership scope check (IDOR)",
    },
    "PY-038": {
        "languages": ["python"],
        "patterns": [
            {"pattern-either": [
                {"pattern": """
@app.route('/login', methods=['POST'])
def $FUNC(...):
    ...
"""},
            ]},
            {"pattern-not-regex": "limiter\\.limit|ratelimit|throttle|Limit"},
        ],
        "message": "Login route without visible rate limiting (brute force vulnerability)",
    },
    "PY-039": {
        "languages": ["python"],
        "patterns": [
            {"pattern-either": [
                {"pattern": "app.debug = True"},
                {"pattern": "traceback.print_exc()"},
                {"pattern": "traceback.format_exc()"},
            ]},
        ],
        "message": "Debug mode enabled or traceback exposed to users",
    },
    "JS-001": {
        "languages": ["javascript", "typescript"],
        "patterns": [
            {"pattern-either": [
                {"pattern": "document.getElementById(...).innerHTML = $VAR"},
                {"pattern": "document.querySelector(...).innerHTML = $VAR"},
                {"pattern": "element.innerHTML = $VAR"},
            ]},
            {"pattern-not-regex": "DOMPurify|sanitize|escape|encode"},
        ],
        "message": "DOM-based XSS via innerHTML assignment without sanitization",
    },
    "JS-007": {
        "languages": ["javascript", "typescript"],
        "patterns": [
            {"pattern-either": [
                {"pattern": "child_process.exec($CMD)"},
                {"pattern": "child_process.execSync($CMD)"},
                {"pattern": "child_process.spawn($CMD, ...)"},
            ]},
        ],
        "message": "OS command injection via child_process",
    },
    "JS-009": {
        "languages": ["javascript", "typescript"],
        "patterns": [
            {"pattern-either": [
                {"pattern": "db.query('SELECT ... ' + $VAR + ' ...')"},
                {"pattern": "db.execute('SELECT ... ' + $VAR + ' ...')"},
                {"pattern": "connection.query('SELECT ... ' + $VAR + ' ...')"},
            ]},
            {"pattern-not-regex": "\\?|\\$\\d|placeholder"},
        ],
        "message": "SQL injection via string concatenation in query",
    },
    "JS-011": {
        "languages": ["javascript", "typescript"],
        "patterns": [
            {"pattern-either": [
                {"pattern": "const $KEY = '...'"},
                {"pattern": "let $KEY = '...'"},
            ]},
            {"pattern-regex": r"(?i)(password|secret|api[_-]?key|token)\s*=\s*['\\\"][^'\\\"]{8,}"},
        ],
        "message": "Hardcoded credential or API key detected",
    },
    "JS-013": {
        "languages": ["javascript", "typescript"],
        "patterns": [
            {"pattern-either": [
                {"pattern": "fs.readFile(req.query.$FILE)"},
                {"pattern": "fs.readFileSync(req.query.$FILE)"},
                {"pattern": "path.join(__dirname, req.query.$FILE)"},
            ]},
        ],
        "message": "Path traversal via user-controlled file path",
    },
    "JS-015": {
        "languages": ["javascript", "typescript"],
        "patterns": [
            {"pattern-either": [
                {"pattern": "axios.get(req.query.$URL)"},
                {"pattern": "axios.post(req.query.$URL, ...)"},
                {"pattern": "fetch(req.query.$URL)"},
                {"pattern": "request(req.query.$URL)"},
            ]},
        ],
        "message": "Server-Side Request Forgery (SSRF) via user-controlled URL",
    },
    "JS-034": {
        "languages": ["javascript", "typescript"],
        "patterns": [
            {"pattern-either": [
                {"pattern": """
app.get('/admin...', (req, res) => {
    ...
})
"""},
                {"pattern": """
router.get('/admin...', (req, res) => {
    ...
})
"""},
            ]},
            {"pattern-not-regex": "requireAuth|authenticate|isAuthenticated|verifyToken|middleware|guard"},
        ],
        "message": "Admin route without visible authentication middleware",
    },
    "JS-039": {
        "languages": ["javascript", "typescript"],
        "patterns": [
            {"pattern-either": [
                {"pattern": "res.redirect(req.query.$VAR)"},
                {"pattern": "res.redirect(req.body.$VAR)"},
                {"pattern": "window.location.href = req.query.$VAR"},
            ]},
        ],
        "message": "Open redirect via unvalidated user input",
    },
    "JS-043": {
        "languages": ["javascript", "typescript"],
        "patterns": [
            {"pattern-either": [
                {"pattern": "new DOMParser().parseFromString($XML, 'text/xml')"},
                {"pattern": "libxmljs.parseXml($XML)"},
            ]},
            {"pattern-not-regex": r"resolveExternalEntities:\s*false|noent|noentities"},
        ],
        "message": "XML External Entity (XXE) injection via unsecured XML parser",
    },
    "JS-045": {
        "languages": ["javascript", "typescript"],
        "patterns": [
            {"pattern-either": [
                {"pattern": "res.cookie('session', $TOKEN, { httpOnly: true })"},
                {"pattern": "res.cookie('session', $TOKEN)"},
                {"pattern": "res.cookie('token', $TOKEN)"},
            ]},
            {"pattern-not-regex": r"secure:\s*true"},
        ],
        "message": "Cookie without secure flag set (CWE-614)",
    },
    "JS-046": {
        "languages": ["javascript", "typescript"],
        "patterns": [
            {"pattern-either": [
                {"pattern": "serialize.unserialize($DATA)"},
                {"pattern": "unserialize($DATA)"},
                {"pattern": "JSON.parse($DATA)"},
            ]},
            {"pattern-not-regex": "JSON\\.parse\\([^)]*\\)"},
        ],
        "message": "Unsafe deserialization of user-controlled data",
    },
    "JS-051": {
        "languages": ["javascript", "typescript"],
        "patterns": [
            {"pattern": "db.collection(...).find({ $where: $VAR })"},
        ],
        "message": "NoSQL injection via $where operator with unsanitized input",
    },
}


def _yaml_value(value: Any, indent: int = 0) -> str:
    """Format a Python value as Semgrep-compatible YAML (which is JSON-superset)."""
    prefix = "  " * indent
    if isinstance(value, dict):
        if not value:
            return "{}"
        lines = ["{"]
        for k, v in value.items():
            lines.append(f"{prefix}  {k}: {_yaml_value(v, indent + 1)}")
        lines.append(f"{prefix}}}")
        return "\n".join(lines)
    elif isinstance(value, list):
        if not value:
            return "[]"
        items = []
        for item in value:
            items.append(f"\n{prefix}  - {_yaml_value(item, indent + 1)}")
        return "".join(items)
    elif isinstance(value, str):
        # Use pipe block scalar for multi-line strings
        if "\n" in value:
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            return f'|-\n{prefix}  {escaped.strip()}'
        return f'"{value}"'
    elif isinstance(value, bool):
        return "true" if value else "false"
    elif value is None:
        return "null"
    else:
        return str(value)


def _build_semgrep_rule(
    rule_id: str,
    mapping: dict[str, Any],
    contract: Any | None,
) -> str:
    """Build a single Semgrep rule YAML string from an ansede rule mapping."""
    cwe = contract.cwe if contract and hasattr(contract, "cwe") else ""
    severity = contract.default_severity.upper() if contract and hasattr(contract, "default_severity") else "WARNING"
    summary = contract.summary if contract and hasattr(contract, "summary") else mapping.get("message", f"Rule {rule_id}")
    title = contract.title if contract and hasattr(contract, "title") else mapping.get("message", f"Rule {rule_id}")

    languages = mapping.get("languages", ["python"])
    lang_list = ", ".join(f'"{l}"' for l in languages)

    message = mapping.get("message", summary)

    # Build the patterns section
    patterns = mapping.get("patterns", [])
    patterns_yaml = _yaml_value(patterns, 2)

    tags_yaml = _yaml_value(["ansede", f"cwe-{cwe.lower().replace('-', '')}" if cwe else "security"], 2)

    return f"""rules:
  - id: ansede-{rule_id.lower()}
    languages: [{lang_list}]
    severity: {severity.upper()}
    message: "{message}"
    patterns:{patterns_yaml}
    metadata:
      cwe: "{cwe}"
      source: "ansede-static"
      rule_id: "{rule_id}"
      category: "security"
      technology: "{', '.join(languages)}"
      name: "{title}"
      tags: {tags_yaml}
"""


def transpile_rule(rule_id: str) -> str:
    """Transpile a single ansede rule to Semgrep YAML.

    Args:
        rule_id: The ansede rule ID (e.g. "PY-004", "JS-001").

    Returns:
        Semgrep-compatible YAML string, or empty string if rule has no mapping.

    Raises:
        KeyError: If the rule_id is not found in either the pattern mapping
                  or the rule contracts.
    """
    # Check if we have a manual pattern mapping
    mapping = _SEMGREP_PATTERNS.get(rule_id)
    if mapping is None:
        # Fall back: try to get the rule contract and generate a generic rule
        contract = get_rule_contract(rule_id)
        if contract is None:
            raise KeyError(f"No Semgrep mapping or rule contract for {rule_id}")
        return _build_semgrep_rule(rule_id, {"message": contract.summary or contract.title}, contract)

    contract = get_rule_contract(rule_id)
    # Some rules (e.g., JS rules) are loaded dynamically; if contract is None we still emit
    if contract is None:
        # Generate a minimal rule using just the mapping
        languages = mapping.get("languages", ["python"])
        lang_list = ", ".join(f'"{l}"' for l in languages)
        patterns_yaml = _yaml_value(mapping.get("patterns", []), 2)
        message = mapping.get("message", f"Rule {rule_id}")
        return f"""rules:
  - id: ansede-{rule_id.lower()}
    languages: [{lang_list}]
    severity: WARNING
    message: "{message}"
    patterns:{patterns_yaml}
    metadata:
      source: "ansede-static"
      rule_id: "{rule_id}"
      category: "security"
"""
    return _build_semgrep_rule(rule_id, mapping, contract)


def transpile_all() -> str:
    """Transpile all supported ansede rules to Semgrep YAML.

    Returns:
        A complete Semgrep rules file as a YAML string.
    """
    parts = []
    # Sort for deterministic output: Python rules first, then JS rules
    for rule_id in sorted(_SEMGREP_PATTERNS.keys()):
        try:
            parts.append(transpile_rule(rule_id))
        except KeyError:
            continue
    return "\n".join(parts)


def transpile_supported_rules() -> list[str]:
    """Return the list of rule IDs that have Semgrep mappings."""
    return sorted(_SEMGREP_PATTERNS.keys())


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        rule_id = sys.argv[1]
        try:
            print(transpile_rule(rule_id))
        except KeyError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        print(transpile_all())
