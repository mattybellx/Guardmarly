"""
guardmarly.v2.rules.shared.sql_injection
─────────────────────────────────────────────
SQLInjectionRule — CWE-89 (renamed from _rule_12).

Shared between Python and JavaScript; registered against CALL nodes
for both languages.
"""
from __future__ import annotations

import re
from typing import Optional

from guardmarly.v2.nodes import ASTNode, CallNode, FormattedStringNode
from guardmarly.v2.model import SemanticModel
from guardmarly.v2.rule_protocol import Finding, REGISTRY

_SQL_CALLEES = frozenset({
    "execute",
    "executemany",
    "raw",
    "query",
    "db.execute",
    "db.query",
    "cursor.execute",
    "session.execute",
    "conn.execute",
    "connection.execute",
    "sequelize.query",
    "knex.raw",
})

_TAINT_SOURCE_RE = re.compile(
    r"\b(?:request|sys\.argv|os\.environ|os\.getenv|input|params|"
    r"req\.body|req\.query|req\.params)\b"
)

# Safe parameterization patterns — if present in the raw call text, likely safe
_PARAM_SAFE_RE = re.compile(
    r"(?:\?,\s*\(|%s,\s*\(|:[\w]+\s*,|\bparams\b|\bparameters\b)"
)


def _callee_matches_sql(callee: str) -> bool:
    short = callee.split(".")[-1]
    return callee in _SQL_CALLEES or short in {"execute", "executemany", "raw", "query"}


def _arg_is_tainted(arg: ASTNode) -> bool:
    raw = arg.raw_text or ""
    # f-strings passed as query arguments are always suspicious
    if isinstance(arg, FormattedStringNode):
        return True
    return bool(_TAINT_SOURCE_RE.search(raw))


@REGISTRY.register("CALL")
class SQLInjectionRule:
    """
    Detects SQL query construction with user-controlled input (CWE-89).
    Renamed from legacy _rule_12.
    """

    rule_id = "PY-SEC-012"
    cwe = "CWE-89"
    severity = "high"
    title = "SQL Injection"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, CallNode):
            return None

        if not _callee_matches_sql(node.callee):
            return None

        raw = node.raw_text or ""
        has_taint = any(_arg_is_tainted(a) for a in node.args) or bool(_TAINT_SOURCE_RE.search(raw))

        if not has_taint:
            return None

        # Exclude calls that already use safe parameterization
        if _PARAM_SAFE_RE.search(raw):
            return None

        # Check for string concatenation / f-string in raw text
        has_concat = "+" in raw or "%" in raw or "f'" in raw or 'f"' in raw

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"`{node.callee}()` constructs a SQL query with user-controlled data. "
                "An attacker can manipulate the query logic, bypass authentication, "
                "or extract/modify database content."
            ),
            confidence="likely" if has_concat else "possible",
            suggestion=(
                "Use parameterized queries or prepared statements. Pass user data as "
                "a separate parameters tuple, not as part of the SQL string:\n"
                "  cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
            ),
        )
