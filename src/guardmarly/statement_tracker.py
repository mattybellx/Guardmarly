"""Object-sensitive PreparedStatement tracking for FPR reduction.

Distinguishes parameterized PreparedStatements (safe) from dynamic
Statements (potentially vulnerable) by tracking which variable holds
which kind of statement object.
"""
from __future__ import annotations

import re


def classify_statement_variables(method_body: str) -> dict[str, str]:
    """Classify Statement/PreparedStatement variables in a method body.

    Returns dict mapping variable name → "parameterized" | "dynamic" | "unknown"
    """
    result: dict[str, str] = {}

    # Pattern 1: PreparedStatement with ? → parameterized (SAFE)
    for m in re.finditer(
        r'(?:PreparedStatement|CallableStatement)\s+(\w+)\s*=\s*\w+\.prepare(?:Statement|Call)\s*\(\s*"[^"]*\?\s*[^"]*"',
        method_body,
    ):
        result[m.group(1)] = "parameterized"

    # Pattern 2: PreparedStatement assigned from prepareStatement (any kind)
    for m in re.finditer(
        r'(\w+)\s*=\s*\w+\.prepareStatement\s*\(',
        method_body,
    ):
        var = m.group(1)
        if var not in result:
            # Check if the prepareStatement call has ? somewhere nearby
            pos = m.start()
            nearby = method_body[max(0, pos - 50):pos + 200]
            if '?' in nearby:
                result[var] = "parameterized"
            else:
                result[var] = "dynamic"

    # Pattern 3: Statement from createStatement → dynamic (POTENTIALLY VULNERABLE)
    for m in re.finditer(
        r'(?:Statement)\s+(\w+)\s*=\s*\w+\.createStatement\s*\(',
        method_body,
    ):
        result[m.group(1)] = "dynamic"

    # Pattern 4: CallableStatement from prepareCall → check for ?
    for m in re.finditer(
        r'(\w+)\s*=\s*\w+\.prepareCall\s*\(',
        method_body,
    ):
        var = m.group(1)
        if var not in result:
            pos = m.start()
            nearby = method_body[max(0, pos - 50):pos + 200]
            if '?' in nearby:
                result[var] = "parameterized"
            else:
                result[var] = "dynamic"

    return result


def is_safe_sql_call(call_text: str, stmt_vars: dict[str, str]) -> bool:
    """Check if a SQL method call is on a parameterized statement (safe)."""
    # Extract receiver: ps.executeQuery() → ps
    m = re.match(r'(\w+)\.(?:executeQuery|executeUpdate|execute)\s*\(', call_text)
    if not m:
        return False
    receiver = m.group(1)
    return stmt_vars.get(receiver) == "parameterized"
