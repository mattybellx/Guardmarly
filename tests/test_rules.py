from __future__ import annotations

from ansede_static import scan_code
from ansede_static.rules import (
    describe_rule,
    get_rule_contract,
    list_rule_contracts,
    _KNOWN_RULE_IDS,
)


def test_describe_rule_returns_curated_contract():
    contract = describe_rule("PY-020")

    assert contract is not None
    assert contract.cwe == "CWE-862"
    assert "authentication" in contract.title.lower()


def test_get_rule_contract_falls_back_to_placeholder_for_unknown_rule():
    contract = get_rule_contract("PY-999")

    assert contract.rule_id == "PY-999"
    assert contract.docs_url
    assert "Undocumented" in contract.title


def test_list_rule_contracts_contains_known_ids():
    rule_ids = {contract.rule_id for contract in list_rule_contracts()}

    assert "PY-004" in rule_ids
    assert "JS-040" in rule_ids


def test_all_shipped_rule_contracts_are_curated():
    contracts = list_rule_contracts()

    assert contracts
    assert all("Undocumented" not in contract.title for contract in contracts)


def test_generated_js_rule_summaries_do_not_leak_placeholders():
    contract = get_rule_contract("JS-014")

    assert "the flagged line" not in contract.summary
    assert "matched code" not in contract.summary.lower() or "at line" not in contract.summary.lower()


def test_scan_code_accepts_js_backend_keyword():
    result = scan_code(
        "function render(req) { document.getElementById('out').innerHTML = req.query.name; }",
        language="javascript",
        filename="xss.js",
        js_backend="structural",
    )

    assert any(f.cwe == "CWE-79" for f in result.findings)


# ── Rule catalog coverage metrics ────────────────────────────────────────────

def test_all_known_rule_ids_have_non_empty_summary():
    """Every shipped rule must have a real summary (not an empty string)."""
    contracts = list_rule_contracts()
    for contract in contracts:
        assert contract.summary, f"{contract.rule_id} has empty summary"


def test_all_known_rule_ids_have_remediation():
    """Every shipped rule must have actionable remediation text."""
    contracts = list_rule_contracts()
    for contract in contracts:
        assert contract.remediation, f"{contract.rule_id} has empty remediation"


def test_all_known_rule_ids_have_docs_url():
    """Every shipped rule must link to docs (CWE or OWASP page)."""
    contracts = list_rule_contracts()
    for contract in contracts:
        assert contract.docs_url, f"{contract.rule_id} has no docs_url"


def test_all_known_rule_ids_have_cwe():
    """Every security rule must be mapped to a CWE (quality/bug/arch rules may omit it)."""
    NON_SECURITY = {"bug", "quality", "architecture"}
    contracts = list_rule_contracts()
    security_rules = [c for c in contracts if c.category not in NON_SECURITY]
    for contract in security_rules:
        assert contract.cwe and contract.cwe.startswith("CWE-"), (
            f"{contract.rule_id} has invalid cwe: {contract.cwe!r}"
        )


def test_rule_catalog_coverage_floor():
    """At least 70 distinct rules must be in the catalog (regression guard)."""
    contracts = list_rule_contracts()
    assert len(contracts) >= 70, f"Only {len(contracts)} rules cataloged — expected ≥70"


def test_py_and_js_rules_both_present():
    """Catalog must contain both Python and JS rules."""
    contracts = list_rule_contracts()
    py_rules = [c for c in contracts if c.rule_id.startswith("PY-")]
    js_rules = [c for c in contracts if c.rule_id.startswith("JS-")]
    assert len(py_rules) >= 30, f"Only {len(py_rules)} PY rules"
    assert len(js_rules) >= 35, f"Only {len(js_rules)} JS rules"


def test_new_rule_contracts_present():
    """Spot-check that newly added rule IDs have curated contracts."""
    for rule_id in ("PY-038", "JS-043", "JS-044", "JS-045", "JS-046", "JS-047", "JS-048", "JS-049"):
        contract = get_rule_contract(rule_id)
        assert "Undocumented" not in contract.title, f"{rule_id} is still a placeholder"
        assert contract.cwe, f"{rule_id} has no CWE"


def test_rule_severity_values_are_valid():
    """All rule default severities must be one of the accepted values."""
    valid = {"critical", "high", "medium", "low", "info"}
    contracts = list_rule_contracts()
    for contract in contracts:
        assert contract.default_severity in valid, (
            f"{contract.rule_id} has invalid severity: {contract.default_severity!r}"
        )


def test_rule_precision_values_are_valid():
    """All rule precisions must be one of the accepted values."""
    valid = {"high", "medium", "low", "very-high"}
    contracts = list_rule_contracts()
    for contract in contracts:
        assert contract.precision in valid, (
            f"{contract.rule_id} has invalid precision: {contract.precision!r}"
        )
