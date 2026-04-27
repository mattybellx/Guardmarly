from __future__ import annotations

from ansede_static import scan_code
from ansede_static.rules import describe_rule, get_rule_contract, list_rule_contracts


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
