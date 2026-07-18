from __future__ import annotations

from guardmarly.engine.explain import get_explanation


def test_get_explanation_returns_known_cwe_markdown():
    explanation = get_explanation("CWE-89")

    assert "SQL Injection" in explanation
    assert "parameterized queries" in explanation



def test_get_explanation_returns_generic_fallback_for_unknown_cwe():
    explanation = get_explanation("cwe-9999")

    assert explanation.startswith("### CWE-9999")
    assert "OWASP guidelines" in explanation
