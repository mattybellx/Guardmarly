"""Tests for CVSS scoring and OWASP mapping."""
from guardmarly.engine.cvss import get_cvss, get_owasp, enrich_finding_properties


class TestCvss:
    def test_sqli_gets_critical(self):
        cvss = get_cvss("CWE-89")
        assert cvss["severity"] == "critical"
        assert cvss["score"] >= 9.0

    def test_xss_gets_high(self):
        cvss = get_cvss("CWE-79")
        assert cvss["severity"] == "high"

    def test_open_redirect_gets_medium(self):
        cvss = get_cvss("CWE-601")
        assert cvss["severity"] == "medium"

    def test_unknown_cwe_gets_default(self):
        cvss = get_cvss("CWE-99999")
        assert cvss["score"] > 0

    def test_owasp_mapping(self):
        assert "Injection" in get_owasp("CWE-89")
        assert "Access Control" in get_owasp("CWE-639")
        assert "SSRF" in get_owasp("CWE-918")

    def test_enrich_includes_cvss_and_owasp(self):
        props = enrich_finding_properties("CWE-78", 0.92, 4)
        assert "cvss" in props
        assert "owasp" in props
        assert "exploitability" in props
        assert props["cvss"]["score"] >= 9.0
        assert props["exploitability"] == "high"

    def test_low_confidence_exploitability(self):
        props = enrich_finding_properties("CWE-89", 0.50, 1)
        assert props["exploitability"] == "low"
