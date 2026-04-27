from __future__ import annotations

import json

from ansede_static.cache import stable_hash
from ansede_static.engine_version import ENGINE_NAME, SCHEMA_VERSION
from ansede_static.schema import FINGERPRINT_VERSION
from ansede_static.ir import build_issue_records
from ansede_static._types import AnalysisResult, Finding, Severity, TraceFrame
from ansede_static.python_analyzer import analyze_python
from ansede_static.reporters import format_json, format_sarif, format_text_multi


def _sample_results():
    code = """
from flask import request
def dangerous(cursor):
    user_id = request.args.get('id')
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
"""
    return [analyze_python(code, filename="sample.py")]


def _mixed_results():
    return [AnalysisResult(
        file_path="mixed.py",
        language="python",
        findings=[
            Finding(
                category="security",
                severity=Severity.HIGH,
                title="CWE-89: SQL Injection in run_query()",
                description="Untrusted input flows into SQL.",
                line=10,
                suggestion="Use parameterized queries.",
                rule_id="PY-004",
                cwe="CWE-89",
                agent="python-analyzer",
                confidence=0.97,
                analysis_kind="taint-flow",
                trace=(
                    TraceFrame(kind="source", label="source `request.args.get('id')`", line=8),
                    TraceFrame(kind="sink", label="sink `cursor.execute()`", line=10),
                ),
            ),
            Finding(
                category="architecture",
                severity=Severity.MEDIUM,
                title="Excessive complexity in branchy()",
                description="Cyclomatic complexity is too high.",
                line=22,
                suggestion="Extract helper functions.",
                rule_id="PY-028",
                agent="python-analyzer",
                confidence=0.78,
                analysis_kind="metric",
            ),
        ],
        lines_scanned=40,
    )]


def test_json_report_has_versioned_envelope():
    payload = json.loads(format_json(_sample_results()))

    assert payload["schema_version"] == SCHEMA_VERSION
    assert payload["fingerprint_version"] == FINGERPRINT_VERSION
    assert payload["tool"] == ENGINE_NAME
    assert payload["summary"]["total_findings"] == 1
    assert payload["summary"]["security_findings"] == 1
    assert payload["summary"]["quality_findings"] == 0
    assert payload["summary"]["by_category"]["security"] == 1
    assert payload["files_scanned"] == 1
    assert payload["results"][0]["file"] == "sample.py"
    assert payload["results"][0]["file_path"] == "sample.py"
    assert payload["results"][0]["lines_scanned"] > 0
    assert payload["results"][0]["findings"][0]["finding_class"] == "security"
    assert payload["results"][0]["findings"][0]["rule_id"] == "PY-004"
    assert payload["results"][0]["findings"][0]["rule"]["rule_id"] == "PY-004"
    assert payload["results"][0]["findings"][0]["rule"]["precision"] == "high"


def test_ir_builder_emits_records():
    records = build_issue_records(_sample_results())

    assert len(records) == 1
    assert records[0].rule_id == "PY-004"
    assert records[0].location.file_path == "sample.py"
    assert "security" in records[0].tags
    assert len(records[0].trace) >= 2
    assert records[0].trace[0].kind == "source"
    assert records[0].trace[-1].kind == "sink"
    assert records[0].metadata["cwe"] == "CWE-89"


def test_ir_builder_preserves_analysis_kind_metadata():
    records = build_issue_records(_mixed_results())

    assert records[0].metadata["analysis_kind"] == "taint-flow"
    assert records[1].metadata["analysis_kind"] == "metric"


def test_sarif_has_partial_fingerprints():
    payload = json.loads(format_sarif(_sample_results()))
    result = payload["runs"][0]["results"][0]

    assert result["ruleId"] == "PY-004"
    assert "partialFingerprints" in result
    assert len(result["partialFingerprints"]["primaryLocationLineHash"]) == 64
    assert "codeFlows" in result
    assert len(result["codeFlows"][0]["threadFlows"][0]["locations"]) >= 2
    assert result["properties"]["rule"]["rule_id"] == "PY-004"


def test_mixed_report_separates_security_and_quality_findings():
    payload = json.loads(format_json(_mixed_results()))

    assert payload["summary"]["security_findings"] == 1
    assert payload["summary"]["quality_findings"] == 1
    assert payload["summary"]["by_category"]["architecture"] == 1
    assert payload["results"][0]["summary"]["security_findings"] == 1
    assert payload["results"][0]["summary"]["quality_findings"] == 1
    assert payload["results"][0]["findings"][1]["finding_class"] == "quality"
    assert payload["results"][0]["findings"][0]["analysis_kind"] == "taint-flow"
    assert payload["results"][0]["findings"][0]["confidence"] == 0.97
    assert payload["results"][0]["findings"][0]["trace"][0]["kind"] == "source"


def test_text_and_sarif_expose_finding_class_breakdown():
    text_report = format_text_multi(_mixed_results(), colour=False, verbose=True)
    sarif = json.loads(format_sarif(_mixed_results()))

    assert "1 security, 1 quality" in text_report
    assert "flow:" in text_report
    assert "meta: PY-004 · taint-flow · confidence 0.97" in text_report
    classes = {result["properties"]["findingClass"] for result in sarif["runs"][0]["results"]}
    assert classes == {"security", "quality"}
    analysis_kinds = {result["properties"]["analysisKind"] for result in sarif["runs"][0]["results"]}
    assert analysis_kinds == {"taint-flow", "metric"}
    precisions = {rule["properties"]["precision"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert precisions == {"high", "low"}
    rule_ids = {rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids == {"PY-004", "PY-028"}
    maturities = {rule["properties"]["maturity"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert "stable" in maturities


def test_json_and_sarif_can_include_execution_metadata():
    json_payload = json.loads(format_json(_sample_results(), execution={"js_backend": {"requested": "auto", "selected": "structural"}}))
    sarif_payload = json.loads(format_sarif(_sample_results(), execution={"js_backend": {"requested": "auto", "selected": "structural"}}))

    assert json_payload["execution"]["js_backend"]["selected"] == "structural"
    assert sarif_payload["runs"][0]["properties"]["execution"]["js_backend"]["requested"] == "auto"


def test_stable_hash_is_deterministic():
    assert stable_hash("abc") == stable_hash("abc")
    assert stable_hash("abc") != stable_hash("xyz")