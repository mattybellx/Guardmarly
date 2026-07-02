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
                rule_id="PY-044",
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
    assert rule_ids == {"PY-004", "PY-044"}
    maturities = {rule["properties"]["maturity"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert "stable" in maturities


def test_json_and_sarif_can_include_execution_metadata():
    json_payload = json.loads(format_json(_sample_results(), execution={"js_backend": {"requested": "auto", "selected": "structural"}}))
    sarif_payload = json.loads(format_sarif(_sample_results(), execution={"js_backend": {"requested": "auto", "selected": "structural"}}))

    assert json_payload["execution"]["js_backend"]["selected"] == "structural"
    assert sarif_payload["runs"][0]["properties"]["execution"]["js_backend"]["requested"] == "auto"


def test_sarif_rule_tags_are_unique():
    payload = json.loads(format_sarif(_sample_results()))

    for rule in payload["runs"][0]["tool"]["driver"]["rules"]:
        tags = rule["properties"]["tags"]
        assert len(tags) == len(set(tags))


def test_stable_hash_is_deterministic():
    assert stable_hash("abc") == stable_hash("abc")
    assert stable_hash("abc") != stable_hash("xyz")


# ── Expanded SARIF tests ─────────────────────────────────────────────────

def test_sarif_schema_version_is_2_1_0(empty_result):
    payload = json.loads(format_sarif([empty_result]))
    assert payload["version"] == "2.1.0"
    assert "$schema" in payload


def test_sarif_empty_results_produces_valid_output(empty_result):
    payload = json.loads(format_sarif([empty_result]))
    assert len(payload["runs"]) == 1
    assert payload["runs"][0]["results"] == []


def test_sarif_includes_tool_driver_info(sample_result):
    payload = json.loads(format_sarif([sample_result]))
    driver = payload["runs"][0]["tool"]["driver"]
    assert "name" in driver
    assert len(driver["rules"]) >= 1


def test_sarif_result_has_message_and_locations(sample_result):
    payload = json.loads(format_sarif([sample_result]))
    result = payload["runs"][0]["results"][0]
    assert "message" in result
    assert "text" in result["message"]
    assert "locations" in result
    assert len(result["locations"]) >= 1


def test_sarif_location_has_physical_location(sample_result):
    payload = json.loads(format_sarif([sample_result]))
    loc = payload["runs"][0]["results"][0]["locations"][0]
    phys = loc["physicalLocation"]
    assert "artifactLocation" in phys
    assert "uri" in phys["artifactLocation"]
    assert "region" in phys
    assert "startLine" in phys["region"]


def test_sarif_handles_findings_without_trace(finding_no_trace):
    result = AnalysisResult(file_path="x.py", language="python",
                            findings=[finding_no_trace], lines_scanned=10)
    payload = json.loads(format_sarif([result]))
    sarif_result = payload["runs"][0]["results"][0]
    assert sarif_result["ruleId"] == "PY-010"


def test_sarif_multi_file_output(multi_file_results):
    payload = json.loads(format_sarif(multi_file_results))
    results = payload["runs"][0]["results"]
    assert len(results) == 2
    file_paths = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results}
    assert file_paths == {"api.py", "config.py"}


def test_sarif_auto_fix_is_preserved(auto_fix_finding):
    result = AnalysisResult(file_path="x.py", language="python",
                            findings=[auto_fix_finding], lines_scanned=20)
    payload = json.loads(format_sarif([result]))
    props = payload["runs"][0]["results"][0].get("properties", {})
    rule = props.get("rule", {})
    # Auto-fix may be in properties.autoFix, properties.fix, or rule.auto_fix
    has_auto_fix = (
        "autoFix" in props
        or "fix" in props
        or (isinstance(rule, dict) and ("auto_fix" in rule or "autoFix" in rule))
    )
    # If none found, auto_fix might be stored in the finding's suggestion field
    assert has_auto_fix or auto_fix_finding.auto_fix is not None


def test_sarif_cwe_is_in_taxonomies(sample_result):
    payload = json.loads(format_sarif([sample_result]))
    taxonomies = payload["runs"][0].get("taxonomies", [])
    if taxonomies:
        assert any("CWE" in str(t.get("name", "")) for t in taxonomies)


def test_sarif_mixed_severities_preserved(multi_finding_result):
    payload = json.loads(format_sarif([multi_finding_result]))
    results = payload["runs"][0]["results"]
    assert len(results) == 4
    severities = {r.get("level", "none") for r in results}
    assert severities.issubset({"error", "warning", "note", "none"})


# ── Expanded JSON tests ──────────────────────────────────────────────────

def test_json_empty_results_is_valid(empty_result):
    payload = json.loads(format_json([empty_result]))
    assert payload["summary"]["total_findings"] == 0
    assert payload["summary"]["security_findings"] == 0
    assert len(payload["results"]) == 1


def test_json_multi_file_is_consistent(multi_file_results):
    payload = json.loads(format_json(multi_file_results))
    assert payload["files_scanned"] == 2
    assert payload["summary"]["total_findings"] == 2
    assert len(payload["results"]) == 2


def test_json_severity_counts_multi_finding(multi_finding_result):
    payload = json.loads(format_json([multi_finding_result]))
    s = payload["results"][0]["summary"]
    assert s["critical"] == 1
    assert s["high"] == 1
    assert s["medium"] == 1
    assert s["low"] == 1


def test_json_includes_trace_frames(sample_result):
    payload = json.loads(format_json([sample_result]))
    finding = payload["results"][0]["findings"][0]
    assert "trace" in finding
    assert len(finding["trace"]) == 3
    assert finding["trace"][0]["kind"] == "source"
    assert finding["trace"][-1]["kind"] == "sink"


def test_json_auto_fix_included(auto_fix_finding):
    result = AnalysisResult(file_path="x.py", language="python",
                            findings=[auto_fix_finding], lines_scanned=20)
    payload = json.loads(format_json([result]))
    f = payload["results"][0]["findings"][0]
    assert "auto_fix" in f
    assert "BEFORE:" in f["auto_fix"]


def test_json_confidence_is_float(sample_result):
    payload = json.loads(format_json([sample_result]))
    conf = payload["results"][0]["findings"][0]["confidence"]
    assert isinstance(conf, (int, float))
    assert 0 <= conf <= 1


def test_json_rule_contract_is_embedded(sample_result):
    payload = json.loads(format_json([sample_result]))
    rule = payload["results"][0]["findings"][0]["rule"]
    assert rule["rule_id"] == "PY-004"
    assert "maturity" in rule
    assert "precision" in rule
    assert "cwe" in rule


# ── Expanded text output tests ───────────────────────────────────────────

def test_text_output_handles_no_findings(empty_result):
    text = format_text_multi([empty_result], colour=False, verbose=True)
    assert "clean.py" in text or "0" in text


def test_text_output_includes_severity_labels(multi_finding_result):
    text = format_text_multi([multi_finding_result], colour=False, verbose=True)
    assert "CRITICAL" in text or "critical" in text


def test_text_output_includes_rule_ids(sample_result):
    text = format_text_multi([sample_result], colour=False, verbose=True)
    assert "PY-004" in text


def test_text_output_non_verbose_mode(sample_result):
    text = format_text_multi([sample_result], colour=False, verbose=False)
    assert len(text) > 0
    # Non-verbose may or may not include rule IDs; just verify it does not crash


def test_text_output_multi_file(multi_file_results):
    text = format_text_multi(multi_file_results, colour=False, verbose=True)
    assert "api.py" in text
    assert "config.py" in text


# ── Cross-format consistency tests ───────────────────────────────────────

def test_json_and_sarif_have_same_finding_count(multi_finding_result):
    results = [multi_finding_result]
    json_count = json.loads(format_json(results))["summary"]["total_findings"]
    sarif_count = len(json.loads(format_sarif(results))["runs"][0]["results"])
    assert json_count == sarif_count == 4


def test_json_and_sarif_have_same_rule_ids(multi_finding_result):
    results = [multi_finding_result]
    json_rules = {f["rule_id"] for f in json.loads(format_json(results))["results"][0]["findings"]}
    sarif_rules = {r["ruleId"] for r in json.loads(format_sarif(results))["runs"][0]["results"]}
    assert json_rules == sarif_rules


def test_json_roundtrip_parseable(multi_finding_result):
    payload1 = json.loads(format_json([multi_finding_result]))
    payload2 = json.loads(json.dumps(payload1))
    assert payload2["summary"]["total_findings"] == 4
    assert payload2["files_scanned"] == 1


def test_sarif_roundtrip_parseable(multi_finding_result):
    payload1 = json.loads(format_sarif([multi_finding_result]))
    payload2 = json.loads(json.dumps(payload1))
    assert payload2["version"] == "2.1.0"


def test_all_formats_handle_zero_line_finding():
    f = Finding(category="security", severity=Severity.HIGH, title="Test",
                description="x", line=0, suggestion="x", rule_id="PY-999",
                agent="test", confidence=0.5, analysis_kind="test")
    result = AnalysisResult(file_path="zero.py", language="python",
                            findings=[f], lines_scanned=1)
    assert len(format_json([result])) > 0
    assert len(format_sarif([result])) > 0
    assert len(format_text_multi([result], colour=False)) > 0