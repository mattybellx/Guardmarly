from __future__ import annotations

import builtins

from ansede_static._types import AnalysisResult, Finding, Severity
from ansede_static.engine.audit import Verdict, audit_findings


def test_audit_marks_cookie_secure_flag_findings_in_test_files_as_likely_fp():
    result = AnalysisResult(file_path="C:/repo/test/res.cookie.js", language="javascript")
    result.findings.append(
        Finding(
            category="security",
            severity=Severity.MEDIUM,
            title="CWE-614: Cookie set without Secure flag at line 13",
            description="Cookie set without Secure flag in test helper.",
            line=13,
            rule_id="JS-045",
            cwe="CWE-614",
            agent="js-analyzer",
            analysis_kind="pattern",
        )
    )

    report = audit_findings([result])

    assert len(report.findings) == 1
    assert report.findings[0].verdict is Verdict.LIKELY_FP


def test_audit_marks_example_routes_as_likely_fp_even_in_underscore_examples_dir():
    result = AnalysisResult(file_path="C:/repo/chi/_examples/pathvalue/main.go", language="go")
    result.findings.append(
        Finding(
            category="security",
            severity=Severity.HIGH,
            title="Missing authentication on GET /users/{userID}",
            description="HTTP handler pathValueHandler for GET /users/{userID} does not appear to enforce authentication",
            line=12,
            rule_id="GO-862",
            cwe="CWE-862",
            agent="go-analyzer",
            analysis_kind="go-ast-auth",
        )
    )

    report = audit_findings([result])

    assert report.findings[0].verdict is Verdict.LIKELY_FP


def test_audit_marks_design_time_dbcontext_factory_secret_as_likely_fp(tmp_path):
    file_path = tmp_path / "Infrastructure" / "Data" / "AppDbContextFactory.cs"
    file_path.parent.mkdir(parents=True)
    file_path.write_text(
        "using Microsoft.EntityFrameworkCore.Design;\n"
        "public class AppDbContextFactory : IDesignTimeDbContextFactory<AppDbContext> {\n"
        "  private const string Conn = \"Server=localhost;Password=Your$tr0ngP@ss!;\";\n"
        "}\n",
        encoding="utf-8",
    )
    result = AnalysisResult(file_path=str(file_path), language="csharp")
    result.findings.append(
        Finding(
            category="security",
            severity=Severity.HIGH,
            title="CWE-798: Hardcoded connection secret in C# source",
            description="A string literal contains a password or API key directly in source code.",
            line=3,
            rule_id="CS-006",
            cwe="CWE-798",
            agent="csharp-analyzer",
            analysis_kind="pattern",
        )
    )

    report = audit_findings([result])

    assert report.findings[0].verdict is Verdict.LIKELY_FP


def test_audit_marks_spark_framework_helpers_as_likely_fp(tmp_path):
    response_path = tmp_path / "src" / "main" / "java" / "spark" / "Response.java"
    response_path.parent.mkdir(parents=True)
    response_path.write_text("public class Response { void redirect(String location) { response.sendRedirect(location); } }", encoding="utf-8")

    result = AnalysisResult(file_path=str(response_path), language="java")
    result.findings.append(
        Finding(
            category="security",
            severity=Severity.MEDIUM,
            title="CWE-601: Open redirect via sendRedirect in `redirect()`",
            description="HttpServletResponse.sendRedirect() is called with a URL that may be attacker-influenced.",
            line=1,
            rule_id="JV-010",
            cwe="CWE-601",
            agent="java-analyzer",
            analysis_kind="pattern",
        )
    )

    report = audit_findings([result])

    assert report.findings[0].verdict is Verdict.LIKELY_FP


def test_audit_marks_normalized_go_redirect_helper_as_likely_fp(tmp_path):
    file_path = tmp_path / "chi" / "middleware" / "strip.go"
    file_path.parent.mkdir(parents=True)
    file_path.write_text(
        "package middleware\n"
        "import (\n"
        '  "fmt"\n'
        '  "net/http"\n'
        '  "strings"\n'
        ")\n"
        "func RedirectSlashes(w http.ResponseWriter, r *http.Request, path string) {\n"
        '  path = "/" + strings.Trim(path, "/")\n'
        '  path = fmt.Sprintf("%s?%s", path, r.URL.RawQuery)\n'
        '  http.Redirect(w, r, path, 301)\n'
        "}\n",
        encoding="utf-8",
    )
    result = AnalysisResult(file_path=str(file_path), language="go")
    result.findings.append(
        Finding(
            category="security",
            severity=Severity.MEDIUM,
            title="Open Redirect via http.Redirect",
            description="User-controlled data from HTTP request flows into http.Redirect",
            line=9,
            rule_id="GO-601",
            cwe="CWE-601",
            agent="go-analyzer",
            analysis_kind="go-ast-taint",
        )
    )

    report = audit_findings([result])

    assert report.findings[0].verdict is Verdict.LIKELY_FP


def test_audit_marks_retrofit_docs_tab_script_as_likely_fp(tmp_path):
    file_path = tmp_path / "retrofit" / "website" / "public" / "2.x" / "converter-gson" / "script.js"
    file_path.parent.mkdir(parents=True)
    file_path.write_text(
        "function updateTabs(type) {\n"
        "  var spanNode = sNode.firstChild;\n"
        "  spanNode.innerHTML = \"<a href=\\\"javascript:show(\" + value + \" );\\\">\" + tabs[value][1] + \"</a>\";\n"
        "}\n",
        encoding="utf-8",
    )
    result = AnalysisResult(file_path=str(file_path), language="javascript")
    result.findings.append(
        Finding(
            category="security",
            severity=Severity.HIGH,
            title="CWE-79: XSS via innerHTML assignment at line 3",
            description="Potential DOM XSS via innerHTML assignment.",
            line=3,
            rule_id="JS-001",
            cwe="CWE-79",
            agent="js-analyzer",
            analysis_kind="pattern",
        )
    )

    report = audit_findings([result])

    assert report.findings[0].verdict is Verdict.LIKELY_FP


def test_audit_marks_nopcommerce_storefront_missing_auth_as_likely_fp(tmp_path):
    file_path = tmp_path / "nopCommerce" / "src" / "Presentation" / "Nop.Web" / "Controllers" / "CatalogController.cs"
    file_path.parent.mkdir(parents=True)
    file_path.write_text(
        "public class CatalogController : BasePublicController {\n"
        "  [HttpGet]\n"
        "  public IActionResult GetCategoryProducts() => Ok();\n"
        "}\n",
        encoding="utf-8",
    )
    result = AnalysisResult(file_path=str(file_path), language="csharp")
    result.findings.append(
        Finding(
            category="security",
            severity=Severity.HIGH,
            title="CWE-862: ASP.NET action `GetCategoryProducts()` missing [Authorize]",
            description="Controller action exposes a routed endpoint without [Authorize] and no obvious authenticated-user check was found in the body.",
            line=2,
            rule_id="CS-001",
            cwe="CWE-862",
            agent="csharp-analyzer",
            analysis_kind="route_heuristic",
        )
    )

    report = audit_findings([result])

    assert report.findings[0].verdict is Verdict.LIKELY_FP


def test_audit_marks_nopcommerce_public_controller_missing_auth_as_likely_fp(tmp_path):
    file_path = tmp_path / "nopCommerce" / "src" / "Plugins" / "PayPal" / "Controllers" / "PayPalCommercePublicController.cs"
    file_path.parent.mkdir(parents=True)
    file_path.write_text(
        "public class PayPalCommercePublicController : BasePublicController {\n"
        "  [HttpPost]\n"
        "  public IActionResult Callback() => Ok();\n"
        "}\n",
        encoding="utf-8",
    )
    result = AnalysisResult(file_path=str(file_path), language="csharp")
    result.findings.append(
        Finding(
            category="security",
            severity=Severity.HIGH,
            title="CWE-862: ASP.NET action `Callback()` missing [Authorize]",
            description="Controller action exposes a routed endpoint without [Authorize] and no obvious authenticated-user check was found in the body.",
            line=2,
            rule_id="CS-001",
            cwe="CWE-862",
            agent="csharp-analyzer",
            analysis_kind="route_heuristic",
        )
    )

    report = audit_findings([result])

    assert report.findings[0].verdict is Verdict.LIKELY_FP


def test_audit_reuses_source_lines_for_multiple_findings_in_same_file(tmp_path, monkeypatch):
    file_path = tmp_path / "app.py"
    file_path.write_text(
        "def view():\n"
        "    return request.args['name']\n"
        "\n"
        "def other():\n"
        "    return request.args['id']\n",
        encoding="utf-8",
    )

    result = AnalysisResult(file_path=str(file_path), language="python")
    result.findings.extend([
        Finding(
            category="security",
            severity=Severity.HIGH,
            title="Possible issue one",
            description="Route may need auth decorator.",
            line=2,
            rule_id="PY-020",
            cwe="CWE-862",
            agent="python-analyzer",
            analysis_kind="decorator-heuristic",
        ),
        Finding(
            category="security",
            severity=Severity.HIGH,
            title="Possible issue two",
            description="Route may need auth decorator.",
            line=5,
            rule_id="PY-020",
            cwe="CWE-862",
            agent="python-analyzer",
            analysis_kind="decorator-heuristic",
        ),
    ])

    calls = 0
    real_open = builtins.open

    def counting_open(*args, **kwargs):
        nonlocal calls
        calls += 1
        return real_open(*args, **kwargs)

    monkeypatch.setattr(builtins, "open", counting_open)

    report = audit_findings([result])

    assert len(report.findings) == 2
    assert calls == 1