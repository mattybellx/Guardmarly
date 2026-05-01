"""
ansede-studio — Premium Security Scanner Web App
─────────────────────────────────────────────────
Zero-dependency Flask server wrapping ansede-static.
Drop a file or paste code, scan, get beautiful results.

Run:  python webapp/app.py
Open: http://localhost:8765
"""
from __future__ import annotations

import io
import json
import tempfile
import textwrap
from pathlib import Path

from flask import Flask, render_template, request, jsonify, send_file

app = Flask(__name__, template_folder="templates", static_folder="static")

# Import the scanner
from ansede_static.python_analyzer import analyze_python
from ansede_static.js_analyzer import analyze_js
from ansede_static.reporters import format_sarif


@app.route("/")
def index():
    """Serve the main app."""
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Scan uploaded files or pasted code."""
    results_list = []
    total_findings = 0
    language = "unknown"

    # ── Handle file uploads ──────────────────────────────────────────
    if "files" in request.files:
        uploaded = request.files.getlist("files")
        for file in uploaded:
            if not file.filename:
                continue
            code = file.read().decode("utf-8", errors="replace")
            ext = Path(file.filename).suffix.lower()
            language = "python" if ext in (".py", ".pyw") else "javascript" if ext in (".js", ".jsx", ".ts", ".tsx", ".mjs") else "unknown"
            if language == "python":
                result = analyze_python(code, filename=file.filename)
            elif language == "javascript":
                result = analyze_js(code, filename=file.filename)
            else:
                continue
            results_list.append(_serialize_result(result))
            total_findings += len(result.findings)

    # ── Handle pasted code ───────────────────────────────────────────
    code_text = (request.form.get("code") or "").strip()
    if code_text:
        lang = (request.form.get("language") or "auto").strip().lower()
        if lang == "auto":
            lang = "python" if ("import " in code_text or "def " in code_text or "class " in code_text) else "javascript"
        language = lang
        if language == "python":
            result = analyze_python(code_text, filename="<pasted>")
        else:
            result = analyze_js(code_text, filename="<pasted>")
        results_list.append(_serialize_result(result))
        total_findings += len(result.findings)

    return jsonify({
        "success": True,
        "language": language,
        "total_findings": total_findings,
        "results": results_list,
        "fingerprint_version": 2,
    })


@app.route("/api/scan/file", methods=["POST"])
def api_scan_single():
    """Scan a single file and return detailed results."""
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file provided"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"success": False, "error": "Empty filename"}), 400

    code = file.read().decode("utf-8", errors="replace")
    ext = Path(file.filename).suffix.lower()
    language = "python" if ext in (".py", ".pyw") else "javascript" if ext in (".js", ".jsx", ".ts", ".tsx", ".mjs") else "unknown"

    if language == "python":
        result = analyze_python(code, filename=file.filename)
    elif language == "javascript":
        result = analyze_js(code, filename=file.filename)
    else:
        return jsonify({"success": False, "error": f"Unsupported file type: {ext}"}), 400

    return jsonify({
        "success": True,
        "language": language,
        "result": _serialize_result(result, include_code=True, source_code=code),
        "fingerprint_version": 2,
    })


@app.route("/api/export", methods=["POST"])
def api_export():
    """Export findings as SARIF or JSON."""
    data = request.get_json(force=True) or {}
    export_format = data.get("format", "sarif")
    findings_data = data.get("findings", [])

    if not findings_data:
        return jsonify({"success": False, "error": "No findings to export"}), 400

    # Reconstruct minimal results
    from ansede_static._types import AnalysisResult, Finding, Severity, TraceFrame
    results = []
    for file_result in findings_data:
        findings = []
        for fd in file_result.get("findings", []):
            trace = tuple(
                TraceFrame(kind=t.get("kind", ""), label=t.get("label", ""), line=t.get("line"))
                for t in fd.get("trace", [])
            )
            findings.append(Finding(
                category=fd.get("category", "security"),
                severity=Severity(fd.get("severity", "medium")),
                title=fd.get("title", ""),
                description=fd.get("description", ""),
                line=fd.get("line"),
                suggestion=fd.get("suggestion", ""),
                rule_id=fd.get("rule_id", ""),
                cwe=fd.get("cwe", ""),
                agent=fd.get("agent", ""),
                confidence=fd.get("confidence", 1.0),
                trace=trace,
                analysis_kind=fd.get("analysis_kind", ""),
                triggering_code=fd.get("triggering_code", ""),
            ))
        results.append(AnalysisResult(
            file_path=file_result.get("file_path", ""),
            language=file_result.get("language", ""),
            findings=findings,
            lines_scanned=file_result.get("lines_scanned", 0),
        ))

    if export_format == "sarif":
        sarif_str = format_sarif(results)
        return jsonify({"success": True, "format": "sarif", "content": sarif_str})
    else:
        return jsonify({"success": True, "format": "json", "content": json.dumps(
            {"results": [_serialize_result(r) for r in results]},
            indent=2,
        )})


def _serialize_result(result, include_code=False, source_code=""):
    """Convert AnalysisResult to JSON-safe dict."""
    code_lines = source_code.splitlines() if include_code else []
    findings = []
    for finding in result.sorted_findings():
        fd = {
            "severity": finding.severity.value,
            "title": finding.title,
            "description": finding.description,
            "line": finding.line,
            "suggestion": finding.suggestion,
            "rule_id": finding.rule_id,
            "cwe": finding.cwe,
            "agent": finding.agent,
            "confidence": round(finding.confidence, 2),
            "analysis_kind": finding.analysis_kind,
            "trace": [
                {
                    "kind": frame.kind,
                    "label": frame.label,
                    "line": frame.line,
                }
                for frame in (finding.trace or ())
            ],
        }
        # Include the triggering line of code for context
        if include_code and finding.line and 0 < finding.line <= len(code_lines):
            fd["code_snippet"] = code_lines[finding.line - 1].strip()[:120]
            # Also get surrounding context (2 lines before and after)
            ctx_start = max(0, finding.line - 3)
            ctx_end = min(len(code_lines), finding.line + 2)
            fd["code_context"] = [
                {"line_num": i + 1, "code": code_lines[i].rstrip(), "is_target": (i + 1 == finding.line)}
                for i in range(ctx_start, ctx_end)
            ]
        findings.append(fd)

    return {
        "file_path": result.file_path,
        "language": result.language,
        "lines_scanned": result.lines_scanned,
        "parse_error": result.parse_error,
        "findings": findings,
        "critical_count": result.critical_count,
        "high_count": result.high_count,
    }


if __name__ == "__main__":
    print(textwrap.dedent("""
    ╔══════════════════════════════════════════════════════════════╗
    ║           ansede-studio — Premium Security Scanner          ║
    ║                                                            ║
    ║   Open your browser to:  http://localhost:8765             ║
    ║                                                            ║
    ║   Drop a .py or .js file, or paste code directly.         ║
    ║   Results appear instantly with severity, traces,          ║
    ║   and actionable fix suggestions.                          ║
    ╚══════════════════════════════════════════════════════════════╝
    """))
    app.run(host="0.0.0.0", port=8765, debug=True)
