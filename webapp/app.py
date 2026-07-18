"""Guardmarly — Landing page and live scanner demo."""
from flask import Flask, render_template, request, jsonify, send_from_directory
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from guardmarly.python_analyzer import analyze_python
from guardmarly.js_analyzer import analyze_js

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    code = request.json.get("code", "")
    lang = request.json.get("language", "python")
    if not code.strip():
        return jsonify({"error": "No code provided"}), 400

    try:
        if lang == "python":
            result = analyze_python(code, filename="<demo>")
        else:
            result, _ = analyze_js(code, filename="<demo>")

        findings = []
        for f in result.findings:
            findings.append({
                "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                "title": f.title,
                "line": f.line,
                "cwe": f.cwe or "",
                "suggestion": f.suggestion or "",
            })
        return jsonify({"findings": findings, "lines": len(code.splitlines())})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/guard.png")
def logo():
    return send_from_directory("static", "guard.png")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8765, debug=False)
