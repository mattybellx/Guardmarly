"""Guardmarly — Landing page and live scanner demo."""
from flask import Flask, render_template, request, jsonify, send_from_directory
import sys, os, json
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "..", "src"))
from guardmarly.python_analyzer import analyze_python
from guardmarly.js_analyzer import analyze_js

app = Flask(__name__, static_folder=os.path.join(BASE_DIR, "static"))

# ── Persistent scan counter ──────────────────────────────────────────────
COUNTER_FILE = os.path.join(BASE_DIR, "scan_counter.json")

def _read_counter():
    try:
        with open(COUNTER_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"total_scans": 0, "total_repos": 0, "since": datetime.utcnow().isoformat()}

def _write_counter(data):
    with open(COUNTER_FILE, "w") as f:
        json.dump(data, f, indent=2)

@app.route("/")
def index():
    counter = _read_counter()
    return render_template("index.html", counter=counter)

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
                "title": f.title, "line": f.line,
                "cwe": f.cwe or "", "suggestion": f.suggestion or "",
            })
        # Bump scan counter
        counter = _read_counter()
        counter["total_scans"] = counter.get("total_scans", 0) + 1
        _write_counter(counter)
        return jsonify({"findings": findings, "lines": len(code.splitlines())})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/stats")
def stats():
    return jsonify(_read_counter())

@app.route("/guard.png")
def logo():
    return send_from_directory(os.path.join(BASE_DIR, "static"), "guard.png")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8765, debug=False)
