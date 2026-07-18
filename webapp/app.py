"""Guardmarly — Landing page and live scanner demo."""
from flask import Flask, render_template, request, jsonify, send_from_directory
import subprocess, tempfile, os, json

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
    
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(code)
        tmp = f.name
    
    try:
        result = subprocess.run(
            ["guardmarly", tmp, "--format", "json", "--fail-on", "never", "--no-triage"],
            capture_output=True, text=True, timeout=30,
            env={**os.environ, "PYTHONPATH": "/app/src"}
        )
        data = json.loads(result.stdout) if result.stdout.strip() else {"results": []}
        findings = []
        for r in data.get("results", []):
            for f in r.get("findings", []):
                findings.append({
                    "severity": f.get("severity", "info"),
                    "title": f.get("title", ""),
                    "line": f.get("line"),
                    "cwe": f.get("cwe", ""),
                    "suggestion": f.get("suggestion", ""),
                })
        return jsonify({"findings": findings, "lines": len(code.splitlines())})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

@app.route("/guard.png")
def logo():
    return send_from_directory("static", "guard.png")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8765, debug=False)
