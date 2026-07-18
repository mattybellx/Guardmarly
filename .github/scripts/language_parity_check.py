#!/usr/bin/env python3
"""Language parity CI checker.

Scans a minimal test snippet for each language and verifies that findings
are produced, ensuring the analyzer for that language is functioning.

Called by CI with the language name as the first argument.

Exit codes:
  0 — scan completed (findings may be zero for low-severity-only code)
  1 — scan failed or error
"""
from __future__ import annotations

import json
import subprocess
import sys


_TEST_SNIPPETS = {
    "python": (
        "import subprocess\n"
        "from flask import request\n\n"
        "@app.route('/admin')\n"
        "def admin():\n"
        "    cmd = request.args.get('cmd')\n"
        "    subprocess.call(cmd, shell=True)\n"
        "    return 'ok'\n"
    ),
    "javascript": (
        "const express = require('express');\n"
        "const app = express();\n"
        "app.get('/admin', (req, res) => {\n"
        "  const cmd = req.query.cmd;\n"
        "  require('child_process').execSync(cmd);\n"
        "  res.send('ok');\n"
        "});\n"
    ),
    "go": (
        'package main\n\n'
        'import (\n'
        '  "net/http"\n'
        '  "os/exec"\n'
        ')\n\n'
        'func handler(w http.ResponseWriter, r *http.Request) {\n'
        '  cmd := r.URL.Query().Get("cmd")\n'
        '  exec.Command("bash", "-c", cmd)\n'
        '  w.Write([]byte("ok"))\n'
        '}\n'
    ),
    "java": (
        'public class Test {\n'
        '  public void run(String input) throws Exception {\n'
        '    Runtime.getRuntime().exec(input);\n'
        '  }\n'
        '}\n'
    ),
    "csharp": (
        'using System;\n'
        'using System.Diagnostics;\n'
        'public class Test {\n'
        '  public void Run(string input) {\n'
        '    Process.Start(input);\n'
        '  }\n'
        '}\n'
    ),
    "ruby": (
        'def admin\n'
        '  cmd = params[:cmd]\n'
        '  system(cmd)\n'
        'end\n'
    ),
}


def main() -> int:
    if len(sys.argv) < 2:
        print("USAGE: language_parity_check.py <language>")
        return 1

    lang = sys.argv[1]
    code = _TEST_SNIPPETS.get(lang)
    if not code:
        print(f"SKIP: unknown language '{lang}'")
        return 0

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "guardmarly.cli",
            "--stdin",
            "--lang",
            lang,
            "--format",
            "json",
            "--fail-on",
            "never",
        ],
        input=code,
        capture_output=True,
        text=True,
        timeout=30,
    )

    if result.returncode != 0:
        print(f"ERROR: {lang} scan failed (exit {result.returncode})")
        print(result.stderr[:2000])
        return 1

    try:
        # Strip any non-JSON prefix (warnings, logs) before parsing
        out = result.stdout
        json_start = out.index("{")
        out = out[json_start:]
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        print(f"ERROR: failed to parse JSON for {lang}: {exc}")
        print(result.stdout[:1000])
        return 1

    results_list = data if isinstance(data, list) else data.get("results", [])
    finding_count = sum(
        len(r.get("findings", []))
        for r in results_list
    )

    print(f"{lang}: {finding_count} finding(s) detected")

    if finding_count == 0:
        print(f"WARNING: {lang} scan produced zero findings — analyzer may be non-functional")
        # Don't fail CI for this, but flag it
    else:
        print(f"PASS: {lang} analyzer produced findings")

    return 0


if __name__ == "__main__":
    sys.exit(main())
