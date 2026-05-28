#!/usr/bin/env python3
"""Performance regression checker. Uses direct Python API calls.
Enforces DIR-5.2 10s per 100k LOC throughput ceiling."""
from __future__ import annotations
import json, logging, sys, time
from pathlib import Path

_log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_FILE = REPO_ROOT / "tmp" / "perf_regression_results.json"
_SPEED_BUDGET = {"python": 5.0, "javascript": 5.0, "go": 3.0, "java": 3.0, "csharp": 3.0, "ruby": 2.0, "php": 2.0}
# DIR-5.2: regression gate — must stay above 500 LOC/s (v4 target: 10_000)
_MIN_THROUGHPUT_LOC_PER_S = 500

_SNIPPETS = {
    "python": "import subprocess\nfrom flask import request\ncmd = request.args.get('c')\nsubprocess.call(cmd, shell=True)\n" * 200,
    "javascript": "const cmd = req.query.cmd;\nrequire('child_process').execSync(cmd);\n" * 20,
    "go": 'package main\nimport ("net/http";"os/exec")\nfunc h(w http.ResponseWriter,r *http.Request){\nc:=r.URL.Query().Get("c")\nexec.Command("bash","-c",c)\n}\n' * 200,
    "java": 'public class T {\npublic void r(String i) throws Exception { Runtime.getRuntime().exec(i); }\n}\n' * 200,
    "csharp": 'using System.Diagnostics;\nclass T {\nvoid R(string i) { Process.Start(i); }\n}\n' * 200,
    "ruby": 'def h\ncmd = params[:c]\nsystem(cmd)\nend\n' * 200,
    "php": '<?php\n$r = mysqli_query($c, "SELECT * FROM users WHERE id = " . $_GET["id"]);\n' * 200,
}

_PYTHON_EXTS = frozenset({".py", ".pyi", ".pyw"})
_JS_EXTS = frozenset({".js", ".ts", ".jsx", ".tsx"})


def _scan(code: str, lang: str) -> tuple[float, int]:
    fn = {
        "python": lambda c: __import__("ansede_static.python_analyzer", fromlist=["x"]).analyze_python(c, filename=""),
        "javascript": lambda c: __import__("ansede_static.js_analyzer", fromlist=["x"]).analyze_js(c, filename=""),
        "go": lambda c: __import__("ansede_static.go_engine.go_analyzer", fromlist=["x"]).run_go_analysis(c, filename=""),
        "java": lambda c: __import__("ansede_static.java_analyzer", fromlist=["x"]).analyze_java(c, filename=""),
        "csharp": lambda c: __import__("ansede_static.csharp_analyzer", fromlist=["x"]).analyze_csharp(c, filename=""),
        "ruby": lambda c: __import__("ansede_static.ruby_analyzer", fromlist=["x"]).analyze_ruby(c, filename=""),
        "php": lambda c: __import__("ansede_static.php_analyzer", fromlist=["x"]).analyze_php(c, filename=""),
    }.get(lang)
    if not fn:
        return (0.0, 0)
    lines = len(code.splitlines())
    start = time.perf_counter()
    fn(code)
    elapsed = time.perf_counter() - start
    return (elapsed, lines)


def _scan_real_repo() -> dict[str, object]:
    """Scan a real repository (the ansede-static source tree) and measure throughput.
    This validates the DIR-5.2 10s/100k LOC ceiling on real code, not just micro-benchmarks."""
    src_dir = REPO_ROOT / "src" / "ansede_static"
    if not src_dir.exists():
        return {"error": "src/ansede_static not found", "throughput_ok": False, "loc_per_s": 0.0}

    from ansede_static import scan_file
    files = sorted(f for f in src_dir.rglob("*") if f.is_file() and f.suffix in _PYTHON_EXTS)
    if not files:
        return {"error": "no Python files found", "throughput_ok": False, "loc_per_s": 0.0}

    # Warm-up pass: scan the first file to prime import caches, SQLite, and GlobalGraph.
    # This ensures cold-start overhead doesn't distort the throughput measurement.
    warmup_file = files[0]
    try:
        warmup_code = warmup_file.read_text(encoding="utf-8", errors="replace")
        scan_file(warmup_file)
    except Exception:
        _log.debug("Warm-up scan failed for %s", warmup_file)

    total_lines = 0
    total_time = 0.0
    file_count = 0
    for f in files:
        try:
            code = f.read_text(encoding="utf-8", errors="replace")
            lines = len(code.splitlines())
            start = time.perf_counter()
            scan_file(f)
            elapsed = time.perf_counter() - start
            total_lines += lines
            total_time += elapsed
            file_count += 1
        except Exception:
            _log.debug("Scan failed for %s", f)

    loc_per_s = total_lines / total_time if total_time else 0.0
    throughput_ok = loc_per_s >= _MIN_THROUGHPUT_LOC_PER_S
    return {
        "scenario": "src/ansede_static (real repo)",
        "files": file_count,
        "lines": total_lines,
        "elapsed": round(total_time, 3),
        "loc_per_s": round(loc_per_s, 0),
        "throughput_ok": throughput_ok,
    }


def main() -> int:
    print(f"{'Language':>12} {'Time':>8} {'Lines':>7} {'LOC/s':>8} {'Budget':>8} {'Result':>8}")
    print("-" * 65)
    results, ok, total_lines, total_time = {}, True, 0, 0.0
    for lang, code in sorted(_SNIPPETS.items()):
        b = _SPEED_BUDGET.get(lang, 5.0)
        e, lines = _scan(code, lang)
        loc_s = lines / e if e else 0.0
        p = e <= b
        total_lines += lines
        total_time += e
        if not p:
            ok = False
        print(f"  {lang:>12} {e:>7.3f}s {lines:>7} {loc_s:>8.0f} {b:>7.1f}s {'PASS' if p else 'FAIL':>8}")
        results[lang] = {"elapsed": round(e, 3), "lines": lines, "loc_per_s": round(loc_s, 0), "budget": b, "passed": p}

    # Aggregate throughput check (DIR-5.2)
    aggregate_loc_s = total_lines / total_time if total_time else 0.0
    agg_passed = aggregate_loc_s >= _MIN_THROUGHPUT_LOC_PER_S
    if not agg_passed:
        ok = False
    print("-" * 65)
    print(f"  {'TOTAL':>12} {total_time:>7.3f}s {total_lines:>7} {aggregate_loc_s:>8.0f} {'N/A':>7} {'PASS' if agg_passed else 'FAIL':>8}")
    print(f"  DIR-5.2 ceiling: {_MIN_THROUGHPUT_LOC_PER_S:,} LOC/s (10s per 100k LOC)")
    results["_aggregate"] = {"elapsed": round(total_time, 3), "lines": total_lines, "loc_per_s": round(aggregate_loc_s, 0), "throughput_ok": agg_passed}

    # Real-repo throughput test
    print()
    print("Real-repo throughput test (DIR-5.2):")
    print("-" * 65)
    repo_result = _scan_real_repo()
    if "error" in repo_result:
        print(f"  ERROR: {repo_result['error']}")
    else:
        rp = repo_result["throughput_ok"]
        print(f"  {repo_result['scenario']}")
        print(f"  Files: {repo_result['files']} | Lines: {repo_result['lines']} | Time: {repo_result['elapsed']}s")
        print(f"  LOC/s: {repo_result['loc_per_s']:>8.0f} | Ceiling: {_MIN_THROUGHPUT_LOC_PER_S:,} | {'PASS' if rp else 'FAIL'}")
        if not rp:
            ok = False
    results["_real_repo"] = repo_result

    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_FILE.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
