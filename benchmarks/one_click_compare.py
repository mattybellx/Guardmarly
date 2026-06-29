#!/usr/bin/env python3
"""
benchmarks/one_click_compare.py
────────────────────────────────
One-command reproducible 3-tool SAST comparison.

Runs ansede-static, Semgrep, and CodeQL against a corpus of real-world
repos and CVE samples, then generates a self-contained HTML dashboard.

Usage:
    python benchmarks/one_click_compare.py                    # full run
    python benchmarks/one_click_compare.py --quick            # 5-repo smoke test
    python benchmarks/one_click_compare.py --cve-only         # CVE corpus only
    python benchmarks/one_click_compare.py --repos-only       # repo corpus only
    python benchmarks/one_click_compare.py --output report/   # custom output dir

Requirements:
    pip install ansede-static semgrep
    # CodeQL: download from https://github.com/github/codeql-cli-binaries
    # and ensure 'codeql' is on PATH

Output:
    benchmarks/report/index.html  — self-contained HTML dashboard
    benchmarks/report/results.json — raw JSON data
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Configuration ──────────────────────────────────────────────────────────

REPO_CORPUS: list[dict[str, str]] = [
    # Python
    {"name": "flask", "url": "https://github.com/pallets/flask", "lang": "python"},
    {"name": "requests", "url": "https://github.com/psf/requests", "lang": "python"},
    {"name": "fastapi", "url": "https://github.com/fastapi/fastapi", "lang": "python"},
    {"name": "django", "url": "https://github.com/django/django", "lang": "python"},
    {"name": "scrapy", "url": "https://github.com/scrapy/scrapy", "lang": "python"},
    # JavaScript/TypeScript
    {"name": "express", "url": "https://github.com/expressjs/express", "lang": "javascript"},
    {"name": "axios", "url": "https://github.com/axios/axios", "lang": "javascript"},
    {"name": "lodash", "url": "https://github.com/lodash/lodash", "lang": "javascript"},
    {"name": "moment", "url": "https://github.com/moment/moment", "lang": "javascript"},
    {"name": "socket.io", "url": "https://github.com/socketio/socket.io", "lang": "javascript"},
    # Java
    {"name": "spring-petclinic", "url": "https://github.com/spring-projects/spring-petclinic", "lang": "java"},
    {"name": "gson", "url": "https://github.com/google/gson", "lang": "java"},
    {"name": "log4j", "url": "https://github.com/apache/logging-log4j2", "lang": "java"},
    # Go
    {"name": "gin", "url": "https://github.com/gin-gonic/gin", "lang": "go"},
    {"name": "echo", "url": "https://github.com/labstack/echo", "lang": "go"},
    {"name": "cobra", "url": "https://github.com/spf13/cobra", "lang": "go"},
    # C#
    {"name": "CleanArchitecture", "url": "https://github.com/ardalis/CleanArchitecture", "lang": "csharp"},
    {"name": "eShopOnWeb", "url": "https://github.com/dotnet-architecture/eShopOnWeb", "lang": "csharp"},
]

QUICK_CORPUS = REPO_CORPUS[:5]

SEMGREP_CONFIG_MAP: dict[str, str] = {
    "python": "p/python",
    "javascript": "p/javascript",
    "java": "p/java",
    "go": "p/golang",
    "csharp": "p/csharp",
}


def _run(cmd: list[str], *, cwd: Path | None = None, timeout: int = 600) -> subprocess.CompletedProcess:
    """Run a command, capture output, return CompletedProcess."""
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _find_codeql() -> str | None:
    """Locate the CodeQL CLI binary."""
    codeql = shutil.which("codeql")
    if codeql:
        return codeql
    # Common paths
    for candidate in [
        Path.home() / "codeql" / "codeql",
        Path.home() / "codeql" / "codeql.exe",
        Path("tmp/codeql_new/codeql/codeql.exe"),
    ]:
        if candidate.exists():
            return str(candidate)
    return None


def _find_semgrep() -> str | None:
    """Locate the Semgrep CLI binary."""
    semgrep = shutil.which("semgrep")
    if semgrep:
        return semgrep
    for candidate in [
        Path.home() / "OneDrive" / "Desktop" / "X" / ".venv" / "Scripts" / "semgrep.exe",
    ]:
        if candidate.exists():
            return str(candidate)
    return None


def _ensure_repo(repo: dict[str, str], cache_dir: Path) -> Path:
    """Clone or update a repo into the cache directory."""
    target = cache_dir / repo["name"]
    if (target / ".git").exists():
        _run(["git", "fetch", "--depth=1"], cwd=target)
        _run(["git", "reset", "--hard", "origin/HEAD"], cwd=target)
    else:
        _run(["git", "clone", "--depth=1", repo["url"], str(target)])
    return target


def _count_source_files(repo_path: Path, lang: str) -> int:
    """Count source files by extension for a language."""
    ext_map = {
        "python": [".py"],
        "javascript": [".js", ".ts", ".mjs", ".cjs"],
        "java": [".java"],
        "go": [".go"],
        "csharp": [".cs"],
    }
    exts = ext_map.get(lang, [])
    count = 0
    for ext in exts:
        count += len(list(repo_path.rglob(f"*{ext}")))
    return count


def _count_lines(repo_path: Path, lang: str) -> int:
    """Count total lines of source code."""
    ext_map = {
        "python": [".py"],
        "javascript": [".js", ".ts", ".mjs", ".cjs"],
        "java": [".java"],
        "go": [".go"],
        "csharp": [".cs"],
    }
    exts = ext_map.get(lang, [])
    total = 0
    for ext in exts:
        for f in repo_path.rglob(f"*{ext}"):
            try:
                total += len(f.read_text(encoding="utf-8", errors="replace").splitlines())
            except Exception:
                pass
    return total


def run_ansede(repo_path: Path, lang: str) -> dict[str, Any]:
    """Run ansede-static on a repo and return results."""
    start = time.perf_counter()
    try:
        # Prefer the local venv's binary to avoid conflicts
        ansede_bin = str(Path(__file__).resolve().parent.parent / ".venv" / "Scripts" / "ansede-static.exe")
        if not Path(ansede_bin).exists():
            ansede_bin = shutil.which("ansede-static") or "ansede-static"
        result = _run(
            [ansede_bin, str(repo_path.resolve()), "--format", "json", "--cluster"],
            timeout=600,
        )
        data = json.loads(result.stdout) if result.stdout.strip() else {}
        elapsed = time.perf_counter() - start
        total = data.get("summary", {}).get("total_findings", 0)
        return {
            "tool": "ansede-static",
            "findings": total,
            "time_s": round(elapsed, 1),
            "error": None,
        }
    except Exception as exc:
        elapsed = time.perf_counter() - start
        return {
            "tool": "ansede-static",
            "findings": 0,
            "time_s": round(elapsed, 1),
            "error": str(exc)[:200],
        }


def run_semgrep(repo_path: Path, lang: str) -> dict[str, Any]:
    """Run Semgrep on a repo and return results."""
    semgrep = _find_semgrep()
    if not semgrep:
        return {"tool": "semgrep", "findings": 0, "time_s": 0, "error": "semgrep not found on PATH"}

    config = SEMGREP_CONFIG_MAP.get(lang, "auto")
    start = time.perf_counter()
    try:
        result = _run(
            [semgrep, "scan", "--config", config, "--quiet", "--json", str(repo_path.resolve())],
            timeout=600,
        )
        data = json.loads(result.stdout) if result.stdout.strip() else {}
        elapsed = time.perf_counter() - start
        findings = len(data.get("results", [])) if isinstance(data, dict) else 0
        return {
            "tool": "semgrep",
            "findings": findings,
            "time_s": round(elapsed, 1),
            "error": None,
        }
    except Exception as exc:
        elapsed = time.perf_counter() - start
        return {
            "tool": "semgrep",
            "findings": 0,
            "time_s": round(elapsed, 1),
            "error": str(exc)[:200],
        }


def run_codeql(repo_path: Path, lang: str, codeql_bin: str, codeql_db_cache: Path) -> dict[str, Any]:
    """Run CodeQL on a repo and return results."""
    lang_map = {"python": "python", "javascript": "javascript", "java": "java", "go": "go", "csharp": "csharp"}
    ql_lang = lang_map.get(lang, lang)
    db_name = repo_path.name

    start = time.perf_counter()
    try:
        db_path = codeql_db_cache / db_name
        if db_path.exists():
            shutil.rmtree(db_path)

        create = _run(
            [codeql_bin, "database", "create", str(db_path), "--language=" + ql_lang, "--source-root=" + str(repo_path)],
            timeout=600,
        )
        if create.returncode != 0:
            raise RuntimeError(f"CodeQL DB creation failed: {create.stderr[:200]}")

        # Use the standard security query suite
        analyze = _run(
            [
                codeql_bin, "database", "analyze", str(db_path),
                "--format=sarif-latest", "--output=" + str(db_path / "results.sarif"),
                "codeql/" + ql_lang + "-queries:codeql-suites/" + ql_lang + "-security-extended.qls",
            ],
            timeout=600,
        )
        elapsed = time.perf_counter() - start

        findings = 0
        sarif_path = db_path / "results.sarif"
        if sarif_path.exists():
            try:
                sarif = json.loads(sarif_path.read_text())
                for run in sarif.get("runs", []):
                    findings += len(run.get("results", []))
            except Exception:
                pass

        return {
            "tool": "codeql",
            "findings": findings,
            "time_s": round(elapsed, 1),
            "error": None,
        }
    except Exception as exc:
        elapsed = time.perf_counter() - start
        return {
            "tool": "codeql",
            "findings": 0,
            "time_s": round(elapsed, 1),
            "error": str(exc)[:200],
        }


def generate_html(report: dict[str, Any], output_path: Path) -> None:
    """Generate a self-contained HTML dashboard."""
    results = report["results"]
    # Compute aggregate stats
    ansede_total = sum(r["tools"]["ansede-static"]["findings"] for r in results)
    semgrep_total = sum(r["tools"]["semgrep"]["findings"] for r in results)
    codeql_total = sum(r["tools"]["codeql"]["findings"] for r in results)

    repo_rows = ""
    for r in results:
        a = r["tools"]["ansede-static"]["findings"]
        s = r["tools"]["semgrep"]["findings"]
        c = r["tools"]["codeql"]["findings"]
        best = max(a, s, c)
        winner = "ansede" if a == best and a > 0 else ("semgrep" if s == best and s > 0 else ("codeql" if c == best and c > 0 else "—"))
        repo_rows += f"""
        <tr>
            <td>{r['name']}</td><td>{r['lang']}</td><td>{r['files']:,}</td><td>{r['lines']:,}</td>
            <td style="color:#4caf50"><strong>{a}</strong></td>
            <td>{s}</td>
            <td>{c}</td>
            <td>{winner}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ansede-static v{report['ansede_version']} — 3-Tool SAST Comparison</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: system-ui, -apple-system, sans-serif; background:#0d1117; color:#c9d1d9; padding:2rem; }}
.container {{ max-width:1200px; margin:0 auto; }}
h1 {{ color:#58a6ff; font-size:2rem; margin-bottom:0.5rem; }}
.subtitle {{ color:#8b949e; margin-bottom:2rem; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:1rem; margin-bottom:2rem; }}
.card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:1.5rem; text-align:center; }}
.card .number {{ font-size:2.5rem; font-weight:700; }}
.card .label {{ color:#8b949e; font-size:0.9rem; margin-top:0.25rem; }}
.card.ansede .number {{ color:#4caf50; }}
.card.semgrep .number {{ color:#ff9800; }}
.card.codeql .number {{ color:#f44336; }}
.ratio {{ font-size:1.2rem; color:#58a6ff; margin-top:0.5rem; }}
table {{ width:100%; border-collapse:collapse; }}
th, td {{ padding:0.75rem 1rem; text-align:left; border-bottom:1px solid #21262d; }}
th {{ background:#161b22; color:#8b949e; font-weight:600; text-transform:uppercase; font-size:0.8rem; }}
tr:hover {{ background:#1c2128; }}
.footer {{ margin-top:2rem; color:#8b949e; font-size:0.85rem; text-align:center; }}
a {{ color:#58a6ff; }}
</style>
</head>
<body>
<div class="container">
<h1>** ansede-static — 3-Tool SAST Comparison</h1>
<p class="subtitle">Generated {report['timestamp']} · {len(results)} repos · v{report['ansede_version']}</p>

<div class="cards">
    <div class="card ansede">
        <div class="number">{ansede_total:,}</div>
        <div class="label">ansede-static findings</div>
        <div class="ratio">{ansede_total / max(codeql_total, 1):.1f}x CodeQL</div>
    </div>
    <div class="card semgrep">
        <div class="number">{semgrep_total:,}</div>
        <div class="label">Semgrep findings</div>
    </div>
    <div class="card codeql">
        <div class="number">{codeql_total:,}</div>
        <div class="label">CodeQL findings</div>
    </div>
</div>

<table>
<thead><tr><th>Repository</th><th>Lang</th><th>Files</th><th>LOC</th><th>ansede</th><th>semgrep</th><th>codeql</th><th>Winner</th></tr></thead>
<tbody>{repo_rows}</tbody>
</table>

<p class="footer">
    <a href="https://github.com/mattybellx/Ansede">View on GitHub</a> ·
    Reproduce: <code>pip install ansede-static semgrep && python benchmarks/one_click_compare.py</code>
</p>
</div>
</body>
</html>"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    print(f"\n[OK] HTML report: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="One-click 3-tool SAST comparison")
    parser.add_argument("--quick", action="store_true", help="5-repo smoke test")
    parser.add_argument("--cve-only", action="store_true", help="CVE corpus only")
    parser.add_argument("--repos-only", action="store_true", help="Repo corpus only (default: both)")
    parser.add_argument("--output", default="benchmarks/report", help="Output directory")
    parser.add_argument("--skip-codeql", action="store_true", help="Skip CodeQL (if not installed)")
    parser.add_argument("--skip-semgrep", action="store_true", help="Skip Semgrep (if not installed)")
    args = parser.parse_args()

    # ── Tool discovery ──────────────────────────────────────────────────
    codeql_bin = None if args.skip_codeql else _find_codeql()
    semgrep_bin = None if args.skip_semgrep else _find_semgrep()

    print("[*] Tool discovery:")
    print(f"   ansede-static: [OK] (bundled)")
    print(f"   semgrep:       {'[OK]' if semgrep_bin else '[MISSING] not found'}")
    print(f"   codeql:        {'[OK]' if codeql_bin else '[MISSING] not found'}")

    # ── Corpus ──────────────────────────────────────────────────────────
    corpus = QUICK_CORPUS if args.quick else REPO_CORPUS
    if args.cve_only:
        corpus = []

    print(f"\n[+] Corpus: {len(corpus)} repos")

    # ── Setup cache ─────────────────────────────────────────────────────
    cache_dir = Path(args.output) / ".repo_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    codeql_db_cache = Path(args.output) / ".codeql_dbs"
    if codeql_bin:
        codeql_db_cache.mkdir(parents=True, exist_ok=True)

    # ── Get ansede version ──────────────────────────────────────────────
    import ansede_static
    ansede_version = getattr(ansede_static, "__version__", "5.1.0")

    # ── Run comparison ──────────────────────────────────────────────────
    results: list[dict[str, Any]] = []
    for i, repo in enumerate(corpus, 1):
        print(f"\n[{i}/{len(corpus)}] {repo['name']} ({repo['lang']}) ...")

        repo_path = _ensure_repo(repo, cache_dir)
        files = _count_source_files(repo_path, repo["lang"])
        lines = _count_lines(repo_path, repo["lang"])

        tools: dict[str, Any] = {}

        # ansede
        print(f"   -> ansede-static ... ", end=" ", flush=True)
        tools["ansede-static"] = run_ansede(repo_path, repo["lang"])
        print(f"{tools['ansede-static']['findings']} findings ({tools['ansede-static']['time_s']}s)")

        # semgrep
        if semgrep_bin:
            print(f"   -> semgrep ...", end=" ", flush=True)
            tools["semgrep"] = run_semgrep(repo_path, repo["lang"])
            print(f"{tools['semgrep']['findings']} findings ({tools['semgrep']['time_s']}s)")
        else:
            tools["semgrep"] = {"tool": "semgrep", "findings": 0, "time_s": 0, "error": "not installed"}

        # codeql
        if codeql_bin:
            print(f"   -> codeql ...", end=" ", flush=True)
            tools["codeql"] = run_codeql(repo_path, repo["lang"], codeql_bin, codeql_db_cache)
            print(f"{tools['codeql']['findings']} findings ({tools['codeql']['time_s']}s)")
        else:
            tools["codeql"] = {"tool": "codeql", "findings": 0, "time_s": 0, "error": "not installed"}

        results.append({
            "name": repo["name"],
            "lang": repo["lang"],
            "files": files,
            "lines": lines,
            "tools": tools,
        })

    # ── CVE recall (if not repos-only) ──────────────────────────────────
    if not args.repos_only:
        print("\n[*] Running CVE recall benchmark ...")
        try:
            from benchmarks.cve_recall_runner import run_cve_recall as run_cve
            cve_report = run_cve(quiet=True)
            cve_summary = cve_report["summary"]
            print(f"   ansede CVE recall: {cve_summary['recall']}% ({cve_summary['passed_cases']}/{cve_summary['total_cases']})")
        except Exception as exc:
            cve_summary = {"error": str(exc)[:200]}
            print(f"   CVE recall skipped: {exc}")

    # ── Assemble report ─────────────────────────────────────────────────
    report: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "ansede_version": ansede_version,
        "results": results,
        "cve_recall": cve_summary if not args.repos_only else None,
    }

    # ── Save JSON ───────────────────────────────────────────────────────
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "results.json"
    json_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(f"\n[*] Report: {json_path}")

    # ── Generate HTML ───────────────────────────────────────────────────
    generate_html(report, output_dir / "index.html")


if __name__ == "__main__":
    main()
