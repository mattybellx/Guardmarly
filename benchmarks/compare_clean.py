"""Like-for-like precision and throughput: Guardmarly vs Semgrep vs Bandit.

Runs all three over the identical Python-standard-library sample and reports
findings per kLOC plus wall-clock throughput.  This is the measurement that
decides the precision claim: the labelled corpus only shows whether canonically
vulnerable/safe patterns are believed, whereas the standard library shows what
happens on 190 kLOC of code a reviewer considers clean.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import sysconfig
import time

REPO = pathlib.Path(__file__).resolve().parent.parent
RESULTS = REPO / "benchmarks" / "results"
PY = str(REPO / ".venv" / "Scripts" / "python.exe")
SEMGREP = os.environ.get(
    "SEMGREP_EXE", r"C:\Users\matth\OneDrive\Desktop\X\.venv\Scripts\semgrep.exe")
BANDIT = os.environ.get(
    "BANDIT_EXE", r"C:\Users\matth\OneDrive\Desktop\X\.venv\Scripts\bandit.exe")
SAMPLE = RESULTS / "_stdlib_sample"
FILES = int(os.environ.get("GM_BENCH_STDLIB_FILES", "120"))

SKIP = {"test", "tests", "idlelib", "lib2to3", "tkinter", "site-packages",
        "ensurepip", "distutils", "venv", "__pycache__"}


def build_sample() -> tuple[int, int]:
    if SAMPLE.exists():
        shutil.rmtree(SAMPLE, ignore_errors=True)
    root = pathlib.Path(sysconfig.get_paths()["stdlib"])
    files = []
    for p in root.rglob("*.py"):
        if any(part in SKIP for part in p.relative_to(root).parts[:-1]):
            continue
        files.append(p)
    files.sort(key=lambda p: (-p.stat().st_size, p.as_posix()))
    loc = 0
    for p in files[:FILES]:
        dest = SAMPLE / p.relative_to(root)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, dest)
        loc += len(p.read_text(encoding="utf-8", errors="replace").splitlines())
    return len(files[:FILES]), loc


def timed(cmd: list[str], env: dict | None = None, timeout: int = 3600) -> tuple[float, int, int]:
    """Return (seconds, returncode, stdout_len)."""
    start = time.perf_counter()
    proc = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(REPO), stdin=subprocess.DEVNULL, timeout=timeout, env=env,
    )
    return time.perf_counter() - start, proc.returncode, len(proc.stdout or "")


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    n_files, loc = build_sample()
    kloc = loc / 1000.0
    print(f"sample: {n_files} files, {loc:,} LOC\n")
    rows = []

    # ── Guardmarly ──────────────────────────────────────────────────────
    out = RESULTS / "_cmp_gm.json"
    out.unlink(missing_ok=True)
    secs, _rc, _ = timed([
        PY, "-m", "guardmarly.cli", str(SAMPLE), "--format", "json",
        "--output", str(out), "--fail-on", "never", "--no-colour"])
    report = json.loads(out.read_text(encoding="utf-8"))
    gm_total = report["summary"]["total_findings"]
    gm_high = report["summary"]["critical"] + report["summary"]["high"]
    rows.append(("Guardmarly", gm_total, gm_high, secs))

    # ── Semgrep ─────────────────────────────────────────────────────────
    if pathlib.Path(SEMGREP).exists():
        sg = RESULTS / "_cmp_semgrep.json"
        sg.unlink(missing_ok=True)
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
        secs, _rc, _ = timed([
            SEMGREP, "scan",
            "--config", os.environ.get("GM_SEMGREP_CONFIG", "p/default"),
            "--json", "--quiet", "--no-git-ignore", "--metrics", "off",
            "-o", str(sg), str(SAMPLE)], env=env)
        try:
            data = json.loads(sg.read_text(encoding="utf-8"))
            results = data.get("results", [])
            sev = {"ERROR": 0, "WARNING": 0, "INFO": 0}
            for r in results:
                sev[r.get("extra", {}).get("severity", "INFO")] = \
                    sev.get(r.get("extra", {}).get("severity", "INFO"), 0) + 1
            rows.append(("Semgrep p/default", len(results),
                         sev.get("ERROR", 0) + sev.get("WARNING", 0), secs))
        except Exception as exc:  # noqa: BLE001
            print(f"semgrep: {type(exc).__name__} — {exc}")
    else:
        print("semgrep not found")

    # ── Bandit ──────────────────────────────────────────────────────────
    if pathlib.Path(BANDIT).exists():
        bt = RESULTS / "_cmp_bandit.json"
        bt.unlink(missing_ok=True)
        secs, _rc, _ = timed([
            BANDIT, "-r", str(SAMPLE), "-f", "json", "-o", str(bt), "-q"])
        try:
            results = json.loads(bt.read_text(encoding="utf-8")).get("results", [])
            high = sum(1 for r in results
                       if r.get("issue_severity", "").upper() in ("HIGH", "MEDIUM"))
            rows.append(("Bandit", len(results), high, secs))
        except Exception as exc:  # noqa: BLE001
            print(f"bandit: {type(exc).__name__} — {exc}")

    print(f"{'tool':20s} {'findings':>9s} {'per kLOC':>9s} {'HIGH+':>7s} "
          f"{'HIGH+/kLOC':>11s} {'wall':>8s} {'LOC/s':>8s}")
    for name, total, high, secs in rows:
        print(f"{name:20s} {total:9d} {total / kloc:9.2f} {high:7d} "
              f"{high / kloc:11.2f} {secs:7.1f}s {loc / secs:8.0f}")

    payload = {
        "corpus": "python_stdlib_sample",
        "files": n_files,
        "loc": loc,
        "tools": [
            {"name": n, "findings": t, "high_plus": h, "wall_seconds": round(s, 2),
             "findings_per_kloc": round(t / kloc, 3),
             "high_plus_per_kloc": round(h / kloc, 3),
             "loc_per_second": round(loc / s, 1)}
            for n, t, h, s in rows
        ],
    }
    (RESULTS / "clean_comparison.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print("\n-> benchmarks/results/clean_comparison.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
