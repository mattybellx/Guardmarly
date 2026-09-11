"""Diagnostic: what are the noisy regex-fallback rules actually matching?

Scans a stable sample of the Python standard library and, for each rule,
prints the triggering source line so a human can judge true vs false positive.
"""
from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys
import sysconfig
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
PY = str(REPO / ".venv" / "Scripts" / "python.exe")
SAMPLE = REPO / "benchmarks" / "results" / "_stdlib_sample"
OUT = REPO / "benchmarks" / "results" / "_stdlib_scan.json"

SKIP = {"test", "tests", "idlelib", "lib2to3", "tkinter", "site-packages",
        "ensurepip", "distutils", "venv", "__pycache__"}


def build_sample(limit: int = 120) -> None:
    if SAMPLE.exists():
        shutil.rmtree(SAMPLE, ignore_errors=True)
    root = pathlib.Path(sysconfig.get_paths()["stdlib"])
    files = []
    for p in root.rglob("*.py"):
        if any(part in SKIP for part in p.relative_to(root).parts[:-1]):
            continue
        files.append(p)
    files.sort(key=lambda p: (-p.stat().st_size, p.as_posix()))
    for p in files[:limit]:
        dest = SAMPLE / p.relative_to(root)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, dest)


def main() -> int:
    if "--keep" not in sys.argv:
        build_sample()
    OUT.unlink(missing_ok=True)
    subprocess.run(
        [PY, "-m", "guardmarly.cli", str(SAMPLE), "--format", "json",
         "--output", str(OUT), "--fail-on", "never", "--no-colour"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(REPO), stdin=subprocess.DEVNULL, timeout=1800,
    )
    d = json.loads(OUT.read_text(encoding="utf-8"))
    print(f"scanned {d['files_scanned']} files, {d['summary']['total_findings']} findings, "
          f"{d['summary']['critical'] + d['summary']['high']} HIGH+")

    # bucket findings by rule, remembering the triggering line
    buckets: dict[str, list[tuple[str, int, str]]] = {}
    for res in d["results"]:
        src = pathlib.Path(res["file"])
        try:
            lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            lines = []
        for f in res.get("findings", []):
            if f.get("severity") not in ("critical", "high"):
                continue
            ln = f.get("line") or 0
            text = lines[ln - 1].strip() if 0 < ln <= len(lines) else ""
            buckets.setdefault(f.get("rule_id", "?"), []).append(
                (src.name, ln, text[:110]))

    for rule, items in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
        print(f"\n=== {rule}  ({len(items)} HIGH+) ===")
        for name, ln, text in items[:8]:
            print(f"   {name}:{ln}  {text}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
