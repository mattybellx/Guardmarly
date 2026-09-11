"""Where does the parallel scan lose a finding? Compare per-file CWE sets."""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
PY = str(REPO / ".venv" / "Scripts" / "python.exe")
RESULTS = REPO / "benchmarks" / "results"
TARGET = "benchmarks/corpus"

# Candidate filter stages to bisect: default, then progressively disabled.
VARIANTS = [
    ("default", []),
    ("all-findings", ["--all-findings"]),
    ("no-triage", ["--no-triage"]),
    ("raw", ["--no-triage", "--all-findings", "--min-confidence", "0.0"]),
]
RUNS = int(sys.argv[1]) if len(sys.argv) > 1 else 3


def fingerprint(report: dict) -> dict[str, tuple]:
    out: dict[str, tuple] = {}
    for res in report["results"]:
        name = pathlib.Path(res["file"]).name
        out[name] = tuple(sorted(
            (f.get("rule_id"), f.get("cwe"), f.get("line")) for f in res.get("findings", [])
        ))
    return out


for label, extra in VARIANTS:
    prints = []
    for i in range(RUNS):
        out = RESULTS / f"_bisect_{label}_{i}.json"
        out.unlink(missing_ok=True)
        subprocess.run(
            [PY, "-m", "guardmarly.cli", TARGET, "--format", "json",
             "--output", str(out), "--fail-on", "never", "--no-colour", *extra],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            cwd=str(REPO), stdin=subprocess.DEVNULL, timeout=1800,
        )
        prints.append(fingerprint(json.loads(out.read_text(encoding="utf-8"))))

    base = prints[0]
    diffs = []
    for i, fp in enumerate(prints[1:], start=1):
        for name in sorted(set(base) | set(fp)):
            if base.get(name) != fp.get(name):
                diffs.append(f"{name}: run0={base.get(name)} run{i}={fp.get(name)}")
    status = "stable" if not diffs else f"UNSTABLE ({len(diffs)})"
    print(f"{label:14s} {status}")
    for d in diffs[:4]:
        print(f"    {d}")
