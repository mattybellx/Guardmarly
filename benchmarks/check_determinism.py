"""Is the scan deterministic? Run the identical command N times and compare."""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
PY = str(REPO / ".venv" / "Scripts" / "python.exe")
RESULTS = REPO / "benchmarks" / "results"
TARGET = "benchmarks/corpus"

RUNS = int(sys.argv[1]) if len(sys.argv) > 1 else 3
EXTRA = sys.argv[2:] if len(sys.argv) > 2 else []

fingerprints = []
for i in range(RUNS):
    out = RESULTS / f"_det_{i}.json"
    out.unlink(missing_ok=True)
    subprocess.run(
        [PY, "-m", "guardmarly.cli", TARGET, "--format", "json", "--output", str(out),
         "--fail-on", "never", "--no-colour", *EXTRA],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(REPO), stdin=subprocess.DEVNULL, timeout=1800,
    )
    d = json.loads(out.read_text(encoding="utf-8"))
    per_file = {}
    for res in d["results"]:
        name = pathlib.Path(res["file"]).name
        per_file[name] = sorted(
            (f.get("rule_id"), f.get("cwe")) for f in res.get("findings", []))
    fingerprints.append(per_file)
    print(f"run {i}: total={d['summary']['total_findings']:4d} "
          f"crit={d['summary']['critical']:3d} high={d['summary']['high']:3d}")

base = fingerprints[0]
print(f"\n{'deterministic' if all(f == base for f in fingerprints) else 'NONDETERMINISTIC'}"
      f" across {RUNS} runs{(' with ' + ' '.join(EXTRA)) if EXTRA else ''}")
for i, fp in enumerate(fingerprints[1:], start=1):
    for name in sorted(set(base) | set(fp)):
        a, b = base.get(name, []), fp.get(name, [])
        if a != b:
            only_first = [x for x in a if x not in b]
            only_this = [x for x in b if x not in a]
            print(f"   run0 vs run{i}: {name}\n      only-run0={only_first}\n      only-run{i}={only_this}")
