"""Criterion 2: the same tree must scan identically however the path is passed.

Absolute and relative invocation are both common (CI, IDEs, editor plugins all
differ), so a difference here means two users scanning the same code get two
different answers.  Also compares a trailing-separator and a ``./``-prefixed
form, which are equivalent on every platform.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
PY = str(REPO / ".venv" / "Scripts" / "python.exe")
RESULTS = REPO / "benchmarks" / "results"
TARGET = REPO / "benchmarks" / "corpus"


def fingerprint(target: str, tag: str, extra: list[str] | None = None) -> dict[str, tuple]:
    out = RESULTS / f"_pathind_{tag}.json"
    out.unlink(missing_ok=True)
    subprocess.run(
        [PY, "-m", "guardmarly.cli", target, "--format", "json", "--output", str(out),
         "--fail-on", "never", "--no-colour", *(extra or [])],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(REPO), stdin=subprocess.DEVNULL, timeout=1800,
    )
    report = json.loads(out.read_text(encoding="utf-8"))
    result: dict[str, tuple] = {}
    for res in report["results"]:
        name = pathlib.Path(res["file"]).name
        result[name] = tuple(sorted(
            (f.get("rule_id"), f.get("cwe"), f.get("line")) for f in res.get("findings", [])
        ))
    return result


FORMS = [
    ("absolute", str(TARGET)),
    ("relative", "benchmarks/corpus"),
    ("dot-slash", "./benchmarks/corpus"),
]

prints = {label: fingerprint(target, label) for label, target in FORMS}
base_label, base = FORMS[0][0], prints[FORMS[0][0]]

failures = 0
for label, _ in FORMS[1:]:
    other = prints[label]
    diffs = [n for n in sorted(set(base) | set(other)) if base.get(n) != other.get(n)]
    if diffs:
        failures += 1
        print(f"{base_label} vs {label}: {len(diffs)} file(s) differ")
        for name in diffs[:5]:
            print(f"    {name}\n      {base_label}={base.get(name)}")
            print(f"      {label}={other.get(name)}")
    else:
        print(f"{base_label} vs {label}: identical")

widths = {sum(len(v) for v in p.values()) for p in prints.values()}
print(f"\ntotal findings per form: {[sum(len(v) for v in p.values()) for p in prints.values()]}")
print("path-independent" if failures == 0 and len(widths) == 1 else "PATH-DEPENDENT")
sys.exit(0 if failures == 0 and len(widths) == 1 else 1)
