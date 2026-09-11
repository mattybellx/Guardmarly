"""Compact summary of all benchmark results."""
from __future__ import annotations

import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
RESULTS = HERE / "results"


def load(name: str) -> dict | None:
    p = RESULTS / f"{name}.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


lab = load("labelled")
if lab:
    print(f"LABELLED  recall {lab['recall']:.1%} ({lab['detected']}/{lab['positives']}) | "
          f"FP file rate {lab['false_positive_file_rate']:.1%} "
          f"({lab['negative_files_flagged']}/{lab['negative_files']})")
    print("  misses:", [m["file"] for m in lab["misses"]])
    print("  FPs   :", [n["file"] for n in lab["negatives_with_findings"]])

cl = load("clean")
if cl:
    for c in cl["corpora"]:
        print(f"CLEAN  {c['corpus']:20s} {c['loc']:>7} LOC  {c['total']:>4} findings  "
              f"{c['high_plus']:>4} HIGH+  {c['high_plus_per_kloc']:.2f}/kLOC")

th = load("throughput")
if th:
    print(f"THROUGHPUT {th['loc']} LOC in {th['wall_seconds']}s = "
          f"{th['loc_per_second']} LOC/s")

h = load("headtohead")
if h:
    g = h["guardmarly"]
    s = h["semgrep_oss_p_ci"]
    b = h["bandit_1_9_4"]

    def row(tag: str, x: dict) -> str:
        return (f"{tag:24s} in-scope={x['positives_in_scope']:3d} "
                f"detected={x['detected']:3d} recall={x['recall']:6.1%} "
                f"clean-flagged={x['negative_files_flagged']}/{x['negatives_in_scope']}")

    print("HEAD-TO-HEAD (identical corpus directory, same machine)")
    print("  " + row("Guardmarly (5 langs)", g["all_languages"]))
    print("  " + row("Semgrep (p/default)", s["all_languages"])
          + f" | available={s['available']} | findings={s['total_findings']}")
    print("  " + row("Bandit (python only)", b["python_only"])
          + f" | findings={b['total_findings']}")
    gm_missed = set(g["all_languages"]["missed_files"])
    sg_missed = set(s["all_languages"]["missed_files"])
    print(f"  guardmarly missed: {sorted(gm_missed)}")
    print(f"  semgrep missed:    {len(sg_missed)} fixtures")
    print(f"  detected by guardmarly, missed by semgrep: "
          f"{len(sg_missed - gm_missed)}")
    print(f"  detected by semgrep, missed by guardmarly: "
          f"{sorted(sg_missed - gm_missed and gm_missed - sg_missed)}")

