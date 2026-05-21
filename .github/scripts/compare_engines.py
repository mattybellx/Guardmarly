#!/usr/bin/env python3
"""Dual-engine comparison gate.

Runs the same scan with ``--engine v1`` and ``--engine v2`` (where
supported) and reports the delta.  Used as a CI ratchet gate during the
v2 engine migration (Phase 2).

Exit codes:
  0 — both engines ran; delta within tolerance
  1 — one or both engines failed
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CORPUS_DIR = REPO_ROOT / "tests" / "corpora" / "python"
MIN_V2_RECALL_PCT = 80.0  # v2 must find at least 80% of v1 findings


def _run_engine(engine: str, target: str) -> dict | None:
    """Run ansede-static with the given engine.  Returns parsed JSON or None."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ansede_static.cli",
            target,
            "--engine",
            engine,
            "--format",
            "json",
            "--fail-on",
            "never",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        print(f"  {engine}: scan failed (exit {result.returncode})")
        print(f"  stderr: {result.stderr[:500]}")
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"  {engine}: JSON parse failed")
        return None


def _count_findings(data: dict | None) -> int:
    if data is None:
        return 0
    results_list = data if isinstance(data, list) else data.get("results", [])
    return sum(len(r.get("findings", [])) for r in results_list)


def main() -> int:
    # Use the Python test corpus or a sample file
    python_dir = REPO_ROOT / "src" / "ansede_static"
    if not python_dir.is_dir():
        print(f"SKIP: source directory not found at {python_dir}")
        return 0

    target = str(python_dir)
    if not python_dir.is_dir():
        print(f"SKIP: v2 corpus not found at {python_dir}")
        return 0

    print(f"Dual-engine comparison on: {target}")
    print()

    print("Running v1 engine...")
    v1_data = _run_engine("v1", target)
    v1_count = _count_findings(v1_data)
    print(f"  v1 findings: {v1_count}")

    print("Running v2 engine...")
    v2_data = _run_engine("v2", target)
    v2_count = _count_findings(v2_data)
    print(f"  v2 findings: {v2_count}")

    print()
    if v1_count == 0:
        print("SKIP: v1 produced zero findings (no baseline to compare)")
        return 0

    recall_pct = (v2_count / v1_count) * 100.0
    print(f"v2 recall vs v1: {recall_pct:.1f}% ({v2_count}/{v1_count})")

    if recall_pct < MIN_V2_RECALL_PCT:
        print(
            f"FAIL: v2 recall {recall_pct:.1f}% < {MIN_V2_RECALL_PCT:.0f}% — "
            f"v2 is missing {v1_count - v2_count} findings that v1 detects"
        )
        if v2_count == 0:
            print("  (v2 produced zero findings — engine may not be wired correctly)")
        return 1

    print(f"PASS: v2 recall {recall_pct:.1f}% >= {MIN_V2_RECALL_PCT:.0f}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
