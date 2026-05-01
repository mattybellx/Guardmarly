from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


METRIC_KEYS = ("recall", "precision", "f1", "fp_rate")


def run_one(python_exe: str, cwd: Path, seed: int, n_files: int, timeout_seconds: int, offline: bool) -> dict[str, Any]:
    cmd = [
        python_exe,
        "-m",
        "benchmarks.web_wild_harness",
        "--n-files",
        str(n_files),
        "--seed",
        str(seed),
        "--quiet",
        "--json",
    ]
    if offline:
        cmd.append("--offline")
    started = time.perf_counter()
    completed = subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
        check=True,
    )
    elapsed = round(time.perf_counter() - started, 2)
    payload = json.loads(completed.stdout)
    summary = payload["summary"]
    summary["elapsed_seconds"] = elapsed
    return summary


def avg(rows: list[dict[str, Any]], side: str, key: str) -> float:
    return round(sum(float(r[side][key]) for r in rows) / len(rows), 2) if rows else 0.0


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare web_wild_harness metrics across baseline/current with progress and timeouts")
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--current", required=True, type=Path)
    parser.add_argument("--python", required=True, dest="python_exe")
    parser.add_argument("--seeds", nargs="+", required=True, type=int)
    parser.add_argument("--n-files", type=int, default=40)
    parser.add_argument("--timeout", type=int, default=240, help="Per harness run timeout in seconds")
    parser.add_argument("--offline", action="store_true", help="Use cached repos only to avoid network stalls")
    parser.add_argument("--output", type=Path, default=Path("web_wild_compare_results.json"))
    args = parser.parse_args()

    if not args.baseline.is_dir():
        print(f"ERROR: baseline missing: {args.baseline}", file=sys.stderr)
        return 2
    if not args.current.is_dir():
        print(f"ERROR: current missing: {args.current}", file=sys.stderr)
        return 2

    rows: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    total_runs = len(args.seeds) * 2
    run_index = 0

    for seed in args.seeds:
        row: dict[str, Any] = {"seed": seed}
        for side, cwd in (("baseline", args.baseline), ("current", args.current)):
            run_index += 1
            print(f"[{run_index}/{total_runs}] {side} seed={seed} ...", flush=True)
            try:
                row[side] = run_one(
                    python_exe=args.python_exe,
                    cwd=cwd,
                    seed=seed,
                    n_files=args.n_files,
                    timeout_seconds=args.timeout,
                    offline=args.offline,
                )
                s = row[side]
                print(
                    f"    done in {s['elapsed_seconds']:.2f}s :: "
                    f"R/P/F1/FP = {s['recall']:.2f}/{s['precision']:.2f}/{s['f1']:.2f}/{s['fp_rate']:.2f}",
                    flush=True,
                )
            except subprocess.TimeoutExpired as exc:
                failure = {"seed": seed, "side": side, "error": f"timeout after {args.timeout}s"}
                failures.append(failure)
                row[side] = failure
                print(f"    TIMEOUT after {args.timeout}s", flush=True)
            except subprocess.CalledProcessError as exc:
                failure = {
                    "seed": seed,
                    "side": side,
                    "error": f"exit code {exc.returncode}",
                    "stderr_tail": (exc.stderr or "")[-2000:],
                }
                failures.append(failure)
                row[side] = failure
                print(f"    ERROR exit code {exc.returncode}", flush=True)
        rows.append(row)
        partial = {"rows": rows, "failures": failures, "seeds": args.seeds}
        args.output.write_text(json.dumps(partial, indent=2), encoding="utf-8")

    summary = {
        "rows": rows,
        "failures": failures,
        "seeds": args.seeds,
        "averages": {},
    }

    complete_rows = [r for r in rows if all(isinstance(r.get(side), dict) and "recall" in r[side] for side in ("baseline", "current"))]
    for key in METRIC_KEYS:
        b = avg(complete_rows, "baseline", key)
        c = avg(complete_rows, "current", key)
        summary["averages"][key] = {
            "baseline": b,
            "current": c,
            "delta": round(c - b, 2),
        }

    args.output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("\nSummary averages:", flush=True)
    for key in METRIC_KEYS:
        item = summary["averages"].get(key, {"baseline": 0.0, "current": 0.0, "delta": 0.0})
        print(
            f"  {key}: {item['baseline']:.2f} -> {item['current']:.2f} ({item['delta']:+.2f})",
            flush=True,
        )
    print(f"\nWrote {args.output}", flush=True)
    if failures:
        print(f"Failures: {len(failures)}", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
