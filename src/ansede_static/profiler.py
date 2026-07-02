"""
ansede_static.profiler
──────────────────────
Per-file and per-phase profiling for ansede-static scans.
Use with `--profile` CLI flag to get JSON timing breakdown.
"""
from __future__ import annotations

import json
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any


class ScanProfiler:
    """Records timing per file and per analysis phase.

    Usage:
        profiler = ScanProfiler()
        with profiler.phase("file.py", "parse"):
            ...
        with profiler.phase("file.py", "analyze"):
            ...
        print(profiler.to_json())
    """

    def __init__(self) -> None:
        self._phases: dict[str, float] = {}
        self._file_phases: dict[str, dict[str, float]] = {}

    @contextmanager
    def phase(self, file_path: str, phase_name: str) -> Any:
        """Context manager that times a phase for a file.

        Args:
            file_path: Path to the file being analyzed.
            phase_name: Short name like "parse", "analyze", "taint", "total".
        """
        t0 = time.perf_counter()
        try:
            yield
        finally:
            elapsed = time.perf_counter() - t0
            if file_path not in self._file_phases:
                self._file_phases[file_path] = {}
            self._file_phases[file_path][phase_name] = (
                self._file_phases[file_path].get(phase_name, 0) + elapsed
            )
            self._phases[phase_name] = self._phases.get(phase_name, 0) + elapsed

    def record_file_total(self, file_path: str, elapsed: float) -> None:
        """Record total scan time for a file (outside the profiler context)."""
        if file_path not in self._file_phases:
            self._file_phases[file_path] = {}
        self._file_phases[file_path]["total"] = elapsed

    def to_json(self) -> dict[str, Any]:
        """Export profiling data as a JSON-serializable dict."""
        total_ms = sum(self._phases.values()) * 1000
        return {
            "total_ms": round(total_ms, 1),
            "phases": {
                k: round(v * 1000, 1)
                for k, v in sorted(self._phases.items(), key=lambda x: -x[1])
            },
            "file_phases": {
                k: {pk: round(pv * 1000, 1) for pk, pv in v.items()}
                for k, v in sorted(
                    self._file_phases.items(), key=lambda x: -sum(x[1].values())
                )[:50]
            },
        }

    def save(self, path: str | Path) -> None:
        """Save profile JSON to a file."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_json(), f, indent=2)

    def print_summary(self) -> None:
        """Print a human-readable summary to stderr."""
        data = self.to_json()
        print("\nProfile Summary:", file=__import__("sys").stderr)
        print(f"  Total: {data['total_ms']:.0f}ms", file=__import__("sys").stderr)
        print("  Phases:", file=__import__("sys").stderr)
        for phase, ms in data["phases"].items():
            pct = ms / data["total_ms"] * 100 if data["total_ms"] else 0
            print(f"    {phase:<20s} {ms:>10.1f}ms ({pct:>5.1f}%)",
                  file=__import__("sys").stderr)
        slowest = list(data["file_phases"].items())[:5]
        if slowest:
            print("  Slowest files:", file=__import__("sys").stderr)
            for fname, phases in slowest:
                total = sum(phases.values())
                print(f"    {Path(fname).name:<30s} {total:>10.1f}ms "
                      f"(parse: {phases.get('parse', 0):.0f}ms, "
                      f"analyze: {phases.get('analyze', 0):.0f}ms)",
                      file=__import__("sys").stderr)
