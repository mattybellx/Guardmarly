"""Reproduce every competitive metric from scratch, with a verifiable manifest.

    python benchmarks/reproduce_metrics.py

Writes ``benchmarks/results/EVIDENCE.md`` and ``benchmarks/results/manifest.json``.

Design rule: **no number is typed in by hand.** Everything in the report is
produced by this script on the machine it runs on, and the manifest records the
inputs that would change the numbers -- corpus digests, tool versions, platform,
interpreter -- so a reader can check the result instead of trusting it.

The clean-code corpus (``benchmarks/results/_stdlib_sample``) is built from the
*running* interpreter's standard library, so its digest legitimately differs
between Python versions. The manifest pins ``python_version`` so a mismatch is
explained rather than confusing.

Exit code is 0 when every threshold passes, 1 otherwise, so CI can gate on it.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import platform
import statistics
import subprocess
import sys
import sysconfig
import time

REPO = pathlib.Path(__file__).resolve().parent.parent
RESULTS = REPO / "benchmarks" / "results"
SAMPLE = RESULTS / "_stdlib_sample"
PY = sys.executable

# Third-party scanners are optional; skip cleanly when not installed.
SEMGREP = os.environ.get("GM_SEMGREP", "semgrep")
BANDIT = os.environ.get("GM_BANDIT", "bandit")

# Thresholds the report is judged against. Deliberately conservative: they are
# the *floor* a release must clear, not the current numbers.
THRESHOLDS = {
    "recall": 0.95,
    "high_per_kloc_clean": 0.60,
}

STEPS: list[tuple[str, list[str]]] = [
    ("Determinism", ["benchmarks/check_determinism.py"]),
    ("Labelled corpus: recall + clean-control FP rate", ["benchmarks/run_benchmark.py", "labelled"]),
    ("Clean-code precision and speed, three-way", ["benchmarks/compare_clean.py"]),
    ("Noise breakdown on the clean corpus", ["benchmarks/diagnose_noise.py", "--keep"]),
]


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def digest_tree(root: pathlib.Path) -> dict[str, object]:
    """Digest a directory so a corpus can be pinned and compared.

    The digest is over ``relative/path|sha256`` lines, sorted, so it changes if
    any file's content, name or presence changes -- but not if the tree merely
    moves.
    """
    if not root.exists():
        return {"path": str(root.relative_to(REPO)), "exists": False}
    files = sorted(p for p in root.rglob("*") if p.is_file())
    entries = [f"{p.relative_to(root).as_posix()}|{sha256_file(p)}" for p in files]
    loc = 0
    for p in files:
        try:
            loc += len(p.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            pass
    return {
        "path": str(root.relative_to(REPO)).replace("\\", "/"),
        "exists": True,
        "files": len(files),
        "loc": loc,
        "sha256": hashlib.sha256("\n".join(entries).encode()).hexdigest(),
    }


def tool_version(cmd: str, args: list[str]) -> str:
    """Return a version string, or a marker explaining why it is unavailable."""
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    try:
        proc = subprocess.run(
            [cmd, *args], capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=120, env=env, stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return "not installed"
    except (OSError, subprocess.SubprocessError) as exc:
        return f"unavailable ({type(exc).__name__})"
    text = (proc.stdout or proc.stderr or "").strip().splitlines()
    return text[0].strip() if text else "unknown"


def guardmarly_version() -> str:
    try:
        sys.path.insert(0, str(REPO / "src"))
        from guardmarly._version import __version__  # noqa: PLC0415

        return __version__
    except Exception as exc:  # noqa: BLE001 - reporting must never crash
        return f"unknown ({type(exc).__name__})"


def git_provenance() -> dict[str, object]:
    """HEAD revision and dirty flag, so a figure is attributable to a revision."""
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=str(REPO), capture_output=True,
            text=True, timeout=60, stdin=subprocess.DEVNULL,
        )
        status = subprocess.run(
            # `--untracked-files=no`: only modifications to *tracked* files make
            # the numbers unreproducible. Untracked build artifacts (this
            # directory) would otherwise mark every run dirty, which is a false
            # alarm that trains the reader to ignore the flag.
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=str(REPO), capture_output=True,
            text=True, timeout=60, stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"git_revision": f"unavailable ({type(exc).__name__})", "git_dirty": None}
    return {
        "git_revision": (head.stdout or "").strip() or "unknown",
        "git_dirty": bool((status.stdout or "").strip()),
    }


def manifest() -> dict[str, object]:
    data: dict[str, object] = {
        "generated_by": "benchmarks/reproduce_metrics.py",
        "python_version": platform.python_version(),
        "python_build": sysconfig.get_config_var("BUILD_GNU_TYPE") or "",
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "guardmarly_version": guardmarly_version(),
        "semgrep_version": tool_version(SEMGREP, ["--version"]),
        "bandit_version": tool_version(BANDIT, ["--version"]),
        "corpora": {
            "labelled": digest_tree(REPO / "benchmarks" / "corpus"),
            "clean_stdlib_sample": digest_tree(SAMPLE),
            # The rule catalog decides every finding, so a change to it must be
            # as visible in the manifest as a change to the corpus.
            "rules": digest_tree(REPO / "rules"),
        },
    }
    data.update(git_provenance())
    return data


def run_step(argv: list[str], timeout: int = 3600) -> tuple[int, str]:
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    try:
        proc = subprocess.run(
            [PY, *argv], cwd=str(REPO), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, env=env,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()


def per_language_recall(labelled_output: str) -> list[tuple[str, int, int, float]]:
    """Recall per language, from the ground truth plus the run's miss list.

    The aggregate figure is **not** a per-language claim. With roughly seven
    fixtures per language, a single miss moves that language by ~14 points, so
    reporting one blended number would overstate what has actually been shown.
    Columns: (language, positives, detected, recall).
    """
    start = labelled_output.find("{")
    end = labelled_output.rfind("}")
    if start == -1 or end <= start:
        return []
    try:
        data = json.loads(labelled_output[start:end + 1])
    except json.JSONDecodeError:
        return []
    misses = {
        str(m.get("file"))
        for m in data.get("misses", [])
        if isinstance(m, dict) and m.get("file")
    }
    try:
        ground_truth = json.loads(
            (REPO / "benchmarks" / "ground_truth.json").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        return []

    totals: dict[str, int] = {}
    for path in (ground_truth.get("positives") or {}):
        language = str(path).split("/", 1)[0]
        totals[language] = totals.get(language, 0) + 1

    rows: list[tuple[str, int, int, float]] = []
    for language in sorted(totals):
        total = totals[language]
        missed = sum(1 for m in misses if m.split("/", 1)[0] == language)
        detected = total - missed
        rows.append((language, total, detected, detected / total if total else 0.0))
    return rows


def extract_recall(text: str) -> float | None:
    """Extract the recall figure from the labelled-corpus run.

    `run_benchmark.py labelled` prints a JSON object, so the machine-readable
    key is tried first and the human ``recall 97.2% (35/36)`` shape is only a
    fallback -- the first version of this function only understood the latter
    and reported a false FAIL against a passing run.
    """
    import re as _re

    m = _re.search(r'"recall"\s*:\s*([0-9]*\.?[0-9]+)', text)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            pass
    for line in text.splitlines():
        if "recall" in line.lower():
            for tok in line.replace("(", " ").replace(")", " ").split():
                if tok.endswith("%"):
                    try:
                        return float(tok.rstrip("%")) / 100.0
                    except ValueError:
                        continue
    return None


def extract_high_per_kloc(text: str) -> float | None:
    """Compute HIGH+/kLOC from ``scanned N files, F findings, H HIGH+``."""
    import re as _re

    m = _re.search(r"scanned\s+(\d+)\s+files,\s+(\d+)\s+findings,\s+(\d+)\s+HIGH\+", text)
    if not m:
        return None
    high = int(m.group(3))
    loc = digest_tree(SAMPLE).get("loc") or 0
    if not loc:
        return None
    return high * 1000.0 / float(loc)


def measure_throughput(workers: int = 8, samples: int = 5) -> dict[str, object]:
    """Time an N-worker scan of the clean corpus, over several samples.

    Recorded rather than gated: speed depends on the machine's core count and a
    scan's wall time is bounded below by its slowest phase, so a hard threshold
    here would be a flaky test rather than a useful signal.

    A single wall-clock sample is **not** reproducible. Repeat runs of this exact
    corpus on one machine have spanned 35.7s to 40.3s (~13%), so the median and
    the spread are reported together and any delta smaller than the spread is
    noise. Without this, a real 5% improvement cannot be told from jitter.
    """
    loc = int(digest_tree(SAMPLE).get("loc") or 0)
    out = RESULTS / "_throughput.json"
    timings: list[float] = []
    exits: list[int] = []
    for _ in range(max(1, samples)):
        start = time.perf_counter()
        code, _ = run_step([
            "-m", "guardmarly.cli", SAMPLE.relative_to(REPO).as_posix(),
            "--format", "json", "--output", out.relative_to(REPO).as_posix(),
            "--fail-on", "never", "--no-colour", "--workers", str(workers),
        ], timeout=1800)
        timings.append(time.perf_counter() - start)
        exits.append(code)
    median = statistics.median(timings)
    lo, hi = min(timings), max(timings)
    return {
        "workers": workers,
        "samples": len(timings),
        "seconds_median": round(median, 2),
        "seconds_min": round(lo, 2),
        "seconds_max": round(hi, 2),
        "spread_pct": round((hi - lo) / median * 100.0, 1) if median else 0.0,
        "all_seconds": [round(t, 2) for t in timings],
        "loc": loc,
        "loc_per_second": int(loc / median) if median else 0,
        "exit": max(exits),
    }


def ensure_corpora() -> None:
    """Build any missing corpus so the harness works on a clean checkout.

    Neither corpus is committed: the labelled corpus is generated, and the clean
    corpus is copied out of the *running* interpreter's standard library (which
    is why the manifest pins ``python_version``). Without this the harness would
    only ever work on the machine that happened to build them first.
    """
    if not (REPO / "benchmarks" / "corpus").exists():
        print("[reproduce] building the labelled corpus ...", flush=True)
        run_step(["benchmarks/build_corpus.py"])
    if not SAMPLE.exists():
        print("[reproduce] building the clean stdlib sample ...", flush=True)
        # Without --keep this rebuilds _stdlib_sample from the local stdlib and
        # then scans it; the scan result is ignored, we only want the corpus.
        run_step(["benchmarks/diagnose_noise.py"])


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    ensure_corpora()
    man = manifest()

    sections: list[str] = []
    verdicts: list[tuple[str, bool, str]] = []
    per_lang: list[tuple[str, int, int, float]] = []

    for title, argv in STEPS:
        print(f"[reproduce] {title} ...", flush=True)
        code, output = run_step(argv)
        status = "ok" if code == 0 else f"exit {code}"
        print(f"[reproduce]   -> {status}", flush=True)
        sections.append(f"### {title}\n\n```\n$ python {(' ').join(argv)}\n{output}\n```\n")

        if argv[1:2] == ["labelled"]:
            recall = extract_recall(output)
            per_lang = per_language_recall(output)
            if recall is None:
                verdicts.append(("recall >= 0.95", False, "could not parse a recall figure"))
            else:
                verdicts.append((
                    "recall >= 0.95",
                    recall >= THRESHOLDS["recall"],
                    f"measured {recall * 100:.1f}%",
                ))
        elif "--keep" in argv:
            hp = extract_high_per_kloc(output)
            if hp is None:
                verdicts.append(("HIGH+/kLOC <= 0.60", False, "could not parse a HIGH+ count"))
            else:
                verdicts.append((
                    "HIGH+/kLOC <= 0.60",
                    hp <= THRESHOLDS["high_per_kloc_clean"],
                    f"measured {hp:.3f}",
                ))

    # ── Report ───────────────────────────────────────────────────────────────
    print("[reproduce] Throughput (8 workers) ...", flush=True)
    thr = measure_throughput()
    print(
        f"[reproduce]   -> median {thr['seconds_median']}s "
        f"({thr['seconds_min']}-{thr['seconds_max']}s, spread {thr['spread_pct']}%) "
        f"{thr['loc_per_second']:,} LOC/s",
        flush=True,
    )

    lines: list[str] = [
        "# Evidence — reproducible competitive metrics",
        "",
        "> Generated by `python benchmarks/reproduce_metrics.py`. Every figure below",
        "> was produced on the machine that ran the script; nothing is transcribed.",
        "",
        "## Manifest (the inputs that would change the numbers)",
        "",
        "| Field | Value |",
        "| --- | --- |",
    ]
    for key in ("python_version", "platform", "machine", "cpu_count",
                "guardmarly_version", "semgrep_version", "bandit_version",
                "git_revision", "git_dirty"):
        lines.append(f"| `{key}` | {man[key]} |")
    for name, info in man["corpora"].items():  # type: ignore[union-attr]
        if info.get("exists"):
            lines.append(
                f"| corpus `{name}` | {info['files']} files, {info['loc']:,} LOC, "
                f"sha256 `{str(info['sha256'])[:16]}…` |"
            )

    lines += ["", "## Thresholds", "", "| Check | Result | Detail |", "| --- | --- | --- |"]
    failed = False
    for name, ok, detail in verdicts:
        if not ok:
            failed = True
        lines.append(f"| {name} | {'PASS' if ok else 'FAIL'} | {detail} |")
    if not verdicts:
        lines.append("| (no checks parsed) | FAIL | no recognised step output |")
        failed = True

    if per_lang:
        lines += ["", "## Recall per language", "",
                  "| language | positives | detected | recall |",
                  "| --- | --- | --- | --- |"]
        for language, total, detected, rate in per_lang:
            lines.append(f"| {language} | {total} | {detected} | {rate * 100:.1f}% |")
        lines += ["",
                  "The aggregate recall figure is not a per-language claim: with only a few",
                  "fixtures per language, one miss moves a language by a large fraction.", ""]

    lines += ["", "## Throughput (median of N; recorded, not gated)", "",
              "| workers | samples | median s | min s | max s | spread | LOC | LOC/s (median) |",
              "| --- | --- | --- | --- | --- | --- | --- | --- |",
              f"| {thr['workers']} | {thr['samples']} | {thr['seconds_median']} | {thr['seconds_min']} | "
              f"{thr['seconds_max']} | {thr['spread_pct']}% | {thr['loc']:,} | {thr['loc_per_second']:,} |",
              "",
              f"Raw samples (s): `{thr['all_seconds']}`.",
              "",
              "A single wall-clock sample is not reproducible -- repeat runs of this corpus on",
              "one machine have spanned ~13%. **Any delta smaller than the recorded spread is",
              "noise and must not be reported as a speed-up.** Wall time is also bounded below",
              "by the scan's slowest non-parallel phase, so it does not improve linearly with",
              "worker count. Compare like-for-like only on the same corpus and machine.", ""]
    man["throughput"] = thr

    lines += ["", "## Raw output", ""]
    lines.extend(sections)

    (RESULTS / "EVIDENCE.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (RESULTS / "manifest.json").write_text(json.dumps(man, indent=2), encoding="utf-8")

    print(f"\n[reproduce] wrote {RESULTS / 'EVIDENCE.md'}")
    print(f"[reproduce] wrote {RESULTS / 'manifest.json'}")
    for name, ok, detail in verdicts:
        print(f"[reproduce] {'PASS' if ok else 'FAIL'}  {name}  ({detail})")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
