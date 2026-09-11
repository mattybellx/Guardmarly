"""Guardmarly evidence benchmark — reproducible, self-contained measurement.

Usage
-----
    python benchmarks/run_benchmark.py labelled      # P/R on the labelled corpus
    python benchmarks/run_benchmark.py clean         # noise on trusted code
    python benchmarks/run_benchmark.py throughput    # LOC/s
    python benchmarks/run_benchmark.py headtohead    # vs Bandit / Semgrep
    python benchmarks/run_benchmark.py all           # everything, writes results/

Every number printed here is derived from a scan executed at run time.  Nothing
is hard-coded from documentation or from a previous run.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
CORPUS = HERE / "corpus"
RESULTS = HERE / "results"

PY = str(REPO / ".venv" / "Scripts" / "python.exe")
if not pathlib.Path(PY).exists():  # non-Windows / plain interpreter
    PY = sys.executable

# Optional competitor installs.  Override with env vars if they live elsewhere.
BANDIT = os.environ.get(
    "BANDIT_EXE", r"C:\Users\matth\OneDrive\Desktop\X\.venv\Scripts\bandit.exe"
)
SEMGREP_CONFIG = os.environ.get("GM_SEMGREP_CONFIG", "p/default")
SEMGREP = os.environ.get(
    "SEMGREP_EXE", r"C:\Users\matth\OneDrive\Desktop\X\.venv\Scripts\semgrep.exe"
)

PY_EXTS = {".py"}
LANGS = {".py", ".js", ".ts", ".java", ".go", ".cs"}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def rel(path: str | pathlib.Path) -> str:
    """Path relative to the repo root (for display)."""
    p = pathlib.Path(path)
    for base in (REPO, CORPUS):
        try:
            return p.relative_to(base).as_posix()
        except ValueError:
            continue
    return p.as_posix()


def corpus_key(path: str | pathlib.Path) -> str:
    """Path relative to the corpus root, matching ground_truth.json keys."""
    p = pathlib.Path(path)
    try:
        return p.relative_to(CORPUS).as_posix()
    except ValueError:
        pass
    # Paths reported relative to cwd during a scan
    as_posix = p.as_posix()
    marker = "corpus/"
    idx = as_posix.rfind(marker)
    if idx != -1:
        return as_posix[idx + len(marker):]
    return as_posix


# Well-established CWE equivalences so that two scanners describing the same
# weakness with different (equally valid) CWE ids are not penalised.  Applied
# identically to every tool, so it cannot favour any one of them.
_CWE_EQUIV: dict[str, str] = {
    "CWE-259": "CWE-798",  # hardcoded password -> hardcoded credentials
    "CWE-321": "CWE-798",  # hardcoded crypto key
    "CWE-261": "CWE-798",  # weak password encoding
    "CWE-328": "CWE-327",  # weak hash algorithm variants
    "CWE-23": "CWE-22",    # relative path traversal
    "CWE-36": "CWE-22",    # absolute path traversal
}


def canon(cwe: str) -> str:
    """Normalise a CWE id using the documented equivalence table."""
    return _CWE_EQUIV.get((cwe or "").upper(), (cwe or "").upper())


def count_loc(root: pathlib.Path, exts: set[str] = LANGS) -> tuple[int, int]:
    files = loc = 0
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in exts:
            try:
                loc += len(p.read_text(encoding="utf-8", errors="replace").splitlines())
                files += 1
            except OSError:
                pass
    return files, loc


def guardmarly_scan(target: pathlib.Path, tag: str, timeout: int = 1800,
                    extra: list[str] | None = None) -> dict:
    """Run the shipped CLI the way a user would, return the parsed report."""
    out = RESULTS / f"_scan_{tag}.json"
    RESULTS.mkdir(parents=True, exist_ok=True)
    start = time.perf_counter()
    proc = subprocess.run(
        [
            PY, "-m", "guardmarly.cli", str(target),
            "--format", "json", "--output", str(out),
            "--fail-on", "never", "--no-colour",
            *(extra or []),
        ],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(REPO), stdin=subprocess.DEVNULL, timeout=timeout,
    )
    elapsed = time.perf_counter() - start
    if not out.exists():
        sys.stderr.write(proc.stdout[-2000:] + proc.stderr[-2000:])
        raise SystemExit(f"guardmarly produced no report for {target}")
    data = json.loads(out.read_text(encoding="utf-8"))
    data["_wall_seconds"] = round(elapsed, 2)
    return data


def flatten(report: dict) -> list[dict]:
    out = []
    for res in report.get("results", []):
        for f in res.get("findings", []):
            g = dict(f)
            g["_file"] = res.get("file") or res.get("file_path") or ""
            g["_rel"] = rel(g["_file"])
            g["_key"] = corpus_key(g["_file"])
            out.append(g)
    return out


def _top(hist: dict, n: int = 15) -> dict:
    """Top-N of a rule histogram, tolerant of non-integer values."""
    def weight(item: tuple) -> int:
        value = item[1]
        return value if isinstance(value, int) else 0

    return dict(sorted(hist.items(), key=weight, reverse=True)[:n])


def sec_only(findings: list[dict]) -> list[dict]:
    """Security findings only — quality/style findings are out of scope."""
    return [f for f in findings if f.get("finding_class", "security") == "security"]


# --------------------------------------------------------------------------
# 1. labelled corpus: precision / recall
# --------------------------------------------------------------------------
def _score_files(findings: list[dict], truth: dict) -> tuple[list[dict], list[dict]]:
    """Return (misses, false-positive files) for a set of findings."""
    by_file: dict[str, list[dict]] = {}
    for f in findings:
        by_file.setdefault(f["_key"], []).append(f)
    misses = []
    for path, expected in sorted(truth["positives"].items()):
        got = {f.get("cwe") for f in by_file.get(path, [])}
        if not ({canon(c) for c in got if c} & {canon(c) for c in expected}):
            misses.append({"file": path, "expected": expected,
                           "detected": sorted(c for c in got if c)})
    fps = [
        {"file": path,
         "count": len(by_file[path]),
         "rules": sorted({f.get("rule_id", "?") for f in by_file[path]})}
        for path in truth["negatives"] if by_file.get(path)
    ]
    return misses, fps


def bench_labelled() -> dict:
    truth = json.loads((HERE / "ground_truth.json").read_text(encoding="utf-8"))

    # Two identical runs, same arguments.  Any difference between them is
    # non-reproducibility, which is measured rather than assumed: identical
    # input must produce identical output or baselines and diffs are worthless.
    run_a = guardmarly_scan(CORPUS, "labelled")
    run_b = guardmarly_scan(CORPUS, "labelled_repeat")

    findings = sec_only(flatten(run_a))
    miss_raw, fp_raw = _score_files(findings, truth)

    def fingerprint(report: dict) -> dict[str, list]:
        per_file: dict[str, list] = {}
        for f in sec_only(flatten(report)):
            per_file.setdefault(f["_key"], []).append((f.get("rule_id"), f.get("cwe")))
        return {k: sorted(v) for k, v in per_file.items()}

    fp_a, fp_b = fingerprint(run_a), fingerprint(run_b)
    unstable = sorted(
        k for k in set(fp_a) | set(fp_b) if fp_a.get(k) != fp_b.get(k)
    )

    positives = len(truth["positives"])
    negatives = len(truth["negatives"])
    detected = positives - len(miss_raw)
    return {
        "kind": "labelled",
        "wall_seconds": run_a["_wall_seconds"],
        "positives": positives,
        "detected": detected,
        "missed": len(miss_raw),
        "recall": round(detected / positives, 4) if positives else 0.0,
        "misses": miss_raw,
        "negative_files": negatives,
        "negative_files_flagged": len(fp_raw),
        "negative_false_positives": sum(f["count"] for f in fp_raw),
        "negatives_with_findings": fp_raw,
        "false_positive_file_rate": round(len(fp_raw) / negatives, 4) if negatives else 0.0,
        "total_findings_on_corpus": len(findings),
        "reproducibility": {
            "runs": 2,
            "identical": not unstable,
            "files_differing": len(unstable),
            "differing_files": unstable[:10],
            "note": (
                "Two identical invocations of the shipped CLI over identical "
                "input. Differences indicate non-deterministic output, which "
                "this version exhibits at rule-id granularity."
            ),
        },
    }


# --------------------------------------------------------------------------
# 2. clean corpora: noise on code that is not vulnerable
# --------------------------------------------------------------------------
def stdlib_core_files() -> list[pathlib.Path]:
    """High-quality, security-reviewed Python that ships with the interpreter.

    Excluded: the CPython *test* suites (deliberately full of bad patterns) and
    vendored/third-party trees inside the stdlib.
    """
    import sysconfig

    root = pathlib.Path(sysconfig.get_paths()["stdlib"])
    skip = {"test", "tests", "idlelib", "lib2to3", "tkinter", "site-packages",
            "ensurepip", "distutils", "venv", "__pycache__"}
    out = []
    for p in root.rglob("*.py"):
        if any(part in skip for part in p.relative_to(root).parts[:-1]):
            continue
        out.append(p)
    return out


def bench_clean() -> dict:
    """Findings per kLOC on code that a human would call clean.

    Two independent sources: (a) the Python standard library shipped with this
    interpreter, (b) framework releases of Flask / Django / Express / Gin that
    have been publicly audited for years.  Any HIGH+ finding here is a
    demonstrable false positive: a reviewer can open the file and read it.
    """
    corpora: list[tuple[str, pathlib.Path]] = []
    lib = REPO / ".corpora"
    for name in ("flask_fresh", "express_fresh", "gin_fresh"):
        if (lib / name).exists():
            corpora.append((name, lib / name))
    # Django is ~523 kLOC and does not finish inside the benchmark budget at
    # current throughput; opt in with GM_BENCH_DJANGO=1 (see EVIDENCE.md).
    if os.environ.get("GM_BENCH_DJANGO") == "1" and (lib / "django_fresh").exists():
        corpora.append(("django_fresh", lib / "django_fresh"))

    import shutil
    import sysconfig
    import tempfile

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="gmstdlib_"))
    stdlib_root = pathlib.Path(sysconfig.get_paths()["stdlib"])
    # Bounded sample so the benchmark finishes in minutes on any machine while
    # staying deterministic: the N largest core-stdlib modules.
    cap = int(os.environ.get("GM_BENCH_STDLIB_FILES", "400"))
    try:
        # Copy only the core stdlib files (see stdlib_core_files) into a flat
        # tree; scanning in place would drag in site-packages.
        core = sorted(
            stdlib_core_files(),
            key=lambda p: (-p.stat().st_size, p.as_posix()),
        )[:cap]
        for p in core:
            dest = tmp / p.relative_to(stdlib_root)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, dest)
        corpora.append(("python_stdlib_core", tmp))

        results = []
        for name, path in corpora:
            files, loc = count_loc(path, PY_EXTS if "stdlib" in name or "flask" in name or "django" in name else LANGS)
            report = guardmarly_scan(path, f"clean_{name}")
            findings = sec_only(flatten(report))
            sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in findings:
                sev[f.get("severity", "info")] = sev.get(f.get("severity", "info"), 0) + 1
            high_plus = sev["critical"] + sev["high"]
            kloc = max(loc, 1) / 1000.0
            rules: dict[str, int] = {}
            for f in findings:
                rules[f.get("rule_id", "?")] = rules.get(f.get("rule_id", "?"), 0) + 1
            results.append({
                "corpus": name,
                "files": files,
                "loc": loc,
                "kloc": round(kloc, 2),
                "total": len(findings),
                "severity": sev,
                "high_plus": high_plus,
                "findings_per_kloc": round(len(findings) / kloc, 3),
                "high_plus_per_kloc": round(high_plus / kloc, 3),
                "wall_seconds": report["_wall_seconds"],
                "loc_per_second": round(loc / max(report["_wall_seconds"], 0.01), 1),
                "top_rules": dict(sorted(rules.items(), key=lambda kv: -kv[1])[:10]),
                "high_plus_rules": dict(sorted(
                    (
                        (r, c) for r, c in rules.items()
                        if any(
                            f.get("rule_id") == r and f.get("severity") in ("critical", "high")
                            for f in findings
                        )
                    ),
                    key=lambda kv: -kv[1],
                )[:10]),
            })
        return {"kind": "clean", "corpora": results}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------
# 3. throughput
# --------------------------------------------------------------------------
def bench_throughput() -> dict:
    import shutil
    import sysconfig
    import tempfile

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="gmthru_"))
    root = pathlib.Path(sysconfig.get_paths()["stdlib"])
    cap = int(os.environ.get("GM_BENCH_THROUGHPUT_FILES", "150"))
    try:
        n = 0
        for p in root.rglob("*.py"):
            rp = p.relative_to(root)
            if rp.parts and rp.parts[0] in ("test", "tests", "site-packages"):
                continue
            dest = tmp / rp
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, dest)
            n += 1
            if n >= cap:
                break
        files, loc = count_loc(tmp, PY_EXTS)
        report = guardmarly_scan(tmp, "throughput")
        return {
            "kind": "throughput",
            "corpus": "python_stdlib_sample",
            "files": files,
            "loc": loc,
            "wall_seconds": report["_wall_seconds"],
            "loc_per_second": round(loc / max(report["_wall_seconds"], 0.01), 1),
            "files_per_second": round(files / max(report["_wall_seconds"], 0.01), 2),
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------
# 4. head-to-head against Bandit / Semgrep on the identical corpus
# --------------------------------------------------------------------------
def run_bandit(target: pathlib.Path) -> tuple[int, int, dict]:
    """Return (python_targets, findings, rule_histogram)."""
    if not pathlib.Path(BANDIT).exists():
        return 0, 0, {}
    # Bandit's stdout is not reliable through a pipe on Windows; write to a file.
    bt_out = RESULTS / "_bandit_hist.json"
    RESULTS.mkdir(parents=True, exist_ok=True)
    bt_out.unlink(missing_ok=True)
    subprocess.run(
        [BANDIT, "-r", str(target), "-f", "json", "-o", str(bt_out), "-q"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(REPO), stdin=subprocess.DEVNULL, timeout=900,
    )
    try:
        data = json.loads(bt_out.read_text(encoding="utf-8"))
    except Exception:
        return 0, 0, {}
    # Measure over the same files Guardmarly was given: Python files only,
    # because Bandit does not analyse other languages at all.
    py_targets = len(list(target.rglob("*.py")))
    results = data.get("results", [])
    hist: dict[str, int] = {}
    for r in results:
        hist[r.get("test_id", "?")] = hist.get(r.get("test_id", "?"), 0) + 1
    return py_targets, len(results), hist


def run_semgrep(target: pathlib.Path) -> tuple[int, dict, dict]:
    """Return (findings, per-file cwes, histogram).

    Semgrep is given a UTF-8 environment: it aborts with ``UnicodeEncodeError``
    on a legacy Windows console (``'charmap' codec can't encode '\\u202a'``),
    which is the same defect class this repository fixed in ``_stdio``.  The
    ruleset is selectable because ``p/ci`` is deliberately minimal and would
    understate the comparison.
    """
    if not pathlib.Path(SEMGREP).exists():
        return 0, {}, {}

    sg_out = RESULTS / "_semgrep.json"
    RESULTS.mkdir(parents=True, exist_ok=True)
    sg_out.unlink(missing_ok=True)
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    subprocess.run(
        [SEMGREP, "scan", "--config", SEMGREP_CONFIG, "--json", "--quiet",
         "--no-git-ignore", "--metrics", "off", "-o", str(sg_out), str(target)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(REPO), stdin=subprocess.DEVNULL, timeout=1800, env=env,
    )
    try:
        data = json.loads(sg_out.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return 0, {}, {"_error": f"{type(exc).__name__}: no semgrep report"}

    per_file: dict[str, set[str]] = {}
    hist: dict[str, int] = {}
    for r in data.get("results", []):
        fp = r.get("path", "")
        meta = r.get("extra", {}).get("metadata", {}) or {}
        cwe_value = meta.get("cwe")
        cwe = ""
        if isinstance(cwe_value, str):
            cwe = cwe_value.split(":")[0].strip()
        elif isinstance(cwe_value, list) and cwe_value:
            cwe = str(cwe_value[0]).split(":")[0].strip()
        if cwe:
            per_file.setdefault(corpus_key(fp), set()).add(cwe)
        hist[r.get("check_id", "?")] = hist.get(r.get("check_id", "?"), 0) + 1
    return len(data.get("results", [])), per_file, hist


def bench_headtohead() -> dict:
    truth = json.loads((HERE / "ground_truth.json").read_text(encoding="utf-8"))
    positives = truth["positives"]
    negatives = set(truth["negatives"])

    gm = guardmarly_scan(CORPUS, "h2h")
    gm_by_file: dict[str, set[str]] = {}
    for f in sec_only(flatten(gm)):
        if f.get("cwe"):
            gm_by_file.setdefault(f["_key"], set()).add(f["cwe"])

    sg_total, sg_by_file, sg_hist = run_semgrep(CORPUS)
    bt_targets, bt_total, bt_hist = run_bandit(CORPUS)

    def score(get_cwes, *, languages: set[str]) -> dict:
        """Score one tool on the subset of positives/negatives it can address."""
        rel_lang = {".py": "python", ".js": "javascript", ".java": "java", ".go": "go", ".cs": "csharp"}
        pos = {k: v for k, v in positives.items() if rel_lang[pathlib.Path(k).suffix] in languages}
        neg = {k for k in negatives if rel_lang[pathlib.Path(k).suffix] in languages}
        hit = [k for k, exp in pos.items()
               if {canon(c) for c in get_cwes(k)} & {canon(c) for c in exp}]
        fp_files = [k for k in neg if get_cwes(k)]
        tp, fn = len(hit), len(pos) - len(hit)
        return {
            "positives_in_scope": len(pos),
            "negatives_in_scope": len(neg),
            "detected": tp,
            "missed": fn,
            "recall": round(tp / len(pos), 4) if pos else 0.0,
            "negative_files_flagged": len(fp_files),
            "false_positive_file_rate": round(len(fp_files) / len(neg), 4) if neg else 0.0,
            "missed_files": sorted(
                k for k, exp in pos.items()
                if not ({canon(c) for c in get_cwes(k)} & {canon(c) for c in exp})
            ),
            "false_positive_files": sorted(fp_files),
        }

    all_langs = {"python", "javascript", "java", "go", "csharp"}
    gm_all = score(lambda p: gm_by_file.get(p, set()), languages=all_langs)
    gm_py = score(lambda p: gm_by_file.get(p, set()), languages={"python"})
    sg_all = score(lambda p: sg_by_file.get(p, set()), languages=all_langs)
    sg_py = score(lambda p: sg_by_file.get(p, set()), languages={"python"})

    bt_file: dict[str, set[str]] = {}
    if pathlib.Path(BANDIT).exists():
        # Bandit JSON carries test_id + issue_cwe; re-run to collect CWEs.
        bt_out = RESULTS / "_bandit.json"
        bt_out.unlink(missing_ok=True)
        subprocess.run(
            [BANDIT, "-r", str(CORPUS), "-f", "json", "-o", str(bt_out), "-q"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            cwd=str(REPO), stdin=subprocess.DEVNULL, timeout=900,
        )
        try:
            for r in json.loads(bt_out.read_text(encoding="utf-8")).get("results", []):
                cwe = (r.get("issue_cwe") or {}).get("id")
                if cwe:
                    bt_file.setdefault(corpus_key(r.get("filename", "")), set()).add(f"CWE-{cwe}")
        except Exception:
            pass
    bt_py = score(lambda p: bt_file.get(p, set()), languages={"python"})

    return {
        "kind": "headtohead",
        "corpus_files": len(positives) + len(negatives),
        "guardmarly": {"all_languages": gm_all, "python_only": gm_py},
        "semgrep_oss_p_ci": {
            "available": sg_total > 0 or bool(sg_by_file),
            "all_languages": sg_all, "python_only": sg_py,
            "total_findings": sg_total, "rule_histogram": _top(sg_hist),
        },
        "bandit_1_9_4": {
            "available": pathlib.Path(BANDIT).exists(),
            "python_only": bt_py, "total_findings": bt_total,
            "rule_histogram": _top(bt_hist),
        },
        "note": (
            "Semgrep is run with its 'p/default' ruleset (its broadest recommended "
            "security configuration; selectable via GM_SEMGREP_CONFIG), Bandit "
            "with its full default test set. Both are given the identical corpus "
            "directory. A tool that cannot be executed on the measured machine is "
            "reported as unavailable rather than scored zero."
        ),
    }


# --------------------------------------------------------------------------
def emit(name: str, payload: dict) -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    out = RESULTS / f"{name}.json"
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"\n=== {name} ===")
    print(json.dumps(payload, indent=2)[:6000])
    print(f"\n-> written to {out}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("what", choices=["labelled", "clean", "throughput", "headtohead", "all"])
    args = ap.parse_args(argv)
    if args.what in ("labelled", "all"):
        emit("labelled", bench_labelled())
    if args.what in ("throughput", "all"):
        emit("throughput", bench_throughput())
    if args.what in ("clean", "all"):
        emit("clean", bench_clean())
    if args.what in ("headtohead", "all"):
        emit("headtohead", bench_headtohead())
    return 0


if __name__ == "__main__":
    sys.exit(main())
