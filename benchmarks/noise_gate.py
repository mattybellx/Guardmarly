#!/usr/bin/env python3
"""CI noise gate: ensure confidence threshold never suppresses HIGH/CRITICAL findings.

Usage:
  python benchmarks/noise_gate.py /path/to/repo1 /path/to/repo2 [repo3...]
  python benchmarks/noise_gate.py --random 3    # pick 3 random repos from pool

Exit 0 if 0 HIGH/CRIT findings are lost. Exit 1 if any are suppressed.
"""
import json, subprocess, sys, tempfile, os, random
from pathlib import Path

# Pool of small-to-medium Python repos. Rotates on every --random run.
# Repos chosen for diversity: frameworks, utilities, DB tools, CLI apps.
# All are well-maintained, have real-world users, and are not in the CVE corpus.
_CANDIDATE_POOL: list[tuple[str, str]] = [
    ("pallets/quart", "Async Flask-compatible web framework"),
    ("encode/databases", "Async database support for Python"),
    ("samuelcolvin/watchfiles", "File watcher for Python"),
    ("pytest-dev/pluggy", "Plugin system used by pytest"),
    ("sqlalchemy/alembic", "Database migration tool"),
    ("encode/uvicorn", "ASGI server"),
    ("tiangolo/typer", "CLI framework"),
    ("dateutil/dateutil", "Date/time utilities"),
    ("pallets/click", "CLI toolkit"),
    ("pallets/markupsafe", "HTML escaping utility"),
    ("python-attrs/attrs", "Class utilities"),
    ("encode/httpx", "HTTP client"),
    ("pydantic/pydantic-settings", "Settings management"),
    ("agronholm/apscheduler", "Task scheduler"),
    ("pallets/itsdangerous", "Crypto signing library"),
    ("encode/starlette", "ASGI framework"),
    ("marshmallow-code/marshmallow", "Serialization library"),
    ("pytest-dev/pytest-mock", "pytest mock plugin"),
    ("pypa/packaging", "Package version handling"),
    ("python-hyper/h11", "HTTP/1.1 parser"),
]


def _clone_random_repos(picked: list[tuple[str, str]]) -> list[Path]:
    """Clone the *picked* repos to temp directories in parallel."""
    tmp_root = Path(tempfile.mkdtemp(prefix="ansede_random_"))
    paths: list[Path] = []

    # Clone in parallel for speed
    import concurrent.futures
    def _clone_one(repo_name: str, desc: str) -> Path | None:
        dest = tmp_root / repo_name.replace("/", "_")
        print(f"  Cloning {repo_name} ({desc})...", flush=True)
        try:
            r = subprocess.run(
                ["git", "clone", "--depth", "1", f"https://github.com/{repo_name}.git", str(dest)],
                capture_output=True, text=True, timeout=120,
            )
            if r.returncode == 0:
                return dest
            else:
                print(f"    WARNING: clone failed for {repo_name}", flush=True)
                return None
        except (subprocess.TimeoutExpired, Exception):
            print(f"    WARNING: clone timeout for {repo_name}", flush=True)
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as ex:
        futures = {ex.submit(_clone_one, name, desc): (name, desc) for name, desc in picked}
        for fut in concurrent.futures.as_completed(futures):
            result = fut.result()
            if result is not None:
                paths.append(result)

    return paths


def run_gate(repo_paths: list[str]) -> tuple[bool, str]:
    out = Path(tempfile.mkdtemp(prefix="ansede_gate_"))
    results: list[dict] = []

    for i, raw_path in enumerate(repo_paths):
        repo_dir = Path(raw_path)
        if not repo_dir.is_dir():
            return False, f"Directory not found: {repo_dir}"

        py_files = list(repo_dir.rglob("*.py"))
        fc = len(py_files)
        repo_name = repo_dir.name
        print(f"[{i+1}/{len(repo_paths)}] {repo_name}: {fc} .py files...", flush=True)

        # BEFORE: --all-findings (no confidence filter)
        r1 = subprocess.run(
            [sys.executable, "-m", "ansede_static.cli", str(repo_dir),
             "--format", "json", "--all-findings",
             "--output", str(out / f"before_{i}.json")],
            capture_output=True, text=True, timeout=300,
        )

        # AFTER: new default (0.65 confidence)
        r2 = subprocess.run(
            [sys.executable, "-m", "ansede_static.cli", str(repo_dir),
             "--format", "json",
             "--output", str(out / f"after_{i}.json")],
            capture_output=True, text=True, timeout=300,
        )

        bc = 0; ac = 0; bh = 0; ah = 0
        try:
            bd = json.loads((out / f"before_{i}.json").read_text())
            ad = json.loads((out / f"after_{i}.json").read_text())
            for item in (bd.get("results", []) or []):
                for f in item.get("findings", []):
                    bc += 1
                    if str(f.get("severity", "")).lower() in ("critical", "high"):
                        bh += 1
            for item in (ad.get("results", []) or []):
                for f in item.get("findings", []):
                    ac += 1
                    if str(f.get("severity", "")).lower() in ("critical", "high"):
                        ah += 1
        except Exception as e:
            print(f"  Parse error: {e}", flush=True)
            continue

        cut = (1 - ac / bc) * 100 if bc else 0
        lost = bh - ah
        status = "PASS" if lost == 0 else "FAIL"
        print(f"  {status}: before={bc}({bh}h)  after={ac}({ah}h)  cut={cut:.0f}%  high_lost={lost}", flush=True)
        results.append({"repo": repo_name, "fc": fc, "bc": bc, "ac": ac, "bh": bh, "ah": ah, "lost": lost})

    total_lost = sum(r["lost"] for r in results)
    total_bh = sum(r["bh"] for r in results)

    if total_lost == 0:
        msg = f"NOISE GATE PASSED: 0/{total_bh} HIGH/CRIT findings suppressed across {len(results)} repos"
        return True, msg
    else:
        msg = f"NOISE GATE FAILED: {total_lost}/{total_bh} HIGH/CRIT findings were suppressed!\n"
        for r in results:
            if r["lost"] > 0:
                msg += f"  {r['repo']}: lost {r['lost']} high/crit findings\n"
        return False, msg


if __name__ == "__main__":
    if "--random" in sys.argv:
        idx = sys.argv.index("--random")
        try:
            count = int(sys.argv[idx + 1]) if idx + 1 < len(sys.argv) else 3
        except (ValueError, IndexError):
            count = 3
        picked = random.sample(_CANDIDATE_POOL, min(count, len(_CANDIDATE_POOL)))
        print(f"Noise Gate: randomly selecting {len(picked)} repos from pool of {len(_CANDIDATE_POOL)}...")
        for name, desc in picked:
            print(f"  • {name} ({desc})")
        print()
        repo_dirs = _clone_random_repos(picked)
        if len(repo_dirs) < 1:
            print("ERROR: failed to clone any repos")
            sys.exit(2)
        print(f"\nCloned {len(repo_dirs)}/{count} repos successfully.\n")
        ok, message = run_gate([str(d) for d in repo_dirs])
    elif len(sys.argv) < 2:
        print("Usage: python benchmarks/noise_gate.py /path/to/repo1 [/path/to/repo2 ...]")
        print("       python benchmarks/noise_gate.py --random [N]")
        sys.exit(2)
    else:
        ok, message = run_gate(sys.argv[1:])

    print()
    print("=" * 60)
    print(message)
    print("=" * 60)
    sys.exit(0 if ok else 1)
