"""
java_blind_sample.py — Single-language blind audit sampler for Java.

Samples random Java repos from GitHub, runs ansede-static on every .java file,
and saves all findings for human audit.

Usage:
    python -m benchmarks.java_blind_sample --repos 20 --output benchmarks/audit_results/round1_java.json
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ansede_static import scan_file, _JAVA_EXTS
from ansede_static._types import Finding

IGNORE_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor", "dist",
               "build", "coverage", "__pycache__", ".next", ".nuxt",
               ".idea", ".vscode", "target", ".gradle", "bin", "obj"}

MAX_REPO_SIZE_KB = 50000  # 50 MB max
PER_PAGE = 30
CACHE_DIR = Path(tempfile.gettempdir()) / "ansede_java_audit"


def search_github_java_repos(seed: int, per_page: int = PER_PAGE) -> list[dict[str, Any]]:
    """Search GitHub API for random Java repos."""
    import urllib.request
    import urllib.error

    random.seed(seed)
    # Random star range to get diverse repos
    star_ranges = [(10, 50), (50, 200), (200, 500), (500, 2000)]
    range_choice = random.choice(star_ranges)
    stars_query = f"stars:{range_choice[0]}..{range_choice[1]}"

    # Random sort: use different sort orders to mix it up
    sort_options = ["updated", "stars"]
    sort = random.choice(sort_options)

    # Random page offset to avoid always getting the same repos
    page = random.randint(1, 5)

    query = f"language:Java {stars_query}"
    url = (
        f"https://api.github.com/search/repositories"
        f"?q={urllib.request.quote(query)}"
        f"&sort={sort}"
        f"&order=desc"
        f"&per_page={per_page}"
        f"&page={page}"
    )

    headers = {"Accept": "application/vnd.github.v3+json"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"token {os.environ['GITHUB_TOKEN']}"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"GitHub API error: {e.code} — {e.reason}")
        # Try without auth
        req2 = urllib.request.Request(url, headers={"Accept": "application/vnd.github.v3+json"})
        with urllib.request.urlopen(req2, timeout=30) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        print(f"GitHub API failed: {e}")
        return []

    items = data.get("items", [])
    random.shuffle(items)
    return [
        {
            "name": item["full_name"],
            "url": item["clone_url"],
            "stars": item["stargazers_count"],
            "size_kb": item["size"],
            "language": "java",
        }
        for item in items
        if item["size"] <= MAX_REPO_SIZE_KB
    ]


def clone_repo(repo: dict[str, Any], cache_dir: Path) -> Path | None:
    """Shallow clone a repo."""
    dest = cache_dir / repo["name"].replace("/", "__")
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", repo["url"], str(dest)],
            capture_output=True, timeout=120, check=True,
        )
        return dest
    except subprocess.TimeoutExpired:
        print(f"  TIMEOUT cloning {repo['name']}")
    except subprocess.CalledProcessError as e:
        print(f"  FAILED cloning {repo['name']}: {e.stderr.decode()[:100] if e.stderr else 'unknown'}")
    except FileNotFoundError:
        print("  git not found on PATH — skipping clone")
    return None


def collect_java_files(root: Path) -> list[Path]:
    """Find all .java files, skipping ignored dirs."""
    files = []
    for path in root.rglob("*.java"):
        parts = set(path.parts)
        if parts & IGNORE_DIRS:
            continue
        files.append(path)
    return files


def scan_java_files(file_paths: list[Path]) -> dict[str, Any]:
    """Scan all Java files and collect findings, with per-file timeout."""
    import concurrent.futures
    results = []
    total_findings = 0
    total_loc = 0

    for fp in file_paths:
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(scan_file, fp)
                result = future.result(timeout=30)
        except concurrent.futures.TimeoutError:
            print(f"  TIMEOUT {fp.name} — skipping")
            continue
        except Exception as e:
            print(f"  SCAN ERROR {fp.name}: {e}")
            continue

        findings_list = []
        for f in result.sorted_findings():
            findings_list.append({
                "rule_id": f.rule_id or "",
                "title": f.title or "",
                "severity": f.severity.value if f.severity else "info",
                "line": f.line or 0,
                "cwe": f.cwe or "",
                "description": (f.description or "")[:200],
                "suggestion": (f.suggestion or "")[:200],
            })

        total_findings += len(findings_list)
        total_loc += result.lines_scanned

        results.append({
            "file_path": str(fp.relative_to(fp.parents[min(len(fp.parents)-1, 3)])),
            "absolute_path": str(fp),
            "language": "java",
            "lines_scanned": result.lines_scanned,
            "parse_error": result.parse_error or "",
            "findings": findings_list,
        })

    return {
        "files": results,
        "total_findings": total_findings,
        "total_loc": total_loc,
    }


def main():
    parser = argparse.ArgumentParser(description="Blind audit sampler for Java repos")
    parser.add_argument("--repos", type=int, default=20, help="Number of repos to sample")
    parser.add_argument("--seed", type=int, default=None, help="Random seed")
    parser.add_argument("--output", type=str, default="benchmarks/audit_results/round1_java.json")
    parser.add_argument("--keep-repos", action="store_true")
    args = parser.parse_args()

    seed = args.seed or random.randint(1, 100000)
    print(f"Seed: {seed}")
    print(f"Target: {args.repos} Java repos\n")

    # Search for repos
    print("=== Searching GitHub for Java repos ===")
    candidates = search_github_java_repos(seed)
    print(f"Found {len(candidates)} candidates\n")

    # Clone and scan
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    all_repo_results = []
    repos_scanned = 0
    total_findings = 0
    total_loc = 0
    total_files = 0

    for i, repo in enumerate(candidates):
        if repos_scanned >= args.repos:
            break

        print(f"[{repos_scanned+1}/{args.repos}] {repo['name']} ({repo['stars']}★, {repo['size_kb']}KB)")

        repo_dir = clone_repo(repo, CACHE_DIR)
        if repo_dir is None:
            print(f"  SKIP — clone failed\n")
            continue

        java_files = collect_java_files(repo_dir)
        if not java_files:
            print(f"  SKIP — no .java files found\n")
            if not args.keep_repos:
                shutil.rmtree(repo_dir, ignore_errors=True)
            continue

        print(f"  {len(java_files)} .java files — scanning...")
        t0 = time.time()
        scan_data = scan_java_files(java_files)
        elapsed = time.time() - t0

        repos_scanned += 1
        total_findings += scan_data["total_findings"]
        total_loc += scan_data["total_loc"]
        total_files += len(java_files)

        all_repo_results.append({
            "name": repo["name"],
            "stars": repo["stars"],
            "size_kb": repo["size_kb"],
            "java_files": len(java_files),
            "loc": scan_data["total_loc"],
            "findings_count": scan_data["total_findings"],
            "scan_time_s": round(elapsed, 2),
            "files": scan_data["files"],
        })

        print(f"  Done: {scan_data['total_findings']} findings, {scan_data['total_loc']} LOC, {elapsed:.1f}s\n")

        if not args.keep_repos:
            shutil.rmtree(repo_dir, ignore_errors=True)

    # Build summary
    cwe_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    for repo_result in all_repo_results:
        for file_data in repo_result["files"]:
            for f in file_data["findings"]:
                cwe = f.get("cwe", "") or "unknown"
                cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
                sev = f.get("severity", "info")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

    repos_with_findings = sum(1 for r in all_repo_results if r["findings_count"] > 0)

    output = {
        "run_info": {
            "date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "seed": seed,
            "target_repos": args.repos,
            "language": "java",
        },
        "summary": {
            "repos_scanned": repos_scanned,
            "repos_with_findings": repos_with_findings,
            "repos_silent": repos_scanned - repos_with_findings,
            "total_files": total_files,
            "total_loc": total_loc,
            "total_findings": total_findings,
            "by_cwe": dict(sorted(cwe_counts.items(), key=lambda x: -x[1])),
            "by_severity": severity_counts,
        },
        "repos": all_repo_results,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2), encoding="utf-8")

    print("=" * 60)
    print(f"COMPLETE: {repos_scanned} repos scanned")
    print(f"  Files: {total_files}")
    print(f"  LOC: {total_loc:,}")
    print(f"  Findings: {total_findings}")
    print(f"  Repos with findings: {repos_with_findings}")
    print(f"  Silent repos: {repos_scanned - repos_with_findings}")
    print(f"  By CWE: {json.dumps(dict(sorted(cwe_counts.items(), key=lambda x: -x[1])), indent=4)}")
    print(f"  Report: {output_path}")


if __name__ == "__main__":
    main()
