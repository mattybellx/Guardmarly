#!/usr/bin/env python3
"""
pr_bot.py — Automated PR submission bot for ansede-static.

Scans top open-source packages for security vulnerabilities, generates
fix PRs with the --pr flag, and tracks submission metrics.

Usage:
    python tools/pr_bot.py --targets top-pypi.json --dry-run
    python tools/pr_bot.py --targets top-pypi.json --submit

Target format (JSON):
    [
      {"repo": "owner/repo", "language": "python", "clone_url": "...", "stars": 5000},
      ...
    ]

Setup:
    export GITHUB_TOKEN=ghp_xxx
    pip install ansede-static
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ── Config ──────────────────────────────────────────────────────────────────

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
API_BASE = "https://api.github.com"
HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "User-Agent": "ansede-pr-bot/1.0",
}

REPO_ROOT = Path(__file__).resolve().parent.parent


def log(msg: str) -> None:
    """Timestamped log line."""
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def api(method: str, url: str, data: dict | None = None) -> dict | None:
    """Make a GitHub API request."""
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            resp_body = r.read()
            return json.loads(resp_body) if resp_body else {}
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        log(f"  API {method} {url} -> HTTP {e.code}: {error_body[:200]}")
        return None


def clone_repo(clone_url: str, target_dir: Path) -> bool:
    """Shallow clone a repo."""
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", clone_url, str(target_dir)],
            capture_output=True, text=True, timeout=120,
        )
        return target_dir.exists()
    except (subprocess.TimeoutExpired, Exception) as exc:
        log(f"  Clone failed: {exc}")
        return False


def run_ansede_scan(repo_dir: Path) -> dict | None:
    """Run ansede-static on a repo directory, return JSON findings."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "ansede_static.cli", str(repo_dir),
             "--format", "json", "--fail-on", "never"],
            capture_output=True, text=True, timeout=300,
            cwd=str(REPO_ROOT),
            env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")},
        )
        if result.returncode != 0 and not result.stdout.strip():
            return None
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as exc:
        log(f"  Scan error: {exc}")
        return None


def generate_pr_document(repo_dir: Path, findings: dict) -> str | None:
    """Use --pr flag to generate a PR markdown document."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "ansede_static.cli", str(repo_dir),
             "--format", "json", "--pr", "--fail-on", "never"],
            capture_output=True, text=True, timeout=300,
            cwd=str(REPO_ROOT),
            env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")},
        )
        # --pr writes to ansede-pr.md
        pr_file = repo_dir / "ansede-pr.md"
        if pr_file.exists():
            return pr_file.read_text(encoding="utf-8")
        return None
    except Exception as exc:
        log(f"  PR doc generation failed: {exc}")
        return None


def fork_repo(owner: str, repo: str) -> str | None:
    """Fork a repo, return fork full name (e.g., 'myuser/repo')."""
    result = api("POST", f"{API_BASE}/repos/{owner}/{repo}/forks")
    if result:
        return result.get("full_name")
    return None


def create_pr(owner: str, repo: str, branch: str, base: str,
              title: str, body: str) -> str | None:
    """Create a PR from a fork branch."""
    result = api("POST", f"{API_BASE}/repos/{owner}/{repo}/pulls", {
        "title": title,
        "head": branch,
        "base": base,
        "body": body,
    })
    if result:
        return result.get("html_url")
    return None


def process_target(target: dict, dry_run: bool = False) -> dict:
    """Process a single target repo: clone, scan, generate PR.

    Returns a result dict with status, findings count, PR URL (if any).
    """
    repo_name = target["repo"]
    owner, repo = repo_name.split("/")
    clone_url = target.get("clone_url", f"https://github.com/{repo_name}.git")

    result = {
        "repo": repo_name,
        "status": "unknown",
        "findings_count": 0,
        "critical_count": 0,
        "high_count": 0,
        "pr_url": None,
        "error": None,
    }

    log(f"Processing {repo_name}...")

    with tempfile.TemporaryDirectory(prefix="ansede-prbot-") as tmp:
        repo_dir = Path(tmp) / repo
        if not clone_repo(clone_url, repo_dir):
            result["status"] = "clone_failed"
            return result

        findings = run_ansede_scan(repo_dir)
        if findings is None:
            result["status"] = "scan_failed"
            return result

        total = findings.get("total_findings", 0)
        results_list = findings.get("results", [])
        critical = sum(
            len([f for f in r.get("findings", [])
                 if f.get("severity", "").lower() == "critical"])
            for r in results_list
        )
        high = sum(
            len([f for f in r.get("findings", [])
                 if f.get("severity", "").lower() == "high"])
            for r in results_list
        )

        result["findings_count"] = total
        result["critical_count"] = critical
        result["high_count"] = high

        if total == 0:
            result["status"] = "clean"
            log(f"  {repo_name}: clean (0 findings)")
            return result

        log(f"  {repo_name}: {total} findings ({critical} critical, {high} high)")

        if dry_run:
            result["status"] = "dry_run"
            return result

        # Generate PR document
        pr_body = generate_pr_document(repo_dir, findings)
        if not pr_body:
            result["status"] = "no_pr_doc"
            return result

        # Try to fork and submit PR
        fork_name = fork_repo(owner, repo)
        if not fork_name:
            result["status"] = "fork_failed"
            return result

        pr_url = create_pr(
            owner, repo,
            branch=f"{fork_name.split('/')[0]}:add-ansede-fixes",
            base="main",
            title=f"Security fixes detected by ansede-static ({total} findings)",
            body=pr_body,
        )

        if pr_url:
            result["status"] = "pr_submitted"
            result["pr_url"] = pr_url
            log(f"  PR submitted: {pr_url}")
        else:
            result["status"] = "pr_failed"

    return result


def load_targets(path: str) -> list[dict]:
    """Load target repos from JSON file."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "targets" in data:
        return data["targets"]
    raise ValueError("Targets file must be a JSON array or have a 'targets' key")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ansede-static PR auto-submission bot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tools/pr_bot.py --targets top-pypi.json --dry-run
  python tools/pr_bot.py --targets top-pypi.json --submit --max-repos 5
  python tools/pr_bot.py --targets top-pypi.json --submit --min-findings 3
        """,
    )
    parser.add_argument("--targets", required=True, help="JSON file with target repos")
    parser.add_argument("--dry-run", action="store_true", help="Scan only, no PR submission")
    parser.add_argument("--submit", action="store_true", help="Actually submit PRs")
    parser.add_argument("--max-repos", type=int, default=10, help="Max repos to process")
    parser.add_argument("--min-findings", type=int, default=1,
                        help="Only submit PR if at least this many findings")
    parser.add_argument("--min-stars", type=int, default=100,
                        help="Only process repos with at least this many stars")
    parser.add_argument("--output", default="pr_bot_results.json",
                        help="Output JSON file for results")
    args = parser.parse_args()

    if not GITHUB_TOKEN and args.submit:
        log("ERROR: GITHUB_TOKEN environment variable is required for PR submission.")
        sys.exit(1)

    targets = load_targets(args.targets)
    log(f"Loaded {len(targets)} targets from {args.targets}")

    # Filter by stars
    targets = [t for t in targets if t.get("stars", 0) >= args.min_stars]
    log(f"Filtered to {len(targets)} targets with >= {args.min_stars} stars")

    # Limit
    targets = targets[:args.max_repos]
    log(f"Processing up to {len(targets)} repos")

    results = []
    start_time = time.time()

    for i, target in enumerate(targets, 1):
        log(f"[{i}/{len(targets)}] {target['repo']}")
        result = process_target(target, dry_run=args.dry_run or not args.submit)

        # Apply min-findings filter
        if result["findings_count"] < args.min_findings and result["status"] == "dry_run":
            result["status"] = "below_threshold"

        results.append(result)

        # Rate limit: 1 request per 2 seconds to avoid GitHub API abuse
        if not (args.dry_run or not args.submit):
            time.sleep(2)

    elapsed = time.time() - start_time

    # Summary
    statuses = {}
    for r in results:
        statuses[r["status"]] = statuses.get(r["status"], 0) + 1

    total_findings = sum(r["findings_count"] for r in results)
    prs_submitted = sum(1 for r in results if r["status"] == "pr_submitted")

    log("\n" + "=" * 60)
    log(f"COMPLETE — {len(results)} repos in {elapsed:.1f}s")
    log(f"  Total findings: {total_findings}")
    log(f"  PRs submitted: {prs_submitted}")
    for status, count in sorted(statuses.items()):
        log(f"  {status}: {count}")
    log("=" * 60)

    # Save results
    output_path = Path(args.output)
    output_path.write_text(json.dumps({
        "run_at": datetime.now(timezone.utc).isoformat(),
        "targets_file": args.targets,
        "dry_run": args.dry_run or not args.submit,
        "total_repos": len(results),
        "total_findings": total_findings,
        "prs_submitted": prs_submitted,
        "status_counts": statuses,
        "elapsed_seconds": round(elapsed, 1),
        "results": results,
    }, indent=2), encoding="utf-8")
    log(f"Results written to {output_path}")


if __name__ == "__main__":
    main()
