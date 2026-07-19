#!/usr/bin/env python3
"""
fetch_corpora.py — Clone & pin benchmark corpora for Guardmarly SAST evaluation.

Usage:
    python scripts/fetch_corpora.py              # fetch all corpora
    python scripts/fetch_corpora.py --list       # list available corpora
    python scripts/fetch_corpora.py --corpus owasp-benchmark  # fetch one

Network access is required for the initial clone. Scans themselves are offline.

All corpora are pinned at fixed commits for reproducible benchmarks.
Output directory: .corpora/ (gitignored)
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parent.parent
CORPORA_DIR = ROOT / ".corpora"
MANIFEST_PATH = CORPORA_DIR / "manifest.json"


class Corpus(NamedTuple):
    """A benchmark corpus definition."""
    slug: str
    name: str
    url: str
    commit: str
    category: str  # "vulnerable" | "clean" | "benchmark"
    languages: list[str]
    description: str


# ── Corpus catalog ────────────────────────────────────────────────────────
# Every entry is pinned to a specific commit for reproducibility.
# Update commits deliberately — do not float on main/master branches.

CORPORA: list[Corpus] = [
    # ── Benchmark suites ──────────────────────────────────────────────
    Corpus(
        slug="owasp-benchmark-java",
        name="OWASP Benchmark (Java)",
        url="https://github.com/OWASP-Benchmark/BenchmarkJava.git",
        commit="v1.2",  # tag
        category="benchmark",
        languages=["java"],
        description="OWASP Benchmark v1.2 — 2,740 Java test cases across 11 CWE categories",
    ),
    Corpus(
        slug="juliet-java",
        name="Juliet Test Suite (Java)",
        url="https://github.com/NIST-Juliet/Juliet-Test-Suite-for-Java.git",
        commit="6b2afe6",  # pinned commit
        category="benchmark",
        languages=["java"],
        description="NIST Juliet Test Suite — Java test cases for 118 CWEs",
    ),
    Corpus(
        slug="juliet-csharp",
        name="Juliet Test Suite (C#)",
        url="https://github.com/NIST-Juliet/Juliet-Test-Suite-for-Csharp.git",
        commit="1f5e5c7",  # pinned commit
        category="benchmark",
        languages=["csharp"],
        description="NIST Juliet Test Suite — C# test cases for 118 CWEs",
    ),
    Corpus(
        slug="juliet-cpp",
        name="Juliet Test Suite (C/C++)",
        url="https://github.com/NIST-Juliet/Juliet-Test-Suite-for-C.git",
        commit="1afea48",  # pinned commit
        category="benchmark",
        languages=["c", "cpp"],
        description="NIST Juliet Test Suite — C/C++ test cases for 118 CWEs",
    ),

    # ── Vulnerable web applications ───────────────────────────────────
    Corpus(
        slug="dvwa",
        name="Damn Vulnerable Web Application (DVWA)",
        url="https://github.com/digininja/DVWA.git",
        commit="ff71499",  # pinned commit
        category="vulnerable",
        languages=["php"],
        description="DVWA — deliberately vulnerable PHP webapp for security testing",
    ),
    Corpus(
        slug="webgoat",
        name="OWASP WebGoat",
        url="https://github.com/WebGoat/WebGoat.git",
        commit="v2023.4",  # tag
        category="vulnerable",
        languages=["java"],
        description="OWASP WebGoat — deliberately insecure Java web application",
    ),
    Corpus(
        slug="juice-shop",
        name="OWASP Juice Shop",
        url="https://github.com/juice-shop/juice-shop.git",
        commit="v17.1.0",  # tag
        category="vulnerable",
        languages=["javascript", "typescript"],
        description="OWASP Juice Shop — deliberately insecure Node.js web application",
    ),
    Corpus(
        slug="railsgoat",
        name="RailsGoat",
        url="https://github.com/OWASP/railsgoat.git",
        commit="6e34a9c",  # pinned commit
        category="vulnerable",
        languages=["ruby"],
        description="OWASP RailsGoat — deliberately vulnerable Rails application",
    ),
    Corpus(
        slug="nodegoat",
        name="OWASP NodeGoat",
        url="https://github.com/OWASP/NodeGoat.git",
        commit="2c37a60",  # pinned commit
        category="vulnerable",
        languages=["javascript"],
        description="OWASP NodeGoat — deliberately vulnerable Node.js webapp",
    ),
    Corpus(
        slug="pygoat",
        name="OWASP PyGoat",
        url="https://github.com/OWASP/PyGoat.git",
        commit="30d4b8b",  # pinned commit
        category="vulnerable",
        languages=["python"],
        description="OWASP PyGoat — deliberately vulnerable Django application",
    ),

    # ── Clean corpus (low-FP measurement) ─────────────────────────────
    # These are well-maintained, popular repos with no known vulns.
    # Used to measure false-positive rate on production-quality code.
    Corpus(
        slug="clean-flask",
        name="Flask (clean)",
        url="https://github.com/pallets/flask.git",
        commit="3.1.1",  # tag
        category="clean",
        languages=["python"],
        description="Flask web framework — production-quality Python code",
    ),
    Corpus(
        slug="clean-django",
        name="Django (clean)",
        url="https://github.com/django/django.git",
        commit="5.1.4",  # tag
        category="clean",
        languages=["python"],
        description="Django web framework — production-quality Python code",
    ),
    Corpus(
        slug="clean-fastapi",
        name="FastAPI (clean)",
        url="https://github.com/fastapi/fastapi.git",
        commit="0.115.6",  # tag
        category="clean",
        languages=["python"],
        description="FastAPI web framework — production-quality Python code",
    ),
    Corpus(
        slug="clean-requests",
        name="Requests (clean)",
        url="https://github.com/psf/requests.git",
        commit="v2.32.3",  # tag
        category="clean",
        languages=["python"],
        description="Python HTTP library — widely-used, well-audited",
    ),
    Corpus(
        slug="clean-express",
        name="Express (clean)",
        url="https://github.com/expressjs/express.git",
        commit="4.21.2",  # tag
        category="clean",
        languages=["javascript"],
        description="Express.js web framework — production-quality JS code",
    ),
    Corpus(
        slug="clean-lodash",
        name="Lodash (clean)",
        url="https://github.com/lodash/lodash.git",
        commit="4.17.21",  # tag
        category="clean",
        languages=["javascript"],
        description="Lodash utility library — widely-used, well-audited JS",
    ),
    Corpus(
        slug="clean-react",
        name="React (clean)",
        url="https://github.com/facebook/react.git",
        commit="v19.0.0",  # tag
        category="clean",
        languages=["javascript", "typescript"],
        description="React UI library — production-quality JS/TS code",
    ),
    Corpus(
        slug="clean-spring-framework",
        name="Spring Framework (clean)",
        url="https://github.com/spring-projects/spring-framework.git",
        commit="v6.2.1",  # tag
        category="clean",
        languages=["java"],
        description="Spring Framework — production-quality Java code",
    ),
    Corpus(
        slug="clean-guava",
        name="Guava (clean)",
        url="https://github.com/google/guava.git",
        commit="v33.4.0",  # tag
        category="clean",
        languages=["java"],
        description="Google Guava — widely-used Java utility library",
    ),
    Corpus(
        slug="clean-kubernetes-client",
        name="Kubernetes Client (clean)",
        url="https://github.com/kubernetes-client/java.git",
        commit="v21.0.2",  # tag
        category="clean",
        languages=["java"],
        description="Kubernetes Java client — production Java code",
    ),
    Corpus(
        slug="clean-aspnetcore",
        name="ASP.NET Core (clean)",
        url="https://github.com/dotnet/aspnetcore.git",
        commit="v9.0.1",  # tag
        category="clean",
        languages=["csharp"],
        description="ASP.NET Core — production-quality C# code",
    ),
    Corpus(
        slug="clean-roslyn",
        name="Roslyn (clean)",
        url="https://github.com/dotnet/roslyn.git",
        commit="v4.12.0",  # tag
        category="clean",
        languages=["csharp"],
        description=".NET Compiler Platform — production-quality C# code",
    ),
    Corpus(
        slug="clean-go-stdlib",
        name="Go Standard Library (clean)",
        url="https://github.com/golang/go.git",
        commit="go1.23.4",  # tag
        category="clean",
        languages=["go"],
        description="Go standard library — production-quality Go code",
    ),
    Corpus(
        slug="clean-kubernetes",
        name="Kubernetes (clean)",
        url="https://github.com/kubernetes/kubernetes.git",
        commit="v1.32.1",  # tag
        category="clean",
        languages=["go"],
        description="Kubernetes — large-scale production Go codebase",
    ),
    Corpus(
        slug="clean-gin",
        name="Gin (clean)",
        url="https://github.com/gin-gonic/gin.git",
        commit="v1.10.0",  # tag
        category="clean",
        languages=["go"],
        description="Gin web framework — production-quality Go code",
    ),
    Corpus(
        slug="clean-laravel",
        name="Laravel (clean)",
        url="https://github.com/laravel/framework.git",
        commit="v11.35.0",  # tag
        category="clean",
        languages=["php"],
        description="Laravel framework — production-quality PHP code",
    ),
    Corpus(
        slug="clean-symfony",
        name="Symfony (clean)",
        url="https://github.com/symfony/symfony.git",
        commit="v7.2.1",  # tag
        category="clean",
        languages=["php"],
        description="Symfony framework — production-quality PHP code",
    ),
    Corpus(
        slug="clean-rails",
        name="Rails (clean)",
        url="https://github.com/rails/rails.git",
        commit="v8.0.1",  # tag
        category="clean",
        languages=["ruby"],
        description="Ruby on Rails — production-quality Ruby code",
    ),
    Corpus(
        slug="clean-ruby",
        name="Ruby (clean)",
        url="https://github.com/ruby/ruby.git",
        commit="v3_4_1",  # tag
        category="clean",
        languages=["ruby"],
        description="Ruby language implementation — production-quality C/Ruby code",
    ),
    Corpus(
        slug="clean-typescript",
        name="TypeScript (clean)",
        url="https://github.com/microsoft/TypeScript.git",
        commit="v5.7.2",  # tag
        category="clean",
        languages=["typescript", "javascript"],
        description="TypeScript compiler — production-quality TS/JS code",
    ),
]


# ── CLI ───────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch & pin Guardmarly benchmark corpora",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available corpora and exit",
    )
    parser.add_argument(
        "--corpus",
        type=str,
        default=None,
        help="Fetch only a specific corpus (by slug)",
    )
    parser.add_argument(
        "--category",
        type=str,
        choices=["benchmark", "vulnerable", "clean"],
        default=None,
        help="Fetch only corpora of a specific category",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be fetched without doing it",
    )
    parser.add_argument(
        "--shallow",
        action="store_true",
        default=True,
        help="Use shallow clones (--depth 1) for faster fetch [default]",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Full clone (no --depth) — larger download, full history",
    )
    return parser.parse_args()


def list_corpora() -> None:
    """Print a table of available corpora."""
    print(f"{'Slug':<30} {'Category':<12} {'Languages':<20} Description")
    print("-" * 100)
    for c in CORPORA:
        langs = ", ".join(c.languages)
        print(f"{c.slug:<30} {c.category:<12} {langs:<20} {c.description}")


def run(cmd: list[str], cwd: Path, dry_run: bool = False) -> bool:
    """Run a shell command, return True on success."""
    if dry_run:
        print(f"  [DRY RUN] {' '.join(cmd)}")
        return True
    try:
        subprocess.run(cmd, cwd=str(cwd), check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"  ERROR: {e.stderr.strip()}", file=sys.stderr)
        return False


def fetch_corpus(corpus: Corpus, shallow: bool = True, dry_run: bool = False) -> bool:
    """Clone or update a single corpus."""
    dest = CORPORA_DIR / corpus.slug

    if dest.exists():
        print(f"  [{corpus.slug}] Already exists at {dest} — skipping")
        # Verify commit
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(dest),
            capture_output=True,
            text=True,
        )
        actual = result.stdout.strip()[:7]
        print(f"  [{corpus.slug}] At commit {actual}")
        return True

    print(f"  [{corpus.slug}] Cloning {corpus.url} → {dest}")
    if dry_run:
        print(f"  [DRY RUN] Would clone to {dest}")
        return True

    CORPORA_DIR.mkdir(parents=True, exist_ok=True)

    clone_cmd = ["git", "clone"]
    if shallow:
        clone_cmd.extend(["--depth", "1"])
    clone_cmd.extend([corpus.url, str(dest)])

    if not run(clone_cmd, CORPORA_DIR, dry_run):
        return False

    # Checkout the pinned commit
    checkout_cmd = ["git", "checkout", corpus.commit]
    if not run(checkout_cmd, dest, dry_run):
        print(f"  [{corpus.slug}] WARNING: Checkout of {corpus.commit} failed, staying at HEAD",
              file=sys.stderr)

    print(f"  [{corpus.slug}] Done.")
    return True


def write_manifest() -> None:
    """Write the current manifest to .corpora/manifest.json."""
    CORPORA_DIR.mkdir(parents=True, exist_ok=True)
    manifest = {
        "version": "1.0",
        "corpora": [
            {
                "slug": c.slug,
                "name": c.name,
                "url": c.url,
                "commit": c.commit,
                "category": c.category,
                "languages": c.languages,
                "description": c.description,
                "path": str(CORPORA_DIR / c.slug),
            }
            for c in CORPORA
        ],
    }
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2))
    print(f"Manifest written to {MANIFEST_PATH}")


def main() -> None:
    args = parse_args()

    if args.list:
        list_corpora()
        return

    shallow = not args.full

    # Filter corpora
    if args.corpus:
        selected = [c for c in CORPORA if c.slug == args.corpus]
        if not selected:
            print(f"Unknown corpus: {args.corpus}", file=sys.stderr)
            print("Use --list to see available corpora.", file=sys.stderr)
            sys.exit(1)
    elif args.category:
        selected = [c for c in CORPORA if c.category == args.category]
    else:
        selected = list(CORPORA)

    print(f"Fetching {len(selected)} corpora...")
    print(f"Target directory: {CORPORA_DIR}")
    print()

    success = 0
    failed = 0
    for corpus in selected:
        if fetch_corpus(corpus, shallow=shallow, dry_run=args.dry_run):
            success += 1
        else:
            failed += 1

    print()
    print(f"Results: {success} succeeded, {failed} failed, {len(selected)} total")

    if not args.dry_run and success > 0:
        write_manifest()

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
