"""
tools.check_binary_guardrails
─────────────────────────────
DIR-5.3 guardrail enforcement: dependency and size checks.

Ensures:
  1. `pyproject.toml` declares only `rich` as the sole production dependency.
  2. Built wheel / installed package stays under 10 MB.

Exit codes:
    0 — all guardrails pass
    1 — one or more guardrails fail
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
MAX_SIZE_MB = 10.0
ALLOWED_DEPS: frozenset[str] = frozenset({"rich"})


def _check_dependencies(*, quiet: bool = False) -> list[str]:
    """Check pyproject.toml for disallowed production dependencies."""
    failures: list[str] = []
    if not PYPROJECT.exists():
        failures.append(f"pyproject.toml not found at {PYPROJECT}")
        return failures

    try:
        import tomllib  # Python 3.11+ stdlib
    except ImportError:
        import tomli as tomllib  # Python <3.11 backport

    try:
        data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    except Exception as exc:
        failures.append(f"Failed to parse pyproject.toml: {exc}")
        return failures

    deps: list[str] = data.get("project", {}).get("dependencies", [])
    disallowed: list[str] = []
    for dep in deps:
        pkg_name = dep.split(">=")[0].split("==")[0].split("<")[0].split("~")[0].strip()
        if pkg_name not in ALLOWED_DEPS:
            disallowed.append(dep)

    if disallowed:
        failures.append(
            f"Disallowed production dependencies found ({len(disallowed)}): {', '.join(disallowed)}"
        )
    elif not quiet:
        allowed_list = ", ".join(sorted(ALLOWED_DEPS))
        print(f"  [OK] Production dependencies: only allowed ({allowed_list})")
    return failures


def _check_dist_size(*, quiet: bool = False) -> list[str]:
    """Check wheel / sdist size against the 10 MB limit."""
    failures: list[str] = []

    dist_dir = ROOT / "dist"
    if not dist_dir.exists():
        if not quiet:
            print("  ~ dist/ directory not found — skipping size check (run `pip install build && python -m build` first)")
        return failures

    total_bytes = 0
    for artifact in dist_dir.iterdir():
        if artifact.is_file() and artifact.suffix in {".whl", ".tar.gz", ".zip"}:
            total_bytes += artifact.stat().st_size

    if total_bytes == 0:
        if not quiet:
            print("  ~ No wheel/sdist artifacts in dist/ — skipping size check")
        return failures

    size_mb = total_bytes / (1024 * 1024)
    if size_mb > MAX_SIZE_MB:
        failures.append(
            f"Distribution size {size_mb:.2f} MB exceeds {MAX_SIZE_MB:.2f} MB limit"
        )
    elif not quiet:
        print(f"  [OK] Distribution size: {size_mb:.2f} MB (limit: {MAX_SIZE_MB:.2f} MB)")
    return failures


def _check_ls_factor(*, quiet: bool = False) -> list[str]:
    """Ensure the library stays lean by checking src/ansede_static total size."""
    failures: list[str] = []
    src_dir = ROOT / "src" / "ansede_static"
    if not src_dir.exists():
        failures.append(f"Source directory not found: {src_dir}")
        return failures

    # Exclude .pyc bytecode cache files (not distributed)
    total_bytes = sum(
        f.stat().st_size for f in src_dir.rglob("*")
        if f.is_file() and f.suffix != ".pyc"
    )
    size_mb = total_bytes / (1024 * 1024)
    # The src tree is distributed; flag if it exceeds the binary-size budget.
    if size_mb > MAX_SIZE_MB:
        failures.append(
            f"Source tree {size_mb:.2f} MB exceeds {MAX_SIZE_MB:.2f} MB limit "
            "(install-time size, excluding .pyc)"
        )
    elif not quiet:
        print(f"  [OK] Source tree size: {size_mb:.2f} MB (limit: {MAX_SIZE_MB:.2f} MB, excluding .pyc)")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="DIR-5.3 guardrail enforcement")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    json_mode = args.json
    all_failures: list[str] = []
    all_failures.extend(_check_dependencies(quiet=json_mode))
    all_failures.extend(_check_dist_size(quiet=json_mode))
    all_failures.extend(_check_ls_factor(quiet=json_mode))

    passed = len(all_failures) == 0
    result = {
        "kind": "ansede-binary-guardrails",
        "version": 1,
        "max_size_mb": MAX_SIZE_MB,
        "passed": passed,
        "failures": all_failures,
    }

    if args.json:
        print(json.dumps(result, indent=2))
        return 0 if passed else 1

    print("DIR-5.3 binary and dependency guardrails")
    print("=" * 50)
    print(f"  Max size: {MAX_SIZE_MB} MB")
    print()
    print(f"  Result: {'[OK] PASS' if passed else '[!!] FAIL'}")
    if all_failures:
        for f in all_failures:
            print(f"    - {f}")
    print()

    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
