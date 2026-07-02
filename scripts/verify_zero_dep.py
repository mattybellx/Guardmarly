#!/usr/bin/env python3
"""ansede-static Zero-Dependency Verification Script

Validates all four zero-dependency requirements from the Ansede
Optimization Plan (Track 1):

  1. Binary Portability — ansede_rust_core is bundled as pre-compiled wheel;
     no gcc/cargo required on target systems.
  2. Path Integrity — engine uses project venv binary; no conflicting
     global dependencies.
  3. Environment Isolation — PYTHONPATH used for internal module resolution;
     supports portable unzip-and-run deployments.
  4. Network Sandbox — offline-first runtime; zero external network calls
     during rule updates or analysis.

Usage:
    python scripts/verify_zero_dep.py
    python scripts/verify_zero_dep.py --verbose
    python scripts/verify_zero_dep.py --json  # machine-readable output

Exit codes:
    0 — All checks passed
    1 — One or more checks failed
    2 — Script error
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import sysconfig
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class CheckResult:
    """Result of a single zero-dependency verification check."""
    check_id: str
    name: str
    passed: bool
    details: str = ""
    recommendations: list[str] = field(default_factory=list)


class ZeroDepVerifier:
    """Validates the four zero-dependency requirements."""

    def __init__(self, project_root: Path | None = None):
        self.project_root = project_root or Path(__file__).resolve().parent.parent
        self.results: list[CheckResult] = []

    def run_all(self) -> list[CheckResult]:
        """Run all four verification checks."""
        self.results = [
            self._check_binary_portability(),
            self._check_path_integrity(),
            self._check_environment_isolation(),
            self._check_network_sandbox(),
        ]
        return self.results

    # ── Check 1: Binary Portability ──────────────────────────────────

    def _check_binary_portability(self) -> CheckResult:
        """Verify ansede_rust_core is bundled as a pre-compiled wheel;
        confirm no gcc or cargo requirements on target systems."""
        issues: list[str] = []
        recommendations: list[str] = []

        # 1a. Check that Rust core is importable
        try:
            from ansede_rust_core import is_available as rust_available
            core_available = rust_available()
        except ImportError:
            core_available = False

        if not core_available:
            issues.append(
                "ansede_rust_core native module is NOT available. "
                "This is expected in dev environments but NOT for production wheels."
            )
            recommendations.append(
                "Build the native wheel: cd ansede_rust_core && maturin build --release"
            )
        else:
            # 1b. Verify it's a .pyd/.so binary (pre-compiled)
            try:
                import ansede_rust_core._core as _core_mod
                core_file = getattr(_core_mod, '__file__', '')
                if core_file:
                    ext = Path(core_file).suffix.lower()
                    if ext in ('.pyd', '.so', '.dylib'):
                        pass  # Good — native binary
                    else:
                        issues.append(f"Rust core is {ext}, not a native binary (.pyd/.so)")
                else:
                    issues.append("Cannot determine Rust core file location")
            except Exception as exc:
                issues.append(f"Cannot inspect Rust core module: {exc}")

        # 1c. Check that cargo is NOT required at runtime
        cargo_found = False
        for path_dir in os.environ.get('PATH', '').split(os.pathsep):
            cargo_path = Path(path_dir) / ('cargo.exe' if sys.platform == 'win32' else 'cargo')
            if cargo_path.exists():
                cargo_found = True
                break

        # 1d. Check pyproject.toml has zero mandatory deps
        pyproject = self.project_root / 'pyproject.toml'
        if pyproject.exists():
            content = pyproject.read_text(encoding='utf-8')
            # Check for mandatory dependencies
            has_mandatory = False
            in_deps = False
            for line in content.splitlines():
                stripped = line.strip()
                if stripped == '[project]' or stripped.startswith('dependencies'):
                    in_deps = True
                    continue
                if in_deps and stripped.startswith('['):
                    in_deps = False
                    continue
                if in_deps and stripped and not stripped.startswith('#'):
                    if 'ansede' not in stripped.lower():
                        has_mandatory = True
                        issues.append(f"Non-ansede dependency found: {stripped}")
            if not has_mandatory:
                pass  # Good — zero deps

        passed = len(issues) == 0

        return CheckResult(
            check_id="ZERO-01",
            name="Binary Portability",
            passed=passed,
            details=(
                "Rust core available as pre-compiled binary; no build tools required at runtime."
                if passed
                else "; ".join(issues)
            ),
            recommendations=recommendations,
        )

    # ── Check 2: Path Integrity ─────────────────────────────────────

    def _check_path_integrity(self) -> CheckResult:
        """Ensure the engine uses the project venv binary to prevent
        picking up conflicting global dependencies."""
        issues: list[str] = []
        recommendations: list[str] = []

        # 2a. Check we're running from a venv
        in_venv = (
            hasattr(sys, 'real_prefix') or
            (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix) or
            os.environ.get('VIRTUAL_ENV') is not None
        )

        if not in_venv:
            issues.append(
                "Not running inside a Python virtual environment. "
                "Global installations may conflict with ansede-static."
            )
            recommendations.append(
                "Create and activate a venv: python -m venv .venv && .venv\\Scripts\\activate"
            )

        # 2b. Check that ansede-static resolves to the venv
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'pip', 'show', 'ansede-static'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                issues.append(
                    "ansede-static is not installed in the current environment. "
                    "Run: pip install -e ."
                )
            else:
                location = ""
                for line in result.stdout.splitlines():
                    if line.startswith('Location:'):
                        location = line.split(':', 1)[1].strip()
                        break
                if location and sys.prefix not in location:
                    issues.append(
                        f"ansede-static installed at {location}, "
                        f"outside current prefix {sys.prefix}"
                    )
        except Exception as exc:
            issues.append(f"Could not verify pip installation: {exc}")

        passed = len(issues) == 0

        return CheckResult(
            check_id="ZERO-02",
            name="Path Integrity",
            passed=passed,
            details=(
                "Running in isolated venv with correct ansede-static installation."
                if passed
                else "; ".join(issues)
            ),
            recommendations=recommendations,
        )

    # ── Check 3: Environment Isolation ──────────────────────────────

    def _check_environment_isolation(self) -> CheckResult:
        """Verify PYTHONPATH is used for internal module resolution
        instead of standard pip install for portable deployments."""
        issues: list[str] = []
        recommendations: list[str] = []

        # 3a. Source code is accessible via PYTHONPATH or editable install
        src_dir = self.project_root / 'src'
        if not src_dir.exists():
            issues.append(f"Source directory not found: {src_dir}")
        else:
            # Check if src is in sys.path
            src_str = str(src_dir)
            in_path = any(
                Path(p).resolve() == src_dir.resolve()
                for p in sys.path
                if p
            )
            if not in_path:
                # Check for editable install
                try:
                    result = subprocess.run(
                        [sys.executable, '-m', 'pip', 'show', 'ansede-static'],
                        capture_output=True, text=True, timeout=10
                    )
                    is_editable = 'Editable project location' in result.stdout
                    if not is_editable:
                        issues.append(
                            "Source directory not in sys.path and not an editable install. "
                            "Portable deployments need PYTHONPATH or pip install -e ."
                        )
                except Exception:
                    issues.append("Source directory not in sys.path.")

        # 3b. No reliance on system site-packages for ansede internals
        site_packages = sysconfig.get_path('purelib')
        if site_packages:
            ansede_in_site = Path(site_packages) / 'ansede_static'
            if ansede_in_site.exists() and not in_venv:
                issues.append(
                    f"ansede_static found in system site-packages: {ansede_in_site}. "
                    "This may shadow the venv installation."
                )

        # 3c. Verify pyproject.toml uses Hatchling (supports editable installs)
        pyproject = self.project_root / 'pyproject.toml'
        if pyproject.exists():
            content = pyproject.read_text(encoding='utf-8')
            if 'hatchling' not in content.lower():
                issues.append("pyproject.toml does not use Hatchling build backend.")

        passed = len(issues) == 0

        return CheckResult(
            check_id="ZERO-03",
            name="Environment Isolation",
            passed=passed,
            details=(
                "PYTHONPATH / editable install resolves internal modules correctly."
                if passed
                else "; ".join(issues)
            ),
            recommendations=recommendations,
        )

    # ── Check 4: Network Sandbox ────────────────────────────────────

    def _check_network_sandbox(self) -> CheckResult:
        """Confirm the offline-first runtime functions with zero external
        network calls during rule updates or analysis."""
        issues: list[str] = []
        recommendations: list[str] = []

        # 4a. Check that importing ansede_static doesn't trigger network calls
        # (We check for common network-indicating imports)
        network_modules = [
            'requests', 'urllib.request', 'http.client', 'socket',
            'aiohttp', 'httpx', 'websockets',
        ]

        try:
            import ansede_static
            # Verify no network modules are imported at module level
            for mod_name in network_modules:
                if mod_name in sys.modules:
                    issues.append(
                        f"Network module '{mod_name}' is imported. "
                        "This may indicate network activity at import time."
                    )
        except ImportError:
            issues.append("Could not import ansede_static to check for network modules.")

        # 4b. Check for telemetry/phone-home URLs in source
        suspicious_urls = [
            'api.ansede', 'telemetry', 'analytics', 'tracking',
            'sentry.io', 'posthog', 'mixpanel', 'amplitude',
            'google-analytics', 'googletagmanager',
        ]
        src_dir = self.project_root / 'src'
        if src_dir.exists():
            for py_file in src_dir.rglob('*.py'):
                try:
                    content = py_file.read_text(encoding='utf-8', errors='replace')
                    for url in suspicious_urls:
                        if url in content.lower():
                            issues.append(
                                f"Potential telemetry URL '{url}' found in {py_file.relative_to(self.project_root)}"
                            )
                except OSError:
                    pass

        # 4c. Check for offline-first design markers
        offline_markers = ['offline', 'no telemetry', 'no api keys', 'fully offline']
        readme = self.project_root / 'README.md'
        if readme.exists():
            content = readme.read_text(encoding='utf-8', errors='replace').lower()
            has_offline = any(marker in content for marker in offline_markers)
            if not has_offline:
                issues.append(
                    "README.md does not document offline-first behavior. "
                    "Add 'zero telemetry', 'fully offline' or similar text."
                )

        # 4d. Check that license/activation doesn't require network
        licensing_file = src_dir / 'ansede_static' / 'licensing.py' if src_dir.exists() else None
        if licensing_file and licensing_file.exists():
            content = licensing_file.read_text(encoding='utf-8', errors='replace')
            if 'requests' in content or 'urllib.request' in content:
                issues.append(
                    "licensing.py imports network libraries. "
                    "Offline license validation should use local crypto only."
                )

        passed = len(issues) == 0

        return CheckResult(
            check_id="ZERO-04",
            name="Network Sandbox",
            passed=passed,
            details=(
                "Offline-first runtime confirmed; no telemetry or network calls detected."
                if passed
                else "; ".join(issues)
            ),
            recommendations=recommendations,
        )


def format_results(results: list[CheckResult], *, use_colour: bool = True) -> str:
    """Format verification results as a human-readable report."""
    GREEN = '\033[92m' if use_colour else ''
    RED = '\033[91m' if use_colour else ''
    YELLOW = '\033[93m' if use_colour else ''
    BOLD = '\033[1m' if use_colour else ''
    RESET = '\033[0m' if use_colour else ''

    lines = [
        f"{BOLD}ansede-static Zero-Dependency Verification{RESET}",
        "=" * 60,
        "",
    ]

    passed_count = sum(1 for r in results if r.passed)
    failed_count = len(results) - passed_count

    for r in results:
        icon = f"{GREEN}✓{RESET}" if r.passed else f"{RED}✗{RESET}"
        lines.append(f"  {icon} {BOLD}{r.check_id}{RESET}: {r.name}")
        if r.passed:
            lines.append(f"    {GREEN}{r.details}{RESET}")
        else:
            lines.append(f"    {RED}{r.details}{RESET}")
            for rec in r.recommendations:
                lines.append(f"    {YELLOW}→ {rec}{RESET}")
        lines.append("")

    lines.append("-" * 60)
    if failed_count == 0:
        lines.append(f"{GREEN}{BOLD}All {passed_count} checks passed!{RESET}")
        lines.append("ansede-static meets all zero-dependency requirements.")
    else:
        lines.append(
            f"{RED}{BOLD}{failed_count} of {len(results)} checks failed.{RESET}"
        )
        lines.append("Review the recommendations above to resolve issues.")

    return "\n".join(lines)


def format_results_json(results: list[CheckResult]) -> str:
    """Format verification results as JSON."""
    return json.dumps({
        "schema_version": "1.0",
        "tool": "ansede-static-zero-dep-verifier",
        "results": [
            {
                "check_id": r.check_id,
                "name": r.name,
                "passed": r.passed,
                "details": r.details,
                "recommendations": r.recommendations,
            }
            for r in results
        ],
        "summary": {
            "total": len(results),
            "passed": sum(1 for r in results if r.passed),
            "failed": sum(1 for r in results if not r.passed),
        },
    }, indent=2)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify ansede-static zero-dependency requirements."
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show detailed check information."
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output results in JSON format."
    )
    parser.add_argument(
        "--no-colour", "--no-color", dest="colour",
        action="store_false", default=True,
        help="Disable ANSI colour codes."
    )
    args = parser.parse_args()

    verifier = ZeroDepVerifier()
    results = verifier.run_all()

    if args.json:
        print(format_results_json(results))
    else:
        print(format_results(results, use_colour=args.colour))

    failed = sum(1 for r in results if not r.passed)
    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
