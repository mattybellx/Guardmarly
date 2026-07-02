#!/usr/bin/env python3
"""
demo_scan.py — Produces a visually compelling terminal recording for ansede-static.

Usage:
    python tools/demo_scan.py

This scans the bundled samples/ directory and writes a self-contained HTML
report, then prints a summary suitable for screen-recording an animated GIF.

Requirements: ansede-static installed (pip install -e .)

The output is designed to showcase:
  - Fast scan speed (< 5 seconds for samples)
  - Rich color output (via Rich library)
  - Clear, actionable findings with CWE codes
  - Multiple output formats (text, JSON, HTML)
"""

import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

def banner(text: str) -> None:
    print(f"\n{'=' * 72}")
    print(f"  {text}")
    print(f"{'=' * 72}\n")

def run(cmd: list[str], timeout: int = 60) -> None:
    """Run a command and stream output (good for screen recording)."""
    print(f"$ {' '.join(cmd)}\n")
    result = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=timeout)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    if result.returncode != 0:
        print(f"  → exit code: {result.returncode}")

def main() -> None:
    banner("ansede-static — Offline SAST Demo")

    # 1. Version check
    print("📦 Version:")
    run(["ansede-static", "--version"])

    time.sleep(0.5)

    # 2. Scan the samples directory
    banner("🔍 Scanning samples/ directory (text output)")
    run(["ansede-static", "samples/", "--verbose"])

    time.sleep(0.5)

    # 3. Strict mode (HIGH+CRITICAL only)
    banner("🎯 Strict mode: HIGH+CRITICAL only (CodeQL-level precision)")
    run(["ansede-static", "samples/", "--strict"])

    time.sleep(0.5)

    # 4. JSON output
    banner("📋 JSON output (CI/CD integration)")
    run(["ansede-static", "samples/", "--format", "json", "--output", "tmp/demo_findings.json"])

    time.sleep(0.5)

    # 5. SARIF output (GitHub Code Scanning)
    banner("🛡️  SARIF output (GitHub Security tab)")
    run(["ansede-static", "samples/", "--format", "sarif", "--output", "tmp/demo_results.sarif"])

    time.sleep(0.5)

    # 6. Rule catalog
    banner("📚 Built-in rule catalog")
    run(["ansede-static", "--list-rules"])

    time.sleep(0.5)

    # 7. CWE explanation
    banner("📖 Offline CWE explanation")
    run(["ansede-static", "--explain-cwe", "CWE-89"])

    banner("✅ Demo complete!")
    print("Output files:")
    print("  tmp/demo_findings.json  — JSON report")
    print("  tmp/demo_results.sarif  — SARIF 2.1.0 report")
    print()
    print("Record with: asciinema rec demo.cast --command 'python tools/demo_scan.py'")
    print("Or screen-capture this terminal for an animated GIF.")

if __name__ == "__main__":
    main()
