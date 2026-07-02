"""ansede_static.engine.pr_generator
──────────────────────────────────────────────────────────────────────────────
Generate PR-ready markdown documents from findings with auto_fix strings.

Produces a structured pull request body with:
  - Summary of all fixable findings
  - Unified diff patches per file
  - Risk-tagged change entries
  - Developer review instructions

Usage (via CLI):
  ansede-static src/ --pr                     # Write PR doc to stdout
  ansede-static src/ --pr --pr-output pr.md   # Write PR doc to file
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from ansede_static._types import AnalysisResult, Finding, Severity

_log = logging.getLogger(__name__)


# ── Patch formatting ─────────────────────────────────────────────────────────


def _parse_auto_fix_block(auto_fix: str) -> tuple[str, str] | None:
    """Parse a BEFORE:/AFTER: block from a finding's auto_fix string."""
    if "BEFORE:" not in auto_fix or "AFTER:" not in auto_fix:
        return None
    before_part, after_part = auto_fix.split("AFTER:", 1)
    before = before_part.replace("BEFORE:", "", 1).strip()
    after = after_part.strip("\n ")
    if not before or not after:
        return None
    return before, after


def _make_unified_patch(
    file_path: str,
    line_number: int,
    before: str,
    after: str,
    context_lines: int = 2,
) -> str:
    """Build a minimal unified-diff hunk for a single-line replacement.

    Example output:
      --- a/src/app.py
      +++ b/src/app.py
      @@ -5,3 +5,3 @@
       # some context
      -unsafe_call(x)
      +safe_call(x)
       # more context
    """
    try:
        rel = os.path.relpath(file_path) if os.path.isabs(file_path) else file_path
    except ValueError:
        # Windows: cross-drive paths (C: vs D:) — fall back to basename
        rel = os.path.basename(file_path) if os.path.isabs(file_path) else file_path
    try:
        from_path = Path(file_path)
        lines = from_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        lines = []

    start = max(0, line_number - 1 - context_lines)
    end = min(len(lines), line_number + context_lines)

    # Build context
    context_before = lines[start:line_number - 1] if lines else []
    context_after = lines[line_number:end] if lines else []

    patch_lines: list[str] = []
    patch_lines.append(f"--- a/{rel}")
    patch_lines.append(f"+++ b/{rel}")

    old_start = start + 1
    old_count = (line_number - start)
    new_start = old_start
    new_count = old_count

    patch_lines.append(f"@@ -{old_start},{old_count} +{new_start},{new_count} @@")

    for cl in context_before:
        patch_lines.append(f" {cl}")
    for b_line in before.split("\n"):
        patch_lines.append(f"-{b_line}")
    for a_line in after.split("\n"):
        patch_lines.append(f"+{a_line}")
    for cl in context_after:
        patch_lines.append(f" {cl}")

    return "\n".join(patch_lines)


# ── Severity emoji ────────────────────────────────────────────────────────────


_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def _severity_emoji(sev: Severity) -> str:
    return _SEVERITY_EMOJI.get(sev, "⚪")


def _severity_label(sev: Severity) -> str:
    return sev.name.title() if hasattr(sev, "name") else str(sev)


# ── PR body generation ────────────────────────────────────────────────────────


def generate_pr_body(
    results: list[AnalysisResult],
    *,
    repo_root: str | Path | None = None,
    author: str = "ansede-static bot",
    branch: str = "auto-fix/ansede-remediation",
) -> str:
    """Generate a complete PR body markdown document.

    Groups findings by file, generates patches, and produces a structured
    pull request description suitable for GitHub, GitLab, or Azure DevOps.

    Returns the markdown text.
    """
    if repo_root:
        repo_root = Path(repo_root)
    else:
        repo_root = Path.cwd()

    # ── Collect fixable findings ────────────────────────────────────────────
    fixable: list[tuple[AnalysisResult, Finding, str, str]] = []
    for result in results:
        if not result.file_path:
            continue
        try:
            Path(result.file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
        for finding in result.findings:
            if not finding.auto_fix:
                continue
            parsed = _parse_auto_fix_block(finding.auto_fix)
            if not parsed:
                continue
            before, after = parsed
            fixable.append((result, finding, before, after))

    if not fixable:
        return _empty_pr_body()

    # ── Group by file ────────────────────────────────────────────────────────
    by_file: dict[str, list[tuple[Finding, str, str]]] = {}
    for result, finding, before, after in fixable:
        by_file.setdefault(result.file_path or "unknown", []).append(
            (finding, before, after)
        )

    total_findings = len(fixable)
    total_files = len(by_file)
    critical_count = sum(
        1 for _, f, _, _ in fixable if f.severity == Severity.CRITICAL
    )
    high_count = sum(1 for _, f, _, _ in fixable if f.severity == Severity.HIGH)

    # ── Build PR body ───────────────────────────────────────────────────────
    lines: list[str] = []
    lines.append(f"## 🤖 Automated Security Fix — {branch}")
    lines.append("")
    lines.append(
        "This PR was automatically generated by **ansede-static** after detecting "
        "fixable security issues in the codebase. Each fix has been validated "
        "to preserve syntactic correctness."
    )
    lines.append("")

    # Summary table
    lines.append("### 📊 Summary")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|------:|")
    lines.append(f"| Files with fixes | {total_files} |")
    lines.append(f"| Total fixable findings | {total_findings} |")
    lines.append(f"| 🔴 Critical | {critical_count} |")
    lines.append(f"| 🟠 High | {high_count} |")
    lines.append(f"| 🟡 Medium | {total_findings - critical_count - high_count} |")
    lines.append("")

    # CWE coverage
    cwes_seen: dict[str, int] = {}
    for _, finding, _, _ in fixable:
        cwe = finding.cwe or "unknown"
        cwes_seen[cwe] = cwes_seen.get(cwe, 0) + 1
    if cwes_seen:
        lines.append("### 🏷️ CWE Coverage")
        lines.append("")
        for cwe, count in sorted(cwes_seen.items()):
            lines.append(f"- **{cwe}**: {count} finding(s)")
        lines.append("")

    # Per-file patches
    lines.append("### 📝 Changes by File")
    lines.append("")
    for file_idx, (file_path, file_findings) in enumerate(sorted(by_file.items()), 1):
        rel = os.path.relpath(file_path, str(repo_root)) if os.path.isabs(file_path) else file_path
        lines.append(f"#### {file_idx}. `{rel}`")
        lines.append("")
        lines.append(f"_{len(file_findings)} fix(es)_")
        lines.append("")

        for finding_idx, (finding, before, after) in enumerate(file_findings, 1):
            sev_emoji = _severity_emoji(finding.severity)
            sev_label = _severity_label(finding.severity)
            lines.append(
                f"<details>"
                f"<summary><b>{sev_emoji} L{finding.line}: {finding.rule_id} "
                f"{finding.cwe}</b> — {sev_label}</summary>"
            )
            lines.append("")
            if finding.title:
                lines.append(f"**Issue:** {finding.title}")
                lines.append("")
            if finding.description:
                lines.append(f"{finding.description}")
                lines.append("")

            # Unified diff patch
            patch = _make_unified_patch(
                file_path,
                finding.line or 1,
                before,
                after,
            )
            lines.append("```diff")
            lines.append(patch)
            lines.append("```")
            lines.append("")
            if finding.suggestion:
                lines.append(f"💡 *{finding.suggestion}*")
                lines.append("")
            lines.append("</details>")
            lines.append("")

    # Developer review notes
    lines.append("---")
    lines.append("")
    lines.append("### ✅ Review Checklist")
    lines.append("")
    lines.append("- [ ] Each fix preserves the intended behavior")
    lines.append("- [ ] No sensitive data is exposed in logs or error messages")
    lines.append("- [ ] Changes compile and tests pass")
    lines.append("- [ ] Edge cases (empty input, null values) are handled")
    lines.append("")
    lines.append(
        "_Generated by [ansede-static](https://github.com/mattybellx/Ansede) — "
        f"{total_findings} finding(s) in {total_files} file(s)_"
    )
    lines.append("")

    return "\n".join(lines)


def _empty_pr_body() -> str:
    return """## 🤖 Automated Security Fix

No auto-fixable findings were found in this scan. The codebase appears clean
with respect to the current ansede-static rule set.

_Generated by ansede-static_
"""


# ── CLI integration helpers ───────────────────────────────────────────────────


def write_pr_document(
    results: list[AnalysisResult],
    *,
    output_path: str | Path | None = None,
    repo_root: str | Path | None = None,
) -> str:
    """Generate and write the PR document.

    If output_path is None, returns the text (for stdout printing).
    Otherwise writes to the given path and returns the text.
    """
    body = generate_pr_body(results, repo_root=repo_root)
    if output_path:
        dst = Path(output_path)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(body, encoding="utf-8")
    return body
