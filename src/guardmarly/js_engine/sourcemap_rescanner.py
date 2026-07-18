"""
Source-Map-Aware Minified JS Rescanner
──────────────────────────────────────
When a minified JS file has a source map available, resolve the original source
files and run the full structural AST parser on them. Remap findings back to
minified line numbers.

This converts opaque minified-code FNs into real TPs by giving the structural
parser readable source code to work with.
"""

from __future__ import annotations

import logging
from pathlib import Path

from guardmarly._types import Finding, TraceFrame
from guardmarly.js_engine.source_map_resolver import (
    load_sourcemap_path,
    parse_sourcemap_segments,
    SourceMapSegment,
)

_log = logging.getLogger(__name__)


def _collect_source_files(
    segments: dict[int, list[SourceMapSegment]],
) -> list[str]:
    """Extract unique source file paths referenced in a source map."""
    seen: set[str] = set()
    sources: list[str] = []
    for seg_list in segments.values():
        for seg in seg_list:
            src = seg.source_file
            if src and src not in seen:
                seen.add(src)
                sources.append(src)
    return sources


def _resolve_source_file(
    source_name: str,
    source_map_dir: Path,
    minified_dir: Path,
) -> Path | None:
    """Try to find the original source file on disk."""
    # Try relative to source map directory
    candidates = [
        source_map_dir / source_name,
        source_map_dir / Path(source_name).name,
        minified_dir / Path(source_name).name,
        minified_dir / source_name,
    ]
    for c in candidates:
        try:
            resolved = c.resolve(strict=False)
            if resolved.exists() and resolved.suffix in (".js", ".ts", ".jsx", ".tsx"):
                return resolved
        except OSError:
            continue
    return None


def _build_reverse_line_map(
    segments: dict[int, list[SourceMapSegment]],
) -> dict[tuple[str, int], list[int]]:
    """
    Build a reverse map: (source_file, source_line) → [generated_line, ...].
    This lets us remap findings from original source back to minified lines.
    """
    reverse: dict[tuple[str, int], list[int]] = {}
    for gen_line, seg_list in segments.items():
        for seg in seg_list:
            key = (seg.source_file, seg.source_line)
            reverse.setdefault(key, []).append(gen_line)
    return reverse


def rescore_via_source_map(
    code: str,
    filename: str,
    *,
    scan_fn,  # callable: (code: str, filename: str) -> list[Finding]
) -> list[Finding]:
    """
    If `filename` has an available source map, resolve original source files,
    scan them with the structural parser, and remap findings back.

    Returns the remapped findings. Returns empty list if no source map or no
    source files found.
    """
    source_map_path = load_sourcemap_path(filename)
    if source_map_path is None:
        return []

    segments = parse_sourcemap_segments(source_map_path)
    if not segments:
        return []

    source_files = _collect_source_files(segments)
    if not source_files:
        return []

    source_map_dir = source_map_path.parent
    minified_dir = Path(filename).parent if filename else source_map_dir
    reverse_map = _build_reverse_line_map(segments)

    all_findings: list[Finding] = []

    for source_name in source_files:
        source_path = _resolve_source_file(source_name, source_map_dir, minified_dir)
        if source_path is None:
            continue

        try:
            source_code = source_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        try:
            source_findings = scan_fn(source_code, str(source_path))
        except Exception:
            continue

        for finding in source_findings:
            src_line = finding.line or 0
            gen_lines = reverse_map.get((source_name, src_line), [])

            if not gen_lines:
                # Source line not in map — keep with reduced confidence
                all_findings.append(Finding(
                    category=finding.category,
                    severity=finding.severity,
                    title=f"{finding.title} (via source map)",
                    description=f"{finding.description} (remapped from {source_name}:{src_line})",
                    line=src_line,
                    suggestion=finding.suggestion,
                    rule_id=finding.rule_id,
                    cwe=finding.cwe,
                    agent=f"{finding.agent}+sourcemap",
                    confidence=min(finding.confidence, 0.60),
                    auto_fix=finding.auto_fix,
                    explanation=finding.explanation,
                    trace=(
                        TraceFrame(
                            kind="source",
                            label=f"original source {source_name}:{src_line} (via source map)",
                            line=src_line,
                        ),
                    ),
                    analysis_kind=f"{finding.analysis_kind}+sourcemap",
                    triggering_code=finding.triggering_code,
                ))
                continue

            # Remap to all generated lines
            for gen_line in gen_lines:
                all_findings.append(Finding(
                    category=finding.category,
                    severity=finding.severity,
                    title=finding.title,
                    description=(
                        f"{finding.description} "
                        f"(resolved via source map from original {source_name}:{src_line})"
                    ),
                    line=gen_line,
                    suggestion=finding.suggestion,
                    rule_id=finding.rule_id,
                    cwe=finding.cwe,
                    agent=f"{finding.agent}+sourcemap",
                    confidence=finding.confidence,
                    auto_fix=finding.auto_fix,
                    explanation=finding.explanation,
                    trace=(
                        TraceFrame(
                            kind="source",
                            label=f"original source {source_name}:{src_line}",
                            line=src_line,
                        ),
                        TraceFrame(
                            kind="propagator",
                            label=f"remapped to minified L{gen_line} via source map",
                            line=gen_line,
                        ),
                    ),
                    analysis_kind=f"{finding.analysis_kind}+sourcemap",
                    triggering_code=finding.triggering_code,
                ))

    _log.debug(
        "sourcemap-rescanner: %d findings from %d sources for %s",
        len(all_findings), len(source_files), filename,
    )
    return all_findings
