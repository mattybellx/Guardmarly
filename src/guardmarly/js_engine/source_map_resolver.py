from __future__ import annotations

import json
import base64
import re
from dataclasses import dataclass
from pathlib import Path

from guardmarly._types import Finding, TraceFrame

_VLQ_BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_VLQ_MAP = {ch: idx for idx, ch in enumerate(_VLQ_BASE64)}


@dataclass(frozen=True)
class SourceMapSegment:
    generated_line: int
    generated_col: int
    source_file: str
    source_line: int
    source_col: int


def decode_vlq_segment(segment: str) -> list[int]:
    values: list[int] = []
    index = 0
    while index < len(segment):
        shift = 0
        value = 0
        while True:
            if index >= len(segment):
                break
            char = segment[index]
            digit = _VLQ_MAP.get(char)
            if digit is None:
                return values
            continuation = digit & 32
            digit &= 31
            value |= digit << shift
            shift += 5
            index += 1
            if not continuation:
                break

        negative = value & 1
        value >>= 1
        if negative:
            value = -value
        values.append(value)
    return values


def _normalize_source_reference(source_map_path: Path, source_name: str, source_root: str | None = None) -> str:
    source = source_name.replace('\\', '/')
    root = (source_root or '').strip()
    if root:
        if source.startswith('/'):
            source = source[1:]
        source = f"{root.rstrip('/')}/{source}"

    if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', source):
        return source

    try:
        source_path = Path(source)
        if source_path.is_absolute():
            return source_path.as_posix()
        return (source_map_path.parent / source_path).resolve(strict=False).as_posix()
    except OSError:
        return source


def _parse_sourcemap_mapping_lines(
    *,
    mappings_raw: str,
    sources: list[str],
    source_map_path: Path,
    source_root: str | None = None,
    generated_line_offset: int = 0,
    generated_col_offset: int = 0,
) -> dict[int, list[SourceMapSegment]]:
    line_map: dict[int, list[SourceMapSegment]] = {}
    source_index = 0
    original_line = 0
    original_col = 0

    for local_line_index, line in enumerate(mappings_raw.split(';')):
        generated_line = generated_line_offset + local_line_index + 1
        generated_col = generated_col_offset if local_line_index == 0 else 0
        if not line:
            continue
        for segment in line.split(','):
            if not segment:
                continue
            fields = decode_vlq_segment(segment)
            if not fields:
                continue
            generated_col += fields[0]
            if len(fields) >= 4:
                source_index += fields[1]
                original_line += fields[2]
                original_col += fields[3]
                if 0 <= source_index < len(sources):
                    source_name = _normalize_source_reference(
                        source_map_path,
                        str(sources[source_index]),
                        source_root,
                    )
                    line_map.setdefault(generated_line, []).append(SourceMapSegment(
                        generated_line=generated_line,
                        generated_col=max(0, generated_col),
                        source_file=source_name,
                        source_line=original_line + 1,
                        source_col=max(0, original_col),
                    ))
    return line_map


def load_sourcemap_path(filename: str) -> Path | None:
    if not filename:
        return None
    js_path = Path(filename)
    if not js_path.exists():
        return None

    try:
        tail = js_path.read_text(encoding="utf-8", errors="replace")[-8192:]
    except OSError:
        tail = ""

    match = re.search(r"sourceMappingURL=([^\s*]+)", tail, re.IGNORECASE)
    if match:
        mapping_ref = match.group(1).strip()
        if mapping_ref.startswith("data:"):
            return None
        candidate = (js_path.parent / mapping_ref).resolve()
        if candidate.exists() and candidate.suffix == ".map":
            return candidate

    sidecar = js_path.with_suffix(js_path.suffix + ".map")
    if sidecar.exists():
        return sidecar
    return None


_DATA_URL_SOURCEMAP_RE = re.compile(
    r'''sourceMappingURL=data:(?:application|text)/(?:json|javascript)(?:;charset=[^;]+)?;base64,([A-Za-z0-9+/=]+)''',
    re.IGNORECASE,
)


def _decode_inline_sourcemap(tail: str) -> dict | None:
    """Try to extract and decode an inline source map from a data: URL comment."""
    match = _DATA_URL_SOURCEMAP_RE.search(tail)
    if not match:
        return None
    b64_raw = match.group(1).strip()
    try:
        decoded = base64.b64decode(b64_raw)
        return json.loads(decoded)
    except (ValueError, json.JSONDecodeError):
        return None


def load_inline_sourcemap_segments(filename: str) -> dict[int, list[SourceMapSegment]]:
    """Load source-map segments from an inline data: URL, if present."""
    if not filename:
        return {}
    js_path = Path(filename)
    if not js_path.exists():
        return {}
    try:
        tail = js_path.read_text(encoding="utf-8", errors="replace")[-16384:]
    except OSError:
        return {}

    payload = _decode_inline_sourcemap(tail)
    if payload is None:
        return {}

    mappings_raw = payload.get("mappings")
    sources = payload.get("sources", [])
    if not isinstance(mappings_raw, str) or not isinstance(sources, list):
        return {}

    return _parse_sourcemap_mapping_lines(
        mappings_raw=mappings_raw,
        sources=[str(item) for item in sources],
        source_map_path=js_path,
        source_root=payload.get("sourceRoot") if isinstance(payload.get("sourceRoot"), str) else None,
    )


def parse_sourcemap_segments(source_map_path: Path) -> dict[int, list[SourceMapSegment]]:
    try:
        payload = json.loads(source_map_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}

    line_map: dict[int, list[SourceMapSegment]] = {}

    sections = payload.get("sections")
    if isinstance(sections, list) and sections:
        for section in sections:
            if not isinstance(section, dict):
                continue
            offset = section.get("offset", {})
            section_map = section.get("map", {})
            if not isinstance(offset, dict) or not isinstance(section_map, dict):
                continue
            mappings_raw = section_map.get("mappings")
            sources = section_map.get("sources", [])
            if not isinstance(mappings_raw, str) or not isinstance(sources, list):
                continue
            local_map = _parse_sourcemap_mapping_lines(
                mappings_raw=mappings_raw,
                sources=[str(item) for item in sources],
                source_map_path=source_map_path,
                source_root=section_map.get("sourceRoot") if isinstance(section_map.get("sourceRoot"), str) else None,
                generated_line_offset=max(0, int(offset.get("line", 0))),
                generated_col_offset=max(0, int(offset.get("column", 0))),
            )
            for line_no, segments in local_map.items():
                line_map.setdefault(line_no, []).extend(segments)
    else:
        mappings_raw = payload.get("mappings")
        sources = payload.get("sources", [])
        if not isinstance(mappings_raw, str) or not isinstance(sources, list):
            return {}
        line_map = _parse_sourcemap_mapping_lines(
            mappings_raw=mappings_raw,
            sources=[str(item) for item in sources],
            source_map_path=source_map_path,
            source_root=payload.get("sourceRoot") if isinstance(payload.get("sourceRoot"), str) else None,
        )

    for segments in line_map.values():
        segments.sort(key=lambda item: item.generated_col)
    return line_map


def remap_location(
    line_map: dict[int, list[SourceMapSegment]],
    generated_line: int,
    generated_col: int,
) -> tuple[str, int, int] | None:
    segments = line_map.get(generated_line)
    if not segments:
        return None
    chosen = segments[0]
    for segment in segments:
        if segment.generated_col <= generated_col:
            chosen = segment
        else:
            break
    return (chosen.source_file, chosen.source_line, chosen.source_col)


def remap_findings_to_source_map(
    findings: list[Finding],
    filename: str,
    *,
    downgrade_confidence: float = 0.35,
) -> list[Finding]:
    if not filename:
        return findings
    source_map_path = load_sourcemap_path(filename)
    if source_map_path is None:
        # No sidecar .map file — try inline data: URL source map
        line_map = load_inline_sourcemap_segments(filename)
    else:
        line_map = parse_sourcemap_segments(source_map_path)
    if not line_map:
        return findings

    remapped: list[Finding] = []
    for finding in findings:
        if not finding.line:
            remapped.append(finding)
            continue
        trace_col = 1
        if finding.trace and finding.trace[0].start_column:
            trace_col = finding.trace[0].start_column
        location = remap_location(line_map, finding.line, max(0, trace_col - 1))
        if not location:
            remapped.append(Finding(
                category=finding.category,
                severity=finding.severity,
                title=finding.title,
                description=(
                    f"{finding.description} (source map missing precise segment for bundled line {finding.line}; "
                    "kept with downgraded confidence)"
                ),
                line=finding.line,
                suggestion=finding.suggestion,
                rule_id=finding.rule_id,
                cwe=finding.cwe,
                agent=finding.agent,
                confidence=min(finding.confidence, downgrade_confidence),
                auto_fix=finding.auto_fix,
                explanation=finding.explanation,
                trace=finding.trace,
                analysis_kind=finding.analysis_kind,
                triggering_code=finding.triggering_code,
            ))
            continue
        source_file, source_line, source_col = location
        mapped_trace = tuple(
            TraceFrame(
                kind=frame.kind,
                label=frame.label,
                line=(source_line if frame.line == finding.line else frame.line),
                start_column=(source_col + 1 if frame.line == finding.line else frame.start_column),
                file_path=(source_file if frame.line == finding.line else frame.file_path),
            )
            for frame in finding.trace
        )
        remapped.append(Finding(
            category=finding.category,
            severity=finding.severity,
            title=f"{finding.title} [source-mapped]",
            description=f"{finding.description} (mapped from bundled line {finding.line} to {source_file}:{source_line})",
            line=source_line,
            suggestion=finding.suggestion,
            rule_id=finding.rule_id,
            cwe=finding.cwe,
            agent=finding.agent,
            confidence=finding.confidence,
            auto_fix=finding.auto_fix,
            explanation=finding.explanation,
            trace=mapped_trace,
            analysis_kind=finding.analysis_kind,
            triggering_code=finding.triggering_code,
            original_file=source_file,
        ))
    return remapped
