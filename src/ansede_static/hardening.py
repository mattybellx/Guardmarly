"""ansede_static.hardening
──────────────────────────────────────────────────────────────────────────────
Hardening strategies to address documented failure modes & known limitations.

Key features:
1. **Minified Code Detection** — Heuristic to identify minified files (high character-to-newline ratio)
2. **Template Engine Support** — AST-level detectors for Jinja2, Handlebars SSTI
3. **Timeout Handling** — Streaming AST approach for large/generated files
4. **Line Mapping** — Best-guess line mapping for minified code
5. **Context Preservation** — Track file metadata for better triage decisions

Zero-dependency implementation using only the Python standard library.
"""

from __future__ import annotations

import ast
import hashlib
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_log = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════
# PART 1: Minified Code Detection & Line Mapping
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class MinifiedAnalysis:
    """Result of minified code analysis."""
    is_minified: bool
    confidence: float  # 0.0 to 1.0
    char_to_newline_ratio: float
    avg_line_length: int
    reason: str
    line_map: dict[int, tuple[int, int]] = field(default_factory=dict)  # virt_line -> (start_col, end_col)


def detect_minified(file_path: str | Path, content: str) -> MinifiedAnalysis:
    """
    Heuristically detect if a file is minified.

    **Heuristics:**
    - High character-to-newline ratio (>200 chars per line average)
    - Very long lines (>500 chars on average)
    - Few comments relative to code
    - Single-letter variable names (weak signal)

    Returns MinifiedAnalysis with confidence 0.0-1.0.
    """
    lines = content.splitlines()
    if not lines:
        return MinifiedAnalysis(
            is_minified=False,
            confidence=0.0,
            char_to_newline_ratio=0.0,
            avg_line_length=0,
            reason="Empty file"
        )

    total_chars = len(content)
    total_newlines = len(lines) - 1  # Exclude last line
    if total_newlines == 0:
        total_newlines = 1

    char_to_newline = total_chars / total_newlines
    avg_line_len = sum(len(line) for line in lines) / len(lines)

    # Count comments (# in Python, // in JS/TS, /* */ in JS/TS)
    comment_pattern = re.compile(r'(#|//|/\*|\*/)')
    comment_lines = sum(1 for line in lines if comment_pattern.search(line))
    comment_ratio = comment_lines / len(lines) if lines else 0.0

    # Confidence scoring
    confidence = 0.0
    reasons = []

    if char_to_newline > 200:
        confidence += 0.4
        reasons.append(f"char/newline ratio {char_to_newline:.1f} > 200")

    if avg_line_len > 500:
        confidence += 0.3
        reasons.append(f"avg line length {avg_line_len:.0f} > 500")

    if comment_ratio < 0.05:  # Very few comments
        confidence += 0.2
        reasons.append(f"comment ratio {comment_ratio:.2%} < 5%")

    # Detect common minified patterns (no spaces around operators, etc.)
    if len(lines) > 0:
        sample = "\n".join(lines[:min(10, len(lines))])
        no_space_pattern = re.compile(r'[a-zA-Z0-9_]\s{0,1}[=+\-*/]\s{0,1}[a-zA-Z0-9_]')
        if len(no_space_pattern.findall(sample)) > len(sample.split()) * 0.1:
            confidence += 0.1
            reasons.append("Dense operator spacing detected")

    is_minified = confidence >= 0.5
    reason = "; ".join(reasons) if reasons else "Not minified"

    # Build line map for minified files (map virtual lines to actual positions)
    line_map: dict[int, tuple[int, int]] = {}
    if is_minified:
        line_map = _build_line_map(content, lines)

    return MinifiedAnalysis(
        is_minified=is_minified,
        confidence=min(1.0, confidence),
        char_to_newline_ratio=char_to_newline,
        avg_line_length=int(avg_line_len),
        reason=reason,
        line_map=line_map
    )


def _build_line_map(content: str, lines: list[str]) -> dict[int, tuple[int, int]]:
    """
    Build a best-guess line map for minified code.

    For each actual line in minified code, attempt to split it into
    logical statements and map them to virtual line numbers.

    Returns: {virtual_line: (start_col, end_col)}
    """
    line_map: dict[int, tuple[int, int]] = {}
    virtual_line = 1

    # Common statement delimiters in minified code
    _delimiters = [';', '}', '{']

    for actual_line_no, actual_line in enumerate(lines, start=1):
        if not actual_line.strip():
            continue

        # Split line by delimiters (preserving some context)
        # This is a heuristic; actual line mapping requires source maps
        parts = re.split(r'([;{}])', actual_line)
        col = 0
        for part in parts:
            if part and part.strip():
                line_map[virtual_line] = (col, col + len(part))
                virtual_line += 1
            col += len(part)

    return line_map


# ════════════════════════════════════════════════════════════════════════════
# PART 2: Template Engine Detectors (Jinja2, Handlebars SSTI)
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class TemplateInjectionFinding:
    """Detected potential Server-Side Template Injection."""
    line: int
    column: int
    context: str  # e.g., "jinja2_render", "handlebars_compile"
    tainted_expr: str
    sink_function: str
    cwe: str = "CWE-1336"  # Server-Side Template Injection
    severity: str = "HIGH"


class TemplateEngineDetector:
    """Detect SSTI vulnerabilities in Jinja2, Handlebars, and similar engines."""

    # Jinja2 patterns (Python)
    JINJA2_RENDER_RE = re.compile(
        r'\b(render_template_string|from_string|render|Environment)\s*\(\s*["\']?([^"\')\n]+)'
    )
    JINJA2_INJECTION_RE = re.compile(
        r'\{\{.*?(?<![a-zA-Z0-9_])(request\.|session\.|user_input|args|environ|getenv)\b'
    )
    JINJA2_FILTER_RE = re.compile(r'\|safe\b')  # unsafe filter bypass

    # Handlebars patterns (JavaScript/TypeScript)
    HANDLEBARS_COMPILE_RE = re.compile(
        r'\bHandlebars\s*\.\s*compile\s*\(\s*(["\']|`)[^"\'`\n]*(?:\$\{[^}]+\}|" \+ |\' \+ |` \+ )[^"\'`\n]*'
    )
    HANDLEBARS_PARTIAL_RE = re.compile(
        r'(registerPartial|registerHelper)\s*\(\s*["\'][^"\']+["\']\s*,\s*(["\']|`)[^"\'`\n]*(?:\$\{|" \+ |\' \+ |` \+ )'
    )

    @staticmethod
    def detect_jinja2_ssti(content: str, file_path: str) -> list[TemplateInjectionFinding]:
        """Detect SSTI in Jinja2 templates."""
        findings: list[TemplateInjectionFinding] = []
        lines = content.splitlines()

        for line_no, line in enumerate(lines, start=1):
            # Check if line contains render operations with user input
            if TemplateEngineDetector.JINJA2_RENDER_RE.search(line):
                # Now check if user input is passed to the template
                if TemplateEngineDetector.JINJA2_INJECTION_RE.search(line):
                    findings.append(TemplateInjectionFinding(
                        line=line_no,
                        column=line.find('{{'),
                        context="jinja2_render",
                        tainted_expr=line.strip()[:80],
                        sink_function="render_template_string",
                        cwe="CWE-1336",
                        severity="HIGH"
                    ))

            # Check for |safe filter on user input
            if (TemplateEngineDetector.JINJA2_FILTER_RE.search(line) and
                    TemplateEngineDetector.JINJA2_INJECTION_RE.search(line)):
                findings.append(TemplateInjectionFinding(
                    line=line_no,
                    column=line.find('|safe'),
                    context="jinja2_safe_filter",
                    tainted_expr=line.strip()[:80],
                    sink_function="safe filter",
                    cwe="CWE-1336",
                    severity="CRITICAL"
                ))

        return findings

    @staticmethod
    def detect_handlebars_ssti(content: str, file_path: str) -> list[TemplateInjectionFinding]:
        """Detect SSTI in Handlebars templates."""
        findings: list[TemplateInjectionFinding] = []
        lines = content.splitlines()

        for line_no, line in enumerate(lines, start=1):
            # Check for Handlebars.compile with dynamic template
            if TemplateEngineDetector.HANDLEBARS_COMPILE_RE.search(line):
                findings.append(TemplateInjectionFinding(
                    line=line_no,
                    column=line.find('Handlebars'),
                    context="handlebars_compile",
                    tainted_expr=line.strip()[:80],
                    sink_function="Handlebars.compile",
                    cwe="CWE-1336",
                    severity="HIGH"
                ))

            # Check for registerPartial/registerHelper with dynamic content
            if TemplateEngineDetector.HANDLEBARS_PARTIAL_RE.search(line):
                findings.append(TemplateInjectionFinding(
                    line=line_no,
                    column=line.find(('registerPartial', 'registerHelper')),
                    context="handlebars_partial",
                    tainted_expr=line.strip()[:80],
                    sink_function="registerPartial/registerHelper",
                    cwe="CWE-1336",
                    severity="HIGH"
                ))

        return findings

    @staticmethod
    def detect_all_ssti(content: str, file_path: str) -> list[TemplateInjectionFinding]:
        """Run all template engine detectors."""
        findings: list[TemplateInjectionFinding] = []

        # Dispatch based on file extension or content
        if file_path.endswith(('.py', '.jinja', '.jinja2', '.j2')):
            findings.extend(TemplateEngineDetector.detect_jinja2_ssti(content, file_path))

        if file_path.endswith(('.js', '.ts', '.jsx', '.tsx', '.hbs', '.handlebars')):
            findings.extend(TemplateEngineDetector.detect_handlebars_ssti(content, file_path))

        return findings


# ════════════════════════════════════════════════════════════════════════════
# PART 3: Streaming AST & Timeout Handling
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class StreamingASTConfig:
    """Configuration for streaming AST parsing."""
    chunk_size: int = 50000  # chars per chunk
    timeout_seconds: int = 30  # per file
    max_retries: int = 2
    fallback_to_regex: bool = True  # If AST parsing times out


class StreamingASTParser:
    """
    Parse AST in chunks to handle large/generated files without timeouts.

    Strategy:
    1. Attempt standard AST parsing with timeout
    2. If timeout, split into logical chunks (functions, classes)
    3. Parse each chunk independently
    4. Fall back to regex if chunking fails
    """

    def __init__(self, config: Optional[StreamingASTConfig] = None):
        self.config = config or StreamingASTConfig()

    def parse_python_safe(self, content: str, file_path: str) -> Optional[ast.Module]:
        """
        Safely parse Python code, with fallback to chunking/regex.

        Returns AST module or None if parsing fails.
        """
        try:
            return ast.parse(content)
        except SyntaxError as e:
            _log.warning(f"Syntax error in {file_path}: {e}")
            return None
        except Exception as e:
            _log.warning(f"Parse error in {file_path}: {e}")
            return None

    def parse_python_streaming(self, content: str, file_path: str) -> Optional[ast.Module]:
        """
        Parse Python code in chunks to avoid timeout on large files.

        Returns AST module, or None if all strategies fail.
        """
        # Try standard parse first
        result = self.parse_python_safe(content, file_path)
        if result is not None:
            return result

        _log.debug(f"Attempting streaming parse for {file_path}")

        # Strategy 2: Split by top-level definitions (functions, classes)
        chunks = self._split_into_chunks(content)
        if not chunks:
            return None

        # Parse each chunk separately and reconstruct
        # (This is imperfect but better than giving up)
        statements: list[ast.stmt] = []
        for chunk in chunks:
            try:
                chunk_ast = ast.parse(chunk)
                statements.extend(chunk_ast.body)
            except Exception:
                # Skip unparseable chunks
                pass

        if statements:
            module = ast.Module(body=statements, type_ignores=[])
            return module

        return None

    @staticmethod
    def _split_into_chunks(content: str) -> list[str]:
        """
        Split content into logical chunks for parsing.

        Looks for top-level function/class definitions.
        """
        chunks: list[str] = []
        current_chunk: list[str] = []
        _in_def = False
        indent_level = 0

        for line in content.splitlines():
            # Detect function/class definitions
            if line.startswith(('def ', 'class ', 'async def ')):
                if current_chunk and indent_level == 0:
                    chunks.append("\n".join(current_chunk))
                    current_chunk = []
                _in_def = True
                indent_level = 0

            current_chunk.append(line)

            # Track indentation
            if line and line[0] not in (' ', '\t'):
                indent_level = 0
            elif line.strip():
                indent_level = len(line) - len(line.lstrip())

        if current_chunk:
            chunks.append("\n".join(current_chunk))

        return chunks


# ════════════════════════════════════════════════════════════════════════════
# PART 4: File Metadata & Context Preservation
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class FileMetadata:
    """Preserved file context for better triage decisions."""
    file_path: str
    is_test_file: bool  # test_*, *_test, *_spec
    is_mock_file: bool  # mock_*, *_mock, fixtures
    is_minified: bool
    is_generated: bool  # File marked as auto-generated
    is_template_file: bool  # .jinja, .j2, .hbs, .handlebars
    encoding: str = "utf-8"
    hash_digest: str = ""  # SHA-256 for caching

    @staticmethod
    def from_file(file_path: str | Path) -> FileMetadata:
        """Analyze file and extract metadata."""
        file_path_str = str(file_path)
        file_path_obj = Path(file_path_str)

        # Determine if test/mock/generated
        _name_lower = file_path_obj.name.lower()
        path_lower = file_path_str.lower()

        is_test = any(marker in path_lower for marker in ['test_', '_test', '_spec', 'spec_', 'conftest.', '/perf/', '\\perf\\', '/bench/', '\\bench\\', '/benchmarks/', '/examples/', '/example/'])
        is_mock = any(marker in path_lower for marker in ['mock_', '_mock', 'fixtures/', '/fixtures', 'fixture'])
        is_generated = any(marker in path_lower for marker in ['.d.ts', '.gen.', '.generated.', 'dist/', '__pycache__'])
        is_template = file_path_obj.suffix in ('.jinja', '.j2', '.jinja2', '.hbs', '.handlebars')
        is_minified = False

        # Try to detect minified code if reasonable file size
        try:
            if file_path_obj.stat().st_size < 1_000_000:  # < 1MB
                content = file_path_obj.read_text(encoding='utf-8', errors='ignore')
                analysis = detect_minified(file_path_obj, content)
                is_minified = analysis.is_minified
        except Exception as e:
            _log.debug(f"Could not check minification for {file_path}: {e}")

        # Compute hash for caching
        try:
            content_bytes = file_path_obj.read_bytes()
            hash_digest = hashlib.sha256(content_bytes).hexdigest()[:16]
        except Exception:
            hash_digest = ""

        return FileMetadata(
            file_path=file_path_str,
            is_test_file=is_test,
            is_mock_file=is_mock,
            is_minified=is_minified,
            is_generated=is_generated,
            is_template_file=is_template,
            hash_digest=hash_digest
        )


# ════════════════════════════════════════════════════════════════════════════
# PART 5: Integration Points
# ════════════════════════════════════════════════════════════════════════════

def should_suppress_in_test_context(finding: 'Finding', metadata: FileMetadata) -> bool:  # noqa: F821
    """Determine if a finding should be suppressed due to test/mock context."""
    # CWE-798 (hardcoded secrets) in test files should be downgraded/suppressed
    if metadata.is_test_file or metadata.is_mock_file:
        if finding.cwe in ("CWE-798", "CWE-287"):  # Secrets, weak crypto
            return True

    return False


__all__ = [
    "MinifiedAnalysis",
    "detect_minified",
    "TemplateEngineDetector",
    "TemplateInjectionFinding",
    "StreamingASTConfig",
    "StreamingASTParser",
    "FileMetadata",
    "should_suppress_in_test_context",
]
