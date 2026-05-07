"""
Shared Taint Intermediate Representation (STIR)
────────────────────────────────────────────────
A language-agnostic IR for taint facts that both the Python and JS analyzers
emit into. This allows the IFDS/IDE solver to operate on a unified format
without knowing the source language.

Architecture:
  Source Code → Language Parser (Python AST / JS Structural) → STIR Facts
  STIR Facts → GlobalGraph (IFDS solver) → Findings

Adding a new language just requires a STIR emitter — the solver is shared.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class StirSource:
    """A taint source: where untrusted data enters the program."""
    kind: str                     # "parameter", "http_request", "file_read", "env_var", "user_input"
    name: str                     # variable/field name
    location: str                 # "file.py:42" or "routes.js:15"
    language: str                 # "python" | "javascript" | "typescript"
    metadata: dict[str, str] = field(default_factory=dict)  # extra context


@dataclass(frozen=True)
class StirSanitizer:
    """A sanitization point: where tainted data is cleaned/validated."""
    kind: str                     # "html_escape", "sql_parameterize", "url_validate", "path_sanitize"
    name: str                     # function/method name
    location: str
    language: str
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class StirSink:
    """A taint sink: where tainted data could cause harm."""
    kind: str                     # "code_exec", "sql_query", "file_write", "redirect", "xss", "command_exec"
    name: str                     # function/method name (eval, execute, redirect, innerHTML, etc.)
    location: str
    language: str
    severity_hint: str = "high"   # "critical" | "high" | "medium" | "low"
    cwe: str = ""
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class StirTaintFlow:
    """A complete taint flow: source → sanitizers → sink."""
    source: StirSource
    sink: StirSink
    sanitizers: tuple[StirSanitizer, ...] = ()
    propagation_path: tuple[str, ...] = ()  # intermediate variable names
    confidence: float = 0.90
    analysis_kind: str = "taint-flow"


@dataclass
class StirModel:
    """A collection of STIR facts for one file."""
    file_path: str
    language: str
    sources: list[StirSource] = field(default_factory=list)
    sanitizers: list[StirSanitizer] = field(default_factory=list)
    sinks: list[StirSink] = field(default_factory=list)
    flows: list[StirTaintFlow] = field(default_factory=list)

    def add_source(self, **kwargs: Any) -> StirSource:
        s = StirSource(language=self.language, **kwargs)
        self.sources.append(s)
        return s

    def add_sanitizer(self, **kwargs: Any) -> StirSanitizer:
        s = StirSanitizer(language=self.language, **kwargs)
        self.sanitizers.append(s)
        return s

    def add_sink(self, **kwargs: Any) -> StirSink:
        s = StirSink(language=self.language, **kwargs)
        self.sinks.append(s)
        return s

    def add_flow(self, source: StirSource, sink: StirSink,
                 sanitizers: tuple[StirSanitizer, ...] = (),
                 propagation_path: tuple[str, ...] = (),
                 confidence: float = 0.90,
                 analysis_kind: str = "taint-flow") -> StirTaintFlow:
        flow = StirTaintFlow(
            source=source, sink=sink, sanitizers=sanitizers,
            propagation_path=propagation_path, confidence=confidence,
            analysis_kind=analysis_kind,
        )
        self.flows.append(flow)
        return flow

    def is_sanitized(self, flow: StirTaintFlow) -> bool:
        """Check if any sanitizer on the flow path neutralizes the sink."""
        for san in flow.sanitizers:
            if san.kind == "html_escape" and flow.sink.kind == "xss":
                return True
            if san.kind == "sql_parameterize" and flow.sink.kind == "sql_query":
                return True
            if san.kind == "url_validate" and flow.sink.kind == "redirect":
                return True
            if san.kind == "path_sanitize" and flow.sink.kind == "file_write":
                return True
        return False


# ── Sink-to-CWE mapping ─────────────────────────────────────────────────

_SINK_CWE_MAP: dict[str, str] = {
    "code_exec": "CWE-95",
    "sql_query": "CWE-89",
    "file_write": "CWE-22",
    "redirect": "CWE-601",
    "xss": "CWE-79",
    "command_exec": "CWE-78",
    "deserialization": "CWE-502",
    "ssrf": "CWE-918",
    "xxe": "CWE-611",
    "idor": "CWE-639",
    "csrf": "CWE-352",
    "file_upload": "CWE-434",
    "reflection": "CWE-470",
    "auth_bypass": "CWE-287",
    "rate_limit": "CWE-307",
}

_SINK_SEVERITY_MAP: dict[str, str] = {
    "code_exec": "critical",
    "command_exec": "critical",
    "deserialization": "critical",
    "sql_query": "high",
    "file_write": "high",
    "redirect": "high",
    "xss": "high",
    "ssrf": "high",
    "xxe": "high",
    "idor": "high",
    "csrf": "high",
    "file_upload": "high",
    "reflection": "high",
    "auth_bypass": "high",
    "rate_limit": "high",
}


def sink_to_cwe(sink_kind: str) -> str:
    return _SINK_CWE_MAP.get(sink_kind, "CWE-unknown")


def sink_to_severity(sink_kind: str) -> str:
    return _SINK_SEVERITY_MAP.get(sink_kind, "medium")


# ── Python → STIR emitter ──────────────────────────────────────────────

def emit_python_stir(
    code: str,
    filename: str,
    *,
    sources: list[tuple[str, str, int]] | None = None,
    sinks: list[tuple[str, str, int, str]] | None = None,
    sanitizers: list[tuple[str, str, int]] | None = None,
) -> StirModel:
    """
    Convert Python analyzer outputs to STIR.
    Call this from python_analyzer.py after detection to populate the IR.

    Args:
        sources: [(kind, name, line), ...]  e.g. [("http_request", "request", 15)]
        sinks:   [(kind, name, line, cwe), ...]  e.g. [("code_exec", "eval", 42, "CWE-95")]
        sanitizers: [(kind, name, line), ...]
    """
    model = StirModel(file_path=filename, language="python")
    src_map: dict[str, StirSource] = {}

    for kind, name, line in (sources or []):
        loc = f"{filename}:{line}" if filename else f"<stdin>:{line}"
        s = model.add_source(kind=kind, name=name, location=loc)
        src_map[name] = s

    san_map: dict[str, StirSanitizer] = {}
    for kind, name, line in (sanitizers or []):
        loc = f"{filename}:{line}" if filename else f"<stdin>:{line}"
        s = model.add_sanitizer(kind=kind, name=name, location=loc)
        san_map[name] = s

    for kind, name, line, cwe in (sinks or []):
        loc = f"{filename}:{line}" if filename else f"<stdin>:{line}"
        model.add_sink(kind=kind, name=name, location=loc, cwe=cwe)

    return model


# ── JS → STIR emitter ──────────────────────────────────────────────────

def emit_js_stir(
    filename: str,
    *,
    sources: list[tuple[str, str, int]] | None = None,
    sinks: list[tuple[str, str, int, str]] | None = None,
    sanitizers: list[tuple[str, str, int]] | None = None,
) -> StirModel:
    """Convert JS analyzer outputs to STIR. Same interface as emit_python_stir."""
    model = StirModel(file_path=filename, language="javascript")
    for kind, name, line in (sources or []):
        loc = f"{filename}:{line}" if filename else f"<stdin>:{line}"
        model.add_source(kind=kind, name=name, location=loc)
    for kind, name, line in (sanitizers or []):
        loc = f"{filename}:{line}" if filename else f"<stdin>:{line}"
        model.add_sanitizer(kind=kind, name=name, location=loc)
    for kind, name, line, cwe in (sinks or []):
        loc = f"{filename}:{line}" if filename else f"<stdin>:{line}"
        model.add_sink(kind=kind, name=name, location=loc, cwe=cwe)
    return model
