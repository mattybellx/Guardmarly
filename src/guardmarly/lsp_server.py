"""guardmarly.lsp_server
──────────────────────────────────────────────────────────────────────────────
Minimal Language Server Protocol (LSP 3.17) implementation for guardmarly.

Protocol:  JSON-RPC 2.0 over stdio with Content-Length framing.
Zero external dependencies — stdlib only (json, sys, threading, time, logging).

Supported notifications (client → server):
  • initialize          → respond with server capabilities
  • initialized         → no-op
  • textDocument/didOpen    → analyse, publish diagnostics
  • textDocument/didChange  → debounce 500 ms, analyse, publish diagnostics
  • textDocument/didSave    → analyse immediately, publish diagnostics
  • shutdown            → set shutdown flag, acknowledge
  • exit                → sys.exit

Diagnostics are pushed via:
  • textDocument/publishDiagnostics  (server → client notification)

LSP DiagnosticSeverity mapping:
  critical / high   → 1 (Error)
  medium            → 2 (Warning)
  low               → 3 (Information)
  info              → 4 (Hint)

Usage (from CLI):
  guardmarly --lsp          # starts the stdio server
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from typing import Any

_logger = logging.getLogger(__name__)

# ── Severity mapping ──────────────────────────────────────────────────────────

_SEVERITY_MAP: dict[str, int] = {
    "critical": 1,  # Error
    "high":     1,  # Error
    "medium":   2,  # Warning
    "low":      3,  # Information
    "info":     4,  # Hint
}


def _sev_to_lsp(severity_value: str) -> int:
    """Map a Finding severity string to an LSP DiagnosticSeverity integer."""
    return _SEVERITY_MAP.get(severity_value.lower(), 3)


def _findings_to_diagnostics(findings: list[Any]) -> list[dict[str, Any]]:
    """Convert a list of Finding objects to LSP Diagnostic dicts."""
    diagnostics: list[dict[str, Any]] = []
    for finding in findings:
        line_0 = max(0, (finding.line or 1) - 1)
        diag: dict[str, Any] = {
            "range": {
                "start": {"line": line_0, "character": 0},
                "end":   {"line": line_0, "character": 9999},
            },
            "severity": _sev_to_lsp(finding.severity.value),
            "source":   "guardmarly",
            "message":  f"[{finding.rule_id}] {finding.title}\n{finding.description}",
        }
        if finding.cwe:
            diag["code"] = finding.cwe
            diag["codeDescription"] = {
                "href": f"https://cwe.mitre.org/data/definitions/{finding.cwe.replace('CWE-', '')}.html"
            }
        diagnostics.append(diag)
    return diagnostics


# ── Stdio transport ───────────────────────────────────────────────────────────

class _StdioTransport:
    """
    Thread-safe LSP stdio transport using Content-Length header framing.

    The LSP wire format is::

        Content-Length: <N>\\r\\n
        \\r\\n
        <N bytes of UTF-8 JSON>
    """

    def __init__(self) -> None:
        self._out_lock = threading.Lock()

    def read_message(self) -> dict[str, Any] | None:
        """
        Read one JSON-RPC message from stdin.

        Returns the parsed dict, or None on EOF / decode error.
        """
        headers: dict[str, str] = {}
        while True:
            raw = sys.stdin.buffer.readline()
            if not raw:
                return None  # EOF
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if not line:
                break  # blank line separates headers from body
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip().lower()] = value.strip()

        length = int(headers.get("content-length", "0"))
        if length == 0:
            return None

        body = sys.stdin.buffer.read(length)
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            _logger.warning("LSP: failed to decode JSON body")
            return None

    def send_message(self, msg: dict[str, Any]) -> None:
        """Write one JSON-RPC message to stdout with Content-Length framing."""
        body = json.dumps(msg, separators=(",", ":")).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8")
        with self._out_lock:
            sys.stdout.buffer.write(header + body)
            sys.stdout.buffer.flush()


# ── Debouncer ─────────────────────────────────────────────────────────────────

class _Debouncer:
    """
    Schedule a function call after *delay* seconds.

    Each new call to ``schedule()`` cancels the previous pending call.
    Used to avoid re-analysing on every keystroke.
    """

    def __init__(self, delay: float = 0.5) -> None:
        self._delay = delay
        self._timer: threading.Timer | None = None
        self._lock = threading.Lock()

    def schedule(self, func: Any, *args: Any, **kwargs: Any) -> None:
        if self._delay == 0.0:
            # Zero-delay: run synchronously so callers (tests) see results immediately.
            func(*args, **kwargs)
            return
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(self._delay, func, args, kwargs)
            self._timer.daemon = True
            self._timer.start()

    def cancel(self) -> None:
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None


# ── LSP Server ────────────────────────────────────────────────────────────────

class LspServer:
    """
    Minimal guardmarly LSP server.

    Instantiate and call ``serve()`` to enter the message-processing loop.

    Parameters
    ----------
    transport:
        Supply a custom transport for testing. Defaults to ``_StdioTransport()``.
    debounce_delay:
        Seconds to wait before re-analysing after a ``didChange`` event.
    """

    def __init__(
        self,
        transport: _StdioTransport | None = None,
        debounce_delay: float = 0.5,
    ) -> None:
        self._transport = transport or _StdioTransport()
        self._docs: dict[str, str] = {}          # uri → current content
        self._findings_cache: dict[str, list[Any]] = {}  # uri → findings list
        self._debouncer = _Debouncer(delay=debounce_delay)
        self._shutdown = False

    # ── JSON-RPC helpers ──────────────────────────────────────────────────────

    def _respond(self, req_id: Any, result: Any) -> None:
        self._transport.send_message({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": result,
        })

    def _notify(self, method: str, params: Any) -> None:
        self._transport.send_message({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        })

    def _error_response(self, req_id: Any, code: int, message: str) -> None:
        self._transport.send_message({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": code, "message": message},
        })

    # ── Analysis ──────────────────────────────────────────────────────────────

    def _analyze_and_publish(self, uri: str, content: str) -> None:
        """
        Run the appropriate analyser for *uri* and push diagnostics.

        Errors are caught and logged rather than propagated — the LSP loop
        must not crash when a single file fails to parse.
        """
        diagnostics: list[dict[str, Any]] = []
        try:
            findings: list[Any] = []
            if uri.endswith(".py"):
                from guardmarly.python_analyzer import analyze_python
                result = analyze_python(content, filename=uri)
                findings = result.findings
            elif any(uri.endswith(ext) for ext in (".js", ".jsx", ".ts", ".tsx")):
                from guardmarly.js_engine.backends import run_js_analysis
                result, _ = run_js_analysis(content, filename=uri)
                findings = result.findings

            diagnostics = _findings_to_diagnostics(findings)
            # Cache findings keyed by URI so codeAction/hover can reference them
            self._findings_cache[uri] = findings
        except Exception as exc:  # noqa: BLE001
            _logger.exception("LSP analysis error for %s: %s", uri, exc)
        finally:
            # Always publish so clients/tests receive a diagnostics event
            # even when analysis fails unexpectedly.
            self._notify("textDocument/publishDiagnostics", {
                "uri": uri,
                "diagnostics": diagnostics,
            })

    def _schedule_analysis(self, uri: str, content: str) -> None:
        """Debounce analysis — cancel any pending analysis for this URI first."""
        self._debouncer.schedule(self._analyze_and_publish, uri, content)

    # ── Message handlers ──────────────────────────────────────────────────────

    def _handle_initialize(self, msg: dict[str, Any]) -> None:
        self._respond(msg["id"], {
            "capabilities": {
                "textDocumentSync": {
                    "openClose": True,
                    "change": 1,          # 1 = Full document sync
                    "save": {
                        "includeText": True,
                    },
                },
                "codeActionProvider": {
                    "codeActionKinds": ["quickfix"],
                    "resolveProvider": False,
                },
                "hoverProvider": True,
            },
            "serverInfo": {
                "name":    "guardmarly",
                "version": _server_version(),
            },
        })

    def _handle_initialized(self, _msg: dict[str, Any]) -> None:
        pass  # No additional setup needed

    def _handle_did_open(self, msg: dict[str, Any]) -> None:
        doc = msg.get("params", {}).get("textDocument", {})
        uri  = doc.get("uri", "")
        text = doc.get("text", "")
        self._docs[uri] = text
        self._schedule_analysis(uri, text)

    def _handle_did_change(self, msg: dict[str, Any]) -> None:
        params  = msg.get("params", {})
        uri     = params.get("textDocument", {}).get("uri", "")
        changes = params.get("contentChanges", [])
        if changes:
            text = changes[-1].get("text", "")
            self._docs[uri] = text
            self._schedule_analysis(uri, text)

    def _handle_did_save(self, msg: dict[str, Any]) -> None:
        params = msg.get("params", {})
        uri    = params.get("textDocument", {}).get("uri", "")
        text   = params.get("text")
        if text is not None:
            self._docs[uri] = text
        content = self._docs.get(uri, "")
        if content:
            # Run immediately on save — don't debounce
            self._analyze_and_publish(uri, content)

    def _handle_shutdown(self, msg: dict[str, Any]) -> None:
        self._shutdown = True
        self._debouncer.cancel()
        self._respond(msg.get("id"), None)

    def _handle_code_action(self, msg: dict[str, Any]) -> None:
        """Handle textDocument/codeAction — return quick-fix WorkspaceEdits."""
        req_id = msg.get("id")
        params = msg.get("params", {}) or {}
        uri: str = (params.get("textDocument") or {}).get("uri", "")
        findings = self._findings_cache.get(uri, [])
        actions: list[dict[str, Any]] = []
        for f in findings:
            suggestion = getattr(f, "suggestion", None) or ""
            auto_fix = getattr(f, "auto_fix", None) or ""
            if not suggestion and not auto_fix:
                continue
            fix_text = suggestion or auto_fix
            # Truncate long fix strings to a reasonable length for a quick-fix label
            label_text = fix_text[:80] + "..." if len(fix_text) > 80 else fix_text
            action: dict[str, Any] = {
                "title": f"\U0001f6e1 Fix: {label_text}",
                "kind": "quickfix",
                "diagnostics": [],
                "isPreferred": getattr(f, "severity", None) is not None
                    and getattr(f.severity, "value", "") in ("critical", "high"),
                "command": {
                    "title": "Show fix suggestion",
                    "command": "guardmarly.showFix",
                    "arguments": [
                        uri,
                        f.line or 0,
                        getattr(f, "cwe", "") or "",
                        fix_text,
                    ],
                },
            }
            actions.append(action)
        self._respond(req_id, actions)

    def _handle_hover(self, msg: dict[str, Any]) -> None:
        """Handle textDocument/hover — show vulnerability details on hover."""
        req_id = msg.get("id")
        params = msg.get("params", {}) or {}
        uri: str = (params.get("textDocument") or {}).get("uri", "")
        position = (params.get("position") or {})
        hover_line = int(position.get("line", 0)) + 1  # LSP is 0-based
        findings = self._findings_cache.get(uri, [])
        matched = [f for f in findings if (f.line or 0) == hover_line]
        if not matched:
            self._respond(req_id, None)
            return
        f = matched[0]
        cwe_link = ""
        cwe = getattr(f, "cwe", "") or ""
        if cwe:
            num = cwe.replace("CWE-", "")
            cwe_link = f" — [CWE-{num}](https://cwe.mitre.org/data/definitions/{num}.html)"
        sev = getattr(getattr(f, "severity", None), "value", "").upper()
        suggestion = getattr(f, "suggestion", "") or ""
        fix_md = f"\n\n**\U0001f4a1 Fix:** {suggestion}" if suggestion else ""
        md_value = (
            f"**\U0001f6e1 [{sev}] {f.title}**{cwe_link}\n\n"
            f"{getattr(f, 'description', '') or ''}"
            f"{fix_md}"
        )
        self._respond(req_id, {
            "contents": {"kind": "markdown", "value": md_value}
        })

    # ── Dispatch ──────────────────────────────────────────────────────────────

    def _dispatch(self, msg: dict[str, Any]) -> None:
        method = msg.get("method", "")

        if method == "initialize":
            self._handle_initialize(msg)
        elif method == "initialized":
            self._handle_initialized(msg)
        elif method == "textDocument/didOpen":
            self._handle_did_open(msg)
        elif method == "textDocument/didChange":
            self._handle_did_change(msg)
        elif method == "textDocument/didSave":
            self._handle_did_save(msg)
        elif method == "textDocument/codeAction":
            self._handle_code_action(msg)
        elif method == "textDocument/hover":
            self._handle_hover(msg)
        elif method == "shutdown":
            self._handle_shutdown(msg)
        elif method == "exit":
            sys.exit(0 if self._shutdown else 1)
        elif "id" in msg:
            # Unknown request — method not found
            self._error_response(msg["id"], -32601, f"Method not found: {method}")
        # Notifications with unknown methods are silently ignored (per LSP spec)

    # ── Main loop ─────────────────────────────────────────────────────────────

    def serve(self) -> None:
        """Enter the main message-processing loop (blocks until EOF or exit)."""
        while True:
            msg = self._transport.read_message()
            if msg is None:
                break
            try:
                self._dispatch(msg)
            except Exception as exc:  # noqa: BLE001
                _logger.exception("LSP dispatch error: %s", exc)


# ── Entry point ───────────────────────────────────────────────────────────────

def _server_version() -> str:
    try:
        from importlib.metadata import version
        return version("guardmarly")
    except Exception:  # noqa: BLE001
        return "dev"


def run_lsp_server() -> None:
    """
    Start the guardmarly LSP server on stdio.

    This is the entry point invoked by ``guardmarly --lsp``.
    Logging is directed to stderr so as not to pollute the LSP wire format.
    """
    logging.basicConfig(
        level=logging.WARNING,
        stream=sys.stderr,
        format="guardmarly-lsp %(levelname)s: %(message)s",
    )
    LspServer().serve()
