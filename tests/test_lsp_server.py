"""
tests.test_lsp_server
─────────────────────
Unit tests for the LSP server implementation.

We test the server in isolation by supplying a fake transport that feeds
pre-built messages in and captures what is sent back out — no network or
stdio involvement.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from ansede_static.lsp_server import (
    LspServer,
    _Debouncer,
    _findings_to_diagnostics,
    _sev_to_lsp,
    _StdioTransport,
)
from ansede_static._types import Finding, Severity


# ── Fake transport ────────────────────────────────────────────────────────────

class _FakeTransport:
    """In-memory transport: feed messages in, capture messages out."""

    def __init__(self, messages: list[dict[str, Any]] | None = None) -> None:
        self._inbox: list[dict[str, Any]] = list(messages or [])
        self.sent: list[dict[str, Any]] = []

    def read_message(self) -> dict[str, Any] | None:
        if self._inbox:
            return self._inbox.pop(0)
        return None  # EOF

    def send_message(self, msg: dict[str, Any]) -> None:
        self.sent.append(msg)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_finding(
    *,
    category: str = "security",
    rule_id: str = "PY-004",
    title: str = "SQL Injection",
    cwe: str = "CWE-89",
    severity: Severity = Severity.HIGH,
    line: int = 3,
    description: str = "Unsanitised input.",
) -> Finding:
    return Finding(
        category=category,
        rule_id=rule_id,
        title=title,
        cwe=cwe,
        severity=severity,
        line=line,
        description=description,
    )


def _run_server(messages: list[dict[str, Any]]) -> _FakeTransport:
    """Run the LSP server with *messages* and return the transport with sent[]."""
    transport = _FakeTransport(messages)
    server = LspServer(transport=transport, debounce_delay=0.0)
    server.serve()
    return transport


# ── _sev_to_lsp ───────────────────────────────────────────────────────────────

class TestSevToLsp:
    def test_critical_is_error(self):
        assert _sev_to_lsp("critical") == 1

    def test_high_is_error(self):
        assert _sev_to_lsp("high") == 1

    def test_medium_is_warning(self):
        assert _sev_to_lsp("medium") == 2

    def test_low_is_information(self):
        assert _sev_to_lsp("low") == 3

    def test_info_is_hint(self):
        assert _sev_to_lsp("info") == 4

    def test_unknown_falls_back_to_information(self):
        assert _sev_to_lsp("unknown-level") == 3

    def test_case_insensitive(self):
        assert _sev_to_lsp("HIGH") == 1
        assert _sev_to_lsp("Medium") == 2


# ── _findings_to_diagnostics ──────────────────────────────────────────────────

class TestFindingsToDiagnostics:
    def test_empty_list(self):
        assert _findings_to_diagnostics([]) == []

    def test_single_finding_shape(self):
        f = _make_finding(line=5)
        diags = _findings_to_diagnostics([f])
        assert len(diags) == 1
        d = diags[0]
        assert d["range"]["start"]["line"] == 4  # 0-based
        assert d["severity"] == 1               # HIGH → Error
        assert d["source"] == "ansede-static"
        assert "SQL Injection" in d["message"]

    def test_cwe_attached_as_code(self):
        f = _make_finding(cwe="CWE-89")
        diags = _findings_to_diagnostics([f])
        assert diags[0].get("code") == "CWE-89"

    def test_no_cwe_no_code_key(self):
        f = _make_finding(cwe=None)
        diags = _findings_to_diagnostics([f])
        assert "code" not in diags[0]

    def test_line_1_maps_to_line_0(self):
        f = _make_finding(line=1)
        diags = _findings_to_diagnostics([f])
        assert diags[0]["range"]["start"]["line"] == 0

    def test_line_none_maps_to_line_0(self):
        f = _make_finding(line=None)
        diags = _findings_to_diagnostics([f])
        assert diags[0]["range"]["start"]["line"] == 0


# ── _Debouncer ────────────────────────────────────────────────────────────────

class TestDebouncer:
    def test_fires_after_delay(self):
        results: list[str] = []
        d = _Debouncer(delay=0.01)
        d.schedule(results.append, "hello")
        import time
        time.sleep(0.05)
        assert results == ["hello"]

    def test_cancels_previous_call(self):
        """Scheduling twice rapidly should only fire once."""
        results: list[str] = []
        d = _Debouncer(delay=0.05)
        d.schedule(results.append, "first")
        d.schedule(results.append, "second")
        import time
        time.sleep(0.15)
        assert results == ["second"]

    def test_cancel_prevents_fire(self):
        results: list[str] = []
        d = _Debouncer(delay=0.05)
        d.schedule(results.append, "never")
        d.cancel()
        import time
        time.sleep(0.1)
        assert results == []


# ── Initialize handshake ──────────────────────────────────────────────────────

class TestInitialize:
    def test_initialize_returns_capabilities(self):
        transport = _run_server([
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        ])
        assert len(transport.sent) == 1
        resp = transport.sent[0]
        assert resp["id"] == 1
        assert "capabilities" in resp["result"]
        assert "textDocumentSync" in resp["result"]["capabilities"]

    def test_server_info_present(self):
        transport = _run_server([
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        ])
        info = transport.sent[0]["result"].get("serverInfo", {})
        assert info.get("name") == "ansede-static"

    def test_initialized_notification_no_response(self):
        transport = _run_server([
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "initialized", "params": {}},
        ])
        # Only the initialize response, no response to initialized
        assert len(transport.sent) == 1


# ── shutdown / exit ───────────────────────────────────────────────────────────

class TestShutdown:
    def test_shutdown_acknowledged(self):
        transport = _run_server([
            {"jsonrpc": "2.0", "id": 99, "method": "shutdown"},
        ])
        shutdown_resp = transport.sent[-1]
        assert shutdown_resp["id"] == 99
        assert shutdown_resp["result"] is None

    def test_exit_after_shutdown_calls_sys_exit_0(self):
        with pytest.raises(SystemExit) as exc_info:
            _run_server([
                {"jsonrpc": "2.0", "id": 1, "method": "shutdown"},
                {"jsonrpc": "2.0", "method": "exit"},
            ])
        assert exc_info.value.code == 0

    def test_exit_without_shutdown_calls_sys_exit_1(self):
        with pytest.raises(SystemExit) as exc_info:
            _run_server([
                {"jsonrpc": "2.0", "method": "exit"},
            ])
        assert exc_info.value.code == 1


# ── Unknown request ───────────────────────────────────────────────────────────

class TestUnknownRequest:
    def test_method_not_found_error(self):
        transport = _run_server([
            {"jsonrpc": "2.0", "id": 42, "method": "workspace/unknownMethod"},
        ])
        assert len(transport.sent) == 1
        resp = transport.sent[0]
        assert resp["id"] == 42
        assert resp["error"]["code"] == -32601

    def test_unknown_notification_silently_ignored(self):
        """Notifications (no id) should produce no response."""
        transport = _run_server([
            {"jsonrpc": "2.0", "method": "unknown/notification", "params": {}},
        ])
        assert len(transport.sent) == 0


# ── didOpen / didChange / didSave ─────────────────────────────────────────────

class TestDocumentSync:
    def test_did_open_python_publishes_diagnostics(self):
        code = """\
import sqlite3
from flask import request

def q(cursor):
    uid = request.args.get('id')
    cursor.execute(f"SELECT * FROM users WHERE id = '{uid}'")
"""
        transport = _FakeTransport([
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {
                    "textDocument": {
                        "uri": "file:///app.py",
                        "languageId": "python",
                        "version": 1,
                        "text": code,
                    }
                },
            }
        ])
        server = LspServer(transport=transport, debounce_delay=0.0)
        server.serve()

        import time
        time.sleep(0.05)

        # At least one publishDiagnostics notification
        publishes = [m for m in transport.sent if m.get("method") == "textDocument/publishDiagnostics"]
        assert len(publishes) >= 1
        assert publishes[0]["params"]["uri"] == "file:///app.py"

    def test_did_open_safe_python_publishes_empty_diagnostics(self):
        code = "x = 1\n"
        transport = _FakeTransport([
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {
                    "textDocument": {
                        "uri": "file:///safe.py",
                        "languageId": "python",
                        "version": 1,
                        "text": code,
                    }
                },
            }
        ])
        server = LspServer(transport=transport, debounce_delay=0.0)
        server.serve()
        import time
        time.sleep(0.05)

        publishes = [m for m in transport.sent if m.get("method") == "textDocument/publishDiagnostics"]
        assert len(publishes) >= 1
        assert publishes[0]["params"]["diagnostics"] == []

    def test_did_change_updates_document(self):
        initial = "x = 1\n"
        updated = """\
import sqlite3
from flask import request
def q(c):
    uid = request.args.get('id')
    c.execute(f"SELECT * FROM users WHERE id = '{uid}'")
"""
        transport = _FakeTransport([
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {
                    "textDocument": {"uri": "file:///app.py", "languageId": "python", "version": 1, "text": initial}
                },
            },
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didChange",
                "params": {
                    "textDocument": {"uri": "file:///app.py", "version": 2},
                    "contentChanges": [{"text": updated}],
                },
            },
        ])
        server = LspServer(transport=transport, debounce_delay=0.01)
        server.serve()
        import time
        time.sleep(0.2)  # allow debounce timers to fire

        publishes = [m for m in transport.sent if m.get("method") == "textDocument/publishDiagnostics"]
        # At least one publish from didOpen + one from didChange
        assert len(publishes) >= 1
        # After the change, the last publish should reflect the vulnerable content
        last = publishes[-1]
        assert len(last["params"]["diagnostics"]) > 0

    def test_did_save_triggers_immediate_analysis(self):
        code = """\
import sqlite3
from flask import request
def q(c):
    uid = request.args.get('id')
    c.execute(f"SELECT * FROM users WHERE id = '{uid}'")
"""
        transport = _FakeTransport([
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didSave",
                "params": {
                    "textDocument": {"uri": "file:///app.py"},
                    "text": code,
                },
            }
        ])
        server = LspServer(transport=transport, debounce_delay=0.0)
        server.serve()

        import time
        time.sleep(0.05)

        publishes = [m for m in transport.sent if m.get("method") == "textDocument/publishDiagnostics"]
        assert len(publishes) >= 1
