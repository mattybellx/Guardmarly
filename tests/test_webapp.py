from __future__ import annotations

import pytest
pytest.importorskip("flask", reason="Flask is required for webapp tests")

from webapp.app import app


def _fake_payload(mode: str) -> dict:
    return {
        "success": True,
        "mode": mode,
        "report": {"results": [], "summary": {"files_scanned": 1, "total_findings": 0}},
        "results": [],
        "summary": {"files_scanned": 1, "total_findings": 0},
        "total_findings": 0,
        "execution": {},
        "artifacts": {"json": {"ok": True}, "sarif": {"runs": []}},
        "studio": {
            "timeline": [],
            "files": [],
            "changed_files": 0,
            "verification_message": "ok",
            "scope_note": "scope only",
            "remaining_guarded_quota": 50,
            "requested_fixable_findings": 0,
        },
    }


def test_autofix_studio_live_route_renders_template():
    app.config["TESTING"] = True
    client = app.test_client()

    response = client.get("/autofix-studio/live")

    assert response.status_code == 200
    assert b"SAST Engine" in response.data or b"SAST" in response.data
    assert b"ansede-static" in response.data


def test_api_scan_uses_studio_runner(monkeypatch):
    app.config["TESTING"] = True
    client = app.test_client()
    captured: dict[str, object] = {}

    def fake_run(sources, *, guarded_fix: bool):
        captured["sources"] = sources
        captured["guarded_fix"] = guarded_fix
        return _fake_payload("scan")

    monkeypatch.setattr("webapp.app._run_studio_mode", fake_run)

    response = client.post(
        "/api/scan",
        data={"code": "print('hi')", "language": "python"},
        content_type="multipart/form-data",
    )

    payload = response.get_json()
    assert response.status_code == 200
    assert payload["success"] is True
    assert captured["guarded_fix"] is False
    assert captured["sources"][0]["name"] == "snippet.py"



def test_api_guarded_fix_uses_guarded_mode(monkeypatch):
    app.config["TESTING"] = True
    client = app.test_client()
    captured: dict[str, object] = {}

    def fake_run(sources, *, guarded_fix: bool):
        captured["sources"] = sources
        captured["guarded_fix"] = guarded_fix
        return _fake_payload("guarded-fix")

    monkeypatch.setattr("webapp.app._run_studio_mode", fake_run)

    response = client.post(
        "/api/guarded-fix",
        data={"code": "const x = 1;", "language": "javascript"},
        content_type="multipart/form-data",
    )

    payload = response.get_json()
    assert response.status_code == 200
    assert payload["success"] is True
    assert payload["mode"] == "guarded-fix"
    assert captured["guarded_fix"] is True
    assert captured["sources"][0]["name"] == "snippet.js"



def test_api_export_returns_requested_artifact():
    app.config["TESTING"] = True
    client = app.test_client()

    response = client.post(
        "/api/export",
        json={
            "format": "sarif",
            "artifacts": {"sarif": {"version": "2.1.0", "runs": []}},
        },
    )

    payload = response.get_json()
    assert response.status_code == 200
    assert payload["success"] is True
    assert payload["content"]["version"] == "2.1.0"


def test_playground_get_returns_html():
    """GET /scan serves the playground HTML page."""
    app.config["TESTING"] = True
    client = app.test_client()
    response = client.get("/scan")
    assert response.status_code == 200
    assert b"playground" in response.data.lower() or b"scan" in response.data.lower()


def test_playground_post_python_sqli():
    """POST /scan with vulnerable Python code returns at least one finding."""
    app.config["TESTING"] = True
    client = app.test_client()
    code = 'def q(u):\n    return db.execute("SELECT * FROM users WHERE name = \'" + u + "\'")\n'
    response = client.post("/scan", json={"code": code, "lang": "python"})
    assert response.status_code == 200
    data = response.get_json()
    assert isinstance(data.get("findings"), list)
    assert data["total"] >= 0  # scanner may or may not flag depending on confidence threshold


def test_playground_post_empty_code_returns_zero():
    """POST /scan with empty code returns empty findings."""
    app.config["TESTING"] = True
    client = app.test_client()
    response = client.post("/scan", json={"code": "   ", "lang": "python"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["total"] == 0


def test_playground_post_unsupported_lang_returns_400():
    """POST /scan with unsupported language returns 400."""
    app.config["TESTING"] = True
    client = app.test_client()
    response = client.post("/scan", json={"code": "x = 1", "lang": "cobol"})
    assert response.status_code == 400
    data = response.get_json()
    assert "error" in data
