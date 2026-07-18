from __future__ import annotations

from pathlib import Path

from guardmarly.analysis.framework_detector import detect_framework_profile
from guardmarly.analysis.interprocedural import build_project_index


def test_framework_detector_identifies_flask_and_fastapi_signals():
    profile = detect_framework_profile(
        "from flask import Flask\n"
        "from flask_login import login_required\n"
        "from fastapi import APIRouter\n"
        "from fastapi import Depends\n"
        "app = Flask(__name__)\n"
        "router = APIRouter()\n"
        "@login_required\n"
        "@router.get('/x')\n"
        "def x(user=Depends(lambda: 'ok')):\n"
        "    return {'ok': True}\n"
    )
    assert profile.flask is True
    assert profile.fastapi is True


def test_build_project_index_collects_symbols_and_imports(tmp_path: Path):
    package = tmp_path / "app"
    package.mkdir()

    (package / "service.py").write_text(
        "def fetch_user(user_id):\n"
        "    return user_id\n",
        encoding="utf-8",
    )
    (package / "api.py").write_text(
        "from app.service import fetch_user\n"
        "def handler(user_id):\n"
        "    return fetch_user(user_id)\n",
        encoding="utf-8",
    )

    index = build_project_index(tmp_path)

    assert "app.service.fetch_user" in index.symbols
    assert "app.api.handler" in index.symbols
    assert any(name.endswith("fetch_user") for name in index.imports.get("app.api", ()))
