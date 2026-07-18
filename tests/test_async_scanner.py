from __future__ import annotations

from pathlib import Path

from guardmarly._types import AnalysisResult
from guardmarly.engine.async_scanner import scan_files_sync
from guardmarly.registry.sharded_loader import load_custom_rules_for_code


def _scan_stub(path: Path) -> AnalysisResult:
    return AnalysisResult(file_path=str(path), language="python")


def _scan_stub_maybe_error(path: Path) -> AnalysisResult:
    if path.name == "boom.py":
        raise RuntimeError("simulated worker failure")
    return AnalysisResult(file_path=str(path), language="python")


def test_scan_files_sync_returns_results_for_each_file(tmp_path):
    files = [tmp_path / "a.py", tmp_path / "b.py", tmp_path / "c.py"]
    for file in files:
        file.write_text("print('ok')\n", encoding="utf-8")

    results = scan_files_sync(files, scan_fn=_scan_stub, max_workers=2)

    assert set(results.keys()) == set(files)
    assert all(result.language == "python" for result in results.values())


def test_scan_files_sync_continues_when_one_file_raises(tmp_path):
    files = [tmp_path / "ok.py", tmp_path / "boom.py", tmp_path / "ok2.py"]
    for file in files:
        file.write_text("print('ok')\n", encoding="utf-8")

    results = scan_files_sync(files, scan_fn=_scan_stub_maybe_error, max_workers=3)

    assert files[1] not in results
    assert files[0] in results
    assert files[2] in results


def test_sharded_loader_returns_custom_rules_for_language_specific_code():
    code = "from fastapi import APIRouter\nrouter = APIRouter()\n"

    rules = load_custom_rules_for_code(code, "python")

    assert rules
    assert any(getattr(rule, "rule_id", "").startswith("registry/fastapi/") for rule in rules)
