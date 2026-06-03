"""Tests for the day-zero campaign runner."""
from __future__ import annotations

from pathlib import Path

from tools.day_zero_scanner import (
    CampaignSettings,
    _build_report,
    _build_scan_command,
    _clone_attempts,
    _expand_verification_paths,
    _finding_priority_score,
    _select_hotspot_paths,
    _select_verification_candidates,
    _select_verification_focus_paths,
    _verification_settings,
)


def _settings() -> CampaignSettings:
    return CampaignSettings(
        mode="hotspot",
        workers=4,
        repo_workers=3,
        scan_timeout=90,
        clone_timeout=90,
        timeout_per_file=15,
        max_hotspot_files=4,
        include_tests=False,
        js_backend="classic",
        campaign_budget_seconds=None,
        verify_top_repos=1,
        verify_min_signal_score=100,
        verify_scan_timeout=180,
    )


def _verification_report() -> dict:
    return _build_report(
        run_id="20260603_120200",
        requested_batch=2,
        targets=[{"id": "a"}],
        settings=_settings(),
        results=[
            {
                "repo": "https://github.com/example/a",
                "repo_id": "a",
                "status": "scanned",
                "pass_name": "triage",
                "total_findings": 5,
                "selected_file_count": 24,
                "high_critical_findings": [
                    {"cwe": "CWE-287", "severity": "critical", "title": "Missing auth", "confidence": 0.94, "analysis_kind": "incident-cluster", "confidence_label": "structural"}
                ],
                "likely_real_high_critical": [
                    {"cwe": "CWE-287", "severity": "critical", "title": "Missing auth", "confidence": 0.94, "analysis_kind": "incident-cluster", "confidence_label": "structural"}
                ],
            }
        ],
        verification_candidates=[{"repo": "https://github.com/example/a", "repo_id": "a", "signal_score": 170, "high_critical": 1, "likely_real_high_critical": 1, "status": "scanned", "total_findings": 5}],
        verification_results=[
            {
                "repo": "https://github.com/example/a",
                "repo_id": "a",
                "status": "scanned",
                "pass_name": "verification",
                "total_findings": 2,
                "selected_file_count": 72,
                "high_critical_findings": [
                    {"cwe": "CWE-22", "severity": "critical", "title": "Path traversal", "confidence": 0.7, "analysis_kind": "custom-pattern", "confidence_label": "heuristic"}
                ],
                "likely_real_high_critical": [],
            }
        ],
    )


def test_clone_attempts_prefers_sparse_for_hotspot_mode():
    attempts = _clone_attempts("https://github.com/example/repo", Path("repo"), "hotspot")
    assert attempts[0][0] == "sparse"
    assert attempts[1][0] == "full"


def test_clone_attempts_only_full_for_deep_mode():
    attempts = _clone_attempts("https://github.com/example/repo", Path("repo"), "deep")
    assert attempts == [
        ("full", ["git", "clone", "--depth", "1", "https://github.com/example/repo", "repo"])
    ]


def test_select_hotspots_prefers_auth_and_routes_and_skips_tests():
    source_paths = [
        "tests/test_auth.py",
        "docs/example_login.py",
        "src/api/routes.py",
        "src/auth/session_manager.py",
        "src/models/user.py",
        "src/utils/strings.py",
    ]
    selected = _select_hotspot_paths(source_paths, max_files=3, include_tests=False)
    assert "src/auth/session_manager.py" in selected
    assert "src/api/routes.py" in selected
    assert "tests/test_auth.py" not in selected


def test_build_scan_command_enables_parallel_cli():
    cmd = _build_scan_command([Path("repo")], _settings())
    assert "--parallel" in cmd
    assert "--workers" in cmd
    assert "4" in cmd
    assert "--timeout-per-file" in cmd
    assert "15" in cmd


def test_build_report_aggregates_statuses_and_likely_real_findings():
    report = _build_report(
        run_id="20260603_120000",
        requested_batch=2,
        targets=[{"id": "a"}, {"id": "b"}],
        settings=_settings(),
        results=[
            {
                "repo": "https://github.com/example/a",
                "repo_id": "a",
                "status": "scanned",
                "total_findings": 5,
                "high_critical_findings": [
                    {"cwe": "CWE-862", "severity": "high", "title": "Missing auth"}
                ],
                "likely_real_high_critical": [
                    {"cwe": "CWE-862", "severity": "high", "title": "Missing auth"}
                ],
            },
            {
                "repo": "https://github.com/example/b",
                "repo_id": "b",
                "status": "scan-timeout",
                "total_findings": 0,
                "high_critical_findings": [],
                "likely_real_high_critical": [],
            },
        ],
    )
    assert report["summary"]["status_counts"] == {"scanned": 1, "scan-timeout": 1}
    assert report["summary"]["total_findings"] == 5
    assert report["summary"]["total_high_critical"] == 1
    assert report["summary"]["total_likely_real_high_critical"] == 1
    assert report["summary"]["top_cwes"][0] == {"cwe": "CWE-862", "count": 1}


def test_priority_score_prefers_structural_auth_over_log_injection_noise():
    structural_auth = {
        "cwe": "CWE-287",
        "severity": "critical",
        "title": "FastAPI route uses Depends without auth verification",
        "confidence": 0.94,
        "analysis_kind": "incident-cluster",
        "confidence_label": "structural",
    }
    noisy_log = {
        "cwe": "CWE-117",
        "severity": "critical",
        "title": "Log Injection in admin action",
        "confidence": 1.0,
        "analysis_kind": "pattern",
        "confidence_label": "heuristic",
    }
    assert _finding_priority_score(structural_auth) > _finding_priority_score(noisy_log)


def test_build_report_exposes_priority_candidates_and_budget_deferred_targets():
    settings = CampaignSettings(
        mode="hotspot",
        workers=4,
        repo_workers=2,
        scan_timeout=90,
        clone_timeout=90,
        timeout_per_file=15,
        max_hotspot_files=4,
        include_tests=False,
        js_backend="classic",
        campaign_budget_seconds=10,
        verify_top_repos=1,
        verify_min_signal_score=100,
        verify_scan_timeout=180,
    )
    report = _build_report(
        run_id="20260603_120100",
        requested_batch=3,
        targets=[{"id": "a"}, {"id": "b"}, {"id": "c", "url": "https://github.com/example/c"}],
        settings=settings,
        results=[
            {
                "repo": "https://github.com/example/a",
                "repo_id": "a",
                "status": "scanned",
                "total_findings": 7,
                "high_critical_findings": [
                    {
                        "cwe": "CWE-117",
                        "severity": "critical",
                        "title": "Log Injection in admin action",
                        "confidence": 1.0,
                        "analysis_kind": "pattern",
                        "confidence_label": "heuristic",
                    },
                    {
                        "cwe": "CWE-287",
                        "severity": "critical",
                        "title": "FastAPI route uses Depends without auth verification",
                        "confidence": 0.94,
                        "analysis_kind": "incident-cluster",
                        "confidence_label": "structural",
                    },
                ],
                "likely_real_high_critical": [
                    {
                        "cwe": "CWE-287",
                        "severity": "critical",
                        "title": "FastAPI route uses Depends without auth verification",
                        "confidence": 0.94,
                        "analysis_kind": "incident-cluster",
                        "confidence_label": "structural",
                    }
                ],
            }
        ],
        unstarted_targets=[{"id": "c", "url": "https://github.com/example/c"}],
    )
    assert report["summary"]["budget_exhausted"] is True
    assert report["summary"]["unstarted_target_count"] == 1
    assert report["summary"]["priority_candidates"][0]["cwe"] == "CWE-287"
    assert report["summary"]["top_signal_cwes"][0] == {"cwe": "CWE-287", "count": 1}
    assert report["summary"]["top_repos_by_signal"][0]["repo_id"] == "a"


def test_select_verification_candidates_prefers_high_signal_scanned_repos():
    candidates = _select_verification_candidates(
        [
            {
                "repo": "https://github.com/example/a",
                "repo_id": "a",
                "status": "scanned",
                "total_findings": 7,
                "high_critical_findings": [{"cwe": "CWE-287", "severity": "critical", "title": "Missing auth", "confidence": 0.94, "analysis_kind": "incident-cluster", "confidence_label": "structural"}],
                "likely_real_high_critical": [{"cwe": "CWE-287", "severity": "critical", "title": "Missing auth", "confidence": 0.94, "analysis_kind": "incident-cluster", "confidence_label": "structural"}],
            },
            {
                "repo": "https://github.com/example/b",
                "repo_id": "b",
                "status": "scanned",
                "total_findings": 3,
                "high_critical_findings": [{"cwe": "CWE-22", "severity": "high", "title": "Path traversal", "confidence": 0.7, "analysis_kind": "custom-pattern", "confidence_label": "heuristic"}],
                "likely_real_high_critical": [],
            },
            {
                "repo": "https://github.com/example/c",
                "repo_id": "c",
                "status": "campaign-budget-expired",
                "total_findings": 0,
                "high_critical_findings": [],
                "likely_real_high_critical": [],
            },
        ],
        limit=1,
        min_signal_score=100,
    )
    assert [candidate["repo_id"] for candidate in candidates] == ["a"]


def test_verification_settings_switches_to_deep_single_repo_pass():
    settings = _verification_settings(_settings())
    assert settings.mode == "deep"
    assert settings.repo_workers == 1
    assert settings.verify_top_repos == 0
    assert settings.max_hotspot_files >= 72


def test_select_verification_focus_paths_prefers_files_with_strong_hits():
    focus_paths = _select_verification_focus_paths(
        {
            "selected_paths": [
                "backend/auths.py",
                "backend/files.py",
                "backend/config.py",
            ],
            "high_critical_findings": [
                {
                    "file": "C:/tmp/repo/backend/auths.py",
                    "cwe": "CWE-287",
                    "severity": "critical",
                    "title": "Missing auth",
                    "confidence": 0.94,
                    "analysis_kind": "incident-cluster",
                    "confidence_label": "structural",
                },
                {
                    "file": "C:/tmp/repo/backend/files.py",
                    "cwe": "CWE-22",
                    "severity": "high",
                    "title": "Path traversal",
                    "confidence": 0.7,
                    "analysis_kind": "custom-pattern",
                    "confidence_label": "heuristic",
                },
            ],
        },
        limit=2,
    )
    assert focus_paths[0] == "backend/auths.py"


def test_select_verification_focus_paths_breaks_ties_toward_auth_router_config_context():
    focus_paths = _select_verification_focus_paths(
        {
            "selected_paths": [
                "backend/utils.py",
                "backend/router.py",
                "backend/config.py",
            ],
            "high_critical_findings": [
                {
                    "file": "C:/tmp/repo/backend/utils.py",
                    "cwe": "CWE-22",
                    "severity": "high",
                    "title": "Path traversal",
                    "confidence": 0.7,
                    "analysis_kind": "custom-pattern",
                    "confidence_label": "heuristic",
                },
                {
                    "file": "C:/tmp/repo/backend/router.py",
                    "cwe": "CWE-22",
                    "severity": "high",
                    "title": "Path traversal",
                    "confidence": 0.7,
                    "analysis_kind": "custom-pattern",
                    "confidence_label": "heuristic",
                },
            ],
        },
        limit=3,
    )
    assert focus_paths[:2] == ["backend/router.py", "backend/config.py"]


def test_expand_verification_paths_adds_contextual_siblings_under_cap():
    expanded = _expand_verification_paths(
        [
            "backend/auths.py",
            "backend/config.py",
            "backend/models.py",
            "backend/utils.py",
            "workers/jobs.py",
        ],
        ["backend/auths.py"],
        max_files=3,
        siblings_per_focus=2,
    )
    assert "backend/auths.py" in expanded
    assert len(expanded) == 3
    assert any(path in expanded for path in {"backend/config.py", "backend/models.py"})


def test_build_report_includes_verification_summary_and_comparison():
    report = _verification_report()
    assert report["summary"]["verification_candidate_count"] == 1
    assert report["summary"]["verification_attempted_targets"] == 1
    assert report["summary"]["verification_total_high_critical"] == 1
    assert report["summary"]["verification_comparisons"][0]["repo_id"] == "a"
    assert report["verification_high_critical_log"][0]["pass_name"] == "verification"


def test_build_report_includes_verification_efficiency_metrics():
    report = _verification_report()
    assert report["summary"]["verification_comparisons"][0]["triage_selected_file_count"] == 24
    assert report["summary"]["verification_comparisons"][0]["verification_selected_file_count"] == 72
    assert report["summary"]["verification_comparisons"][0]["extra_verification_files"] == 48
    assert report["summary"]["verification_comparisons"][0]["signal_retained_per_extra_file"] == 2.2917
    assert report["summary"]["verification_comparisons"][0]["verification_lift_rate"] == 0.0
    assert report["summary"]["verification_efficiency"]["triage_files_scanned"] == 24
    assert report["summary"]["verification_efficiency"]["verification_files_scanned"] == 72
    assert report["summary"]["verification_efficiency"]["extra_verification_files_scanned"] == 48
    assert report["summary"]["verification_efficiency"]["signal_retained_per_extra_file"] == 2.2917
    assert report["summary"]["verification_efficiency"]["verification_lift_rate"] == 0.0
