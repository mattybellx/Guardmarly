from __future__ import annotations

import json
from pathlib import Path

from benchmarks.web_wild_harness import (
    SampledFile,
    _collect_repo_files,
    _infer_expected_labels,
    _labels_for_sample,
    _load_curated_labels,
    _select_samples,
    _write_report,
)


def _write_file(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_collect_repo_files_supports_vendor_modes(tmp_path):
    repo_root = tmp_path / "repo"
    app_file = _write_file(repo_root / "src" / "app.js", "console.log('ok');\n")
    vendor_file = _write_file(repo_root / "vendor" / "jquery.min.js", "function x(){return 1;}\n")

    included = _collect_repo_files(repo_root, max_file_bytes=50_000, vendor_mode="include")
    excluded = _collect_repo_files(repo_root, max_file_bytes=50_000, vendor_mode="exclude")
    vendor_only = _collect_repo_files(repo_root, max_file_bytes=50_000, vendor_mode="only")

    assert app_file in included and vendor_file in included
    assert app_file in excluded and vendor_file not in excluded
    assert vendor_only == [vendor_file]


def test_select_samples_balances_across_repos(tmp_path):
    candidates: list[SampledFile] = []
    for repo in ("repo-a/project", "repo-b/project"):
        for index in range(3):
            file_path = _write_file(tmp_path / repo.replace("/", "_") / f"file_{index}.js", "eval(userInput);\n")
            candidates.append(
                SampledFile(
                    repo=repo,
                    path=file_path,
                    relative_path=f"src/file_{index}.js",
                )
            )

    sampled, labeled_pool = _select_samples(
        candidates=candidates,
        n_files=4,
        min_labeled=2,
        seed=1337,
        label_mode="weak",
        curated_labels={},
        sampling_mode="balanced",
    )

    counts: dict[str, int] = {}
    for sample in sampled:
        counts[sample.repo] = counts.get(sample.repo, 0) + 1

    assert labeled_pool == len(candidates)
    assert len(sampled) == 4
    assert set(counts) == {"repo-a/project", "repo-b/project"}
    assert abs(counts["repo-a/project"] - counts["repo-b/project"]) <= 1


def test_hybrid_labels_prefer_curated_manifest(tmp_path):
    sample_file = _write_file(tmp_path / "app.js", "eval(userInput);\n")
    manifest_path = tmp_path / "labels.json"
    manifest_path.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "case_id": "curated-open-redirect",
                        "source": {
                            "kind": "git",
                            "repo": "https://github.com/example/demo.git",
                            "ref": "0123456789abcdef0123456789abcdef01234567",
                            "subdir": "src",
                        },
                        "targets": ["app.js"],
                        "expected_cwes": ["CWE-601"],
                        "notes": "hand-reviewed",
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    curated = _load_curated_labels(manifest_path)
    sample = SampledFile(repo="example/demo", path=sample_file, relative_path="src/app.js")

    labels, reasons, source = _labels_for_sample(
        sample,
        sample_file.read_text(encoding="utf-8"),
        label_mode="hybrid",
        curated_labels=curated,
    )

    assert labels == {"CWE-601"}
    assert source == "curated"
    assert any("hand-reviewed" in reason for reason in reasons)


def test_select_samples_hybrid_prefers_curated_candidates(tmp_path):
    curated_file = _write_file(tmp_path / "curated.js", "eval(userInput);\n")
    weak_file = _write_file(tmp_path / "weak.js", "eval(userInput);\n")
    manifest_path = tmp_path / "labels.json"
    manifest_path.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "case_id": "curated-code-exec",
                        "source": {
                            "kind": "git",
                            "repo": "https://github.com/example/demo.git",
                            "ref": "0123456789abcdef0123456789abcdef01234567",
                            "subdir": "src",
                        },
                        "targets": ["curated.js"],
                        "expected_cwes": ["CWE-95"],
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    curated_labels = _load_curated_labels(manifest_path)
    candidates = [
        SampledFile(repo="example/demo", path=curated_file, relative_path="src/curated.js"),
        SampledFile(repo="example/demo", path=weak_file, relative_path="src/weak.js"),
    ]

    sampled, labeled_pool = _select_samples(
        candidates=candidates,
        n_files=1,
        min_labeled=1,
        seed=1337,
        label_mode="hybrid",
        curated_labels=curated_labels,
        sampling_mode="balanced",
    )

    assert labeled_pool == 2
    assert len(sampled) == 1
    assert sampled[0].relative_path == "src/curated.js"


def test_curated_labels_merge_when_multiple_cases_share_same_file(tmp_path):
    sample_file = _write_file(tmp_path / "app.js", "res.redirect(req.query.next);\n")
    manifest_path = tmp_path / "labels.json"
    manifest_path.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "case_id": "curated-open-redirect",
                        "source": {
                            "kind": "git",
                            "repo": "https://github.com/example/demo.git",
                            "ref": "0123456789abcdef0123456789abcdef01234567",
                            "subdir": "src",
                        },
                        "targets": ["app.js"],
                        "expected_cwes": ["CWE-601"],
                        "notes": "redirect",
                    },
                    {
                        "case_id": "curated-bruteforce",
                        "source": {
                            "kind": "git",
                            "repo": "https://github.com/example/demo.git",
                            "ref": "0123456789abcdef0123456789abcdef01234567",
                            "subdir": "src",
                        },
                        "targets": ["app.js"],
                        "expected_cwes": ["CWE-307"],
                        "notes": "rate-limit",
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    curated = _load_curated_labels(manifest_path)
    sample = SampledFile(repo="example/demo", path=sample_file, relative_path="src/app.js")

    labels, reasons, source = _labels_for_sample(
        sample,
        sample_file.read_text(encoding="utf-8"),
        label_mode="hybrid",
        curated_labels=curated,
    )

    assert labels == {"CWE-307", "CWE-601"}
    assert source == "curated"
    assert any("redirect" in reason for reason in reasons)
    assert any("rate-limit" in reason for reason in reasons)


def test_weak_path_label_requires_user_control_signal():
    labels, reasons = _infer_expected_labels(
        """
import os
def auto_find_instance_path(package_path):
    return os.path.join(package_path, 'instance')
"""
    )

    assert "CWE-22" not in labels
    assert not any("CWE-22" in reason for reason in reasons)


def test_weak_path_label_detects_request_driven_file_access():
    labels, reasons = _infer_expected_labels(
        """
from flask import request
filename = request.args.get('file')
path = os.path.join('/uploads', filename)
with open(path) as f:
    print(f.read())
"""
    )

    assert "CWE-22" in labels
    assert any("CWE-22" in reason for reason in reasons)


def test_weak_path_label_ignores_distant_unrelated_request_and_path_code():
    labels, reasons = _infer_expected_labels(
        """
from flask import request

def read_request():
    return request.args.get('user')









def build_template_path(root_path):
    return os.path.join(root_path, 'templates')
"""
    )

    assert "CWE-22" not in labels
    assert not any("CWE-22" in reason for reason in reasons)


def test_framework_repo_suppresses_noisy_weak_path_labels(tmp_path):
    sample_file = _write_file(tmp_path / "helpers.py", "request.args.get('file')\nopen(path)\n")
    sample = SampledFile(repo="pallets/flask", path=sample_file, relative_path="src/flask/helpers.py")

    labels, reasons, source = _labels_for_sample(
        sample,
        sample_file.read_text(encoding="utf-8"),
        label_mode="weak",
        curated_labels={},
    )

    assert source == "weak"
    assert "CWE-22" not in labels
    assert not any("CWE-22" in reason for reason in reasons)


def test_framework_file_specific_suppressions_remove_known_noise(tmp_path):
    selectbox_file = _write_file(tmp_path / "SelectBox.js", "box.innerHTML = '';\n")
    selectbox_sample = SampledFile(
        repo="django/django",
        path=selectbox_file,
        relative_path="django/contrib/admin/static/admin/js/SelectBox.js",
    )
    shell_file = _write_file(
        tmp_path / "shell.py",
        "import sys\ncode = sys.stdin.read()\nexec(code)\nopen(code)\n",
    )
    shell_sample = SampledFile(
        repo="django/django",
        path=shell_file,
        relative_path="django/core/management/commands/shell.py",
    )
    config_file = _write_file(
        tmp_path / "config.py",
        "SECRET_KEY = 'development key'\nexec(compile(config_file.read(), filename, 'exec'))\n",
    )
    config_sample = SampledFile(
        repo="pallets/flask",
        path=config_file,
        relative_path="src/flask/config.py",
    )
    helpers_file = _write_file(
        tmp_path / "helpers.py",
        "import os\nval = os.environ.get('FLASK_DEBUG')\nrequest.args['name']\nsend_file(path)\n",
    )
    helpers_sample = SampledFile(
        repo="pallets/flask",
        path=helpers_file,
        relative_path="src/flask/helpers.py",
    )
    utils_file = _write_file(
        tmp_path / "utils.py",
        "import os\npath = os.environ.get('PATH', '').split(os.pathsep)\nf = os.path.join('x', 'y')\n",
    )
    utils_sample = SampledFile(
        repo="django/django",
        path=utils_file,
        relative_path="django/core/management/utils.py",
    )
    sqlite_file = _write_file(
        tmp_path / "sqlite_base.py",
        'sql = "SELECT * FROM widgets WHERE id = " + ident\n',
    )
    sqlite_sample = SampledFile(
        repo="django/django",
        path=sqlite_file,
        relative_path="django/db/backends/sqlite3/base.py",
    )
    admin_file = _write_file(
        tmp_path / "admin.py",
        "from django.http import HttpResponseRedirect\nHttpResponseRedirect(request.get_full_path())\n",
    )
    admin_sample = SampledFile(
        repo="django/django",
        path=admin_file,
        relative_path="django/contrib/auth/admin.py",
    )
    autoreload_file = _write_file(
        tmp_path / "autoreload.py",
        "import os\nimport subprocess\npath = os.path.join('/tmp', os.environ.get('X', 'v'))\nsubprocess.run(args)\n",
    )
    autoreload_sample = SampledFile(
        repo="django/django",
        path=autoreload_file,
        relative_path="django/utils/autoreload.py",
    )

    selectbox_labels, _, _ = _labels_for_sample(
        selectbox_sample,
        selectbox_file.read_text(encoding="utf-8"),
        label_mode="weak",
        curated_labels={},
    )
    shell_labels, _, _ = _labels_for_sample(
        shell_sample,
        shell_file.read_text(encoding="utf-8"),
        label_mode="weak",
        curated_labels={},
    )
    config_labels, _, _ = _labels_for_sample(
        config_sample,
        config_file.read_text(encoding="utf-8"),
        label_mode="weak",
        curated_labels={},
    )
    helpers_labels, _, _ = _labels_for_sample(
        helpers_sample,
        helpers_file.read_text(encoding="utf-8"),
        label_mode="weak",
        curated_labels={},
    )
    utils_labels, _, _ = _labels_for_sample(
        utils_sample,
        utils_file.read_text(encoding="utf-8"),
        label_mode="weak",
        curated_labels={},
    )
    sqlite_labels, _, _ = _labels_for_sample(
        sqlite_sample,
        sqlite_file.read_text(encoding="utf-8"),
        label_mode="weak",
        curated_labels={},
    )
    admin_labels, _, _ = _labels_for_sample(
        admin_sample,
        admin_file.read_text(encoding="utf-8"),
        label_mode="weak",
        curated_labels={},
    )
    autoreload_labels, _, _ = _labels_for_sample(
        autoreload_sample,
        autoreload_file.read_text(encoding="utf-8"),
        label_mode="weak",
        curated_labels={},
    )
    cli_file = _write_file(
        tmp_path / "cli.py",
        "import os\nstartup = os.environ.get('PYTHONSTARTUP')\neval(open(startup).read())\n",
    )
    cli_sample = SampledFile(
        repo="pallets/flask",
        path=cli_file,
        relative_path="src/flask/cli.py",
    )
    cli_labels, _, _ = _labels_for_sample(
        cli_sample,
        cli_file.read_text(encoding="utf-8"),
        label_mode="weak",
        curated_labels={},
    )

    assert "CWE-79" not in selectbox_labels
    assert "CWE-22" not in shell_labels
    assert "CWE-95" not in config_labels
    assert "CWE-798" in config_labels
    assert "CWE-22" not in helpers_labels
    assert "CWE-22" not in utils_labels
    assert "CWE-89" not in sqlite_labels
    assert "CWE-601" not in admin_labels
    assert "CWE-22" not in autoreload_labels
    assert "CWE-22" not in cli_labels
    assert "CWE-95" not in cli_labels


def test_framework_repo_keeps_env_driven_path_label_for_cli_like_code(tmp_path):
    sample_file = _write_file(
        tmp_path / "cli.py",
        "import os\nstartup = os.environ.get('PYTHONSTARTUP')\nwith open(startup) as f:\n    print(f.read())\n",
    )
    sample = SampledFile(repo="pallets/flask", path=sample_file, relative_path="src/flask/cli.py")

    labels, reasons, source = _labels_for_sample(
        sample,
        sample_file.read_text(encoding="utf-8"),
        label_mode="weak",
        curated_labels={},
    )

    assert source == "weak"
    # Flask CLI is developer tooling — weak labels for path/code exec are suppressed
    assert "CWE-22" not in labels
    assert "CWE-95" not in labels


def test_weak_labels_include_dynamic_require_and_broader_secret_patterns():
    labels, reasons = _infer_expected_labels(
        """
const env = require(path.resolve(__dirname + '/env/' + name + '.js'));
const cfg = { zapApiKey: 'v9dn0balpqas1pcc281tn5ood1' };
"""
    )

    assert "CWE-98" in labels
    assert "CWE-798" in labels
    assert any("CWE-98" in reason for reason in reasons)
    assert any("CWE-798" in reason for reason in reasons)


def test_weak_command_label_ignores_literal_shell_true_but_flags_dynamic_exec():
    literal_labels, _ = _infer_expected_labels(
        """
import subprocess
subprocess.run('git log --pretty=format:%ct --quiet -1 HEAD', shell=True)
"""
    )
    dynamic_labels, dynamic_reasons = _infer_expected_labels(
        """
var exec = require('child_process').exec;
exec(cmd + 'node artifacts/db-reset.js', function() {});
"""
    )

    assert "CWE-78" not in literal_labels
    assert "CWE-78" in dynamic_labels
    assert any("CWE-78" in reason for reason in dynamic_reasons)


def test_weak_exec_label_is_code_injection_not_command_injection():
    labels, reasons = _infer_expected_labels(
        """
def handle(command):
    exec(command)
"""
    )

    assert "CWE-95" in labels
    assert "CWE-78" not in labels
    assert any("CWE-95" in reason for reason in reasons)


def test_weak_exec_label_ignores_eval_method_definitions():
    labels, _ = _infer_expected_labels(
        """
class Literal:
    def eval(self, context):
        return self.value
"""
    )

    assert "CWE-95" not in labels


def test_weak_exec_label_ignores_eval_method_calls():
    labels, _ = _infer_expected_labels(
        """
def walk(node, context):
    return node.eval(context)
"""
    )

    assert "CWE-95" not in labels


def test_weak_secret_label_ignores_password_prompt_but_flags_real_secret_assignment():
    prompt_labels, _ = _infer_expected_labels(
        """
def _get_pass(prompt='Password: '):
    return prompt
"""
    )
    secret_labels, secret_reasons = _infer_expected_labels(
        """
module.exports = { cookieSecret: 'session_cookie_secret_key_here' };
"""
    )

    assert "CWE-798" not in prompt_labels
    assert "CWE-798" in secret_labels
    assert any("CWE-798" in reason for reason in secret_reasons)


def test_weak_secret_label_accepts_secret_key_values_with_spaces():
    labels, reasons = _infer_expected_labels(
        """
SECRET_KEY = 'development key'
"""
    )

    assert "CWE-798" in labels
    assert any("CWE-798" in reason for reason in reasons)


def test_weak_deserialization_label_recognizes_safe_loader_alias():
    safe_labels, _ = _infer_expected_labels(
        """
from yaml import SafeLoader
import yaml

def parse_config(data):
    return yaml.load(data, Loader=SafeLoader)
"""
    )
    unsafe_labels, unsafe_reasons = _infer_expected_labels(
        """
import yaml

def parse_config(data):
    return yaml.load(data)
"""
    )

    assert "CWE-502" not in safe_labels
    assert "CWE-502" in unsafe_labels
    assert any("CWE-502" in reason for reason in unsafe_reasons)


def test_weak_ssrf_label_recognizes_needle_get_with_user_url():
    labels, reasons = _infer_expected_labels(
        """
const url = req.query.url + req.query.symbol;
needle.get(url, cb);
"""
    )

    assert "CWE-918" in labels
    assert any("CWE-918" in reason for reason in reasons)


def test_weak_sqli_label_requires_real_sql_keywords():
    noisy_labels, _ = _infer_expected_labels(
        """
const selectsSelector = interpolate('#%s, #%s_from, #%s_to', [id, id, id]);
selects.find('option').each(function () {});
"""
    )
    update_labels, _ = _infer_expected_labels(
        """
function updateUser(userId) {
    users.update({ _id: userId }, { $set: profile });
}
"""
    )
    real_labels, real_reasons = _infer_expected_labels(
        """
const sql = "SELECT * FROM users WHERE id = " + userId;
db.execute(sql);
"""
    )

    assert "CWE-89" not in noisy_labels
    assert "CWE-89" not in update_labels
    assert "CWE-89" in real_labels
    assert any("CWE-89" in reason for reason in real_reasons)


def test_write_report_writes_utf8_json(tmp_path):
    output_path = tmp_path / "reports" / "profile.json"
    report = {"summary": {"sampled_files": 1}, "repos": []}

    _write_report(output_path, report)

    assert json.loads(output_path.read_text(encoding="utf-8")) == report
