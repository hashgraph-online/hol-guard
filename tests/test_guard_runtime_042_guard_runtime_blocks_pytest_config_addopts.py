"""Runtime regression tests: guard runtime blocks pytest config addopts."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    extract_sensitive_tool_action_request,
    pytest,
    secret_file_requests_module,
)
from tests.guard_runtime_test_scenarios import (
    _assert_pytest_requires_restricted_profile,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
    _run_guard_hook,
    _write_text,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_guard_runtime_blocks_pytest_config_addopts(tmp_path):
    _write_text(tmp_path / "pytest.ini", "[pytest]\naddopts = --basetemp /tmp/guard-pytest\n")

    module_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "python3 -m pytest tests/test_guard_harness_smoke.py -q"},
        cwd=tmp_path,
    )
    binary_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "pytest tests/test_guard_harness_smoke.py -q"},
        cwd=tmp_path,
    )

    assert module_match is not None
    assert module_match.action_class == "destructive shell command"
    assert binary_match is not None
    assert binary_match.action_class == "destructive shell command"


def test_guard_runtime_requires_restricted_profile_for_pytest_config_without_addopts(tmp_path):
    _write_text(tmp_path / "pyproject.toml", "[tool.pytest.ini_options]\ntestpaths = ['tests']\n")

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "python3 -m pytest tests/test_guard_harness_smoke.py -q"},
        cwd=tmp_path,
    )

    _assert_pytest_requires_restricted_profile(match)


def test_guard_runtime_blocks_selected_test_root_pytest_config_addopts(tmp_path):
    _write_text(tmp_path / "sub" / "pytest.ini", "[pytest]\naddopts = -p evil\n")

    module_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "python3 -m pytest sub -q"},
        cwd=tmp_path,
    )
    binary_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "pytest sub -q"},
        cwd=tmp_path,
    )

    assert module_match is not None
    assert module_match.action_class == "destructive shell command"
    assert binary_match is not None
    assert binary_match.action_class == "destructive shell command"


def test_guard_runtime_checks_dotted_selected_test_root_pytest_config_addopts(tmp_path):
    _write_text(tmp_path / "sub.v1" / "pytest.ini", "[pytest]\naddopts = --junit-xml out.xml\n")

    module_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "python3 -m pytest sub.v1 -q"},
        cwd=tmp_path,
    )
    binary_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "pytest sub.v1 -q"},
        cwd=tmp_path,
    )

    assert module_match is not None
    assert module_match.action_class == "destructive shell command"
    assert binary_match is not None
    assert binary_match.action_class == "destructive shell command"


def test_guard_runtime_blocks_multiline_pytest_config_addopts(tmp_path):
    _write_text(tmp_path / "pytest.ini", "[pytest]\naddopts =\n  --basetemp /tmp/guard-pytest\n")

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "python3 -m pytest tests/test_guard_harness_smoke.py -q"},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_guard_runtime_blocks_pytest_config_junit_xml_alias(tmp_path):
    _write_text(tmp_path / "pytest.ini", "[pytest]\naddopts = --junit-xml /tmp/guard-pytest.xml\n")

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "python3 -m pytest tests/test_guard_harness_smoke.py -q"},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_guard_runtime_blocks_pytest_config_cache_clear(tmp_path):
    _write_text(tmp_path / "pytest.ini", "[pytest]\naddopts = --cache-clear\n")

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "python3 -m pytest tests/test_guard_harness_smoke.py -q"},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_guard_runtime_blocks_pytest_config_log_file(tmp_path):
    _write_text(tmp_path / "pytest.ini", "[pytest]\nlog_file = /tmp/guard-pytest.log\n")

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "python3 -m pytest tests/test_guard_harness_smoke.py -q"},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_guard_runtime_blocks_pytest_config_addopts_log_file(tmp_path):
    _write_text(tmp_path / "pytest.ini", "[pytest]\naddopts = --log-file /tmp/guard.log\n")

    module_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "python3 -m pytest tests/test_guard_harness_smoke.py -q"},
        cwd=tmp_path,
    )
    binary_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "pytest tests/test_guard_harness_smoke.py -q"},
        cwd=tmp_path,
    )

    assert module_match is not None
    assert module_match.action_class == "destructive shell command"
    assert binary_match is not None
    assert binary_match.action_class == "destructive shell command"


def test_guard_runtime_requires_restricted_profile_for_pytest_config_addopts_log_formatting(tmp_path):
    _write_text(
        tmp_path / "pytest.ini",
        "[pytest]\naddopts = --log-file-level INFO --log-file-format %(message)s --log-file-date-format %H:%M:%S\n",
    )

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "python3 -m pytest tests/test_guard_harness_smoke.py -q"},
        cwd=tmp_path,
    )

    _assert_pytest_requires_restricted_profile(match)


def test_guard_runtime_checks_absolute_selected_test_root_pytest_config_addopts(tmp_path):
    test_root = tmp_path / "sub"
    _write_text(test_root / "pytest.ini", "[pytest]\naddopts = -p evil\n")

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": f"python3 -m pytest {test_root} -q"},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_guard_runtime_checks_selected_test_path_ancestor_pytest_config_addopts(tmp_path):
    _write_text(tmp_path / "sub" / "pytest.ini", "[pytest]\naddopts = --basetemp /tmp/guard-pytest\n")

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "python3 -m pytest sub/pkg/test_guard.py -q"},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_guard_runtime_requires_restricted_profile_after_prior_cd(tmp_path):
    (tmp_path / "sub").mkdir()
    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "cd sub && pytest -q"},
        cwd=tmp_path,
    )

    _assert_pytest_requires_restricted_profile(match)


def test_guard_runtime_requires_restricted_profile_after_prior_pushd(tmp_path):
    (tmp_path / "sub").mkdir()
    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "pushd sub >/dev/null; pytest -q"},
        cwd=tmp_path,
    )

    _assert_pytest_requires_restricted_profile(match)


def test_guard_runtime_blocks_prior_exported_pytest_environment(tmp_path):
    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "export PYTEST_ADDOPTS='--basetemp /tmp/guard-pytest'; pytest -q"},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_guard_runtime_blocks_prior_declared_pytest_environment(tmp_path):
    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "declare -x PYTEST_ADDOPTS='--basetemp /tmp/guard-pytest'; pytest -q"},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_guard_runtime_blocks_prior_set_export_before_pytest(tmp_path):
    allexport_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "set -a; PYTEST_ADDOPTS='--basetemp /tmp/guard-pytest'; pytest -q"},
        cwd=tmp_path,
    )
    keyword_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "set -k; pytest -q PYTEST_ADDOPTS='--basetemp /tmp/guard-pytest'"},
        cwd=tmp_path,
    )

    assert allexport_match is not None
    assert allexport_match.action_class == "destructive shell command"
    assert keyword_match is not None
    assert keyword_match.action_class == "destructive shell command"


def test_guard_runtime_blocks_pytest_env_shell_script_wrapper(tmp_path):
    bash_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "PYTEST_ADDOPTS='--basetemp /tmp/guard-pytest' bash -c 'pytest -q'"},
        cwd=tmp_path,
    )
    sh_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "PYTEST_PLUGINS=evil sh -c 'python3 -m pytest -q'"},
        cwd=tmp_path,
    )

    assert bash_match is not None
    assert bash_match.action_class == "destructive shell command"
    assert sh_match is not None
    assert sh_match.action_class == "destructive shell command"


def test_guard_runtime_blocks_shell_startup_env_before_wrapped_pytest(tmp_path):
    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "BASH_ENV=./evil bash -c 'pytest -q'"},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_guard_runtime_blocks_split_exported_pytest_environment(tmp_path):
    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "export PYTEST_ADDOPTS; PYTEST_ADDOPTS='--basetemp /tmp/guard-pytest'; pytest -q"},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_guard_runtime_blocks_prior_path_assignment_before_pytest(tmp_path):
    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "PATH=./tools:$PATH; pytest -q"},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_guard_runtime_blocks_path_overridden_pytest_binary(tmp_path):
    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "PATH=./tools:$PATH pytest tests/test_guard_harness_smoke.py -q"},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_guard_hook_codex_requires_sandbox_for_simple_pytest_command(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(home_dir / ".codex" / "config.toml", 'approval_policy = "on-request"\n')
    _write_text(workspace_dir / ".codex" / "config.toml", "\n")
    event = {
        "event": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": (
                "python3 -m pytest "
                "tests/test_guard_harness_smoke.py::TestSmokeEvidenceTemplate::"
                "test_release_checklist_references_smoke_evidence -q"
            )
        },
        "source_scope": "project",
    }

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
        as_json=True,
    )

    assert rc == 1
    assert output["recorded"] is True
    assert output["policy_action"] == "sandbox-required"
    assert output["terminal"] is True
    assert output["terminal_action"] == "sandbox-required"
    assert output["approval_requests"] == []


def test_guard_runtime_requires_restricted_profile_for_pytest_exit_code_echo(tmp_path):
    (tmp_path / "sub").mkdir()
    match = extract_sensitive_tool_action_request(
        "Bash",
        {
            "command": (
                "cd sub && .venv/bin/python -m pytest "
                "tests/test_guard_harness_smoke.py::TestSmokeEvidenceTemplate::"
                'test_release_checklist_references_smoke_evidence -q 2>&1; echo "__EXIT_CODE__:$?"'
            )
        },
        cwd=tmp_path,
    )

    _assert_pytest_requires_restricted_profile(match)


def test_guard_hook_codex_requires_sandbox_for_pytest_exit_code_echo(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(home_dir / ".codex" / "config.toml", 'approval_policy = "on-request"\n')
    _write_text(workspace_dir / ".codex" / "config.toml", "\n")
    (workspace_dir / "sub").mkdir()
    event = {
        "event": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": (
                "cd sub && .venv/bin/python -m pytest "
                "tests/test_guard_harness_smoke.py::TestSmokeEvidenceTemplate::"
                'test_release_checklist_references_smoke_evidence -q 2>&1; echo "__EXIT_CODE__:$?"'
            )
        },
        "source_scope": "project",
    }

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
        as_json=True,
    )

    assert rc == 1
    assert output["recorded"] is True
    assert output["policy_action"] == "sandbox-required"
    assert output["terminal"] is True
    assert output["terminal_action"] == "sandbox-required"
    assert output["approval_requests"] == []


@pytest.mark.parametrize(
    ("command_suffix",),
    [
        ('echo "$HOME"',),
        ('echo "${VAR}"',),
        ('printf "$PATH"',),
    ],
)
def test_guard_runtime_keeps_static_shell_expansions_blocked_after_safe_pytest(tmp_path, command_suffix):
    (tmp_path / "sub").mkdir()
    match = extract_sensitive_tool_action_request(
        "Bash",
        {
            "command": (
                "cd sub && .venv/bin/python -m pytest "
                "tests/test_guard_harness_smoke.py::TestSmokeEvidenceTemplate::"
                "test_release_checklist_references_smoke_evidence -q 2>&1; "
                f"{command_suffix}"
            )
        },
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_guard_runtime_keeps_mutating_pytest_flags_sensitive(tmp_path):
    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "python3 -m pytest --basetemp /tmp/guard-pytest tests/test_guard_harness_smoke.py -q"},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "destructive shell command"

    binary_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "pytest --basetemp /tmp/guard-pytest tests/test_guard_harness_smoke.py -q"},
        cwd=tmp_path,
    )

    assert binary_match is not None
    assert binary_match.action_class == "destructive shell command"


def test_guard_runtime_keeps_pytest_allowlist_disjoint_from_mutating_flags():
    pytest_mutating_flags = secret_file_requests_module._PYTHON_MODULE_MUTATING_FLAGS["pytest"]

    assert secret_file_requests_module._PYTEST_SAFE_FLAGS.isdisjoint(pytest_mutating_flags)
    assert secret_file_requests_module._PYTEST_SAFE_FLAGS_WITH_VALUES.isdisjoint(pytest_mutating_flags)
