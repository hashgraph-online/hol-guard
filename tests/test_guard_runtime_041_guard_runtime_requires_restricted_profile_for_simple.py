"""Runtime regression tests: guard runtime requires restricted profile for simple."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    extract_sensitive_file_write_request,
    extract_sensitive_tool_action_request,
    guard_commands_module,
    io,
    json,
    main,
    pytest,
    secret_file_requests_module,
    sys,
)
from tests.guard_runtime_test_scenarios import (
    _assert_pytest_requires_restricted_profile,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
    _write_text,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_guard_runtime_requires_restricted_profile_for_simple_pytest_module_invocation(tmp_path):
    match = extract_sensitive_tool_action_request(
        "Bash",
        {
            "command": (
                "python3 -m pytest "
                "tests/test_guard_harness_smoke.py::TestSmokeEvidenceTemplate::"
                "test_release_checklist_references_smoke_evidence -q"
            )
        },
        cwd=tmp_path,
    )

    _assert_pytest_requires_restricted_profile(match)


@pytest.mark.parametrize(
    "command",
    (
        "python -c \"import os; os.system('pytest -q')\"",
        "python -c \"import os as ops; ops.popen('python -m pytest -q')\"",
        "python -c \"from os import system as launch; launch('pytest -q')\"",
        "python -c \"import subprocess; subprocess.run(['pytest', '-q'])\"",
        "python -c \"import subprocess as sp; sp.call(('python3', '-m', 'pytest', '-q'))\"",
        "python -c \"import subprocess as sp; sp.check_call(args=['pytest', '-q'])\"",
        "python -c \"import subprocess as sp; sp.check_output(['py.test', '-q'])\"",
        "python -c \"from subprocess import Popen as launch; launch(('pytest', '-q'))\"",
        "python -c \"from subprocess import run as launch; launch('pytest -q')\"",
    ),
)
def test_guard_runtime_requires_restricted_profile_for_inline_process_pytest(command, tmp_path):
    assert secret_file_requests_module._shell_command_targets_pytest(command)

    match = extract_sensitive_tool_action_request("Bash", {"command": command}, cwd=tmp_path)

    assert match is not None
    assert match.guard_default_action == "sandbox-required"
    assert match.reason_code == "pytest_restricted_profile_required"


def test_guard_runtime_does_not_target_harmless_inline_process_command():
    command = "python -c \"import subprocess as sp; sp.run(['echo', 'harmless'])\""

    assert not secret_file_requests_module._shell_command_targets_pytest(
        command,
    )


def test_guard_runtime_allows_apply_patch_to_non_sensitive_source_file(tmp_path):
    patch = """*** Begin Patch
*** Update File: src/codex_plugin_scanner/guard/runtime/secret_file_requests.py
@@
+def _shell_interpreter_flag_payload(parts: list[str], index: int) -> object:
+    return _interpreter_flag_payload(parts, index)
*** End Patch"""

    match = extract_sensitive_file_write_request("apply_patch", {"input": patch}, cwd=tmp_path)

    assert match is None


def test_guard_runtime_does_not_execute_classify_apply_patch_content(tmp_path):
    patch = """*** Begin Patch
*** Update File: docs/notes.md
@@
+Routine maintenance uses `gh pr merge 17 --squash --delete-branch`.
*** End Patch"""

    match = extract_sensitive_tool_action_request("apply_patch", patch, cwd=tmp_path)

    assert match is None


def test_guard_runtime_blocks_apply_patch_to_sensitive_file(tmp_path):
    patch = """*** Begin Patch
*** Update File: .env
@@
-TOKEN=old
+TOKEN=new
*** End Patch"""

    match = extract_sensitive_file_write_request("apply_patch", {"input": patch}, cwd=tmp_path)

    assert match is not None
    assert match.path_class == "local .env file"


def test_guard_runtime_checks_all_apply_patch_payload_keys(tmp_path):
    sensitive_patch = """*** Begin Patch
*** Update File: .env
@@
-TOKEN=old
+TOKEN=new
*** End Patch"""

    match = extract_sensitive_file_write_request(
        "apply_patch",
        {"patch": "no patch headers", "input": sensitive_patch},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.path_class == "local .env file"


def test_guard_runtime_ignores_patch_syntax_for_other_write_tools(tmp_path):
    match = extract_sensitive_file_write_request(
        "write",
        {"input": "*** Update File: .env\n..."},
        cwd=tmp_path,
    )

    assert match is None


def test_guard_runtime_requires_restricted_profile_for_cd_prefixed_pytest_module_invocation(tmp_path):
    (tmp_path / "tests").mkdir()
    match = extract_sensitive_tool_action_request(
        "Bash",
        {
            "command": (
                "cd tests && python3 -m pytest "
                "test_guard_harness_smoke.py::TestSmokeEvidenceTemplate::"
                "test_release_checklist_references_smoke_evidence -q"
            )
        },
        cwd=tmp_path,
    )

    _assert_pytest_requires_restricted_profile(match)


def test_guard_runtime_allows_ruff_check_and_fix_module_invocations(tmp_path):
    for command in (
        "python3 -m ruff check src/codex_plugin_scanner/guard/runtime/secret_file_requests.py",
        "python3 -m ruff check --fix src/codex_plugin_scanner/guard/runtime/secret_file_requests.py",
        "PYTHONPATH=src python3 -m ruff check --fix src/codex_plugin_scanner/guard/runtime/secret_file_requests.py",
    ):
        match = extract_sensitive_tool_action_request("Bash", {"command": command}, cwd=tmp_path)
        assert match is None, command


def test_guard_runtime_allows_chained_cd_and_ruff_dev_workflow(tmp_path):
    (tmp_path / "tests").mkdir()
    command = (
        "cd tests && PYTHONPATH=src python3 -m ruff check --fix ../src/foo.py 2>&1 && "
        "PYTHONPATH=src python3 -m ruff check ../src/foo.py 2>&1"
    )
    match = extract_sensitive_tool_action_request("Bash", {"command": command}, cwd=tmp_path)

    assert match is None


def test_guard_runtime_allows_gh_graphql_pipeline_with_python_parser(tmp_path):
    command = (
        "gh api graphql -f query='query { viewer { login } }' 2>&1 | "
        "python3 -c \"import json,sys; print(json.load(sys.stdin)['data']['viewer']['login'])\""
    )
    match = extract_sensitive_tool_action_request("Bash", {"command": command}, cwd=tmp_path)

    assert match is None


def test_guard_runtime_allows_lean_ctx_wrapped_gh_graphql_pipeline(tmp_path):
    command = (
        "/path/to/lean-ctx -c 'gh api graphql -f query='\\''query { viewer { login } }'\\''' 2>&1 | "
        "python3 -c \"import json,sys; print(json.load(sys.stdin)['data']['viewer']['login'])\""
    )
    match = extract_sensitive_tool_action_request("Bash", {"command": command}, cwd=tmp_path)

    assert match is None


def test_guard_hook_reviews_github_repository_update(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": "gh api repos/example/project -f name=updated --jq '.name' | jq -r '.'"}),
        "sourceScope": "project",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )

    rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "copilot",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["permissionDecision"] == "deny"
    assert "GitHub remote mutation command" in output["permissionDecisionReason"]


def test_guard_runtime_blocks_unsafe_cd_before_pytest_module_invocation(tmp_path):
    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "cd $(rm -rf marker) && python3 -m pytest -q"},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "unresolved shell execution context"
    assert match.shell_execution_context_reason_code == "shell_cwd_unresolved_expression"


def test_guard_runtime_blocks_pythonpath_ruff_module_shadow(tmp_path):
    malicious_dir = tmp_path / "malicious"
    malicious_dir.mkdir()
    _write_text(malicious_dir / "ruff.py", "from pathlib import Path; Path('marker').write_text('owned')\n")

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "PYTHONPATH=./malicious python3 -m ruff check --fix ."},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_guard_runtime_allows_cd_with_parentheses_in_directory_name(tmp_path):
    project_dir = tmp_path / "project (2024)"
    project_dir.mkdir()
    tests_dir = project_dir / "tests"
    tests_dir.mkdir()

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": f'cd "{project_dir.name}" && python3 -m ruff check ../src/foo.py'},
        cwd=tmp_path,
    )

    assert match is None


def test_guard_runtime_blocks_shadowed_pytest_module_invocation(tmp_path):
    _write_text(tmp_path / "pytest.py", "from pathlib import Path; Path('marker').write_text('owned')\n")

    match = extract_sensitive_tool_action_request("Bash", {"command": "python3 -m pytest -q"}, cwd=tmp_path)

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_guard_runtime_blocks_sourceless_pytest_bytecode_shadow(tmp_path):
    _write_text(tmp_path / "pytest.pyc", "not-real-bytecode")

    match = extract_sensitive_tool_action_request("Bash", {"command": "python3 -m pytest -q"}, cwd=tmp_path)

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_guard_runtime_blocks_pytest_package_main_shadow(tmp_path):
    _write_text(tmp_path / "pytest" / "__main__.py", "from pathlib import Path; Path('marker').write_text('owned')\n")

    match = extract_sensitive_tool_action_request("Bash", {"command": "python3 -m pytest -q"}, cwd=tmp_path)

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_guard_runtime_blocks_pytest_package_bytecode_shadow(tmp_path):
    _write_text(tmp_path / "pytest" / "__init__.pyc", "not-real-bytecode")

    match = extract_sensitive_tool_action_request("Bash", {"command": "python3 -m pytest -q"}, cwd=tmp_path)

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_guard_runtime_blocks_local_pytest_entry_point_metadata(tmp_path):
    _write_text(tmp_path / "evil-1.0.dist-info" / "entry_points.txt", "[pytest11]\nevil = evil\n")

    match = extract_sensitive_tool_action_request("Bash", {"command": "python3 -m pytest -q"}, cwd=tmp_path)

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_guard_runtime_requires_restricted_profile_for_simple_pytest_binary_invocation(tmp_path):
    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "pytest tests/test_guard_harness_smoke.py -q"},
        cwd=tmp_path,
    )

    _assert_pytest_requires_restricted_profile(match)


def test_guard_runtime_blocks_pytest_binary_addopts(tmp_path):
    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "PYTEST_ADDOPTS='--basetemp /tmp/guard-pytest' pytest tests/test_guard_harness_smoke.py -q"},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_guard_runtime_blocks_pythonpath_pytest_module_override(tmp_path):
    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "env PYTHONPATH=./tools python3 -m pytest tests/test_guard_harness_smoke.py -q"},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_guard_runtime_blocks_pythonuserbase_pytest_module_override(tmp_path):
    module_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "PYTHONUSERBASE=./ub python3 -m pytest -q"},
        cwd=tmp_path,
    )
    binary_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "PYTHONUSERBASE=./ub pytest -q"},
        cwd=tmp_path,
    )

    assert module_match is not None
    assert module_match.action_class == "destructive shell command"
    assert binary_match is not None
    assert binary_match.action_class == "destructive shell command"


def test_guard_runtime_blocks_pytest_plugin_env_override(tmp_path):
    module_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "PYTEST_PLUGINS=evil python3 -m pytest tests/test_guard_harness_smoke.py -q"},
        cwd=tmp_path,
    )
    binary_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "PYTEST_PLUGINS=evil pytest tests/test_guard_harness_smoke.py -q"},
        cwd=tmp_path,
    )

    assert module_match is not None
    assert module_match.action_class == "destructive shell command"
    assert binary_match is not None
    assert binary_match.action_class == "destructive shell command"


def test_guard_runtime_blocks_pytest_append_assignment_env_override(tmp_path):
    module_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "PYTEST_ADDOPTS+='--junit-xml out.xml' python3 -m pytest -q"},
        cwd=tmp_path,
    )
    binary_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "PYTHONPATH+=:./tools pytest -q"},
        cwd=tmp_path,
    )

    assert module_match is not None
    assert module_match.action_class == "destructive shell command"
    assert binary_match is not None
    assert binary_match.action_class == "destructive shell command"


def test_guard_runtime_blocks_env_split_string_before_pytest(tmp_path):
    module_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "env -S 'rm -rf /tmp/x' python3 -m pytest -q"},
        cwd=tmp_path,
    )
    binary_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "env --split-string='rm -rf /tmp/x' pytest -q"},
        cwd=tmp_path,
    )

    assert module_match is not None
    assert module_match.action_class == "destructive shell command"
    assert binary_match is not None
    assert binary_match.action_class == "destructive shell command"


def test_guard_runtime_blocks_process_substitution_before_pytest(tmp_path):
    module_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "python3 -m pytest <(rm marker) -q"},
        cwd=tmp_path,
    )
    binary_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "pytest >(rm marker) -q"},
        cwd=tmp_path,
    )

    assert module_match is not None
    assert module_match.action_class == "destructive shell command"
    assert binary_match is not None
    assert binary_match.action_class == "destructive shell command"


def test_guard_runtime_blocks_env_chdir_pytest_shadow_bypass(tmp_path):
    module_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "env --chdir ./shadow python3 -m pytest tests/test_guard_harness_smoke.py -q"},
        cwd=tmp_path,
    )
    binary_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "env -C ./shadow pytest tests/test_guard_harness_smoke.py -q"},
        cwd=tmp_path,
    )

    assert module_match is not None
    assert module_match.action_class == "destructive shell command"
    assert binary_match is not None
    assert binary_match.action_class == "destructive shell command"


def test_guard_runtime_blocks_sudo_chdir_pytest_shadow_bypass(tmp_path):
    module_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "sudo -D ./shadow python3 -m pytest tests/test_guard_harness_smoke.py -q"},
        cwd=tmp_path,
    )
    binary_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "sudo --chdir=./shadow pytest tests/test_guard_harness_smoke.py -q"},
        cwd=tmp_path,
    )

    assert module_match is not None
    assert module_match.action_class == "destructive shell command"
    assert binary_match is not None
    assert binary_match.action_class == "destructive shell command"
