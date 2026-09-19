"""Runtime regression tests: guard hook emits copilot native allow response."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    guard_commands_module,
    io,
    json,
    main,
    sys,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_guard_hook_emits_copilot_native_allow_response_for_echoed_node_eval_string(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": """echo node -e "require('fs').unlinkSync('dangerous-marker.json')" """}),
        "sourceScope": "project",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))

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
    assert output == {"permissionDecision": "allow"}


def test_guard_hook_emits_copilot_native_allow_response_for_benign_find_ok_delete_literal(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": """find . -name dangerous-marker.json -ok echo "-delete" \\;"""}),
        "sourceScope": "project",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))

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
    assert output == {"permissionDecision": "allow"}


def test_guard_hook_emits_copilot_native_allow_response_for_perl_sleep_wait(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": "perl -e 'sleep 310'"}),
        "sourceScope": "project",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))

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
    assert output == {"permissionDecision": "allow"}


def test_guard_hook_emits_copilot_native_allow_response_for_git_commit_with_coauthored_by_trailer(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps(
            {
                "command": (
                    f"cd {workspace_dir} && "
                    "git add src/codex_plugin_scanner/guard/runtime/runner.py "
                    "src/codex_plugin_scanner/guard/runtime/__init__.py "
                    "src/codex_plugin_scanner/guard/cli/connect_flow.py && "
                    'git commit -m "fix(guard): gracefully handle free-plan sync 403 in connect flow\n\n'
                    'Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>" 2>&1'
                )
            }
        ),
        "sourceScope": "project",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))

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


def test_guard_hook_emits_copilot_native_deny_for_node_inline_delete_bypass(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": """node -e "require('fs').unlinkSync('dangerous-marker.json')" """}),
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
    assert "hol guard" in output["permissionDecisionReason"].lower()


def test_guard_hook_emits_copilot_native_deny_for_git_rm_delete(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": "git rm --force dangerous-shell-marker.txt"}),
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
    assert "hol guard" in output["permissionDecisionReason"].lower()


def test_guard_hook_emits_copilot_native_deny_for_find_exec_rm_bypass(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": "find . -name dangerous-shell-marker.txt -exec rm {} ;"}),
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
    assert "hol guard" in output["permissionDecisionReason"].lower()


def test_guard_hook_emits_copilot_native_deny_for_git_c_rm_delete(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps(
            {
                "command": "git -C /mock-workspace rm --force dangerous-shell-marker.txt",
            }
        ),
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
    assert "hol guard" in output["permissionDecisionReason"].lower()


def test_guard_hook_emits_copilot_native_deny_for_node_template_interpolation_bypass(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps(
            {
                "command": """node -e "console.log(`x ${require('fs').unlinkSync('dangerous-marker.json')}`)" """,
            }
        ),
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
    assert "hol guard" in output["permissionDecisionReason"].lower()


def test_guard_hook_emits_copilot_native_deny_for_node_template_interpolation_regex_bypass(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    command = (
        """node -e "console.log(`x ${/}/.test('a') || """
        """require('fs').unlinkSync('dangerous-marker.json')}`)" """
    )
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": command}),
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
    assert "hol guard" in output["permissionDecisionReason"].lower()


def test_guard_hook_emits_copilot_native_allow_for_git_help_modes(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": "git --help rm"}),
        "sourceScope": "project",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))

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
    assert output == {"permissionDecision": "allow"}


def test_guard_hook_emits_copilot_native_deny_for_quoted_space_redirection_target(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": '''echo owned >"dangerous marker.json"'''}),
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
    assert "hol guard" in output["permissionDecisionReason"].lower()
