"""Runtime regression tests: guard hook emits copilot native ask response."""

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


def test_guard_hook_emits_copilot_native_ask_response_for_node_title_option_before_eval_delete(
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
            {"command": """node --title guard-proof -e "require('fs').unlinkSync('dangerous-marker.json')" """}
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
    assert "approve it in hol guard, then retry." in output["permissionDecisionReason"].lower()


def test_guard_hook_emits_copilot_native_ask_response_for_uppercase_node_eval_delete(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": """NODE -e "require('fs').unlinkSync('dangerous-marker.json')" """}),
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
    assert "approve it in hol guard, then retry." in output["permissionDecisionReason"].lower()


def test_guard_hook_emits_copilot_native_ask_response_for_unlink_delete_bypass(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": "unlink dangerous-marker.json"}),
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
    assert "approve it in hol guard, then retry." in output["permissionDecisionReason"].lower()


def test_guard_hook_emits_copilot_native_ask_response_for_node_inline_bracket_delete_bypass(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": """node -e "require('fs')['unlinkSync']('dangerous-marker.json')" """}),
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
    assert "approve it in hol guard, then retry." in output["permissionDecisionReason"].lower()


def test_guard_hook_emits_copilot_native_ask_response_for_node_inline_parenthesized_delete_bypass(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": """node -e "(require('fs').unlinkSync)('dangerous-marker.json')" """}),
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
    assert "approve it in hol guard, then retry." in output["permissionDecisionReason"].lower()


def test_guard_hook_emits_copilot_native_ask_response_for_node_inline_optional_chain_delete_bypass(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": """node -e "require('fs').unlinkSync?.('dangerous-marker.json')" """}),
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
    assert "approve it in hol guard, then retry." in output["permissionDecisionReason"].lower()


def test_guard_hook_emits_copilot_native_ask_response_for_node_inline_call_delete_bypass(
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
            {"command": """node -e "require('fs').unlinkSync.call(null, 'dangerous-marker.json')" """}
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
    assert "approve it in hol guard, then retry." in output["permissionDecisionReason"].lower()


def test_guard_hook_emits_copilot_native_ask_response_for_node_inline_apply_delete_bypass(
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
            {"command": """node -e "require('fs').unlinkSync.apply(null, ['dangerous-marker.json'])" """}
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
    assert "approve it in hol guard, then retry." in output["permissionDecisionReason"].lower()


def test_guard_hook_emits_copilot_native_ask_response_for_node_inline_optional_chain_apply_delete_bypass(
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
            {"command": """node -e "require('fs').unlinkSync?.apply(null, ['dangerous-marker.json'])" """}
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
    assert "approve it in hol guard, then retry." in output["permissionDecisionReason"].lower()


def test_guard_hook_emits_copilot_native_ask_response_for_env_split_string_find_delete(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": """env -S "find . -name dangerous-marker.json -delete" """}),
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
    assert "approve it in hol guard, then retry." in output["permissionDecisionReason"].lower()


def test_guard_hook_emits_copilot_native_ask_response_for_env_split_string_node_eval_delete(
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
            {"command": """env -S "node -e \\\"require('fs').unlinkSync('dangerous-marker.json')\\\"\" """}
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
    assert "approve it in hol guard, then retry." in output["permissionDecisionReason"].lower()
