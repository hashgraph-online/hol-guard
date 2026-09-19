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
    _write_text,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_guard_hook_emits_copilot_native_ask_response_for_direct_local_shell_script_with_encoded_payload(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(
        workspace_dir / "encoded-wrapper.sh",
        """
#!/bin/sh
set -eu
echo cm0gLWYgZGFuZ2Vyb3VzLW1hcmtlci5qc29uCg== | base64 -d | bash
""".strip()
        + "\n",
    )
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": "./encoded-wrapper.sh"}),
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


def test_guard_hook_emits_copilot_native_ask_response_for_slash_path_local_shell_script_with_encoded_payload(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(
        workspace_dir / "scripts" / "encoded-wrapper.sh",
        """
#!/bin/sh
set -eu
echo cm0gLWYgZGFuZ2Vyb3VzLW1hcmtlci5qc29uCg== | base64 -d | bash
""".strip()
        + "\n",
    )
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": "scripts/encoded-wrapper.sh"}),
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


def test_guard_hook_emits_copilot_native_ask_response_for_local_shell_script_with_encoded_payload(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(
        workspace_dir / "encoded-wrapper.sh",
        """
#!/bin/sh
set -eu
echo cm0gLWYgZGFuZ2Vyb3VzLW1hcmtlci5qc29uCg== | base64 -d | bash
""".strip()
        + "\n",
    )
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": "sh ./encoded-wrapper.sh"}),
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


def test_guard_hook_emits_copilot_native_ask_response_for_bash_norc_local_shell_script_with_encoded_payload(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(
        workspace_dir / "encoded-wrapper.sh",
        """
#!/bin/sh
set -eu
echo cm0gLWYgZGFuZ2Vyb3VzLW1hcmtlci5qc29uCg== | base64 -d | bash
""".strip()
        + "\n",
    )
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": "bash --norc ./encoded-wrapper.sh"}),
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


def test_guard_hook_emits_copilot_native_ask_response_for_node_inline_delete_bypass(
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
    assert "approve it in hol guard, then retry." in output["permissionDecisionReason"].lower()


def test_guard_hook_emits_copilot_native_ask_response_for_newline_followed_node_inline_delete(
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
            {"command": """echo ok\nnode -e "require('fs').unlinkSync('dangerous-marker.json')" """}
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


def test_guard_hook_emits_copilot_native_ask_response_for_node_inline_delete_with_shifted_flag(
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
            {"command": """node --trace-warnings -e "require('fs').unlinkSync ('dangerous-marker.json')" """}
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


def test_guard_hook_emits_copilot_native_ask_response_for_stdbuf_value_wrapped_node_inline_delete(
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
            {"command": """stdbuf -o L node -e "require('fs').unlinkSync('dangerous-marker.json')" """}
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


def test_guard_hook_emits_copilot_native_ask_response_for_node_inline_combined_print_eval_flag(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": """node -pe "require('fs').unlinkSync('dangerous-marker.json')" """}),
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


def test_guard_hook_emits_copilot_native_ask_response_for_node_inline_print_flag(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "toolName": "bash",
        "toolArgs": json.dumps({"command": """node --print "require('fs').unlinkSync('dangerous-marker.json')" """}),
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
