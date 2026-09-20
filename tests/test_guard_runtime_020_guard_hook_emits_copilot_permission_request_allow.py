"""Runtime regression tests: guard hook emits copilot permission request allow."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardStore,
    _runtime_policy_path,
    guard_commands_module,
    io,
    json,
    main,
    sys,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
    _write_json,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_guard_hook_emits_copilot_permission_request_allow_for_safe_mcp_tool(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "hookName": "permissionRequest",
        "toolName": "danger_lab/safe_echo",
        "toolInput": {"text": "ok"},
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
    assert output == {"behavior": "allow"}
    events = GuardStore(home_dir).list_guard_events_v1(uploaded=False)
    usage_events = [event for event in events if event["event_type"] == "harness.mcp.used"]
    assert len(usage_events) == 1
    assert usage_events[0]["payload"]["payload"]["status"] == "allowed"


def test_guard_hook_emits_copilot_permission_request_allow_for_hook_event_name_variant(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "hookEventName": "permissionRequest",
        "toolName": "danger_lab/safe_echo",
        "toolInput": {"text": "ok"},
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
    assert output == {"behavior": "allow"}


def test_guard_hook_emits_copilot_permission_request_deny_for_risky_mcp_tool(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    event = {
        "hookName": "permissionRequest",
        "toolName": "danger_lab/dangerous_delete",
        "toolInput": {"target": "dangerous-marker.json"},
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
    assert output["behavior"] == "deny"
    assert output["interrupt"] is True
    assert "HOL Guard blocked" in output["message"]
    assert "danger_lab:dangerous_delete" in output["message"]
    assert "http://127.0.0.1:4455/requests/" in output["message"]
    events = GuardStore(home_dir).list_guard_events_v1(uploaded=False)
    usage_events = [event for event in events if event["event_type"] == "harness.mcp.used"]
    assert len(usage_events) == 1
    assert usage_events[0]["payload"]["payload"]["status"] == "blocked"
    assert usage_events[0]["payload"]["payload"]["policyAction"] == "review"


def test_guard_hook_emits_copilot_permission_request_deny_from_tool_calls_payload(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    event = {
        "hookName": "permissionRequest",
        "toolCalls": [
            {
                "id": "call-dangerous",
                "name": "danger_lab/dangerous_delete",
                "args": json.dumps({"target": "dangerous-marker.json"}),
            }
        ],
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
    assert output["behavior"] == "deny"
    assert "danger_lab:dangerous_delete" in output["message"]


def test_normalize_hook_payload_prefers_matching_tool_call_args() -> None:
    payload = guard_commands_module._normalize_hook_payload(
        {
            "toolName": "danger_lab/dangerous_delete",
            "toolCalls": [
                {
                    "id": "call-safe",
                    "name": "safe_tools/read_file",
                    "args": json.dumps({"path": "README.md"}),
                },
                {
                    "id": "call-dangerous",
                    "name": "danger_lab/dangerous_delete",
                    "args": json.dumps({"target": "dangerous-marker.json"}),
                },
            ],
        }
    )

    assert payload["tool_name"] == "danger_lab/dangerous_delete"
    assert payload["tool_input"] == {"target": "dangerous-marker.json"}
    assert payload["arguments"] == {"target": "dangerous-marker.json"}


def test_copilot_runtime_tool_call_prefers_cli_workspace_config_when_workspace_is_inferred(tmp_path):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_json(
        workspace_dir / ".mcp.json",
        {"mcpServers": {"danger_lab": {"command": "python3", "args": ["cli-danger-lab.py"]}}},
    )
    _write_json(
        workspace_dir / ".vscode" / "mcp.json",
        {"servers": {"danger_lab": {"command": "python3", "args": ["ide-danger-lab.py"]}}},
    )

    artifact = guard_commands_module._copilot_runtime_tool_call(
        payload={
            "tool_name": "mcp_danger_lab_dangerous_delete",
            "tool_input": {"target": "dangerous-marker.json"},
            "source_scope": "project",
        },
        home_dir=home_dir,
        workspace=workspace_dir,
        preferred_workspace_config="cli",
    )

    assert artifact is not None
    runtime_artifact, _artifact_hash, _arguments = artifact
    assert runtime_artifact.config_path == str(workspace_dir / ".mcp.json")


def test_copilot_runtime_tool_call_prefers_ide_workspace_config_when_workspace_is_explicit(tmp_path):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_json(
        workspace_dir / ".mcp.json",
        {"mcpServers": {"danger_lab": {"command": "python3", "args": ["cli-danger-lab.py"]}}},
    )
    _write_json(
        workspace_dir / ".vscode" / "mcp.json",
        {"servers": {"danger_lab": {"command": "python3", "args": ["ide-danger-lab.py"]}}},
    )

    artifact = guard_commands_module._copilot_runtime_tool_call(
        payload={
            "tool_name": "mcp_danger_lab_dangerous_delete",
            "tool_input": {"target": "dangerous-marker.json"},
            "source_scope": "project",
        },
        home_dir=home_dir,
        workspace=workspace_dir,
        preferred_workspace_config="ide",
    )

    assert artifact is not None
    runtime_artifact, _artifact_hash, _arguments = artifact
    assert runtime_artifact.config_path == str(workspace_dir / ".vscode" / "mcp.json")


def test_runtime_policy_path_prefers_pi_workspace_settings(tmp_path):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_json(workspace_dir / ".pi" / "settings.json", {"extensions": []})

    assert _runtime_policy_path("pi", home_dir, workspace_dir) == workspace_dir / ".pi" / "settings.json"


def test_runtime_policy_path_defaults_to_pi_workspace_settings_without_payload_override(tmp_path):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_json(workspace_dir / ".omp" / "settings.json", {"extensions": []})

    assert _runtime_policy_path("pi", home_dir, workspace_dir) == workspace_dir / ".pi" / "settings.json"


def test_runtime_policy_path_honors_payload_config_path_for_pi(tmp_path):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    config_path = workspace_dir / ".omp" / "settings.json"
    _write_json(workspace_dir / ".pi" / "settings.json", {"extensions": []})
    _write_json(config_path, {"extensions": []})

    assert _runtime_policy_path("pi", home_dir, workspace_dir, payload={"config_path": str(config_path)}) == config_path


def test_runtime_policy_path_ignores_forged_payload_config_path_for_pi(tmp_path):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    forged_path = workspace_dir / ".cursor" / "mcp.json"
    _write_json(workspace_dir / ".pi" / "settings.json", {"extensions": []})
    _write_json(forged_path, {"servers": {}})

    assert _runtime_policy_path("pi", home_dir, workspace_dir, payload={"config_path": str(forged_path)}) == (
        workspace_dir / ".pi" / "settings.json"
    )


def test_runtime_policy_path_ignores_payload_config_path_for_other_harnesses(tmp_path):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_json(workspace_dir / ".omp" / "settings.json", {"extensions": []})

    assert _runtime_policy_path(
        "codex",
        home_dir,
        workspace_dir,
        payload={"config_path": str(workspace_dir / ".omp" / "settings.json")},
    ) == (workspace_dir / ".codex" / "config.toml")


def test_guard_hook_emits_copilot_native_deny_for_risky_mcp_pre_tool_use(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_json(
        workspace_dir / ".vscode" / "mcp.json",
        {
            "servers": {
                "danger_lab": {
                    "type": "local",
                    "command": "python3",
                    "args": ["danger-lab.py"],
                }
            }
        },
    )
    event = {
        "hook_event_name": "PreToolUse",
        "toolName": "mcp_danger_lab_dangerous_delete",
        "toolArgs": json.dumps({"target": "dangerous-marker.json"}),
        "sourceScope": "project",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))

    rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--guard-home",
            str(guard_home),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "copilot",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    store = GuardStore(guard_home)
    receipts = store.list_receipts(limit=20)

    assert rc == 0
    assert output["permissionDecision"] == "deny"
    assert "hol guard" in output["permissionDecisionReason"].lower()
    assert "destructive" in output["permissionDecisionReason"].lower()
    assert receipts == []


def test_guard_hook_emits_copilot_native_allow_for_safe_mcp_pre_tool_use(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_json(
        workspace_dir / ".vscode" / "mcp.json",
        {
            "servers": {
                "danger_lab": {
                    "type": "local",
                    "command": "python3",
                    "args": ["danger-lab.py"],
                }
            }
        },
    )
    event = {
        "hook_event_name": "PreToolUse",
        "toolName": "mcp_danger_lab_safe_echo",
        "toolArgs": json.dumps({"text": "ok"}),
        "sourceScope": "project",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))

    rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--guard-home",
            str(guard_home),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "copilot",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    store = GuardStore(guard_home)
    receipts = store.list_receipts(limit=20)

    assert rc == 0
    assert output == {"permissionDecision": "allow"}
    assert any(
        receipt["artifact_id"] == "copilot:runtime:project:danger_lab:safe_echo"
        and receipt["policy_decision"] == "warn"
        for receipt in receipts
    )
    runtime_event = store.list_events(limit=1, event_name="runtime_tool_call_allowed")[0]
    assert runtime_event["payload"]["policy_action"] == "warn"
