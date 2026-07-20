"""P22 regressions for complete Codex hook pre-activation inventory."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters import codex as codex_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.codex_config import dump_toml
from codex_plugin_scanner.guard.codex_hook_inventory import (
    CODEX_HOOK_INVENTORY_MALFORMED_GROUP,
    CODEX_HOOK_INVENTORY_UNKNOWN_HANDLER,
    CODEX_HOOK_INVENTORY_UNMANAGED_EXECUTABLE,
    enumerate_codex_hooks,
)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _install_args(home_dir: Path, workspace_dir: Path) -> list[str]:
    return [
        "guard",
        "install",
        "codex",
        "--home",
        str(home_dir),
        "--workspace",
        str(workspace_dir),
        "--json",
    ]


def _command_group(command: str = "python3 harmless-marker.py", **handler_fields: object) -> dict[str, object]:
    return {
        "matcher": "fixture",
        "hooks": [{"type": "command", "command": command, **handler_fields}],
    }


@pytest.mark.parametrize(
    "event_name",
    (
        "PreToolUse",
        "PermissionRequest",
        "UserPromptSubmit",
        "PostToolUse",
        "SessionStart",
        "Stop",
        "FutureAgentEvent",
    ),
)
def test_every_known_and_future_executable_event_blocks_preactivation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    event_name: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    config_path = workspace_dir / ".codex" / "config.toml"
    hooks_path = workspace_dir / ".codex" / "hooks.json"
    original_config = 'approval_policy = "never"\n\n[features]\nhooks = false\n'
    original_hooks = json.dumps({"hooks": {event_name: [_command_group()]}}, indent=2) + "\n"
    _write(config_path, original_config)
    _write(hooks_path, original_hooks)

    rc = main(_install_args(home_dir, workspace_dir))
    captured = capsys.readouterr()

    assert rc == 1
    assert CODEX_HOOK_INVENTORY_UNMANAGED_EXECUTABLE in captured.err
    assert f"{event_name}/group[0]/handler[0]" in captured.err
    assert config_path.read_text(encoding="utf-8") == original_config
    assert hooks_path.read_text(encoding="utf-8") == original_hooks


@pytest.mark.parametrize("scope", ("global", "project"))
@pytest.mark.parametrize("source_format", ("json", "toml"))
def test_global_and_workspace_json_and_toml_sources_are_checked_before_any_write(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    scope: str,
    source_format: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    source_root = home_dir if scope == "global" else workspace_dir
    config_path = source_root / ".codex" / "config.toml"
    hooks_path = source_root / ".codex" / "hooks.json"
    payload: dict[str, object] = {"hooks": {"FutureAgentEvent": [_command_group()]}}
    if source_format == "json":
        _write(config_path, "[features]\nhooks = false\n")
        _write(hooks_path, json.dumps(payload, indent=2) + "\n")
        source_path = hooks_path
    else:
        payload["features"] = {"hooks": False}
        _write(config_path, dump_toml(payload))
        source_path = config_path
    original = source_path.read_bytes()

    rc = main(_install_args(home_dir, workspace_dir))
    captured = capsys.readouterr()

    assert rc == 1
    assert CODEX_HOOK_INVENTORY_UNMANAGED_EXECUTABLE in captured.err
    assert str(source_path) in captured.err
    assert source_path.read_bytes() == original
    assert (home_dir / ".codex" / "config.toml").exists() is (scope == "global")


def test_inventory_preserves_handler_coordinates_and_execution_fields(tmp_path: Path) -> None:
    payload = {
        "hooks": {
            "FutureAgentEvent": [
                {
                    "matcher": "agent|resume",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "python3 fixture.py",
                            "timeout": 12,
                            "env": {"TOKEN": "redacted", "MODE": "safe"},
                            "enabled": False,
                        }
                    ],
                }
            ]
        }
    }

    inventory = enumerate_codex_hooks(
        payload,
        source_path=tmp_path / "hooks.json",
        source_scope="project",
        source_format="json",
        source_hooks_enabled=False,
    )

    assert inventory.complete is True
    assert len(inventory.records) == 1
    record = inventory.records[0]
    assert record.coordinate == "FutureAgentEvent/group[0]/handler[0]"
    assert record.matcher == "agent|resume"
    assert record.handler_type == "command"
    assert record.command == "python3 fixture.py"
    assert record.timeout == 12
    assert record.environment_keys == ("MODE", "TOKEN")
    assert record.active is False
    assert record.source_hooks_enabled is False
    assert record.ownership == "unmanaged"


@pytest.mark.parametrize(
    "handler",
    (
        {
            "type": "command",
            "command": "python /untrusted/codex_daemon_hook_bridge.py '{}'",
            "statusMessage": "HOL Guard checking tool action",
        },
        {
            "type": "command",
            "command": (
                "/home/user/.local/pipx/venvs/hol-guard/bin/python -m codex_plugin_scanner.cli guard hook "
                "--harness codex"
            ),
        },
    ),
)
def test_managed_looking_paths_commands_and_status_are_unmanaged_without_identity(
    tmp_path: Path,
    handler: dict[str, object],
) -> None:
    inventory = enumerate_codex_hooks(
        {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [handler]}]}},
        source_path=tmp_path / "config.toml",
        source_scope="global",
        source_format="toml",
        source_hooks_enabled=False,
    )

    assert inventory.complete is True
    assert inventory.records[0].ownership == "unmanaged"
    assert inventory.unmanaged_active_executables == inventory.records


def test_authenticated_manifest_binding_is_the_managed_ownership_authority(tmp_path: Path) -> None:
    handler = {"type": "command", "command": "python3 exact-guard-hook.py"}
    group = {"matcher": "Bash", "hooks": [handler]}
    binding = {"event": "PreToolUse", "group": group, "handler": handler}

    inventory = enumerate_codex_hooks(
        {"hooks": {"PreToolUse": [group]}},
        source_path=tmp_path / "config.toml",
        source_scope="global",
        source_format="toml",
        source_hooks_enabled=False,
        authenticated_bindings=(binding,),
    )

    assert inventory.complete is True
    assert inventory.records[0].ownership == "authenticated_manifest"
    assert inventory.unmanaged_active_executables == ()


def test_mixed_exact_legacy_and_unmanaged_handlers_block_only_the_unmanaged_handler(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    context = HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir)
    managed_group = codex_adapter._managed_hook_groups(context)["PreToolUse"]
    handlers = managed_group["hooks"]
    assert isinstance(handlers, list)
    mixed_group = {**managed_group, "hooks": [*handlers, {"type": "command", "command": "python3 custom.py"}]}
    hooks_path = workspace_dir / ".codex" / "hooks.json"
    _write(workspace_dir / ".codex" / "config.toml", "[features]\nhooks = false\n")
    _write(hooks_path, json.dumps({"hooks": {"PreToolUse": [mixed_group]}}, indent=2) + "\n")

    rc = main(_install_args(home_dir, workspace_dir))
    captured = capsys.readouterr()

    assert rc == 1
    assert CODEX_HOOK_INVENTORY_UNMANAGED_EXECUTABLE in captured.err
    assert "PreToolUse/group[0]/handler[1]" in captured.err


def test_disabled_unmanaged_entry_and_metadata_only_event_are_preserved_without_review(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    hooks_path = home_dir / ".codex" / "hooks.json"
    _write(
        hooks_path,
        json.dumps(
            {
                "hooks": {
                    "FutureAgentEvent": [
                        {**_command_group(), "enabled": False},
                        {"matcher": "metadata", "description": "retained metadata"},
                    ]
                }
            },
            indent=2,
        )
        + "\n",
    )

    codex_adapter.CodexHarnessAdapter().install(
        HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir)
    )

    installed = codex_adapter.tomllib.loads((home_dir / ".codex" / "config.toml").read_text(encoding="utf-8"))
    assert hooks_path.exists() is False
    assert installed["hooks"]["FutureAgentEvent"] == [
        {**_command_group(), "enabled": False},
        {"matcher": "metadata", "description": "retained metadata"},
    ]


@pytest.mark.parametrize(
    ("payload", "reason_code"),
    (
        ({"hooks": {"Stop": ["not-a-group"]}}, CODEX_HOOK_INVENTORY_MALFORMED_GROUP),
        (
            {"hooks": {"Stop": [{"hooks": [{"type": "future-exec", "command": "python3 fixture.py"}]}]}},
            CODEX_HOOK_INVENTORY_UNKNOWN_HANDLER,
        ),
        (
            {"hooks": {"Stop": [{"hooks": [{"type": "future-exec", "argv": ["python3", "fixture.py"]}]}]}},
            CODEX_HOOK_INVENTORY_UNKNOWN_HANDLER,
        ),
    ),
)
def test_incomplete_inventory_fails_closed_even_when_hooks_are_already_enabled(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    payload: dict[str, object],
    reason_code: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    config_path = workspace_dir / ".codex" / "config.toml"
    payload["features"] = {"hooks": True}
    original = dump_toml(payload)
    _write(config_path, original)

    rc = main(_install_args(home_dir, workspace_dir))
    captured = capsys.readouterr()

    assert rc == 1
    assert reason_code in captured.err
    assert config_path.read_text(encoding="utf-8") == original


@pytest.mark.parametrize(
    ("path_name", "content", "reason_code"),
    (
        (
            "hooks.json",
            '{"hooks":{"Stop":[]},"hooks":{"FutureAgentEvent":[]}}\n',
            "codex_hook_inventory_source_duplicate_key",
        ),
        (
            "config.toml",
            "[features]\nhooks = false\n[hooks]\nStop = []\nStop = []\n",
            "codex_hook_inventory_source_duplicate_key",
        ),
        ("hooks.json", '{"hooks":', "codex_hook_inventory_source_malformed"),
        ("config.toml", "[hooks\n", "codex_hook_inventory_source_malformed"),
    ),
)
def test_duplicate_or_malformed_sources_fail_before_writes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    path_name: str,
    content: str,
    reason_code: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    source_path = workspace_dir / ".codex" / path_name
    _write(source_path, content)

    rc = main(_install_args(home_dir, workspace_dir))
    captured = capsys.readouterr()

    assert rc == 1
    assert reason_code in captured.err
    assert source_path.read_text(encoding="utf-8") == content
    assert (home_dir / ".codex" / "config.toml").exists() is False


def test_non_file_config_source_fails_closed_before_writes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    (workspace_dir / ".codex" / "config.toml").mkdir(parents=True)

    rc = main(_install_args(home_dir, workspace_dir))
    captured = capsys.readouterr()

    assert rc == 1
    assert "codex_hook_inventory_source_unreadable" in captured.err
    assert (home_dir / ".codex" / "config.toml").exists() is False


@pytest.mark.parametrize("source_name", ("config.toml", "hooks.json"))
def test_symlink_config_source_fails_closed_before_writes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    source_name: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    external_path = tmp_path / f"external-{source_name}"
    external_content = "" if source_name.endswith(".toml") else "{}\n"
    _write(external_path, external_content)
    source_path = workspace_dir / ".codex" / source_name
    source_path.parent.mkdir(parents=True)
    source_path.symlink_to(external_path)

    rc = main(_install_args(home_dir, workspace_dir))
    captured = capsys.readouterr()

    assert rc == 1
    assert "codex_hook_inventory_source_unreadable" in captured.err
    assert external_path.read_text(encoding="utf-8") == external_content
    assert (home_dir / ".codex" / "config.toml").exists() is False


def test_source_change_after_inventory_stops_before_activation_write(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    hooks_path = workspace_dir / ".codex" / "hooks.json"
    original_payload = {"hooks": {"FutureAgentEvent": [{**_command_group("python3 first.py"), "enabled": False}]}}
    changed_payload = {"hooks": {"FutureAgentEvent": [{**_command_group("python3 changed.py"), "enabled": False}]}}
    _write(hooks_path, json.dumps(original_payload, indent=2) + "\n")
    original_verify = codex_adapter._require_hook_inventory_sources_unchanged

    def mutate_then_verify(
        *,
        config_payloads: Mapping[Path, dict[str, object]],
        hook_payloads: Mapping[Path, dict[str, object]],
    ) -> None:
        _write(hooks_path, json.dumps(changed_payload, indent=2) + "\n")
        original_verify(config_payloads=config_payloads, hook_payloads=hook_payloads)

    monkeypatch.setattr(codex_adapter, "_require_hook_inventory_sources_unchanged", mutate_then_verify)

    rc = main(_install_args(home_dir, workspace_dir))
    captured = capsys.readouterr()

    assert rc == 1
    assert "codex_hook_inventory_source_changed" in captured.err
    assert (home_dir / ".codex" / "config.toml").exists() is False
    assert json.loads(hooks_path.read_text(encoding="utf-8")) == changed_payload
