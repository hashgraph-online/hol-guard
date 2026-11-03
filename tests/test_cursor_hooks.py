"""Regression tests for Cursor native hook installation and payload mapping."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor_hooks import (
    _MANAGED_HOOK_EVENTS,
    HOOK_SCRIPT_NAME,
    _strip_managed_hook_entries,
    cursor_hooks_path,
    cursor_native_hook_state,
    install_cursor_hooks,
    uninstall_cursor_hooks,
)
from codex_plugin_scanner.guard.cli import update_commands as guard_update_commands_module
from codex_plugin_scanner.guard.store import GuardStore
from tests.cursor_hook_payload_support import prepare_cursor_hook_payload


def test_prepare_cursor_hook_payload_maps_before_read_file() -> None:
    payload = prepare_cursor_hook_payload(
        {
            "hook_event_name": "beforeReadFile",
            "file_path": "/tmp/secrets.env",
        }
    )
    assert payload["hook_event_name"] == "PreToolUse"
    assert payload["tool_name"] == "Read"
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    assert tool_input["file_path"] == "/tmp/secrets.env"
    assert tool_input["path"] == "/tmp/secrets.env"


def test_prepare_cursor_hook_payload_infers_shell_without_event_name() -> None:
    payload = prepare_cursor_hook_payload({"command": "echo hello", "cwd": "/tmp"})
    assert payload["tool_name"] == "Shell"
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    assert tool_input["command"] == "echo hello"
    assert tool_input["working_directory"] == "/tmp"


def test_prepare_cursor_hook_payload_infers_read_without_event_name() -> None:
    payload = prepare_cursor_hook_payload({"file_path": "/tmp/secrets.env"})
    assert payload["tool_name"] == "Read"
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    assert tool_input["file_path"] == "/tmp/secrets.env"


def test_prepare_cursor_hook_payload_maps_before_shell_execution() -> None:
    payload = prepare_cursor_hook_payload(
        {
            "hook_event_name": "beforeShellExecution",
            "command": "echo hello",
            "cwd": "/tmp",
        }
    )
    assert payload["tool_name"] == "Shell"
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    assert tool_input["command"] == "echo hello"
    assert tool_input["working_directory"] == "/tmp"


def test_prepare_cursor_hook_payload_maps_after_shell_execution() -> None:
    payload = prepare_cursor_hook_payload(
        {
            "hook_event_name": "afterShellExecution",
            "command": "echo hello",
            "cwd": "/tmp",
            "duration": 12,
        }
    )
    assert payload["hook_event_name"] == "afterShellExecution"
    assert payload["tool_name"] == "Shell"
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    assert tool_input["command"] == "echo hello"
    assert tool_input["working_directory"] == "/tmp"


def test_cursor_resolve_guard_cli_command_ignores_path_collisions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.adapters.cursor_hooks import _resolve_guard_cli_command

    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    marker = tmp_path / "path-collision-ran"
    for name in ("plugin-guard", "hol-guard"):
        collision = fake_bin / name
        collision.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
        collision.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}")
    context = HarnessContext(
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard",
        workspace_dir=tmp_path / "workspace",
    )

    command = _resolve_guard_cli_command(context)

    assert command == [str(Path(sys.executable).absolute()), "-I", "-s", "-m", "codex_plugin_scanner.cli"]
    assert not marker.exists()


@pytest.mark.parametrize("collision_kind", ["executable", "symlink", "non-executable", "other-venv"])
def test_cursor_install_persists_only_attested_cli_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    collision_kind: str,
) -> None:
    fake_bin = tmp_path / ("other-venv" if collision_kind == "other-venv" else "fake-bin") / "bin"
    fake_bin.mkdir(parents=True)
    marker = tmp_path / "path-collision-ran"
    target = fake_bin / "collision-target"
    target.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
    target.chmod(0o755)
    for name in ("plugin-guard", "hol-guard"):
        collision = fake_bin / name
        if collision_kind == "symlink":
            collision.symlink_to(target)
        else:
            collision.write_text(target.read_text(encoding="utf-8"), encoding="utf-8")
            collision.chmod(0o644 if collision_kind == "non-executable" else 0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}")
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    context = HarnessContext(home_dir=home, guard_home=tmp_path / "guard", workspace_dir=workspace)

    manifest = install_cursor_hooks(context)

    identity = manifest["guard_cli_identity"]
    assert isinstance(identity, dict)
    assert identity["command"] == [
        str(Path(sys.executable).absolute()),
        "-I",
        "-s",
        "-m",
        "codex_plugin_scanner.cli",
    ]
    assert identity["entry_point"] == "codex_plugin_scanner.cli:main"
    assert identity["package_root"] == str(Path(__file__).resolve().parents[1] / "src")
    interpreter = identity["interpreter"]
    assert isinstance(interpreter, dict)
    assert Path(str(interpreter["target_path"])).is_absolute()
    assert len(str(interpreter["target_sha256"])) == 64
    assert not marker.exists()
    assert cursor_native_hook_state(context)["protection_active"] is True


def test_cursor_install_from_home_does_not_remove_global_hook_state(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    context = HarnessContext(home_dir=home, guard_home=tmp_path / "guard", workspace_dir=home)

    manifest = install_cursor_hooks(context)

    assert Path(str(manifest["state_path"])).is_file()
    assert cursor_native_hook_state(context)["protection_active"] is True


def test_cursor_update_repairs_tampered_cli_binding(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    context = HarnessContext(home_dir=home, guard_home=tmp_path / "guard", workspace_dir=workspace)
    hooks_manifest = install_cursor_hooks(context)
    store = GuardStore(context.guard_home)
    store.set_managed_install(
        "cursor",
        True,
        str(workspace),
        {"surface": "editor", **hooks_manifest},
        "2026-07-20T00:00:00+00:00",
    )
    script_path = Path(str(hooks_manifest["managed_hook_script_path"]))
    original_source = script_path.read_text(encoding="utf-8")
    script_path.write_text(
        original_source.replace("codex_plugin_scanner.cli", "attacker_controlled.cli", 1),
        encoding="utf-8",
    )
    assert cursor_native_hook_state(context)["reason"] == "guard_cursor_hook_script_tampered"

    repaired, warning = guard_update_commands_module._repair_cursor_install(
        context=context,
        store=store,
        workspace=str(workspace),
        now="2026-07-20T00:01:00+00:00",
    )

    assert warning is None
    assert repaired is not None
    assert cursor_native_hook_state(context)["protection_active"] is True
    assert script_path.read_text(encoding="utf-8") == original_source


def test_cursor_update_repairs_stale_attested_cli_identity(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    context = HarnessContext(home_dir=home, guard_home=tmp_path / "guard", workspace_dir=workspace)
    hooks_manifest = install_cursor_hooks(context)
    store = GuardStore(context.guard_home)
    store.set_managed_install(
        "cursor",
        True,
        str(workspace),
        {"surface": "editor", **hooks_manifest},
        "2026-07-20T00:00:00+00:00",
    )
    state_path = Path(str(hooks_manifest["state_path"]))
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["guard_cli_identity"]["guard_version"] = "0.0.0-stale"
    state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    stale = cursor_native_hook_state(context)

    repaired, warning = guard_update_commands_module._repair_cursor_install(
        context=context,
        store=store,
        workspace=str(workspace),
        now="2026-07-20T00:01:00+00:00",
    )

    assert stale["reason"] == "guard_cursor_cli_identity_mismatch"
    assert warning is None
    assert repaired is not None
    assert cursor_native_hook_state(context)["protection_active"] is True


def test_cursor_update_repairs_legacy_all_surface(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    context = HarnessContext(home_dir=home, guard_home=tmp_path / "guard", workspace_dir=workspace)
    hooks_manifest = install_cursor_hooks(context)
    store = GuardStore(context.guard_home)
    store.set_managed_install(
        "cursor",
        True,
        str(workspace),
        {"surface": "all", **hooks_manifest},
        "2026-07-20T00:00:00+00:00",
    )
    script_path = Path(str(hooks_manifest["managed_hook_script_path"]))
    script_path.write_text("tampered", encoding="utf-8")

    repaired, warning = guard_update_commands_module._repair_cursor_install(
        context=context,
        store=store,
        workspace=str(workspace),
        now="2026-07-20T00:01:00+00:00",
    )

    assert warning is None
    assert repaired is not None
    assert repaired["manifest"]["surface"] == "all"
    assert cursor_native_hook_state(context)["protection_active"] is True


def test_cursor_update_reports_context_resolution_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", guard_home=tmp_path / "guard", workspace_dir=None)
    store = GuardStore(context.guard_home)
    store.set_managed_install(
        "cursor",
        True,
        str(tmp_path / "workspace"),
        {"surface": "editor"},
        "2026-07-20T00:00:00+00:00",
    )

    def _fail_context_resolution(*_args: object, **_kwargs: object) -> tuple[HarnessContext, str | None]:
        raise RuntimeError("invalid repair context")

    monkeypatch.setattr(
        guard_update_commands_module,
        "_repair_context_from_managed_install",
        _fail_context_resolution,
    )

    repaired, warning = guard_update_commands_module._repair_cursor_install(
        context=context,
        store=store,
        workspace=None,
        now="2026-07-20T00:01:00+00:00",
    )

    assert repaired is None
    assert warning == "Could not inspect Cursor protection during update: invalid repair context"


def test_cursor_update_reports_surface_contract_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", guard_home=tmp_path / "guard", workspace_dir=None)
    store = GuardStore(context.guard_home)
    store.set_managed_install(
        "cursor",
        True,
        str(tmp_path / "workspace"),
        {"surface": "editor"},
        "2026-07-20T00:00:00+00:00",
    )
    monkeypatch.setattr(
        guard_update_commands_module,
        "cursor_native_hook_state",
        lambda _context: {"protection_active": False},
    )
    monkeypatch.setattr(
        guard_update_commands_module,
        "apply_managed_install",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("unsupported repair surface")),
    )

    repaired, warning = guard_update_commands_module._repair_cursor_install(
        context=context,
        store=store,
        workspace=None,
        now="2026-07-20T00:01:00+00:00",
    )

    assert repaired is None
    assert warning == "Could not repair Cursor protection during update: unsupported repair surface"


def test_cursor_install_is_idempotent_across_path_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    context = HarnessContext(home_dir=home, guard_home=tmp_path / "guard", workspace_dir=workspace)
    markers: list[Path] = []
    manifests: list[dict[str, object]] = []
    for index in range(2):
        fake_bin = tmp_path / f"fake-bin-{index}"
        fake_bin.mkdir()
        marker = tmp_path / f"path-collision-{index}-ran"
        markers.append(marker)
        for name in ("plugin-guard", "hol-guard"):
            collision = fake_bin / name
            collision.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
            collision.chmod(0o755)
        monkeypatch.setenv("PATH", str(fake_bin))
        manifests.append(install_cursor_hooks(context))

    hooks = json.loads(cursor_hooks_path(context).read_text(encoding="utf-8"))["hooks"]
    assert manifests[0]["guard_cli_identity"] == manifests[1]["guard_cli_identity"]
    assert all(len(hooks[event_name]) == 1 for event_name in _MANAGED_HOOK_EVENTS)
    assert not any(marker.exists() for marker in markers)
    assert cursor_native_hook_state(context)["protection_active"] is True


def test_strip_managed_hook_entries_removes_hol_guard_pretooluse(tmp_path: Path) -> None:
    script_path = tmp_path / "hol-guard-cursor-hook.py"
    script_path.write_text("# Managed by HOL Guard\n", encoding="utf-8")
    entries = [
        {"command": "lean-ctx hook rewrite", "matcher": "Shell"},
        {
            "command": str(script_path.resolve()),
            "failClosed": True,
            "matcher": "Shell|MCP|mcp__.*|Bash|Read",
            "timeout": 35,
        },
    ]
    stripped = _strip_managed_hook_entries(entries, script_path=script_path)
    assert stripped == [{"command": "lean-ctx hook rewrite", "matcher": "Shell"}]


def test_install_cursor_hooks_preserves_top_level_event_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    guard_home = tmp_path / "guard"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    hooks_path = home / ".cursor" / "hooks.json"
    hooks_path.parent.mkdir(parents=True)
    existing_entries = {event_name: [{"command": f"user-{event_name}"}] for event_name in _MANAGED_HOOK_EVENTS}
    hooks_path.write_text(json.dumps({"version": 1, **existing_entries}) + "\n", encoding="utf-8")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hooks._resolve_guard_cli_command",
        lambda _context: ["hol-guard"],
    )

    install_cursor_hooks(HarnessContext(home_dir=home, guard_home=guard_home, workspace_dir=workspace))
    installed = json.loads(hooks_path.read_text(encoding="utf-8"))

    for event_name in _MANAGED_HOOK_EVENTS:
        entries = installed["hooks"][event_name]
        assert entries[0] == existing_entries[event_name][0]
        assert HOOK_SCRIPT_NAME in entries[-1]["command"]


def test_prepare_cursor_hook_payload_maps_before_mcp_execution() -> None:
    payload = prepare_cursor_hook_payload(
        {
            "hook_event_name": "beforeMCPExecution",
            "tool_name": "plugin-notion-workspace-notion",
            "url": "https://example.com/mcp",
        }
    )
    assert payload["tool_name"] == "plugin-notion-workspace-notion"
    assert payload["cursor_source_hook_event"] == "beforeMCPExecution"
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    assert tool_input["url"] == "https://example.com/mcp"


def test_prepare_cursor_hook_payload_maps_after_mcp_execution() -> None:
    payload = prepare_cursor_hook_payload(
        {
            "hook_event_name": "afterMCPExecution",
            "tool_name": "ctx_shell",
            "tool_input": {"command": "pnpm test"},
            "result_json": '{"ok": true}',
            "duration": 42,
        }
    )
    assert payload["hook_event_name"] == "afterMCPExecution"
    assert payload["tool_name"] == "ctx_shell"
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    assert tool_input["command"] == "pnpm test"


def test_install_cursor_hooks_registers_after_shell_observer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    guard_home = tmp_path / "guard"
    workspace = tmp_path / "workspace"
    home.mkdir()
    guard_home.mkdir()
    workspace.mkdir()
    hooks_path = home / ".cursor" / "hooks.json"
    hooks_path.parent.mkdir(parents=True)
    hooks_path.write_text('{"version": 1, "hooks": {}}\n', encoding="utf-8")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hooks._resolve_guard_cli_command",
        lambda _context: ["hol-guard"],
    )
    context = HarnessContext(home_dir=home, guard_home=guard_home, workspace_dir=workspace)
    install_cursor_hooks(context)
    installed = json.loads(hooks_path.read_text(encoding="utf-8"))
    after_shell = installed["hooks"]["afterShellExecution"][-1]
    assert after_shell.get("failClosed") is not True
    after_mcp = installed["hooks"]["afterMCPExecution"][-1]
    assert after_mcp.get("failClosed") is not True
    read_entry = installed["hooks"]["beforeReadFile"][-1]
    assert HOOK_SCRIPT_NAME in str(read_entry["command"])
    assert str(read_entry["command"]).endswith(HOOK_SCRIPT_NAME) or HOOK_SCRIPT_NAME in str(read_entry["command"])
    command_tokens = str(read_entry["command"]).split()
    assert Path(command_tokens[0]).name.lower().startswith("python")
    assert read_entry["failClosed"] is True
    assert (guard_home / "secrets" / "cursor-hook-attestation.key").is_file()


def test_extract_sensitive_tool_action_request_accepts_generic_mcp_tool_command() -> None:
    from codex_plugin_scanner.guard.runtime.secret_file_requests import (
        extract_sensitive_tool_action_request,
    )

    match = extract_sensitive_tool_action_request(
        "custom_mcp_shell_gateway",
        {"command": "rm -rf ./hol-guard-cursor-native-mcp-marker"},
    )
    assert match is not None
    assert match.action_class == "destructive shell command"


def test_uninstall_cursor_hooks_restores_backup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    guard_home = tmp_path / "guard"
    workspace = tmp_path / "workspace"
    home.mkdir()
    guard_home.mkdir()
    workspace.mkdir()
    hooks_path = home / ".cursor" / "hooks.json"
    hooks_path.parent.mkdir(parents=True)
    hooks_path.write_text('{"version": 1, "hooks": {"preToolUse": []}}\n', encoding="utf-8")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hooks._resolve_guard_cli_command",
        lambda _context: ["hol-guard"],
    )
    context = HarnessContext(home_dir=home, guard_home=guard_home, workspace_dir=workspace)
    install_cursor_hooks(context)
    result = uninstall_cursor_hooks(context)
    assert result["restored"] is True
    assert json.loads(hooks_path.read_text(encoding="utf-8")) == {"version": 1, "hooks": {"preToolUse": []}}
