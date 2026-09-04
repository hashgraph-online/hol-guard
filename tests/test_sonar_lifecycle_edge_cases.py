"""Security regressions for adapter lifecycle edge cases found during PR review."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import copilot_state_paths
from codex_plugin_scanner.guard.adapters import cursor_hooks as cursor_hooks_module
from codex_plugin_scanner.guard.adapters.adapter_state_integrity import (
    adapter_state_is_authenticated,
    authenticate_adapter_state,
)
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.copilot import CopilotHarnessAdapter
from codex_plugin_scanner.guard.adapters.cursor_hooks import install_cursor_hooks, managed_hook_script_path
from codex_plugin_scanner.guard.adapters.hermes_state_paths import hermes_cleanup_values


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def test_unsigned_global_copilot_state_cannot_authorize_cleanup(tmp_path: Path) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    adapter = CopilotHarnessAdapter()
    target = context.home_dir / ".copilot" / "mcp-config.json"
    backup = adapter._backup_path(target, context)
    state_path = adapter._state_path(target, context)
    _write_json(target, {"owned": "user"})
    _write_json(backup, {"existed": False, "content": None})
    _write_json(
        state_path,
        {
            "managed_config_path": str(target),
            "backup_path": str(backup),
            "scope": "global",
            "workspace_dir": None,
        },
    )

    adapter.uninstall(context)

    assert json.loads(target.read_text(encoding="utf-8")) == {"owned": "user"}
    assert backup.exists()
    assert state_path.exists()


def test_failed_copilot_target_write_does_not_reuse_orphaned_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    adapter = CopilotHarnessAdapter()
    target = context.home_dir / ".copilot" / "mcp-config.json"
    first_content = {"mcpServers": {"first": {"command": "first-command"}}}
    second_content = {"mcpServers": {"second": {"command": "second-command"}}}
    _write_json(target, first_content)
    backup = adapter._backup_path(target, context)
    real_write = copilot_state_paths.write_text_at_authorized_path
    fail_target = True

    def fail_first_target_write(path: Path, payload: str) -> None:
        nonlocal fail_target
        if path == target and fail_target:
            fail_target = False
            raise OSError("simulated target write failure")
        real_write(path, payload)

    monkeypatch.setattr(copilot_state_paths, "write_text_at_authorized_path", fail_first_target_write)

    with pytest.raises(OSError, match="target write"):
        adapter.install(context)

    assert backup.exists() is False
    _write_json(target, second_content)
    adapter.install(context)
    adapter.uninstall(context)

    assert json.loads(target.read_text(encoding="utf-8")) == second_content


def test_cursor_executable_update_does_not_follow_swapped_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    managed_script = managed_hook_script_path(context)
    outside = tmp_path / "outside.py"
    outside.write_text("# user owned\n", encoding="utf-8")
    outside.chmod(0o600)
    original_mode = stat.S_IMODE(outside.stat().st_mode)
    safe_make_executable = cursor_hooks_module._make_executable

    def swap_before_permission_update(path: Path) -> None:
        if path == managed_script:
            path.unlink()
            path.symlink_to(outside)
        safe_make_executable(path)

    monkeypatch.setattr(cursor_hooks_module, "_make_executable", swap_before_permission_update)

    with pytest.raises(OSError, match=r"non-regular|symlink"):
        install_cursor_hooks(context)

    assert stat.S_IMODE(outside.stat().st_mode) == original_mode


@pytest.mark.skipif(os.name != "posix", reason="POSIX no-follow directory descriptors")
def test_adapter_state_key_rejects_symlinked_managed_directory(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    alternate = guard_home / "alternate"
    alternate.mkdir(parents=True)
    alternate.chmod(0o755)
    original_mode = stat.S_IMODE(alternate.stat().st_mode)
    (guard_home / "managed").symlink_to(alternate, target_is_directory=True)

    with pytest.raises(OSError):
        authenticate_adapter_state(guard_home, harness="copilot", payload={"scope": "global"})

    assert stat.S_IMODE(alternate.stat().st_mode) == original_mode
    assert (alternate / "adapter-state.key").exists() is False


@pytest.mark.skipif(os.name != "posix", reason="POSIX no-follow directory descriptors")
def test_adapter_state_verification_does_not_create_or_chmod_key_directory(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    managed = guard_home / "managed"
    managed.mkdir(parents=True)
    managed.chmod(0o755)
    authentication = {
        "algorithm": "hmac-sha256",
        "key_id": "missing",
        "mac": "0" * 64,
        "schema_version": 1,
    }

    assert (
        adapter_state_is_authenticated(
            guard_home,
            harness="copilot",
            payload={"state_authentication": authentication},
        )
        is False
    )
    assert stat.S_IMODE(managed.stat().st_mode) == 0o755

    missing_guard_home = tmp_path / "missing-guard-home"
    assert (
        adapter_state_is_authenticated(
            missing_guard_home,
            harness="copilot",
            payload={"state_authentication": authentication},
        )
        is False
    )
    assert (missing_guard_home / "managed").exists() is False


def test_hermes_legacy_cleanup_accepts_resolved_guard_home_marker(tmp_path: Path) -> None:
    real_guard_home = tmp_path / "real-guard-home"
    real_guard_home.mkdir()
    guard_home_alias = tmp_path / "guard-home-alias"
    guard_home_alias.symlink_to(real_guard_home, target_is_directory=True)
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=guard_home_alias)
    config_path = context.home_dir / ".hermes" / "config.yaml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "mcp_servers:\n"
        "  guard-managed:\n"
        "    command: python\n"
        "    args: [-m, codex_plugin_scanner.cli, hermes, mcp-proxy, --guard-home, "
        f"{real_guard_home}]\n",
        encoding="utf-8",
    )

    managed, _previous_guard = hermes_cleanup_values(context, {}, config_path)

    assert managed == ["guard-managed"]


def test_hermes_legacy_cleanup_ignores_non_string_guard_home_marker(tmp_path: Path) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    config_path = context.home_dir / ".hermes" / "config.yaml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "mcp_servers:\n"
        "  malformed:\n"
        "    command: python\n"
        "    args: [-m, codex_plugin_scanner.cli, hermes, mcp-proxy, --guard-home, [unexpected]]\n",
        encoding="utf-8",
    )

    managed, _previous_guard = hermes_cleanup_values(context, {}, config_path)

    assert managed == []
