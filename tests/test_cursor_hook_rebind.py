"""Cursor hooks must bake a prune-safe launcher and rebind stale versioned paths."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor_hooks import cursor_hook_script_source
from codex_plugin_scanner.guard.adapters.guard_cli_attestation import resolve_attested_guard_cli
from codex_plugin_scanner.guard.cursor_hook_rebind import (
    cursor_hook_script_bakes_ephemeral_cli,
    rebind_stale_cursor_hooks,
)
from codex_plugin_scanner.guard.frozen_runtime_commands import frozen_daemon_recovery_command
from codex_plugin_scanner.guard.stable_guard_cli import uses_top_level_hook_command


def _managed_hook_source(*, argv0: str) -> str:
    return (
        "#!/usr/bin/env python3\n"
        '"""Managed by HOL Guard. Re-run `hol-guard install cursor` after moving Guard home."""\n'
        "from pathlib import Path\n"
        f"GUARD_CLI = {json.dumps([argv0])}\n"
        f"GUARD_RECOVERY_COMMAND = {json.dumps([argv0])}\n"
        "HOOK_SCRIPT_NAME = 'hol-guard-cursor-hook.py'\n"
    )


def _executable_file(path: Path, body: str = "#!/bin/sh\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


def test_uses_top_level_hook_command_for_stable_desktop_shim() -> None:
    assert uses_top_level_hook_command(["/core/current-hol-guard"]) is True
    assert uses_top_level_hook_command(["/core/current-hol-guard.cmd"]) is True
    assert uses_top_level_hook_command(["/core/versions/3.0.57/hol-guard"]) is True
    assert uses_top_level_hook_command(["/usr/bin/python3", "-m", "codex_plugin_scanner.cli"]) is False


def test_cursor_hook_script_source_does_not_prefix_guard_for_stable_shim(tmp_path: Path) -> None:
    context = HarnessContext(
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard",
        workspace_dir=tmp_path / "workspace",
    )
    source = cursor_hook_script_source(
        context,
        guard_cli=[str(tmp_path / "core" / "current-hol-guard")],
        recovery_command=["true"],
    )
    assert '["guard", "hook"' not in source
    assert '"hook"' in source


def test_cursor_hook_script_bakes_ephemeral_cli_detects_versioned_core(tmp_path: Path) -> None:
    versioned = str(tmp_path / "core" / "versions" / "3.0.57" / "hol-guard")
    shim = str(tmp_path / "core" / "current-hol-guard")
    assert cursor_hook_script_bakes_ephemeral_cli(_managed_hook_source(argv0=versioned)) is True
    assert cursor_hook_script_bakes_ephemeral_cli(_managed_hook_source(argv0=shim)) is False
    assert cursor_hook_script_bakes_ephemeral_cli("print('not managed')\n") is False


def test_rebind_skips_unfrozen_process_even_when_script_is_ephemeral(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    guard_home = tmp_path / "guard"
    versioned = tmp_path / "core" / "versions" / "3.0.57" / "hol-guard"
    script = home / ".cursor" / "hooks" / "hol-guard-cursor-hook.py"
    script.parent.mkdir(parents=True)
    script.write_text(_managed_hook_source(argv0=str(versioned)), encoding="utf-8")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cursor_hook_rebind.sys.frozen",
        False,
        raising=False,
    )
    result = rebind_stale_cursor_hooks(guard_home, home_dir=home)
    assert result["rebound"] is False
    assert result["reason"] == "stable_frozen_cli_unavailable"
    assert "versions/3.0.57" in script.read_text(encoding="utf-8")


def test_rebind_rewrites_versioned_cli_to_current_hol_guard_shim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    core_dir = tmp_path / "core"
    versioned = _executable_file(core_dir / "versions" / "3.0.57" / "hol-guard")
    shim = _executable_file(core_dir / "current-hol-guard", "#!/bin/sh\nexec true\n")
    home = tmp_path / "home"
    guard_home = tmp_path / "guard"
    script = home / ".cursor" / "hooks" / "hol-guard-cursor-hook.py"
    script.parent.mkdir(parents=True)
    script.write_text(_managed_hook_source(argv0=str(versioned)), encoding="utf-8")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cursor_hook_rebind.sys.frozen",
        True,
        raising=False,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.guard_cli_attestation.sys.frozen",
        True,
        raising=False,
    )
    monkeypatch.setattr("codex_plugin_scanner.guard.stable_guard_cli.sys.executable", str(versioned))
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.guard_cli_attestation.sys.executable",
        str(versioned),
    )
    monkeypatch.setattr("codex_plugin_scanner.guard.frozen_runtime_commands.sys.frozen", True, raising=False)
    monkeypatch.setattr("codex_plugin_scanner.guard.frozen_runtime_commands.sys.executable", str(shim))

    result = rebind_stale_cursor_hooks(guard_home, home_dir=home)

    assert result["rebound"] is True
    rewritten = script.read_text(encoding="utf-8")
    assert "current-hol-guard" in rewritten
    assert "versions/3.0.57" not in rewritten
    assert '["guard", "hook"' not in rewritten


def test_resolve_attested_guard_cli_bakes_current_hol_guard_shim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    core_dir = tmp_path / "core"
    versioned = _executable_file(core_dir / "versions" / "3.0.57" / "hol-guard")
    shim = _executable_file(core_dir / "current-hol-guard", "#!/bin/sh\nexec true\n")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.guard_cli_attestation.sys.frozen",
        True,
        raising=False,
    )
    monkeypatch.setattr("codex_plugin_scanner.guard.stable_guard_cli.sys.executable", str(versioned))
    context = HarnessContext(home_dir=tmp_path / "home", guard_home=tmp_path / "guard", workspace_dir=None)
    attested = resolve_attested_guard_cli(context)
    assert attested.frozen is True
    assert Path(attested.command[0]).name == "current-hol-guard"
    assert attested.command == (str(shim.expanduser().absolute()),)


def test_frozen_recovery_command_defaults_to_stable_shim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    core_dir = tmp_path / "core"
    versioned = _executable_file(core_dir / "versions" / "3.0.57" / "hol-guard")
    shim = _executable_file(core_dir / "current-hol-guard", "#!/bin/sh\nexec true\n")
    monkeypatch.setattr("codex_plugin_scanner.guard.frozen_runtime_commands.sys.frozen", True, raising=False)
    monkeypatch.setattr("codex_plugin_scanner.guard.frozen_runtime_commands.sys.executable", str(versioned))
    monkeypatch.setattr("codex_plugin_scanner.guard.stable_guard_cli.sys.executable", str(versioned))
    command = frozen_daemon_recovery_command(tmp_path / "guard", tmp_path / "home")
    assert Path(command[0]).name == "current-hol-guard"
    assert command[0] == str(shim)


def test_reconcile_rebinds_ephemeral_cursor_hooks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard import runtime_artifact_reconciliation as reconciliation
    from codex_plugin_scanner.guard.shim_refresh import ShimRefreshResult

    store = type(
        "Store",
        (),
        {
            "guard_home": tmp_path / "guard",
            "list_managed_installs": staticmethod(lambda: []),
        },
    )()
    monkeypatch.setattr(
        reconciliation,
        "refresh_stale_harness_shims",
        lambda **_kwargs: ShimRefreshResult(refreshed=(), unchanged=(), errors=()),
    )
    monkeypatch.setattr(
        reconciliation,
        "repair_failing_managed_harness_hooks",
        lambda *_args, **_kwargs: ((), ()),
    )
    monkeypatch.setattr(
        reconciliation,
        "package_shim_status",
        lambda _context: {"installed_managers": []},
    )
    monkeypatch.setattr(
        reconciliation,
        "rebind_stale_cursor_hooks",
        lambda *_args, **_kwargs: {"rebound": True, "reason": "cursor_hook_script_rebound"},
    )

    result = reconciliation.reconcile_runtime_artifacts(store, home_dir=tmp_path / "home")

    assert result.repaired_harnesses == ("cursor",)
    assert result.changed is True
    assert result.healthy is True
