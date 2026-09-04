"""Live Codex and Cursor hook health uses intercept proof, not attested identity."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approvals import _live_hook_verification
from codex_plugin_scanner.guard.codex_hook_health import codex_runtime_hooks_verified
from codex_plugin_scanner.guard.codex_hook_registration import live_guard_codex_hooks_intercept
from codex_plugin_scanner.guard.cursor_hook_health import cursor_runtime_hooks_verified
from codex_plugin_scanner.guard.store import GuardStore

_GUARD_CODEX_HOOK_COMMAND = (
    "python -I ./codex_daemon_hook_bridge.py "
    '\'{"fallback_command":["python","-c","from codex_plugin_scanner.cli import main"]}\''
)


def _ctx(tmp_path: Path) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard-home",
    )


def _write_codex_runtime_hooks(
    home: Path,
    *,
    include_permission: bool,
    guard_command: str,
    extra_foreign: bool,
    enabled: bool = True,
    matcher: str = "Bash",
) -> None:
    codex_home = home / ".codex"
    codex_home.mkdir(parents=True, exist_ok=True)
    (codex_home / "config.toml").write_text("[features]\nhooks = true\n", encoding="utf-8")
    guard_handler: dict[str, object] = {"type": "command", "command": guard_command, "timeout": 30}
    if not enabled:
        guard_handler["disabled"] = True
    pretool: list[dict[str, object]] = [{"matcher": matcher, "hooks": [guard_handler]}]
    if extra_foreign:
        pretool.append(
            {
                "matcher": "Edit",
                "hooks": [{"type": "command", "command": "node extra-hook.js", "timeout": 5}],
            }
        )
    payload: dict[str, object] = {"hooks": {"PreToolUse": pretool}}
    hooks = payload["hooks"]
    assert isinstance(hooks, dict)
    if include_permission:
        hooks["PermissionRequest"] = [{"matcher": matcher, "hooks": [guard_handler]}]
    (codex_home / "hooks.json").write_text(json.dumps(payload), encoding="utf-8")


def _write_cursor_runtime_hooks(
    home: Path,
    *,
    include_file_io_hooks: bool,
    create_script: bool = True,
    command: str | None = None,
) -> Path:
    cursor_home = home / ".cursor"
    script_path = cursor_home / "hooks" / "hol-guard-cursor-hook.py"
    script_path.parent.mkdir(parents=True, exist_ok=True)
    if create_script:
        script_path.write_text("# Managed by HOL Guard\n", encoding="utf-8")
    resolved = command if command is not None else str(script_path.resolve())
    hooks: dict[str, object] = {
        "beforeShellExecution": [{"command": resolved, "timeout": 45, "failClosed": True}],
        "beforeMCPExecution": [{"command": resolved, "timeout": 45, "failClosed": True}],
        "afterShellExecution": [{"command": "node extra-hook.js", "timeout": 5}],
    }
    if include_file_io_hooks:
        hooks["beforeReadFile"] = [{"command": resolved, "timeout": 45, "failClosed": True}]
        hooks["beforeWriteFile"] = [{"command": resolved, "timeout": 45, "failClosed": True}]
    (cursor_home / "hooks.json").write_text(json.dumps({"version": 1, "hooks": hooks}), encoding="utf-8")
    return script_path


def test_live_codex_hooks_pass_when_authenticated_manifest_is_stale(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: ctx.home_dir)
    _write_codex_runtime_hooks(
        ctx.home_dir,
        include_permission=True,
        guard_command=_GUARD_CODEX_HOOK_COMMAND,
        extra_foreign=True,
    )
    store = GuardStore(ctx.guard_home, prime_policy_integrity=False)
    store.set_managed_install("codex", True, None, {"harness": "codex", "active": True}, "2026-08-17T12:00:00+00:00")

    assert live_guard_codex_hooks_intercept(
        json.loads((ctx.home_dir / ".codex" / "hooks.json").read_text(encoding="utf-8"))["hooks"]
    )
    assert codex_runtime_hooks_verified(ctx) is True
    assert _live_hook_verification(store.list_managed_installs(), store) == {"codex": True}


def test_live_codex_hooks_reject_missing_permission_intercept(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: ctx.home_dir)
    _write_codex_runtime_hooks(
        ctx.home_dir,
        include_permission=False,
        guard_command=_GUARD_CODEX_HOOK_COMMAND,
        extra_foreign=False,
    )
    store = GuardStore(ctx.guard_home, prime_policy_integrity=False)
    store.set_managed_install("codex", True, None, {"harness": "codex", "active": True}, "2026-08-17T12:00:00+00:00")

    assert codex_runtime_hooks_verified(ctx) is False
    assert _live_hook_verification(store.list_managed_installs(), store) == {"codex": False}


def test_live_codex_hooks_reject_disabled_or_non_shell_matchers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: ctx.home_dir)
    _write_codex_runtime_hooks(
        ctx.home_dir,
        include_permission=True,
        guard_command=_GUARD_CODEX_HOOK_COMMAND,
        extra_foreign=False,
        enabled=False,
    )
    assert codex_runtime_hooks_verified(ctx) is False
    _write_codex_runtime_hooks(
        ctx.home_dir,
        include_permission=True,
        guard_command=_GUARD_CODEX_HOOK_COMMAND,
        extra_foreign=False,
        enabled=True,
        matcher="Edit",
    )
    assert codex_runtime_hooks_verified(ctx) is False


def test_live_cursor_hooks_pass_when_attested_identity_is_stale(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: ctx.home_dir)
    _write_cursor_runtime_hooks(ctx.home_dir, include_file_io_hooks=True)
    store = GuardStore(ctx.guard_home, prime_policy_integrity=False)
    store.set_managed_install("cursor", True, None, {"harness": "cursor", "active": True}, "2026-08-17T12:00:00+00:00")

    assert cursor_runtime_hooks_verified(ctx) is True
    assert _live_hook_verification(store.list_managed_installs(), store) == {"cursor": True}


def test_live_cursor_hooks_reject_missing_read_intercept(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: ctx.home_dir)
    _write_cursor_runtime_hooks(ctx.home_dir, include_file_io_hooks=False)
    store = GuardStore(ctx.guard_home, prime_policy_integrity=False)
    store.set_managed_install("cursor", True, None, {"harness": "cursor", "active": True}, "2026-08-17T12:00:00+00:00")

    assert cursor_runtime_hooks_verified(ctx) is False
    assert _live_hook_verification(store.list_managed_installs(), store) == {"cursor": False}


def test_live_cursor_hooks_reject_empty_command_or_missing_script(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: ctx.home_dir)
    script_path = _write_cursor_runtime_hooks(ctx.home_dir, include_file_io_hooks=True, command="")
    assert cursor_runtime_hooks_verified(ctx) is False
    script_path.unlink(missing_ok=True)
    _write_cursor_runtime_hooks(ctx.home_dir, include_file_io_hooks=True, create_script=False)
    assert cursor_runtime_hooks_verified(ctx) is False


def test_live_codex_hooks_pass_for_frozen_cli_bridge_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: ctx.home_dir)
    _write_codex_runtime_hooks(
        ctx.home_dir,
        include_permission=True,
        guard_command="current-hol-guard -I ./codex_daemon_hook_bridge.py '{}'",
        extra_foreign=False,
    )
    store = GuardStore(ctx.guard_home, prime_policy_integrity=False)
    store.set_managed_install("codex", True, None, {"harness": "codex", "active": True}, "2026-08-17T12:00:00+00:00")

    assert live_guard_codex_hooks_intercept(
        json.loads((ctx.home_dir / ".codex" / "hooks.json").read_text(encoding="utf-8"))["hooks"]
    )
    assert codex_runtime_hooks_verified(ctx) is True
    assert _live_hook_verification(store.list_managed_installs(), store) == {"codex": True}


def test_live_codex_hooks_reject_marker_only_noop_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: ctx.home_dir)
    _write_codex_runtime_hooks(
        ctx.home_dir,
        include_permission=True,
        guard_command="true --harness codex hol-guard hook",
        extra_foreign=False,
    )
    assert codex_runtime_hooks_verified(ctx) is False


def test_live_codex_hooks_pass_when_native_shell_protection_active(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: ctx.home_dir)
    _write_codex_runtime_hooks(
        ctx.home_dir,
        include_permission=False,
        guard_command="true --harness codex hol-guard hook",
        extra_foreign=False,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.codex.codex_native_hook_state",
        lambda _context: {"shell_protection_active": True},
    )
    assert codex_runtime_hooks_verified(ctx) is True


def test_live_cursor_hooks_reject_name_only_noop_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(Path, "home", lambda: ctx.home_dir)
    _write_cursor_runtime_hooks(
        ctx.home_dir,
        include_file_io_hooks=True,
        command="echo hol-guard-cursor-hook",
    )
    assert cursor_runtime_hooks_verified(ctx) is False
