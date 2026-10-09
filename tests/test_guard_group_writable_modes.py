"""Group-writable user files (umask 0002) must not abort Guard transitions or uninstall."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.adapters import claude_hook_argv
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.claude_frozen_hook import FROZEN_CLAUDE_HOOK_COMMAND, run_frozen_claude_hook
from codex_plugin_scanner.guard.adapters.claude_hook_config import (
    CLAUDE_GUARD_DAEMON_HOOK_MARKER,
    CLAUDE_GUARD_SESSION_START_HOOK_MARKER,
    is_guard_hook_command,
)
from codex_plugin_scanner.guard.cli import uninstall_commands
from codex_plugin_scanner.guard.runtime_transition import TransitionError, TransitionFile
from codex_plugin_scanner.guard.store import GuardStore

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")


@posix_only
def test_changed_user_file_group_write_is_normalized(tmp_path: Path) -> None:
    change = TransitionFile(tmp_path / ".zshrc", b"a", b"b", before_mode=0o664, after_mode=0o664)
    payload = change.payload()
    assert payload["before_mode"] == 0o664
    assert payload["after_mode"] == 0o644


@posix_only
def test_shim_style_executable_mode_drops_group_write(tmp_path: Path) -> None:
    change = TransitionFile(tmp_path / "shim", b"a", b"b", before_mode=0o664, after_mode=0o664 | 0o755)
    assert change.payload()["after_mode"] == 0o755


@posix_only
def test_private_guard_file_stays_private(tmp_path: Path) -> None:
    assert TransitionFile(tmp_path / "x", None, b"b", after_mode=0o600).payload()["after_mode"] == 0o600


@posix_only
def test_unchanged_group_writable_file_is_not_rewritten_or_rejected(tmp_path: Path) -> None:
    change = TransitionFile(tmp_path / "x", b"a", b"a", before_mode=0o664, after_mode=0o664)
    assert change.payload()["after_mode"] == 0o664


@posix_only
def test_world_writable_source_is_published_privately(tmp_path: Path) -> None:
    target = tmp_path / ".bashrc"
    assert TransitionFile(target, b"a", b"b", before_mode=0o666, after_mode=0o666).payload()["after_mode"] == 0o644
    assert TransitionFile(target, b"a", b"b", before_mode=0o666, after_mode=0o600).payload()["after_mode"] == 0o600
    assert TransitionFile(target, b"a", None, before_mode=0o666, after_mode=0o600).payload()["after_mode"] == 0o600


@posix_only
def test_direct_writers_see_the_normalized_mode(tmp_path: Path) -> None:
    # Writers that publish change.after_mode themselves must agree with payload().
    change = TransitionFile(tmp_path / ".zprofile", b"a", b"b", before_mode=0o664, after_mode=0o664)
    assert change.after_mode == 0o644
    assert change.payload()["after_mode"] == change.after_mode


@posix_only
def test_new_group_writable_file_request_is_rejected_with_path(tmp_path: Path) -> None:
    target = tmp_path / "new"
    with pytest.raises(TransitionError, match="file_mode_invalid") as raised:
        TransitionFile(target, None, b"b", after_mode=0o664).payload()
    assert str(target) in str(raised.value)


@pytest.mark.parametrize("mode", [0o4755, 0o2755, 0o1755])
def test_special_mode_bits_are_still_rejected_with_path(tmp_path: Path, mode: int) -> None:
    target = tmp_path / "x"
    with pytest.raises(TransitionError) as raised:
        TransitionFile(target, b"a", b"b", before_mode=0o644, after_mode=mode).payload()
    assert str(target) in str(raised.value)


@posix_only
def test_pinned_group_writable_dependency_is_still_rejected(tmp_path: Path) -> None:
    target = tmp_path / "authority"
    target.write_bytes(b"secret")
    target.chmod(0o664)
    with pytest.raises(TransitionError) as raised:
        TransitionFile.identity_dependency(target).payload()
    assert str(target.resolve()) in str(raised.value)


def _frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)


def test_claude_hooks_use_entrypoint_not_dash_c_when_frozen(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _frozen(monkeypatch)
    context = HarnessContext(home_dir=tmp_path / "h", workspace_dir=None, guard_home=tmp_path / "g")
    daemon = claude_hook_argv.daemon_hook_command_parts(context, fallback_daemon_url="http://127.0.0.1:1")
    session = claude_hook_argv.session_start_command_parts(context)
    fallback = claude_hook_argv.guard_hook_command_parts(context)
    for argv in (daemon, session, fallback):
        assert "-c" not in argv and "-m" not in argv
    assert daemon[1:3] == (FROZEN_CLAUDE_HOOK_COMMAND, CLAUDE_GUARD_DAEMON_HOOK_MARKER)
    assert session[1:3] == (FROZEN_CLAUDE_HOOK_COMMAND, CLAUDE_GUARD_SESSION_START_HOOK_MARKER)
    assert fallback[1] == "hook"
    assert any(is_guard_hook_command(part) for part in daemon)
    assert any(is_guard_hook_command(part) for part in session)


def test_claude_hooks_keep_python_launcher_when_not_frozen(tmp_path: Path) -> None:
    context = HarnessContext(home_dir=tmp_path / "h", workspace_dir=None, guard_home=tmp_path / "g")
    assert claude_hook_argv.session_start_command_parts(context)[1] == "-c"


def test_frozen_dispatch_routes_claude_hook(monkeypatch: pytest.MonkeyPatch) -> None:
    _frozen(monkeypatch)
    seen: list[list[str]] = []
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.claude_frozen_hook.run_frozen_claude_hook",
        lambda argv: seen.append(list(argv)) or 7,
    )
    assert cli._run_frozen_early_dispatch(["__guard-claude-hook", "M", "x"]) == 7
    assert seen == [["M", "x"]]


def test_frozen_claude_hook_rejects_unknown_marker() -> None:
    with pytest.raises(SystemExit):
        run_frozen_claude_hook(["bogus"])


def _uninstall_context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    guard_home = home / ".hol-guard"
    guard_home.mkdir(parents=True)
    return HarnessContext(home_dir=home, workspace_dir=None, guard_home=guard_home)


def _patch_uninstall(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(uninstall_commands, "_current_version", lambda: "3.36.0")
    monkeypatch.setattr(uninstall_commands, "_installer_kind", lambda: "pip")
    monkeypatch.setattr(uninstall_commands, "package_shim_status", lambda _c: {"installed_managers": []})
    monkeypatch.setattr(uninstall_commands, "retire_all_guard_daemons_for_home", lambda _g: [])


def test_frozen_self_uninstall_skips_pip_and_keeps_guard_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _frozen(monkeypatch)
    _patch_uninstall(monkeypatch)
    context = _uninstall_context(tmp_path)
    store = GuardStore(context.guard_home)
    cleared: list[bool] = []
    monkeypatch.setattr(store, "clear_oauth_local_credentials", lambda: cleared.append(True))
    monkeypatch.setattr(uninstall_commands, "remove_guard_profile_blocks", lambda _c: {"changed": False})
    monkeypatch.setattr(
        uninstall_commands, "uninstall_package_shims", lambda _c, managers=None: {"removed_managers": []}
    )

    def _boom(*_a: object, **_k: object) -> None:
        raise AssertionError("pip must not run")

    monkeypatch.setattr(uninstall_commands.subprocess, "run", _boom)
    payload, code = uninstall_commands.run_guard_self_uninstall(
        dry_run=False, context=context, store=store, now="2026-01-01T00:00:00Z"
    )
    assert code == 0
    assert payload["package_uninstall_skipped"] is True
    assert payload["package_removed"] is False
    assert context.guard_home.exists()
    assert any("desktop" in str(note) for note in payload["notes"])  # type: ignore[union-attr]
    assert payload["oauth_credentials_cleared"] is True
    assert cleared == [True]


@pytest.mark.parametrize("installer", ["uv", "pipx"])
def test_frozen_self_uninstall_never_runs_a_package_manager(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, installer: str
) -> None:
    _frozen(monkeypatch)
    _patch_uninstall(monkeypatch)
    monkeypatch.setattr(uninstall_commands, "_installer_kind", lambda: installer)
    context = _uninstall_context(tmp_path)
    monkeypatch.setattr(uninstall_commands, "remove_guard_profile_blocks", lambda _c: {"changed": False})
    monkeypatch.setattr(
        uninstall_commands, "uninstall_package_shims", lambda _c, managers=None: {"removed_managers": []}
    )
    monkeypatch.setattr(uninstall_commands.subprocess, "run", lambda *_a, **_k: pytest.fail("no package manager"))
    payload, code = uninstall_commands.run_guard_self_uninstall(
        dry_run=False, context=context, store=GuardStore(context.guard_home), now="2026-01-01T00:00:00Z"
    )
    assert code == 0
    assert payload["package_uninstall_skipped"] is True
    assert payload["command"] == []


def test_frozen_dry_run_does_not_promise_package_removal(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _frozen(monkeypatch)
    _patch_uninstall(monkeypatch)
    context = _uninstall_context(tmp_path)
    payload, code = uninstall_commands.run_guard_self_uninstall(
        dry_run=True, context=context, store=GuardStore(context.guard_home), now="2026-01-01T00:00:00Z"
    )
    assert code == 0
    assert payload["command"] == []
    assert "hol-guard package" not in str(payload["message"])
    assert "desktop core" in str(payload["message"])


def test_frozen_claude_bridge_recovers_through_the_frozen_core(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard import frozen_runtime_commands
    from codex_plugin_scanner.guard.adapters import claude_daemon_hook_bridge

    monkeypatch.setattr(frozen_runtime_commands, "is_frozen_guard_runtime", lambda: True)
    monkeypatch.setattr(frozen_runtime_commands, "resolve_frozen_guard_cli", lambda: "/opt/guard/hol-guard")
    command = claude_daemon_hook_bridge._recovery_command(tmp_path / "guard-home" / "state.json", "home=/h")
    assert command[:2] == ("/opt/guard/hol-guard", frozen_runtime_commands.FROZEN_DAEMON_RECOVER_ARG)
    assert "-c" not in command


def test_failed_harness_removal_reports_name_and_prior_removals(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_uninstall(monkeypatch)
    context = _uninstall_context(tmp_path)
    store = GuardStore(context.guard_home)
    for harness in ("codex", "cursor"):
        store.set_managed_install(harness, True, None, {}, "2026-01-01T00:00:00Z")

    def _apply(command, harness, install_all, ctx, st, workspace, now):  # type: ignore[no-untyped-def]
        if harness == "cursor":
            raise TransitionError("file_mode_invalid", "/home/u/.cursor/mcp.json")
        return {"managed_install": {"harness": harness}}

    monkeypatch.setattr(uninstall_commands, "apply_managed_install", _apply)
    payload, code = uninstall_commands.run_guard_self_uninstall(
        dry_run=False, context=context, store=store, now="2026-01-01T00:00:00Z"
    )
    assert code == 1
    assert "/home/u/.cursor/mcp.json" in str(payload["error"])
    assert payload["failed_harness"] == "cursor"
    assert "codex" in str(payload["message"]) and "cursor" in str(payload["message"])
