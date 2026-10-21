"""Tests for full HOL Guard self-uninstall flows."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import uninstall_commands, update_retirement
from codex_plugin_scanner.guard.native_resident_update_lock import NativeResidentUpdateLockError
from codex_plugin_scanner.guard.store import GuardStore


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    guard_home = home / ".hol-guard"
    home.mkdir(parents=True, exist_ok=True)
    guard_home.mkdir(parents=True, exist_ok=True)
    return HarnessContext(home_dir=home, workspace_dir=None, guard_home=guard_home)


def test_self_uninstall_dry_run_reports_full_removal_plan(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    store.set_managed_install("codex", True, None, {"shim_path": "guard-codex"}, "2026-06-18T00:00:00Z")
    monkeypatch.setattr(uninstall_commands, "_current_version", lambda: "2.0.764")
    monkeypatch.setattr(uninstall_commands, "_installer_kind", lambda: "pip")
    monkeypatch.setattr(
        uninstall_commands,
        "package_shim_status",
        lambda _context: {"installed_managers": ["npm", "pip"]},
    )

    payload, exit_code = uninstall_commands.run_guard_self_uninstall(
        dry_run=True,
        context=context,
        store=store,
        now="2026-06-18T00:00:00Z",
    )

    assert exit_code == 0
    assert payload["status"] == "planned"
    assert payload["command"] == [sys.executable, "-m", "pip", "uninstall", "-y", "hol-guard"]
    assert payload["planned_managed_harnesses"] == ["codex"]
    assert payload["planned_package_shim_managers"] == ["npm", "pip"]
    assert payload["changed"] is False
    assert context.guard_home.exists()


def test_self_uninstall_removes_managed_surfaces_before_package(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    store.set_managed_install("codex", True, None, {"shim_path": "guard-codex"}, "2026-06-18T00:00:00Z")
    (context.guard_home / "state.txt").write_text("keep", encoding="utf-8")
    commands: list[list[str]] = []

    monkeypatch.setattr(uninstall_commands, "_current_version", lambda: "2.0.764")
    monkeypatch.setattr(uninstall_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(uninstall_commands, "package_shim_status", lambda _context: {"installed_managers": ["npm"]})
    monkeypatch.setattr(uninstall_commands, "retire_all_guard_daemons_for_home", lambda _guard_home: [4242])
    monkeypatch.setattr(
        uninstall_commands,
        "apply_managed_install",
        lambda command, harness, install_all, context, store, workspace, now: {
            "managed_install": {
                "harness": harness,
                "active": False,
                "workspace": workspace,
                "manifest": {"removed_paths": [str(context.guard_home / "bin" / f"guard-{harness}")]},
                "updated_at": now,
            }
        },
    )
    monkeypatch.setattr(
        uninstall_commands,
        "uninstall_package_shims",
        lambda _context, managers=None: {
            "removed_managers": list(managers or ()),
            "removed_paths": [],
            "remaining_managers": [],
            "manifest_path": str(context.guard_home / "package-shims" / "manifest.json"),
            "shim_dir": str(context.guard_home / "package-shims" / "bin"),
        },
    )
    monkeypatch.setattr(
        uninstall_commands,
        "remove_guard_profile_blocks",
        lambda _context: {"changed": True, "changed_paths": [str(context.home_dir / ".zshrc")], "removed_paths": []},
    )

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="hol-guard removed", stderr="")

    monkeypatch.setattr(uninstall_commands.subprocess, "run", fake_run)

    payload, exit_code = uninstall_commands.run_guard_self_uninstall(
        dry_run=False,
        context=context,
        store=store,
        now="2026-06-18T00:00:00Z",
    )

    assert exit_code == 0
    assert commands == [["pipx", "uninstall", "hol-guard"]]
    assert payload["status"] == "removed"
    assert payload["package_removed"] is True
    assert payload["guard_home_removed"] is True
    assert payload["oauth_credentials_cleared"] is True
    assert payload["managed_installs"][0]["harness"] == "codex"
    assert payload["managed_installs"][0]["active"] is False
    assert payload["package_shim_uninstall"]["removed_managers"] == ["npm"]
    assert not context.guard_home.exists()


def test_self_uninstall_stops_before_package_when_managed_cleanup_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    store.set_managed_install("codex", True, None, {"shim_path": "guard-codex"}, "2026-06-18T00:00:00Z")
    called = {"installer": False}

    monkeypatch.setattr(uninstall_commands, "_current_version", lambda: "2.0.764")
    monkeypatch.setattr(uninstall_commands, "_installer_kind", lambda: "uv")
    monkeypatch.setattr(uninstall_commands, "package_shim_status", lambda _context: {"installed_managers": []})
    monkeypatch.setattr(uninstall_commands, "retire_all_guard_daemons_for_home", lambda _guard_home: [])

    def fail_uninstall(*args: object, **kwargs: object) -> dict[str, object]:
        del args, kwargs
        raise RuntimeError("hook cleanup failed")

    monkeypatch.setattr(uninstall_commands, "apply_managed_install", fail_uninstall)

    def unexpected_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        del command, kwargs
        called["installer"] = True
        raise AssertionError("package uninstall should not run after a managed cleanup failure")

    monkeypatch.setattr(uninstall_commands.subprocess, "run", unexpected_run)

    payload, exit_code = uninstall_commands.run_guard_self_uninstall(
        dry_run=False,
        context=context,
        store=store,
        now="2026-06-18T00:00:00Z",
    )

    assert exit_code == 1
    assert payload["status"] == "failed"
    assert str(payload["message"]).startswith("HOL Guard removal stopped at harness codex")
    assert payload["error"] == "hook cleanup failed"
    assert called["installer"] is False
    assert context.guard_home.exists()


def test_self_uninstall_continues_when_managed_install_state_is_unreadable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)

    monkeypatch.setattr(uninstall_commands, "_current_version", lambda: "2.0.764")
    monkeypatch.setattr(uninstall_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(store, "list_managed_installs", lambda: (_ for _ in ()).throw(RuntimeError("db locked")))
    monkeypatch.setattr(uninstall_commands, "package_shim_status", lambda _context: {"installed_managers": []})
    monkeypatch.setattr(uninstall_commands, "retire_all_guard_daemons_for_home", lambda _guard_home: [])
    monkeypatch.setattr(
        uninstall_commands,
        "remove_guard_profile_blocks",
        lambda _context: {"changed": False, "changed_paths": [], "removed_paths": []},
    )
    monkeypatch.setattr(
        uninstall_commands,
        "uninstall_package_shims",
        lambda _context, managers=None: {
            "removed_managers": list(managers or ()),
            "removed_paths": [],
            "remaining_managers": [],
            "manifest_path": str(context.guard_home / "package-shims" / "manifest.json"),
            "shim_dir": str(context.guard_home / "package-shims" / "bin"),
        },
    )
    monkeypatch.setattr(
        uninstall_commands.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 0, stdout="removed", stderr=""),
    )

    payload, exit_code = uninstall_commands.run_guard_self_uninstall(
        dry_run=False,
        context=context,
        store=store,
        now="2026-06-18T00:00:00Z",
    )

    assert exit_code == 0
    assert payload["status"] == "removed"
    assert payload["planned_managed_harnesses"] == []
    assert any("Could not read managed install state before uninstall: db locked" in note for note in payload["notes"])


def test_self_uninstall_catches_managed_install_context_resolution_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    store.set_managed_install("codex", True, None, {"shim_path": "guard-codex"}, "2026-06-18T00:00:00Z")

    monkeypatch.setattr(uninstall_commands, "_current_version", lambda: "2.0.764")
    monkeypatch.setattr(uninstall_commands, "_installer_kind", lambda: "uv")
    monkeypatch.setattr(uninstall_commands, "package_shim_status", lambda _context: {"installed_managers": []})
    monkeypatch.setattr(uninstall_commands, "retire_all_guard_daemons_for_home", lambda _guard_home: [])
    monkeypatch.setattr(
        uninstall_commands,
        "_managed_install_context",
        lambda context, managed_install: (_ for _ in ()).throw(OSError("bad workspace")),
    )
    monkeypatch.setattr(
        uninstall_commands.subprocess,
        "run",
        lambda command, **kwargs: (_ for _ in ()).throw(AssertionError("installer should not run")),
    )

    payload, exit_code = uninstall_commands.run_guard_self_uninstall(
        dry_run=False,
        context=context,
        store=store,
        now="2026-06-18T00:00:00Z",
    )

    assert exit_code == 1
    assert payload["status"] == "failed"
    assert str(payload["message"]).startswith("HOL Guard removal stopped at harness codex")
    assert payload["error"] == "bad workspace"


def _stub_removal(monkeypatch: pytest.MonkeyPatch, context: HarnessContext) -> None:
    """Take every removal step except native retirement out of the way."""

    monkeypatch.setattr(uninstall_commands, "_current_version", lambda: "2.0.764")
    monkeypatch.setattr(uninstall_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(uninstall_commands, "package_shim_status", lambda _context: {"installed_managers": []})
    monkeypatch.setattr(uninstall_commands, "retire_all_guard_daemons_for_home", lambda _guard_home: [])
    monkeypatch.setattr(
        uninstall_commands,
        "remove_guard_profile_blocks",
        lambda _context: {"changed": False, "changed_paths": [], "removed_paths": []},
    )
    monkeypatch.setattr(
        uninstall_commands,
        "uninstall_package_shims",
        lambda _context, managers=None: {
            "removed_managers": list(managers or ()),
            "removed_paths": [],
            "remaining_managers": [],
            "manifest_path": str(context.guard_home / "package-shims" / "manifest.json"),
            "shim_dir": str(context.guard_home / "package-shims" / "bin"),
        },
    )
    monkeypatch.setattr(
        uninstall_commands.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 0, stdout="removed", stderr=""),
    )


def test_self_uninstall_retires_the_native_resident(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A Windows tester found `hol-guard-runtime.exe` still running afterwards.

    Retiring the Python daemons leaves the native resident alone, and the
    resident holds the runtime executable open, so on Windows the file cannot
    even be deleted while it lives.
    """

    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    _stub_removal(monkeypatch, context)
    retired: list[Path] = []

    def retire(guard_home: Path) -> bool:
        retired.append(guard_home)
        return True

    monkeypatch.setattr(uninstall_commands, "retire_native_resident_for_home", retire)

    payload, exit_code = uninstall_commands.run_guard_self_uninstall(
        dry_run=False,
        context=context,
        store=store,
        now="2026-06-18T00:00:00Z",
    )

    assert exit_code == 0
    assert retired == [context.guard_home]
    assert payload["daemon_cleanup"]["native_resident_retired"] is True


def test_self_uninstall_reports_a_native_resident_it_could_not_stop(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    _stub_removal(monkeypatch, context)
    monkeypatch.setattr(uninstall_commands, "retire_native_resident_for_home", lambda _guard_home: False)

    payload, exit_code = uninstall_commands.run_guard_self_uninstall(
        dry_run=False,
        context=context,
        store=store,
        now="2026-06-18T00:00:00Z",
    )

    assert exit_code == 0
    assert payload["daemon_cleanup"]["native_resident_retired"] is False
    assert any("Could not stop the Guard native runtime" in note for note in payload["notes"])


def test_uninstall_holds_the_update_barrier_until_hooks_are_gone(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A hook that fires after the stop and before hook removal starts the resident again."""

    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    store.set_managed_install("codex", True, None, {"shim_path": "guard-codex"}, "2026-06-18T00:00:00Z")
    _stub_removal(monkeypatch, context)
    events: list[str] = []

    @contextmanager
    def hold(_guard_home: Path, **_kwargs: object) -> Iterator[None]:
        events.append("acquire")
        yield
        events.append("release")

    monkeypatch.setattr(uninstall_commands, "hold_native_resident_update_lock", hold)
    monkeypatch.setattr(uninstall_commands, "resident_stop_executable", lambda: tmp_path / "runtime")

    def retire(_guard_home: Path) -> bool:
        events.append("retire")
        return True

    monkeypatch.setattr(uninstall_commands, "retire_native_resident_for_home", retire)
    monkeypatch.setattr(
        uninstall_commands,
        "_managed_install_context",
        lambda install_context, _managed: (install_context, None),
    )
    monkeypatch.setattr(
        uninstall_commands,
        "apply_managed_install",
        lambda *_args, **_kwargs: events.append("hooks") or {"managed_install": {"harness": "codex"}},
    )

    payload, exit_code = uninstall_commands.run_guard_self_uninstall(
        dry_run=False,
        context=context,
        store=store,
        now="2026-06-18T00:00:00Z",
    )

    assert exit_code == 0
    assert payload["daemon_cleanup"]["native_resident_retired"] is True
    assert events == ["acquire", "retire", "hooks", "release"]


def test_a_busy_update_barrier_stops_uninstall_before_hooks_are_removed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    store.set_managed_install("codex", True, None, {"shim_path": "guard-codex"}, "2026-06-18T00:00:00Z")
    _stub_removal(monkeypatch, context)

    def hold(_guard_home: Path, **_kwargs: object) -> None:
        raise NativeResidentUpdateLockError("update_native_resident_lock_busy")

    monkeypatch.setattr(uninstall_commands, "hold_native_resident_update_lock", hold)
    monkeypatch.setattr(
        uninstall_commands,
        "apply_managed_install",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("hooks removed")),
    )

    payload, exit_code = uninstall_commands.run_guard_self_uninstall(
        dry_run=False,
        context=context,
        store=store,
        now="2026-06-18T00:00:00Z",
    )

    assert exit_code == 1
    assert payload["status"] == "failed"
    assert payload["managed_installs"] == []
    assert any("update barrier" in note for note in payload["notes"])


def test_a_missing_runtime_with_no_resident_state_is_already_stopped(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing-runtime"
    monkeypatch.setattr(update_retirement, "_runtime_candidates", lambda: (missing,))
    monkeypatch.setattr(update_retirement, "_bundled_runtime_candidate", lambda: missing)
    monkeypatch.setattr(
        update_retirement,
        "retire_native_resident_for_update",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("launched")),
    )

    assert update_retirement.retire_native_resident_for_home(tmp_path / "home") is True


def test_a_missing_runtime_with_resident_state_is_not_reported_stopped(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    state = home / "native-runtime" / "resident-v3-abc"
    state.mkdir(parents=True)
    (state / "generation-1.json").write_text("{}", encoding="utf-8")
    missing = tmp_path / "missing-runtime"
    monkeypatch.setattr(update_retirement, "_runtime_candidates", lambda: (missing,))
    monkeypatch.setattr(update_retirement, "_bundled_runtime_candidate", lambda: missing)
    monkeypatch.setattr(update_retirement.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(update_retirement, "retire_native_resident_for_update", lambda **_kwargs: False)

    assert update_retirement.retire_native_resident_for_home(home) is False


def test_a_forced_override_is_the_runtime_that_gets_stopped(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    override = tmp_path / "override-runtime"
    override.write_bytes(b"runtime")
    seen: list[Path] = []
    monkeypatch.setattr(update_retirement, "_runtime_candidates", lambda: (override, tmp_path / "bundled"))
    monkeypatch.setattr(
        update_retirement,
        "retire_native_resident_for_update",
        lambda **kwargs: seen.append(kwargs["executable"]) or True,
    )

    assert update_retirement.retire_native_resident_for_home(tmp_path / "home") is True
    assert seen == [override]
