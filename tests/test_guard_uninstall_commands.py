"""Tests for full HOL Guard self-uninstall flows."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import uninstall_commands
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
    assert payload["message"] == "HOL Guard removal stopped before the package uninstall command ran."
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
    assert payload["message"] == "HOL Guard removal stopped before the package uninstall command ran."
    assert payload["error"] == "bad workspace"
