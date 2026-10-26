from __future__ import annotations

import argparse
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import desktop_foreign_installs
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import desktop_converge, update_commands
from codex_plugin_scanner.guard.cli.commands_lifecycle_gate import lifecycle_gate_requirement
from codex_plugin_scanner.guard.cli.commands_parser_desktop import _configure_guard_desktop_parser
from codex_plugin_scanner.guard.cli.desktop_converge import converge_on_desktop_core, repair_hooks_then_converge
from codex_plugin_scanner.guard.desktop_foreign_installs import (
    DESKTOP_PATH_SHIM_MARKER,
    inventory_foreign_installs,
    remove_foreign_installs,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX venv and bin layout")

_ENV = ("PIPX_HOME", "PIPX_BIN_DIR", "UV_TOOL_DIR", "UV_TOOL_BIN_DIR", "XDG_BIN_HOME")


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    for name in _ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
    (home / ".local" / "bin").mkdir(parents=True)
    return home


def _launcher(home: Path) -> Path:
    launcher = home / ".local" / "share" / "org.hol.guard.desktop" / "core" / "current-hol-guard"
    launcher.parent.mkdir(parents=True)
    _ = launcher.write_text("#!/bin/sh\nexit 0\n")
    launcher.chmod(0o755)
    return launcher


def _pipx_venv(home: Path, name: str = "hol-guard") -> Path:
    venv = home / ".local" / "pipx" / "venvs" / name
    scripts = venv / "bin"
    scripts.mkdir(parents=True)
    _ = (scripts / "hol-guard").write_text(f"#!{scripts}/python\nfrom codex_plugin_scanner import main\n")
    (scripts / "hol-guard").chmod(0o755)
    runtime = venv / "lib" / "python3.12" / "site-packages" / "codex_plugin_scanner" / "guard" / "_native"
    runtime.mkdir(parents=True)
    _ = (runtime / "hol-guard-runtime").write_bytes(b"runtime")
    return venv


def _context(home: Path, tmp_path: Path) -> HarnessContext:
    return HarnessContext(home_dir=home, workspace_dir=tmp_path, guard_home=tmp_path / "guard-home")


def _converge(home: Path, tmp_path: Path, *, runtime_stops: bool = True, dry_run: bool = False) -> dict[str, object]:
    retired: list[Path] = []
    package_refreshes: list[bool] = []

    def retire(runtime: Path) -> bool:
        retired.append(runtime)
        return runtime_stops

    def refresh_package_shims() -> None:
        package_refreshes.append(True)

    payload = converge_on_desktop_core(
        _context(home, tmp_path),
        dry_run=dry_run,
        path_env=str(home / ".local" / "bin"),
        retire_runtime=retire,
        retire_daemons=lambda: None,
        refresh_package_shims=refresh_package_shims,
    )
    payload["_retired"] = retired
    payload["_package_refreshes"] = len(package_refreshes)
    return payload


def test_removes_pipx_install_and_points_path_at_desktop(home: Path, tmp_path: Path) -> None:
    launcher = _launcher(home)
    venv = _pipx_venv(home)
    sibling = _pipx_venv(home, "hol-guard-dev")
    bin_dir = home / ".local" / "bin"
    (bin_dir / "hol-guard").symlink_to(venv / "bin" / "hol-guard")
    (bin_dir / "plugin-guard").symlink_to(home / ".local" / "share" / "uv" / "tools" / "hol-guard" / "bin" / "gone")

    payload = _converge(home, tmp_path)

    assert payload["status"] == "converged", payload
    assert not venv.exists()
    assert sibling.exists()
    assert not (bin_dir / "plugin-guard").is_symlink()
    shim = (bin_dir / "hol-guard").read_text()
    assert DESKTOP_PATH_SHIM_MARKER in shim
    assert f"exec '{launcher}'" in shim
    assert payload["resolved_cli_is_desktop"] is True
    assert payload["daemon_restart_required"] is True
    assert {item["kind"] for item in payload["removed"]} == {"pipx", "stale_link"}  # pyright: ignore[reportGeneralTypeIssues]
    assert payload["_retired"] == [
        venv / "lib/python3.12/site-packages/codex_plugin_scanner/guard/_native/hol-guard-runtime"
    ]
    assert payload["_package_refreshes"] == 1


def test_keeps_install_whose_resident_will_not_stop(home: Path, tmp_path: Path) -> None:
    _ = _launcher(home)
    venv = _pipx_venv(home)
    (home / ".local" / "bin" / "hol-guard").symlink_to(venv / "bin" / "hol-guard")

    payload = _converge(home, tmp_path, runtime_stops=False)

    assert payload["status"] == "partial"
    assert venv.exists()
    assert (home / ".local" / "bin" / "hol-guard").is_symlink()
    assert payload["_package_refreshes"] == 0


def test_leaves_everything_when_desktop_has_no_core(home: Path, tmp_path: Path) -> None:
    venv = _pipx_venv(home)

    payload = _converge(home, tmp_path)

    assert payload["status"] == "skipped"
    assert venv.exists()


def test_dry_run_reports_without_removing(home: Path, tmp_path: Path) -> None:
    _ = _launcher(home)
    venv = _pipx_venv(home)

    payload = _converge(home, tmp_path, dry_run=True)

    assert payload["status"] == "planned"
    assert payload["found"] == [{"kind": "pipx", "path": str(venv)}]
    assert venv.exists()


def test_never_replaces_a_users_own_wrapper(home: Path, tmp_path: Path) -> None:
    _ = _launcher(home)
    own = home / ".local" / "bin" / "hol-guard"
    _ = own.write_text('#!/bin/sh\nexec /opt/custom/hol-guard "$@"\n')
    own.chmod(0o755)

    payload = _converge(home, tmp_path)

    assert payload["path_shim"] == {"status": "unchanged"}
    assert "/opt/custom" in own.read_text()
    assert payload["status"] == "partial"


def test_keeps_installs_when_hook_repair_reports_a_problem(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _ = _launcher(home)
    venv = _pipx_venv(home)
    monkeypatch.setattr(
        update_commands,
        "_repair_supported_harnesses_in_process",
        lambda **_: ([], ["Could not repair Codex hooks."]),
    )
    monkeypatch.setattr(
        desktop_converge,
        "converge_on_desktop_core",
        lambda context, **kwargs: converge_on_desktop_core(context, path_env=str(home / ".local" / "bin"), **kwargs),
    )

    payload, _, notes = repair_hooks_then_converge(
        _context(home, tmp_path),
        store=object(),  # pyright: ignore[reportArgumentType]
        workspace=None,
        now="2026-10-22T00:00:00Z",
    )

    assert payload["status"] == "deferred"
    assert notes == ["Could not repair Codex hooks."]
    assert venv.exists()


def test_converges_when_hook_repair_only_reports_information(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _ = _launcher(home)
    venv = _pipx_venv(home)
    note = "Refreshed the OpenCode pretool plugin during update. Restart OpenCode to load it."
    monkeypatch.setattr(update_commands, "_repair_supported_harnesses_in_process", lambda **_: ([], [note]))
    monkeypatch.setattr(
        desktop_converge,
        "converge_on_desktop_core",
        lambda context, **kwargs: converge_on_desktop_core(
            context,
            path_env=str(home / ".local" / "bin"),
            retire_runtime=lambda _: True,
            retire_daemons=lambda: None,
            refresh_package_shims=lambda: None,
            **kwargs,
        ),
    )

    payload, _, notes = repair_hooks_then_converge(
        _context(home, tmp_path),
        store=object(),  # pyright: ignore[reportArgumentType]
        workspace=None,
        now="2026-10-22T00:00:00Z",
    )

    assert payload["status"] == "converged", payload
    assert notes == [note]
    assert not venv.exists()


def test_restart_reminder_alone_reports_converged(home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    note = "Refreshed the OpenCode pretool plugin during update. Restart OpenCode to load it."
    monkeypatch.setattr(desktop_converge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        desktop_converge,
        "repair_hooks_then_converge",
        lambda *_, **__: ({"status": "converged", "notes": []}, [], [note]),
    )
    output = io.StringIO()

    exit_code = desktop_converge.run_desktop_converge(
        argparse.Namespace(dry_run=False, json=True),
        context=_context(home, tmp_path),
        store=object(),  # pyright: ignore[reportArgumentType]
        workspace=None,
        output_stream=output,
    )

    payload = json.loads(output.getvalue())
    assert (exit_code, payload["status"], payload["notes"]) == (0, "converged", [note])


def test_keeps_installs_when_the_daemon_will_not_stop(home: Path, tmp_path: Path) -> None:
    _ = _launcher(home)
    venv = _pipx_venv(home)

    def retire_daemons() -> None:
        raise RuntimeError("daemon did not exit")

    payload = converge_on_desktop_core(
        _context(home, tmp_path),
        path_env=str(home / ".local" / "bin"),
        retire_runtime=lambda _: True,
        retire_daemons=retire_daemons,
        refresh_package_shims=lambda: None,
    )

    assert payload["status"] == "partial"
    assert payload["removed"] == []
    assert venv.exists()


def test_removes_a_relative_link_left_by_a_deleted_venv(home: Path) -> None:
    link = home / ".local" / "bin" / "hol-guard"
    link.symlink_to(Path("..") / "pipx" / "venvs" / "hol-guard" / "bin" / "hol-guard")

    inventory = inventory_foreign_installs(home, path_env=str(link.parent))

    assert inventory.stale_entries == (link,)


@pytest.mark.parametrize(
    ("probe_exit", "probe_stdout", "expected_kind", "uninstalled", "script_kept"),
    [
        (0, "{user_site}", "pip_user", True, True),
        (3, "", "stale_script", False, False),
        (4, "", None, False, True),
    ],
)
def test_pip_user_removal_checks_where_hol_guard_is_installed(
    home: Path,
    tmp_path: Path,
    probe_exit: int,
    probe_stdout: str,
    expected_kind: str | None,
    uninstalled: bool,
    script_kept: bool,
) -> None:
    python = tmp_path / "system" / "bin" / "python3.12"
    python.parent.mkdir(parents=True)
    _ = python.write_text("")
    script = home / ".local" / "bin" / "hol-guard"
    _ = script.write_text(f"#!{python}\nfrom codex_plugin_scanner.cli import main\n")
    script.chmod(0o755)
    user_site = tmp_path / "user-site"
    commands: list[list[str]] = []

    def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[1] == "-c":
            return subprocess.CompletedProcess(command, probe_exit, probe_stdout.format(user_site=user_site), "")
        return subprocess.CompletedProcess(command, 0, "", "")

    inventory = inventory_foreign_installs(home, path_env=str(script.parent))
    result = remove_foreign_installs(inventory, retire_runtime=lambda _: True, run=run)

    assert inventory.user_site_interpreters == (python,)
    assert [item["kind"] for item in result.removed] == ([expected_kind] if expected_kind else [])
    assert any(command[1:3] == ["-m", "pip"] for command in commands) is uninstalled
    assert script.exists() is script_kept
    assert bool(result.notes) is (expected_kind is None)


def test_ignores_a_users_own_shell_wrapper(home: Path) -> None:
    wrapper = home / ".local" / "bin" / "hol-guard"
    _ = wrapper.write_text('#!/bin/sh\nexec python3 -m codex_plugin_scanner.cli "$@"\n')
    wrapper.chmod(0o755)

    inventory = inventory_foreign_installs(home, path_env=str(wrapper.parent))

    assert inventory.empty


def test_dry_run_works_outside_the_desktop_core(home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _ = _launcher(home)
    venv = _pipx_venv(home)
    # The preview runs from the very pipx install the Core run would remove.
    monkeypatch.setattr(desktop_foreign_installs, "_protected_roots", lambda: (venv,))
    output = io.StringIO()
    args = argparse.Namespace(dry_run=True, json=True)

    exit_code = desktop_converge.run_desktop_converge(
        args,
        context=_context(home, tmp_path),
        store=object(),  # pyright: ignore[reportArgumentType]
        workspace=None,
        output_stream=output,
    )

    payload = json.loads(output.getvalue())
    assert (exit_code, payload["status"]) == (0, "planned")
    assert {"kind": "pipx", "path": str(venv)} in payload["found"]
    assert venv.exists()


def test_converge_requires_the_update_approval_unless_dry_run() -> None:
    args = argparse.Namespace(guard_command="desktop", desktop_command="converge", dry_run=False)
    requirement = lifecycle_gate_requirement(args)
    assert requirement is not None
    assert (requirement.action, requirement.subject) == ("update", "hol-guard")
    args.dry_run = True
    assert lifecycle_gate_requirement(args) is None


def test_parser_accepts_converge() -> None:
    parser = argparse.ArgumentParser()
    _configure_guard_desktop_parser(parser.add_subparsers(dest="guard_command"))
    args = parser.parse_args(["desktop", "converge", "--json", "--dry-run"])
    assert (args.desktop_command, args.json, args.dry_run) == ("converge", True, True)
