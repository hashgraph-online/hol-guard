"""Phase 03 Guard local install, update, connect, and approval flow contracts."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import get_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.cli.approval_commands import run_approval_open_command
from codex_plugin_scanner.guard.cli.install_commands import apply_managed_install
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    workspace.mkdir(parents=True, exist_ok=True)
    return HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=guard_home)


def test_daemon_refresh_after_update_uses_fresh_interpreter(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context(tmp_path)
    context.guard_home.mkdir(parents=True)
    (context.guard_home / "daemon-state.json").write_text("{}", encoding="utf-8")

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command[-2:] == ["-c", update_commands._DAEMON_REFRESH_SCRIPT]
        assert json.loads(str(kwargs["input"])) == {"guard_home": str(context.guard_home)}
        return subprocess.CompletedProcess(command, 0, '{"status":"restarted","retired":[123]}', "")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, note = update_commands.refresh_guard_daemon_after_update(context)

    assert payload == {"status": "restarted", "retired": [123]}
    assert note == "Restarted the Guard daemon to load the updated package."


def test_daemon_refresh_after_update_skips_when_daemon_is_not_running(tmp_path: Path) -> None:
    payload, note = update_commands.refresh_guard_daemon_after_update(_context(tmp_path))

    assert payload is None
    assert note is None


def test_update_failure_redacts_output_and_returns_retry_command(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.0")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.0")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pip")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.1")
    monkeypatch.setattr(update_commands.sys, "executable", "/opt/guard/bin/python")
    monkeypatch.setattr(update_commands.sysconfig, "get_path", lambda name: "/opt/guard/bin")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/usr/local/bin/hol-guard" if name == "hol-guard" else None,
    )

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command == [
            "/opt/guard/bin/python",
            "-m",
            "pip",
            "install",
            "--upgrade",
            "--force-reinstall",
            "hol-guard==2.0.1",
        ]
        return subprocess.CompletedProcess(command, 1, "", "AUTH_TOKEN=hunter2\nnetwork unreachable")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 1
    assert payload["status"] == "failed"
    assert payload["retry_command"] == (
        "/opt/guard/bin/python -m pip install --upgrade --force-reinstall hol-guard==2.0.1"
    )
    assert "network unreachable" in str(payload["stderr"])
    assert "hunter2" not in json.dumps(payload)
    assert payload["binary_diagnostics"]["path_status"] == "path_mismatch"


def test_update_binary_diagnostics_accepts_same_environment_script(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.0")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pip")
    monkeypatch.setattr(update_commands.sys, "executable", "/opt/guard/bin/python")
    monkeypatch.setattr(update_commands.sysconfig, "get_path", lambda name: "/opt/guard/bin")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/opt/guard/bin/hol-guard" if name == "hol-guard" else None,
    )

    payload, exit_code = update_commands.run_guard_update(dry_run=True)

    assert exit_code == 0
    assert payload["binary_diagnostics"]["path_status"] == "matches_installer"
    assert payload["binary_diagnostics"]["expected_script_dir"] == "/opt/guard/bin"


def test_update_binary_diagnostics_keeps_venv_script_dir_without_resolving_python(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.0")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pip")
    monkeypatch.setattr(update_commands.sys, "executable", "/workspace/.venv/bin/python")
    monkeypatch.setattr(update_commands.sysconfig, "get_path", lambda name: "/workspace/.venv/bin")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/workspace/.venv/bin/hol-guard" if name == "hol-guard" else None,
    )

    payload, exit_code = update_commands.run_guard_update(dry_run=True)

    assert exit_code == 0
    assert payload["binary_diagnostics"]["path_status"] == "matches_installer"
    assert payload["binary_diagnostics"]["expected_script_dir"] == "/workspace/.venv/bin"


def test_update_binary_diagnostics_uses_python_scripts_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.0")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pip")
    monkeypatch.setattr(update_commands.sys, "executable", "/opt/python/bin/python")
    monkeypatch.setattr(update_commands.sysconfig, "get_path", lambda name: "/opt/python/scripts")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/opt/python/scripts/hol-guard" if name == "hol-guard" else None,
    )

    payload, exit_code = update_commands.run_guard_update(dry_run=True)

    assert exit_code == 0
    assert payload["binary_diagnostics"]["path_status"] == "matches_installer"
    assert payload["binary_diagnostics"]["expected_script_dir"] == "/opt/python/scripts"


def test_update_binary_diagnostics_treats_pipx_shim_as_healthy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.0")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/mock-home/.local/bin/hol-guard" if name == "hol-guard" else None,
    )
    monkeypatch.setattr(update_commands, "_sync_dashboard_assets", lambda: {"notes": ["synced dashboard"]})
    monkeypatch.setattr(update_commands, "_repair_supported_harnesses", lambda **_: ([], ["repaired codex hooks"]))

    payload, exit_code = update_commands.run_guard_update(dry_run=True)

    assert exit_code == 0
    assert payload["binary_diagnostics"]["path_status"] == "pipx_shim_detected"
    assert payload["binary_diagnostics"]["expected_script_dir"] is None


def test_update_uses_real_pipx_binary_when_guard_package_shims_are_installed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    manifest_path = context.guard_home / "package-shims" / "manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps({"installed_managers": ["pipx"]}), encoding="utf-8")
    shim_dir = context.guard_home / "package-shims" / "bin"
    shim_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("PATH", f"{shim_dir}{os.pathsep}/opt/homebrew/bin")
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.829")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.830")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.830")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    def fake_which(name: str, path: str | None = None) -> str | None:
        if name == "pipx" and isinstance(path, str) and "/package-shims/bin" not in path:
            return "/opt/homebrew/bin/pipx"
        if name == "hol-guard":
            return "/mock-home/.local/bin/hol-guard"
        return None

    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        fake_which,
    )
    monkeypatch.setattr(update_commands, "_sync_dashboard_assets", lambda: None)
    monkeypatch.setattr(update_commands, "_refresh_package_shims_after_update", lambda **_: (None, None))

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command == ["/opt/homebrew/bin/pipx", "install", "--force", "hol-guard==2.0.830"]
        return subprocess.CompletedProcess(command, 0, "installed hol-guard 2.0.830", "")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False, context=context)

    assert exit_code == 0
    assert payload["status"] == "updated"
    assert payload["command"] == ["pipx", "install", "--force", "hol-guard==2.0.830"]


def test_build_guard_install_surface_payload_stays_local(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/mock-home/.local/bin/hol-guard" if name == "hol-guard" else None,
    )
    monkeypatch.setattr(
        update_commands,
        "_version_check_payload",
        lambda _current_version: (_ for _ in ()).throw(AssertionError("network version check should not run")),
    )

    payload = update_commands.build_guard_install_surface_payload()

    assert payload["installer"] == "pipx"
    assert payload["binary_diagnostics"]["path_status"] == "pipx_shim_detected"


def test_version_check_reports_python_incompatible_latest_release(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.807")
    monkeypatch.setattr(update_commands, "_latest_version_python_requirements", lambda latest: (">=3.10,<3.14",))
    monkeypatch.setattr(update_commands, "_latest_compatible_release_version", lambda current, runtime: None)
    monkeypatch.setattr(update_commands, "_runtime_python_version", lambda: "3.14.0")

    payload = update_commands._version_check_payload("2.0.789")

    assert payload["status"] == "python_incompatible"
    assert payload["latest_version"] == "2.0.807"
    assert payload["update_available"] is True
    assert payload["required_python"] == ">=3.10,<3.14"
    assert payload["runtime_python"] == "3.14.0"


def test_latest_version_python_requirements_uses_all_non_yanked_files(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        update_commands,
        "_last_pypi_payload",
        {
            "info": {"version": "2.0.807", "requires_python": ">=3.10"},
            "releases": {
                "2.0.807": [
                    {"requires_python": ">=3.10,<3.14", "yanked": "bad wheel"},
                    {"requires_python": ">=3.10,<3.14", "yanked": False},
                    {"yanked": False},
                    {"requires_python": ">=3.11,<3.15", "yanked": False},
                ],
            },
        },
    )

    assert update_commands._latest_version_python_requirements("2.0.807") == (
        ">=3.10,<3.14",
        ">=3.11,<3.15",
    )
    assert update_commands._python_requirements_satisfied((">=3.10,<3.14", ">=3.11,<3.15"), "3.14.0")


def test_version_check_targets_newer_compatible_release_when_pypi_latest_is_incompatible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.900")
    monkeypatch.setattr(
        update_commands,
        "_last_pypi_payload",
        {
            "info": {"version": "2.0.900", "requires_python": ">=3.10,<3.14"},
            "releases": {
                "2.0.765": [{"requires_python": ">=3.10", "yanked": True}],
                "2.0.800": [{"requires_python": ">=3.10", "yanked": False}],
                "2.0.900": [{"requires_python": ">=3.10,<3.14", "yanked": False}],
            },
        },
    )
    monkeypatch.setattr(update_commands, "_runtime_python_version", lambda: "3.14.0")

    payload = update_commands._version_check_payload("2.0.764")

    assert payload["status"] == "stale"
    assert payload["latest_version"] == "2.0.800"
    assert payload["update_available"] is True
    assert payload["pypi_latest_version"] == "2.0.900"
    assert payload["pypi_latest_python_incompatible"] is True


def test_update_blocks_python_incompatible_latest_release(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.789")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.807")
    monkeypatch.setattr(update_commands, "_latest_version_python_requirements", lambda latest: (">=3.10,<3.14",))
    monkeypatch.setattr(update_commands, "_latest_compatible_release_version", lambda current, runtime: None)
    monkeypatch.setattr(update_commands, "_runtime_python_version", lambda: "3.14.0")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise AssertionError(f"update should be blocked before running {command}")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 1
    assert payload["status"] == "blocked"
    assert payload["changed"] is False
    assert payload["python_update_required"] is True
    assert "requires Python >=3.10,<3.14" in str(payload["message"])
    assert "running Python 3.14.0" in str(payload["message"])
    assert "retry_command" not in payload


def test_update_requested_local_wheel_bypasses_python_incompatible_latest_release(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "hol_guard-2.0.790-py3-none-any.whl"
    wheel.write_bytes(b"fake-wheel")
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.789")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.790")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.807")
    monkeypatch.setattr(update_commands, "_latest_version_python_requirements", lambda latest: (">=3.10,<3.14",))
    monkeypatch.setattr(update_commands, "_latest_compatible_release_version", lambda current, runtime: None)
    monkeypatch.setattr(update_commands, "_runtime_python_version", lambda: "3.14.0")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    captured_commands: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured_commands.append(command)
        return subprocess.CompletedProcess(command, 0, "reinstalled hol-guard 2.0.790", "")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False, wheel=str(wheel))

    assert exit_code == 0
    assert captured_commands == [["pipx", "runpip", "hol-guard", "install", "--force-reinstall", str(wheel)]]
    assert payload["status"] == "updated"
    assert payload["upgrade_source"] == "local_wheel"
    assert payload["requested_wheel"] == str(wheel)
    assert payload["version_check"]["latest_version"] == "2.0.807"
    assert payload["version_check"]["status"] == "python_incompatible"
    assert payload["version_check"]["required_python"] == ">=3.10,<3.14"
    assert payload["version_check"]["runtime_python"] == "3.14.0"
    assert "python_update_required" not in payload


def test_update_skips_existing_local_source_install(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source_dir = tmp_path / "src-install"
    source_dir.mkdir()
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.345")
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {"dir_info": {}, "url": source_dir.as_uri()},
    )
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/mock-home/.local/bin/hol-guard" if name == "hol-guard" else None,
    )

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 0
    assert payload["status"] == "skipped"
    assert payload["changed"] is False
    assert "disabled for local source installs" in str(payload["error"])
    assert payload["source_install"]["path_exists"] is True
    assert "version_check" not in payload


def test_update_repairs_missing_pipx_local_source_install(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    missing_dir = tmp_path / "missing-src-install"
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.489")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.489")
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {"dir_info": {}, "url": missing_dir.as_uri()},
    )
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/mock-home/.local/bin/hol-guard" if name == "hol-guard" else None,
    )

    captured_commands: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured_commands.append(command)
        return subprocess.CompletedProcess(command, 0, "installed hol-guard", "")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 0
    assert captured_commands[0] == ["pipx", "install", "--force", "hol-guard==2.0.489"]
    assert payload["recovery_source_install"] is True
    assert payload["source_install"]["path_exists"] is False
    assert payload["status"] == "updated"
    assert payload["message"] == "Updated HOL Guard from 2.0.345 to 2.0.489."


def test_update_treats_nonzero_pipx_repair_as_updated_when_version_changed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    missing_dir = tmp_path / "missing-src-install"
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.628")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.628")
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {"dir_info": {}, "url": missing_dir.as_uri()},
    )
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/mock-home/.local/bin/hol-guard" if name == "hol-guard" else None,
    )
    monkeypatch.setattr(update_commands, "_sync_dashboard_assets", lambda: {"notes": ["synced dashboard"]})

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command == ["pipx", "install", "--force", "hol-guard==2.0.628"]
        return subprocess.CompletedProcess(
            command,
            1,
            "hol-guard 2.0.628 installed",
            "TypeError: expected string or bytes-like object, got 'NoneType'",
        )

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 0
    assert payload["status"] == "updated"
    assert payload["changed"] is True
    assert payload["resulting_version"] == "2.0.628"
    assert payload["message"] == "Updated HOL Guard from 2.0.345 to 2.0.628."
    assert "dashboard_sync" in payload
    notes = payload.get("notes")
    assert isinstance(notes, list)
    assert any("Installer exited with code 1 after version changed." in str(note) for note in notes)


def test_update_repairs_missing_pip_local_source_install(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    missing_dir = tmp_path / "missing-src-install"
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.489")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.489")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.489")
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {"dir_info": {}, "url": missing_dir.as_uri()},
    )
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pip")
    monkeypatch.setattr(update_commands.sys, "executable", "/opt/guard/bin/python")

    captured_commands: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured_commands.append(command)
        return subprocess.CompletedProcess(command, 0, "installed hol-guard", "")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 0
    assert captured_commands[0] == [
        "/opt/guard/bin/python",
        "-m",
        "pip",
        "install",
        "--upgrade",
        "--force-reinstall",
        "hol-guard",
    ]
    assert payload["recovery_source_install"] is True
    assert payload["upgrade_source"] == "pypi"


def test_update_skips_pypi_recovery_when_missing_local_source_is_newer_than_pypi(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    missing_dir = tmp_path / "missing-dev-install"
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.1.0.dev0")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.489")
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {"dir_info": {}, "url": missing_dir.as_uri()},
    )
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    payload, exit_code = update_commands.run_guard_update(dry_run=True)

    assert exit_code == 0
    assert payload["command"] == ["pipx", "upgrade", "hol-guard"]
    assert payload.get("upgrade_source") is None


def test_update_skips_existing_local_wheel_install(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    wheel = tmp_path / "hol-guard.whl"
    wheel.write_bytes(b"fake-wheel")
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.345")
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {
            "url": wheel.as_uri(),
            "archive_info": {"hash": "sha256:abc", "hashes": {"sha256": "abc"}},
        },
    )
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    payload, exit_code = update_commands.run_guard_update(dry_run=True)

    assert exit_code == 0
    assert payload["status"] == "skipped"
    assert payload["archive_install"]["archive_type"] == "wheel"
    assert payload["archive_install"]["path_exists"] is True
    assert "disabled for local wheel installs" in str(payload["error"])


def test_update_installs_requested_local_wheel_with_pipx(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    wheel = tmp_path / "hol_guard-2.0.345-py3-none-any.whl"
    wheel.write_bytes(b"fake-wheel")
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.344")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    captured_commands: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured_commands.append(command)
        return subprocess.CompletedProcess(command, 0, "reinstalled hol-guard 2.0.345", "")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False, wheel=str(wheel))

    assert exit_code == 0
    assert captured_commands == [["pipx", "runpip", "hol-guard", "install", "--force-reinstall", str(wheel)]]
    assert payload["upgrade_source"] == "local_wheel"
    assert payload["requested_wheel"] == str(wheel)
    assert payload["resulting_version"] == "2.0.345"


def test_update_requested_local_wheel_does_not_report_stale_against_pypi(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "hol_guard-2.0.500-py3-none-any.whl"
    wheel.write_bytes(b"fake-wheel")
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.499")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.500")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.600")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "reinstalled hol-guard 2.0.500", "")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False, wheel=str(wheel))

    assert exit_code == 0
    assert payload["status"] == "updated"
    assert payload["upgrade_source"] == "local_wheel"
    assert "retry_command" not in payload or "pipx install --force hol-guard" not in str(payload.get("retry_command"))


def test_update_requested_same_version_local_wheel_reports_current(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "hol_guard-2.0.500-py3-none-any.whl"
    wheel.write_bytes(b"fake-wheel")
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.500")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.500")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.600")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "reinstalled hol-guard 2.0.500", "")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False, wheel=str(wheel))

    assert exit_code == 0
    assert payload["status"] == "current"
    assert payload["changed"] is False
    assert payload["upgrade_source"] == "local_wheel"


def test_update_installs_requested_local_wheel_from_editable_install(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "hol_guard-2.0.345-py3-none-any.whl"
    wheel.write_bytes(b"fake-wheel")
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.344")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.345")
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {"dir_info": {"editable": True}, "url": "file:///mock-workspace/hol-guard"},
    )
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    captured_commands: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured_commands.append(command)
        return subprocess.CompletedProcess(command, 0, "reinstalled hol-guard 2.0.345", "")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False, wheel=str(wheel))

    assert exit_code == 0
    assert captured_commands == [["pipx", "runpip", "hol-guard", "install", "--force-reinstall", str(wheel)]]
    assert payload["upgrade_source"] == "local_wheel"


def test_update_resolves_requested_wheel_from_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()
    older_wheel = dist_dir / "hol_guard-2.0.344-py3-none-any.whl"
    older_wheel.write_bytes(b"older-wheel")
    newer_wheel = dist_dir / "hol_guard-2.0.345-py3-none-any.whl"
    newer_wheel.write_bytes(b"newer-wheel")
    os.utime(older_wheel, (100, 100))
    os.utime(newer_wheel, (200, 200))
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.344")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    payload, exit_code = update_commands.run_guard_update(dry_run=True, wheel=str(dist_dir))

    assert exit_code == 0
    assert payload["status"] == "planned"
    assert payload["requested_wheel"] == str(newer_wheel)
    assert payload["command"] == [
        "pipx",
        "runpip",
        "hol-guard",
        "install",
        "--force-reinstall",
        str(newer_wheel),
    ]
    assert payload["message"] == "Review the planned local wheel install command before updating."


def test_update_resolves_requested_wheel_from_directory_by_version_first(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()
    newer_version = dist_dir / "hol_guard-2.0.345-py3-none-any.whl"
    newer_version.write_bytes(b"newer-version")
    older_version = dist_dir / "hol_guard-2.0.344-py3-none-any.whl"
    older_version.write_bytes(b"older-version")
    os.utime(newer_version, (100, 100))
    os.utime(older_version, (200, 200))
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.344")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    payload, exit_code = update_commands.run_guard_update(dry_run=True, wheel=str(dist_dir))

    assert exit_code == 0
    assert payload["requested_wheel"] == str(newer_version)


def test_update_rejects_missing_wheel_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.344")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    payload, exit_code = update_commands.run_guard_update(dry_run=True, wheel=str(tmp_path / "missing-dist"))

    assert exit_code == 1
    assert payload["status"] == "failed"
    assert "Directory of wheels not found" in str(payload["error"])


def test_update_rejects_unresolvable_requested_wheel_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "hol_guard-2.0.345-py3-none-any.whl"
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.344")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    original_resolve = Path.resolve

    def fake_resolve(self: Path, strict: bool = False) -> Path:
        if self == wheel:
            raise RuntimeError("symlink loop from test wheel")
        return original_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", fake_resolve)

    payload, exit_code = update_commands.run_guard_update(dry_run=True, wheel=str(wheel))

    assert exit_code == 1
    assert payload["status"] == "failed"
    assert "Could not resolve HOL Guard wheel path" in str(payload["error"])
    assert "symlink loop" in str(payload["error"]).lower()


def test_update_rejects_unreadable_wheel_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.344")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    original_iterdir = Path.iterdir

    def fake_iterdir(self: Path):
        if self == dist_dir:
            raise PermissionError("permission denied")
        return original_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", fake_iterdir)

    payload, exit_code = update_commands.run_guard_update(dry_run=True, wheel=str(dist_dir))

    assert exit_code == 1
    assert payload["status"] == "failed"
    assert "Could not read HOL Guard wheel directory" in str(payload["error"])
    assert "permission denied" in str(payload["error"]).lower()


def test_update_rejects_non_hol_guard_wheel(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    wheel = tmp_path / "some_dependency-1.0.0-py3-none-any.whl"
    wheel.write_bytes(b"not-hol-guard")
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.344")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    payload, exit_code = update_commands.run_guard_update(dry_run=True, wheel=str(wheel))

    assert exit_code == 1
    assert payload["status"] == "failed"
    assert "Expected a HOL Guard wheel file" in str(payload["error"])


def test_update_rejects_non_regular_hol_guard_wheel_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    wheel = tmp_path / "hol_guard-2.0.345-py3-none-any.whl"
    wheel.write_bytes(b"not-a-regular-wheel")
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.344")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    original_is_file = Path.is_file

    def fake_is_file(self: Path) -> bool:
        if self == wheel:
            return False
        return original_is_file(self)

    monkeypatch.setattr(Path, "is_file", fake_is_file)

    payload, exit_code = update_commands.run_guard_update(dry_run=True, wheel=str(wheel))

    assert exit_code == 1
    assert payload["status"] == "failed"
    assert "Expected a HOL Guard wheel file" in str(payload["error"])


def test_update_accepts_uppercase_hol_guard_wheel(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    wheel = tmp_path / "hol_guard-2.0.345-py3-none-any.WHL"
    wheel.write_bytes(b"uppercase-wheel")
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.344")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    payload, exit_code = update_commands.run_guard_update(dry_run=True, wheel=str(wheel))

    assert exit_code == 0
    assert payload["status"] == "planned"
    assert payload["requested_wheel"] == str(wheel)


def test_update_resolves_uppercase_hol_guard_wheel_from_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()
    wheel = dist_dir / "hol_guard-2.0.345-py3-none-any.WHL"
    wheel.write_bytes(b"uppercase-wheel")
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.344")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    payload, exit_code = update_commands.run_guard_update(dry_run=True, wheel=str(dist_dir))

    assert exit_code == 0
    assert payload["requested_wheel"] == str(wheel)


def test_update_does_not_skip_existing_local_non_wheel_archive(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    archive = tmp_path / "hol_guard-2.0.345.tar.gz"
    archive.write_bytes(b"fake-archive")
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.345")
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {
            "url": archive.as_uri(),
            "archive_info": {"hash": "sha256:abc", "hashes": {"sha256": "abc"}},
        },
    )
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    payload, exit_code = update_commands.run_guard_update(dry_run=True)

    assert exit_code == 0
    assert payload["status"] == "planned"
    assert payload["archive_install"]["archive_type"] == "archive"


def test_update_skips_missing_local_wheel_until_new_wheel_is_supplied(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    missing_wheel = tmp_path / "dist" / "hol_guard-2.0.345-py3-none-any.whl"
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.400")
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {
            "url": missing_wheel.as_uri(),
            "archive_info": {"hash": "sha256:abc", "hashes": {"sha256": "abc"}},
        },
    )
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    payload, exit_code = update_commands.run_guard_update(dry_run=True)

    assert exit_code == 0
    assert payload["status"] == "skipped"
    assert "original wheel file is gone" in str(payload["error"])
    assert "hol-guard update --wheel <wheel-or-directory>" in str(payload["error"])


def test_update_status_handles_unresolvable_local_wheel_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "hol_guard-2.0.345-py3-none-any.whl"
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.345")
    monkeypatch.setattr(
        update_commands,
        "build_guard_install_surface_payload",
        lambda: {"installer": "pipx", "binary_diagnostics": {}},
    )
    monkeypatch.setattr(
        update_commands,
        "_version_check_payload",
        lambda current_version: {
            "source": "pypi",
            "status": "current",
            "current_version": current_version,
            "latest_version": current_version,
            "update_available": False,
        },
    )
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {
            "url": wheel.as_uri(),
            "archive_info": {"hash": "sha256:abc"},
        },
    )

    original_resolve = Path.resolve

    def fake_resolve(self: Path, strict: bool = False) -> Path:
        if self == wheel:
            raise RuntimeError("symlink loop from test wheel")
        return original_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", fake_resolve)

    payload = update_commands.build_guard_update_status_payload()

    assert payload["auto_updatable"] is False
    assert payload["recovery_reinstall_available"] is True
    assert "local wheel whose source file is no longer available" in str(payload["blocked_reason"])


def test_local_archive_install_payload_preserves_file_url_authority() -> None:
    payload = update_commands._local_archive_install_payload(
        {
            "url": "file://server/share/hol_guard-2.0.345-py3-none-any.whl",
            "archive_info": {"hash": "sha256:abc"},
        }
    )

    assert payload is not None
    assert payload["path_exists"] is False
    assert "server" in str(payload["path"])
    assert "share" in str(payload["path"])


def test_update_marks_partial_pypi_repair_as_stale(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.400")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.489")
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {
            "url": "https://github.com/hashgraph-online/hol-guard.git",
            "vcs_info": {
                "commit_id": "ea81cb21edf6fbf2c83658299a81043e9fe37c57",
                "requested_revision": "main",
                "vcs": "git",
            },
        },
    )
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "installed hol-guard 2.0.400", "")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 0
    assert payload["status"] == "stale"
    assert payload["changed"] is True
    assert payload["resulting_version"] == "2.0.400"
    assert "behind PyPI 2.0.489" in str(payload["message"])


def test_update_syncs_dashboard_assets_after_partial_stale_upgrade(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.400")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.489")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/mock-home/.local/bin/hol-guard" if name == "hol-guard" else None,
    )
    monkeypatch.setattr(update_commands, "_sync_dashboard_assets", lambda: {"notes": ["synced dashboard"]})

    captured_commands: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured_commands.append(command)
        return subprocess.CompletedProcess(command, 0, "installed hol-guard 2.0.400", "")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 0
    assert captured_commands == [["pipx", "install", "--force", "hol-guard==2.0.489"]]
    assert payload["status"] == "stale"
    assert payload["changed"] is True
    assert payload["dashboard_sync"] == {"notes": ["synced dashboard"]}
    assert "synced dashboard" in payload["notes"]


def test_refresh_package_shims_after_update_uses_fresh_python_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    manifest_path = context.guard_home / "package-shims" / "manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps({"installed_managers": ["pnpm"]}), encoding="utf-8")

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command == [
            update_commands.sys.executable,
            *update_commands._trusted_python_flags(),
            "-c",
            update_commands._PACKAGE_SHIM_REFRESH_SCRIPT,
        ]
        refresh_context = json.loads(str(kwargs.get("input")))
        assert refresh_context == {
            "home_dir": str(context.home_dir),
            "workspace_dir": str(context.workspace_dir),
            "guard_home": str(context.guard_home),
        }
        assert kwargs.get("cwd") == str(update_commands._trusted_import_root())
        refresh_env = kwargs.get("env")
        assert isinstance(refresh_env, dict)
        assert "PYTHONPATH" not in refresh_env
        assert kwargs.get("timeout") == update_commands._PACKAGE_SHIM_REFRESH_TIMEOUT_SECONDS
        refresh_payload = {
            "before": {"installed_managers": ["pnpm"]},
            "repair": {"repaired": ["pnpm"], "repaired_count": 1},
            "after": {
                "installed_managers": ["pnpm"],
                "manager_details": [{"manager": "pnpm", "integrity": "ok"}],
                "path_repair_required": [],
            },
        }
        return subprocess.CompletedProcess(command, 0, json.dumps(refresh_payload), "")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, note = update_commands._refresh_package_shims_after_update(context=context, dry_run=False)

    assert payload is not None
    assert payload["repair"] == {"repaired": ["pnpm"], "repaired_count": 1}
    assert note == "Refreshed package firewall shims during update for pnpm."


def test_update_records_package_shim_refresh_after_successful_update(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.826")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.830")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.830")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/mock-home/.local/bin/hol-guard" if name == "hol-guard" else None,
    )
    monkeypatch.setattr(update_commands, "_sync_dashboard_assets", lambda: None)
    monkeypatch.setattr(
        update_commands,
        "_refresh_package_shims_after_update",
        lambda **_: (
            {
                "before": {"installed_managers": ["pnpm"]},
                "repair": {"repaired": ["pnpm"], "repaired_count": 1},
                "after": {
                    "installed_managers": ["pnpm"],
                    "manager_details": [{"manager": "pnpm", "integrity": "ok"}],
                    "path_repair_required": [],
                },
            },
            "Refreshed package firewall shims during update for pnpm.",
        ),
    )

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command == ["pipx", "install", "--force", "hol-guard==2.0.830"]
        return subprocess.CompletedProcess(command, 0, "installed hol-guard 2.0.830", "")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False, context=_context(tmp_path))

    assert exit_code == 0
    assert payload["status"] == "updated"
    assert payload["package_shims"]["repair"] == {"repaired": ["pnpm"], "repaired_count": 1}
    assert "Refreshed package firewall shims during update for pnpm." in payload["notes"]


def test_update_keeps_success_when_package_shim_refresh_warns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.826")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.830")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.830")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/mock-home/.local/bin/hol-guard" if name == "hol-guard" else None,
    )
    monkeypatch.setattr(update_commands, "_sync_dashboard_assets", lambda: None)
    monkeypatch.setattr(
        update_commands,
        "_refresh_package_shims_after_update",
        lambda **_: (None, "Could not refresh package firewall shims during update: import failed"),
    )

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command == ["pipx", "install", "--force", "hol-guard==2.0.830"]
        return subprocess.CompletedProcess(command, 0, "installed hol-guard 2.0.830", "")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False, context=_context(tmp_path))

    assert exit_code == 0
    assert payload["status"] == "updated"
    assert "Could not refresh package firewall shims during update: import failed" in payload["notes"]


def test_update_skips_package_shim_refresh_for_stale_no_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.584")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.584")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.585")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/mock-home/.local/bin/hol-guard" if name == "hol-guard" else None,
    )
    monkeypatch.setattr(update_commands, "_sync_dashboard_assets", lambda: None)

    refresh_attempted = False

    def fake_refresh(**_: object) -> tuple[dict[str, object] | None, str | None]:
        nonlocal refresh_attempted
        refresh_attempted = True
        return None, None

    monkeypatch.setattr(update_commands, "_refresh_package_shims_after_update", fake_refresh)

    captured_commands: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured_commands.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            "hol-guard is already at latest version 2.0.584",
            "upgrading shared libraries...\nupgrading hol-guard...\n",
        )

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 0
    assert captured_commands == [["pipx", "install", "--force", "hol-guard==2.0.585"]]
    assert payload["status"] == "stale"
    assert refresh_attempted is False


def test_update_marks_pinned_pipx_install_as_stale_when_version_does_not_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.584")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.584")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.585")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/mock-home/.local/bin/hol-guard" if name == "hol-guard" else None,
    )

    captured_commands: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured_commands.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            "hol-guard is already at latest version 2.0.584",
            "upgrading shared libraries...\nupgrading hol-guard...\n",
        )

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 0
    assert captured_commands == [["pipx", "install", "--force", "hol-guard==2.0.585"]]
    assert payload["status"] == "stale"
    assert payload["changed"] is False
    assert payload["resulting_version"] == "2.0.584"
    assert payload["retry_command"] == "pipx install --force hol-guard==2.0.585"
    assert "behind PyPI 2.0.585 after the update attempt" in str(payload["message"])


def test_update_reports_blocked_when_force_install_hits_dependency_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.741")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.741")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.749")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/mock-home/.local/bin/hol-guard" if name == "hol-guard" else None,
    )

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command == ["pipx", "install", "--force", "hol-guard==2.0.749"]
        return subprocess.CompletedProcess(
            command,
            1,
            "",
            "ERROR: ResolutionImpossible: hol-guard 2.0.749 depends on rich>=15.0.0; "
            "cisco-ai-skill-scanner 2.0.11 depends on rich<15,>=14.0",
        )

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 1
    assert payload["status"] == "blocked"
    assert payload["dependency_conflict"] is True
    assert "incompatible rich versions" in str(payload["message"]).lower()
    assert "retry_command" not in payload


def test_update_installs_detected_pipx_release_directly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.584")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.585")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/mock-home/.local/bin/hol-guard" if name == "hol-guard" else None,
    )

    captured_commands: list[list[str]] = []
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.585")

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured_commands.append(command)
        assert command == ["pipx", "install", "--force", "hol-guard==2.0.585"]
        return subprocess.CompletedProcess(command, 0, "installed hol-guard 2.0.585", "")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 0
    assert captured_commands == [["pipx", "install", "--force", "hol-guard==2.0.585"]]
    assert payload["status"] == "updated"
    assert payload["resulting_version"] == "2.0.585"


def test_update_switches_git_install_to_pypi_when_release_is_newer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.489")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.489")
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {
            "url": "https://github.com/hashgraph-online/hol-guard.git",
            "vcs_info": {
                "commit_id": "ea81cb21edf6fbf2c83658299a81043e9fe37c57",
                "requested_revision": "main",
                "vcs": "git",
            },
        },
    )
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/Users/test/.local/bin/hol-guard" if name == "hol-guard" else None,
    )

    captured_commands: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured_commands.append(command)
        return subprocess.CompletedProcess(command, 0, "installed hol-guard 2.0.489", "")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 0
    assert captured_commands[0] == ["pipx", "install", "--force", "hol-guard==2.0.489"]
    assert payload["upgrade_source"] == "pypi"
    assert payload["status"] == "updated"
    assert payload["message"] == "Updated HOL Guard from 2.0.345 to 2.0.489."


def test_update_marks_git_install_stale_when_pypi_upgrade_leaves_old_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.489")
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {
            "url": "https://github.com/hashgraph-online/hol-guard.git",
            "vcs_info": {
                "commit_id": "ea81cb21edf6fbf2c83658299a81043e9fe37c57",
                "requested_revision": "main",
                "vcs": "git",
            },
        },
    )
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    captured_commands: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured_commands.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            "hol-guard is already at latest version 2.0.345",
            "upgrading hol-guard from spec 'git+https://github.com/hashgraph-online/hol-guard.git@main'...",
        )

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 0
    assert captured_commands[0] == ["pipx", "install", "--force", "hol-guard==2.0.489"]
    assert payload["status"] == "stale"
    assert "behind PyPI 2.0.489" in str(payload["message"])
    assert "pipx install --force hol-guard" in str(payload["message"])


def test_update_reports_current_after_successful_pypi_repair_when_post_check_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.345")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda: "2.0.489")
    call_count = {"count": 0}

    def fake_latest() -> str | None:
        call_count["count"] += 1
        return "2.0.489" if call_count["count"] == 1 else None

    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", fake_latest)
    monkeypatch.setattr(
        update_commands,
        "_direct_url_payload",
        lambda: {
            "url": "https://github.com/hashgraph-online/hol-guard.git",
            "vcs_info": {"vcs": "git", "requested_revision": "main", "commit_id": "abc"},
        },
    )
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "installed hol-guard 2.0.489", "")

    monkeypatch.setattr(update_commands.subprocess, "run", fake_run)

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 0
    assert payload["status"] == "updated"
    assert payload["message"] == "Updated HOL Guard from 2.0.345 to 2.0.489."


def test_install_aliases_resolve_to_native_contracts() -> None:
    aliases = {
        "claude": "claude-code",
        "claude-code": "claude-code",
        "codex": "codex",
        "opencode": "opencode",
        "copilot": "copilot",
        "cursor": "cursor",
        "gemini": "gemini",
    }

    for alias, canonical in aliases.items():
        adapter = get_adapter(alias)
        contract = adapter.setup_contract()
        assert adapter.harness == canonical
        assert alias in contract.install_aliases
        assert contract.coverage.browser_fallback is True
        assert contract.coverage.native_hooks == (canonical in {"claude-code", "codex", "copilot"})


def test_managed_install_is_idempotent_and_uninstall_tracks_guard_owned_state(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)

    first = apply_managed_install(
        "install", "opencode", False, context, store, str(context.workspace_dir), "2026-05-12T00:00:00Z"
    )
    second = apply_managed_install(
        "install", "opencode", False, context, store, str(context.workspace_dir), "2026-05-12T00:00:01Z"
    )
    removed = apply_managed_install(
        "uninstall",
        "opencode",
        False,
        context,
        store,
        str(context.workspace_dir),
        "2026-05-12T00:00:02Z",
    )

    assert first["managed_install"]["harness"] == "opencode"
    assert second["managed_install"]["config_path"] == first["managed_install"]["config_path"]
    assert removed["managed_install"]["active"] is False
    assert store.get_managed_install("opencode")["active"] is False


def test_approval_open_repairs_stale_local_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = GuardApprovalRequest(
        request_id="request-1",
        harness="codex",
        artifact_id="artifact-1",
        artifact_name="Tool",
        artifact_hash="hash",
        policy_action="block",
        recommended_scope="artifact",
        changed_fields=(),
        source_scope="local",
        config_path="config.toml",
        review_command="hol-guard approvals approve request-1",
        approval_url="http://127.0.0.1:4000/approvals/request-1",
    )
    store.add_approval_request(request, "2026-05-12T00:00:00Z")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.approval_commands.load_guard_daemon_url",
        lambda guard_home: "http://127.0.0.1:4781",
    )

    payload, exit_code = run_approval_open_command(argparse.Namespace(request_id="request-1"), store=store)

    assert exit_code == 0
    assert payload["approval_url"] == "http://127.0.0.1:4781/approvals/request-1"
    assert payload["repaired"] is True


def test_approval_open_repairs_ipv6_local_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = GuardApprovalRequest(
        request_id="request-ipv6",
        harness="codex",
        artifact_id="artifact-1",
        artifact_name="Tool",
        artifact_hash="hash",
        policy_action="block",
        recommended_scope="artifact",
        changed_fields=(),
        source_scope="local",
        config_path="config.toml",
        review_command="hol-guard approvals approve request-ipv6",
        approval_url="http://[::1]:4000/approvals/request-ipv6",
    )
    store.add_approval_request(request, "2026-05-12T00:00:00Z")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.approval_commands.load_guard_daemon_url",
        lambda guard_home: "http://127.0.0.1:4781",
    )

    payload, exit_code = run_approval_open_command(argparse.Namespace(request_id="request-ipv6"), store=store)

    assert exit_code == 0
    assert payload["approval_url"] == "http://127.0.0.1:4781/approvals/request-ipv6"
    assert payload["repaired"] is True


def test_approval_open_preserves_malformed_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = GuardApprovalRequest(
        request_id="request-bad-url",
        harness="codex",
        artifact_id="artifact-1",
        artifact_name="Tool",
        artifact_hash="hash",
        policy_action="block",
        recommended_scope="artifact",
        changed_fields=(),
        source_scope="local",
        config_path="config.toml",
        review_command="hol-guard approvals approve request-bad-url",
        approval_url="http://[::1:4000/approvals/request-bad-url",
    )
    store.add_approval_request(request, "2026-05-12T00:00:00Z")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.approval_commands.load_guard_daemon_url",
        lambda guard_home: "http://127.0.0.1:4781",
    )

    payload, exit_code = run_approval_open_command(argparse.Namespace(request_id="request-bad-url"), store=store)

    assert exit_code == 0
    assert payload["approval_url"] == "http://[::1:4000/approvals/request-bad-url"
    assert payload["repaired"] is False
