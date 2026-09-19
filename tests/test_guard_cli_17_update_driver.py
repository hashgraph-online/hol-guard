"""Guard CLI update driver behavior."""

from __future__ import annotations

import json
import subprocess

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.cli import update_commands as guard_update_commands_module
from tests.guard_cli_fixture_support import _write_text
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_update_runs_pip_upgrade_in_current_environment(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        commands: list[list[str]] = []

        def fake_run(command: list[str], **_: object):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, stdout="updated", stderr="")

        monkeypatch.setattr(guard_update_commands_module.subprocess, "run", fake_run)
        monkeypatch.setattr(guard_update_commands_module.sys, "prefix", "/opt/guard-venv")
        monkeypatch.setattr(guard_update_commands_module.sys, "executable", "/opt/guard-venv/bin/python")
        monkeypatch.setattr(guard_update_commands_module, "_direct_url_payload", lambda: None)
        monkeypatch.setattr(guard_update_commands_module, "_current_version", lambda: "2.0.18")
        monkeypatch.setattr(
            guard_update_commands_module, "_current_version_from_subprocess", lambda *_args, **_kwargs: "2.0.18"
        )
        monkeypatch.setattr(guard_update_commands_module, "_latest_version_from_pypi", lambda: "2.0.18")

        rc = main(["guard", "update", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["installer"] == "pip"
        assert commands == []
        assert output["status"] == "current"
        assert output["changed"] is False
        assert output["message"] == "HOL Guard is already current."

    def test_guard_update_uses_pipx_when_running_from_pipx(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        commands: list[list[str]] = []

        def fake_run(command: list[str], **_: object):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, stdout="pipx-updated", stderr="")

        monkeypatch.setattr(guard_update_commands_module.subprocess, "run", fake_run)
        monkeypatch.setattr(guard_update_commands_module.sys, "prefix", "/mock-home/.local/pipx/venvs/hol-guard")
        monkeypatch.setattr(guard_update_commands_module, "_direct_url_payload", lambda: None)
        monkeypatch.setattr(guard_update_commands_module, "_current_version", lambda: "2.0.18")
        monkeypatch.setattr(
            guard_update_commands_module, "_current_version_from_subprocess", lambda *_args, **_kwargs: "2.0.18"
        )
        monkeypatch.setattr(guard_update_commands_module, "_latest_version_from_pypi", lambda: "2.0.18")

        rc = main(["guard", "update", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["installer"] == "pipx"
        assert commands == []
        assert output["status"] == "current"
        assert output["changed"] is False
        assert output["message"] == "HOL Guard is already current."

    def test_guard_update_pins_detected_stable_release_from_uv_canary(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        commands: list[list[str]] = []

        def fake_run(command: list[str], **_: object):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, stdout="updated", stderr="")

        monkeypatch.setattr(guard_update_commands_module.subprocess, "run", fake_run)
        monkeypatch.setattr(guard_update_commands_module.sys, "prefix", "/mock-home/.local/share/uv/tools/hol-guard")
        monkeypatch.setattr(guard_update_commands_module, "_direct_url_payload", lambda: None)
        monkeypatch.setattr(guard_update_commands_module, "_current_version", lambda: "2.0.1091.dev10044056673277")
        monkeypatch.setattr(
            guard_update_commands_module, "_current_version_from_subprocess", lambda *_args, **_kwargs: "2.0.1092"
        )
        monkeypatch.setattr(guard_update_commands_module, "_latest_version_from_pypi", lambda: "2.0.1092")

        rc = main(["guard", "update", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["installer"] == "uv"
        assert commands == [
            [
                "uv",
                "tool",
                "install",
                "--force",
                "--refresh-package",
                "hol-guard",
                "hol-guard==2.0.1092",
            ]
        ]
        assert output["resulting_version"] == "2.0.1092"
        assert output["status"] == "updated"

    def test_guard_update_marks_already_current_pipx_runs_as_current(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        commands: list[list[str]] = []

        def fake_run(command: list[str], **_: object):
            commands.append(command)
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=(
                    "hol-guard is already at latest version 2.0.36 "
                    "(location: /tmp/hol-guard-user/.local/pipx/venvs/hol-guard)"
                ),
                stderr="upgrading shared libraries...\nupgrading hol-guard...\n",
            )

        monkeypatch.setattr(guard_update_commands_module.subprocess, "run", fake_run)
        monkeypatch.setattr(guard_update_commands_module.sys, "prefix", "/mock-home/.local/pipx/venvs/hol-guard")
        monkeypatch.setattr(guard_update_commands_module, "_direct_url_payload", lambda: None)
        monkeypatch.setattr(guard_update_commands_module, "_current_version", lambda: "2.0.36")
        monkeypatch.setattr(
            guard_update_commands_module, "_current_version_from_subprocess", lambda *_args, **_kwargs: "2.0.36"
        )
        monkeypatch.setattr(guard_update_commands_module, "_latest_version_from_pypi", lambda: "2.0.36")

        rc = main(["guard", "update", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["installer"] == "pipx"
        assert commands == []
        assert output["status"] == "current"
        assert output["changed"] is False
        assert output["message"] == "HOL Guard is already current."

    def test_guard_update_treats_first_install_as_updated_when_only_dependencies_are_current(
        self, tmp_path, monkeypatch, capsys
    ):
        home_dir = tmp_path / "home"
        commands: list[list[str]] = []

        def fake_run(command: list[str], **_: object):
            commands.append(command)
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=(
                    "Requirement already satisfied: pip in /mock/python/site-packages\n"
                    "Successfully installed hol-guard-2.0.36"
                ),
                stderr="",
            )

        monkeypatch.setattr(guard_update_commands_module.subprocess, "run", fake_run)
        monkeypatch.setattr(guard_update_commands_module.sys, "prefix", "/opt/guard-venv")
        monkeypatch.setattr(guard_update_commands_module.sys, "executable", "/opt/guard-venv/bin/python")
        monkeypatch.setattr(guard_update_commands_module, "_direct_url_payload", lambda: None)
        monkeypatch.setattr(guard_update_commands_module, "_current_version", lambda: "unknown")
        monkeypatch.setattr(
            guard_update_commands_module, "_current_version_from_subprocess", lambda *_args, **_kwargs: "2.0.36"
        )
        monkeypatch.setattr(guard_update_commands_module, "_latest_version_from_pypi", lambda: "2.0.36")

        rc = main(["guard", "update", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert commands == [["/opt/guard-venv/bin/python", "-m", "pip", "install", "--upgrade", "hol-guard"]]
        assert output["status"] == "updated"
        assert output["changed"] is True
        assert output["message"] == "HOL Guard update completed successfully."

    def test_guard_update_dry_run_emits_planned_command(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        monkeypatch.setattr(guard_update_commands_module, "_direct_url_payload", lambda: None)
        monkeypatch.setattr(guard_update_commands_module, "_current_version", lambda: "3.0.1a1")
        monkeypatch.setattr(
            guard_update_commands_module,
            "_latest_alpha_version_from_pypi",
            lambda _current: "3.0.1a2",
        )

        rc = main(["guard", "update", "--home", str(home_dir), "--alpha", "--dry-run", "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["status"] == "planned"
        assert output["dry_run"] is True
        assert output["command"]

    def test_guard_update_dry_run_skips_guard_store_init(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        monkeypatch.setattr(guard_update_commands_module, "_direct_url_payload", lambda: None)
        monkeypatch.setattr(guard_update_commands_module, "_current_version", lambda: "3.0.1a1")
        monkeypatch.setattr(
            guard_update_commands_module,
            "_latest_alpha_version_from_pypi",
            lambda _current: "3.0.1a2",
        )
        monkeypatch.setattr(
            guard_commands_module,
            "GuardStore",
            lambda _guard_home: (_ for _ in ()).throw(OSError("db unavailable")),
        )

        rc = main(["guard", "update", "--home", str(home_dir), "--alpha", "--dry-run", "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["status"] == "planned"
        assert output["dry_run"] is True
        assert "notes" not in output

    def test_guard_update_skips_editable_installs(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        monkeypatch.setattr(
            guard_update_commands_module,
            "_direct_url_payload",
            lambda: {"dir_info": {"editable": True}, "url": "file:///mock-workspace/ai-plugin-scanner"},
        )

        rc = main(["guard", "update", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["status"] == "skipped"
        assert output["editable_install"] is True
        assert "disabled for editable installs" in output["error"]

    def test_guard_update_ignores_malformed_guard_config(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        _write_text(home_dir / "config.toml", "[broken\n")
        monkeypatch.setattr(
            guard_commands_module,
            "run_guard_update",
            lambda **_: ({"status": "updated", "message": "ok"}, 0),
        )

        rc = main(["guard", "update", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["status"] == "updated"
        assert output["message"] == "ok"

    def test_guard_update_ignores_guard_store_failures(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        captured_store: list[object] = []

        monkeypatch.setattr(
            guard_commands_module,
            "GuardStore",
            lambda _guard_home: (_ for _ in ()).throw(OSError("db unavailable")),
        )
        monkeypatch.setattr(
            guard_commands_module,
            "run_guard_update",
            lambda **kwargs: (
                captured_store.append(kwargs.get("store")) or {"status": "updated", "message": "ok"},
                0,
            ),
        )

        rc = main(["guard", "update", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert captured_store == [None]
        assert output["status"] == "updated"
        assert any("Skipped local Guard repair during update" in note for note in output["notes"])

    def test_guard_update_forwards_requested_wheel(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        captured_wheels: list[object] = []

        monkeypatch.setattr(
            guard_commands_module,
            "run_guard_update",
            lambda **kwargs: (
                captured_wheels.append(kwargs.get("wheel")) or {"status": "planned", "message": "ok"},
                0,
            ),
        )

        rc = main(["guard", "update", "--home", str(home_dir), "--wheel", "dist", "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert captured_wheels == ["dist"]
        assert output["status"] == "planned"
