"""Product-flow behavior tests for Guard onboarding and local launch setup."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _build_guard_fixture(home_dir: Path, workspace_dir: Path) -> None:
    _write_text(
        home_dir / ".codex" / "config.toml",
        """
[mcp_servers.global_tools]
command = "python"
args = ["-m", "http.server", "9000"]
""".strip()
        + "\n",
    )
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
[mcp_servers.workspace_skill]
command = "node"
args = ["workspace-skill.js"]
""".strip()
        + "\n",
    )
    _write_json(
        workspace_dir / ".mcp.json",
        {
            "mcpServers": {
                "workspace-tools": {"command": "python", "args": ["-m", "http.server", "9100"]},
            }
        },
    )


class TestGuardProductFlow:
    def test_plugin_scanner_help_stays_scanner_only(self, capsys, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["plugin-scanner"])

        with pytest.raises(SystemExit) as excinfo:
            main(["--help"])

        output = capsys.readouterr().out

        assert excinfo.value.code == 0
        assert "Scan plugin ecosystems for CI and publish readiness." in output
        assert "{scan,lint,verify,submit,doctor}" in output
        assert "guard" not in output

    def test_python_module_entry_keeps_combined_surface(self, capsys, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["cli.py"])

        with pytest.raises(SystemExit) as excinfo:
            main(["--help"])

        output = capsys.readouterr().out

        assert excinfo.value.code == 0
        assert "Run HOL Guard locally or scan plugin ecosystems for CI and publish readiness." in output
        assert "{scan,lint,verify,submit,doctor,guard}" in output

    def test_guard_start_json_guides_first_run(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
            [
                "guard",
                "start",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        codex_summary = next(item for item in output["harnesses"] if item["harness"] == "codex")

        assert rc == 0
        assert output["recommended_harness"] == "codex"
        assert output["sync_configured"] is False
        assert output["cloud_state"] == "local_only"
        assert output["receipt_count"] == 0
        assert codex_summary["managed"] is False
        assert codex_summary["next_action"] == "install"
        assert output["next_steps"][0]["command"] == "hol-guard install codex"
        assert output["next_steps"][1]["command"] == "hol-guard run codex --dry-run"

    def test_guard_start_recommends_copilot_when_it_is_the_only_detected_harness(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / ".copilot" / "mcp-config.json",
            {"servers": {"global-tool": {"command": "npx", "args": ["server.js"]}}},
        )
        monkeypatch.setattr("shutil.which", lambda _command: None)

        rc = main(
            [
                "guard",
                "start",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        copilot_summary = next(item for item in output["harnesses"] if item["harness"] == "copilot")

        assert rc == 0
        assert output["recommended_harness"] == "copilot"
        assert copilot_summary["install_command"] == "hol-guard install copilot"
        assert output["next_steps"][1]["command"] == "hol-guard run copilot --dry-run"

    def test_guard_connect_json_surfaces_local_only_state(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        guard_home = tmp_path / "guard-home"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
            [
                "guard",
                "connect",
                "--home",
                str(home_dir),
                "--guard-home",
                str(guard_home),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["cloud_state"] == "local_only"
        assert output["sync_configured"] is False
        assert output["connect_url"] == "https://hol.org/guard/connect"
        assert output["dashboard_url"] == "https://hol.org/guard"
        assert output["next_steps"][0]["command"] == "https://hol.org/guard/connect"

    def test_guard_start_human_output_highlights_guard_loop(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
            [
                "guard",
                "start",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
            ]
        )
        output = capsys.readouterr().out

        assert rc == 0
        assert "Install Guard for codex" in output
        assert "Run Guard before launch" in output
        assert "Optional sync later" in output

    def test_hol_guard_direct_entrypoint_runs_without_nested_guard_command(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        monkeypatch.setattr(sys, "argv", ["hol-guard"])

        rc = main(
            [
                "start",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["recommended_harness"] == "codex"
        assert output["next_steps"][0]["command"] == "hol-guard install codex"

    def test_hol_guard_windows_entrypoint_runs_without_nested_guard_command(
        self,
        tmp_path,
        capsys,
        monkeypatch,
    ):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        monkeypatch.setattr(sys, "argv", ["hol-guard.exe"])

        rc = main(
            [
                "start",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["recommended_harness"] == "codex"
        assert output["next_steps"][0]["command"] == "hol-guard install codex"

    def test_guard_install_creates_wrapper_shim(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
            [
                "guard",
                "install",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        shim_path = Path(output["managed_install"]["manifest"]["shim_path"])

        assert rc == 0
        assert output["managed_install"]["active"] is True
        assert shim_path.exists() is True
        assert os.access(shim_path, os.X_OK) is True
        assert "'--guard-home'" in shim_path.read_text(encoding="utf-8")
        assert f"'{home_dir}'" in shim_path.read_text(encoding="utf-8")
        assert "'guard'" in shim_path.read_text(encoding="utf-8")
        assert "'run'" in shim_path.read_text(encoding="utf-8")
        assert "'codex'" in shim_path.read_text(encoding="utf-8")

    def test_guard_install_without_home_override_keeps_real_home_detection(self, tmp_path, capsys, monkeypatch):
        real_home = tmp_path / "real-home"
        workspace_dir = tmp_path / "workspace"
        guard_home = tmp_path / "guard-home"
        _build_guard_fixture(real_home, workspace_dir)
        monkeypatch.setattr(Path, "home", lambda: real_home)

        rc = main(
            [
                "guard",
                "install",
                "codex",
                "--guard-home",
                str(guard_home),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        shim_path = Path(output["managed_install"]["manifest"]["shim_path"])
        shim_text = shim_path.read_text(encoding="utf-8")

        assert rc == 0
        assert "'--guard-home'" in shim_text
        assert f"'{guard_home}'" in shim_text
        assert "'--home'" not in shim_text

    def test_guard_status_reports_managed_launch_and_review_queue(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\n')

        install_rc = main(
            [
                "guard",
                "install",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)
        first_run_rc = main(
            [
                "guard",
                "run",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--dry-run",
                "--default-action",
                "allow",
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)
        _write_text(home_dir / "config.toml", 'changed_hash_action = "require-reapproval"\n')
        _write_text(
            workspace_dir / ".codex" / "config.toml",
            """
[mcp_servers.workspace_skill]
command = "node"
args = ["workspace-skill.js", "--changed"]
""".strip()
            + "\n",
        )

        status_rc = main(
            [
                "guard",
                "status",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        status_output = json.loads(capsys.readouterr().out)
        codex_summary = next(item for item in status_output["harnesses"] if item["harness"] == "codex")

        assert install_rc == 0
        assert first_run_rc == 0
        assert status_rc == 0
        assert status_output["managed_harnesses"] == 1
        assert status_output["receipt_count"] >= 1
        assert codex_summary["managed"] is True
        assert codex_summary["review_count"] >= 1
        assert codex_summary["next_action"] == "review"

    def test_guard_shim_forwards_dash_prefixed_args(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        fake_bin = tmp_path / "fake-bin"
        fake_codex = fake_bin / "codex"
        args_file = tmp_path / "codex-args.txt"
        _build_guard_fixture(home_dir, workspace_dir)
        _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\n')
        _write_text(
            fake_codex,
            "\n".join(
                (
                    "#!/bin/sh",
                    f'printf "%s\\n" "$@" > "{args_file}"',
                    "exit 0",
                    "",
                )
            ),
        )
        fake_bin.mkdir(parents=True, exist_ok=True)
        fake_codex.chmod(fake_codex.stat().st_mode | 0o755)

        main(
            [
                "guard",
                "install",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        install_output = json.loads(capsys.readouterr().out)
        shim_path = Path(install_output["managed_install"]["manifest"]["shim_path"])
        env = os.environ.copy()
        env["PATH"] = f"{fake_bin}:{env['PATH']}"

        result = subprocess.run([str(shim_path), "--help"], capture_output=True, text=True, env=env, check=False)

        assert result.returncode == 0
        assert args_file.read_text(encoding="utf-8").strip() == "--help"
