"""Guard CLI update codex integrity behavior."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]
from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters import codex as codex_adapter_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import update_commands as guard_update_commands_module
from codex_plugin_scanner.guard.codex_config import dump_toml
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_cli_fixture_support import _read_codex_hooks, _write_text
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_update_repairs_stale_codex_native_hooks(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        context = HarnessContext(
            home_dir=home_dir,
            workspace_dir=None,
            guard_home=home_dir,
            home_override_explicit=True,
        )
        config_payload: dict[str, object] = {
            "approval_policy": "never",
            "features": {"hooks": True},
            "mcp_servers": {
                "test-stdio": {
                    "command": "/bin/sh",
                    "args": ["-lc", "echo hi"],
                }
            },
        }
        guard_update_commands_module.CodexHarnessAdapter._install_config_hooks(config_payload, context)
        hooks = config_payload["hooks"]
        assert isinstance(hooks, dict)
        pre_tool_groups = hooks["PreToolUse"]
        assert isinstance(pre_tool_groups, list)
        pre_tool_group = pre_tool_groups[-1]
        assert isinstance(pre_tool_group, dict)
        entries = pre_tool_group["hooks"]
        assert isinstance(entries, list)
        entry = entries[0]
        assert isinstance(entry, dict)
        config_path = home_dir / ".codex" / "config.toml"
        guard_update_commands_module.CodexHarnessAdapter._write_authenticated_hook_config(
            context,
            config_path=config_path,
            payload=config_payload,
            previous_manifest=None,
        )
        entry["command"] = f"{entry['command']} --tampered"
        _write_text(config_path, dump_toml(config_payload))
        stale_state = guard_update_commands_module.codex_native_hook_state(context)
        assert stale_state["protection_active"] is False
        assert stale_state["shell_protection_active"] is False
        GuardStore(home_dir).set_managed_install(
            "codex",
            True,
            None,
            {"backup_path": str(home_dir / "managed" / "codex" / "repair.backup.toml")},
            "2026-04-21T00:00:00+00:00",
        )

        monkeypatch.setattr(
            guard_update_commands_module.subprocess,
            "run",
            lambda command, **_: subprocess.CompletedProcess(
                command,
                0,
                stdout="hol-guard is already at latest version 2.0.39",
                stderr="",
            ),
        )
        monkeypatch.setattr(guard_update_commands_module, "_direct_url_payload", lambda: None)
        monkeypatch.setattr(guard_update_commands_module, "_current_version", lambda: "2.0.39")
        monkeypatch.setattr(
            guard_update_commands_module, "_current_version_from_subprocess", lambda *_args, **_kwargs: "2.0.39"
        )
        monkeypatch.setattr(guard_update_commands_module, "_latest_version_from_pypi", lambda: "2.0.39")

        rc = main(["guard", "update", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)
        config_text = config_path.read_text(encoding="utf-8")
        hooks_payload = _read_codex_hooks(config_path)
        repaired_state = guard_update_commands_module.codex_native_hook_state(context)

        assert rc == 0
        assert output["status"] == "current"
        assert output["managed_install"]["harness"] == "codex"
        assert output["managed_install"]["active"] is True
        assert "hooks = true" in config_text
        assert "codex_hooks" not in config_text
        assert hooks_payload["PreToolUse"]
        assert repaired_state["shell_protection_active"] is True

    def test_guard_update_repairs_authenticated_codex_hook_tampering_despite_shape_match(
        self, tmp_path, monkeypatch, capsys
    ):
        home_dir = tmp_path / "home"
        install_rc = main(["guard", "install", "codex", "--home", str(home_dir), "--json"])
        json.loads(capsys.readouterr().out)
        config_path = home_dir / ".codex" / "config.toml"
        config_payload = tomllib.loads(config_path.read_text(encoding="utf-8"))
        managed_handler = config_payload["hooks"]["PreToolUse"][-1]["hooks"][0]
        managed_handler["statusMessage"] = "HOL Guard checking tool action (tampered)"
        _write_text(config_path, codex_adapter_module.dump_toml(config_payload))
        context = HarnessContext(home_dir=home_dir, workspace_dir=Path.cwd(), guard_home=home_dir)

        before = codex_adapter_module.codex_native_hook_state(context)

        assert install_rc == 0
        assert before["protection_active"] is False
        assert before["integrity_reason"] == "codex_hook_registration_mismatch"

        monkeypatch.setattr(
            guard_update_commands_module.subprocess,
            "run",
            lambda command, **_: subprocess.CompletedProcess(
                command,
                0,
                stdout="hol-guard is already at latest version 2.0.39",
                stderr="",
            ),
        )
        monkeypatch.setattr(guard_update_commands_module, "_direct_url_payload", lambda: None)
        monkeypatch.setattr(guard_update_commands_module, "_current_version", lambda: "2.0.39")
        monkeypatch.setattr(
            guard_update_commands_module, "_current_version_from_subprocess", lambda *_args, **_kwargs: "2.0.39"
        )
        monkeypatch.setattr(guard_update_commands_module, "_latest_version_from_pypi", lambda: "2.0.39")

        update_rc = main(["guard", "update", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)
        repaired = codex_adapter_module.codex_native_hook_state(context)

        assert update_rc == 0
        assert output["managed_install"]["active"] is True
        assert repaired["protection_active"] is True
        assert repaired["integrity_status"] == "valid"

    def test_guard_update_refuses_to_replace_altered_codex_identity_record(self, tmp_path, monkeypatch, capsys):
        home_dir = tmp_path / "home"
        assert main(["guard", "install", "codex", "--home", str(home_dir), "--json"]) == 0
        json.loads(capsys.readouterr().out)
        context = HarnessContext(home_dir=home_dir, workspace_dir=Path.cwd(), guard_home=home_dir)
        installed_state = codex_adapter_module.codex_native_hook_state(context)
        manifest_path = Path(str(installed_state["manifest_path"]))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        bridge_identity = next(item for item in manifest["packaged_files"] if item["role"] == "bridge")
        bridge_identity["sha256"] = "0" * 64
        _write_text(manifest_path, json.dumps(manifest, sort_keys=True) + "\n")
        altered_manifest = manifest_path.read_bytes()

        altered_state = codex_adapter_module.codex_native_hook_state(context)

        assert altered_state["protection_active"] is False
        assert altered_state["integrity_status"] == "tampered"
        assert altered_state["integrity_reason"] == "codex_hook_manifest_mac_invalid"

        monkeypatch.setattr(
            guard_update_commands_module.subprocess,
            "run",
            lambda command, **_: subprocess.CompletedProcess(
                command,
                0,
                stdout="hol-guard is already at latest version 2.0.39",
                stderr="",
            ),
        )
        monkeypatch.setattr(guard_update_commands_module, "_direct_url_payload", lambda: None)
        monkeypatch.setattr(guard_update_commands_module, "_current_version", lambda: "2.0.39")
        monkeypatch.setattr(
            guard_update_commands_module, "_current_version_from_subprocess", lambda *_args, **_kwargs: "2.0.39"
        )
        monkeypatch.setattr(guard_update_commands_module, "_latest_version_from_pypi", lambda: "2.0.39")

        update_rc = main(["guard", "update", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)
        final_state = codex_adapter_module.codex_native_hook_state(context)

        assert update_rc == 0
        assert "managed_install" not in output
        assert any("Reinstall hol-guard from a trusted package" in note for note in output["notes"])
        assert manifest_path.read_bytes() == altered_manifest
        assert final_state["protection_active"] is False
        assert final_state["integrity_reason"] == "codex_hook_manifest_mac_invalid"

    def test_guard_update_does_not_reauthenticate_same_version_tampered_packaged_hook(
        self, tmp_path, monkeypatch, capsys
    ):
        home_dir = tmp_path / "home"
        bridge_path = tmp_path / "package" / "codex_daemon_hook_bridge.py"
        bridge_path.parent.mkdir(parents=True)
        original_bridge = Path(codex_adapter_module.__file__).with_name("codex_daemon_hook_bridge.py").read_bytes()
        bridge_path.write_bytes(original_bridge)
        bridge_path.chmod(0o644)
        original_command_parts = codex_adapter_module._hook_command_parts
        original_packaged_paths = codex_adapter_module._hook_packaged_file_paths

        def relocated_command_parts(hook_context: HarnessContext) -> tuple[str, ...]:
            parts = list(original_command_parts(hook_context))
            parts[1] = str(bridge_path)
            return tuple(parts)

        def relocated_packaged_paths() -> tuple[tuple[str, Path], ...]:
            return tuple((role, bridge_path if role == "bridge" else path) for role, path in original_packaged_paths())

        monkeypatch.setattr(codex_adapter_module, "_hook_command_parts", relocated_command_parts)
        monkeypatch.setattr(codex_adapter_module, "_hook_packaged_file_paths", relocated_packaged_paths)
        assert main(["guard", "install", "codex", "--home", str(home_dir), "--json"]) == 0
        json.loads(capsys.readouterr().out)
        context = HarnessContext(home_dir=home_dir, workspace_dir=Path.cwd(), guard_home=home_dir)
        installed_state = codex_adapter_module.codex_native_hook_state(context)
        manifest_path = Path(str(installed_state["manifest_path"]))
        original_manifest = manifest_path.read_bytes()
        tampered_bridge = original_bridge + b"\n# local tamper\n"
        bridge_path.write_bytes(tampered_bridge)

        altered_state = codex_adapter_module.codex_native_hook_state(context)

        assert altered_state["protection_active"] is False
        assert altered_state["integrity_reason"] == "codex_hook_bridge_hash_mismatch"

        def fake_update(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="hol-guard is already at latest version 2.0.39",
                stderr="",
            )

        monkeypatch.setattr(guard_update_commands_module.subprocess, "run", fake_update)
        monkeypatch.setattr(guard_update_commands_module, "_direct_url_payload", lambda: None)
        monkeypatch.setattr(guard_update_commands_module, "_current_version", lambda: "2.0.39")
        monkeypatch.setattr(
            guard_update_commands_module, "_current_version_from_subprocess", lambda *_args, **_kwargs: "2.0.39"
        )
        monkeypatch.setattr(guard_update_commands_module, "_latest_version_from_pypi", lambda: "2.0.39")

        update_rc = main(["guard", "update", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)
        final_state = codex_adapter_module.codex_native_hook_state(context)

        assert update_rc == 0
        assert "managed_install" not in output
        assert any("refused to authenticate changed same-version hook code" in note for note in output["notes"])
        assert bridge_path.read_bytes() == tampered_bridge
        assert manifest_path.read_bytes() == original_manifest
        assert final_state["protection_active"] is False
        assert final_state["integrity_reason"] == "codex_hook_bridge_hash_mismatch"
