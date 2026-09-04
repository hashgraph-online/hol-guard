"""Regression coverage for Sonar-reported adapter path-authority boundaries."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
import yaml

from codex_plugin_scanner.guard.adapters import claude_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.copilot import CopilotHarnessAdapter
from codex_plugin_scanner.guard.adapters.cursor_hooks import managed_hook_script_path, uninstall_cursor_hooks
from codex_plugin_scanner.guard.adapters.hermes import HermesHarnessAdapter
from codex_plugin_scanner.guard.adapters.openclaw import OpenClawHarnessAdapter
from codex_plugin_scanner.guard.daemon.discovery import authenticate_daemon_state, ensure_daemon_discovery_key
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from tests.test_guard_extension_control_authority import MemorySecretStore, _store


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def test_claude_daemon_url_rejects_noncanonical_state_path(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=r"absolute daemon-state[.]json"):
        bridge._daemon_url(tmp_path / "renamed-state.json", "http://127.0.0.1:5474/")


def test_claude_daemon_url_does_not_follow_state_symlink(tmp_path: Path) -> None:
    external_state = tmp_path / "external.json"
    external_state.write_text(json.dumps({"port": 6553}), encoding="utf-8")
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "daemon-state.json").symlink_to(external_state)
    assert bridge._daemon_url(guard_home / "daemon-state.json", "http://127.0.0.1:5474/") == ("http://127.0.0.1:5474/")


def test_claude_daemon_url_uses_authenticated_local_state(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    discovery_key = ensure_daemon_discovery_key(guard_home)
    state = authenticate_daemon_state(
        {
            "guard_home": str(guard_home.resolve()),
            "host": "127.0.0.1",
            "port": 6553,
        },
        discovery_key=discovery_key,
    )
    state_path = guard_home / "daemon-state.json"
    _write_json(state_path, state)
    state_path.chmod(0o600)

    assert bridge._daemon_url(state_path, "http://127.0.0.1:5474/") == "http://127.0.0.1:6553/"


def test_claude_bridge_falls_back_when_hook_state_binding_is_stale(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO('{"hook_event_name":"PreToolUse"}'))
    monkeypatch.setattr(bridge, "_run_local_fallback", lambda *args, **kwargs: '{"fallback":true}')

    result = bridge.main(
        state_path=tmp_path / "old-home" / "daemon-state.json",
        fallback_daemon_url="http://127.0.0.1:5474/",
        fallback_command=("trusted-guard", "hook"),
        query=f"guard-home={tmp_path / 'new-home'}",
    )

    assert result == 0
    assert json.loads(capsys.readouterr().out) == {"fallback": True}


def test_copilot_uninstall_ignores_tampered_lifecycle_paths(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True)
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )
    global_context = HarnessContext(home_dir=context.home_dir, workspace_dir=None, guard_home=context.guard_home)
    adapter = CopilotHarnessAdapter()
    install_payload = adapter.install(context)
    state_paths = install_payload["state_paths"]
    assert isinstance(state_paths, list)
    state_path = Path(str(state_paths[0]))
    outside_target = tmp_path / "outside" / ".mcp.json"
    outside_backup = tmp_path / "outside" / "backup.json"
    _write_json(outside_target, {"owned": "user"})
    _write_json(outside_backup, {"existed": False, "content": None})
    state_payload = json.loads(state_path.read_text(encoding="utf-8"))
    state_payload.update({"managed_config_path": str(outside_target), "backup_path": str(outside_backup)})
    _write_json(state_path, state_payload)

    uninstall_payload = adapter.uninstall(global_context)

    assert json.loads(outside_target.read_text(encoding="utf-8")) == {"owned": "user"}
    assert outside_backup.exists() is True
    assert state_path.exists() is True
    managed_config_paths = uninstall_payload["managed_config_paths"]
    assert isinstance(managed_config_paths, list)
    assert str(outside_target) not in managed_config_paths


def test_copilot_uninstall_does_not_follow_managed_config_symlink(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )
    adapter = CopilotHarnessAdapter()
    install_payload = adapter.install(context)
    state_paths = install_payload["state_paths"]
    assert isinstance(state_paths, list)
    managed_path = workspace_dir / ".mcp.json"
    managed_path.unlink()
    outside_target = tmp_path / "outside.json"
    outside_target.write_text('{"owned":"user"}', encoding="utf-8")
    managed_path.symlink_to(outside_target)

    adapter.uninstall(HarnessContext(home_dir=context.home_dir, workspace_dir=None, guard_home=context.guard_home))

    assert outside_target.read_text(encoding="utf-8") == '{"owned":"user"}'
    assert Path(str(state_paths[0])).exists() is True


def test_copilot_unsigned_legacy_state_cannot_authorize_other_workspace(tmp_path: Path) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    external_workspace = tmp_path / "external-workspace"
    external_target = external_workspace / ".mcp.json"
    external_target.parent.mkdir()
    external_target.write_text('{"owned":"user"}', encoding="utf-8")
    backup_path = CopilotHarnessAdapter._backup_path(external_target, context)
    backup_path.parent.mkdir(parents=True)
    _write_json(backup_path, {"existed": False, "content": None})
    state_path = CopilotHarnessAdapter._state_path(external_target, context)
    _write_json(
        state_path,
        {
            "managed_config_path": str(external_target),
            "backup_path": str(backup_path),
            "workspace_dir": str(external_workspace),
        },
    )

    CopilotHarnessAdapter().uninstall(context)

    assert external_target.read_text(encoding="utf-8") == '{"owned":"user"}'
    assert backup_path.exists() is True
    assert state_path.exists() is True


def test_hermes_uninstall_authenticates_external_recorded_config_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )
    custom_home = tmp_path / "external-hermes"
    config_path = custom_home / "config.yaml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("mcp_servers:\n  github:\n    command: npx\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(custom_home))
    adapter = HermesHarnessAdapter()
    adapter.install(context)

    monkeypatch.delenv("HERMES_HOME")
    adapter.uninstall(context)

    config_after = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert "guard" not in config_after
    assert "guard-github" not in config_after.get("mcp_servers", {})


def test_hermes_uninstall_ignores_tampered_manifest_paths_outside_home(tmp_path: Path) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    adapter = HermesHarnessAdapter()
    manifest = adapter.install(context)
    manifest_path = Path(str(manifest["managed_manifest_path"]))
    outside_root = tmp_path / "outside"
    outside_overlay = outside_root / "mcp-overlay.json"
    outside_hook = outside_root / "pretool-hook.json"
    outside_config = outside_root / "config.yaml"
    outside_root.mkdir()
    outside_overlay.write_text("user overlay", encoding="utf-8")
    outside_hook.write_text("user hook", encoding="utf-8")
    outside_config.write_text("guard:\n  enabled: false\n", encoding="utf-8")
    tampered = json.loads(manifest_path.read_text(encoding="utf-8"))
    tampered.update(
        {
            "mcp_overlay_path": str(outside_overlay),
            "pretool_hook_path": str(outside_hook),
            "hermes_config_yaml_path": str(outside_config),
        }
    )
    _write_json(manifest_path, tampered)

    uninstall_payload = adapter.uninstall(context)

    assert uninstall_payload["active"] is False
    assert outside_overlay.read_text(encoding="utf-8") == "user overlay"
    assert outside_hook.read_text(encoding="utf-8") == "user hook"
    assert outside_config.read_text(encoding="utf-8") == "guard:\n  enabled: false\n"
    assert Path(str(manifest["mcp_overlay_path"])).exists() is False
    assert Path(str(manifest["pretool_hook_path"])).exists() is False


def test_hermes_uninstall_ignores_tampered_auxiliary_cleanup_state(tmp_path: Path) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    config_path = context.home_dir / ".hermes" / "config.yaml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "mcp_servers:\n  github:\n    command: npx\nguard:\n  enabled: false\n",
        encoding="utf-8",
    )
    adapter = HermesHarnessAdapter()
    adapter.install(context)
    managed_root = context.guard_home / "hermes"
    _write_json(managed_root / "managed-servers.json", {"servers": ["github"]})
    _write_json(managed_root / "previous-guard-section.json", {"guard": {"enabled": "attacker"}})

    adapter.uninstall(context)

    config_after = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert config_after["mcp_servers"]["github"] == {"command": "npx"}
    assert config_after["guard"] == {"enabled": False}


def test_hermes_uninstall_preserves_current_guard_section_when_state_key_is_missing(tmp_path: Path) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    config_path = context.home_dir / ".hermes" / "config.yaml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("mcp_servers: {}\nguard:\n  enabled: false\n", encoding="utf-8")
    adapter = HermesHarnessAdapter()
    adapter.install(context)
    (context.guard_home / "managed" / "adapter-state.key").unlink()
    installed_config = yaml.safe_load(config_path.read_text(encoding="utf-8"))

    adapter.uninstall(context)

    config_after = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert config_after["guard"] == installed_config["guard"]


def test_hermes_launch_environment_rejects_tampered_managed_paths(tmp_path: Path) -> None:
    context = HarnessContext(home_dir=tmp_path, workspace_dir=None, guard_home=tmp_path / "guard-home")
    adapter = HermesHarnessAdapter()
    manifest = adapter.install(context)
    manifest_path = Path(str(manifest["managed_manifest_path"]))
    tampered = json.loads(manifest_path.read_text(encoding="utf-8"))
    tampered["mcp_overlay_path"] = str(tmp_path / "different-overlay.json")
    _write_json(manifest_path, tampered)

    assert adapter.launch_environment(context) == {}
    runtime_probe = adapter.runtime_probe(context)
    assert runtime_probe is not None
    assert runtime_probe["managed_install_ready"] is False


def test_cursor_uninstall_does_not_unlink_managed_copy_symlink(tmp_path: Path) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    outside_script = tmp_path / "outside.py"
    outside_script.write_text("# user-owned\n", encoding="utf-8")
    managed_script = managed_hook_script_path(context)
    managed_script.parent.mkdir(parents=True)
    managed_script.symlink_to(outside_script)

    with pytest.raises(ValueError, match="Cursor managed hook script"):
        uninstall_cursor_hooks(context)

    assert outside_script.read_text(encoding="utf-8") == "# user-owned\n"
    assert managed_script.is_symlink()


def test_openclaw_runtime_probe_rejects_symlinked_managed_root(tmp_path: Path) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    outside_root = tmp_path / "outside-openclaw"
    outside_root.mkdir()
    _write_json(
        outside_root / "manifest.json",
        {
            "managed_overlay_path": str(outside_root / "overlay.json"),
            "pretool_hook_path": str(outside_root / "pretool-hook.json"),
        },
    )
    context.guard_home.mkdir()
    (context.guard_home / "openclaw").symlink_to(outside_root, target_is_directory=True)
    adapter = OpenClawHarnessAdapter()

    assert adapter.launch_environment(context) == {}
    runtime_probe = adapter.runtime_probe(context)
    assert runtime_probe is not None
    assert runtime_probe["managed_install_present"] is False
    assert runtime_probe["managed_install_ready"] is False


def test_missing_protected_authority_key_is_treated_as_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )
    store = _store(tmp_path, MemorySecretStore())
    protected = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert protected.health is AuthorityHealth.PROTECTED
    monkeypatch.setattr(store, "_read_extension_control_authority_locked", lambda *args, **kwargs: protected)
    monkeypatch.setattr(store, "_authority_key", lambda *, required: None)

    view = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert view.health is AuthorityHealth.TAMPERED
