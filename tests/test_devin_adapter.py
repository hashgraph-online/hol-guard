"""Tests for the Devin harness adapter."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import get_adapter, list_adapters
from codex_plugin_scanner.guard.adapters.base import HarnessContext, _shell_command
from codex_plugin_scanner.guard.adapters.devin import DevinHarnessAdapter
from codex_plugin_scanner.guard.adapters.devin_config import (
    DEVIN_GUARD_TOOL_MATCHER,
    GUARD_MANAGED_MARKER,
    is_guard_managed_hook_command,
    load_devin_jsonc,
)
from codex_plugin_scanner.guard.adapters.devin_hooks import (
    devin_hook_response_from_guard,
    devin_hook_should_block,
    emit_devin_hook_response,
    prepare_devin_hook_payload,
)
from codex_plugin_scanner.guard.inventory_contract import _agent_type

FIXTURES = Path(__file__).parent / "fixtures" / "devin"


def _ctx(tmp_path: Path, *, workspace: bool = False) -> HarnessContext:
    workspace_dir = tmp_path / "workspace" if workspace else None
    if workspace_dir is not None:
        workspace_dir.mkdir(parents=True, exist_ok=True)
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )


def _write(path: Path, payload: dict[str, object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _user_config_path(ctx: HarnessContext) -> Path:
    return ctx.home_dir / ".config" / "devin" / "config.json"


def _fixture_payload(name: str) -> dict[str, object]:
    payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


def _managed_commands(payload: dict[str, object]) -> list[str]:
    commands: list[str] = []
    hooks = payload.get("hooks")
    if isinstance(hooks, dict):
        for groups in hooks.values():
            if not isinstance(groups, list):
                continue
            for group in groups:
                if not isinstance(group, dict):
                    continue
                for handler in group.get("hooks") or []:
                    if isinstance(handler, dict) and is_guard_managed_hook_command(handler.get("command")):
                        commands.append(str(handler["command"]))
    return commands


class TestDevinAdapterIdentity:
    def test_harness_identifier_is_devin(self) -> None:
        assert DevinHarnessAdapter.harness == "devin"

    def test_aliases_resolve(self) -> None:
        for alias in ("devin", "devin-cli", "cognition-devin"):
            assert get_adapter(alias).harness == "devin"

    def test_get_adapter_returns_devin_instance(self) -> None:
        assert isinstance(get_adapter("devin"), DevinHarnessAdapter)

    def test_devin_is_registered_in_adapter_list(self) -> None:
        assert "devin" in {item.harness for item in list_adapters()}

    def test_contract_resolve(self) -> None:
        from codex_plugin_scanner.guard.adapters.contracts import contract_for, setup_contract_for

        contract = contract_for("devin")
        assert contract is not None
        assert contract.harness == "devin"
        assert contract.smoke_command == "hol-guard install devin --dry-run"
        setup = setup_contract_for("devin-cli")
        assert setup is not None

    def test_agent_type_attributes_devin(self) -> None:
        assert _agent_type("devin") == "devin"


class TestDevinDetect:
    def test_detects_user_config_hooks_and_legacy_mcp(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write(_user_config_path(ctx), _fixture_payload("user_config.json"))
        result = DevinHarnessAdapter().detect(ctx)
        assert result.installed is True
        assert any(".config/devin/config.json" in path for path in result.config_paths)
        hooks = [a for a in result.artifacts if a.artifact_type == "hook"]
        assert any(a.command == "echo user-pretool" and a.metadata.get("event") == "PreToolUse" for a in hooks)
        assert any(a.command == "echo session-start" and a.metadata.get("event") == "SessionStart" for a in hooks)
        mcp = [a for a in result.artifacts if a.artifact_type == "mcp_server"]
        assert any(a.name == "legacy-inline" and a.command == "node" for a in mcp)

    def test_detects_user_mcp_config_stdio_and_http(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write(ctx.home_dir / ".config" / "devin" / "mcp_config.json", _fixture_payload("mcp_config.json"))
        result = DevinHarnessAdapter().detect(ctx)
        mcp = {a.name: a for a in result.artifacts if a.artifact_type == "mcp_server"}
        assert mcp["local-stdio"].command == "uvx"
        assert mcp["local-stdio"].transport == "stdio"
        assert mcp["remote-http"].url == "https://mcp.example.com/sse"
        assert mcp["remote-http"].transport == "http"

    def test_detects_project_hooks_v1_file(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        _write(ctx.workspace_dir / ".devin" / "hooks.v1.json", _fixture_payload("hooks_v1.json"))
        result = DevinHarnessAdapter().detect(ctx)
        hooks = [a for a in result.artifacts if a.artifact_type == "hook" and a.source_scope == "project"]
        assert any(a.command == "echo post-edit" and a.metadata.get("event") == "PostToolUse" for a in hooks)
        assert any(a.command == "echo stop" and a.metadata.get("event") == "Stop" for a in hooks)

    def test_detects_project_mcp_config_local(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        _write(
            ctx.workspace_dir / ".devin" / "mcp_config.local.json",
            _fixture_payload("mcp_config.local.json"),
        )
        result = DevinHarnessAdapter().detect(ctx)
        mcp = [a for a in result.artifacts if a.artifact_type == "mcp_server" and a.source_scope == "project"]
        assert any(a.name == "project-local" for a in mcp)

    def test_detects_project_config_files(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        _write(
            ctx.workspace_dir / ".devin" / "config.json",
            {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "echo project-config"}]}]}},
        )
        _write(
            ctx.workspace_dir / ".devin" / "config.local.json",
            {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "echo project-local"}]}]}},
        )
        result = DevinHarnessAdapter().detect(ctx)
        hooks = [a for a in result.artifacts if a.artifact_type == "hook" and a.source_scope == "project"]
        assert any(a.command == "echo project-config" for a in hooks)
        assert any(a.command == "echo project-local" for a in hooks)

    def test_detects_skills_in_all_four_roots(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        workspace_dir = ctx.workspace_dir
        roots = {
            ctx.home_dir / ".config" / "devin" / "skills" / "global-devin": "global",
            ctx.home_dir / ".agents" / "skills" / "global-agents": "global",
            workspace_dir / ".devin" / "skills" / "project-devin": "project",
            workspace_dir / ".agents" / "skills" / "project-agents": "project",
        }
        for root in roots:
            (root).mkdir(parents=True, exist_ok=True)
            (root / "SKILL.md").write_text("# Skill\n", encoding="utf-8")
        result = DevinHarnessAdapter().detect(ctx)
        skills = {(a.name, a.source_scope) for a in result.artifacts if a.artifact_type == "skill"}
        assert ("global-devin", "global") in skills
        assert ("global-agents", "global") in skills
        assert ("project-devin", "project") in skills
        assert ("project-agents", "project") in skills

    def test_guard_managed_hooks_excluded_from_artifacts(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write(
            _user_config_path(ctx),
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "exec",
                            "hooks": [
                                {"type": "command", "command": "echo user-hook"},
                                {
                                    "type": "command",
                                    "command": (
                                        f"python -m codex_plugin_scanner.cli guard hook # {GUARD_MANAGED_MARKER}"
                                    ),
                                },
                            ],
                        }
                    ]
                }
            },
        )
        result = DevinHarnessAdapter().detect(ctx)
        commands = [a.command for a in result.artifacts if a.artifact_type == "hook"]
        assert commands == ["echo user-hook"]

    def test_jsonc_config_is_read_tolerantly(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config_path = _user_config_path(ctx)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text((FIXTURES / "config_with_comments.jsonc").read_text(encoding="utf-8"), encoding="utf-8")
        result = DevinHarnessAdapter().detect(ctx)
        hooks = [a for a in result.artifacts if a.artifact_type == "hook"]
        assert any(a.command == "echo jsonc-hook" for a in hooks)

    def test_load_devin_jsonc_flags_commented_payload(self, tmp_path: Path) -> None:
        path = tmp_path / "config.json"
        path.write_text((FIXTURES / "config_with_comments.jsonc").read_text(encoding="utf-8"), encoding="utf-8")
        document = load_devin_jsonc(path)
        assert document.had_comments is True
        assert document.parse_failed is False
        assert document.payload["permissions"]["allow"] == ["exec(ls*)"]

    def test_unparseable_config_warns_and_is_still_found(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config_path = _user_config_path(ctx)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text('{"permissions": ', encoding="utf-8")
        result = DevinHarnessAdapter().detect(ctx)
        assert str(config_path) in result.config_paths
        assert any("could not be parsed" in warning for warning in result.warnings)

    def test_claude_hooks_overlap_warns(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        _write(_user_config_path(ctx), {})
        assert ctx.workspace_dir is not None
        _write(
            ctx.workspace_dir / ".claude" / "settings.json",
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": (
                                        "python -m codex_plugin_scanner.cli 'guard', 'hook' '--harness claude-code'"
                                    ),
                                }
                            ],
                        }
                    ]
                }
            },
        )
        result = DevinHarnessAdapter().detect(ctx)
        assert any("Claude Code hooks" in warning for warning in result.warnings)

    def _ctx_with_managed_claude_hook(self, tmp_path: Path) -> HarnessContext:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        _write(
            ctx.workspace_dir / ".claude" / "settings.json",
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": (
                                        "python -m codex_plugin_scanner.cli 'guard', 'hook' '--harness claude-code'"
                                    ),
                                }
                            ],
                        }
                    ]
                }
            },
        )
        return ctx

    def test_read_config_from_claude_false_suppresses_overlap_warning(self, tmp_path: Path) -> None:
        ctx = self._ctx_with_managed_claude_hook(tmp_path)
        _write(_user_config_path(ctx), {"read_config_from": {"claude": False}})
        result = DevinHarnessAdapter().detect(ctx)
        assert not any("Claude Code hooks" in warning for warning in result.warnings)

    def test_read_config_from_claude_true_keeps_overlap_warning(self, tmp_path: Path) -> None:
        ctx = self._ctx_with_managed_claude_hook(tmp_path)
        _write(_user_config_path(ctx), {"read_config_from": {"claude": True}})
        result = DevinHarnessAdapter().detect(ctx)
        assert any("Claude Code hooks" in warning for warning in result.warnings)

    def test_no_overlap_no_warning(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write(_user_config_path(ctx), {})
        result = DevinHarnessAdapter().detect(ctx)
        assert not any("Claude Code hooks" in warning for warning in result.warnings)


class TestDevinWindowsPaths:
    def test_appdata_config_dir_on_windows(self, tmp_path: Path, monkeypatch) -> None:
        from pathlib import PureWindowsPath

        ctx = _ctx(tmp_path)
        appdata = tmp_path / "AppData" / "Roaming"
        monkeypatch.setattr(os, "name", "nt")
        monkeypatch.setenv("APPDATA", str(appdata))
        monkeypatch.setattr("codex_plugin_scanner.guard.adapters.devin.Path", PureWindowsPath)
        adapter = DevinHarnessAdapter()
        expected = PureWindowsPath(str(appdata)) / "devin" / "config.json"
        assert adapter._user_config_path(ctx) == expected

    def test_unix_config_dir_ignores_appdata(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        monkeypatch.setattr(os, "name", "posix")
        monkeypatch.setenv("APPDATA", str(tmp_path / "unused"))
        adapter = DevinHarnessAdapter()
        assert adapter._user_config_path(ctx) == ctx.home_dir / ".config" / "devin" / "config.json"

    def test_utf16_config_warns_and_install_refuses(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        config_path = _user_config_path(ctx)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_bytes('{"permissions": {}}'.encode("utf-16"))
        result = DevinHarnessAdapter().detect(ctx)
        assert str(config_path) in result.config_paths
        assert any("could not be parsed" in warning for warning in result.warnings)
        self._shim_safe(monkeypatch, ctx)
        with pytest.raises(ValueError, match="could not be parsed"):
            DevinHarnessAdapter().install(ctx)

    def _shim_safe(self, monkeypatch, ctx: HarnessContext) -> None:
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.devin.install_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-devin"), "notes": []},
        )
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.devin.remove_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-devin"), "notes": []},
        )

    def test_unparseable_mcp_config_warns(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        mcp_path = ctx.workspace_dir / ".devin" / "mcp_config.json"
        mcp_path.parent.mkdir(parents=True, exist_ok=True)
        mcp_path.write_text("{not json", encoding="utf-8")
        result = DevinHarnessAdapter().detect(ctx)
        assert str(mcp_path) in result.config_paths
        assert any("could not be parsed" in warning for warning in result.warnings)

    def test_artifact_ids_include_config_file_name(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write(_user_config_path(ctx), _fixture_payload("user_config.json"))
        result = DevinHarnessAdapter().detect(ctx)
        assert result.artifacts
        for artifact in result.artifacts:
            assert "config.json" in artifact.artifact_id, artifact.artifact_id

    def test_claude_daemon_hook_marker_triggers_overlap_warning(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        _write(_user_config_path(ctx), {})
        assert ctx.workspace_dir is not None
        _write(
            ctx.workspace_dir / ".claude" / "settings.json",
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "run-hook # HOL_GUARD_CLAUDE_DAEMON_HOOK",
                                }
                            ],
                        }
                    ]
                }
            },
        )
        result = DevinHarnessAdapter().detect(ctx)
        assert any("Claude Code hooks" in warning for warning in result.warnings)

    def test_frozen_and_script_forms_detected_as_managed(self) -> None:
        frozen = '/bin/python __guard-bounded-hook {"harness":"devin","timeout_seconds":25}'
        assert is_guard_managed_hook_command(frozen)
        script = "/opt/guard/managed/bounded-hooks/devin.py"
        assert is_guard_managed_hook_command(f"/opt/python -I {script}")
        windows_script = "C:\\guard\\managed\\bounded-hooks\\devin.py"
        assert is_guard_managed_hook_command(f"C:\\Python\\python.exe -I {windows_script}")

    def test_unreadable_existing_config_fails_closed(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        config_path = _user_config_path(ctx)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text("{}", encoding="utf-8")
        original_bytes = config_path.read_bytes()

        def _deny(*_args: object, **_kwargs: object) -> str:
            raise PermissionError("denied")

        monkeypatch.setattr(Path, "read_text", _deny)
        result = DevinHarnessAdapter().detect(ctx)
        assert str(config_path) in result.config_paths
        assert any("could not be parsed" in warning for warning in result.warnings)
        with pytest.raises(ValueError, match="could not be parsed"):
            DevinHarnessAdapter().install(ctx)
        monkeypatch.undo()
        assert config_path.read_bytes() == original_bytes

    def test_missing_config_still_counts_as_absent(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        missing = _user_config_path(ctx)
        assert not missing.exists()
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.devin.install_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-devin"), "notes": []},
        )
        DevinHarnessAdapter().install(ctx)
        assert json.loads(missing.read_text(encoding="utf-8"))["hooks"]

    def test_install_writes_config_atomically_without_leftover_temps(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.devin.install_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-devin"), "notes": []},
        )
        DevinHarnessAdapter().install(ctx)
        config_path = _user_config_path(ctx)
        assert json.loads(config_path.read_text(encoding="utf-8"))["hooks"]
        assert not list(config_path.parent.glob("*.tmp"))
        assert not list(config_path.parent.glob("*.guard-tmp"))
        assert not list(config_path.parent.glob(".*.tmp"))


class TestDevinInstallUninstall:
    def _patch_shims(self, monkeypatch, ctx: HarnessContext) -> None:
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.devin.install_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-devin"), "notes": []},
        )
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.devin.remove_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-devin"), "notes": []},
        )

    def test_install_writes_four_managed_event_groups(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        self._patch_shims(monkeypatch, ctx)
        manifest = DevinHarnessAdapter().install(ctx)
        assert manifest["active"] is True
        config_path = _user_config_path(ctx)
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        hooks = payload["hooks"]
        assert set(hooks.keys()) == {"PreToolUse", "PermissionRequest", "UserPromptSubmit", "PostToolUse"}
        for event in ("PreToolUse", "PermissionRequest", "PostToolUse"):
            matchers = {entry.get("matcher") for entry in hooks[event] if isinstance(entry, dict)}
            assert DEVIN_GUARD_TOOL_MATCHER in matchers
        prompt_entries = [entry for entry in hooks["UserPromptSubmit"] if isinstance(entry, dict)]
        assert prompt_entries and all("matcher" not in entry for entry in prompt_entries)
        for groups in hooks.values():
            for group in groups:
                for handler in group.get("hooks", []):
                    if is_guard_managed_hook_command(handler.get("command")):
                        assert handler["type"] == "command"
                        assert isinstance(handler["timeout"], int)

        def _managed_timeout(event: str) -> int:
            group = next(e for e in hooks[event] if e.get("matcher") == DEVIN_GUARD_TOOL_MATCHER)
            return group["hooks"][0]["timeout"]

        assert _managed_timeout("PreToolUse") == _managed_timeout("PostToolUse")
        assert _managed_timeout("PermissionRequest") == 30
        prompt_timeout = prompt_entries[0]["hooks"][0]["timeout"]
        assert prompt_timeout == 30

    def test_install_preserves_user_config_keys_and_hooks(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        _write(_user_config_path(ctx), _fixture_payload("user_config.json"))
        self._patch_shims(monkeypatch, ctx)
        DevinHarnessAdapter().install(ctx)
        payload = json.loads(_user_config_path(ctx).read_text(encoding="utf-8"))
        assert payload["permissions"]["allow"] == ["exec(ls*)"]
        assert payload["read_config_from"]["claude"] is True
        assert payload["mcpServers"]["legacy-inline"]["command"] == "node"
        pretool_commands = [
            handler["command"]
            for group in payload["hooks"]["PreToolUse"]
            for handler in group.get("hooks", [])
            if isinstance(handler, dict)
        ]
        assert "echo user-pretool" in pretool_commands
        session_start = payload["hooks"]["SessionStart"]
        assert any(
            handler.get("command") == "echo session-start"
            for group in session_start
            for handler in group.get("hooks", [])
        )

    def test_install_is_idempotent(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        _write(_user_config_path(ctx), _fixture_payload("user_config.json"))
        self._patch_shims(monkeypatch, ctx)
        adapter = DevinHarnessAdapter()
        adapter.install(ctx)
        adapter.install(ctx)
        payload = json.loads(_user_config_path(ctx).read_text(encoding="utf-8"))
        managed = _managed_commands(payload)
        assert len(managed) == 4, f"expected one managed handler per event, got {managed}"

    def test_install_creates_backup_and_state_once(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        config_path = _write(_user_config_path(ctx), _fixture_payload("user_config.json"))
        original = config_path.read_text(encoding="utf-8")
        self._patch_shims(monkeypatch, ctx)
        adapter = DevinHarnessAdapter()
        adapter.install(ctx)
        backup = ctx.guard_home / "managed" / "devin" / "config.json.backup"
        state = ctx.guard_home / "managed" / "devin" / "install.state.json"
        assert backup.read_text(encoding="utf-8") == original
        assert json.loads(state.read_text(encoding="utf-8"))["managed_config_path"] == str(config_path)
        # Second install must not overwrite the pristine backup.
        adapter.install(ctx)
        assert backup.read_text(encoding="utf-8") == original

    def test_install_refuses_jsonc_config(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        config_path = _user_config_path(ctx)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        original = (FIXTURES / "config_with_comments.jsonc").read_text(encoding="utf-8")
        config_path.write_text(original, encoding="utf-8")
        self._patch_shims(monkeypatch, ctx)
        with pytest.raises(ValueError, match="comments or trailing commas"):
            DevinHarnessAdapter().install(ctx)
        assert config_path.read_text(encoding="utf-8") == original

    def test_install_refuses_unparseable_config(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        config_path = _user_config_path(ctx)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        original = '{"permissions": '
        config_path.write_text(original, encoding="utf-8")
        self._patch_shims(monkeypatch, ctx)
        with pytest.raises(ValueError, match="could not be parsed"):
            DevinHarnessAdapter().install(ctx)
        assert config_path.read_text(encoding="utf-8") == original
        assert not (ctx.guard_home / "managed" / "devin" / "install.state.json").exists()

    def test_install_refuses_non_object_config(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        config_path = _user_config_path(ctx)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text("[]", encoding="utf-8")
        self._patch_shims(monkeypatch, ctx)
        with pytest.raises(ValueError, match="could not be parsed"):
            DevinHarnessAdapter().install(ctx)
        assert config_path.read_text(encoding="utf-8") == "[]"

    def test_install_handles_empty_config_file(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        config_path = _user_config_path(ctx)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text("", encoding="utf-8")
        self._patch_shims(monkeypatch, ctx)
        manifest = DevinHarnessAdapter().install(ctx)
        assert manifest["active"] is True
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        assert set(payload["hooks"].keys()) == {"PreToolUse", "PermissionRequest", "UserPromptSubmit", "PostToolUse"}

    def test_uninstall_leaves_unparseable_config_untouched(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        config_path = _user_config_path(ctx)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        original = '{"permissions": '
        config_path.write_text(original, encoding="utf-8")
        self._patch_shims(monkeypatch, ctx)
        manifest = DevinHarnessAdapter().uninstall(ctx)
        assert config_path.read_text(encoding="utf-8") == original
        assert any("could not be parsed" in note for note in manifest["notes"])
        assert not any("entries removed" in note for note in manifest["notes"])

    def test_uninstall_leaves_managed_handlers_in_jsonc_config(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        self._patch_shims(monkeypatch, ctx)
        adapter = DevinHarnessAdapter()
        adapter.install(ctx)
        config_path = _user_config_path(ctx)
        commented = config_path.read_text(encoding="utf-8").replace('"hooks"', '// user comment\n  "hooks"', 1)
        config_path.write_text(commented, encoding="utf-8")
        manifest = adapter.uninstall(ctx)
        assert config_path.read_text(encoding="utf-8") == commented
        assert any("left its managed hook entries in place" in note for note in manifest["notes"])
        assert not any("entries removed" in note for note in manifest["notes"])

    def test_uninstall_removes_only_managed_handlers(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        _write(_user_config_path(ctx), _fixture_payload("user_config.json"))
        self._patch_shims(monkeypatch, ctx)
        adapter = DevinHarnessAdapter()
        adapter.install(ctx)
        manifest = adapter.uninstall(ctx)
        assert manifest["active"] is False
        payload = json.loads(_user_config_path(ctx).read_text(encoding="utf-8"))
        assert _managed_commands(payload) == []
        pretool_commands = [
            handler["command"] for group in payload["hooks"]["PreToolUse"] for handler in group.get("hooks", [])
        ]
        assert pretool_commands == ["echo user-pretool"]
        assert "SessionStart" in payload["hooks"]
        assert not (ctx.guard_home / "managed" / "devin" / "install.state.json").exists()

    def test_uninstall_drops_empty_hooks_object(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        self._patch_shims(monkeypatch, ctx)
        adapter = DevinHarnessAdapter()
        adapter.install(ctx)
        adapter.uninstall(ctx)
        payload = json.loads(_user_config_path(ctx).read_text(encoding="utf-8"))
        assert "hooks" not in payload

    def test_rendered_command_detected_managed_without_marker(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        parts = DevinHarnessAdapter._hook_command_parts(ctx)
        for windows in (False, True):
            rendered = _shell_command(parts, windows=windows)
            assert GUARD_MANAGED_MARKER not in rendered
            assert is_guard_managed_hook_command(rendered), rendered

    def test_legacy_marker_entries_pruned_on_reinstall_and_uninstall(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        config_path = _user_config_path(ctx)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            json.dumps(
                {
                    "hooks": {
                        "PreToolUse": [
                            {
                                "matcher": ".*",
                                "hooks": [
                                    {"type": "command", "command": "echo user-hook", "timeout": 10},
                                    {
                                        "type": "command",
                                        "command": f"old-guard # {GUARD_MANAGED_MARKER}",
                                        "timeout": 10,
                                    },
                                ],
                            }
                        ]
                    }
                }
            ),
            encoding="utf-8",
        )
        self._patch_shims(monkeypatch, ctx)
        adapter = DevinHarnessAdapter()
        adapter.install(ctx)
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        commands = [
            handler["command"] for group in payload["hooks"]["PreToolUse"] for handler in group.get("hooks", [])
        ]
        assert "echo user-hook" in commands
        assert not any(GUARD_MANAGED_MARKER in command for command in commands)
        managed = _managed_commands(payload)
        assert len(managed) == 4
        adapter.uninstall(ctx)
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        assert _managed_commands(payload) == []
        remaining = [
            handler["command"] for group in payload["hooks"]["PreToolUse"] for handler in group.get("hooks", [])
        ]
        assert remaining == ["echo user-hook"]

    def test_install_refuses_non_object_hooks_value(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        config_path = _user_config_path(ctx)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        original = json.dumps({"hooks": ["not-a-dict"]})
        config_path.write_text(original, encoding="utf-8")
        self._patch_shims(monkeypatch, ctx)
        with pytest.raises(ValueError, match="non-object hooks"):
            DevinHarnessAdapter().install(ctx)
        assert config_path.read_text(encoding="utf-8") == original


class TestDevinHookPayload:
    def test_exec_maps_to_bash(self, monkeypatch) -> None:
        monkeypatch.delenv("DEVIN_PROJECT_DIR", raising=False)
        normalized = prepare_devin_hook_payload(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "exec",
                "tool_input": {"command": "ls"},
                "session_id": "s",
                "prompt_id": "p",
            }
        )
        assert normalized["hook_event_name"] == "PreToolUse"
        assert normalized["tool_name"] == "Bash"
        assert normalized["tool_input"] == {"command": "ls"}
        assert normalized["session_id"] == "s"
        assert normalized["prompt_id"] == "p"

    def test_mcp_call_tool_synthesizes_canonical_name(self, monkeypatch) -> None:
        monkeypatch.delenv("DEVIN_PROJECT_DIR", raising=False)
        normalized = prepare_devin_hook_payload(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp_call_tool",
                "tool_input": {
                    "server_name": "github",
                    "tool_name": "create_issue",
                    "arguments": {"title": "hi"},
                },
            }
        )
        assert normalized["tool_name"] == "mcp__github__create_issue"
        assert normalized["tool_input"] == {"title": "hi"}
        assert normalized["devin_mcp_call"] == {"server_name": "github", "tool_name": "create_issue"}

    def test_direct_mcp_tool_name_preserved(self, monkeypatch) -> None:
        monkeypatch.delenv("DEVIN_PROJECT_DIR", raising=False)
        normalized = prepare_devin_hook_payload(
            {"hook_event_name": "PreToolUse", "tool_name": "mcp__github__create_issue", "tool_input": {"x": 1}}
        )
        assert normalized["tool_name"] == "mcp__github__create_issue"

    def test_devin_project_dir_supplies_cwd(self, monkeypatch) -> None:
        monkeypatch.setenv("DEVIN_PROJECT_DIR", "/workspace/project-root")
        normalized = prepare_devin_hook_payload({"hook_event_name": "PreToolUse", "tool_name": "exec"})
        assert normalized["cwd"] == "/workspace/project-root"

    def test_explicit_cwd_wins_over_env(self, monkeypatch) -> None:
        monkeypatch.setenv("DEVIN_PROJECT_DIR", "/workspace/project-root")
        normalized = prepare_devin_hook_payload(
            {"hook_event_name": "PreToolUse", "tool_name": "exec", "cwd": "/elsewhere"}
        )
        assert normalized["cwd"] == "/elsewhere"

    def test_user_prompt_submit_event(self, monkeypatch) -> None:
        monkeypatch.delenv("DEVIN_PROJECT_DIR", raising=False)
        normalized = prepare_devin_hook_payload(
            {"hook_event_name": "UserPromptSubmit", "prompt": "hello", "session_id": "s"}
        )
        assert normalized["hook_event_name"] == "UserPromptSubmit"
        assert normalized["prompt"] == "hello"


class TestDevinHookResponses:
    def test_block_response_has_decision_and_deny(self) -> None:
        response = devin_hook_response_from_guard(policy_action="block", reason="no", event_name="PreToolUse")
        assert response["decision"] == "block"
        assert response["reason"] == "no"
        specific = response["hookSpecificOutput"]
        assert specific["permissionDecision"] == "deny"
        assert specific["permissionDecisionReason"] == "no"

    def test_allow_response_has_no_decision(self) -> None:
        response = devin_hook_response_from_guard(policy_action="allow", reason="", event_name="PreToolUse")
        assert "decision" not in response
        assert "permissionDecision" not in response["hookSpecificOutput"]

    def test_no_approve_decision_is_ever_emitted(self) -> None:
        for action in ("allow", "review", "require-reapproval", "sandbox-required", "block"):
            response = devin_hook_response_from_guard(policy_action=action, reason="r", event_name="PreToolUse")
            assert response.get("decision") != "approve"

    def test_prompt_block_uses_additional_context(self) -> None:
        response = devin_hook_response_from_guard(policy_action="review", reason="check", event_name="UserPromptSubmit")
        assert response["decision"] == "block"
        assert response["hookSpecificOutput"]["additionalContext"] == "check"

    def test_emit_writes_response_to_stream(self) -> None:
        stream = io.StringIO()
        emit_devin_hook_response(policy_action="block", reason="no", event_name="PreToolUse", output_stream=stream)
        response = json.loads(stream.getvalue())
        assert response["decision"] == "block"

    def test_should_block_classification(self) -> None:
        for action in ("review", "require-reapproval", "sandbox-required", "block"):
            assert devin_hook_should_block(policy_action=action) is True
        assert devin_hook_should_block(policy_action="allow") is False


class TestDevinManagedMarker:
    def test_marker_detects_guard_commands(self) -> None:
        assert is_guard_managed_hook_command(f"echo hi # {GUARD_MANAGED_MARKER}") is True
        assert is_guard_managed_hook_command("echo hi") is False
        assert is_guard_managed_hook_command(None) is False
        assert is_guard_managed_hook_command(42) is False
