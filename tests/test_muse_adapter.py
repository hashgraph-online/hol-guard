"""Tests for the Muse harness adapter."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import hook_failure_bridge, muse_hook_render
from codex_plugin_scanner.guard import native_harness_ops as harness_ops
from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.inventory_contract import _agent_type
from codex_plugin_scanner.guard.muse_hook_render import muse_bridge_response
from codex_plugin_scanner.guard.native_harness_client import ask
from codex_plugin_scanner.guard.native_runner_authority import native_runner_authority
from tests import harness_ops_support as harness_support

FIXTURES = Path(__file__).parent / "fixtures" / "muse"
MUSE_GUARD_EVENT_COUNT = 6


def is_guard_managed_hook_command(command: object) -> bool:
    request = {"op": "managed", "harness": "muse", "commands": [command]}
    return native_runner_authority("harness_hook_settings", request) == {"managed": [True]}


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


def _settings_path(ctx: HarnessContext) -> Path:
    return ctx.home_dir / ".config" / "muse" / "settings.json"


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


class TestMuseAdapterIdentity:
    def test_harness_identifier_is_muse(self) -> None:
        assert harness_ops.canonical_harness("muse") == "muse"

    def test_aliases_resolve(self) -> None:
        for alias in ("muse", "muse-code"):
            assert harness_ops.canonical_harness(alias) == "muse"

    def test_get_adapter_returns_muse_instance(self) -> None:
        assert harness_ops.canonical_harness("muse") == "muse"

    def test_muse_is_registered_in_adapter_list(self) -> None:
        assert "muse" in set(harness_ops.list_harnesses())

    def test_contract_resolve(self) -> None:
        from codex_plugin_scanner.guard.setup_contracts import contract_for, setup_contract_for

        contract = contract_for("muse")
        assert contract is not None
        assert contract.harness == "muse"
        assert contract.resume_support is True
        assert contract.native_approval is True
        assert contract.smoke_command == "hol-guard install muse --dry-run"
        setup = setup_contract_for("muse-code")
        assert setup is not None
        assert setup.harness == "muse"

    def test_agent_type_attributes_muse(self) -> None:
        assert _agent_type("muse") == "muse"

    def test_capability_rows_cover_muse_events(self) -> None:
        from codex_plugin_scanner.guard.setup_contracts import contract_for

        contract = contract_for("muse")
        assert contract is not None
        events = {row.event for row in contract.capability_events}
        assert {"PreToolUse", "PermissionRequest", "UserPromptSubmit", "PostToolUse", "SessionStart", "Stop"} <= events


class TestMuseDetect:
    def test_detects_settings_hooks_and_mcp(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write(_settings_path(ctx), _fixture_payload("settings.json"))
        result = harness_ops.detect("muse", ctx)
        assert result.installed is True
        assert any(".config/muse/settings.json" in path for path in result.config_paths)
        hooks = [a for a in result.artifacts if a.artifact_type == "hook"]
        assert any(a.command == "echo user-pretool" and a.metadata.get("event") == "PreToolUse" for a in hooks)
        assert any(a.command == "echo session-start" and a.metadata.get("event") == "SessionStart" for a in hooks)
        mcp = {a.name: a for a in result.artifacts if a.artifact_type == "mcp_server"}
        assert mcp["local-stdio"].command == "python3"
        assert mcp["local-stdio"].args == ("mcp/server.py",)
        assert mcp["local-stdio"].transport == "stdio"
        assert mcp["remote-http"].url == "https://mcp.example.com/sse"
        assert mcp["remote-http"].transport == "http"

    def test_detects_project_plugin_manifest(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        _write(ctx.workspace_dir / ".muse-plugin" / "plugin.json", _fixture_payload("plugin.json"))
        result = harness_ops.detect("muse", ctx)
        hooks = [a for a in result.artifacts if a.artifact_type == "hook"]
        assert any(a.metadata.get("event") == "PreToolUse" for a in hooks)
        mcp = [a for a in result.artifacts if a.artifact_type == "mcp_server"]
        assert any(a.name == "workspace-index" for a in mcp)

    def test_guard_managed_hooks_excluded_from_artifacts(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        payload = _fixture_payload("settings.json")
        hooks = payload["hooks"]
        assert isinstance(hooks, dict)
        groups = hooks["PreToolUse"]
        assert isinstance(groups, list)
        groups.append(
            {"hooks": [{"type": "command", "command": "python3 guard hook --harness muse # HOL_GUARD_MANAGED_MUSE"}]}
        )
        _write(_settings_path(ctx), payload)
        result = harness_ops.detect("muse", ctx)
        commands = [a.command for a in result.artifacts if a.artifact_type == "hook"]
        assert "echo user-pretool" in commands
        assert not any(command and "HOL_GUARD_MANAGED_MUSE" in command for command in commands)

    def test_workspace_agent_skill_is_published_once(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        skill = ctx.workspace_dir / ".agents" / "skills" / "release-notes" / "SKILL.md"
        skill.parent.mkdir(parents=True, exist_ok=True)
        skill.write_text("# Release notes\n", encoding="utf-8")
        result = harness_ops.detect("muse", ctx)
        skills = [a for a in result.artifacts if a.artifact_type == "skill"]
        assert len(skills) == 1
        assert skills[0].artifact_id == "muse:project:skill:.agents/skills:release-notes"

    def test_project_muse_skill_root_is_detected(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        skill = ctx.workspace_dir / ".muse" / "skills" / "changelog" / "SKILL.md"
        skill.parent.mkdir(parents=True, exist_ok=True)
        skill.write_text("# Changelog\n", encoding="utf-8")
        result = harness_ops.detect("muse", ctx)
        names = {a.name for a in result.artifacts if a.artifact_type == "skill"}
        assert names == {"changelog"}

    def test_unparseable_settings_warns_and_is_still_found(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        path = _settings_path(ctx)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json", encoding="utf-8")
        result = harness_ops.detect("muse", ctx)
        assert any(".config/muse/settings.json" in found for found in result.config_paths)
        assert any("could not be parsed" in warning for warning in result.warnings)


class TestMuseInstallUninstall:
    def _patch_shims(self, monkeypatch: pytest.MonkeyPatch, ctx: HarnessContext) -> None:
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.shims.remove_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-muse"), "notes": []},
        )

    def test_install_writes_six_managed_event_groups(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ctx = _ctx(tmp_path)
        self._patch_shims(monkeypatch, ctx)
        manifest = harness_support.install("muse", ctx)
        assert manifest["active"] is True
        payload = json.loads(_settings_path(ctx).read_text(encoding="utf-8"))
        assert payload["schema_version"] == 1
        hooks = payload["hooks"]
        assert set(hooks.keys()) == {
            "PreToolUse",
            "PermissionRequest",
            "UserPromptSubmit",
            "PostToolUse",
            "SessionStart",
            "Stop",
        }
        # No matcher: Muse reads an omitted matcher as every tool.
        for groups in hooks.values():
            for group in groups:
                assert "matcher" not in group
                for handler in group.get("hooks", []):
                    if is_guard_managed_hook_command(handler.get("command")):
                        assert handler["type"] == "command"
                        assert isinstance(handler["timeout"], int)
        assert _managed_commands(payload)

        def _managed_timeout(event: str) -> int:
            return hooks[event][0]["hooks"][0]["timeout"]

        assert _managed_timeout("PreToolUse") == _managed_timeout("PostToolUse")
        assert _managed_timeout("PreToolUse") > 30
        assert _managed_timeout("PermissionRequest") == 30
        assert _managed_timeout("UserPromptSubmit") == 30
        # Muse has to outlast the bridge client, or it kills the bridge while
        # the approval is still open and the call falls through unjudged.
        assert _managed_timeout("PreToolUse") > ask("hook_spec", ctx, harness="muse")["timeout_seconds"]

    def test_install_refuses_a_non_list_hooks_event_value(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ctx = _ctx(tmp_path)
        _write(_settings_path(ctx), {"schema_version": 1, "hooks": {"PreToolUse": {"hooks": []}}})
        self._patch_shims(monkeypatch, ctx)

        with pytest.raises(ValueError, match=r"non-list hooks\.PreToolUse"):
            harness_support.install("muse", ctx)

        # Guard refuses rather than replacing a value it cannot merge.
        payload = json.loads(_settings_path(ctx).read_text(encoding="utf-8"))
        assert payload["hooks"]["PreToolUse"] == {"hooks": []}

    def test_install_preserves_user_settings_and_hooks(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ctx = _ctx(tmp_path)
        _write(_settings_path(ctx), _fixture_payload("settings.json"))
        self._patch_shims(monkeypatch, ctx)
        harness_support.install("muse", ctx)
        payload = json.loads(_settings_path(ctx).read_text(encoding="utf-8"))
        assert payload["provider"] == "meta"
        assert payload["model"] == "muse-wonder-1.0"
        assert payload["mcpServers"]["remote-http"]["url"] == "https://mcp.example.com/sse"
        pretool_commands = [
            handler["command"]
            for group in payload["hooks"]["PreToolUse"]
            for handler in group.get("hooks", [])
            if isinstance(handler, dict)
        ]
        assert "echo user-pretool" in pretool_commands

    def test_install_is_idempotent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ctx = _ctx(tmp_path)
        self._patch_shims(monkeypatch, ctx)
        harness_support.install("muse", ctx)
        first = _settings_path(ctx).read_text(encoding="utf-8")
        harness_support.install("muse", ctx)
        second = _settings_path(ctx).read_text(encoding="utf-8")
        assert json.loads(first) == json.loads(second)
        assert len(_managed_commands(json.loads(second))) == MUSE_GUARD_EVENT_COUNT

    def test_install_creates_backup_and_state(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ctx = _ctx(tmp_path)
        _write(_settings_path(ctx), _fixture_payload("settings.json"))
        self._patch_shims(monkeypatch, ctx)
        harness_support.install("muse", ctx)
        state_dir = ctx.guard_home / "managed" / "muse"
        assert (state_dir / "settings.json.backup").is_file()
        assert (state_dir / "install.state.json").is_file()

    def test_install_refuses_unparseable_settings(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ctx = _ctx(tmp_path)
        path = _settings_path(ctx)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json", encoding="utf-8")
        self._patch_shims(monkeypatch, ctx)
        with pytest.raises(ValueError, match="could not be parsed"):
            harness_support.install("muse", ctx)

    def test_install_refuses_non_object_hooks_value(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ctx = _ctx(tmp_path)
        _write(_settings_path(ctx), {"schema_version": 1, "hooks": []})
        self._patch_shims(monkeypatch, ctx)
        with pytest.raises(ValueError, match="non-object hooks"):
            harness_support.install("muse", ctx)

    def test_uninstall_removes_managed_hooks_and_keeps_user_ones(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ctx = _ctx(tmp_path)
        _write(_settings_path(ctx), _fixture_payload("settings.json"))
        self._patch_shims(monkeypatch, ctx)
        harness_support.install("muse", ctx)
        manifest = harness_support.uninstall("muse", ctx)
        assert manifest["active"] is False
        payload = json.loads(_settings_path(ctx).read_text(encoding="utf-8"))
        assert _managed_commands(payload) == []
        pretool_commands = [
            handler["command"]
            for group in payload["hooks"]["PreToolUse"]
            for handler in group.get("hooks", [])
            if isinstance(handler, dict)
        ]
        assert "echo user-pretool" in pretool_commands
        assert payload["mcpServers"]["local-stdio"]["command"] == ["python3", "mcp/server.py"]
        assert not (ctx.guard_home / "managed" / "muse" / "install.state.json").exists()


class TestMuseHookRender:
    """The document itself is the resident's; these pin what happens without it.

    Every shape the renderer produces is pinned in Rust
    (``hook_responses::muse``). What stays here is the Python edge: a resident
    that cannot answer, and a hook whose budget is already spent.
    """

    def test_fails_closed_without_a_resident(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(muse_hook_render, "native_muse_bridge", lambda *_args, **_kwargs: None)
        assert muse_bridge_response(
            {"policy_action": "allow", "reason": "ok"},
            event_name="PreToolUse",
            guard_home=tmp_path / "guard-home",
        ) == ("", "HOL Guard blocked this action.", 2)

    def test_render_stops_at_the_hook_deadline(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from codex_plugin_scanner.guard import native_hook_render

        def forbidden(**_kwargs: object) -> None:
            raise AssertionError("an expired hook budget must not reach the resident")

        monkeypatch.setattr(native_hook_render, "_resident_request", forbidden)
        _stdout, _stderr, code = muse_bridge_response(
            {"policy_action": "allow", "reason": "ok"},
            event_name="PreToolUse",
            guard_home=tmp_path / "guard-home",
            deadline=time.monotonic() - 0.01,
        )
        assert code == 2

    @pytest.mark.parametrize("event_name", ["PostToolUse", "SessionStart", "Stop"])
    def test_an_observation_event_stays_silent_without_a_resident(
        self, event_name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A tool that already ran, a session start and a stop cannot be refused.

        Exit 2 on ``Stop`` would keep the agent from stopping, which protects
        nothing. Only a deciding event fails closed.
        """

        monkeypatch.setattr(muse_hook_render, "native_muse_bridge", lambda *_args, **_kwargs: None)
        assert muse_bridge_response(
            {"policy_action": "allow", "reason": "ok"},
            event_name=event_name,
            guard_home=tmp_path / "guard-home",
        ) == ("", "", 0)

    @pytest.mark.parametrize("event_name", ["PreToolUse", "PermissionRequest", "UserPromptSubmit"])
    def test_a_deciding_event_refuses_without_a_resident(
        self, event_name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(muse_hook_render, "native_muse_bridge", lambda *_args, **_kwargs: None)
        assert muse_bridge_response(
            {"policy_action": "allow", "reason": "ok"},
            event_name=event_name,
            guard_home=tmp_path / "guard-home",
        ) == ("", "HOL Guard blocked this action.", 2)

    @pytest.mark.parametrize(
        ("event_name", "expected"),
        [
            ("PreToolUse", ("", hook_failure_bridge.RUNTIME_MISSING, 2)),
            ("PermissionRequest", ("", hook_failure_bridge.RUNTIME_MISSING, 2)),
            ("UserPromptSubmit", ("", hook_failure_bridge.RUNTIME_MISSING, 2)),
            ("PostToolUse", ("", "", 0)),
            ("SessionStart", ("", "", 0)),
            ("Stop", ("", "", 0)),
        ],
    )
    def test_the_outage_table_applies_with_both_native_calls_unavailable(
        self,
        event_name: str,
        expected: tuple[str, str, int],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """No render and no ``hook_failure`` answer: the same table runs in this process."""

        from codex_plugin_scanner.guard import native_runner_authority as authority

        def unavailable(*_args: object, **_kwargs: object) -> None:
            raise authority.NativeRunnerAuthorityError("native_runner_authority_unavailable")

        monkeypatch.setattr(muse_hook_render, "native_muse_bridge", lambda *_args, **_kwargs: None)
        monkeypatch.setattr(authority, "native_runner_authority", unavailable)
        assert (
            muse_bridge_response(
                {"policy_action": "allow", "reason": "ok"},
                event_name=event_name,
                guard_home=tmp_path / "guard-home",
            )
            == expected
        )
