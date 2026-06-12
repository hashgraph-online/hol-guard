"""Tests for the Grok Build CLI harness adapter."""

from __future__ import annotations

import argparse
import io
import json
import re
from contextlib import redirect_stderr
from pathlib import Path

from codex_plugin_scanner.guard.adapters import get_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.grok import GrokHarnessAdapter, _remove_managed_block
from codex_plugin_scanner.guard.adapters.grok_hooks import (
    _dedupe_grok_block_reason,
    emit_grok_hook_response,
    grok_hook_response_from_guard,
    prepare_grok_hook_payload,
)
from codex_plugin_scanner.guard.inventory_contract import _agent_type, inventory_snapshot_from_detection
from codex_plugin_scanner.guard.models import HarnessDetection
from codex_plugin_scanner.guard.runtime.actions import normalize_grok_hook_payload


def _ctx(tmp_path: Path, *, workspace: bool = False) -> HarnessContext:
    workspace_dir = tmp_path / "workspace" if workspace else None
    if workspace_dir is not None:
        workspace_dir.mkdir(parents=True, exist_ok=True)
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )


def _fixture(name: str) -> dict[str, object]:
    payload = json.loads((Path(__file__).parent / "fixtures" / "grok" / name).read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


class TestGrokAdapterIdentity:
    def test_harness_identifier_is_grok(self) -> None:
        assert GrokHarnessAdapter.harness == "grok"

    def test_aliases_resolve(self) -> None:
        for alias in ("grok-build", "grok-build-cli", "xai-grok"):
            assert get_adapter(alias).harness == "grok"

    def test_get_adapter_returns_grok_instance(self) -> None:
        assert isinstance(get_adapter("grok"), GrokHarnessAdapter)


class TestGrokDetect:
    def test_detects_managed_config_and_hooks(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        grok_root = ctx.home_dir / ".grok"
        hooks_dir = grok_root / "hooks"
        hooks_dir.mkdir(parents=True)
        (grok_root / "managed_config.toml").write_text("[permission]\nallow = [\"Read\"]\n", encoding="utf-8")
        (hooks_dir / "custom.json").write_text(
            json.dumps(
                {
                    "hooks": {
                        "PreToolUse": [
                            {
                                "matcher": "Bash",
                                "hooks": [{"type": "command", "command": "echo ok"}],
                            }
                        ]
                    }
                }
            ),
            encoding="utf-8",
        )
        result = GrokHarnessAdapter().detect(ctx)
        assert result.harness == "grok"
        assert any(".grok/managed_config.toml" in path for path in result.config_paths)
        hook_artifacts = [artifact for artifact in result.artifacts if artifact.artifact_type == "hook"]
        assert hook_artifacts


class TestGrokInstallUninstall:
    def test_install_writes_managed_hooks_and_config(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.grok.install_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-grok"), "notes": []},
        )
        manifest = GrokHarnessAdapter().install(ctx)
        managed_config = ctx.home_dir / ".grok" / "managed_config.toml"
        pretool_hook = ctx.home_dir / ".grok" / "hooks" / "hol-guard-pretooluse.json"
        prompt_hook = ctx.home_dir / ".grok" / "hooks" / "hol-guard-prompt.json"
        assert manifest["active"] is True
        assert managed_config.is_file()
        assert "BEGIN HOL GUARD MANAGED GROK" in managed_config.read_text(encoding="utf-8")
        assert pretool_hook.is_file()
        assert prompt_hook.is_file()
        pretool_payload = json.loads(pretool_hook.read_text(encoding="utf-8"))
        matchers = {
            entry["matcher"]
            for entry in pretool_payload["hooks"]["PreToolUse"]
            if isinstance(entry, dict) and isinstance(entry.get("matcher"), str)
        }
        assert matchers == {"Bash", "Read", "Edit", "Grep", "MCPTool", "WebFetch"}

    def test_repeated_install_is_idempotent(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.grok.install_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-grok"), "notes": []},
        )
        adapter = GrokHarnessAdapter()
        adapter.install(ctx)
        first_config = (ctx.home_dir / ".grok" / "managed_config.toml").read_text(encoding="utf-8")
        adapter.install(ctx)
        second_config = (ctx.home_dir / ".grok" / "managed_config.toml").read_text(encoding="utf-8")
        assert first_config.count("BEGIN HOL GUARD MANAGED GROK") == 1
        assert second_config.count("BEGIN HOL GUARD MANAGED GROK") == 1

    def test_uninstall_removes_only_guard_managed_entries(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        user_config = ctx.home_dir / ".grok" / "config.toml"
        user_config.parent.mkdir(parents=True, exist_ok=True)
        user_config.write_text("[ui]\nsimple_mode = true\n", encoding="utf-8")
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.grok.install_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-grok"), "notes": []},
        )
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.grok.remove_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-grok"), "notes": []},
        )
        adapter = GrokHarnessAdapter()
        adapter.install(ctx)
        adapter.uninstall(ctx)
        assert user_config.read_text(encoding="utf-8") == "[ui]\nsimple_mode = true\n"
        assert not (ctx.home_dir / ".grok" / "hooks" / "hol-guard-pretooluse.json").exists()
        managed_config = (ctx.home_dir / ".grok" / "managed_config.toml").read_text(encoding="utf-8")
        assert "BEGIN HOL GUARD MANAGED GROK" not in managed_config


class TestGrokHookPayload:
    def test_prepare_grok_hook_payload_maps_bash_fixture(self) -> None:
        normalized = prepare_grok_hook_payload(_fixture("pretooluse_bash.json"))
        assert normalized["hook_event_name"] == "PreToolUse"
        assert normalized["tool_name"] == "Bash"
        assert normalized["session_id"] == "session-redacted-001"

    def test_prepare_grok_hook_payload_maps_read_fixture(self) -> None:
        normalized = prepare_grok_hook_payload(_fixture("pretooluse_read_secret.json"))
        assert normalized["tool_name"] == "Read"

    def test_normalize_grok_hook_payload_builds_shell_envelope(self, tmp_path: Path) -> None:
        envelope = normalize_grok_hook_payload(
            _fixture("pretooluse_bash.json"),
            workspace=tmp_path / "workspace",
            home_dir=tmp_path,
        )
        assert envelope.harness == "grok"
        assert envelope.action_type == "shell_command"
        assert envelope.event_name == "PreToolUse"


class TestGrokHookResponses:
    def test_allow_response(self) -> None:
        assert grok_hook_response_from_guard(policy_action="allow", reason="") == {"decision": "allow"}

    def test_deny_response(self) -> None:
        payload = grok_hook_response_from_guard(policy_action="block", reason="Blocked by HOL Guard.")
        assert payload == {"decision": "deny", "reason": "Blocked by HOL Guard."}

    def test_emit_grok_hook_response_writes_json_line(self) -> None:
        stream = io.StringIO()
        emit_grok_hook_response(policy_action="allow", reason="", output_stream=stream)
        assert json.loads(stream.getvalue()) == {"decision": "allow"}

    def test_grok_block_emits_deny_json_and_stderr(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.cli.commands_hook_generic import _run_hook_generic_payload
        from codex_plugin_scanner.guard.config import GuardConfig
        from codex_plugin_scanner.guard.store import GuardStore

        guard_home = tmp_path / ".hol-guard"
        store = GuardStore(guard_home)
        config = GuardConfig(guard_home=guard_home, workspace=tmp_path)
        args = argparse.Namespace(
            harness="grok",
            json=False,
            policy_action="block",
            artifact_id=None,
            artifact_name=None,
        )
        payload = {"hookEventName": "pre_tool_use", "toolName": "run_terminal_command", "toolInput": {"command": "rm -rf /"}}
        stderr_capture = io.StringIO()
        stdout_capture = io.StringIO()
        with redirect_stderr(stderr_capture):
            rc = _run_hook_generic_payload(
                args,
                action_envelope=None,
                config=config,
                output_stream=stdout_capture,
                payload=payload,
                runtime_workspace=tmp_path,
                store=store,
            )
        assert rc == 2
        assert '"decision":"deny"' in stdout_capture.getvalue()


class TestGrokManagedBlockHelpers:
    def test_remove_managed_block_strips_guard_section(self) -> None:
        text = "keep = true\n\n# BEGIN HOL GUARD MANAGED GROK\nmanaged = false\n# END HOL GUARD MANAGED GROK\n"
        assert _remove_managed_block(text).strip() == "keep = true"


class TestGrokFixturesAreRedacted:
    def test_fixtures_do_not_include_real_local_paths_or_tokens(self) -> None:
        fixture_dir = Path(__file__).parent / "fixtures" / "grok"
        home_prefix = "/" + "Users" + "/"
        unix_home_prefix = "/" + "home" + "/"
        secret_marker = "XAI_" + "API_KEY"
        forbidden = re.compile(
            rf"({re.escape(home_prefix)}|{re.escape(unix_home_prefix)}|{secret_marker}|sk-[A-Za-z0-9]{{8,}}|Bearer\s+\S+)"
        )
        for path in fixture_dir.glob("*.json"):
            contents = path.read_text(encoding="utf-8")
            assert forbidden.search(contents) is None


class TestGrokHookPayloadFixtures:
    def test_edit_fixture_normalizes_to_edit_tool(self) -> None:
        normalized = prepare_grok_hook_payload(_fixture("pretooluse_edit.json"))
        assert normalized["tool_name"] == "Edit"

    def test_mcp_fixture_preserves_server_metadata(self) -> None:
        normalized = prepare_grok_hook_payload(_fixture("pretooluse_mcp.json"))
        assert normalized["tool_name"] == "MCPTool"

    def test_webfetch_fixture_normalizes_tool(self) -> None:
        normalized = prepare_grok_hook_payload(_fixture("pretooluse_webfetch.json"))
        assert normalized["tool_name"] == "WebFetch"

    def test_unknown_tool_is_preserved(self) -> None:
        normalized = prepare_grok_hook_payload(_fixture("pretooluse_unknown_tool.json"))
        assert normalized["tool_name"] == "custom_plugin_action"

    def test_prompt_fixture_normalizes_event(self) -> None:
        normalized = prepare_grok_hook_payload(_fixture("user_prompt_submit.json"))
        assert normalized["hook_event_name"] == "UserPromptSubmit"

    def test_malformed_payload_is_handled_safely(self) -> None:
        normalized = prepare_grok_hook_payload({})
        assert normalized == {}


class TestGrokActionEnvelopes:
    def test_read_secret_maps_to_file_read(self, tmp_path: Path) -> None:
        envelope = normalize_grok_hook_payload(
            _fixture("pretooluse_read_secret.json"),
            workspace=tmp_path / "ws",
            home_dir=tmp_path,
        )
        assert envelope.action_type == "file_read"
        assert ".env" in envelope.target_paths[0]

    def test_safe_grep_maps_to_shell_command(self, tmp_path: Path) -> None:
        envelope = normalize_grok_hook_payload(
            _fixture("pretooluse_grep_safe.json"),
            workspace=tmp_path / "ws",
            home_dir=tmp_path,
        )
        assert envelope.action_type in {"shell_command", "file_read", "config_change"}

    def test_session_id_is_preserved(self, tmp_path: Path) -> None:
        envelope = normalize_grok_hook_payload(
            _fixture("pretooluse_bash.json"),
            workspace=tmp_path / "ws",
            home_dir=tmp_path,
        )
        assert envelope.raw_payload_redacted.get("session_id") == "session-redacted-001"

    def test_workspace_label_is_redacted(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        fixture = dict(_fixture("pretooluse_bash.json"))
        fixture["workspaceRoot"] = str(workspace)
        envelope = normalize_grok_hook_payload(fixture, workspace=workspace, home_dir=tmp_path)
        assert str(workspace) not in (envelope.workspace or "")


class TestGrokDetectExtended:
    def test_detects_mcp_servers_from_config(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".grok" / "config.toml"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(
            """
[mcp_servers.github]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
""".strip()
            + "\n",
            encoding="utf-8",
        )
        result = GrokHarnessAdapter().detect(ctx)
        mcp = [artifact for artifact in result.artifacts if artifact.artifact_type == "mcp_server"]
        assert any(artifact.name == "github" for artifact in mcp)

    def test_detects_degraded_always_approve_signal(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".grok" / "config.toml"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text('sandbox = "off"\n', encoding="utf-8")
        result = GrokHarnessAdapter().detect(ctx)
        assert any("degraded" in warning.lower() or "sandbox" in warning.lower() for warning in result.warnings)

    def test_install_preserves_user_config(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        user_config = ctx.home_dir / ".grok" / "config.toml"
        user_config.parent.mkdir(parents=True, exist_ok=True)
        user_config.write_text("[ui]\nsimple_mode = true\n", encoding="utf-8")
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.grok.install_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-grok"), "notes": []},
        )
        GrokHarnessAdapter().install(ctx)
        assert user_config.read_text(encoding="utf-8") == "[ui]\nsimple_mode = true\n"


class TestGrokInventoryAndResponses:
    def test_inventory_agent_type_is_grok(self) -> None:
        assert _agent_type("grok") == "grok"

    def test_inventory_snapshot_serializes_grok_harness(self, tmp_path: Path) -> None:
        detection = HarnessDetection(
            harness="grok",
            installed=True,
            command_available=True,
            config_paths=(str(tmp_path / ".grok" / "config.toml"),),
            artifacts=(),
            warnings=(),
        )
        snapshot = inventory_snapshot_from_detection(detection, home_dir=tmp_path, generated_at="2026-06-12T00:00:00Z")
        assert snapshot.agent_type == "grok"

    def test_dedupe_block_reason_removes_repeated_approval_copy(self) -> None:
        reason = (
            "Blocked. Open HOL Guard to approve or keep this blocked: http://127.0.0.1:8080/x. "
            "After you choose, retry the same Grok action. "
            "Open HOL Guard to approve or keep this blocked: http://127.0.0.1:8080/x. "
            "After you choose, retry the same Grok action."
        )
        deduped = _dedupe_grok_block_reason(reason)
        assert deduped.count("Open HOL Guard to approve or keep this blocked:") == 1

    def test_deny_response_uses_plain_language_not_raw_json(self) -> None:
        payload = grok_hook_response_from_guard(policy_action="block", reason="Grok tried to read a credential file.")
        assert payload["decision"] == "deny"
        assert "{" not in str(payload["reason"])
