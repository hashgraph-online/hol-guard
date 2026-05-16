"""Tests for the Cursor harness adapter."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor import CursorHarnessAdapter


def _ctx(tmp_path: Path, *, workspace: bool = False) -> HarnessContext:
    workspace_dir = tmp_path / "workspace" if workspace else None
    if workspace_dir is not None:
        workspace_dir.mkdir(parents=True, exist_ok=True)
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )


def _write_mcp_json(path: Path, servers: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")


class TestCursorAdapterIdentity:
    def test_harness_identifier_is_cursor(self) -> None:
        assert CursorHarnessAdapter.harness == "cursor"

    def test_executable_is_cursor_agent(self) -> None:
        assert CursorHarnessAdapter.executable == "cursor-agent"

    def test_approval_tier_is_native_harness(self) -> None:
        assert CursorHarnessAdapter.approval_tier == "native-harness"

    def test_approval_prompt_channel_is_native(self) -> None:
        assert CursorHarnessAdapter.approval_prompt_channel == "native"

    def test_auto_open_browser_is_disabled(self) -> None:
        assert CursorHarnessAdapter.approval_auto_open_browser is False


class TestCursorPolicyPath:
    def test_policy_path_uses_workspace_when_provided(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        expected = ctx.workspace_dir / ".cursor" / "mcp.json"
        assert CursorHarnessAdapter().policy_path(ctx) == expected

    def test_policy_path_falls_back_to_home_without_workspace(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=False)
        expected = (tmp_path / "home") / ".cursor" / "mcp.json"
        assert CursorHarnessAdapter().policy_path(ctx) == expected


class TestCursorDetectEmptyConfig:
    def test_empty_dir_returns_not_installed_and_no_artifacts(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        result = CursorHarnessAdapter().detect(ctx)
        assert result.harness == "cursor"
        assert result.artifacts == ()
        assert result.config_paths == ()

    def test_mcp_json_with_no_mcp_servers_key_yields_no_artifacts(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        mcp = ctx.home_dir / ".cursor" / "mcp.json"
        mcp.parent.mkdir(parents=True, exist_ok=True)
        mcp.write_text(json.dumps({"other": "data"}), encoding="utf-8")
        result = CursorHarnessAdapter().detect(ctx)
        assert result.artifacts == ()
        assert result.installed is True

    def test_mcp_json_with_empty_mcp_servers_yields_no_artifacts(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_mcp_json(ctx.home_dir / ".cursor" / "mcp.json", {})
        result = CursorHarnessAdapter().detect(ctx)
        assert result.artifacts == ()
        assert result.installed is True


class TestCursorDetectGlobalScope:
    def test_single_global_server_detected_with_correct_id(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_mcp_json(
            ctx.home_dir / ".cursor" / "mcp.json",
            {"my-tools": {"command": "npx", "args": ["-y", "my-mcp-server"]}},
        )
        result = CursorHarnessAdapter().detect(ctx)
        assert len(result.artifacts) == 1
        art = result.artifacts[0]
        assert art.artifact_id == "cursor:global:my-tools"
        assert art.name == "my-tools"
        assert art.harness == "cursor"
        assert art.artifact_type == "mcp_server"
        assert art.source_scope == "global"
        assert art.command == "npx"
        assert art.args == ("-y", "my-mcp-server")

    def test_multiple_global_servers_all_detected(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_mcp_json(
            ctx.home_dir / ".cursor" / "mcp.json",
            {
                "server-a": {"command": "node", "args": ["a.js"]},
                "server-b": {"command": "npx", "args": ["b"]},
            },
        )
        result = CursorHarnessAdapter().detect(ctx)
        ids = {a.artifact_id for a in result.artifacts}
        assert ids == {"cursor:global:server-a", "cursor:global:server-b"}

    def test_global_server_config_path_points_to_home_mcp_json(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        config = ctx.home_dir / ".cursor" / "mcp.json"
        _write_mcp_json(config, {"srv": {"command": "x"}})
        result = CursorHarnessAdapter().detect(ctx)
        assert result.artifacts[0].config_path == str(config)
        assert str(config) in result.config_paths

    def test_installed_is_true_when_home_config_exists(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_mcp_json(ctx.home_dir / ".cursor" / "mcp.json", {"s": {"command": "x"}})
        result = CursorHarnessAdapter().detect(ctx)
        assert result.installed is True


class TestCursorDetectProjectScope:
    def test_project_server_gets_project_scope(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        _write_mcp_json(
            ctx.workspace_dir / ".cursor" / "mcp.json",
            {"project-srv": {"command": "node", "args": ["project.js"]}},
        )
        result = CursorHarnessAdapter().detect(ctx)
        assert len(result.artifacts) == 1
        assert result.artifacts[0].artifact_id == "cursor:project:project-srv"
        assert result.artifacts[0].source_scope == "project"

    def test_global_and_project_configs_produce_distinct_ids(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        _write_mcp_json(
            ctx.home_dir / ".cursor" / "mcp.json",
            {"shared-tools": {"command": "npx", "args": ["global-server"]}},
        )
        _write_mcp_json(
            ctx.workspace_dir / ".cursor" / "mcp.json",
            {"shared-tools": {"command": "npx", "args": ["project-server"]}},
        )
        result = CursorHarnessAdapter().detect(ctx)
        ids = [a.artifact_id for a in result.artifacts]
        assert "cursor:global:shared-tools" in ids
        assert "cursor:project:shared-tools" in ids
        assert len(ids) == 2

    def test_no_workspace_means_only_home_scanned(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=False)
        _write_mcp_json(ctx.home_dir / ".cursor" / "mcp.json", {"g": {"command": "x"}})
        result = CursorHarnessAdapter().detect(ctx)
        assert all(a.source_scope == "global" for a in result.artifacts)


class TestCursorTransportDetection:
    def test_http_transport_when_url_present(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_mcp_json(
            ctx.home_dir / ".cursor" / "mcp.json",
            {"remote-srv": {"url": "http://localhost:3000/mcp"}},
        )
        result = CursorHarnessAdapter().detect(ctx)
        art = result.artifacts[0]
        assert art.transport == "http"
        assert art.url == "http://localhost:3000/mcp"
        assert art.command is None

    def test_stdio_transport_when_command_present(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_mcp_json(
            ctx.home_dir / ".cursor" / "mcp.json",
            {"local-srv": {"command": "node", "args": ["server.js"]}},
        )
        result = CursorHarnessAdapter().detect(ctx)
        art = result.artifacts[0]
        assert art.transport == "stdio"
        assert art.url is None
        assert art.command == "node"

    def test_non_string_url_ignored(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_mcp_json(
            ctx.home_dir / ".cursor" / "mcp.json",
            {"srv": {"url": 12345, "command": "node"}},
        )
        result = CursorHarnessAdapter().detect(ctx)
        art = result.artifacts[0]
        assert art.url is None
        assert art.transport == "stdio"

    def test_only_string_args_included(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_mcp_json(
            ctx.home_dir / ".cursor" / "mcp.json",
            {"srv": {"command": "node", "args": ["script.js", 8080, True]}},
        )
        result = CursorHarnessAdapter().detect(ctx)
        assert result.artifacts[0].args == ("script.js",)


class TestCursorDetectResiliency:
    def test_malformed_json_file_yields_no_artifacts(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        mcp = ctx.home_dir / ".cursor" / "mcp.json"
        mcp.parent.mkdir(parents=True, exist_ok=True)
        mcp.write_text("{ not valid json }", encoding="utf-8")
        result = CursorHarnessAdapter().detect(ctx)
        assert result.artifacts == ()

    def test_mcp_servers_non_dict_value_skipped(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        mcp = ctx.home_dir / ".cursor" / "mcp.json"
        mcp.parent.mkdir(parents=True, exist_ok=True)
        mcp.write_text(json.dumps({"mcpServers": {"bad": "not-a-dict"}}), encoding="utf-8")
        result = CursorHarnessAdapter().detect(ctx)
        assert result.artifacts == ()

    def test_mcp_servers_with_integer_key_in_json_treated_as_string(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        mcp = ctx.home_dir / ".cursor" / "mcp.json"
        mcp.parent.mkdir(parents=True, exist_ok=True)
        mcp.write_text(json.dumps({"mcpServers": {123: {"command": "x"}}}), encoding="utf-8")
        result = CursorHarnessAdapter().detect(ctx)
        assert len(result.artifacts) == 1
        assert result.artifacts[0].artifact_id == "cursor:global:123"

    def test_missing_config_files_dont_crash_detect(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        result = CursorHarnessAdapter().detect(ctx)
        assert isinstance(result.artifacts, tuple)

    def test_non_string_command_stored_as_none(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        mcp = ctx.home_dir / ".cursor" / "mcp.json"
        mcp.parent.mkdir(parents=True, exist_ok=True)
        mcp.write_text(json.dumps({"mcpServers": {"srv": {"command": 42}}}), encoding="utf-8")
        result = CursorHarnessAdapter().detect(ctx)
        assert result.artifacts[0].command is None


class TestCursorDiagnosticWarnings:
    def test_no_warnings_when_no_artifacts(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        detection = CursorHarnessAdapter().detect(ctx)
        warnings = CursorHarnessAdapter().diagnostic_warnings(detection, None)
        assert warnings == []

    def test_warning_when_cursor_cli_reports_zero_but_artifacts_found(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_mcp_json(ctx.home_dir / ".cursor" / "mcp.json", {"s": {"command": "x"}})
        detection = CursorHarnessAdapter().detect(ctx)
        runtime_probe = {"reported_artifacts": 0, "returncode": 0}
        warnings = CursorHarnessAdapter().diagnostic_warnings(detection, runtime_probe)
        assert any("Cursor CLI reported no MCP servers" in w for w in warnings)

    def test_no_warning_when_cursor_cli_count_matches(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_mcp_json(ctx.home_dir / ".cursor" / "mcp.json", {"s": {"command": "x"}})
        detection = CursorHarnessAdapter().detect(ctx)
        runtime_probe = {"reported_artifacts": 1, "returncode": 0}
        warnings = CursorHarnessAdapter().diagnostic_warnings(detection, runtime_probe)
        assert not any("Cursor CLI reported no MCP servers" in w for w in warnings)

    def test_no_warning_when_runtime_probe_is_none(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_mcp_json(ctx.home_dir / ".cursor" / "mcp.json", {"s": {"command": "x"}})
        detection = CursorHarnessAdapter().detect(ctx)
        warnings = CursorHarnessAdapter().diagnostic_warnings(detection, None)
        assert not any("Cursor CLI reported no MCP servers" in w for w in warnings)


class TestCursorAdapterContract:
    def test_adapter_has_setup_contract(self) -> None:
        contract = CursorHarnessAdapter().setup_contract()
        assert contract.harness == "cursor"
        assert contract.display_name

    def test_adapter_has_connect_step(self) -> None:
        contract = CursorHarnessAdapter().setup_contract()
        step_ids = {s.step_id for s in contract.setup_steps}
        assert "connect" in step_ids

    def test_artifact_risk_includes_mcp_server(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_mcp_json(
            ctx.home_dir / ".cursor" / "mcp.json",
            {"remote": {"url": "http://example.com/mcp"}},
        )
        result = CursorHarnessAdapter().detect(ctx)
        assert len(result.artifacts) == 1
        art = result.artifacts[0]
        assert art.artifact_type == "mcp_server"
