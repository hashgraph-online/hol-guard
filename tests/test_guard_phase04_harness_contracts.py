"""Phase 04 harness contract and install matrix proof tests."""

from __future__ import annotations

import json
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

from codex_plugin_scanner.guard import native_harness_ops as harness_ops
from codex_plugin_scanner.guard.claude_hook_entry import CLAUDE_GUARD_DAEMON_HOOK_MARKER
from codex_plugin_scanner.guard.cli.install_commands import list_harness_setup_items
from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.store import GuardStore
from tests import harness_ops_support as harness_support


def _context(tmp_path: Path) -> HarnessContext:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )


def _read_codex_hooks(config_path: Path) -> dict[str, object]:
    with config_path.open("rb") as handle:
        hooks = tomllib.load(handle).get("hooks")
    assert isinstance(hooks, dict)
    return hooks


def test_gr091_cursor_adapter_detects_workspace_mcp_smoke(tmp_path: Path) -> None:
    context = _context(tmp_path)
    config_path = context.workspace_dir / ".cursor" / "mcp.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        json.dumps({"mcpServers": {"team-tools": {"command": "node", "args": ["server.js"]}}}),
        encoding="utf-8",
    )

    detection = harness_ops.detect("cursor", context)

    assert detection.installed is True
    assert detection.artifacts[0].harness == "cursor"
    assert detection.artifacts[0].artifact_type == "mcp_server"


def test_gr092_gemini_adapter_detects_cli_settings_smoke(tmp_path: Path) -> None:
    context = _context(tmp_path)
    settings_path = context.workspace_dir / ".gemini" / "settings.json"
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(
        json.dumps({"mcpServers": {"team-tools": {"command": "node", "args": ["server.js"]}}}),
        encoding="utf-8",
    )

    detection = harness_ops.detect("gemini", context)

    assert detection.installed is True
    assert detection.artifacts[0].harness == "gemini"
    assert detection.artifacts[0].artifact_type == "mcp_server"


def test_gr093_harness_install_matrix_exposes_statuses_and_coverage(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    store.set_managed_install(
        "codex",
        True,
        str(context.workspace_dir),
        {"managed_hooks_path": str(context.workspace_dir / ".codex" / "hooks.json")},
        "2026-05-12T00:00:00+00:00",
    )
    (context.home_dir / ".cursor").mkdir(parents=True, exist_ok=True)
    (context.home_dir / ".cursor" / "mcp.json").write_text(
        json.dumps({"mcpServers": {"team-tools": {"command": "node"}}}),
        encoding="utf-8",
    )

    items = list_harness_setup_items(context, store)
    by_harness = {str(item["harness"]): item for item in items}

    assert by_harness["codex"]["status"] == "protected"
    assert by_harness["cursor"]["status"] == "found"
    assert by_harness["openclaw"]["status"] == "not_found"
    assert by_harness["codex"]["coverage"]["native_hooks"] is True
    assert by_harness["cursor"]["coverage"]["browser_fallback"] is True


def test_gr094_inactive_harness_copy_says_observed_not_protected(tmp_path: Path) -> None:
    context = _context(tmp_path)
    cursor_config = context.home_dir / ".cursor" / "mcp.json"
    cursor_config.parent.mkdir(parents=True, exist_ok=True)
    cursor_config.write_text(json.dumps({"mcpServers": {"team-tools": {"command": "node"}}}), encoding="utf-8")

    items = list_harness_setup_items(context, GuardStore(context.guard_home))
    cursor_item = next(item for item in items if item["harness"] == "cursor")

    assert cursor_item["status"] == "found"
    assert cursor_item["installed"] is False
    assert cursor_item["observed_copy"] == "Observed locally, not protected by Guard yet."


def test_gr096_managed_hook_json_matches_each_harness_schema(tmp_path: Path) -> None:
    context = _context(tmp_path)

    codex_manifest = harness_support.install("codex", context)
    harness_support.install("claude-code", context)
    opencode_config = context.home_dir / ".config" / "opencode" / "opencode.json"
    opencode_config.parent.mkdir(parents=True, exist_ok=True)
    opencode_config.write_text(
        json.dumps({"mcp": {"team-tools": {"type": "local", "command": ["node", "server.js"]}}}),
        encoding="utf-8",
    )
    opencode_manifest = harness_support.install("opencode", context)
    harness_support.install("copilot", context)

    codex_hooks = _read_codex_hooks(Path(str(codex_manifest["managed_hook_config_path"])))
    claude_hooks = json.loads((context.home_dir / ".claude" / "settings.json").read_text(encoding="utf-8"))["hooks"]
    opencode_runtime = json.loads(Path(str(opencode_manifest["runtime_config_path"])).read_text(encoding="utf-8"))
    copilot_hooks = json.loads((context.workspace_dir / ".github" / "hooks" / "hol-guard-copilot.json").read_text())

    assert {"PreToolUse", "PermissionRequest", "UserPromptSubmit", "PostToolUse"}.issubset(codex_hooks)
    assert claude_hooks["PreToolUse"][0]["hooks"][0]["type"] == "command"
    assert CLAUDE_GUARD_DAEMON_HOOK_MARKER in json.dumps(
        claude_hooks["PreToolUse"][0]["hooks"][0],
        ensure_ascii=False,
    )
    assert opencode_runtime["permission"]
    assert {"preToolUse", "postToolUse", "permissionRequest", "userPromptSubmitted"}.issubset(copilot_hooks["hooks"])


def test_gr099_managed_hooks_use_lightweight_cli_entrypoints(tmp_path: Path) -> None:
    context = _context(tmp_path)

    codex_manifest = harness_support.install("codex", context)
    harness_support.install("claude-code", context)
    harness_support.install("copilot", context)

    codex_hooks = _read_codex_hooks(Path(str(codex_manifest["managed_hook_config_path"])))
    claude_hooks = json.loads((context.home_dir / ".claude" / "settings.json").read_text(encoding="utf-8"))["hooks"]
    copilot_hooks = json.loads(
        (context.workspace_dir / ".github" / "hooks" / "hol-guard-copilot.json").read_text(encoding="utf-8")
    )["hooks"]
    serialized = json.dumps([codex_hooks, claude_hooks, copilot_hooks])

    assert "codex_plugin_scanner.cli" in serialized
    assert "dashboard" not in serialized.lower()
    assert "react" not in serialized.lower()
    assert "vite" not in serialized.lower()
