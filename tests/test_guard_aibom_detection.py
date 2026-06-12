from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor import CursorHarnessAdapter
from codex_plugin_scanner.guard.adapters.hermes import HermesHarnessAdapter
from codex_plugin_scanner.guard.adapters.openclaw import OpenClawHarnessAdapter
from codex_plugin_scanner.guard.aibom_detection import (
    INVENTORY_ITEM_KINDS,
    discover_codex_skill_artifacts,
    discover_shared_workspace_aibom_artifacts,
    extend_detection_with_workspace_aibom,
    file_content_hash,
    instruction_role_for_path,
)
from codex_plugin_scanner.guard.consumer.service import artifact_hash, diff_artifact
from codex_plugin_scanner.guard.inventory_contract import inventory_snapshot_from_detection
from codex_plugin_scanner.guard.models import HarnessDetection


def test_inventory_item_kinds_align_with_portal_contract() -> None:
    portal_kinds = {
        "agent",
        "daemon_plugin",
        "harness",
        "model_provider",
        "package",
        "prompt_pack",
        "skill",
        "mcp_server",
        "mcp_tool",
        "plugin",
        "channel",
        "hook",
        "overlay",
        "repository",
        "container_image",
        "policy",
        "secret_reference",
        "network_endpoint",
    }
    assert set(INVENTORY_ITEM_KINDS) == portal_kinds


def test_discover_agents_md_and_cursor_rules(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    agents_md = workspace / "AGENTS.md"
    agents_md.write_text("# Agent rules\nAlways use tests.\n", encoding="utf-8")
    rules_dir = workspace / ".cursor" / "rules"
    rules_dir.mkdir(parents=True)
    (rules_dir / "typescript.mdc").write_text("Use strict TS.\n", encoding="utf-8")

    artifacts = discover_shared_workspace_aibom_artifacts(
        "cursor",
        home_dir=tmp_path,
        workspace_dir=workspace,
    )
    kinds = {artifact.artifact_type for artifact in artifacts}
    roles = {
        artifact.metadata.get("instructionRole")
        for artifact in artifacts
        if isinstance(artifact.metadata, dict)
    }

    assert "instruction" in kinds
    assert "agents_md" in roles
    assert "cursor_rules" in roles


def test_discover_codex_skills_and_marketplace_plugins(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    plugin_dir = workspace / "plugins" / "demo"
    plugin_manifest = plugin_dir / ".codex-plugin" / "plugin.json"
    plugin_manifest.parent.mkdir(parents=True, exist_ok=True)
    plugin_manifest.write_text('{"name":"demo"}\n', encoding="utf-8")

    marketplace_dir = workspace / ".agents" / "plugins"
    marketplace_dir.mkdir(parents=True)
    (marketplace_dir / "marketplace.json").write_text(
        json.dumps(
            {
                "name": "demo-market",
                "plugins": [{"name": "demo", "source": {"source": "local", "path": "./plugins/demo"}}],
            }
        ),
        encoding="utf-8",
    )

    skill_root = workspace / ".agents" / "skills" / "lint"
    skill_root.mkdir(parents=True)
    (skill_root / "SKILL.md").write_text("---\nname: lint\n---\n", encoding="utf-8")

    shared_artifacts = discover_shared_workspace_aibom_artifacts(
        "codex",
        home_dir=tmp_path,
        workspace_dir=workspace,
    )
    skill_artifacts = discover_codex_skill_artifacts(
        "codex",
        home_dir=tmp_path,
        workspace_dir=workspace,
    )

    assert "plugin" in {artifact.artifact_type for artifact in shared_artifacts}
    assert "skill" in {artifact.artifact_type for artifact in skill_artifacts}


def test_content_hash_detects_tail_changes_beyond_one_mebibyte(tmp_path: Path) -> None:
    prefix = b"A" * (1024 * 1024)
    path = tmp_path / "AGENTS.md"
    path.write_bytes(prefix + b"tail-version-one\n")
    first = file_content_hash(path)
    path.write_bytes(prefix + b"tail-version-two\n")
    second = file_content_hash(path)

    assert first is not None
    assert second is not None
    assert first != second


def test_diff_artifact_detects_tail_only_instruction_change(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    agents_md = workspace / "AGENTS.md"
    prefix = b"policy-" * (1024 * 1024 // len(b"policy-") + 1)
    prefix = prefix[: 1024 * 1024]
    agents_md.write_bytes(prefix + b"approved-tail\n")

    artifacts_v1 = discover_shared_workspace_aibom_artifacts(
        "codex",
        home_dir=tmp_path,
        workspace_dir=workspace,
    )
    artifact_v1 = next(
        (artifact for artifact in artifacts_v1 if artifact.artifact_type == "instruction"),
        None,
    )
    assert artifact_v1 is not None, "Expected an instruction artifact in v1 discovery"
    previous = {
        **artifact_v1.to_dict(),
        "artifact_hash": artifact_hash(artifact_v1),
        "env_keys": [],
    }

    agents_md.write_bytes(prefix + b"malicious-tail\n")
    artifacts_v2 = discover_shared_workspace_aibom_artifacts(
        "codex",
        home_dir=tmp_path,
        workspace_dir=workspace,
    )
    artifact_v2 = next(
        (artifact for artifact in artifacts_v2 if artifact.artifact_type == "instruction"),
        None,
    )
    assert artifact_v2 is not None, "Expected an instruction artifact in v2 discovery"

    diff = diff_artifact(previous, artifact_v2)

    assert diff["changed"] is True
    assert diff["previous_hash"] != diff["current_hash"]


def test_content_hash_changes_when_instruction_file_changes(tmp_path: Path) -> None:
    path = tmp_path / "AGENTS.md"
    path.write_text("version one\n", encoding="utf-8")
    first = file_content_hash(path)
    path.write_text("version two\n", encoding="utf-8")
    second = file_content_hash(path)

    assert first is not None
    assert second is not None
    assert first != second


def test_inventory_snapshot_includes_workspace_instructions(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    (workspace / "AGENTS.md").write_text("repo policy\n", encoding="utf-8")

    snapshot = inventory_snapshot_from_detection(
        HarnessDetection(
            harness="hermes",
            installed=True,
            command_available=False,
            config_paths=(),
            artifacts=(),
        ),
        generated_at="2026-06-10T00:00:00Z",
        home_dir=tmp_path,
        workspace_dir=workspace,
    )

    overlay_items = [item for item in snapshot.items if item.item_kind == "overlay"]
    assert len(overlay_items) == 1
    assert overlay_items[0].metadata.get("instructionRole") == "agents_md"


def test_hermes_and_openclaw_inventory_snapshots_include_workspace_agents_md(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    (workspace / "AGENTS.md").write_text("shared policy\n", encoding="utf-8")
    hermes_home = tmp_path / "home" / ".hermes"
    hermes_home.mkdir(parents=True)
    (hermes_home / "config.yaml").write_text("mcp_servers: {}\n", encoding="utf-8")
    openclaw_home = tmp_path / "home" / ".openclaw"
    openclaw_home.mkdir(parents=True)
    (openclaw_home / "openclaw.json").write_text(
        '{"gateway":{"mode":"local"},"agents":{"defaults":{}},"channels":{},"mcpServers":{}}\n',
        encoding="utf-8",
    )
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace,
        guard_home=tmp_path / ".hol-guard",
    )

    for adapter in (HermesHarnessAdapter(), OpenClawHarnessAdapter()):
        snapshot = adapter.inventory_snapshot(context, generated_at="2026-06-10T00:00:00Z")
        overlay_items = [item for item in snapshot.items if item.item_kind == "overlay"]
        assert any(item.metadata.get("instructionRole") == "agents_md" for item in overlay_items)


def test_instruction_role_ignores_unrelated_rules_paths(tmp_path: Path) -> None:
    unrelated = tmp_path / "src" / "rules" / "guide.md"
    unrelated.parent.mkdir(parents=True)
    unrelated.write_text("not cursor\n", encoding="utf-8")
    cursor_rule = tmp_path / ".cursor" / "rules" / "typescript.mdc"
    cursor_rule.parent.mkdir(parents=True)
    cursor_rule.write_text("cursor rule\n", encoding="utf-8")

    assert instruction_role_for_path(unrelated) is None
    assert instruction_role_for_path(cursor_rule) == "cursor_rules"


def test_marketplace_escape_path_does_not_read_outside_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "plugin.json").write_text('{"name":"evil"}\n', encoding="utf-8")

    marketplace_dir = workspace / ".agents" / "plugins"
    marketplace_dir.mkdir(parents=True)
    (marketplace_dir / "marketplace.json").write_text(
        json.dumps(
            {
                "name": "demo-market",
                "plugins": [
                    {
                        "name": "evil",
                        "source": {"source": "local", "path": "./../../outside"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    artifacts = discover_shared_workspace_aibom_artifacts(
        "codex",
        home_dir=tmp_path,
        workspace_dir=workspace,
    )
    evil_plugins = [artifact for artifact in artifacts if artifact.name == "evil"]

    assert len(evil_plugins) == 1
    assert "content_hash" not in evil_plugins[0].metadata


def test_extend_detection_does_not_mark_harness_installed_from_workspace_files(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    (workspace / "AGENTS.md").write_text("policy\n", encoding="utf-8")

    extended = extend_detection_with_workspace_aibom(
        HarnessDetection(
            harness="codex",
            installed=False,
            command_available=False,
            config_paths=(),
            artifacts=(),
        ),
        home_dir=tmp_path,
        workspace_dir=workspace,
    )

    assert extended.installed is False
    assert any(artifact.artifact_type == "instruction" for artifact in extended.artifacts)


def test_cursor_detect_extends_workspace_aibom(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    (workspace / "AGENTS.md").write_text("policy\n", encoding="utf-8")
    context = HarnessContext(home_dir=tmp_path, workspace_dir=workspace, guard_home=tmp_path / ".hol-guard")

    detection = CursorHarnessAdapter().detect(context)
    extended = extend_detection_with_workspace_aibom(
        detection,
        home_dir=context.home_dir,
        workspace_dir=context.workspace_dir,
    )

    assert any(
        artifact.artifact_type == "instruction"
        for artifact in extended.artifacts
    )
