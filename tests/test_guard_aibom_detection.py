from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import aibom_detection
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.cursor import CursorHarnessAdapter
from codex_plugin_scanner.guard.adapters.hermes import HermesHarnessAdapter
from codex_plugin_scanner.guard.adapters.openclaw import OpenClawHarnessAdapter
from codex_plugin_scanner.guard.aibom_detection import (
    INVENTORY_ITEM_KINDS,
    NativeAibomError,
    discover_codex_skill_artifacts,
    discover_shared_workspace_aibom_artifacts,
    extend_codex_runtime_inventory,
    extend_detection_with_workspace_aibom,
    instruction_role_for_path,
)
from codex_plugin_scanner.guard.consumer.service import artifact_hash, diff_artifact
from codex_plugin_scanner.guard.inventory_contract import (
    inventory_snapshot_from_detection,
    serialize_inventory_snapshot,
)
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError


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
    roles = {artifact.metadata.get("instructionRole") for artifact in artifacts if isinstance(artifact.metadata, dict)}

    assert "instruction" in kinds
    assert "agents_md" in roles
    assert "cursor_rules" in roles


def test_instruction_role_for_path_recognizes_standards_files() -> None:
    assert instruction_role_for_path(Path("PRODUCT.md")) == "product_md"
    assert instruction_role_for_path(Path("DESIGN.md")) == "design_md"
    assert instruction_role_for_path(Path("CLAUDE.md")) == "claude_md"
    assert instruction_role_for_path(Path("docs/PRODUCT.md")) == "product_md"


def test_discover_standards_context_files_in_root_and_fallback_dirs(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    (workspace / "PRODUCT.md").write_text("# Product\n", encoding="utf-8")
    (workspace / "DESIGN.md").write_text("# Design\n", encoding="utf-8")
    (workspace / "CLAUDE.md").write_text("# Claude\n", encoding="utf-8")

    context_dir = workspace / ".agents" / "context"
    context_dir.mkdir(parents=True)
    (context_dir / "PRODUCT.md").write_text("# Product context\n", encoding="utf-8")

    docs_dir = workspace / "docs"
    docs_dir.mkdir()
    (docs_dir / "DESIGN.md").write_text("# Design docs\n", encoding="utf-8")

    artifacts = discover_shared_workspace_aibom_artifacts(
        "codex",
        home_dir=tmp_path,
        workspace_dir=workspace,
    )
    roles = {
        artifact.metadata.get("instructionRole")
        for artifact in artifacts
        if artifact.artifact_type == "instruction" and isinstance(artifact.metadata, dict)
    }
    names = {artifact.name for artifact in artifacts if artifact.artifact_type == "instruction"}

    assert roles == {"product_md", "design_md", "claude_md"}
    assert "PRODUCT.md (.agents/context)" in names
    assert "DESIGN.md (docs)" in names


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


def _agents_md_content_hash(workspace: Path) -> object:
    artifacts = discover_shared_workspace_aibom_artifacts("codex", home_dir=workspace / "home", workspace_dir=workspace)
    (agents_md,) = [artifact for artifact in artifacts if artifact.name == "AGENTS.md"]
    return agents_md.metadata["content_hash"]


def test_content_hash_detects_tail_changes_beyond_one_mebibyte(tmp_path: Path) -> None:
    prefix = b"A" * (1024 * 1024)
    path = tmp_path / "AGENTS.md"
    path.write_bytes(prefix + b"tail-version-one\n")
    first = _agents_md_content_hash(tmp_path)
    path.write_bytes(prefix + b"tail-version-two\n")
    second = _agents_md_content_hash(tmp_path)

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
    first = _agents_md_content_hash(tmp_path)
    path.write_text("version two\n", encoding="utf-8")
    second = _agents_md_content_hash(tmp_path)

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
    assert overlay_items[0].description


def test_inventory_snapshot_items_include_descriptions(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    skill_dir = workspace / "skills" / "review"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: review\ndescription: Review code changes carefully.\n---\n",
        encoding="utf-8",
    )

    snapshot = inventory_snapshot_from_detection(
        HarnessDetection(
            harness="hermes",
            installed=True,
            command_available=False,
            config_paths=(),
            artifacts=(
                GuardArtifact(
                    artifact_id="hermes:skill:review:review",
                    name="review",
                    harness="hermes",
                    artifact_type="skill",
                    source_scope="workspace",
                    config_path=str(skill_dir / "SKILL.md"),
                    metadata={"description": "Review code changes carefully."},
                ),
            ),
        ),
        generated_at="2026-06-10T00:00:00Z",
        home_dir=tmp_path,
        workspace_dir=workspace,
    )

    skill_items = [item for item in snapshot.items if item.item_kind == "skill"]
    assert skill_items
    assert "Review code changes carefully." in skill_items[0].description

    payload = serialize_inventory_snapshot(snapshot)
    payload_items = payload["items"]
    assert isinstance(payload_items, list)
    first_payload_item = payload_items[0]
    assert isinstance(first_payload_item, dict)
    assert first_payload_item["description"] == skill_items[0].description


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


def test_discover_named_instruction_docs(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    (workspace / "DESIGN.md").write_text("# Design\n", encoding="utf-8")
    (workspace / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    standards_dir = workspace / "docs" / "standards"
    standards_dir.mkdir(parents=True)
    (standards_dir / "api.md").write_text("# Standards\n", encoding="utf-8")
    policies_dir = workspace / "docs" / "policies"
    policies_dir.mkdir(parents=True)
    (policies_dir / "access.md").write_text("# Policy\n", encoding="utf-8")

    artifacts = discover_shared_workspace_aibom_artifacts(
        "cursor",
        home_dir=tmp_path,
        workspace_dir=workspace,
    )
    roles = {artifact.metadata.get("instructionRole") for artifact in artifacts if isinstance(artifact.metadata, dict)}

    assert "design_md" in roles
    assert "security_md" in roles
    assert "standards_md" in roles
    assert "policy_md" in roles


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


def test_extend_detection_replaces_legacy_rules_collision_with_workspace_claude_md(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    root_claude_md = workspace / "CLAUDE.md"
    root_claude_md.write_text("# root instructions\n", encoding="utf-8")
    legacy_rule = workspace / ".claude" / "rules" / "claude-md.md"
    legacy_rule.parent.mkdir(parents=True)
    legacy_rule.write_text("# legacy rule id\n", encoding="utf-8")

    base = HarnessDetection(
        harness="claude-code",
        installed=True,
        command_available=True,
        config_paths=(str(legacy_rule),),
        artifacts=(
            GuardArtifact(
                artifact_id="claude-code:project:instruction:claude-md",
                name="claude-md",
                harness="claude-code",
                artifact_type="instruction",
                source_scope="project",
                config_path=str(legacy_rule),
                metadata={"instructionRole": "cursor_rules"},
            ),
        ),
    )
    extended = extend_detection_with_workspace_aibom(
        base,
        home_dir=tmp_path,
        workspace_dir=workspace,
    )
    artifacts = {artifact.artifact_id: artifact for artifact in extended.artifacts}

    assert artifacts["claude-code:project:instruction:claude-md"].config_path == str(root_claude_md)
    assert artifacts["claude-code:project:instruction:claude-md"].metadata.get("instructionRole") == "claude_md"


def test_extend_detection_does_not_replace_colliding_mcp_server_with_claude_md(
    tmp_path: Path,
    native_context_digest: Path,
) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    (workspace / "CLAUDE.md").write_text("# root instructions\n", encoding="utf-8")
    mcp_config = workspace / ".mcp.json"
    mcp_config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "instruction:claude-md": {
                        "command": "python3",
                        "args": ["-m", "http.server", "9000"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    context = HarnessContext(home_dir=tmp_path, workspace_dir=workspace, guard_home=tmp_path / ".hol-guard")
    detection = ClaudeCodeHarnessAdapter().detect(context)
    artifacts = {artifact.artifact_id: artifact for artifact in detection.artifacts}

    assert artifacts["claude-code:project:mcp:instruction:claude-md"].artifact_type == "mcp_server"
    assert artifacts["claude-code:project:instruction:claude-md"].artifact_type == "instruction"


def test_extend_detection_prefers_workspace_root_claude_md_on_legacy_id_collision(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    root_claude_md = workspace / "CLAUDE.md"
    root_claude_md.write_text("# root instructions\n", encoding="utf-8")
    colliding_rule = workspace / ".claude" / "rules" / "claude-md.md"
    colliding_rule.parent.mkdir(parents=True)
    colliding_rule.write_text("# colliding rule\n", encoding="utf-8")

    context = HarnessContext(home_dir=tmp_path, workspace_dir=workspace, guard_home=tmp_path / ".hol-guard")
    detection = ClaudeCodeHarnessAdapter().detect(context)
    artifacts = {artifact.artifact_id: artifact for artifact in detection.artifacts}

    assert artifacts["claude-code:project:instruction:claude-md"].config_path == str(root_claude_md)
    assert artifacts["claude-code:project:instruction:rules-claude-md"].config_path == str(colliding_rule)


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

    assert any(artifact.artifact_type == "instruction" for artifact in extended.artifacts)


def test_workspace_skills_excluded_for_hermes(tmp_path: Path) -> None:
    """Hermes uses ~/.hermes/skills/, not .agents/skills/.

    Workspace-level ``.agents/skills/`` is a Codex/OpenClaw convention.
    Hermes (and other harnesses that don't natively scan it) must not pick
    up those skills in their inventory snapshots, otherwise skills from
    one harness leak into another harness's Protection Graph.
    """
    workspace = tmp_path / "repo"
    workspace.mkdir()
    skill_dir = workspace / ".agents" / "skills" / "bare-metal-server"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: bare-metal-server\ndescription: test\n---\nbody\n",
        encoding="utf-8",
    )

    # Hermes must NOT discover .agents/skills/
    hermes_artifacts = discover_shared_workspace_aibom_artifacts(
        "hermes",
        home_dir=tmp_path,
        workspace_dir=workspace,
    )
    hermes_skill_names = {a.name for a in hermes_artifacts if a.artifact_type == "skill"}
    assert "bare-metal-server" not in hermes_skill_names

    # Codex and OpenClaw SHOULD discover .agents/skills/
    for harness in ("codex", "openclaw"):
        artifacts = discover_shared_workspace_aibom_artifacts(
            harness,
            home_dir=tmp_path,
            workspace_dir=workspace,
        )
        skill_names = {a.name for a in artifacts if a.artifact_type == "skill"}
        assert "bare-metal-server" in skill_names, f"{harness} should discover .agents/skills/"

    # Copilot also doesn't use .agents/skills/
    for harness in ("copilot",):
        artifacts = discover_shared_workspace_aibom_artifacts(
            harness,
            home_dir=tmp_path,
            workspace_dir=workspace,
        )
        skill_names = {a.name for a in artifacts if a.artifact_type == "skill"}
        assert "bare-metal-server" not in skill_names, f"{harness} should not discover .agents/skills/"


def test_workspace_skills_excluded_for_hermes_inventory_snapshot(tmp_path: Path) -> None:
    """Full inventory snapshot for Hermes must not include workspace .agents/skills/."""
    workspace = tmp_path / "repo"
    workspace.mkdir()
    skill_dir = workspace / ".agents" / "skills" / "bare-metal-server"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: bare-metal-server\ndescription: test\n---\nbody\n",
        encoding="utf-8",
    )
    context = HarnessContext(
        home_dir=tmp_path,
        workspace_dir=workspace,
        guard_home=tmp_path / ".guard",
    )
    snapshot = HermesHarnessAdapter().inventory_snapshot(
        context,
        generated_at="2026-01-01T00:00:00Z",
    )
    skill_names = {
        item.metadata.get("skill_name") or item.display_name for item in snapshot.items if item.item_kind == "skill"
    }
    assert "bare-metal-server" not in skill_names


def _unavailable_native(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(kind: str, args: object, guard_home: object = None, **_kwargs: object) -> dict[str, object]:
        raise NativeRunnerAuthorityError("native_runner_authority_unavailable")

    monkeypatch.setattr(aibom_detection, "native_runner_authority", refuse)


def _recording_native(
    monkeypatch: pytest.MonkeyPatch,
    answer: dict[str, object],
) -> list[tuple[str, dict[str, object]]]:
    calls: list[tuple[str, dict[str, object]]] = []

    def answer_with(
        kind: str, args: dict[str, object], guard_home: object = None, **kwargs: object
    ) -> dict[str, object]:
        calls.append((kind, {**args, **kwargs}))
        return answer

    monkeypatch.setattr(aibom_detection, "native_runner_authority", answer_with)
    return calls


def _detection(
    *artifacts: GuardArtifact,
    config_paths: tuple[str, ...] = (),
    harness: str = "claude-code",
) -> HarnessDetection:
    return HarnessDetection(
        harness=harness,
        installed=True,
        command_available=True,
        config_paths=config_paths,
        artifacts=artifacts,
        warnings=(),
    )


def test_discovery_fails_closed_when_native_is_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _unavailable_native(monkeypatch)
    (tmp_path / "AGENTS.md").write_text("instructions\n", encoding="utf-8")

    with pytest.raises(NativeAibomError, match="native_runner_authority_unavailable"):
        discover_shared_workspace_aibom_artifacts("codex", home_dir=tmp_path, workspace_dir=tmp_path)
    with pytest.raises(NativeAibomError):
        discover_codex_skill_artifacts("codex", home_dir=tmp_path, workspace_dir=tmp_path)
    with pytest.raises(NativeAibomError):
        extend_detection_with_workspace_aibom(_detection(), home_dir=tmp_path, workspace_dir=tmp_path)
    with pytest.raises(NativeAibomError):
        extend_codex_runtime_inventory(_detection(harness="codex"), home_dir=tmp_path, workspace_dir=tmp_path)


def test_merge_applies_native_plan_to_callers_artifacts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def wire(artifact_id: str, config_path: str) -> dict[str, object]:
        return {
            "artifact_id": artifact_id,
            "name": artifact_id,
            "harness": "claude-code",
            "artifact_type": "instruction",
            "source_scope": "project",
            "config_path": config_path,
            "command": None,
            "args": [],
            "url": None,
            "transport": None,
            "publisher": None,
            "metadata": {"instructionRole": "claude_md"},
        }

    kept = GuardArtifact(
        artifact_id="kept",
        name="kept",
        harness="claude-code",
        artifact_type="mcp_server",
        source_scope="project",
        config_path="/kept",
        runtime_private_metadata={"signed_url": "private"},
    )
    replaced = GuardArtifact(
        artifact_id="rules-old",
        name="old",
        harness="claude-code",
        artifact_type="instruction",
        source_scope="project",
        config_path="/old",
    )
    calls = _recording_native(
        monkeypatch,
        {
            "extra_count": 2,
            "replacements": [{"index": 1, "artifact": wire("rules-old", "/new/CLAUDE.md")}],
            "appended": [wire("added", "/new/AGENTS.md")],
            "found_paths": ["/new/CLAUDE.md", "/new/AGENTS.md"],
        },
    )

    merged = extend_detection_with_workspace_aibom(
        _detection(kept, replaced, config_paths=("/kept", "/new/AGENTS.md")),
        home_dir=tmp_path,
        workspace_dir=tmp_path,
    )

    assert [artifact.artifact_id for artifact in merged.artifacts] == ["kept", "rules-old", "added"]
    assert merged.artifacts[0] is kept
    assert merged.artifacts[0].runtime_private_metadata == {"signed_url": "private"}
    assert merged.artifacts[1].config_path == "/new/CLAUDE.md"
    assert merged.config_paths == ("/kept", "/new/AGENTS.md", "/new/CLAUDE.md")
    kind, request = calls[0]
    assert kind == "aibom_workspace_plan"
    assert request["workspace_dir"] == str(tmp_path)
    assert request["existing"] == [
        {"artifact_id": "kept", "artifact_type": "mcp_server", "harness": "claude-code", "config_path": "/kept"},
        {"artifact_id": "rules-old", "artifact_type": "instruction", "harness": "claude-code", "config_path": "/old"},
    ]


def test_merge_returns_detection_unchanged_when_native_finds_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _recording_native(monkeypatch, {"extra_count": 0, "replacements": [], "appended": [], "found_paths": []})
    detection = _detection()

    assert extend_detection_with_workspace_aibom(detection, home_dir=tmp_path, workspace_dir=tmp_path) is detection


@pytest.mark.parametrize(
    "answer",
    [
        {},
        {"artifacts": "not-a-list"},
        {"artifacts": [{"artifact_id": "x"}]},
        {"artifacts": [{"artifact_id": 1}]},
    ],
)
def test_malformed_native_answers_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: dict[str, object]
) -> None:
    _recording_native(monkeypatch, answer)

    with pytest.raises(NativeAibomError, match="native_runner_authority_result_invalid"):
        discover_shared_workspace_aibom_artifacts("codex", home_dir=tmp_path, workspace_dir=tmp_path)


def test_malformed_merge_plans_are_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for plan in (
        {"extra_count": 1, "replacements": [{"index": 5, "artifact": {}}], "appended": [], "found_paths": []},
        {"extra_count": 1, "replacements": [], "appended": [], "found_paths": [3]},
        {"extra_count": "1", "replacements": [], "appended": [], "found_paths": []},
    ):
        _recording_native(monkeypatch, plan)
        with pytest.raises(NativeAibomError):
            extend_detection_with_workspace_aibom(_detection(), home_dir=tmp_path, workspace_dir=tmp_path)


def test_portable_walk_ships_finished_skills_to_native(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Hosts the resident cannot walk (Windows) send Python-built skill artifacts."""

    workspace = tmp_path / "work"
    home = tmp_path / "home"
    (workspace / ".agents" / "skills" / "proj").mkdir(parents=True)
    (workspace / ".agents" / "skills" / "proj" / "SKILL.md").write_text("# proj\n", encoding="utf-8")
    (home / ".codex" / "skills" / "glob").mkdir(parents=True)
    (home / ".codex" / "skills" / "glob" / "SKILL.md").write_text("# glob\n", encoding="utf-8")
    monkeypatch.setattr(aibom_detection, "_needs_portable_walk", lambda: True)
    calls = _recording_native(monkeypatch, {"artifacts": []})

    discover_shared_workspace_aibom_artifacts("codex", home_dir=home, workspace_dir=workspace)
    discover_codex_skill_artifacts("codex", home_dir=home, workspace_dir=workspace)
    discover_shared_workspace_aibom_artifacts("hermes", home_dir=home, workspace_dir=workspace)

    workspace_request = calls[0][1]
    (project,) = workspace_request["skills"]
    assert project["artifact_id"] == "codex:project:skill:.agents/skills:proj"
    assert project["source_scope"] == "project"
    assert project["config_path"] == str(workspace.resolve() / ".agents" / "skills" / "proj" / "SKILL.md")
    codex_request = calls[1][1]
    assert [item["name"] for item in codex_request["project_skills"]] == ["proj"]
    assert [item["name"] for item in codex_request["global_skills"]] == ["glob"]
    assert "skills" not in calls[2][1]


def test_native_walk_is_used_when_the_host_supports_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(aibom_detection, "_needs_portable_walk", lambda: False)
    calls = _recording_native(monkeypatch, {"artifacts": []})

    discover_shared_workspace_aibom_artifacts("codex", home_dir=tmp_path, workspace_dir=tmp_path)
    discover_codex_skill_artifacts("codex", home_dir=tmp_path, workspace_dir=None)

    assert "skills" not in calls[0][1]
    assert calls[1][1]["workspace_dir"] is None
    assert "project_skills" not in calls[1][1]
    assert "global_skills" not in calls[1][1]
