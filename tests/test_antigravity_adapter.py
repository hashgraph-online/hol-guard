"""Focused Antigravity adapter skill-identity and discovery tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.antigravity import AntigravityHarnessAdapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.consumer.service import artifact_hash


def _context(tmp_path: Path, *, workspace: bool) -> HarnessContext:
    workspace_dir = tmp_path / "workspace" if workspace else None
    if workspace_dir is not None:
        workspace_dir.mkdir(parents=True)
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )


def _write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


@pytest.mark.parametrize("workspace", [False, True], ids=["global", "workspace"])
def test_antigravity_skill_identity_covers_primary_and_nested_files(tmp_path: Path, workspace: bool) -> None:
    context = _context(tmp_path, workspace=workspace)
    base_dir = context.workspace_dir if workspace else context.home_dir
    assert base_dir is not None
    skill_dir = base_dir / ".gemini" / "antigravity" / "skills" / "review"
    skill_path = skill_dir / "SKILL.md"
    script_path = skill_dir / "scripts" / "review.py"
    resource_path = skill_dir / "templates" / "nested" / "review.txt"
    _write_text(skill_path, "---\nname: review\n---\nVersion one.\n")
    _write_text(script_path, "print('one')\n")
    _write_text(resource_path, "Template one.\n")

    adapter = AntigravityHarnessAdapter()

    def detected_skill_hash() -> tuple[str, dict[str, object]]:
        detection = adapter.detect(context)
        artifact = next(
            item
            for item in detection.artifacts
            if item.artifact_id == f"antigravity:{'project' if workspace else 'global'}:skill:skills/review"
        )
        return artifact_hash(artifact), artifact.metadata

    original_hash, metadata = detected_skill_hash()
    stable_hash, stable_metadata = detected_skill_hash()

    assert original_hash == stable_hash
    assert metadata == stable_metadata
    assert isinstance(metadata.get("content_hash"), str)
    assert isinstance(metadata.get("directory_hash"), str)
    identity_metadata = metadata.get("skillDirectoryIdentity")
    assert isinstance(identity_metadata, dict)
    assert identity_metadata.get("schemaVersion") == "guard.skill-directory-identity.v1"
    assert identity_metadata.get("reusable") is True
    version_info = metadata.get("versionInfo")
    assert isinstance(version_info, dict)
    assert metadata["directory_hash"] == version_info["contentHash"]

    _write_text(skill_path, "---\nname: review\n---\nVersion two.\n")
    primary_hash, _ = detected_skill_hash()
    assert primary_hash != original_hash

    _write_text(script_path, "print('two')\n")
    script_hash, _ = detected_skill_hash()
    assert script_hash != primary_hash

    _write_text(resource_path, "Template two.\n")
    resource_hash, _ = detected_skill_hash()
    assert resource_hash != script_hash


def test_antigravity_incomplete_skill_identity_warns_without_external_path_disclosure(tmp_path: Path) -> None:
    context = _context(tmp_path, workspace=False)
    skill_dir = context.home_dir / ".gemini" / "antigravity" / "skills" / "review"
    _write_text(skill_dir / "SKILL.md", "---\nname: review\n---\n")
    outside = tmp_path / "private" / "external-reference.md"
    _write_text(outside, "outside\n")
    try:
        (skill_dir / "references").symlink_to(outside)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    result = AntigravityHarnessAdapter().detect(context)
    skill = next(item for item in result.artifacts if item.artifact_type == "skill")
    identity_metadata = skill.metadata.get("skillDirectoryIdentity")

    assert isinstance(identity_metadata, dict)
    assert identity_metadata.get("reusable") is False
    assert result.warnings
    assert all(str(outside) not in warning for warning in result.warnings)
    assert any("approval reuse is disabled" in warning for warning in result.warnings)


def test_antigravity_policy_path_workspace_and_global(tmp_path: Path) -> None:
    adapter = AntigravityHarnessAdapter()
    global_context = _context(tmp_path, workspace=False)
    assert adapter.policy_path(global_context) == global_context.home_dir / ".gemini" / "antigravity" / "mcp_config.json"

    workspace_context = _context(tmp_path, workspace=True)
    assert workspace_context.workspace_dir is not None
    assert adapter.policy_path(workspace_context) == workspace_context.workspace_dir / ".gemini" / "antigravity" / "mcp_config.json"


def test_antigravity_detect_xdg_lowercase_settings(tmp_path: Path) -> None:
    context = _context(tmp_path, workspace=False)
    settings_path = context.home_dir / ".config" / "antigravity" / "user" / "settings.json"
    _write_text(settings_path, '{"mcpServers": {"demo_server": {"command": "demo"}}}\n')

    detection = AntigravityHarnessAdapter().detect(context)
    assert any(item.artifact_type == "mcp_server" and item.name == "demo_server" for item in detection.artifacts)
    assert any("antigravity" in path.lower() and "settings.json" in path for path in detection.config_paths)


def test_antigravity_detect_plugin_skills(tmp_path: Path) -> None:
    context = _context(tmp_path, workspace=False)
    plugin_skill = (
        context.home_dir / ".gemini" / "config" / "plugins" / "my-plugin" / "skills" / "custom" / "SKILL.md"
    )
    _write_text(plugin_skill, "---\nname: custom\n---\nCustom plugin skill.\n")

    detection = AntigravityHarnessAdapter().detect(context)
    skill_artifact = next(
        (item for item in detection.artifacts if item.artifact_type == "skill" and "custom" in item.name),
        None,
    )
    assert skill_artifact is not None
    assert skill_artifact.source_scope == "global"
    identity_metadata = skill_artifact.metadata.get("skillDirectoryIdentity")
    assert isinstance(identity_metadata, dict)
    assert identity_metadata.get("reusable") is True


def test_antigravity_detect_workspace_agent_skills(tmp_path: Path) -> None:
    context = _context(tmp_path, workspace=True)
    assert context.workspace_dir is not None
    agent_skill = context.workspace_dir / ".agents" / "skills" / "team-helper" / "SKILL.md"
    _write_text(agent_skill, "---\nname: team-helper\n---\nTeam agent skill.\n")

    detection = AntigravityHarnessAdapter().detect(context)
    skill_artifact = next(
        (item for item in detection.artifacts if item.artifact_type == "skill" and "team-helper" in item.name),
        None,
    )
    assert skill_artifact is not None
    assert skill_artifact.source_scope == "project"
    identity_metadata = skill_artifact.metadata.get("skillDirectoryIdentity")
    assert isinstance(identity_metadata, dict)
    assert identity_metadata.get("reusable") is True


def test_antigravity_detect_mcp_config_and_extensions(tmp_path: Path) -> None:
    context = _context(tmp_path, workspace=False)
    ext_index = context.home_dir / ".antigravity" / "extensions" / "extensions.json"
    ext_pkg = context.home_dir / "ext" / "corp_tool" / "package.json"
    _write_text(
        ext_index,
        json.dumps(
            [
                {
                    "identifier": {"id": "corp.tool"},
                    "location": {"path": str(ext_pkg.parent)},
                    "metadata": {"publisherDisplayName": "Corp"},
                }
            ]
        ),
    )
    _write_text(ext_pkg, json.dumps({"displayName": "Corp Tool", "description": "Helper"}))
    mcp_path = context.home_dir / ".gemini" / "antigravity" / "mcp_config.json"
    _write_text(mcp_path, json.dumps({"mcpServers": {"remote": {"url": "https://mcp.corp.internal"}}}))

    detection = AntigravityHarnessAdapter().detect(context)
    assert any(item.artifact_type == "extension" and item.name == "Corp Tool" for item in detection.artifacts)
    assert any(item.artifact_type == "mcp_server" and item.name == "remote" for item in detection.artifacts)
