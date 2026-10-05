"""Tests for Codex skill enablement config resolution."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.aibom_detection import (
    discover_codex_skill_artifacts,
    extend_codex_runtime_inventory,
)
from codex_plugin_scanner.guard.codex_skill_config import (
    load_codex_skill_config_rules,
    resolve_codex_skill_enabled,
)
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime.decisions import (
    AUTHORITATIVE_DECISION_INCONSISTENT,
    evaluation_authority_error,
)
from codex_plugin_scanner.guard.runtime.runner import _detection_with_prompt_artifacts, evaluate_detection
from codex_plugin_scanner.guard.store import GuardStore

pytestmark = pytest.mark.usefixtures("native_prompt_runtime")


def test_load_codex_skill_config_rules_merges_home_and_workspace(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    (home / ".codex").mkdir()
    (workspace / ".codex").mkdir()
    (home / ".codex" / "config.toml").write_text(
        '[[skills.config]]\npath = "home-skill"\nenabled = false\n',
        encoding="utf-8",
    )
    (workspace / ".codex" / "config.toml").write_text(
        '[[skills.config]]\nname = "workspace-skill"\nenabled = false\n',
        encoding="utf-8",
    )

    rules = load_codex_skill_config_rules(home_dir=home, workspace_dir=workspace)

    assert len(rules) == 2
    assert rules[0].path == str((home / "home-skill").resolve())
    assert rules[0].enabled is False
    assert rules[1].name == "workspace-skill"
    assert rules[1].enabled is False


def test_resolve_codex_skill_enabled_matches_skill_directory_path(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    skill_md = home / ".codex" / "skills" / "lint" / "SKILL.md"
    skill_md.parent.mkdir(parents=True)
    skill_md.write_text("# lint\n", encoding="utf-8")
    (home / ".codex").mkdir(exist_ok=True)
    (home / ".codex" / "config.toml").write_text(
        f'[[skills.config]]\npath = "{skill_md.parent}"\nenabled = false\n',
        encoding="utf-8",
    )
    rules = load_codex_skill_config_rules(home_dir=home, workspace_dir=None)
    assert not resolve_codex_skill_enabled(
        config_path=str(skill_md),
        display_name="lint",
        rules=rules,
        home_dir=home,
    )


def test_resolve_codex_skill_enabled_matches_path_and_name(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    skill_md = home / ".codex" / "skills" / "lint" / "SKILL.md"
    skill_md.parent.mkdir(parents=True)
    skill_md.write_text("# lint\n", encoding="utf-8")

    assert resolve_codex_skill_enabled(
        config_path=str(skill_md),
        display_name="lint",
        rules=(),
        home_dir=home,
    )

    from codex_plugin_scanner.guard.codex_skill_config import CodexSkillConfigRule

    disabled_by_name = (CodexSkillConfigRule(enabled=False, name="lint"),)
    assert not resolve_codex_skill_enabled(
        config_path=str(skill_md),
        display_name="lint",
        rules=disabled_by_name,
        home_dir=home,
    )


def test_workspace_skill_path_rules_resolve_against_workspace_dir(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    (home / ".codex").mkdir()
    (workspace / ".codex").mkdir()
    project_skill = workspace / ".agents" / "skills" / "workspace-skill"
    project_skill.mkdir(parents=True)
    skill_md = project_skill / "SKILL.md"
    skill_md.write_text("# workspace\n", encoding="utf-8")
    (workspace / ".codex" / "config.toml").write_text(
        f'[[skills.config]]\npath = "{project_skill}"\nenabled = false\n',
        encoding="utf-8",
    )

    artifacts = discover_codex_skill_artifacts(
        "codex",
        home_dir=home,
        workspace_dir=workspace,
    )
    by_name = {artifact.name: artifact for artifact in artifacts}
    assert by_name["workspace-skill"].metadata["enabled"] is False


def test_discover_codex_skill_artifacts_applies_enablement(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    (home / ".codex").mkdir()
    (workspace / ".codex").mkdir()
    (home / ".codex" / "config.toml").write_text(
        '[[skills.config]]\nname = "global-skill"\nenabled = false\n',
        encoding="utf-8",
    )

    global_skill = home / ".codex" / "skills" / "global-skill"
    global_skill.mkdir(parents=True)
    (global_skill / "SKILL.md").write_text("# global\n", encoding="utf-8")

    project_skill = workspace / ".agents" / "skills" / "project-skill"
    project_skill.mkdir(parents=True)
    (project_skill / "SKILL.md").write_text("# project\n", encoding="utf-8")

    artifacts = discover_codex_skill_artifacts(
        "codex",
        home_dir=home,
        workspace_dir=workspace,
    )
    by_name = {artifact.name: artifact for artifact in artifacts}

    assert by_name["global-skill"].metadata["enabled"] is False
    assert by_name["project-skill"].metadata["enabled"] is True


def test_extend_codex_runtime_inventory_replaces_workspace_skills(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()

    global_skill = home / ".codex" / "skills" / "only-global"
    global_skill.mkdir(parents=True)
    (global_skill / "SKILL.md").write_text("# only\n", encoding="utf-8")

    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(),
        artifacts=(),
        warnings=(),
    )
    extended = extend_codex_runtime_inventory(
        detection,
        home_dir=home,
        workspace_dir=workspace,
    )

    assert len(extended.artifacts) == 1
    assert extended.artifacts[0].name == "only-global"
    assert extended.artifacts[0].source_scope == "global"


def test_disabled_codex_skill_is_inventory_only_during_launch(tmp_path: Path) -> None:
    def artifact(name: str, artifact_type: str, *, enabled: bool = True) -> GuardArtifact:
        return GuardArtifact(
            artifact_id=f"codex:global:{artifact_type}:{name}",
            name=name,
            harness="codex",
            artifact_type=artifact_type,
            source_scope="global",
            config_path=str(tmp_path / name),
            metadata={"enabled": enabled},
        )

    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(),
        artifacts=(
            artifact("disabled-skill", "skill", enabled=False),
            artifact("enabled-skill", "skill"),
            artifact("guard_canary", "mcp_server"),
        ),
    )
    context = HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=tmp_path / "guard")

    launch = _detection_with_prompt_artifacts(detection, context, [])

    assert [item.name for item in launch.artifacts] == ["disabled-skill", "enabled-skill", "guard_canary"]
    assert launch.artifacts[0].runtime_private_metadata["inventory_only"] is True
    assert launch.artifacts[0].metadata.get("inventory_only") is None
    assert [item.name for item in detection.artifacts] == ["disabled-skill", "enabled-skill", "guard_canary"]


def test_disabled_codex_skill_is_recorded_without_launch_review(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    artifact = GuardArtifact(
        artifact_id="codex:global:skill:disabled",
        name="disabled",
        harness="codex",
        artifact_type="skill",
        source_scope="global",
        config_path=str(tmp_path / "SKILL.md"),
        metadata={"enabled": False},
    )
    detection = HarnessDetection("codex", True, True, (), (artifact,))
    context = HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=guard_home)
    launch = _detection_with_prompt_artifacts(detection, context, [])

    result = evaluate_detection(
        launch,
        GuardStore(guard_home),
        GuardConfig(guard_home=guard_home, workspace=tmp_path, mode="prompt"),
        persist=False,
    )

    assert result["blocked"] is False
    assert result["artifacts"][0]["inventory_only"] is True
    assert result["artifacts"][0]["authoritative_decision"]["enforcement"]["launch_permitted"] is False
    assert evaluation_authority_error(result, require_launch_permitted=True) is None

    forged = {**result, "artifacts": [{**result["artifacts"][0], "artifact_type": "mcp_server"}]}
    assert evaluation_authority_error(forged, require_launch_permitted=True) == AUTHORITATIVE_DECISION_INCONSISTENT


def test_untrusted_inventory_only_metadata_cannot_skip_mcp_policy(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    artifact = GuardArtifact(
        artifact_id="codex:global:mcp:example",
        name="example",
        harness="codex",
        artifact_type="mcp_server",
        source_scope="global",
        config_path=str(tmp_path / "config.toml"),
        command="example-server",
        metadata={"inventory_only": True},
        runtime_private_metadata={"inventory_only": True},
    )
    detection = HarnessDetection("codex", True, True, (), (artifact,))

    result = evaluate_detection(
        detection,
        GuardStore(guard_home),
        GuardConfig(guard_home=guard_home, workspace=tmp_path, mode="prompt"),
        persist=False,
    )

    assert result["artifacts"][0].get("inventory_only") is not True
    assert result["artifacts"][0]["policy_action"] != "allow"
