"""Tests for Codex skill enablement config resolution."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.aibom_detection import (
    discover_codex_skill_artifacts,
    extend_codex_runtime_inventory,
)
from codex_plugin_scanner.guard.codex_skill_config import (
    load_codex_skill_config_rules,
    resolve_codex_skill_enabled,
)
from codex_plugin_scanner.guard.models import HarnessDetection


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
