"""Shared helpers for focused skill-directory identity tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.skill_directory_identity import (
    SkillDirectoryIdentity,
    SkillDirectoryIdentityLimits,
    inspect_skill_directory,
)


def make_skill(scope: Path, name: str = "example") -> Path:
    skill = scope / name / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("# Example skill\n", encoding="utf-8")
    return skill


def complete_identity(
    skill: Path,
    scope: Path,
    *,
    limits: SkillDirectoryIdentityLimits | None = None,
) -> SkillDirectoryIdentity:
    identity = (
        inspect_skill_directory(skill, scope_root=scope, limits=limits)
        if limits is not None
        else inspect_skill_directory(skill, scope_root=scope)
    )
    assert identity.status == "complete", identity
    assert identity.directory_hash is not None
    assert identity.primary_content_hash is not None
    assert identity.failure_reason is None
    assert identity.incomplete_state_hash is None
    return identity


def incomplete_identity(
    skill: Path,
    scope: Path,
    reason: str,
    *,
    limits: SkillDirectoryIdentityLimits | None = None,
) -> SkillDirectoryIdentity:
    identity = (
        inspect_skill_directory(skill, scope_root=scope, limits=limits)
        if limits is not None
        else inspect_skill_directory(skill, scope_root=scope)
    )
    assert identity.status == "incomplete", identity
    assert identity.directory_hash is None
    assert identity.failure_reason == reason
    assert identity.incomplete_state_hash is not None
    return identity


def symlink_or_skip(link: Path, target: str | Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
