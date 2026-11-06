"""Discovery and deterministic race tests for skill-directory identity."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.skill_directory_identity import (
    SkillDirectoryIdentityLimits,
    discover_skill_documents,
)
from tests.skill_directory_identity_test_support import (
    incomplete_identity as _incomplete,
)
from tests.skill_directory_identity_test_support import (
    symlink_or_skip as _symlink_or_skip,
)


def test_discovery_reports_broken_and_looped_skill_roots(tmp_path: Path) -> None:
    skill_root = tmp_path / "skills"
    skill_root.mkdir()
    broken = skill_root / "broken"
    loop = skill_root / "loop"
    _symlink_or_skip(broken, "missing", directory=True)
    _symlink_or_skip(loop, loop.name, directory=True)

    discovery = discover_skill_documents(skill_root)

    assert discovery.documents == ()
    assert {issue.path: issue.failure_reason for issue in discovery.issues} == {
        broken: "symlink_broken",
        loop: "symlink_loop",
    }


def test_discovery_entry_and_depth_budgets_emit_typed_issues(tmp_path: Path) -> None:
    skill_root = tmp_path / "skills"
    (skill_root / "one").mkdir(parents=True)
    (skill_root / "two").mkdir()

    entry_limited = discover_skill_documents(
        skill_root,
        limits=SkillDirectoryIdentityLimits(max_entries=1),
    )
    depth_limited = discover_skill_documents(
        skill_root,
        limits=SkillDirectoryIdentityLimits(max_depth=0),
    )

    assert any(issue.failure_reason == "max_entries_exceeded" for issue in entry_limited.issues)
    assert depth_limited.documents == ()
    assert {issue.failure_reason for issue in depth_limited.issues} == {"max_depth_exceeded"}


@pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="requires POSIX permissions enforced for the current user",
)
def test_discovery_unreadable_grouping_directory_emits_typed_issue(tmp_path: Path) -> None:
    skill_root = tmp_path / "skills"
    unreadable = skill_root / "unreadable"
    unreadable.mkdir(parents=True)
    unreadable.chmod(0)
    try:
        discovery = discover_skill_documents(skill_root)
    finally:
        unreadable.chmod(0o700)

    assert discovery.documents == ()
    assert len(discovery.issues) == 1
    assert discovery.issues[0].path == unreadable / "SKILL.md"
    assert discovery.issues[0].failure_reason == "unreadable_entry"


@pytest.mark.parametrize(
    ("setup", "reason"),
    [
        ("missing-root", "root_missing"),
        ("root-file", "root_not_directory"),
        ("outside-scope", "symlink_escape"),
    ],
)
def test_invalid_roots_fail_closed(tmp_path: Path, setup: str, reason: str) -> None:
    scope = tmp_path / "scope"
    scope.mkdir()
    if setup == "missing-root":
        skill = scope / "missing" / "SKILL.md"
    elif setup == "root-file":
        root_file = scope / "not-a-directory"
        root_file.write_text("file", encoding="utf-8")
        skill = root_file / "SKILL.md"
    else:
        skill = tmp_path / "outside" / "SKILL.md"

    _incomplete(skill, scope, reason)
