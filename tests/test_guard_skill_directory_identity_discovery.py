"""Discovery and deterministic race tests for skill-directory identity."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import skill_directory_discovery as discovery_module
from codex_plugin_scanner.guard import skill_directory_identity as identity_module
from codex_plugin_scanner.guard.skill_directory_identity import (
    SkillDirectoryIdentityLimits,
    discover_skill_documents,
)
from tests.skill_directory_identity_test_support import (
    incomplete_identity as _incomplete,
)
from tests.skill_directory_identity_test_support import (
    make_skill as _make_skill,
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


def test_discovery_unreadable_grouping_directory_emits_typed_issue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skill_root = tmp_path / "skills"
    unreadable = skill_root / "unreadable"
    unreadable.mkdir(parents=True)
    original_scandir = discovery_module.os.scandir

    def selective_scandir(path: Path):
        if Path(path) == unreadable:
            raise PermissionError("simulated unreadable grouping directory")
        return original_scandir(path)

    monkeypatch.setattr(discovery_module.os, "scandir", selective_scandir)

    discovery = discover_skill_documents(skill_root)

    assert discovery.documents == ()
    assert len(discovery.issues) == 1
    assert discovery.issues[0].path == unreadable
    assert discovery.issues[0].failure_reason == "unreadable_entry"


def test_discovery_iterator_failure_emits_typed_issue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skill_root = tmp_path / "skills"
    skill_root.mkdir()
    original_scandir = discovery_module.os.scandir

    class FailingIterator:
        def __iter__(self) -> FailingIterator:
            return self

        def __next__(self) -> object:
            raise OSError("simulated late directory read failure")

        def close(self) -> None:
            return None

    def failing_scandir(path: Path):
        if path == skill_root:
            return FailingIterator()
        return original_scandir(path)

    monkeypatch.setattr(discovery_module.os, "scandir", failing_scandir)

    discovery = discover_skill_documents(skill_root)

    assert discovery.documents == ()
    assert len(discovery.issues) == 1
    assert discovery.issues[0].path == skill_root
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


def test_structure_added_between_collection_passes_is_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    original_collect = identity_module._collect_entries
    calls = 0

    def mutating_collect(
        root: Path,
        *,
        limits: SkillDirectoryIdentityLimits,
    ) -> tuple[list[identity_module._TreeEntry], tuple[tuple[object, ...], ...]]:
        nonlocal calls
        calls += 1
        if calls == 2:
            (root / "late-addition.txt").write_text("late", encoding="utf-8")
        return original_collect(root, limits=limits)

    monkeypatch.setattr(identity_module, "_collect_entries", mutating_collect)

    _incomplete(skill, scope, "tree_changed_during_hash")
    assert calls == 2


def test_root_replaced_after_final_collection_is_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    original_collect = identity_module._collect_entries
    calls = 0

    def replacing_collect(
        root: Path,
        *,
        limits: SkillDirectoryIdentityLimits,
    ) -> tuple[list[identity_module._TreeEntry], tuple[tuple[object, ...], ...]]:
        nonlocal calls
        calls += 1
        result = original_collect(root, limits=limits)
        if calls == 2:
            original_root = root.with_name(f"{root.name}-original")
            root.rename(original_root)
            root.mkdir()
            (root / "SKILL.md").write_text("replacement\n", encoding="utf-8")
        return result

    monkeypatch.setattr(identity_module, "_collect_entries", replacing_collect)

    _incomplete(skill, scope, "tree_changed_during_hash")
    assert calls == 2


def test_symlink_retargeted_while_target_is_hashed_is_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    first = skill.parent / "first.txt"
    second = skill.parent / "second.txt"
    first.write_text("first", encoding="utf-8")
    second.write_text("second", encoding="utf-8")
    alias = skill.parent / "alias.txt"
    _symlink_or_skip(alias, first.name)
    original_hash = identity_module._hash_regular_file
    retargeted = False

    def retargeting_hash(
        path: Path,
        *,
        expected_metadata: os.stat_result,
        limits: SkillDirectoryIdentityLimits,
        state: identity_module._InspectionState,
    ) -> tuple[str, int]:
        nonlocal retargeted
        result = original_hash(
            path,
            expected_metadata=expected_metadata,
            limits=limits,
            state=state,
        )
        if path == first and not retargeted:
            alias.unlink()
            alias.symlink_to(second.name)
            retargeted = True
        return result

    monkeypatch.setattr(identity_module, "_hash_regular_file", retargeting_hash)

    _incomplete(skill, scope, "tree_changed_during_hash")
    assert retargeted is True
