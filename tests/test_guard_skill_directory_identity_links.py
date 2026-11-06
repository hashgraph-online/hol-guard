"""Link-policy and resource-limit tests for skill-directory identities."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.skill_directory_identity import (
    SKILL_DIRECTORY_IDENTITY_SCHEMA,
    SkillDirectoryIdentityLimits,
    inspect_skill_directory,
    skill_directory_identity_metadata,
)
from tests.skill_directory_identity_test_support import (
    complete_identity as _complete,
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


def test_in_tree_regular_file_symlink_binds_target_and_raw_spelling(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    first = skill.parent / "first.py"
    second = skill.parent / "second.py"
    first.write_text("same target bytes", encoding="utf-8")
    second.write_text("same target bytes", encoding="utf-8")
    alias = skill.parent / "alias.py"
    _symlink_or_skip(alias, first.name)
    first_identity = _complete(skill, scope)

    alias.unlink()
    _symlink_or_skip(alias, second.name)
    retargeted = _complete(skill, scope)
    assert retargeted.directory_hash != first_identity.directory_hash
    assert retargeted.primary_content_hash == first_identity.primary_content_hash

    alias.unlink()
    _symlink_or_skip(alias, f"./{second.name}")
    respelled = _complete(skill, scope)
    assert respelled.directory_hash != retargeted.directory_hash

    second.write_text("changed target bytes", encoding="utf-8")
    changed_target = _complete(skill, scope)
    assert changed_target.directory_hash != respelled.directory_hash


def test_primary_document_symlink_is_rejected_even_when_target_is_in_tree(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill_dir = scope / "review"
    skill_dir.mkdir(parents=True)
    body = skill_dir / "BODY.md"
    body.write_text("# Review\n", encoding="utf-8")
    primary = skill_dir / "SKILL.md"
    _symlink_or_skip(primary, body.name)

    _incomplete(primary, scope, "primary_symlink_unsupported")


def test_broken_nested_symlink_fails_closed(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    _symlink_or_skip(skill.parent / "broken", "missing-target")

    _incomplete(skill, scope, "symlink_broken")


def test_nested_symlink_loop_fails_closed(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    first = skill.parent / "first"
    second = skill.parent / "second"
    _symlink_or_skip(first, second.name)
    _symlink_or_skip(second, first.name)

    _incomplete(skill, scope, "symlink_loop")


def test_nested_symlink_cannot_escape_skill_even_within_scope(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    outside_skill = scope / "shared.py"
    outside_skill.write_text("outside", encoding="utf-8")
    _symlink_or_skip(skill.parent / "escape.py", Path("..") / outside_skill.name)

    _incomplete(skill, scope, "symlink_escape")


def test_nested_directory_symlink_is_rejected(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    real_directory = skill.parent / "real-directory"
    real_directory.mkdir()
    (real_directory / "nested.txt").write_text("nested", encoding="utf-8")
    _symlink_or_skip(skill.parent / "directory-link", real_directory.name, directory=True)

    _incomplete(skill, scope, "symlink_directory_unsupported")


def test_root_symlink_within_scope_is_rejected_consistently(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    first_skill = _make_skill(scope, "first-real")
    link = scope / "linked-skill"
    _symlink_or_skip(link, first_skill.parent.name, directory=True)
    linked_primary = link / "SKILL.md"

    _incomplete(linked_primary, scope, "symlink_directory_unsupported")


def test_root_symlink_outside_scope_fails_closed(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    scope.mkdir()
    outside_skill = _make_skill(tmp_path / "outside-scope")
    link = scope / "linked-skill"
    _symlink_or_skip(link, outside_skill.parent, directory=True)

    _incomplete(link / "SKILL.md", scope, "symlink_directory_unsupported")


def test_symlinked_parent_directory_is_rejected(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    real_parent = scope / "real-parent"
    skill = _make_skill(real_parent)
    parent_link = scope / "parent-link"
    _symlink_or_skip(parent_link, real_parent.name, directory=True)

    _incomplete(parent_link / skill.parent.name / "SKILL.md", scope, "symlink_directory_unsupported")


def test_limits_allow_exact_boundaries(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    nested = skill.parent / "nested" / "payload.bin"
    nested.parent.mkdir()
    nested.write_bytes(b"12345")
    total_bytes = len(skill.read_bytes()) + len(nested.read_bytes())
    limits = SkillDirectoryIdentityLimits(
        max_depth=2,
        max_entries=3,
        max_file_bytes=max(len(skill.read_bytes()), len(nested.read_bytes())),
        max_total_bytes=total_bytes,
    )

    identity = _complete(skill, scope, limits=limits)

    assert identity.entry_count == 3
    assert identity.total_bytes == total_bytes


def test_max_depth_limit_fails_closed(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    nested = skill.parent / "level-one" / "level-two.txt"
    nested.parent.mkdir()
    nested.write_text("nested", encoding="utf-8")
    limits = SkillDirectoryIdentityLimits(max_depth=1)

    _incomplete(skill, scope, "max_depth_exceeded", limits=limits)


def test_max_entry_count_limit_fails_closed(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    (skill.parent / "extra.txt").write_text("extra", encoding="utf-8")
    limits = SkillDirectoryIdentityLimits(max_entries=1)

    _incomplete(skill, scope, "max_entries_exceeded", limits=limits)


def test_max_per_file_byte_limit_fails_closed(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    primary_bytes = skill.read_bytes()
    limits = SkillDirectoryIdentityLimits(max_file_bytes=len(primary_bytes) - 1)

    _incomplete(skill, scope, "max_file_bytes_exceeded", limits=limits)


def test_max_total_byte_limit_fails_closed(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    extra = skill.parent / "extra.txt"
    extra.write_bytes(b"extra bytes")
    limits = SkillDirectoryIdentityLimits(
        max_file_bytes=1024,
        max_total_bytes=len(skill.read_bytes()) + len(extra.read_bytes()) - 1,
    )

    identity = _incomplete(skill, scope, "max_total_bytes_exceeded", limits=limits)
    assert identity.primary_content_hash is not None


@pytest.mark.parametrize(
    "limits",
    [
        SkillDirectoryIdentityLimits(max_depth=-1),
        SkillDirectoryIdentityLimits(max_entries=-1),
        SkillDirectoryIdentityLimits(max_file_bytes=-1),
        SkillDirectoryIdentityLimits(max_total_bytes=-1),
        SkillDirectoryIdentityLimits(max_depth=True),
    ],
)
def test_invalid_limits_are_rejected(limits: SkillDirectoryIdentityLimits, tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)

    with pytest.raises(ValueError, match="non-negative integers"):
        inspect_skill_directory(skill, scope_root=scope, limits=limits)


def test_incomplete_identity_has_stable_state_hash_and_nonreusable_metadata(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    root = scope / "missing-primary"
    root.mkdir(parents=True)
    (root / "README.md").write_text("not a skill", encoding="utf-8")
    skill = root / "SKILL.md"

    first = _incomplete(skill, scope, "primary_missing")
    second = _incomplete(skill, scope, "primary_missing")

    assert first.incomplete_state_hash == second.incomplete_state_hash
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", first.incomplete_state_hash or "")
    first_metadata = skill_directory_identity_metadata(first, version_label="Codex skill")
    second_metadata = skill_directory_identity_metadata(second, version_label="Codex skill")
    first_envelope = first_metadata["skillDirectoryIdentity"]
    assert isinstance(first_envelope, dict)
    assert first_envelope == {
        "schemaVersion": SKILL_DIRECTORY_IDENTITY_SCHEMA,
        "status": "incomplete",
        "entryCount": 1,
        "totalBytes": 0,
        "reusable": False,
        "reason": "primary_missing",
        "incompleteStateHash": first.incomplete_state_hash,
    }
    assert "directory_hash" not in first_metadata
    assert first_metadata["versionInfo"] == second_metadata["versionInfo"]
