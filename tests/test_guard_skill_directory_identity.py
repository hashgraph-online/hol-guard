"""Contract tests for complete, bounded skill-directory identities."""

from __future__ import annotations

import os
import stat
from copy import deepcopy
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import skill_directory_identity as identity_module
from codex_plugin_scanner.guard.skill_directory_identity import (
    SKILL_DIRECTORY_IDENTITY_SCHEMA,
    SkillDirectoryIdentity,
    SkillDirectoryIdentityLimits,
    discover_skill_documents,
    inspect_skill_directory,
    skill_directory_identity_metadata,
    validated_complete_skill_directory_hash,
)


def _make_skill(scope: Path, name: str = "example") -> Path:
    skill = scope / name / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("# Example skill\n", encoding="utf-8")
    return skill


def _complete(
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


def _incomplete(
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


def _symlink_or_skip(link: Path, target: str | Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlinks unavailable: {exc}")


@pytest.mark.skipif(os.name != "nt", reason="Windows suffix-derived execute bits are required")
def test_windows_command_suffix_has_complete_identity(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    (skill.parent / "run.cmd").write_text("@echo off\r\n", encoding="utf-8")

    _complete(skill, scope)


def test_discovery_reports_a_linked_skill_root_without_following_it(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill_root = scope / "skills"
    skill_root.mkdir(parents=True)
    target = _make_skill(scope / "linked-targets", "review")
    _make_skill(target.parent, "nested")
    linked_root = skill_root / "review"
    _symlink_or_skip(linked_root, target.parent, directory=True)

    discovery = discover_skill_documents(skill_root)

    assert discovery.documents == ()
    assert len(discovery.issues) == 1
    assert discovery.issues[0].path == linked_root
    assert discovery.issues[0].failure_reason == "symlink_directory_unsupported"


def test_complete_identity_reports_schema_counts_bytes_and_metadata(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    script = skill.parent / "scripts" / "run.py"
    script.parent.mkdir()
    script.write_bytes(b"print('safe')\n")

    identity = _complete(skill, scope)

    assert identity.schema_version == SKILL_DIRECTORY_IDENTITY_SCHEMA
    assert identity.entry_count == 3
    assert identity.total_bytes == len(skill.read_bytes()) + len(script.read_bytes())
    metadata = skill_directory_identity_metadata(identity, version_label="Gemini skill")
    assert metadata["content_hash"] == identity.primary_content_hash
    assert metadata["directory_hash"] == identity.directory_hash
    assert metadata["versionInfo"] == {
        "versionLabel": "Gemini skill",
        "hashBasis": "skill-directory-v1",
        "contentHash": identity.directory_hash,
        "changedFields": [],
    }
    assert metadata["skillDirectoryIdentity"] == {
        "schemaVersion": SKILL_DIRECTORY_IDENTITY_SCHEMA,
        "status": "complete",
        "entryCount": 3,
        "totalBytes": identity.total_bytes,
        "reusable": True,
        "contentHash": identity.directory_hash,
    }
    assert validated_complete_skill_directory_hash(metadata) == identity.directory_hash


@pytest.mark.parametrize(
    "mutation",
    (
        "schema",
        "status",
        "reusable",
        "reason",
        "state",
        "legacy-nonce",
        "directory",
        "version",
        "basis",
        "count",
    ),
)
def test_complete_metadata_validator_rejects_malformed_or_mismatched_envelopes(
    tmp_path: Path,
    mutation: str,
) -> None:
    scope = tmp_path / "scope"
    identity = _complete(_make_skill(scope), scope)
    metadata = skill_directory_identity_metadata(identity, version_label="skill")
    altered = deepcopy(metadata)
    envelope = altered["skillDirectoryIdentity"]
    version_info = altered["versionInfo"]
    assert isinstance(envelope, dict)
    assert isinstance(version_info, dict)
    if mutation == "schema":
        envelope["schemaVersion"] = "guard.skill-directory-identity.v0"
    elif mutation == "status":
        envelope["status"] = "incomplete"
    elif mutation == "reusable":
        envelope["reusable"] = False
    elif mutation == "reason":
        envelope["reason"] = "unreadable_entry"
    elif mutation == "state":
        envelope["incompleteStateHash"] = "sha256:" + ("2" * 64)
    elif mutation == "legacy-nonce":
        envelope["reuseNonce"] = "legacy"
    elif mutation == "directory":
        altered["directory_hash"] = "sha256:" + ("0" * 64)
    elif mutation == "version":
        version_info["contentHash"] = "sha256:" + ("1" * 64)
    elif mutation == "basis":
        version_info["hashBasis"] = "legacy"
    else:
        envelope["entryCount"] = True

    assert validated_complete_skill_directory_hash(altered) is None


def test_complete_metadata_validator_rejects_non_string_mapping_keys(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    identity = _complete(_make_skill(scope), scope)
    metadata: dict[object, object] = {}
    metadata.update(skill_directory_identity_metadata(identity, version_label="skill"))
    metadata[1] = "ambiguous"

    assert validated_complete_skill_directory_hash(metadata) is None


def test_primary_document_content_changes_both_hashes(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    before = _complete(skill, scope)

    skill.write_text("# Changed skill\n", encoding="utf-8")
    after = _complete(skill, scope)

    assert after.primary_content_hash != before.primary_content_hash
    assert after.directory_hash != before.directory_hash


def test_nested_file_content_changes_only_directory_hash(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    nested = skill.parent / "scripts" / "run.py"
    nested.parent.mkdir()
    nested.write_text("print(1)\n", encoding="utf-8")
    before = _complete(skill, scope)

    nested.write_text("print(2)\n", encoding="utf-8")
    after = _complete(skill, scope)

    assert after.primary_content_hash == before.primary_content_hash
    assert after.directory_hash != before.directory_hash


def test_regular_file_tail_beyond_one_mebibyte_is_fully_hashed(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    payload = skill.parent / "payload.bin"
    payload.write_bytes((b"a" * (1024 * 1024 + 17)) + b"first-tail")
    before = _complete(skill, scope)

    payload.write_bytes((b"a" * (1024 * 1024 + 17)) + b"other-tail")
    after = _complete(skill, scope)

    assert payload.stat().st_size > 1024 * 1024
    assert after.directory_hash != before.directory_hash
    assert after.primary_content_hash == before.primary_content_hash


@pytest.mark.skipif(os.name == "nt", reason="POSIX executable mode is not portable to Windows")
def test_executable_mode_change_changes_directory_hash(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    executable = skill.parent / "run.sh"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o644)
    before = _complete(skill, scope)

    executable.chmod(0o755)
    after = _complete(skill, scope)

    assert after.directory_hash != before.directory_hash
    assert after.primary_content_hash == before.primary_content_hash


def test_add_remove_and_rename_bind_every_relative_path(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    baseline = _complete(skill, scope)

    added = skill.parent / "added.txt"
    added.write_text("same bytes", encoding="utf-8")
    with_file = _complete(skill, scope)
    assert with_file.directory_hash != baseline.directory_hash

    renamed = skill.parent / "renamed.txt"
    added.rename(renamed)
    after_rename = _complete(skill, scope)
    assert after_rename.directory_hash != with_file.directory_hash

    renamed.unlink()
    after_remove = _complete(skill, scope)
    assert after_remove.directory_hash == baseline.directory_hash


def test_empty_files_and_directories_are_identity_entries(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    baseline = _complete(skill, scope)

    empty_file = skill.parent / "empty"
    empty_file.touch()
    with_empty_file = _complete(skill, scope)
    assert with_empty_file.directory_hash != baseline.directory_hash
    assert with_empty_file.entry_count == baseline.entry_count + 1
    assert with_empty_file.total_bytes == baseline.total_bytes

    empty_directory = skill.parent / "empty-directory"
    empty_directory.mkdir()
    with_both = _complete(skill, scope)
    assert with_both.directory_hash != with_empty_file.directory_hash
    assert with_both.entry_count == with_empty_file.entry_count + 1
    assert with_both.total_bytes == with_empty_file.total_bytes

    empty_file.unlink()
    without_file = _complete(skill, scope)
    assert without_file.directory_hash != with_both.directory_hash
    empty_directory.rmdir()
    assert _complete(skill, scope).directory_hash == baseline.directory_hash


def test_changing_regular_file_to_directory_changes_entry_type_identity(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    node = skill.parent / "node"
    node.touch()
    as_file = _complete(skill, scope)

    node.unlink()
    node.mkdir()
    as_directory = _complete(skill, scope)

    assert as_directory.entry_count == as_file.entry_count
    assert as_directory.total_bytes == as_file.total_bytes
    assert as_directory.directory_hash != as_file.directory_hash


def test_mtime_changes_do_not_change_content_identity(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    nested = skill.parent / "script.py"
    nested.write_text("print('stable')\n", encoding="utf-8")
    before = _complete(skill, scope)

    metadata = nested.stat()
    os.utime(
        nested,
        ns=(metadata.st_atime_ns + 1_000_000_000, metadata.st_mtime_ns + 2_000_000_000),
    )
    after = _complete(skill, scope)

    assert after.directory_hash == before.directory_hash
    assert after.primary_content_hash == before.primary_content_hash


def test_directory_enumeration_order_does_not_change_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    for relative_path in ("z.txt", "a.txt", "nested/y.txt", "nested/b.txt"):
        path = skill.parent / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(relative_path, encoding="utf-8")
    baseline = _complete(skill, scope)
    original_scandir = os.scandir

    def reversed_scandir(path: os.PathLike[str] | str) -> object:
        with original_scandir(path) as iterator:
            return iter(reversed(list(iterator)))

    monkeypatch.setattr(identity_module.os, "scandir", reversed_scandir)
    reversed_identity = _complete(skill, scope)

    assert reversed_identity.directory_hash == baseline.directory_hash
    assert reversed_identity.primary_content_hash == baseline.primary_content_hash


def test_unicode_names_are_normalized_to_nfc(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    decomposed_skill = _make_skill(scope, "decomposed")
    composed_skill = _make_skill(scope, "composed")
    (decomposed_skill.parent / "cafe\N{COMBINING ACUTE ACCENT}.txt").write_text(
        "same",
        encoding="utf-8",
    )
    (composed_skill.parent / "caf\N{LATIN SMALL LETTER E WITH ACUTE}.txt").write_text(
        "same",
        encoding="utf-8",
    )

    decomposed = _complete(decomposed_skill, scope)
    composed = _complete(composed_skill, scope)

    assert decomposed.directory_hash == composed.directory_hash


def test_unicode_nfc_aliases_are_rejected_as_duplicate_paths(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    decomposed = skill.parent / "cafe\N{COMBINING ACUTE ACCENT}.txt"
    composed = skill.parent / "caf\N{LATIN SMALL LETTER E WITH ACUTE}.txt"
    decomposed.write_text("first", encoding="utf-8")
    composed.write_text("second", encoding="utf-8")
    names = {entry.name for entry in os.scandir(skill.parent)}
    if decomposed.name not in names or composed.name not in names:
        pytest.skip("filesystem aliases canonically equivalent Unicode names")

    _incomplete(skill, scope, "duplicate_path")


def test_casefold_colliding_paths_are_rejected(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    upper = skill.parent / "Runner.py"
    lower = skill.parent / "runner.py"
    upper.write_text("first", encoding="utf-8")
    lower.write_text("second", encoding="utf-8")
    names = {entry.name for entry in os.scandir(skill.parent)}
    if upper.name not in names or lower.name not in names:
        pytest.skip("filesystem aliases casefold-equivalent names")

    _incomplete(skill, scope, "case_collision")


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics are required")
def test_unreadable_regular_file_fails_closed(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    unreadable = skill.parent / "secret.txt"
    unreadable.write_text("secret", encoding="utf-8")
    unreadable.chmod(0)
    try:
        try:
            descriptor = os.open(unreadable, os.O_RDONLY)
        except PermissionError:
            pass
        else:
            os.close(descriptor)
            pytest.skip("current user can read mode-000 files")
        _incomplete(skill, scope, "unreadable_entry")
    finally:
        unreadable.chmod(stat.S_IRUSR | stat.S_IWUSR)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO creation is unavailable")
def test_special_file_fails_closed(tmp_path: Path) -> None:
    scope = tmp_path / "scope"
    skill = _make_skill(scope)
    fifo = skill.parent / "events.fifo"
    try:
        os.mkfifo(fifo)
    except OSError as exc:
        pytest.skip(f"FIFO creation unavailable: {exc}")

    _incomplete(skill, scope, "special_file")
