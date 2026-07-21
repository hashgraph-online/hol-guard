"""Codex/AIBOM skill-directory identity integration tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.aibom_detection import (
    discover_codex_skill_artifacts,
    file_content_hash,
)
from codex_plugin_scanner.guard.consumer.service import artifact_hash
from codex_plugin_scanner.guard.models import GuardArtifact


def test_codex_skill_uses_complete_directory_identity_and_detects_secondary_tail_change(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    skill_dir = workspace / ".agents" / "skills" / "review"
    skill_dir.mkdir(parents=True)
    skill_path = skill_dir / "SKILL.md"
    script_path = skill_dir / "scripts" / "review.py"
    skill_path.write_text("---\nname: review\n---\nReview carefully.\n", encoding="utf-8")
    script_path.parent.mkdir()
    prefix = b"#" * (1024 * 1024)
    script_path.write_bytes(prefix + b"tail-one\n")

    def discovered_skill() -> GuardArtifact:
        return next(
            artifact
            for artifact in discover_codex_skill_artifacts(
                "codex",
                home_dir=tmp_path / "home",
                workspace_dir=workspace,
            )
            if artifact.source_scope == "project" and artifact.name == "review"
        )

    first = discovered_skill()
    stable = discovered_skill()

    assert artifact_hash(first) == artifact_hash(stable)
    assert first.metadata == stable.metadata
    assert first.metadata.get("content_hash") == f"sha256:{file_content_hash(skill_path)}"
    assert isinstance(first.metadata.get("directory_hash"), str)
    identity_metadata = first.metadata.get("skillDirectoryIdentity")
    assert isinstance(identity_metadata, dict)
    assert identity_metadata.get("schemaVersion") == "guard.skill-directory-identity.v1"
    assert identity_metadata.get("reusable") is True
    version_info = first.metadata.get("versionInfo")
    assert isinstance(version_info, dict)
    assert first.metadata["directory_hash"] == version_info["contentHash"]

    script_path.write_bytes(prefix + b"tail-two\n")
    changed = discovered_skill()

    assert changed.metadata.get("content_hash") == first.metadata.get("content_hash")
    assert changed.metadata.get("directory_hash") != first.metadata.get("directory_hash")
    assert artifact_hash(changed) != artifact_hash(first)


@pytest.mark.skipif(os.name == "nt", reason="POSIX executable mode is not portable to Windows")
def test_codex_skill_directory_identity_detects_secondary_executable_mode_change(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    skill_dir = workspace / ".agents" / "skills" / "review"
    skill_dir.mkdir(parents=True)
    skill_path = skill_dir / "SKILL.md"
    script_path = skill_dir / "scripts" / "review.sh"
    skill_path.write_text("---\nname: review\n---\nReview carefully.\n", encoding="utf-8")
    script_path.parent.mkdir()
    script_path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script_path.chmod(0o644)

    def discovered_skill() -> GuardArtifact:
        return next(
            artifact
            for artifact in discover_codex_skill_artifacts(
                "codex",
                home_dir=tmp_path / "home",
                workspace_dir=workspace,
            )
            if artifact.source_scope == "project" and artifact.name == "review"
        )

    not_executable = discovered_skill()
    script_path.chmod(0o744)
    executable = discovered_skill()

    assert executable.metadata.get("content_hash") == not_executable.metadata.get("content_hash")
    assert executable.metadata.get("directory_hash") != not_executable.metadata.get("directory_hash")
    assert artifact_hash(executable) != artifact_hash(not_executable)


def test_codex_skill_external_primary_link_is_reported_as_incomplete_metadata(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    skill_dir = workspace / ".agents" / "skills" / "escaped"
    skill_dir.mkdir(parents=True)
    outside = tmp_path / "private" / "SKILL.md"
    outside.parent.mkdir()
    outside.write_text("---\nname: escaped\n---\nOutside instructions.\n", encoding="utf-8")
    skill_path = skill_dir / "SKILL.md"
    try:
        skill_path.symlink_to(outside)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    artifact = next(
        item
        for item in discover_codex_skill_artifacts(
            "codex",
            home_dir=tmp_path / "home",
            workspace_dir=workspace,
        )
        if item.source_scope == "project" and item.name == "escaped"
    )
    identity_metadata = artifact.metadata.get("skillDirectoryIdentity")

    assert artifact.config_path == str(skill_path)
    assert isinstance(identity_metadata, dict)
    assert identity_metadata.get("schemaVersion") == "guard.skill-directory-identity.v1"
    assert identity_metadata.get("status") == "incomplete"
    assert identity_metadata.get("reusable") is False
    assert isinstance(identity_metadata.get("reason"), str)
    assert isinstance(identity_metadata.get("incompleteStateHash"), str)
    assert "directory_hash" not in artifact.metadata


def test_codex_broken_linked_skill_root_emits_incomplete_artifact(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    skill_root = workspace / ".agents" / "skills"
    skill_root.mkdir(parents=True)
    broken = skill_root / "broken"
    try:
        broken.symlink_to("missing", target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    artifact = next(
        item
        for item in discover_codex_skill_artifacts(
            "codex",
            home_dir=tmp_path / "home",
            workspace_dir=workspace,
        )
        if "skill-discovery" in item.artifact_id
    )
    identity_metadata = artifact.metadata.get("skillDirectoryIdentity")

    assert artifact.config_path == str(broken)
    assert isinstance(identity_metadata, dict)
    assert identity_metadata["status"] == "incomplete"
    assert identity_metadata["reason"] == "symlink_broken"
    assert identity_metadata["reusable"] is False
