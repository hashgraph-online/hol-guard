"""Gemini adapter integration tests for complete skill-directory identity."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.gemini import GeminiHarnessAdapter
from codex_plugin_scanner.guard.consumer.service import artifact_hash


def _ctx(tmp_path: Path, *, workspace: bool = False) -> HarnessContext:
    workspace_dir = tmp_path / "workspace" if workspace else None
    if workspace_dir is not None:
        workspace_dir.mkdir(parents=True, exist_ok=True)
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


@pytest.mark.parametrize("workspace", [False, True], ids=["global", "workspace"])
def test_skill_identity_covers_primary_and_nested_files(tmp_path: Path, workspace: bool) -> None:
    ctx = _ctx(tmp_path, workspace=workspace)
    base_dir = ctx.workspace_dir if workspace else ctx.home_dir
    assert base_dir is not None
    skill_dir = base_dir / ".gemini" / "skills" / "review"
    skill_path = skill_dir / "SKILL.md"
    script_path = skill_dir / "scripts" / "review.py"
    reference_path = skill_dir / "references" / "nested" / "policy.md"
    _write_text(skill_path, "---\nname: review\n---\nVersion one.\n")
    _write_text(script_path, "print('one')\n")
    _write_text(reference_path, "Policy one.\n")

    adapter = GeminiHarnessAdapter()

    def detected_skill_hash() -> tuple[str, dict[str, object]]:
        detection = adapter.detect(ctx)
        artifact = next(
            item
            for item in detection.artifacts
            if item.artifact_id == f"gemini:{'project' if workspace else 'global'}:skill:skills/review"
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

    _write_text(reference_path, "Policy two.\n")
    reference_hash, _ = detected_skill_hash()
    assert reference_hash != script_hash


def test_linked_skill_directory_is_reported_as_nonreusable_discovery(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    skill_root = ctx.home_dir / ".gemini" / "skills"
    target = ctx.home_dir / "linked-skills" / "review"
    _write_text(target / "SKILL.md", "---\nname: review\n---\n")
    _write_text(target / "scripts" / "run.py", "print('linked')\n")
    skill_root.mkdir(parents=True)
    linked_root = skill_root / "review"
    try:
        linked_root.symlink_to(target, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    result = GeminiHarnessAdapter().detect(ctx)
    skill = next(item for item in result.artifacts if "skill-discovery" in item.artifact_id)
    identity_metadata = skill.metadata.get("skillDirectoryIdentity")

    assert skill.config_path == str(linked_root)
    assert isinstance(identity_metadata, dict)
    assert identity_metadata["status"] == "incomplete"
    assert identity_metadata["reason"] == "symlink_directory_unsupported"
    assert identity_metadata["reusable"] is False
    assert result.warnings


def test_broken_linked_skill_root_is_not_silently_omitted(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    skill_root = ctx.home_dir / ".gemini" / "skills"
    skill_root.mkdir(parents=True)
    broken = skill_root / "broken"
    try:
        broken.symlink_to("missing", target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    result = GeminiHarnessAdapter().detect(ctx)
    artifact = next(item for item in result.artifacts if "skill-discovery" in item.artifact_id)
    identity_metadata = artifact.metadata.get("skillDirectoryIdentity")

    assert result.installed is True
    assert isinstance(identity_metadata, dict)
    assert identity_metadata["reason"] == "symlink_broken"
    assert identity_metadata["reusable"] is False
    assert result.warnings


def test_incomplete_skill_identity_warns_without_external_path_disclosure(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    skill_dir = ctx.home_dir / ".gemini" / "skills" / "review"
    _write_text(skill_dir / "SKILL.md", "---\nname: review\n---\n")
    outside = tmp_path / "private" / "external-reference.md"
    _write_text(outside, "outside\n")
    try:
        (skill_dir / "references").symlink_to(outside)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    result = GeminiHarnessAdapter().detect(ctx)
    skill = next(item for item in result.artifacts if item.artifact_type == "skill")
    identity_metadata = skill.metadata.get("skillDirectoryIdentity")

    assert isinstance(identity_metadata, dict)
    assert identity_metadata.get("reusable") is False
    assert result.warnings
    assert all(str(outside) not in warning for warning in result.warnings)
    assert any("approval reuse is disabled" in warning for warning in result.warnings)
