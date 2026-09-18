"""Collection traversal reuse must stay local and cannot cache scan authority."""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import inventory_cisco
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.gemini import GeminiHarnessAdapter
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection


def _context(tmp_path: Path) -> HarnessContext:
    home, workspace = tmp_path / "home", tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    return HarnessContext(home, workspace, tmp_path / "guard", home_override_explicit=True)


def _skill(context: HarnessContext, name: str) -> Path:
    path = context.home_dir / ".gemini" / "skills" / name / "SKILL.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"---\nname: {name}\n---\nLocal notes.\n", encoding="utf-8")
    return path


def test_collection_enumeration_is_coalesced_without_reusing_scan_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _context(tmp_path)
    for index in range(12):
        _skill(context, f"fixture-{index}")
    detection = GeminiHarnessAdapter().detect(context)
    counts: Counter[Path] = Counter()
    original = inventory_cisco._skill_dirs_under

    def enumerated(path: Path) -> tuple[Path, ...]:
        counts[path] += 1
        return original(path)

    monkeypatch.setattr(inventory_cisco, "_skill_dirs_under", enumerated)
    expected = (context.home_dir / ".gemini" / "skills",)
    for refresh in range(1, 3):
        selected = inventory_cisco._skill_scan_roots(harness="gemini", context=context, detection=detection)
        assert selected == expected
        assert counts == {expected[0]: refresh}


def test_new_refresh_observes_creation_and_removal(tmp_path: Path) -> None:
    context = _context(tmp_path)

    def roots() -> tuple[Path, ...]:
        return inventory_cisco._skill_scan_roots(
            harness="gemini", context=context, detection=GeminiHarnessAdapter().detect(context)
        )

    assert roots() == ()
    path = _skill(context, "fixture")
    assert roots() == (context.home_dir / ".gemini" / "skills",)
    path.unlink()
    assert roots() == ()
    path.write_text("New skill.\n", encoding="utf-8")
    assert roots() == (context.home_dir / ".gemini" / "skills",)


def test_negative_directory_proof_is_not_reused_within_refresh(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context(tmp_path)
    collection = context.home_dir / "collection"
    collection.mkdir()
    artifacts = tuple(
        GuardArtifact(
            artifact_id=f"gemini:fixture:{index}",
            harness="gemini",
            name=f"fixture-{index}",
            artifact_type="skill",
            source_scope="global",
            config_path=str(context.home_dir / "absent"),
            metadata={"skill_root": str(collection)},
        )
        for index in range(3)
    )
    detection = HarnessDetection(
        harness="gemini", installed=True, command_available=False, config_paths=(), artifacts=artifacts
    )
    calls = 0
    original = inventory_cisco._skill_dirs_under

    def enumerate_then_create(path: Path) -> tuple[Path, ...]:
        nonlocal calls
        calls += 1
        result = original(path)
        if calls == 1:
            skill = collection / "created" / "SKILL.md"
            skill.parent.mkdir()
            skill.write_text("Created during root selection.\n", encoding="utf-8")
        return result

    monkeypatch.setattr(inventory_cisco, "_skill_dirs_under", enumerate_then_create)
    assert inventory_cisco._skill_scan_roots(harness="gemini", context=context, detection=detection) == (collection,)
    assert calls == 2


def test_same_size_and_mtime_change_invalidates_actual_directory_identity(tmp_path: Path) -> None:
    context = _context(tmp_path)
    path = _skill(context, "fixture")

    def identity() -> object:
        detection = GeminiHarnessAdapter().detect(context)
        assert len(detection.artifacts) == 1
        return detection.artifacts[0].metadata["skillDirectoryIdentity"]

    before = identity()
    metadata = path.stat()
    path.write_bytes(path.read_bytes().replace(b"Local notes.", b"Other notes."))
    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    assert path.stat().st_size == metadata.st_size
    assert identity() != before
