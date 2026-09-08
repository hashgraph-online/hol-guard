"""Repository integration preserves human work and requires explicit bounded writes."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.extension_builder.io import canonical_json
from codex_plugin_scanner.guard.extension_builder.kit import build_kit
from codex_plugin_scanner.guard.extension_builder.models import make_discovery as normalized_discovery
from codex_plugin_scanner.guard.extension_builder.render_native import contribution_path, detector_path
from codex_plugin_scanner.guard.extension_builder.repository_edits import (
    CATALOG_PATH,
    PYPROJECT_PATH,
    STAGING_PATH,
    TRUST_PATH,
)
from codex_plugin_scanner.guard.extension_builder.repository_plan import ownership_root, plan_repository
from codex_plugin_scanner.guard.extension_builder.repository_write import LOCK_NAME, apply_kit
from codex_plugin_scanner.guard.extension_builder.review import default_review
from tests.extension_builder_support import file_snapshot, make_kit, repository_fixture


@pytest.mark.parametrize("kind", ["cli", "mcp"])
def test_plan_only_is_read_only_and_content_bound(tmp_path: Path, kind: str) -> None:
    kit = make_kit(tmp_path, kind)
    repository = repository_fixture(tmp_path)
    before = file_snapshot(repository)
    result = apply_kit(kit, repository)
    assert result["written"] is False
    assert result["activeProtectionChanged"] is False
    assert len(result["planDigest"]) == 64
    assert result == apply_kit(kit, repository)
    assert file_snapshot(repository) == before
    assert not (repository / LOCK_NAME).exists()
    assert all(not item["path"].startswith("/") for item in result["files"])


@pytest.mark.parametrize("kind", ["cli", "mcp"])
def test_apply_registers_external_packages_and_is_idempotent(tmp_path: Path, kind: str) -> None:
    kit = make_kit(tmp_path, kind, reviewed=True)
    repository = repository_fixture(tmp_path)
    inspected = apply_kit(kit, repository)
    result = apply_kit(kit, repository, write=True, expected_plan=inspected["planDigest"])
    assert result["written"] is True
    assert (repository / contribution_path(kit.discovery.metadata)).is_file()
    trust = json.loads((repository / TRUST_PATH).read_text(encoding="utf-8"))
    assert kit.discovery.metadata.catalog_id in trust["classes"]["external"]
    assert kit.discovery.metadata.catalog_id not in trust["classes"]["first-party"]
    assert contribution_path(kit.discovery.metadata) in (repository / PYPROJECT_PATH).read_text(encoding="utf-8")
    assert contribution_path(kit.discovery.metadata) in (repository / STAGING_PATH).read_text(encoding="utf-8")
    before = file_snapshot(repository)
    repeated = apply_kit(kit, repository, write=True)
    assert all(item["action"] == "unchanged" for item in repeated["files"])
    assert file_snapshot(repository) == before
    assert not (repository / LOCK_NAME).exists()


@pytest.mark.parametrize("write", [False, True])
def test_wrong_expected_plan_never_writes(tmp_path: Path, write: bool) -> None:
    kit = make_kit(tmp_path)
    repository = repository_fixture(tmp_path)
    before = file_snapshot(repository)
    with pytest.raises(BuilderError, match="inspected digest"):
        apply_kit(kit, repository, write=write, expected_plan="f" * 64)
    assert file_snapshot(repository) == before


def test_intervening_repository_change_invalidates_inspected_plan(tmp_path: Path) -> None:
    kit = make_kit(tmp_path)
    repository = repository_fixture(tmp_path)
    plan = apply_kit(kit, repository)
    project = repository / PYPROJECT_PATH
    project.write_text(
        project.read_text(encoding="utf-8") + "\n# A maintainer changed this after planning.\n", encoding="utf-8"
    )
    before = file_snapshot(repository)
    with pytest.raises(BuilderError, match="inspected digest"):
        apply_kit(kit, repository, write=True, expected_plan=plan["planDigest"])
    assert file_snapshot(repository) == before


def test_review_update_preserves_unrelated_shared_file_edits(tmp_path: Path) -> None:
    original = make_kit(tmp_path)
    repository = repository_fixture(tmp_path)
    apply_kit(original, repository, write=True)
    project = repository / PYPROJECT_PATH
    project.write_text(project.read_text(encoding="utf-8") + "\n# Keep this maintainer note.\n", encoding="utf-8")
    catalog = repository / CATALOG_PATH
    catalog.write_text(catalog.read_text(encoding="utf-8") + "\n# Keep this catalog note.\n", encoding="utf-8")
    updated = make_kit(tmp_path, reviewed=True)
    plan = apply_kit(updated, repository)
    assert any(item["action"] == "update" for item in plan["files"])
    apply_kit(updated, repository, write=True, expected_plan=plan["planDigest"])
    assert "# Keep this maintainer note." in project.read_text(encoding="utf-8")
    assert "# Keep this catalog note." in catalog.read_text(encoding="utf-8")
    assert (repository / detector_path(updated.discovery.metadata)).read_text(
        encoding="utf-8"
    ) == updated.native_files()[detector_path(updated.discovery.metadata)]


@pytest.mark.parametrize("remove", [False, True])
def test_manually_changed_owned_file_is_never_overwritten(tmp_path: Path, remove: bool) -> None:
    original = make_kit(tmp_path)
    repository = repository_fixture(tmp_path)
    apply_kit(original, repository, write=True)
    target = repository / detector_path(original.discovery.metadata)
    if remove:
        target.unlink()
    else:
        target.write_text(
            target.read_text(encoding="utf-8") + "\n# Hand-written behavior must be preserved.\n", encoding="utf-8"
        )
    before = file_snapshot(repository)
    with pytest.raises(BuilderError, match="edited or removed"):
        apply_kit(make_kit(tmp_path, reviewed=True), repository, write=True)
    assert file_snapshot(repository) == before


def test_removed_shared_registration_is_not_silently_restored(tmp_path: Path) -> None:
    kit = make_kit(tmp_path)
    repository = repository_fixture(tmp_path)
    apply_kit(kit, repository, write=True)
    path = repository / TRUST_PATH
    trust = json.loads(path.read_text(encoding="utf-8"))
    trust["classes"]["external"].remove(kit.discovery.metadata.catalog_id)
    path.write_text(canonical_json(trust), encoding="utf-8")
    before = file_snapshot(repository)
    with pytest.raises(BuilderError, match="removed"):
        apply_kit(kit, repository, write=True)
    assert file_snapshot(repository) == before


@pytest.mark.parametrize(
    "path,original,replacement",
    [
        (CATALOG_PATH, "_DIRECT_EXTENSION_CATALOGS = (", "_OTHER_CATALOG = ("),
        (STAGING_PATH, "_ARTIFACTS = {", "_OTHER_ARTIFACTS = {"),
        (PYPROJECT_PATH, "[tool.hatch.build.targets.wheel.force-include]", "[tool.hatch.build.targets.wheel.other]"),
    ],
)
def test_unknown_repository_layout_fails_without_changes(
    tmp_path: Path, path: str, original: str, replacement: str
) -> None:
    kit = make_kit(tmp_path)
    repository = repository_fixture(tmp_path)
    target = repository / path
    target.write_text(target.read_text(encoding="utf-8").replace(original, replacement), encoding="utf-8")
    before = file_snapshot(repository)
    with pytest.raises(BuilderError):
        apply_kit(kit, repository, write=True)
    assert file_snapshot(repository) == before


def test_existing_unmanaged_native_file_is_a_conflict(tmp_path: Path) -> None:
    kit = make_kit(tmp_path)
    repository = repository_fixture(tmp_path)
    target = repository / detector_path(kit.discovery.metadata)
    target.write_text("# Existing maintainer detector.\n", encoding="utf-8")
    before = file_snapshot(repository)
    with pytest.raises(BuilderError, match="ownership record"):
        apply_kit(kit, repository, write=True)
    assert file_snapshot(repository) == before


@pytest.mark.parametrize("identity", ["git", "docker", "npm"])
def test_existing_executable_coverage_is_not_duplicated(tmp_path: Path, identity: str) -> None:
    base = make_kit(tmp_path)
    discovery = normalized_discovery(
        replace(base.discovery.metadata, executable=identity),
        base.discovery.adapter,
        base.discovery.source_sha256,
        base.discovery.operations,
        base.discovery.limitations,
    )
    kit = build_kit(discovery, default_review(discovery))
    repository = repository_fixture(tmp_path)
    with pytest.raises(BuilderError, match="already has Guard coverage"):
        plan_repository(kit, repository)


def test_existing_mcp_package_is_not_duplicated(tmp_path: Path) -> None:
    base = make_kit(tmp_path, "mcp")
    discovery = normalized_discovery(
        replace(base.discovery.metadata, package="@modelcontextprotocol/server-filesystem"),
        base.discovery.adapter,
        base.discovery.source_sha256,
        base.discovery.operations,
        base.discovery.limitations,
    )
    kit = build_kit(discovery, default_review(discovery))
    repository = repository_fixture(tmp_path)
    with pytest.raises(BuilderError, match="already has a contribution"):
        plan_repository(kit, repository)


def test_authoring_record_cannot_claim_arbitrary_paths(tmp_path: Path) -> None:
    kit = make_kit(tmp_path)
    repository = repository_fixture(tmp_path)
    apply_kit(kit, repository, write=True)
    record = repository / ownership_root(kit.discovery.metadata) / "record.json"
    payload = json.loads(record.read_text(encoding="utf-8"))
    payload["managedFiles"]["../../outside"] = "0" * 64
    record.write_text(canonical_json(payload), encoding="utf-8")
    before = file_snapshot(repository)
    with pytest.raises(BuilderError, match="ownership record"):
        apply_kit(kit, repository, write=True)
    assert file_snapshot(repository) == before


def test_existing_lock_is_preserved_and_prevents_writing(tmp_path: Path) -> None:
    kit = make_kit(tmp_path)
    repository = repository_fixture(tmp_path)
    lock = repository / LOCK_NAME
    lock.write_text("another writer", encoding="utf-8")
    before = file_snapshot(repository)
    with pytest.raises(BuilderError, match="lock"):
        apply_kit(kit, repository, write=True)
    assert file_snapshot(repository) == before
    assert lock.read_text(encoding="utf-8") == "another writer"


def test_ordinary_write_failure_rolls_back_completed_changes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.extension_builder import repository_write

    kit = make_kit(tmp_path)
    repository = repository_fixture(tmp_path)
    before = file_snapshot(repository)
    real_replace = repository_write.os.replace
    calls = 0

    def fail_second(source: Path, destination: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("Synthetic write failure")
        real_replace(source, destination)

    monkeypatch.setattr(repository_write.os, "replace", fail_second)
    with pytest.raises(BuilderError, match="rolled back"):
        apply_kit(kit, repository, write=True)
    assert file_snapshot(repository) == before
    assert not list(repository.glob(".hol-guard-*"))


def test_concurrent_human_edit_is_preserved_during_rollback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.extension_builder import repository_write

    kit = make_kit(tmp_path)
    repository = repository_fixture(tmp_path)
    before = file_snapshot(repository)
    real_replace = repository_write.os.replace
    injected = False
    project = repository / PYPROJECT_PATH
    modified = before[PYPROJECT_PATH] + b"\n# Concurrent maintainer edit.\n"

    def replace_then_edit(source: Path, destination: Path) -> None:
        nonlocal injected
        real_replace(source, destination)
        if not injected:
            injected = True
            project.write_bytes(modified)

    monkeypatch.setattr(repository_write.os, "replace", replace_then_edit)
    with pytest.raises(BuilderError, match="rolled back"):
        apply_kit(kit, repository, write=True)
    before[PYPROJECT_PATH] = modified
    assert file_snapshot(repository) == before


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode preservation")
def test_existing_file_modes_are_preserved(tmp_path: Path) -> None:
    kit = make_kit(tmp_path)
    repository = repository_fixture(tmp_path)
    project = repository / PYPROJECT_PATH
    project.chmod(0o600)
    apply_kit(kit, repository, write=True)
    assert stat.S_IMODE(project.stat().st_mode) == 0o600
    assert stat.S_IMODE((repository / detector_path(kit.discovery.metadata)).stat().st_mode) == 0o644


def test_symlinked_repository_target_is_rejected(tmp_path: Path) -> None:
    kit = make_kit(tmp_path)
    repository = repository_fixture(tmp_path)
    target = repository / PYPROJECT_PATH
    outside = tmp_path / "outside.toml"
    target.rename(outside)
    try:
        target.symlink_to(outside)
    except OSError:
        pytest.skip("Symlink creation is unavailable")
    content = outside.read_bytes()
    with pytest.raises(BuilderError, match="Symlink"):
        apply_kit(kit, repository, write=True)
    assert outside.read_bytes() == content
    assert not (repository / LOCK_NAME).exists()
