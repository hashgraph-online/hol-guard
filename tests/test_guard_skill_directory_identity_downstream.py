from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.gemini import GeminiHarnessAdapter
from codex_plugin_scanner.guard.aibom_content_upload import (
    primary_content_sources_from_artifacts,
    upload_primary_content_sources,
)
from codex_plugin_scanner.guard.inventory_contract import (
    extract_aibom_metadata_extensions,
    inventory_snapshot_from_detection,
)
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection


def _sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _complete_metadata(*, primary_hash: str, directory_hash: str) -> dict[str, object]:
    return {
        "content_hash": primary_hash,
        "directory_hash": directory_hash,
        "skillDirectoryIdentity": {
            "schemaVersion": "guard.skill-directory-identity.v1",
            "status": "complete",
            "contentHash": directory_hash,
            "entryCount": 3,
            "totalBytes": 41,
            "reusable": True,
        },
        "versionInfo": {
            "hashBasis": "skill-directory-v1",
            "contentHash": directory_hash,
        },
    }


def _skill_detection(
    skill_path: Path,
    *,
    metadata: dict[str, object],
    harness: str = "gemini",
) -> HarnessDetection:
    artifact = GuardArtifact(
        artifact_id=f"{harness}:skill:review",
        name="review",
        harness=harness,
        artifact_type="skill",
        source_scope="global",
        config_path=str(skill_path),
        metadata=metadata,
    )
    return HarnessDetection(
        harness=harness,
        installed=True,
        command_available=False,
        config_paths=(str(skill_path),),
        artifacts=(artifact,),
    )


def test_inventory_uses_complete_directory_hash_but_keeps_primary_evidence(tmp_path: Path) -> None:
    skill_path = tmp_path / ".gemini" / "skills" / "review" / "SKILL.md"
    skill_path.parent.mkdir(parents=True)
    body = b"# Review\nUse the complete bundle.\n"
    skill_path.write_bytes(body)
    primary_hash = _sha256(body)
    directory_hash = _sha256(b"canonical full directory stream")
    detection = _skill_detection(
        skill_path,
        metadata=_complete_metadata(
            primary_hash=primary_hash,
            directory_hash=directory_hash,
        ),
    )

    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-07-19T00:00:00Z",
        home_dir=tmp_path,
    )
    item = snapshot.items[0]
    evidence = item.metadata["contentEvidence"]

    assert item.content_hash == f"sha256:{directory_hash}"
    assert item.metadata["primaryContentHash"] == f"sha256:{primary_hash}"
    assert isinstance(evidence, dict)
    assert evidence["contentHash"] == f"sha256:{primary_hash}"
    assert (
        extract_aibom_metadata_extensions(item.metadata)["skillDirectoryIdentity"]
        == (item.metadata["skillDirectoryIdentity"])
    )


def test_inventory_snapshot_tracks_secondary_identity_and_is_time_stable(tmp_path: Path) -> None:
    skill_path = tmp_path / ".gemini" / "skills" / "review" / "SKILL.md"
    skill_path.parent.mkdir(parents=True)
    body = b"# Review\n"
    skill_path.write_bytes(body)
    primary_hash = _sha256(body)
    first_directory_hash = _sha256(b"scripts/check.py:first")
    first_detection = _skill_detection(
        skill_path,
        metadata=_complete_metadata(
            primary_hash=primary_hash,
            directory_hash=first_directory_hash,
        ),
    )

    first = inventory_snapshot_from_detection(
        first_detection,
        generated_at="2026-07-19T00:00:00Z",
        home_dir=tmp_path,
    )
    replayed = inventory_snapshot_from_detection(
        first_detection,
        generated_at="2026-07-19T01:00:00Z",
        home_dir=tmp_path,
    )
    second_directory_hash = _sha256(b"scripts/check.py:second")
    changed = inventory_snapshot_from_detection(
        _skill_detection(
            skill_path,
            metadata=_complete_metadata(
                primary_hash=primary_hash,
                directory_hash=second_directory_hash,
            ),
        ),
        generated_at="2026-07-19T02:00:00Z",
        home_dir=tmp_path,
    )

    assert replayed.snapshot_id == first.snapshot_id
    assert replayed.items[0].content_hash == first.items[0].content_hash
    assert changed.snapshot_id != first.snapshot_id
    assert changed.items[0].content_hash == f"sha256:{second_directory_hash}"
    assert changed.items[0].metadata["primaryContentHash"] == first.items[0].metadata["primaryContentHash"]


def test_unchanged_incomplete_skill_has_stable_snapshot_identity(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    skill_dir = home_dir / ".gemini" / "skills" / "review"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("# Review\n", encoding="utf-8")
    try:
        (skill_dir / "broken-reference").symlink_to("missing.md")
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=tmp_path / "guard")

    first_detection = GeminiHarnessAdapter().detect(context)
    second_detection = GeminiHarnessAdapter().detect(context)
    first = inventory_snapshot_from_detection(
        first_detection,
        generated_at="2026-07-19T00:00:00Z",
        home_dir=home_dir,
    )
    second = inventory_snapshot_from_detection(
        second_detection,
        generated_at="2026-07-19T00:00:00Z",
        home_dir=home_dir,
    )

    assert first.snapshot_id == second.snapshot_id
    assert first.items[0].content_hash == second.items[0].content_hash
    assert first.items[0].metadata["skillDirectoryIdentity"] == second.items[0].metadata["skillDirectoryIdentity"]


def test_symlinked_primary_is_nonreusable_and_not_uploadable(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    skill_dir = home_dir / ".gemini" / "skills" / "review"
    skill_dir.mkdir(parents=True)
    body = skill_dir / "BODY.md"
    body.write_text("# Review\n", encoding="utf-8")
    primary = skill_dir / "SKILL.md"
    try:
        primary.symlink_to(body.name)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=tmp_path / "guard")

    detection = GeminiHarnessAdapter().detect(context)
    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-07-19T00:00:00Z",
        home_dir=home_dir,
    )
    sources = primary_content_sources_from_artifacts(
        detection.artifacts,
        snapshot,
        workspace_dir=None,
    )
    identity = detection.artifacts[0].metadata["skillDirectoryIdentity"]

    assert isinstance(identity, dict)
    assert identity["status"] == "incomplete"
    assert identity["reason"] == "primary_symlink_unsupported"
    assert "primaryContentHash" not in snapshot.items[0].metadata
    assert sources == ()


def test_inventory_does_not_promote_incomplete_or_malformed_directory_claim(tmp_path: Path) -> None:
    skill_path = tmp_path / ".gemini" / "skills" / "review" / "SKILL.md"
    skill_path.parent.mkdir(parents=True)
    body = b"# Review\n"
    skill_path.write_bytes(body)
    primary_hash = _sha256(body)
    directory_hash = _sha256(b"partial walk")
    metadata = _complete_metadata(primary_hash=primary_hash, directory_hash=directory_hash)
    identity = metadata["skillDirectoryIdentity"]
    assert isinstance(identity, dict)
    identity.update({"status": "incomplete", "reusable": False, "reason": "entry_limit"})

    incomplete = inventory_snapshot_from_detection(
        _skill_detection(skill_path, metadata=metadata),
        generated_at="2026-07-19T00:00:00Z",
        home_dir=tmp_path,
    )
    mismatched_metadata = _complete_metadata(
        primary_hash=primary_hash,
        directory_hash=directory_hash,
    )
    mismatched_identity = mismatched_metadata["skillDirectoryIdentity"]
    assert isinstance(mismatched_identity, dict)
    mismatched_identity["contentHash"] = _sha256(b"different claim")
    mismatched = inventory_snapshot_from_detection(
        _skill_detection(skill_path, metadata=mismatched_metadata),
        generated_at="2026-07-19T00:00:00Z",
        home_dir=tmp_path,
    )

    assert incomplete.items[0].content_hash == f"sha256:{primary_hash}"
    assert mismatched.items[0].content_hash == f"sha256:{primary_hash}"
    assert incomplete.items[0].content_hash != f"sha256:{directory_hash}"
    assert "directory_hash" not in incomplete.items[0].metadata
    assert "directory_hash" not in mismatched.items[0].metadata


def test_unmigrated_hermes_skill_keeps_primary_only_inventory_identity(tmp_path: Path) -> None:
    skill_path = tmp_path / ".hermes" / "skills" / "ops" / "review" / "SKILL.md"
    skill_path.parent.mkdir(parents=True)
    body = b"# Hermes review\n"
    skill_path.write_bytes(body)
    detection = _skill_detection(
        skill_path,
        harness="hermes",
        metadata={"content_hash": _sha256(body)},
    )

    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-07-19T00:00:00Z",
        home_dir=tmp_path,
    )

    assert snapshot.items[0].content_hash == f"sha256:{_sha256(body)}"
    assert "skillDirectoryIdentity" not in snapshot.items[0].metadata


def test_primary_upload_uses_exact_skill_document_not_directory_identity(tmp_path: Path) -> None:
    skill_path = tmp_path / ".gemini" / "skills" / "review" / "SKILL.md"
    skill_path.parent.mkdir(parents=True)
    # Deliberately exceeds the 256 KiB analysis preview while remaining below
    # the primary-content uploader's 1 MiB body limit.
    body = b"# Review\n" + (b"A" * (300 * 1024))
    skill_path.write_bytes(body)
    primary_hash = _sha256(body)
    directory_hash = _sha256(b"directory stream including scripts and mode bits")
    detection = _skill_detection(
        skill_path,
        metadata=_complete_metadata(
            primary_hash=primary_hash,
            directory_hash=directory_hash,
        ),
    )
    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-07-19T00:00:00Z",
        home_dir=tmp_path,
    )
    sources = primary_content_sources_from_artifacts(
        detection.artifacts,
        snapshot,
        workspace_dir=None,
    )
    requests: list[bytes] = []

    def guard_sync_request(_auth_context, *, data, **_kwargs):
        requests.append(data)
        return SimpleNamespace(data=data)

    runner = SimpleNamespace(
        _guard_sync_request=guard_sync_request,
        _urlopen_json_with_timeout_retry=lambda **_kwargs: {
            "storedCount": 1,
            "hashOnlyCount": 0,
            "failedCount": 0,
        },
    )

    summary, _auth = upload_primary_content_sources(
        object(),
        runner,
        {"sync_url": "https://hol.test/api/v1/guard/events"},
        sources=sources,
        workspace_id="workspace-1",
    )
    payload = json.loads(requests[0])
    uploaded = payload["items"][0]

    assert snapshot.items[0].content_hash == f"sha256:{directory_hash}"
    assert sources[0].content_hash == f"sha256:{primary_hash}"
    assert uploaded["contentHash"] == f"sha256:{primary_hash}"
    assert base64.b64decode(uploaded["bodyBase64"]) == body
    assert summary["stored"] == 1
