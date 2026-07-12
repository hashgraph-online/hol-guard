from __future__ import annotations

import hashlib
import json
import urllib.error
from dataclasses import replace
from email.message import Message
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.gemini import GeminiHarnessAdapter
from codex_plugin_scanner.guard.aibom_content_upload import (
    GuardAibomPrimaryContentSource,
    primary_content_sources_from_artifacts,
    upload_primary_content_sources,
)
from codex_plugin_scanner.guard.inventory_contract import (
    cloud_inventory_artifacts_from_detection,
    inventory_snapshot_from_detection,
)
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection


def _source(skills_root: Path, index: int) -> GuardAibomPrimaryContentSource:
    path = skills_root / "category" / f"skill-{index}" / "SKILL.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    body = f"# Skill {index}\n".encode()
    path.write_bytes(body)
    content_hash = f"sha256:{hashlib.sha256(body).hexdigest()}"
    return GuardAibomPrimaryContentSource(
        agent_id="hermes:local",
        allowed_root=skills_root,
        content_hash=content_hash,
        harness_id="hermes",
        item_id=f"hermes:skill:category:skill-{index}",
        item_kind="skill",
        mime_type="text/markdown; charset=utf-8",
        path=path,
        snapshot_id="hermes:snapshot:1",
        version_id=f"fingerprint-{index}",
    )


@pytest.mark.parametrize(
    "harness",
    (
        "hermes",
        "openclaw",
        "codex",
        "claude-code",
        "cursor",
        "antigravity",
        "gemini",
        "opencode",
        "kimi",
        "grok",
        "pi",
        "zcode",
    ),
)
def test_primary_content_sources_include_skill_bodies_for_every_harness(
    tmp_path: Path,
    harness: str,
) -> None:
    skill_path = tmp_path / f".{harness}" / "skills" / "ops" / "review" / "SKILL.md"
    skill_path.parent.mkdir(parents=True)
    body = f"# {harness} review skill\n".encode()
    skill_path.write_bytes(body)
    raw_content_hash = hashlib.sha256(body).hexdigest()
    item_id = f"{harness}:skill:ops:review"
    artifact = GuardArtifact(
        artifact_id=item_id,
        name="review",
        harness=harness,
        artifact_type="skill",
        source_scope="global",
        config_path=str(skill_path),
    )
    detection = HarnessDetection(
        harness=harness,
        installed=True,
        command_available=False,
        config_paths=(str(skill_path),),
        artifacts=(artifact,),
    )

    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-07-10T00:00:00Z",
        home_dir=tmp_path,
    )
    sources = primary_content_sources_from_artifacts(
        detection.artifacts,
        snapshot,
        workspace_dir=None,
    )

    assert len(sources) == 1
    assert sources[0].item_id == item_id
    assert sources[0].content_hash == f"sha256:{raw_content_hash}"
    assert sources[0].path == skill_path


def test_gemini_adapter_skill_without_metadata_hash_has_uploadable_primary_content(tmp_path: Path) -> None:
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )
    skill_path = context.home_dir / ".gemini" / "skills" / "review" / "SKILL.md"
    skill_path.parent.mkdir(parents=True)
    skill_path.write_text("# Gemini review\n", encoding="utf-8")

    detection = GeminiHarnessAdapter().detect(context)
    skill_artifact = next(artifact for artifact in detection.artifacts if artifact.artifact_type == "skill")
    assert "content_hash" not in skill_artifact.metadata

    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-07-10T00:00:00Z",
        home_dir=context.home_dir,
    )
    sources = primary_content_sources_from_artifacts(
        detection.artifacts,
        snapshot,
        workspace_dir=None,
    )

    assert len(sources) == 1
    assert sources[0].content_hash == f"sha256:{hashlib.sha256(skill_path.read_bytes()).hexdigest()}"
    assert sources[0].path == skill_path

    runner = SimpleNamespace(
        _guard_sync_request=lambda *_args, **kwargs: SimpleNamespace(data=kwargs["data"]),
        _urlopen_json_with_timeout_retry=lambda **_kwargs: {
            "storedCount": 1,
            "hashOnlyCount": 0,
            "failedCount": 0,
        },
    )
    summary, _auth_context = upload_primary_content_sources(
        object(),
        runner,
        {"sync_url": "https://hol.test/api/v1/guard/events"},
        sources=sources,
        workspace_id="workspace-1",
    )

    assert summary["eligible"] == 1
    assert summary["attempted"] == 1
    assert summary["stored"] == 1
    assert summary["failed"] == 0


def test_gemini_skill_through_symlinked_workspace_has_uploadable_primary_content(tmp_path: Path) -> None:
    real_workspace = tmp_path / "workspace-real"
    workspace_dir = tmp_path / "workspace-link"
    skill_path = workspace_dir / ".gemini" / "skills" / "review" / "SKILL.md"
    real_skill_path = real_workspace / ".gemini" / "skills" / "review" / "SKILL.md"
    real_skill_path.parent.mkdir(parents=True)
    real_skill_path.write_text("# Symlinked workspace review\n", encoding="utf-8")
    workspace_dir.symlink_to(real_workspace, target_is_directory=True)
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )

    detection = GeminiHarnessAdapter().detect(context)
    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-07-10T00:00:00Z",
        home_dir=context.home_dir,
        workspace_dir=workspace_dir,
    )
    sources = primary_content_sources_from_artifacts(
        detection.artifacts,
        snapshot,
        workspace_dir=workspace_dir,
    )
    expected_hash = f"sha256:{hashlib.sha256(real_skill_path.read_bytes()).hexdigest()}"

    assert len(sources) == 1
    assert sources[0].path == skill_path
    assert sources[0].content_hash == expected_hash


def test_workspace_instruction_without_metadata_hash_has_uploadable_primary_content(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    instruction_path = workspace_dir / "AGENTS.md"
    instruction_path.parent.mkdir(parents=True)
    instruction_path.write_text("# Workspace instructions\n", encoding="utf-8")
    artifact = GuardArtifact(
        artifact_id="codex:project:instruction:AGENTS.md",
        name="AGENTS.md",
        harness="codex",
        artifact_type="instruction",
        source_scope="project",
        config_path=str(instruction_path),
    )
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=False,
        config_paths=(str(instruction_path),),
        artifacts=(artifact,),
    )
    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-07-10T00:00:00Z",
        home_dir=tmp_path / "home",
        workspace_dir=workspace_dir,
    )

    sources = primary_content_sources_from_artifacts(
        detection.artifacts,
        snapshot,
        workspace_dir=workspace_dir,
    )

    assert len(sources) == 1
    assert sources[0].content_hash == f"sha256:{hashlib.sha256(instruction_path.read_bytes()).hexdigest()}"
    assert sources[0].path == instruction_path


def test_primary_content_sources_ignore_supplementary_skill_files(tmp_path: Path) -> None:
    skill_root = tmp_path / ".codex" / "skills" / "review"
    primary_path = skill_root / "SKILL.md"
    supplementary_path = skill_root / "references" / "commands.md"
    primary_path.parent.mkdir(parents=True)
    supplementary_path.parent.mkdir(parents=True)
    primary_path.write_text("# Review\n", encoding="utf-8")
    supplementary_path.write_text("Supplementary commands\n", encoding="utf-8")
    primary_hash = hashlib.sha256(primary_path.read_bytes()).hexdigest()
    item_id = "codex:skill:review"
    primary = GuardArtifact(
        artifact_id=item_id,
        name="review",
        harness="codex",
        artifact_type="skill",
        source_scope="global",
        config_path=str(primary_path),
        metadata={"content_hash": primary_hash},
    )
    supplementary = GuardArtifact(
        artifact_id="codex:skill-file:review:references/commands.md",
        name="commands.md",
        harness="codex",
        artifact_type="skill_file",
        source_scope="global",
        config_path=str(supplementary_path),
    )
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=False,
        config_paths=(str(primary_path),),
        artifacts=(primary, supplementary),
    )
    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-07-10T00:00:00Z",
        home_dir=tmp_path,
    )

    sources = primary_content_sources_from_artifacts(
        detection.artifacts,
        snapshot,
        workspace_dir=None,
    )

    assert [source.path for source in sources] == [primary_path]


def test_openclaw_supplementary_skill_files_stay_out_of_cloud_inventory(tmp_path: Path) -> None:
    skill_path = tmp_path / ".openclaw" / "skills" / "review" / "SKILL.md"
    reference_path = skill_path.parent / "references" / "commands.md"
    skill_path.parent.mkdir(parents=True)
    reference_path.parent.mkdir(parents=True)
    skill_path.write_text("# Review\n", encoding="utf-8")
    reference_path.write_text("Supplementary commands\n", encoding="utf-8")
    primary = GuardArtifact(
        artifact_id="openclaw:skill:review",
        name="review",
        harness="openclaw",
        artifact_type="skill",
        source_scope="global",
        config_path=str(skill_path),
    )
    supplementary = GuardArtifact(
        artifact_id="openclaw:skill:review:references/commands.md",
        name="review/references/commands.md",
        harness="openclaw",
        artifact_type="skill_file",
        source_scope="global",
        config_path=str(reference_path),
    )
    detection = HarnessDetection(
        harness="openclaw",
        installed=True,
        command_available=False,
        config_paths=(str(skill_path),),
        artifacts=(primary, supplementary),
    )

    cloud_artifacts = cloud_inventory_artifacts_from_detection(
        detection,
        home_dir=tmp_path,
    )

    assert [artifact.artifact_id for artifact in cloud_artifacts] == [primary.artifact_id]


def test_symlinked_primary_skill_does_not_advertise_uploadable_body_hash(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    real_skill_dir = home_dir / ".codex" / "real-skills" / "review"
    real_skill_dir.mkdir(parents=True)
    real_skill_path = real_skill_dir / "SKILL.md"
    real_skill_path.write_text("# Review\n", encoding="utf-8")
    skills_root = home_dir / ".codex" / "skills"
    skills_root.mkdir(parents=True)
    linked_skill_dir = skills_root / "review"
    linked_skill_dir.symlink_to(real_skill_dir, target_is_directory=True)
    linked_skill_path = linked_skill_dir / "SKILL.md"
    artifact = GuardArtifact(
        artifact_id="codex:skill:review",
        name="review",
        harness="codex",
        artifact_type="skill",
        source_scope="global",
        config_path=str(linked_skill_path),
        metadata={"content_hash": hashlib.sha256(real_skill_path.read_bytes()).hexdigest()},
    )
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=False,
        config_paths=(str(linked_skill_path),),
        artifacts=(artifact,),
    )

    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-07-10T00:00:00Z",
        home_dir=home_dir,
    )
    sources = primary_content_sources_from_artifacts(
        detection.artifacts,
        snapshot,
        workspace_dir=None,
    )
    body_hash = f"sha256:{hashlib.sha256(real_skill_path.read_bytes()).hexdigest()}"

    assert snapshot.items[0].content_hash != body_hash
    assert not snapshot.items[0].content_hash.startswith("sha256:")
    assert sources == ()


def test_skill_outside_skills_root_does_not_advertise_uploadable_body_hash(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    skill_path = home_dir / ".codex" / "review" / "SKILL.md"
    skill_path.parent.mkdir(parents=True)
    skill_path.write_text("# Review\n", encoding="utf-8")
    artifact = GuardArtifact(
        artifact_id="codex:skill:review",
        name="review",
        harness="codex",
        artifact_type="skill",
        source_scope="global",
        config_path=str(skill_path),
        metadata={"content_hash": hashlib.sha256(skill_path.read_bytes()).hexdigest()},
    )
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=False,
        config_paths=(str(skill_path),),
        artifacts=(artifact,),
    )

    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-07-10T00:00:00Z",
        home_dir=home_dir,
    )
    sources = primary_content_sources_from_artifacts(
        detection.artifacts,
        snapshot,
        workspace_dir=None,
    )

    assert not snapshot.items[0].content_hash.startswith("sha256:")
    assert sources == ()


def test_primary_content_upload_batches_exact_bodies_and_item_count(tmp_path: Path) -> None:
    sources = tuple(_source(tmp_path / "skills", index) for index in range(101))
    requests: list[SimpleNamespace] = []

    def guard_sync_request(_auth_context, *, request_url, method, data, extra_headers):
        request = SimpleNamespace(data=data, full_url=request_url, method=method)
        requests.append(request)
        assert extra_headers is None
        return request

    def respond(*, request, **_kwargs):
        payload = json.loads(request.data)
        return {
            "storedCount": len(payload["items"]),
            "hashOnlyCount": 0,
            "failedCount": 0,
        }

    runner = SimpleNamespace(
        _guard_sync_request=guard_sync_request,
        _urlopen_json_with_timeout_retry=respond,
    )

    summary, _auth_context = upload_primary_content_sources(
        object(),
        runner,
        {"sync_url": "https://hol.test/api/v1/guard/events"},
        sources=sources,
        workspace_id="workspace-1",
    )

    assert summary == {
        "eligible": 101,
        "attempted": 101,
        "uploaded": 101,
        "stored": 101,
        "hash_only": 0,
        "failed": 0,
        "skipped": 0,
        "batches": 2,
    }
    assert [len(json.loads(request.data)["items"]) for request in requests] == [100, 1]
    assert all(
        request.full_url.endswith("/api/guard/aibom/workspaces/workspace-1/content-upload") for request in requests
    )
    first_item = json.loads(requests[0].data)["items"][0]
    assert first_item["bodyBase64"] == "IyBTa2lsbCAwCg=="
    assert first_item["agentId"] == sources[0].agent_id
    assert first_item["contentHash"] == sources[0].content_hash
    assert first_item["snapshotId"] == sources[0].snapshot_id
    assert first_item["versionId"] == sources[0].version_id


def test_primary_content_upload_failure_is_nonfatal(tmp_path: Path) -> None:
    source = _source(tmp_path / "skills", 1)

    def fail(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            url="https://hol.test/content-upload",
            code=404,
            msg="Not Found",
            hdrs=Message(),
            fp=None,
        )

    runner = SimpleNamespace(
        _guard_sync_request=lambda *_args, **kwargs: SimpleNamespace(data=kwargs["data"]),
        _urlopen_json_with_timeout_retry=fail,
    )

    summary, _auth_context = upload_primary_content_sources(
        object(),
        runner,
        {"sync_url": "https://hol.test/api/v1/guard/events"},
        sources=(source,),
        workspace_id="workspace-1",
    )

    assert summary["attempted"] == 1
    assert summary["uploaded"] == 0
    assert summary["failed"] == 1
    assert summary["reason"] == "endpoint_unavailable"


def test_primary_content_upload_accounts_for_partial_batch_failure(tmp_path: Path) -> None:
    sources = tuple(_source(tmp_path / "skills", index) for index in range(2))
    runner = SimpleNamespace(
        _guard_sync_request=lambda *_args, **kwargs: SimpleNamespace(data=kwargs["data"]),
        _urlopen_json_with_timeout_retry=lambda **_kwargs: {
            "storedCount": 1,
            "hashOnlyCount": 0,
            "failedCount": 1,
        },
    )

    summary, _auth_context = upload_primary_content_sources(
        object(),
        runner,
        {"sync_url": "https://hol.test/api/v1/guard/events"},
        sources=sources,
        workspace_id="workspace-1",
    )

    assert summary["attempted"] == 2
    assert summary["uploaded"] == 1
    assert summary["stored"] == 1
    assert summary["hash_only"] == 0
    assert summary["failed"] == 1


def test_primary_content_upload_skips_changed_body(tmp_path: Path) -> None:
    source = _source(tmp_path / "skills", 1)
    source.path.write_text("changed after snapshot\n", encoding="utf-8")
    runner = SimpleNamespace(
        _guard_sync_request=lambda *_args, **_kwargs: None,
        _urlopen_json_with_timeout_retry=lambda **_kwargs: {},
    )

    summary, _auth_context = upload_primary_content_sources(
        object(),
        runner,
        {"sync_url": "https://hol.test/api/v1/guard/events"},
        sources=(source,),
        workspace_id="workspace-1",
    )

    assert summary["eligible"] == 1
    assert summary["attempted"] == 0
    assert summary["skipped"] == 1


def test_primary_content_upload_accepts_an_empty_primary_file(tmp_path: Path) -> None:
    source = _source(tmp_path / "skills", 1)
    source.path.write_bytes(b"")
    source = replace(
        source,
        content_hash=f"sha256:{hashlib.sha256(b'').hexdigest()}",
    )
    runner = SimpleNamespace(
        _guard_sync_request=lambda *_args, **kwargs: SimpleNamespace(data=kwargs["data"]),
        _urlopen_json_with_timeout_retry=lambda **_kwargs: {
            "storedCount": 1,
            "hashOnlyCount": 0,
            "failedCount": 0,
        },
    )

    summary, _auth_context = upload_primary_content_sources(
        object(),
        runner,
        {"sync_url": "https://hol.test/api/v1/guard/events"},
        sources=(source,),
        workspace_id="workspace-1",
    )

    assert summary["attempted"] == 1
    assert summary["stored"] == 1
    assert summary["failed"] == 0
