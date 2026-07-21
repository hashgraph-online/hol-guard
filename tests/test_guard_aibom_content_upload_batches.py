"""Batching and transport tests for AIBOM primary-content upload."""

from __future__ import annotations

import hashlib
import json
import urllib.error
from dataclasses import replace
from email.message import Message
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.aibom_content_upload import (
    GuardAibomPrimaryContentSource,
    upload_primary_content_sources,
)


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
