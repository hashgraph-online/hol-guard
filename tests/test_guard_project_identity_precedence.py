from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.project_identity import resolve_portable_project_identity
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_project_identity import (
    _NOW,
    _activate_project_memory_bundle,
    _init_repository,
    _signed_project_memory_bundle,
)


def test_portable_block_does_not_consume_shadowed_local_one_shot(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    _init_repository(workspace, "git@example.invalid:owner/repository.git")
    project_identity = resolve_portable_project_identity(workspace)
    assert project_identity is not None

    store = GuardStore(tmp_path / "guard-home")
    store.record_local_once_approval(
        request_id="request-shadowed-local",
        harness="codex",
        artifact_id="tool:read",
        artifact_hash="sha256:shadowed-local",
        workspace=str(workspace),
        publisher=None,
        action="allow",
        created_at=_NOW,
        expires_at="2026-08-08T20:00:00+00:00",
    )
    _activate_project_memory_bundle(
        store,
        _signed_project_memory_bundle(
            ("portable-block", "block", project_identity),
        ),
    )

    assert (
        store.resolve_policy(
            "codex",
            "tool:read",
            artifact_hash="sha256:shadowed-local",
            workspace=str(workspace),
            now=_NOW,
        )
        == "block"
    )

    store.clear_policy_bundle_authority(
        "2026-08-07T20:01:00+00:00",
        policy_bundle_last_error={"code": "test-cleared"},
    )

    assert (
        store.resolve_policy(
            "codex",
            "tool:read",
            artifact_hash="sha256:shadowed-local",
            workspace=str(workspace),
            now="2026-08-07T20:02:00+00:00",
        )
        == "allow"
    )
    assert (
        store.resolve_policy(
            "codex",
            "tool:read",
            artifact_hash="sha256:shadowed-local",
            workspace=str(workspace),
            now="2026-08-07T20:03:00+00:00",
        )
        is None
    )
