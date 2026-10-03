from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.codex_live_decision as live_decision_module
from codex_plugin_scanner.guard.codex_live_decision import complete_codex_live_decision
from codex_plugin_scanner.guard.local_authority_integrity import sign_local_authority_payload
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.runtime.exact_cloud_review import enable_exact_cloud_review
from codex_plugin_scanner.guard.runtime.exact_cloud_review_apply import apply_exact_cloud_review
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_exact_cloud_local_once import claim_exact_cloud_local_once_approval_locked
from tests.guard_exact_cloud_review_support import (
    add_review_request,
    connected_exact_review_store,
    remote_approval,
    review_request,
)
from tests.test_codex_live_decision import _seed_waiting_request


def _workspace_key(value: str) -> str:
    return f"workspace:{sha256(str(Path(value).resolve()).encode('utf-8')).hexdigest()}"


def test_exact_cloud_authority_is_invisible_to_generic_lookup_and_request_bound(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    request = review_request("exact-provenance-bound")
    add_review_request(store, request)
    _ = enable_exact_cloud_review(store)
    resolution = apply_exact_cloud_review(
        store,
        remote_approval=remote_approval(store, request.request_id, receipt_id="exact-provenance-receipt"),
    )
    resolved = store.get_approval_request(request.request_id)
    assert isinstance(resolved, dict)
    resolved_at = str(resolution.resolved_request["resolved_at"])

    generic = store.resolve_policy_decision_lookup(
        request.harness,
        request.artifact_id,
        artifact_hash=request.artifact_hash,
        workspace=request.workspace,
        publisher=request.publisher,
        now=resolved_at,
        consume_one_shot=False,
    )
    assert generic["decision"] is None
    assert generic["ignored_local_integrity"] is None

    exact = store.peek_exact_cloud_local_once_approval(request_id=request.request_id, now=resolved_at)
    assert exact is not None
    assert exact["authority_kind"] == "exact-cloud"
    assert exact["request_id"] == request.request_id
    approval_id = exact["approval_id"]
    assert isinstance(approval_id, str)
    assert store.claim_local_once_approval(approval_id, claimed_at=resolved_at) is False
    assert store.claim_approval_reuse_decision(exact, now=resolved_at) is False

    assert store.peek_exact_cloud_local_once_approval(request_id="caller-chosen-request", now=resolved_at) is None
    key, key_id = store._policy_integrity_secret_material(create=False)  # pyright: ignore[reportPrivateUsage]
    assert key is not None and key_id is not None
    with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
        _ = connection.execute("begin immediate")
        claimed = claim_exact_cloud_local_once_approval_locked(
            connection,
            request_id=request.request_id,
            expected_decision=exact,
            now=resolved_at,
            integrity_key=key,
            integrity_key_id=key_id,
        )
    assert claimed is not None
    assert store.peek_exact_cloud_local_once_approval(request_id=request.request_id, now=resolved_at) is None


def test_new_legacy_local_once_authority_preserves_generic_package_path(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    approval_id = store.record_local_once_approval(
        request_id="legacy-local-request",
        harness="codex",
        artifact_id="codex:project:tool-action:legacy",
        artifact_hash="hash-legacy",
        workspace="/workspace/repo",
        publisher=None,
        action="allow",
        created_at="2026-07-17T12:00:00+00:00",
        expires_at="2026-07-17T14:00:00+00:00",
    )
    assert approval_id is not None
    lookup = store.resolve_policy_decision_lookup(
        "codex",
        "codex:project:tool-action:legacy",
        artifact_hash="hash-legacy",
        workspace="/workspace/repo",
        now="2026-07-17T12:30:00+00:00",
        consume_one_shot=False,
    )
    assert lookup["decision"] is not None
    assert lookup["decision"]["authority_kind"] == "legacy"


def test_valid_old_mac_without_provenance_is_quarantined(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    key, key_id = store._policy_integrity_secret_material(create=True)  # pyright: ignore[reportPrivateUsage]
    assert key is not None and key_id is not None
    row = {
        "approval_id": "old-mac-row",
        "request_id": "old-exact-cloud-request",
        "harness": "codex",
        "artifact_id": "codex:project:tool-action:old",
        "artifact_hash": "hash-old",
        "workspace": _workspace_key("/workspace/repo"),
        "publisher": None,
        "action": "allow",
        "created_at": "2026-07-17T12:00:00+00:00",
        "expires_at": "2026-07-17T14:00:00+00:00",
        "claimed_at": None,
    }
    integrity = sign_local_authority_payload(
        row,
        key=key,
        key_id=key_id,
        purpose="guard-local-once-approval",
        signed_at=str(row["created_at"]),
    )
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """
            insert into guard_local_once_approvals (
              approval_id, request_id, harness, artifact_id, artifact_hash, workspace, publisher, action,
              created_at, expires_at, claimed_at, integrity_version, payload_hash, payload_mac,
              integrity_key_id, signed_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                *row.values(),
                integrity["integrity_version"],
                integrity["payload_hash"],
                integrity["payload_mac"],
                integrity["integrity_key_id"],
                integrity["signed_at"],
            ),
        )

    lookup = store.resolve_policy_decision_lookup(
        "codex",
        "codex:project:tool-action:old",
        artifact_hash="hash-old",
        workspace="/workspace/repo",
        now="2026-07-17T12:30:00+00:00",
        consume_one_shot=False,
    )
    assert lookup["decision"] is None
    ignored = lookup["ignored_local_integrity"]
    assert isinstance(ignored, dict)
    assert ignored["integrity_status"] == "ambiguous_legacy"


def test_live_completion_consumes_only_original_exact_cloud_request(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    shared_artifact_id = "codex:project:identical-artifact"
    shared_artifact_hash = "hash-identical-artifact"
    store, _ = _seed_waiting_request(
        tmp_path,
        request_id="exact-live-original",
        store=store,
        artifact_id=shared_artifact_id,
        artifact_hash=shared_artifact_hash,
    )
    store, sibling_now = _seed_waiting_request(
        tmp_path,
        request_id="exact-live-sibling",
        store=store,
        artifact_id=shared_artifact_id,
        artifact_hash=shared_artifact_hash,
        target_path="/workspace/project/other.txt",
    )
    enable_exact_cloud_review(store)
    resolution = apply_exact_cloud_review(
        store,
        remote_approval=remote_approval(store, "exact-live-original", receipt_id="exact-live-receipt"),
    )
    resolved_at = str(resolution.resolved_request["resolved_at"])
    assert store.resolve_one_request_only(
        "exact-live-sibling",
        resolution_action="allow",
        resolution_scope="artifact",
        reason="identical artifact must remain request-bound",
        resolved_at=sibling_now,
    )

    sibling_result = complete_codex_live_decision(
        store,
        request_id="exact-live-sibling",
        now=sibling_now,
        fresh_allow_authorized=True,
    )
    assert sibling_result == {"completed": False, "error": "exact_approval_authority_missing"}
    assert store.peek_exact_cloud_local_once_approval(request_id="exact-live-original", now=resolved_at) is not None

    original_result = complete_codex_live_decision(
        store,
        request_id="exact-live-original",
        now=resolved_at,
        fresh_allow_authorized=True,
    )
    assert original_result["completed"] is True
    assert original_result["action"] == "allow"
    assert store.peek_exact_cloud_local_once_approval(request_id="exact-live-original", now=resolved_at) is None
    resume = store.get_request_resume("exact-live-original")
    assert resume is not None and resume["status"] == "sent"


def test_live_completion_fails_closed_when_authority_revision_changes_before_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = connected_exact_review_store(tmp_path)
    store, _ = _seed_waiting_request(
        tmp_path,
        request_id="exact-live-revision-race",
        store=store,
    )
    enable_exact_cloud_review(store)
    resolution = apply_exact_cloud_review(
        store,
        remote_approval=remote_approval(store, "exact-live-revision-race", receipt_id="exact-race-receipt"),
    )
    resolved_at = str(resolution.resolved_request["resolved_at"])
    original_record = live_decision_module.record_live_hook_completion

    def mutate_authority_then_record(
        completion_store: GuardStore,
        *,
        request_id: str,
        action: str,
        now: str,
        approval_decision: Mapping[str, object] | None = None,
    ) -> dict[str, object] | None:
        completion_store.replace_remote_policies(
            [
                PolicyDecision(
                    harness="codex",
                    scope="artifact",
                    action="block",
                    artifact_id="codex:project:unrelated-authority-mutation",
                    artifact_hash="hash-unrelated-authority-mutation",
                    workspace="/workspace/project",
                    source="team-policy",
                )
            ],
            now,
            remote_write_authorized=True,
        )
        return original_record(
            completion_store,
            request_id=request_id,
            action=action,
            now=now,
            approval_decision=approval_decision,
        )

    monkeypatch.setattr(live_decision_module, "record_live_hook_completion", mutate_authority_then_record)
    result = complete_codex_live_decision(
        store,
        request_id="exact-live-revision-race",
        now=resolved_at,
        fresh_allow_authorized=True,
    )

    assert result == {"completed": False, "error": "continuation_not_recorded"}
    assert (
        store.peek_exact_cloud_local_once_approval(request_id="exact-live-revision-race", now=resolved_at) is not None
    )
    resume = store.get_request_resume("exact-live-revision-race")
    assert resume is not None and resume["status"] == "pending"
