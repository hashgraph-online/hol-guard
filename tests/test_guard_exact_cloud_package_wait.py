"""A package install that waited on its own request may use the Cloud allow for it, once.

A Cloud Review "Allow once" resolves exactly one queue item and saves no
reusable approval. The package shim that queued the item waits for it in
process, so only that waiting install names the request, reads the exact Cloud
allow issued for it, and spends it. A later retry from a new process names no
request and is reviewed again.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import codex_plugin_scanner.guard.local_supply_chain as local_supply_chain_module
from codex_plugin_scanner.guard.local_supply_chain import build_package_protect_payload
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.native_package_policy_resolve import _hydrate
from codex_plugin_scanner.guard.runtime.exact_cloud_review import enable_exact_cloud_review
from codex_plugin_scanner.guard.runtime.exact_cloud_review_apply import apply_exact_cloud_review
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import connected_exact_review_store, remote_approval
from tests.manifest_install_fixtures import (
    _fake_policy_integrity_keyring,  # noqa: F401 -- registers the module autouse fixture
    _native_package_intent,  # noqa: F401 -- registers the module autouse fixture
    _package_policy_config,
    _review_package_evaluation,
)

ARTIFACT_ID = "guard-cli:project:package-request:npm-install-left-pad"
ARTIFACT_HASH = "hash-package-context"


def _package_request(
    request_id: str,
    workspace: Path,
    *,
    artifact_id: str = ARTIFACT_ID,
    artifact_hash: str = ARTIFACT_HASH,
) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="claude-code",
        artifact_id=artifact_id,
        artifact_name="npm install left-pad",
        artifact_type="package_request",
        artifact_hash=artifact_hash,
        publisher=None,
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("package_request",),
        source_scope="project",
        config_path=str(workspace / "hol-guard.toml"),
        workspace=str(workspace),
        launch_target="npm install left-pad",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:5474/approvals/{request_id}",
    )


def _cloud_approved_package_request(tmp_path: Path, request_id: str) -> tuple[GuardStore, str]:
    workspace = tmp_path / "app"
    workspace.mkdir()
    store = connected_exact_review_store(tmp_path)
    store.add_approval_request(_package_request(request_id, workspace), datetime.now(timezone.utc).isoformat())
    enable_exact_cloud_review(store)
    resolution = apply_exact_cloud_review(
        store,
        remote_approval=remote_approval(store, request_id, receipt_id=f"receipt-{request_id}"),
    )
    return store, str(resolution.resolved_request["resolved_at"])


def _artifact() -> SimpleNamespace:
    return SimpleNamespace(harness="guard-cli", artifact_id=ARTIFACT_ID, publisher=None)


def test_the_waiting_install_reads_the_cloud_allow_for_its_own_request(tmp_path: Path) -> None:
    store, now = _cloud_approved_package_request(tmp_path, "pkg-cloud-1")

    facts = _hydrate(
        store,
        artifact=_artifact(),
        artifact_hash=ARTIFACT_HASH,
        policy_workspaces=(str(tmp_path / "app"),),
        now=now,
        waited_request_ids=("pkg-cloud-1",),
    )

    decision = facts["decision"]
    assert isinstance(decision, dict)
    assert decision["authority_kind"] == "exact-cloud"
    assert decision["request_id"] == "pkg-cloud-1"
    request = facts["approval_request"]
    assert isinstance(request, dict)
    assert request["request_id"] == "pkg-cloud-1"
    assert request["artifact_type"] == "package_request"
    assert request["status"] == "resolved"


def test_a_retry_that_waited_on_nothing_reads_no_cloud_allow(tmp_path: Path) -> None:
    store, now = _cloud_approved_package_request(tmp_path, "pkg-cloud-2")

    facts = _hydrate(
        store,
        artifact=_artifact(),
        artifact_hash=ARTIFACT_HASH,
        policy_workspaces=(str(tmp_path / "app"),),
        now=now,
    )

    assert "decision" not in facts


def test_the_cloud_allow_binds_the_artifact_hash_and_is_spent_once(tmp_path: Path) -> None:
    store, now = _cloud_approved_package_request(tmp_path, "pkg-cloud-3")

    assert (
        store.peek_waited_exact_cloud_package_allow(
            request_id="pkg-cloud-3", artifact_id=ARTIFACT_ID, artifact_hash="hash-changed", now=now
        )
        is None
    )
    decision = store.peek_waited_exact_cloud_package_allow(
        request_id="pkg-cloud-3", artifact_id=ARTIFACT_ID, artifact_hash=ARTIFACT_HASH, now=now
    )
    assert decision is not None

    assert store.consume_waited_exact_cloud_package_allow(decision, now=now) is True
    assert store.consume_waited_exact_cloud_package_allow(decision, now=now) is False
    assert (
        store.peek_waited_exact_cloud_package_allow(
            request_id="pkg-cloud-3", artifact_id=ARTIFACT_ID, artifact_hash=ARTIFACT_HASH, now=now
        )
        is None
    )


def test_the_install_that_waited_runs_once_and_a_later_retry_is_reviewed_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        local_supply_chain_module,
        "evaluate_package_request_artifact",
        lambda **_kwargs: _review_package_evaluation(),
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = connected_exact_review_store(tmp_path)
    config = _package_policy_config(guard_home=store.guard_home, workspace_dir=workspace)

    def check(now: str, waited: tuple[str, ...] = ()) -> tuple[dict[str, object], int]:
        result = build_package_protect_payload(
            command=["npm", "install", "guard-proof"],
            store=store,
            workspace_dir=workspace,
            dry_run=True,
            now=now,
            config=config,
            unsafe_raw_output=False,
            timeout_seconds=30,
            waited_request_ids=waited,
        )
        assert result is not None
        return result

    baseline, baseline_rc = check("2026-07-17T00:00:00Z")
    assert baseline_rc == 2
    receipt = baseline["receipt"]
    assert isinstance(receipt, dict)
    request = _package_request(
        "pkg-cloud-flow",
        workspace,
        artifact_id=str(receipt["artifact_id"]),
        artifact_hash=str(receipt["artifact_hash"]),
    )
    store.add_approval_request(request, datetime.now(timezone.utc).isoformat())
    enable_exact_cloud_review(store)
    apply_exact_cloud_review(store, remote_approval=remote_approval(store, "pkg-cloud-flow", receipt_id="receipt-flow"))

    # A retry from a new process names no request: still a review.
    _, retry_rc = check("2026-07-17T00:01:00Z")
    assert retry_rc == 2

    # The install that waited on the request may run.
    waited, waited_rc = check("2026-07-17T00:01:00Z", ("pkg-cloud-flow",))
    assert waited_rc == 0
    evaluation = waited["supply_chain_evaluation"]
    assert isinstance(evaluation, dict)
    assert evaluation["reasons"][0]["code"] == "saved_package_approval"

    # Running it spends the allow: the claim the resolver asks for consumes it.
    now = "2026-07-17T00:02:00Z"
    authority = local_supply_chain_module._build_package_protect_authority(  # pyright: ignore[reportPrivateUsage]
        command=["npm", "install", "guard-proof"],
        store=store,
        workspace_dir=workspace,
        now=now,
        config=config,
        additional_current_action=None,
        additional_policy_context=None,
    )
    assert authority is not None
    claimed = local_supply_chain_module._resolve_stored_package_policy_override(  # pyright: ignore[reportPrivateUsage]
        authority.evaluation,
        store=store,
        artifact=authority.artifact,
        artifact_hash=authority.artifact_hash,
        workspace_dir=workspace,
        now=now,
        execution_context=authority.execution_context,
        current_action=authority.current_action,
        claim_saved_approval=True,
        waited_request_ids=("pkg-cloud-flow",),
    )
    assert claimed.claim_disposition == "consumed"
    assert claimed.evaluation.reasons[0]["code"] == "saved_package_approval"
    assert (
        store.peek_waited_exact_cloud_package_allow(
            request_id="pkg-cloud-flow",
            artifact_id=str(receipt["artifact_id"]),
            artifact_hash=str(receipt["artifact_hash"]),
            now=now,
        )
        is None
    )

    # Once spent, even the request's own name no longer lets it run.
    _, again_rc = check("2026-07-17T00:03:00Z", ("pkg-cloud-flow",))
    assert again_rc == 2
