"""A package install that waited on its own request may use the Cloud allow for it, once.

A Cloud Review "Allow once" resolves exactly one queue item and saves no
reusable approval. The package shim that queued the item waits for it in
process, so only that waiting install names the request, reads the exact Cloud
allow issued for it, and spends it. A later retry from a new process names no
request and is reviewed again.
"""

from __future__ import annotations

import os
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


def _ordinary_lookup_returns(store: GuardStore, monkeypatch: pytest.MonkeyPatch, decision: dict[str, object]) -> None:
    monkeypatch.setattr(
        store,
        "resolve_policy_decision_lookup",
        lambda *_args, **_kwargs: {"decision": dict(decision), "ignored_local_integrity": None},
    )


def test_a_family_rule_row_does_not_hide_the_waited_cloud_allow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The package-request family rule that queued the request for review is
    # broader than the exact Cloud allow answering that request.
    store, now = _cloud_approved_package_request(tmp_path, "pkg-cloud-family")
    family_row: dict[str, object] = {
        "action": "block",
        "artifact_hash": None,
        "artifact_id": "family:package-request",
        "decision_id": 3,
        "harness": "guard-cli",
        "owner": "rule-1",
        "scope": "harness",
        "source": "policy-bundle",
    }
    _ordinary_lookup_returns(store, monkeypatch, family_row)

    def hydrate(waited: tuple[str, ...]) -> dict[str, object]:
        return _hydrate(
            store,
            artifact=_artifact(),
            artifact_hash=ARTIFACT_HASH,
            policy_workspaces=(str(tmp_path / "app"),),
            now=now,
            waited_request_ids=waited,
        )

    unwaited = hydrate(())["decision"]
    assert isinstance(unwaited, dict)
    assert unwaited["artifact_id"] == "family:package-request"
    waited = hydrate(("pkg-cloud-family",))["decision"]
    assert isinstance(waited, dict)
    assert waited["authority_kind"] == "exact-cloud"
    assert waited["request_id"] == "pkg-cloud-family"


def test_a_block_saved_for_the_artifact_still_wins_over_the_waited_cloud_allow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, now = _cloud_approved_package_request(tmp_path, "pkg-cloud-block")
    _ordinary_lookup_returns(
        store,
        monkeypatch,
        {
            "action": "block",
            "artifact_hash": ARTIFACT_HASH,
            "artifact_id": ARTIFACT_ID,
            "decision_id": 4,
            "harness": "guard-cli",
            "scope": "artifact",
            "source": "approval-gate",
        },
    )

    facts = _hydrate(
        store,
        artifact=_artifact(),
        artifact_hash=ARTIFACT_HASH,
        policy_workspaces=(str(tmp_path / "app"),),
        now=now,
        waited_request_ids=("pkg-cloud-block",),
    )

    decision = facts["decision"]
    assert isinstance(decision, dict)
    assert decision["action"] == "block"
    assert decision["decision_id"] == 4


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


@pytest.mark.skipif(os.name == "nt", reason="launches a POSIX shell stub as npm")
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
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    launches = tmp_path / "npm-launches.txt"
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf 'launch\\n' >> '{launches}'\n", encoding="utf-8")
    npm.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))

    def check(now: str, waited: tuple[str, ...] = (), *, dry_run: bool = True) -> tuple[dict[str, object], int]:
        result = build_package_protect_payload(
            command=["npm", "install", "guard-proof"],
            store=store,
            workspace_dir=workspace,
            dry_run=dry_run,
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

    assert launches.exists() is False

    # The install that waited runs, and running it spends the allow.
    ran, ran_rc = check("2026-07-17T00:02:00Z", ("pkg-cloud-flow",), dry_run=False)
    assert ran_rc == 0
    assert ran["executed"] is True
    assert launches.read_text(encoding="utf-8").splitlines() == ["launch"]
    assert (
        store.peek_waited_exact_cloud_package_allow(
            request_id="pkg-cloud-flow",
            artifact_id=str(receipt["artifact_id"]),
            artifact_hash=str(receipt["artifact_hash"]),
            now="2026-07-17T00:02:00Z",
        )
        is None
    )

    # Once spent, even the request's own name no longer launches it.
    again, again_rc = check("2026-07-17T00:03:00Z", ("pkg-cloud-flow",), dry_run=False)
    assert again_rc == 2
    assert again["executed"] is False
    assert launches.read_text(encoding="utf-8").splitlines() == ["launch"]
