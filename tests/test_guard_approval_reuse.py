from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from typing import cast

import pytest

from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import _runtime_saved_allow_validation_reason
from codex_plugin_scanner.guard.memory_pattern_fingerprint import build_exact_command_memory_artifact_id
from codex_plugin_scanner.guard.models import (
    GUARD_ACTION_VALUES,
    DecisionScope,
    GuardAction,
    GuardApprovalRequest,
    GuardArtifact,
    PolicyDecision,
)
from codex_plugin_scanner.guard.runtime.approval_context import build_approval_context_token
from codex_plugin_scanner.guard.runtime.approval_reuse import (
    APPROVAL_REUSE_ACCEPTED,
    APPROVAL_REUSE_CLAIM_FAILED,
    APPROVAL_REUSE_CURRENT_ACTION_NOT_REVIEW,
    APPROVAL_REUSE_CURRENT_ACTION_UNKNOWN,
    APPROVAL_REUSE_CURRENT_BLOCK,
    APPROVAL_REUSE_NO_SAVED_DECISION,
    APPROVAL_REUSE_REAPPROVAL_REQUIRED,
    APPROVAL_REUSE_SANDBOX_REQUIRED,
    APPROVAL_REUSE_SAVED_ACTION_NOT_ALLOW,
    APPROVAL_REUSE_SAVED_ACTION_UNKNOWN,
    APPROVAL_REUSE_SAVED_BLOCK,
    ApprovalReuseValidationFailure,
    evaluate_approval_reuse,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_policy import (
    _bounded_local_approval_reuse_diagnostic_rows,
    _bounded_non_consuming_policy_rows,
    _bounded_policy_approval_reuse_diagnostic_rows,
)


def _approval_context_token(
    *,
    identity: object | None = None,
    content: str = "sha256:content",
    capabilities: object | None = None,
    policy: object | None = None,
    sandbox: object | None = None,
) -> str:
    return build_approval_context_token(
        identity=identity
        if identity is not None
        else {"artifact_id": "codex:project:mcp-tool:read", "workspace": "/workspace/a"},
        content=content,
        capabilities=capabilities if capabilities is not None else ["filesystem:read"],
        policy=policy if policy is not None else {"version": "policy-v1"},
        sandbox=sandbox if sandbox is not None else {"profile": "workspace-read"},
    )


@pytest.mark.parametrize("current_action", GUARD_ACTION_VALUES)
def test_no_saved_approval_preserves_recomputed_current_action(current_action: str) -> None:
    result = evaluate_approval_reuse(current_action)

    assert result.action == current_action
    assert result.status == "not-applicable"
    assert result.reason_code == APPROVAL_REUSE_NO_SAVED_DECISION
    assert result.should_claim is False


def test_exact_saved_allow_can_satisfy_only_current_review() -> None:
    result = evaluate_approval_reuse("review", "allow")

    assert result.action == "allow"
    assert result.status == "accepted"
    assert result.reason_code == APPROVAL_REUSE_ACCEPTED
    assert result.should_claim is True


@pytest.mark.parametrize(
    ("current_action", "expected_reason"),
    (
        ("require-reapproval", APPROVAL_REUSE_REAPPROVAL_REQUIRED),
        ("sandbox-required", APPROVAL_REUSE_SANDBOX_REQUIRED),
        ("block", APPROVAL_REUSE_CURRENT_BLOCK),
    ),
)
def test_saved_allow_never_lowers_stronger_current_action(current_action: str, expected_reason: str) -> None:
    result = evaluate_approval_reuse(current_action, "allow")

    assert result.action == current_action
    assert result.status == "rejected"
    assert result.reason_code == expected_reason
    assert result.should_claim is False


@pytest.mark.parametrize("current_action", ("allow", "warn"))
def test_saved_allow_is_not_consumed_when_current_action_needs_no_review(current_action: str) -> None:
    result = evaluate_approval_reuse(current_action, "allow")

    assert result.action == current_action
    assert result.status == "not-applicable"
    assert result.reason_code == APPROVAL_REUSE_CURRENT_ACTION_NOT_REVIEW
    assert result.should_claim is False


def test_integrity_invalid_authority_requires_reapproval_even_when_current_action_allows() -> None:
    result = evaluate_approval_reuse(
        "allow",
        "allow",
        validation_reason="approval_reuse_integrity_failure",
    )

    assert result.action == "require-reapproval"
    assert result.status == "rejected"
    assert result.reason_code == "approval_reuse_integrity_failure"
    assert result.should_claim is False


@pytest.mark.parametrize("current_action", GUARD_ACTION_VALUES)
def test_saved_block_remains_block_for_every_current_action(current_action: str) -> None:
    result = evaluate_approval_reuse(current_action, "block")

    assert result.action == "block"
    assert result.status == "accepted"
    assert result.reason_code == APPROVAL_REUSE_SAVED_BLOCK
    assert result.should_claim is False


def test_non_allow_saved_action_cannot_satisfy_review() -> None:
    result = evaluate_approval_reuse("review", "warn")

    assert result.action == "review"
    assert result.status == "rejected"
    assert result.reason_code == APPROVAL_REUSE_SAVED_ACTION_NOT_ALLOW


@pytest.mark.parametrize(
    ("validation_reason", "expected_action"),
    (
        ("approval_reuse_identity_changed", "review"),
        ("approval_reuse_content_changed", "review"),
        ("approval_reuse_capability_changed", "review"),
        ("approval_reuse_policy_changed", "review"),
        ("approval_reuse_sandbox_changed", "review"),
        ("approval_reuse_expired", "review"),
        ("approval_reuse_integrity_failure", "require-reapproval"),
    ),
)
def test_invalidated_saved_allow_is_rejected_with_stable_reason(
    validation_reason: ApprovalReuseValidationFailure,
    expected_action: str,
) -> None:
    result = evaluate_approval_reuse(
        "review",
        "allow",
        validation_reason=validation_reason,
    )

    assert result.action == expected_action
    assert result.status == "rejected"
    assert result.reason_code == validation_reason
    assert result.should_claim is False


def test_unknown_current_action_fails_closed_with_diagnostics() -> None:
    result = evaluate_approval_reuse("future-permissive-action", "allow")

    assert result.action == "block"
    assert result.reason_code == APPROVAL_REUSE_CURRENT_ACTION_UNKNOWN
    assert result.current_normalization_reason_code == "guard_action_unknown"
    assert result.original_current_action == "future-permissive-action"
    assert result.should_claim is False


def test_present_malformed_saved_action_requires_reapproval_with_diagnostics() -> None:
    result = evaluate_approval_reuse("review", None, saved_decision_present=True)

    assert result.action == "require-reapproval"
    assert result.reason_code == APPROVAL_REUSE_SAVED_ACTION_UNKNOWN
    assert result.saved_normalization_reason_code == "guard_action_unknown"
    assert result.original_saved_type == "NoneType"
    assert result.to_evidence()["saved_action"] == "require-reapproval"


def test_claim_failure_reason_takes_precedence_and_preserves_normalization_diagnostics() -> None:
    result = evaluate_approval_reuse(
        "review",
        None,
        saved_decision_present=True,
        validation_reason=APPROVAL_REUSE_CLAIM_FAILED,
    )

    assert result.action == "require-reapproval"
    assert result.reason_code == APPROVAL_REUSE_CLAIM_FAILED
    assert result.saved_normalization_reason_code == "guard_action_unknown"


def test_non_consuming_lookup_requires_explicit_atomic_claim(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    approval_id = store.record_local_once_approval(
        request_id="req-once",
        harness="codex",
        artifact_id="codex:project:tool-action:exact",
        artifact_hash="sha256:exact",
        workspace=str(tmp_path),
        publisher="publisher-a",
        action="allow",
        created_at="2026-07-17T12:00:00+00:00",
        expires_at="2026-07-17T13:00:00+00:00",
    )
    assert approval_id is not None

    first = store.resolve_policy_decision(
        "codex",
        "codex:project:tool-action:exact",
        "sha256:exact",
        str(tmp_path),
        "publisher-a",
        "2026-07-17T12:05:00+00:00",
        consume_one_shot=False,
    )
    second = store.resolve_policy_decision(
        "codex",
        "codex:project:tool-action:exact",
        "sha256:exact",
        str(tmp_path),
        "publisher-a",
        "2026-07-17T12:06:00+00:00",
        consume_one_shot=False,
    )

    assert first is not None and first["approval_id"] == approval_id
    assert second is not None and second["approval_id"] == approval_id
    assert store.list_events(event_name="approval.local_once_applied") == []
    assert store.claim_approval_reuse_decision(first, now="2026-07-17T12:07:00+00:00") is True
    assert store.claim_approval_reuse_decision(first, now="2026-07-17T12:08:00+00:00") is False
    assert (
        store.resolve_policy_decision(
            "codex",
            "codex:project:tool-action:exact",
            "sha256:exact",
            str(tmp_path),
            "publisher-a",
            "2026-07-17T12:09:00+00:00",
            consume_one_shot=False,
        )
        is None
    )
    events = store.list_events(event_name="approval.local_once_applied")
    assert len(events) == 1
    payload = cast(Mapping[str, object], events[0]["payload"])
    assert payload["approval_id"] == approval_id


def test_batch_claim_consumes_two_exact_one_shot_approvals_atomically(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    selected: list[Mapping[str, object]] = []
    approval_ids: list[str] = []
    for suffix in ("outer", "package"):
        artifact_id = f"codex:project:tool-action:{suffix}"
        artifact_hash = _approval_context_token(content=f"sha256:{suffix}")
        approval_id = store.record_local_once_approval(
            request_id=f"request-{suffix}",
            harness="codex",
            artifact_id=artifact_id,
            artifact_hash=artifact_hash,
            workspace=str(tmp_path),
            publisher=None,
            action="allow",
            created_at="2026-07-17T12:00:00+00:00",
            expires_at="2026-07-17T13:00:00+00:00",
        )
        assert approval_id is not None
        approval_ids.append(approval_id)
    for suffix in ("outer", "package"):
        decision = store.resolve_policy_decision(
            "codex",
            f"codex:project:tool-action:{suffix}",
            _approval_context_token(content=f"sha256:{suffix}"),
            str(tmp_path),
            None,
            "2026-07-17T12:05:00+00:00",
            consume_one_shot=False,
        )
        assert decision is not None
        selected.append(decision)

    assert store.claim_approval_reuse_decisions(selected, now="2026-07-17T12:06:00+00:00")

    with sqlite3.connect(store.path) as connection:
        rows = connection.execute(
            "select approval_id, claimed_at from guard_local_once_approvals order by approval_id"
        ).fetchall()
    assert {row[0] for row in rows} == set(approval_ids)
    assert all(row[1] is not None for row in rows)


def test_batch_claim_rolls_back_every_sibling_when_one_row_fails_integrity(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    selected: list[Mapping[str, object]] = []
    approval_ids: list[str] = []
    for suffix in ("outer", "package"):
        artifact_id = f"codex:project:tool-action:rollback-{suffix}"
        artifact_hash = _approval_context_token(content=f"sha256:rollback-{suffix}")
        approval_id = store.record_local_once_approval(
            request_id=f"request-rollback-{suffix}",
            harness="codex",
            artifact_id=artifact_id,
            artifact_hash=artifact_hash,
            workspace=str(tmp_path),
            publisher=None,
            action="allow",
            created_at="2026-07-17T12:00:00+00:00",
            expires_at="2026-07-17T13:00:00+00:00",
        )
        assert approval_id is not None
        approval_ids.append(approval_id)
    for suffix in ("outer", "package"):
        decision = store.resolve_policy_decision(
            "codex",
            f"codex:project:tool-action:rollback-{suffix}",
            _approval_context_token(content=f"sha256:rollback-{suffix}"),
            str(tmp_path),
            None,
            "2026-07-17T12:05:00+00:00",
            consume_one_shot=False,
        )
        assert decision is not None
        selected.append(decision)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "update guard_local_once_approvals set payload_mac = ? where approval_id = ?",
            ("0" * 64, approval_ids[1]),
        )

    assert not store.claim_approval_reuse_decisions(selected, now="2026-07-17T12:06:00+00:00")

    with sqlite3.connect(store.path) as connection:
        rows = connection.execute(
            "select claimed_at from guard_local_once_approvals where approval_id in (?, ?)",
            tuple(approval_ids),
        ).fetchall()
    assert len(rows) == 2
    assert all(row[0] is None for row in rows)


def test_default_lookup_still_consumes_non_package_local_once_approval(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.record_local_once_approval(
        request_id="req-compat",
        harness="codex",
        artifact_id="codex:project:tool-action:compat",
        artifact_hash="sha256:compat",
        workspace=None,
        publisher=None,
        action="allow",
        created_at="2026-07-17T12:00:00+00:00",
        expires_at="2026-07-17T13:00:00+00:00",
    )

    first = store.resolve_policy_decision(
        "codex",
        "codex:project:tool-action:compat",
        "sha256:compat",
        now="2026-07-17T12:05:00+00:00",
    )
    second = store.resolve_policy_decision(
        "codex",
        "codex:project:tool-action:compat",
        "sha256:compat",
        now="2026-07-17T12:06:00+00:00",
    )

    assert first is not None and first["action"] == "allow"
    assert second is None


@pytest.mark.parametrize("scope", ("artifact", "workspace", "publisher", "harness", "global"))
def test_approval_resolution_preserves_exact_context_token_across_every_scope(tmp_path, scope: str) -> None:
    store = GuardStore(tmp_path / "guard-home")
    workspace = "/workspace/a"
    artifact_id = "codex:project:mcp-tool:read"
    current_token = _approval_context_token()
    store.add_approval_request(
        GuardApprovalRequest(
            request_id=f"request-context-{scope}",
            harness="codex",
            artifact_id=artifact_id,
            artifact_name="read",
            artifact_type="tool_call",
            artifact_hash=current_token,
            publisher="trusted-publisher",
            policy_action="review",
            recommended_scope="artifact",
            changed_fields=("tool_call",),
            source_scope="project",
            config_path="/workspace/a/.codex/config.toml",
            workspace=workspace,
            review_command="hol-guard approvals approve request-context",
            approval_url="http://127.0.0.1:4455/approvals/request-context",
        ),
        "2026-07-17T12:00:00+00:00",
    )
    apply_approval_resolution(
        store=store,
        request_id=f"request-context-{scope}",
        action="allow",
        scope=scope,
        workspace=workspace if scope == "workspace" else None,
        reason="approved exact context",
        now="2026-07-17T12:01:00+00:00",
        persist_policy=True,
    )

    stored = store.list_policy_decisions()
    assert len(stored) == 1
    assert stored[0]["artifact_hash"] == current_token
    assert (
        store.resolve_policy(
            "codex",
            artifact_id,
            current_token,
            workspace=workspace,
            publisher="trusted-publisher",
            now="2026-07-17T12:02:00+00:00",
            consume_one_shot=False,
        )
        == "allow"
    )
    changed_token = _approval_context_token(content="sha256:changed")
    assert (
        store.resolve_policy(
            "codex",
            artifact_id,
            changed_token,
            workspace=workspace,
            publisher="trusted-publisher",
            now="2026-07-17T12:03:00+00:00",
            consume_one_shot=False,
        )
        is None
    )
    assert (
        store.approval_reuse_validation_reason(
            "codex",
            artifact_id,
            changed_token,
            workspace,
            "trusted-publisher",
            "2026-07-17T12:03:00+00:00",
        )
        == "approval_reuse_content_changed"
    )


def test_broad_scope_exact_context_allow_does_not_resolve_or_authorize_other_context(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    first_token = _approval_context_token(content="sha256:first")
    second_token = _approval_context_token(
        identity={"artifact_id": "codex:project:mcp-tool:write", "workspace": "/workspace/a"},
        content="sha256:second",
        capabilities=["filesystem:write"],
    )
    for request_id, artifact_id, token in (
        ("request-first", "codex:project:mcp-tool:read", first_token),
        ("request-second", "codex:project:mcp-tool:write", second_token),
    ):
        store.add_approval_request(
            GuardApprovalRequest(
                request_id=request_id,
                harness="codex",
                artifact_id=artifact_id,
                artifact_name=artifact_id.rsplit(":", maxsplit=1)[-1],
                artifact_type="tool_call",
                artifact_hash=token,
                policy_action="review",
                recommended_scope="harness",
                changed_fields=("tool_call",),
                source_scope="project",
                config_path="/workspace/a/.codex/config.toml",
                workspace="/workspace/a",
                review_command=f"hol-guard approvals approve {request_id}",
                approval_url=f"http://127.0.0.1:4455/approvals/{request_id}",
            ),
            "2026-07-17T12:00:00+00:00",
        )

    apply_approval_resolution(
        store=store,
        request_id="request-first",
        action="allow",
        scope="harness",
        workspace=None,
        reason="approve only the reviewed context",
        now="2026-07-17T12:01:00+00:00",
    )

    assert store.get_approval_request("request-first")["status"] == "resolved"
    assert store.get_approval_request("request-second")["status"] == "pending"
    assert (
        store.resolve_policy(
            "codex",
            "codex:project:mcp-tool:read",
            first_token,
            now="2026-07-17T12:02:00+00:00",
            consume_one_shot=False,
        )
        == "allow"
    )
    assert (
        store.resolve_policy(
            "codex",
            "codex:project:mcp-tool:write",
            second_token,
            now="2026-07-17T12:02:00+00:00",
            consume_one_shot=False,
        )
        is None
    )


@pytest.mark.parametrize("consume_one_shot", (False, True))
def test_lookup_preserves_stored_block_over_local_once_allow(tmp_path, consume_one_shot: bool) -> None:
    store = GuardStore(tmp_path / "guard-home")
    artifact_id = "codex:project:tool-action:blocked-after-approval"
    artifact_hash = "sha256:blocked-after-approval"
    approval_id = store.record_local_once_approval(
        request_id="req-stale-allow",
        harness="codex",
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
        workspace="/workspace/a",
        publisher=None,
        action="allow",
        created_at="2026-07-17T12:00:00+00:00",
        expires_at="2026-07-17T13:00:00+00:00",
    )
    store.replace_remote_policies(
        [
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="block",
                artifact_id=artifact_id,
                artifact_hash=artifact_hash,
                source="team-policy",
            )
        ],
        "2026-07-17T12:01:00+00:00",
        remote_write_authorized=True,
    )

    selected = store.resolve_policy_decision(
        "codex",
        artifact_id,
        artifact_hash,
        workspace="/workspace/a",
        now="2026-07-17T12:02:00+00:00",
        consume_one_shot=consume_one_shot,
    )

    assert selected is not None
    assert selected["action"] == "block"
    assert selected["source"] == "team-policy"
    assert store.claim_local_once_approval(approval_id, claimed_at="2026-07-17T12:03:00+00:00") is True


def test_non_consuming_runtime_lookup_composes_specific_allow_with_broader_managed_block(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    artifact_id = "codex:project:mcp-tool:managed-block"
    approval_hash = _approval_context_token(content="sha256:managed-block")
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=artifact_id,
            artifact_hash=approval_hash,
            source="approval-gate",
        ),
        "2026-07-17T12:00:00+00:00",
    )
    store.replace_remote_policies(
        [
            PolicyDecision(
                harness="codex",
                scope="global",
                action="block",
                source="team-policy",
            )
        ],
        "2026-07-17T12:01:00+00:00",
        remote_write_authorized=True,
    )

    runtime_decision = store.resolve_policy_decision(
        "codex",
        artifact_id,
        approval_hash,
        now="2026-07-17T12:02:00+00:00",
        consume_one_shot=False,
    )
    legacy_scope_precedence = store.resolve_policy_decision(
        "codex",
        artifact_id,
        approval_hash,
        now="2026-07-17T12:02:00+00:00",
    )

    assert runtime_decision is not None
    assert runtime_decision["action"] == "block"
    assert runtime_decision["source"] == "team-policy"
    assert legacy_scope_precedence is not None
    assert legacy_scope_precedence["action"] == "allow"
    assert store.list_events(event_name="policy_integrity_violation") == []
    assert store.list_events(event_name="rule.ignored.local_integrity") == []


@pytest.mark.parametrize("scope", ("workspace", "harness", "global"))
@pytest.mark.parametrize("source", ("local", "team-policy"))
def test_non_consuming_scope_lookup_preserves_specificity_and_stronger_actions(
    tmp_path,
    scope: DecisionScope,
    source: str,
) -> None:
    artifact_id = "codex:project:prompt-env-read:specificity"
    workspace = "/workspace/specificity"
    context_hash = _approval_context_token(
        identity={"artifact_id": artifact_id, "workspace": workspace},
        content="sha256:specificity",
    )
    policy_harness = "*" if scope == "global" else "codex"

    def policy(*, action: GuardAction, reason: str, artifact_hash: str | None, broad: bool = False) -> PolicyDecision:
        return PolicyDecision(
            harness=policy_harness,
            scope=scope,
            action=action,
            artifact_id=None if broad else artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace if scope == "workspace" else None,
            reason=reason,
            source=source,
        )

    def store_with_policies(name: str, decisions: list[PolicyDecision]) -> GuardStore:
        store = GuardStore(tmp_path / name)
        if source == "team-policy":
            store.replace_remote_policies(
                decisions,
                "2026-07-18T12:03:00Z",
                remote_write_authorized=True,
            )
        else:
            for minute, decision in enumerate(decisions):
                store.upsert_policy(decision, f"2026-07-18T12:0{minute}:00Z")
        return store

    exact_store = store_with_policies(
        f"guard-home-{scope}-{source}-exact",
        [
            policy(action="allow", reason="exact context allow", artifact_hash=context_hash),
            policy(action="allow", reason="family-bound allow", artifact_hash=None),
            policy(action="allow", reason="broad allow", artifact_hash=None, broad=True),
        ],
    )
    exact = exact_store.resolve_policy_decision(
        "codex",
        artifact_id,
        context_hash,
        workspace=workspace,
        now="2026-07-18T12:04:00Z",
        consume_one_shot=False,
    )

    assert exact is not None
    assert exact["reason"] == "exact context allow"
    if source == "local":
        assert exact["integrity_status"] == "valid"

    family_store = store_with_policies(
        f"guard-home-{scope}-{source}-family",
        [
            policy(action="allow", reason="family-bound allow", artifact_hash=None),
            policy(action="allow", reason="broad allow", artifact_hash=None, broad=True),
        ],
    )
    family = family_store.resolve_policy_decision(
        "codex",
        artifact_id,
        context_hash,
        workspace=workspace,
        now="2026-07-18T12:04:00Z",
        consume_one_shot=False,
    )

    assert family is not None
    assert family["reason"] == "family-bound allow"
    if source == "local":
        assert family["integrity_status"] == "valid"

    stronger_store = store_with_policies(
        f"guard-home-{scope}-{source}-stronger",
        [
            policy(action="allow", reason="exact context allow", artifact_hash=context_hash),
            policy(action="allow", reason="family-bound allow", artifact_hash=None),
            policy(action="block", reason="stronger broad block", artifact_hash=None, broad=True),
        ],
    )
    stronger = stronger_store.resolve_policy_decision(
        "codex",
        artifact_id,
        context_hash,
        workspace=workspace,
        now="2026-07-18T12:04:00Z",
        consume_one_shot=False,
    )

    assert stronger is not None
    assert stronger["action"] == "block"
    assert stronger["reason"] == "stronger broad block"
    if source == "local":
        assert stronger["integrity_status"] == "valid"


def test_non_consuming_runtime_lookup_composes_direct_allow_with_exact_command_block(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    artifact_id = "codex:project:tool-action:shell"
    command = "deploy production"
    exact_command_id = build_exact_command_memory_artifact_id(command)
    assert exact_command_id is not None
    approval_hash = _approval_context_token(content="sha256:deploy")
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=artifact_id,
            artifact_hash=approval_hash,
            source="approval-gate",
        ),
        "2026-07-17T12:00:00+00:00",
    )
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="block",
            artifact_id=exact_command_id,
            artifact_hash=approval_hash,
            source="manual",
        ),
        "2026-07-17T12:01:00+00:00",
    )

    lookup = store.resolve_policy_decision_lookup_with_memory_pattern(
        "codex",
        artifact_id,
        artifact_hash=approval_hash,
        memory_command=command,
        memory_artifact_type="tool_action_request",
        memory_artifact_name="shell",
        now="2026-07-17T12:02:00+00:00",
        consume_one_shot=False,
    )

    assert lookup["decision"] is not None
    assert lookup["decision"]["action"] == "block"
    assert lookup["decision"]["artifact_id"] == exact_command_id


def test_atomic_claim_rejects_changed_expected_local_once_identity_without_consuming(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.record_local_once_approval(
        request_id="req-identity",
        harness="codex",
        artifact_id="codex:project:tool-action:identity",
        artifact_hash="sha256:identity",
        workspace=None,
        publisher=None,
        action="allow",
        created_at="2026-07-17T12:00:00+00:00",
        expires_at="2026-07-17T13:00:00+00:00",
    )
    selected = store.resolve_policy_decision(
        "codex",
        "codex:project:tool-action:identity",
        "sha256:identity",
        now="2026-07-17T12:01:00+00:00",
        consume_one_shot=False,
    )
    assert selected is not None
    changed = {**selected, "artifact_hash": "sha256:changed"}

    assert store.claim_approval_reuse_decision(changed, now="2026-07-17T12:02:00+00:00") is False
    assert store.claim_approval_reuse_decision(selected, now="2026-07-17T12:03:00+00:00") is True


def test_claim_rejects_policy_row_replaced_after_non_consuming_lookup(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    allow = PolicyDecision(
        harness="codex",
        scope="artifact",
        action="allow",
        artifact_id="codex:project:tool-action:remote",
        artifact_hash="sha256:remote",
        source="team-policy",
    )
    store.replace_remote_policies(
        [allow],
        "2026-07-17T12:00:00+00:00",
        remote_write_authorized=True,
    )
    selected = store.resolve_policy_decision(
        "codex",
        allow.artifact_id,
        allow.artifact_hash,
        now="2026-07-17T12:01:00+00:00",
        consume_one_shot=False,
    )
    assert selected is not None

    store.replace_remote_policies(
        [
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="block",
                artifact_id=allow.artifact_id,
                artifact_hash=allow.artifact_hash,
                source="team-policy",
            )
        ],
        "2026-07-17T12:02:00+00:00",
        remote_write_authorized=True,
    )

    assert store.claim_approval_reuse_decision(selected, now="2026-07-17T12:03:00+00:00") is False


def test_claim_rejects_policy_integrity_tamper_after_non_consuming_lookup(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    allow = PolicyDecision(
        harness="codex",
        scope="artifact",
        action="allow",
        artifact_id="codex:project:tool-action:tamper-race",
        artifact_hash="sha256:tamper-race",
        source="approval-gate",
    )
    store.upsert_policy(allow, "2026-07-17T12:00:00+00:00")
    selected = store.resolve_policy_decision(
        "codex",
        allow.artifact_id,
        allow.artifact_hash,
        now="2026-07-17T12:01:00+00:00",
        consume_one_shot=False,
    )
    assert selected is not None

    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "update policy_decisions set payload_mac = ? where decision_id = ?",
            ("00", selected["decision_id"]),
        )

    assert store.claim_approval_reuse_decision(selected, now="2026-07-17T12:02:00+00:00") is False


def test_claim_accepts_unchanged_persistent_policy_without_consuming_it(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    allow = PolicyDecision(
        harness="codex",
        scope="artifact",
        action="allow",
        artifact_id="codex:project:tool-action:persistent",
        artifact_hash="sha256:persistent",
        source="team-policy",
    )
    store.replace_remote_policies(
        [allow],
        "2026-07-17T12:00:00+00:00",
        remote_write_authorized=True,
    )
    selected = store.resolve_policy_decision(
        "codex",
        allow.artifact_id,
        allow.artifact_hash,
        now="2026-07-17T12:01:00+00:00",
        consume_one_shot=False,
    )
    assert selected is not None

    assert store.claim_approval_reuse_decision(selected, now="2026-07-17T12:02:00+00:00") is True
    assert (
        store.resolve_policy(
            "codex",
            allow.artifact_id,
            allow.artifact_hash,
            now="2026-07-17T12:03:00+00:00",
            consume_one_shot=False,
        )
        == "allow"
    )
    assert len(store.list_events(event_name="approval.policy_reuse_applied")) == 1


def test_claim_rejects_allow_when_broader_block_is_inserted_after_lookup(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    artifact_id = "codex:project:tool-action:authority-race"
    approval_hash = _approval_context_token(content="sha256:authority-race")
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=artifact_id,
            artifact_hash=approval_hash,
            source="approval-gate",
        ),
        "2026-07-17T12:00:00+00:00",
    )
    selected = store.resolve_policy_decision(
        "codex",
        artifact_id,
        approval_hash,
        now="2026-07-17T12:01:00+00:00",
        consume_one_shot=False,
    )
    assert selected is not None

    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="global",
            action="block",
            artifact_id=None,
            artifact_hash=None,
            source="manual",
        ),
        "2026-07-17T12:02:00+00:00",
    )

    assert store.claim_approval_reuse_decision(selected, now="2026-07-17T12:03:00+00:00") is False


def test_claim_rejects_direct_allow_when_memory_block_is_inserted_after_lookup(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    artifact_id = "codex:project:tool-action:memory-race"
    command = "deploy production"
    approval_hash = _approval_context_token(content="sha256:memory-race")
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=artifact_id,
            artifact_hash=approval_hash,
            source="approval-gate",
        ),
        "2026-07-17T12:00:00+00:00",
    )
    lookup = store.resolve_policy_decision_lookup_with_memory_pattern(
        "codex",
        artifact_id,
        artifact_hash=approval_hash,
        memory_command=command,
        memory_artifact_type="tool_action_request",
        memory_artifact_name="shell",
        now="2026-07-17T12:01:00+00:00",
        consume_one_shot=False,
    )
    selected = lookup["decision"]
    assert selected is not None
    memory_artifact_id = build_exact_command_memory_artifact_id(command)
    assert memory_artifact_id is not None

    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="block",
            artifact_id=memory_artifact_id,
            artifact_hash=approval_hash,
            source="manual",
        ),
        "2026-07-17T12:02:00+00:00",
    )

    assert store.claim_approval_reuse_decision(selected, now="2026-07-17T12:03:00+00:00") is False


def test_claim_rejects_local_once_when_policy_changes_and_keeps_it_unclaimed(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    artifact_id = "codex:project:tool-action:local-once-race"
    approval_hash = _approval_context_token(content="sha256:local-once-race")
    approval_id = store.record_local_once_approval(
        request_id="request-local-once-race",
        harness="codex",
        artifact_id=artifact_id,
        artifact_hash=approval_hash,
        workspace=None,
        publisher=None,
        action="allow",
        created_at="2026-07-17T12:00:00+00:00",
        expires_at="2026-07-17T13:00:00+00:00",
    )
    selected = store.resolve_policy_decision(
        "codex",
        artifact_id,
        approval_hash,
        now="2026-07-17T12:01:00+00:00",
        consume_one_shot=False,
    )
    assert selected is not None

    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="harness",
            action="block",
            artifact_id=None,
            artifact_hash=None,
            source="manual",
        ),
        "2026-07-17T12:02:00+00:00",
    )

    assert store.claim_approval_reuse_decision(selected, now="2026-07-17T12:03:00+00:00") is False
    with sqlite3.connect(store.path) as connection:
        claimed_at = connection.execute(
            "select claimed_at from guard_local_once_approvals where approval_id = ?",
            (approval_id,),
        ).fetchone()[0]
    assert claimed_at is None


@pytest.mark.parametrize(
    ("artifact_hash", "workspace", "now", "expected_reason"),
    (
        ("sha256:changed", "/workspace/a", "2026-07-17T12:05:00+00:00", "approval_reuse_content_changed"),
        ("sha256:exact", "/workspace/b", "2026-07-17T12:05:00+00:00", "approval_reuse_identity_changed"),
        ("sha256:exact", "/workspace/a", "2026-07-17T13:05:00+00:00", "approval_reuse_expired"),
    ),
)
def test_lookup_miss_reports_stable_saved_approval_invalidation_reason(
    tmp_path,
    artifact_hash: str,
    workspace: str,
    now: str,
    expected_reason: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.record_local_once_approval(
        request_id="req-diagnostic",
        harness="codex",
        artifact_id="codex:project:tool-action:diagnostic",
        artifact_hash="sha256:exact",
        workspace="/workspace/a",
        publisher="publisher-a",
        action="allow",
        created_at="2026-07-17T12:00:00+00:00",
        expires_at="2026-07-17T13:00:00+00:00",
    )

    reason = store.approval_reuse_validation_reason(
        "codex",
        "codex:project:tool-action:diagnostic",
        artifact_hash,
        workspace,
        "publisher-a",
        now,
    )

    assert reason == expected_reason


def test_lookup_miss_diagnostic_remains_targeted_with_many_unrelated_allows(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    with sqlite3.connect(store.path) as connection:
        connection.executemany(
            """
            insert into guard_local_once_approvals (
              approval_id, request_id, harness, artifact_id, artifact_hash, workspace, publisher,
              action, created_at, expires_at, claimed_at
            ) values (?, ?, 'codex', ?, ?, null, null, 'allow', ?, ?, null)
            """,
            (
                (
                    f"unrelated-{index:04d}",
                    f"request-{index:04d}",
                    f"codex:project:tool-action:unrelated-{index:04d}",
                    f"sha256:unrelated-{index:04d}",
                    f"2026-07-17T12:{index % 60:02d}:00+00:00",
                    "2026-07-17T14:00:00+00:00",
                )
                for index in range(2_000)
            ),
        )
        connection.executemany(
            """
            insert into policy_decisions (
              harness, scope, artifact_id, artifact_hash, workspace, publisher, action, source, updated_at
            ) values ('codex', ?, ?, ?, ?, ?, 'allow', 'team-policy', ?)
            """,
            (
                (
                    scope,
                    artifact_id,
                    f"guard-approval-context:v1:irrelevant-{index:04d}",
                    workspace,
                    publisher,
                    f"2026-07-17T12:{index % 60:02d}:00+00:00",
                )
                for index in range(1_000)
                for scope, artifact_id, workspace, publisher in (
                    ("artifact", f"codex:project:tool-action:unrelated-policy-{index:04d}", None, None),
                    (
                        "artifact",
                        f"codex:project:tool-action:same-publisher-other-scope-{index:04d}",
                        None,
                        "publisher-current",
                    ),
                    ("workspace", None, f"workspace:sha256:unrelated-{index:04d}", None),
                    ("publisher", None, None, f"publisher-{index:04d}"),
                    ("harness", "family:file-read", None, None),
                    ("global", "family:file-read", None, None),
                )
            ),
        )
    store.record_local_once_approval(
        request_id="request-near-match",
        harness="codex",
        artifact_id="codex:project:tool-action:diagnostic-scale",
        artifact_hash="sha256:old-content",
        workspace="/workspace/a",
        publisher=None,
        action="allow",
        created_at="2026-07-17T11:00:00+00:00",
        expires_at="2026-07-17T14:00:00+00:00",
    )

    reason = store.approval_reuse_validation_reason(
        "codex",
        "codex:project:tool-action:diagnostic-scale",
        "sha256:new-content",
        "/workspace/a",
        None,
        "2026-07-17T12:30:00+00:00",
    )

    assert reason == "approval_reuse_content_changed"


def test_non_consuming_policy_lookup_is_bounded_and_fails_closed_on_match_overflow(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.replace_remote_policies(
        [
            PolicyDecision(
                harness="codex",
                scope="harness",
                action="allow",
                artifact_id=None,
                artifact_hash=None,
                reason=f"broad allow {index}",
                source="team-policy",
            )
            for index in range(300)
        ],
        "2026-07-17T12:00:00+00:00",
        remote_write_authorized=True,
    )

    lookup = store.resolve_policy_decision_lookup(
        "codex",
        "codex:project:tool-action:bounded",
        artifact_hash=_approval_context_token(content="sha256:bounded"),
        now="2026-07-17T12:01:00+00:00",
        consume_one_shot=False,
    )

    assert lookup["decision"] is not None
    assert lookup["decision"]["action"] == "block"
    assert lookup["decision"]["source"] == "guard-policy-match-cap"
    assert lookup["decision"]["_approval_authority_revision"] == lookup["authority_revision"]
    overflow_events = store.list_events(event_name="approval.policy_lookup_overflow")
    assert len(overflow_events) == 1
    with sqlite3.connect(store.path) as connection:
        connection.row_factory = sqlite3.Row
        query_plan = _bounded_non_consuming_policy_rows(
            connection,
            harness="codex",
            artifact_id="codex:project:tool-action:bounded",
            artifact_hash=_approval_context_token(content="sha256:bounded"),
            runtime_exact_match_key=None,
            workspace_key=None,
            workspace=None,
            publisher=None,
            action_family_key=None,
            current_time="2026-07-17T12:01:00+00:00",
            _explain=True,
        )
    query_plan_details = [str(row[3]) for row in query_plan]
    assert not any(detail == "SCAN policy_decisions" for detail in query_plan_details)
    assert not any("USE TEMP B-TREE" in detail for detail in query_plan_details)
    assert {
        "idx_policy_decisions_lookup_artifact",
        "idx_policy_decisions_lookup_harness",
        "idx_policy_decisions_lookup_global",
    }.issubset({index for detail in query_plan_details for index in detail.split()})


def test_non_consuming_policy_lookup_miss_uses_only_fully_constrained_scope_probes(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    current_hash = _approval_context_token(content="sha256:current")
    with sqlite3.connect(store.path) as connection:
        connection.executemany(
            """
            insert into policy_decisions (
              harness, scope, artifact_id, artifact_hash, workspace, publisher, action, source, updated_at
            ) values ('codex', ?, ?, ?, ?, ?, 'allow', 'team-policy', '2026-07-17T12:00:00+00:00')
            """,
            (
                (
                    scope,
                    artifact_id,
                    f"guard-approval-context:v1:irrelevant-{index:04d}",
                    workspace,
                    publisher,
                )
                for index in range(1_000)
                for scope, artifact_id, workspace, publisher in (
                    ("artifact", f"codex:project:tool-action:unrelated-{index:04d}", None, None),
                    ("workspace", None, f"workspace:sha256:unrelated-{index:04d}", None),
                    ("publisher", None, None, f"publisher-{index:04d}"),
                    ("harness", "family:file-read", None, None),
                    ("global", "family:file-read", None, None),
                )
            ),
        )

    lookup = store.resolve_policy_decision_lookup(
        "codex",
        "codex:project:tool-action:bounded-miss",
        artifact_hash=current_hash,
        workspace="/workspace/current",
        publisher="publisher-current",
        now="2026-07-17T12:01:00+00:00",
        consume_one_shot=False,
    )

    assert lookup["decision"] is None
    with sqlite3.connect(store.path) as connection:
        connection.row_factory = sqlite3.Row
        query_plan = _bounded_non_consuming_policy_rows(
            connection,
            harness="codex",
            artifact_id="codex:project:tool-action:bounded-miss",
            artifact_hash=current_hash,
            runtime_exact_match_key="runtime-exact:current",
            workspace_key="workspace:sha256:current",
            workspace="/workspace/current",
            publisher="publisher-current",
            action_family_key="family:tool-action",
            current_time="2026-07-17T12:01:00+00:00",
            _explain=True,
        )
    plan_details = [str(row[3]) for row in query_plan]
    assert plan_details
    assert all(detail.startswith("SEARCH policy_decisions USING INDEX") for detail in plan_details)
    assert not any("USE TEMP B-TREE" in detail for detail in plan_details)
    assert not any(
        "lookup_harness" in detail and "harness=? AND artifact_id=?" not in detail for detail in plan_details
    )
    assert not any("lookup_global" in detail and "harness=? AND artifact_id=?" not in detail for detail in plan_details)
    assert not any(
        "lookup_publisher" in detail and "publisher=? AND harness=?" not in detail for detail in plan_details
    )
    assert {
        "idx_policy_decisions_lookup_artifact",
        "idx_policy_decisions_lookup_workspace",
        "idx_policy_decisions_lookup_publisher",
        "idx_policy_decisions_lookup_publisher_legacy",
        "idx_policy_decisions_lookup_harness",
        "idx_policy_decisions_lookup_harness_legacy",
        "idx_policy_decisions_lookup_global",
        "idx_policy_decisions_lookup_global_legacy",
    }.issubset({index for detail in plan_details for index in detail.split()})


def test_non_consuming_policy_probe_partitions_preserve_every_scope_selector(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    artifact_id = "codex:project:tool-action:selector-matrix"
    context_hash = _approval_context_token(content="sha256:selector-matrix")
    runtime_hash = "runtime-exact:selector-matrix"
    matching_rows = (
        ("artifact-null", "codex", "artifact", artifact_id, None, None, None),
        ("artifact-context", "codex", "artifact", artifact_id, context_hash, None, None),
        ("artifact-runtime", "*", "artifact", artifact_id, runtime_hash, None, None),
        (
            "workspace-broad",
            "codex",
            "workspace",
            None,
            "guard-approval-context:v1:other",
            "workspace:sha256:current",
            None,
        ),
        ("workspace-null", "codex", "workspace", artifact_id, None, "/workspace/current", None),
        (
            "workspace-context",
            "*",
            "workspace",
            artifact_id,
            context_hash,
            "workspace:sha256:current",
            None,
        ),
        ("publisher-null", "codex", "publisher", None, None, None, "publisher-current"),
        ("publisher-context", "codex", "publisher", None, context_hash, None, "publisher-current"),
        ("publisher-legacy", "*", "publisher", None, "sha256:legacy", None, "publisher-current"),
        ("harness-broad", "codex", "harness", None, None, None, None),
        ("harness-context", "codex", "harness", "family:tool-action", context_hash, None, None),
        ("harness-runtime", "*", "harness", "family:tool-action", runtime_hash, None, None),
        ("harness-legacy", "codex", "harness", "family:tool-action", "sha256:legacy", None, None),
        ("global-broad", "codex", "global", None, None, None, None),
        ("global-artifact", "codex", "global", artifact_id, context_hash, None, None),
        ("global-family", "*", "global", "family:tool-action", runtime_hash, None, None),
        ("global-legacy", "codex", "global", "family:tool-action", "sha256:legacy", None, None),
    )
    ignored_rows = (
        ("artifact-other-context", "codex", "artifact", artifact_id, "guard-approval-context:v1:other", None, None),
        (
            "workspace-runtime",
            "codex",
            "workspace",
            artifact_id,
            runtime_hash,
            "workspace:sha256:current",
            None,
        ),
        (
            "publisher-other-context",
            "codex",
            "publisher",
            None,
            "guard-approval-context:v1:other",
            None,
            "publisher-current",
        ),
        (
            "harness-other-family",
            "codex",
            "harness",
            "family:file-read",
            "sha256:legacy",
            None,
            None,
        ),
        (
            "global-other-context",
            "codex",
            "global",
            "family:tool-action",
            "guard-approval-context:v1:other",
            None,
            None,
        ),
        ("other-harness", "cursor", "global", None, None, None, None),
    )
    with sqlite3.connect(store.path) as connection:
        connection.executemany(
            """
            insert into policy_decisions (
              reason, harness, scope, artifact_id, artifact_hash, workspace, publisher,
              action, source, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, 'allow', 'team-policy', '2026-07-17T12:00:00+00:00')
            """,
            (*matching_rows, *ignored_rows),
        )
        connection.row_factory = sqlite3.Row
        rows = _bounded_non_consuming_policy_rows(
            connection,
            harness="codex",
            artifact_id=artifact_id,
            artifact_hash=context_hash,
            runtime_exact_match_key=runtime_hash,
            workspace_key="workspace:sha256:current",
            workspace="/workspace/current",
            publisher="publisher-current",
            action_family_key="family:tool-action",
            current_time="2026-07-17T12:01:00+00:00",
        )

    assert {str(row["reason"]) for row in rows} == {row[0] for row in matching_rows}


def test_approval_reuse_diagnostic_live_probes_are_index_ordered_without_temp_sort(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    with sqlite3.connect(store.path) as connection:
        connection.row_factory = sqlite3.Row
        local_plan = _bounded_local_approval_reuse_diagnostic_rows(
            connection,
            harness="codex",
            artifact_id="codex:project:tool-action:diagnostic-plan",
            artifact_family="family:tool-action",
            artifact_hash="sha256:current",
            _explain=True,
        )
        policy_plan = _bounded_policy_approval_reuse_diagnostic_rows(
            connection,
            harness="codex",
            artifact_id="codex:project:tool-action:diagnostic-plan",
            artifact_family="family:tool-action",
            artifact_hash="sha256:current",
            publisher="publisher-current",
            _explain=True,
        )

    local_details = [str(row[3]) for row in local_plan]
    policy_details = [str(row[3]) for row in policy_plan]
    assert local_details and policy_details
    assert all(detail.startswith("SEARCH guard_local_once_approvals USING INDEX") for detail in local_details)
    assert all(detail.startswith("SEARCH policy_decisions USING INDEX") for detail in policy_details)
    assert not any("USE TEMP B-TREE" in detail for detail in (*local_details, *policy_details))
    assert not any(
        "diagnostic_artifact" in detail and "harness=? AND artifact_id=?" not in detail for detail in local_details
    )
    assert not any(
        "diagnostic_hash" in detail and "harness=? AND artifact_hash=?" not in detail for detail in local_details
    )
    assert not any(
        "reuse_artifact" in detail and "action=? AND harness=? AND artifact_id=?" not in detail
        for detail in policy_details
    )
    assert not any(
        "reuse_hash" in detail and "action=? AND harness=? AND artifact_hash=?" not in detail
        for detail in policy_details
    )
    assert not any("diagnostic_harness_broad" in detail and "harness=?" not in detail for detail in policy_details)
    assert not any("diagnostic_global_broad" in detail and "harness=?" not in detail for detail in policy_details)
    assert not any(
        "diagnostic_publisher" in detail and "harness=? AND publisher=?" not in detail for detail in policy_details
    )
    assert {
        "idx_guard_local_once_diagnostic_artifact",
        "idx_guard_local_once_diagnostic_hash",
    }.issubset({index for detail in local_details for index in detail.split()})
    assert {
        "idx_policy_decisions_reuse_artifact",
        "idx_policy_decisions_reuse_hash",
        "idx_policy_decisions_diagnostic_harness_broad",
        "idx_policy_decisions_diagnostic_global_broad",
        "idx_policy_decisions_diagnostic_publisher",
    }.issubset({index for detail in policy_details for index in detail.split()})


def test_exact_package_local_once_approval_remains_reusable_for_three_retries(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    artifact_id = "guard-cli:project:package-request:npm-install"
    context_hash = _approval_context_token(content="sha256:unchanged-package")
    approval_id = store.record_local_once_approval(
        request_id="request-package-retry",
        harness="guard-cli",
        artifact_id=artifact_id,
        artifact_hash=context_hash,
        workspace=str(tmp_path / "workspace"),
        publisher="npm",
        action="allow",
        created_at="2026-07-17T12:00:00+00:00",
        expires_at="2026-07-17T13:00:00+00:00",
    )
    assert approval_id is not None

    for minute in (1, 2, 3):
        lookup = store.resolve_policy_decision_lookup(
            "guard-cli",
            artifact_id,
            artifact_hash=context_hash,
            workspace=str(tmp_path / "workspace"),
            publisher="npm",
            now=f"2026-07-17T12:0{minute}:00+00:00",
            consume_one_shot=False,
        )
        decision = lookup["decision"]
        assert decision is not None
        assert decision["approval_id"] == approval_id
        assert store.claim_approval_reuse_decision(
            decision,
            now=f"2026-07-17T12:0{minute}:30+00:00",
        )

    with sqlite3.connect(store.path) as connection:
        claimed_at = connection.execute(
            "select claimed_at from guard_local_once_approvals where approval_id = ?",
            (approval_id,),
        ).fetchone()[0]
    assert claimed_at is None
    assert len(store.list_events(event_name="approval.local_once_reused")) == 3


@pytest.mark.parametrize(
    ("expires_at", "expected_utc"),
    (
        ("2026-07-18T02:00:00+07:00", "2026-07-17T19:00:00.000000+00:00"),
        ("2026-07-17T19:00:00Z", "2026-07-17T19:00:00.000000+00:00"),
        ("2026-07-17T19:00:00", "2026-07-17T19:00:00.000000+00:00"),
    ),
)
def test_policy_expiry_is_utc_normalized_and_excluded_at_boundary(
    tmp_path,
    expires_at: str,
    expected_utc: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    artifact_id = "codex:project:tool-action:expiry"
    context_hash = _approval_context_token(content="sha256:expiry")
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=artifact_id,
            artifact_hash=context_hash,
            source="local",
            expires_at=expires_at,
        ),
        "2026-07-17T18:00:00Z",
    )

    with sqlite3.connect(store.path) as connection:
        stored_expiry = connection.execute(
            "select expires_at from policy_decisions where artifact_id = ?",
            (artifact_id,),
        ).fetchone()[0]
    assert stored_expiry == expected_utc
    before_expiry = store.resolve_policy_decision_lookup(
        "codex",
        artifact_id,
        context_hash,
        now="2026-07-17T18:59:59Z",
        consume_one_shot=False,
    )
    assert before_expiry["decision"] is not None
    assert not store.claim_approval_reuse_decision(
        before_expiry["decision"],
        now="2026-07-17T19:00:00Z",
    )
    assert (
        store.resolve_policy_decision(
            "codex",
            artifact_id,
            context_hash,
            now="2026-07-17T19:00:00Z",
            consume_one_shot=False,
        )
        is None
    )


def test_local_once_offset_expiry_is_normalized_and_excluded_after_actual_instant(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    artifact_id = "codex:project:tool-action:local-expiry"
    context_hash = _approval_context_token(content="sha256:local-expiry")
    approval_id = store.record_local_once_approval(
        request_id="request-local-expiry",
        harness="codex",
        artifact_id=artifact_id,
        artifact_hash=context_hash,
        workspace=None,
        publisher=None,
        action="allow",
        created_at="2026-07-17T10:00:00+07:00",
        expires_at="2026-07-18T02:00:00+07:00",
    )
    assert approval_id is not None

    with sqlite3.connect(store.path) as connection:
        created_at, expires_at = connection.execute(
            "select created_at, expires_at from guard_local_once_approvals where approval_id = ?",
            (approval_id,),
        ).fetchone()
    assert created_at == "2026-07-17T03:00:00.000000+00:00"
    assert expires_at == "2026-07-17T19:00:00.000000+00:00"
    before_expiry = store.resolve_policy_decision_lookup(
        "codex",
        artifact_id,
        context_hash,
        now="2026-07-17T18:59:59Z",
        consume_one_shot=False,
    )
    assert before_expiry["decision"] is not None
    assert not store.claim_approval_reuse_decision(
        before_expiry["decision"],
        now="2026-07-17T19:00:00Z",
    )
    assert (
        store.peek_local_once_approval(
            harness="codex",
            artifact_id=artifact_id,
            artifact_hash=context_hash,
            workspace=None,
            publisher=None,
            now="2026-07-17T18:59:59Z",
        )
        is not None
    )
    assert (
        store.peek_local_once_approval(
            harness="codex",
            artifact_id=artifact_id,
            artifact_hash=context_hash,
            workspace=None,
            publisher=None,
            now="2026-07-17T19:00:00Z",
        )
        is None
    )


@pytest.mark.parametrize(
    ("current_token", "expected_reason"),
    (
        (
            _approval_context_token(
                identity={"artifact_id": "codex:project:mcp-tool:read", "workspace": "/workspace/b"}
            ),
            "approval_reuse_identity_changed",
        ),
        (_approval_context_token(content="sha256:changed"), "approval_reuse_content_changed"),
        (
            _approval_context_token(capabilities=["filesystem:read", "network:egress"]),
            "approval_reuse_capability_changed",
        ),
        (_approval_context_token(policy={"version": "policy-v2"}), "approval_reuse_policy_changed"),
        (_approval_context_token(sandbox={"profile": "host"}), "approval_reuse_sandbox_changed"),
    ),
)
def test_lookup_miss_diagnostic_reports_changed_context_dimension(
    tmp_path,
    current_token: str,
    expected_reason: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    artifact_id = "codex:project:mcp-tool:read"
    store.record_local_once_approval(
        request_id="request-context-diagnostic",
        harness="codex",
        artifact_id=artifact_id,
        artifact_hash=_approval_context_token(),
        workspace=None,
        publisher=None,
        action="allow",
        created_at="2026-07-17T12:00:00+00:00",
        expires_at="2026-07-17T14:00:00+00:00",
    )

    reason = store.approval_reuse_validation_reason(
        "codex",
        artifact_id,
        current_token,
        None,
        None,
        "2026-07-17T12:30:00+00:00",
    )

    assert reason == expected_reason


def test_runtime_saved_artifact_allow_requires_matching_v1_context_token() -> None:
    artifact = GuardArtifact(
        artifact_id="codex:project:file-read:.env",
        name="Read sensitive local file",
        harness="codex",
        artifact_type="file_read_request",
        source_scope="project",
        config_path="/workspace/.env",
    )

    current_token = _approval_context_token()

    assert (
        _runtime_saved_allow_validation_reason(
            {"action": "allow", "scope": "artifact", "artifact_hash": None},
            artifact=artifact,
            artifact_hash=current_token,
        )
        == "approval_reuse_content_changed"
    )
    assert (
        _runtime_saved_allow_validation_reason(
            {"action": "allow", "scope": "artifact", "artifact_hash": "sha256:current"},
            artifact=artifact,
            artifact_hash="sha256:current",
        )
        == "approval_reuse_content_changed"
    )
    assert (
        _runtime_saved_allow_validation_reason(
            {"action": "allow", "scope": "artifact", "artifact_hash": current_token},
            artifact=artifact,
            artifact_hash=current_token,
        )
        is None
    )
