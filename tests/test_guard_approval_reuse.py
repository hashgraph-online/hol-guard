from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from pathlib import Path
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
from codex_plugin_scanner.guard.policy_bundle_decisions import build_policy_bundle_decisions
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
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
    ApprovalReuseMalformedResultError,
    ApprovalReuseValidationFailure,
    evaluate_approval_reuse,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_policy import (
    _bounded_local_approval_reuse_diagnostic_rows,
    _bounded_policy_approval_reuse_diagnostic_rows,
)
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring, sign_policy_bundle

_POLICY_BUNDLE_WORKSPACE_ID = "workspace-1"


def _install_signed_exact_policies(
    store: GuardStore,
    policies: list[tuple[str, str, str]],
    *,
    now: str,
    bundle_version: str,
) -> None:
    rules = [
        {
            "ruleId": f"test-rule-{index}",
            "action": action,
            "reason": reason,
            "artifactId": artifact_id,
            "scope": {
                "agents": [],
                "devices": [],
                "ecosystems": [],
                "environments": [],
                "harnesses": ["codex"],
                "locations": [],
            },
        }
        for index, (artifact_id, action, reason) in enumerate(policies)
    ]
    bundle = sign_policy_bundle(
        {
            "contractVersion": "guard-policy-bundle.v1",
            "bundleVersion": bundle_version,
            "bundleHash": "",
            "issuedAt": now,
            "expiresAt": None,
            "rolloutState": "enforcing",
            "policyDefaults": {
                "mode": "observe",
                "defaultAction": "allow",
                "unknownPublisherAction": "allow",
                "changedHashAction": "allow",
                "newNetworkDomainAction": "allow",
                "subprocessAction": "allow",
                "telemetryEnabled": False,
                "syncEnabled": True,
            },
            "rules": rules,
            "cloudExceptions": [],
            "acknowledgements": [],
        },
        workspace_id=_POLICY_BUNDLE_WORKSPACE_ID,
    )
    keyring = policy_bundle_test_keyring(workspace_id=_POLICY_BUNDLE_WORKSPACE_ID)
    store.set_sync_payload(
        "oauth_local_credentials",
        {"workspace_id": _POLICY_BUNDLE_WORKSPACE_ID},
        now,
    )
    device = store.get_device_metadata()
    decisions = build_policy_bundle_decisions(
        bundle,
        device_id=device["installation_id"],
        device_name=device["device_label"],
    )
    assert [(item.artifact_id, item.action, item.reason) for item in decisions] == policies
    store.apply_policy_bundle_authority(
        decisions,
        now,
        policy_bundle=bundle,
        policy_bundle_keyring=keyring,
        cloud_exceptions=[],
        policy_bundle_ack={"bundleVersion": bundle_version, "status": "applied"},
        policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
        update_last_good=True,
        remote_write_authorized=True,
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
def test_no_saved_approval_preserves_recomputed_current_action(
    current_action: str,
    native_context_digest: Path,
) -> None:
    result = evaluate_approval_reuse(current_action)

    assert result.action == current_action
    assert result.status == "not-applicable"
    assert result.reason_code == APPROVAL_REUSE_NO_SAVED_DECISION
    assert result.should_claim is False


@pytest.mark.parametrize("field", ("current_action", "saved_action"))
def test_non_json_action_cannot_become_allow(field: str, native_context_digest: Path) -> None:
    from codex_plugin_scanner.guard.runtime.approval_reuse import ApprovalReuseMalformedResultError

    class LooksLikeAllow:
        def __str__(self) -> str:
            return "allow"

    actions = {"current_action": "review", "saved_action": "allow"}
    actions[field] = LooksLikeAllow()
    with pytest.raises(ApprovalReuseMalformedResultError):
        evaluate_approval_reuse(**actions)


def test_exact_saved_allow_can_satisfy_only_current_review(native_context_digest: Path) -> None:
    result = evaluate_approval_reuse("review", "allow")

    assert result.action == "allow"
    assert result.status == "accepted"
    assert result.reason_code == APPROVAL_REUSE_ACCEPTED
    assert result.should_claim is True


def test_fresh_local_allow_satisfies_current_reapproval_once(native_context_digest: Path) -> None:
    result = evaluate_approval_reuse(
        "require-reapproval",
        "allow",
        fresh_local_approval=True,
    )

    assert result.action == "allow"
    assert result.status == "accepted"
    assert result.reason_code == APPROVAL_REUSE_ACCEPTED
    assert result.should_claim is True


def test_durable_exact_allow_satisfies_identical_current_reapproval(native_context_digest: Path) -> None:
    result = evaluate_approval_reuse(
        "require-reapproval",
        "allow",
        durable_exact_approval=True,
    )

    assert result.action == "allow"
    assert result.status == "accepted"
    assert result.reason_code == APPROVAL_REUSE_ACCEPTED
    assert result.should_claim is True


def test_changed_durable_exact_allow_cannot_satisfy_reapproval(native_context_digest: Path) -> None:
    result = evaluate_approval_reuse(
        "require-reapproval",
        "allow",
        validation_reason="approval_reuse_content_changed",
        durable_exact_approval=True,
    )

    assert result.action == "require-reapproval"
    assert result.status == "rejected"
    assert result.reason_code == "approval_reuse_content_changed"


@pytest.mark.parametrize("current_action", ("sandbox-required", "block"))
def test_durable_exact_allow_never_lowers_terminal_enforcement(
    current_action: str,
    native_context_digest: Path,
) -> None:
    result = evaluate_approval_reuse(
        current_action,
        "allow",
        durable_exact_approval=True,
    )

    assert result.action == current_action
    assert result.status == "rejected"
    assert result.should_claim is False


@pytest.mark.parametrize("current_action", ("sandbox-required", "block"))
def test_fresh_local_allow_never_lowers_enforcement(
    current_action: str,
    native_context_digest: Path,
) -> None:
    result = evaluate_approval_reuse(
        current_action,
        "allow",
        fresh_local_approval=True,
    )

    assert result.action == current_action
    assert result.status == "rejected"
    assert result.should_claim is False


def test_changed_fresh_local_allow_cannot_satisfy_reapproval(native_context_digest: Path) -> None:
    result = evaluate_approval_reuse(
        "require-reapproval",
        "allow",
        validation_reason="approval_reuse_content_changed",
        fresh_local_approval=True,
    )

    assert result.action == "require-reapproval"
    assert result.status == "rejected"
    assert result.reason_code == "approval_reuse_content_changed"
    assert result.should_claim is False


@pytest.mark.parametrize(
    ("current_action", "expected_reason"),
    (
        ("require-reapproval", APPROVAL_REUSE_REAPPROVAL_REQUIRED),
        ("sandbox-required", APPROVAL_REUSE_SANDBOX_REQUIRED),
        ("block", APPROVAL_REUSE_CURRENT_BLOCK),
    ),
)
def test_saved_allow_never_lowers_stronger_current_action(
    current_action: str,
    expected_reason: str,
    native_context_digest: Path,
) -> None:
    result = evaluate_approval_reuse(current_action, "allow")

    assert result.action == current_action
    assert result.status == "rejected"
    assert result.reason_code == expected_reason
    assert result.should_claim is False


@pytest.mark.parametrize("current_action", ("allow", "warn"))
def test_saved_allow_is_not_consumed_when_current_action_needs_no_review(
    current_action: str,
    native_context_digest: Path,
) -> None:
    result = evaluate_approval_reuse(current_action, "allow")

    assert result.action == current_action
    assert result.status == "not-applicable"
    assert result.reason_code == APPROVAL_REUSE_CURRENT_ACTION_NOT_REVIEW
    assert result.should_claim is False


def test_integrity_invalid_authority_requires_reapproval_even_when_current_action_allows(
    native_context_digest: Path,
) -> None:
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
def test_saved_block_remains_block_for_every_current_action(
    current_action: str,
    native_context_digest: Path,
) -> None:
    result = evaluate_approval_reuse(current_action, "block")

    assert result.action == "block"
    assert result.status == "accepted"
    assert result.reason_code == APPROVAL_REUSE_SAVED_BLOCK
    assert result.should_claim is False


def test_non_allow_saved_action_cannot_satisfy_review(native_context_digest: Path) -> None:
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
    native_context_digest: Path,
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


def test_unknown_current_action_fails_closed_with_diagnostics(native_context_digest: Path) -> None:
    result = evaluate_approval_reuse("future-permissive-action", "allow")

    assert result.action == "block"
    assert result.reason_code == APPROVAL_REUSE_CURRENT_ACTION_UNKNOWN
    assert result.current_normalization_reason_code == "guard_action_unknown"
    assert result.original_current_action == "future-permissive-action"
    assert result.should_claim is False


def test_present_malformed_saved_action_requires_reapproval_with_diagnostics(
    native_context_digest: Path,
) -> None:
    result = evaluate_approval_reuse("review", None, saved_decision_present=True)

    assert result.action == "require-reapproval"
    assert result.reason_code == APPROVAL_REUSE_SAVED_ACTION_UNKNOWN
    assert result.saved_normalization_reason_code == "guard_action_unknown"
    assert result.original_saved_type == "NoneType"
    assert result.to_evidence()["saved_action"] == "require-reapproval"


def test_claim_failure_reason_takes_precedence_and_preserves_normalization_diagnostics(
    native_context_digest: Path,
) -> None:
    result = evaluate_approval_reuse(
        "review",
        None,
        saved_decision_present=True,
        validation_reason=APPROVAL_REUSE_CLAIM_FAILED,
    )

    assert result.action == "require-reapproval"
    assert result.reason_code == APPROVAL_REUSE_CLAIM_FAILED
    assert result.saved_normalization_reason_code == "guard_action_unknown"


def test_malformed_native_payload_raises_instead_of_granting_reuse(
    monkeypatch: pytest.MonkeyPatch,
    native_context_digest: Path,
) -> None:
    """A well-formed envelope with an invalid decision payload is a contract
    violation, not a successful no-decision: it raises and never claims."""

    from codex_plugin_scanner.guard import native_approval_reuse

    def _payload(**overrides: object) -> dict[str, object]:
        payload: dict[str, object] = {
            "action": "allow",
            "status": "accepted",
            "reason_code": APPROVAL_REUSE_ACCEPTED,
            "current_action": "review",
            "saved_action": "allow",
            "should_claim": True,
            "original_current_type": "str",
        }
        payload.update(overrides)
        return payload

    for malformed in (
        # would grant a claim with a string-typed should_claim
        _payload(should_claim="yes"),
        # action outside the canonical lattice
        _payload(action="execute-anyway"),
        # status outside the closed set
        _payload(status="approved"),
        # missing reason code
        _payload(reason_code=None),
        # saved action outside the lattice
        _payload(saved_action="maybe"),
        _payload(current_action=None),
        _payload(saved_action=42),
        _payload(reason_code=""),
        # not a mapping at all
        "not-a-mapping",
    ):
        monkeypatch.setattr(
            native_approval_reuse,
            "approval_reuse_decide_native",
            lambda *args, _malformed=malformed, **kwargs: _malformed,
        )
        with pytest.raises(ApprovalReuseMalformedResultError):
            evaluate_approval_reuse("review", "allow", saved_decision_present=True)


@pytest.mark.parametrize("corruption", ("json", "schema", "request_id", "request_sha256", "status", "code", "payload"))
def test_invalid_resident_envelope_cannot_grant_reuse(
    corruption: str, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    import hashlib
    import json

    from codex_plugin_scanner.guard import native_approval_reuse

    # Malformed transport frames must not poison the session resident used by
    # independent behavior tests.
    monkeypatch.setattr(native_approval_reuse, "native_record_resident_failure", lambda *a, **kw: None)

    def reply(*args: object, **kwargs: object) -> bytes:
        if corruption == "json":
            return b"not-json"
        request = json.loads(kwargs["payload"])["request"]
        envelope = {
            "schema": "guard-approval-reuse-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:"
            + hashlib.sha256(
                json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
            ).hexdigest(),
            "status": "ok",
            "code": "ok",
            "payload": {
                "action": "allow",
                "status": "accepted",
                "reason_code": APPROVAL_REUSE_ACCEPTED,
                "current_action": "review",
                "saved_action": "allow",
                "should_claim": True,
                "original_current_type": "str",
            },
        }
        envelope[corruption] = None if corruption == "payload" else "invalid"
        return json.dumps(envelope).encode()

    monkeypatch.setattr(native_approval_reuse, "native_resident_client_request", reply)
    with pytest.raises(ApprovalReuseMalformedResultError):
        evaluate_approval_reuse("review", "allow", saved_decision_present=True)


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


def test_batch_claim_consumes_two_exact_one_shot_approvals_atomically(tmp_path, native_context_digest: Path) -> None:
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


def test_batch_claim_rolls_back_every_sibling_when_one_row_fails_integrity(
    tmp_path, native_context_digest: Path
) -> None:
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
def test_approval_resolution_preserves_exact_context_token_across_every_scope(
    tmp_path, scope: str, native_context_digest: Path
) -> None:
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
    resolved = apply_approval_resolution(
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
    assert stored == []
    assert resolved["applied_scope"] == "artifact"
    if scope != "artifact":
        assert resolved["scope_warning"] == "legacy_scope_narrowed_to_artifact"
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


def test_broad_scope_exact_context_allow_does_not_resolve_or_authorize_other_context(
    tmp_path, native_context_digest: Path
) -> None:
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
    _install_signed_exact_policies(
        store,
        [(artifact_id, "block", "Signed managed block")],
        now="2026-07-17T12:01:00+00:00",
        bundle_version="policy-2026-07-17.block-after-approval",
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
    assert selected["source"] == "policy-bundle"
    assert store.claim_local_once_approval(approval_id, claimed_at="2026-07-17T12:03:00+00:00") is True


def test_non_consuming_runtime_lookup_composes_specific_allow_with_broader_managed_block(
    tmp_path, native_context_digest: Path
) -> None:
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
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="global",
            action="block",
            source="manual",
        ),
        "2026-07-17T12:01:00+00:00",
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
    assert runtime_decision["source"] == "manual"
    assert legacy_scope_precedence is not None
    assert legacy_scope_precedence["action"] == "allow"
    assert store.list_events(event_name="policy_integrity_violation") == []
    assert store.list_events(event_name="rule.ignored.local_integrity") == []


@pytest.mark.parametrize("scope", ("workspace", "harness", "global"))
@pytest.mark.parametrize("source", ("local", "manual"))
def test_non_consuming_scope_lookup_preserves_specificity_and_stronger_actions(
    tmp_path,
    scope: DecisionScope,
    source: str,
    native_context_digest: Path,
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
    assert stronger["integrity_status"] == "valid"


def test_non_consuming_runtime_lookup_composes_direct_allow_with_exact_command_block(
    tmp_path, native_context_digest: Path
) -> None:
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
    artifact_id = "codex:project:tool-action:remote"
    artifact_hash = "sha256:remote"
    _install_signed_exact_policies(
        store,
        [(artifact_id, "allow", "Signed remote allow")],
        now="2026-07-17T12:00:00+00:00",
        bundle_version="policy-2026-07-17.remote-allow",
    )
    selected = store.resolve_policy_decision(
        "codex",
        artifact_id,
        artifact_hash,
        now="2026-07-17T12:01:00+00:00",
        consume_one_shot=False,
    )
    assert selected is not None

    _install_signed_exact_policies(
        store,
        [(artifact_id, "block", "Signed remote block")],
        now="2026-07-17T12:02:00+00:00",
        bundle_version="policy-2026-07-17.remote-block",
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
    artifact_id = "codex:project:tool-action:persistent"
    artifact_hash = "sha256:persistent"
    _install_signed_exact_policies(
        store,
        [(artifact_id, "allow", "Signed persistent allow")],
        now="2026-07-17T12:00:00+00:00",
        bundle_version="policy-2026-07-17.persistent-allow",
    )
    selected = store.resolve_policy_decision(
        "codex",
        artifact_id,
        artifact_hash,
        now="2026-07-17T12:01:00+00:00",
        consume_one_shot=False,
    )
    assert selected is not None

    assert store.claim_approval_reuse_decision(selected, now="2026-07-17T12:02:00+00:00") is True
    assert (
        store.resolve_policy(
            "codex",
            artifact_id,
            artifact_hash,
            now="2026-07-17T12:03:00+00:00",
            consume_one_shot=False,
        )
        == "allow"
    )
    assert len(store.list_events(event_name="approval.policy_reuse_applied")) == 1


def test_claim_rejects_allow_when_broader_block_is_inserted_after_lookup(tmp_path, native_context_digest: Path) -> None:
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


def test_claim_rejects_direct_allow_when_memory_block_is_inserted_after_lookup(
    tmp_path, native_context_digest: Path
) -> None:
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


def test_claim_rejects_local_once_when_policy_changes_and_keeps_it_unclaimed(
    tmp_path, native_context_digest: Path
) -> None:
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


def test_exact_package_local_once_approval_remains_reusable_for_three_retries(
    tmp_path, native_context_digest: Path
) -> None:
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
    native_context_digest: Path,
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


def test_local_once_offset_expiry_is_normalized_and_excluded_after_actual_instant(
    tmp_path, native_context_digest: Path
) -> None:
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


def test_lookup_miss_diagnostic_reports_changed_context_dimension(
    tmp_path,
    native_context_digest: Path,
) -> None:
    # Tokens must be built inside the test: parametrize arguments are evaluated
    # at collection time, before the native runtime fixture can run.
    cases: list[tuple[tuple[object, ...], str]] = [
        (
            (
                _approval_context_token(
                    identity={"artifact_id": "codex:project:mcp-tool:read", "workspace": "/workspace/b"}
                ),
            ),
            "approval_reuse_identity_changed",
        ),
        (
            (_approval_context_token(content="sha256:changed"),),
            "approval_reuse_content_changed",
        ),
        (
            (_approval_context_token(capabilities=["filesystem:read", "network:egress"]),),
            "approval_reuse_capability_changed",
        ),
        (
            (_approval_context_token(policy={"version": "policy-v2"}),),
            "approval_reuse_policy_changed",
        ),
        (
            (_approval_context_token(sandbox={"profile": "host"}),),
            "approval_reuse_sandbox_changed",
        ),
    ]
    for index, ((current_token,), expected_reason) in enumerate(cases):
        store = GuardStore(tmp_path / f"guard-home-{index}")
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


def test_runtime_saved_artifact_allow_requires_matching_v1_context_token(native_context_digest: Path) -> None:
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


def test_shared_deadline_expiry_cannot_grant_another_reuse(
    monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    import time
    from types import SimpleNamespace

    from codex_plugin_scanner.guard import native_approval_reuse

    now = time.monotonic()
    deadline = now + 30.0
    first = evaluate_approval_reuse("review", "allow", saved_decision_present=True, deadline_monotonic=deadline)
    assert first is not None and first.action == "allow" and first.should_claim
    monkeypatch.setattr(native_approval_reuse, "time", SimpleNamespace(monotonic=lambda: deadline + 1.0))

    def forbidden_transport(**kwargs: object) -> bytes:
        pytest.fail("expired request dispatched to the resident")

    monkeypatch.setattr(native_approval_reuse, "native_resident_client_request", forbidden_transport)
    second = evaluate_approval_reuse("review", "allow", saved_decision_present=True, deadline_monotonic=deadline)
    assert second is None


def test_already_expired_deadline_cannot_grant_reuse(monkeypatch: pytest.MonkeyPatch) -> None:
    import time

    from codex_plugin_scanner.guard import native_approval_reuse

    def forbidden_transport(**kwargs: object) -> bytes:
        pytest.fail("expired request dispatched to the resident")

    monkeypatch.setattr(native_approval_reuse, "native_resident_client_request", forbidden_transport)
    assert (
        evaluate_approval_reuse("review", "allow", saved_decision_present=True, deadline_monotonic=time.monotonic() - 1)
        is None
    )


@pytest.mark.parametrize("caller_deadline", (None, 101.0, 110.0))
@pytest.mark.parametrize("expiry_stage", ("discovery", "serialization"))
def test_approval_reuse_discovery_and_serialization_cannot_restart_budget(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caller_deadline: float | None,
    expiry_stage: str,
) -> None:
    from types import SimpleNamespace

    from codex_plugin_scanner.guard import native_approval_reuse

    clock = [100.0]
    deadline = min(102.0, caller_deadline) if caller_deadline is not None else 102.0
    monkeypatch.setattr(native_approval_reuse, "time", SimpleNamespace(monotonic=lambda: clock[0]))

    def discover(*, deadline_monotonic: float) -> object:
        assert deadline_monotonic == deadline
        if expiry_stage == "discovery":
            clock[0] = deadline
        return SimpleNamespace(
            mode="auto",
            available=True,
            compatible=True,
            identity=SimpleNamespace(path=tmp_path / "resident", sha256="runtime"),
            capabilities=SimpleNamespace(features={"resident-protocol-v2", "approval-reuse-v1"}),
        )

    monkeypatch.setattr(native_approval_reuse, "native_runtime_status", discover)
    monkeypatch.setattr(
        native_approval_reuse, "native_runtime_health_snapshot", lambda *args: SimpleNamespace(circuit_open=False)
    )
    original_dumps = native_approval_reuse.json.dumps

    def serialize(*args: object, **kwargs: object) -> str:
        result = original_dumps(*args, **kwargs)
        if expiry_stage == "serialization":
            clock[0] = deadline
        return result

    monkeypatch.setattr(native_approval_reuse.json, "dumps", serialize)

    def forbidden_transport(**kwargs: object) -> bytes:
        pytest.fail("budget exhausted before resident dispatch")

    monkeypatch.setattr(native_approval_reuse, "native_resident_client_request", forbidden_transport)
    assert (
        native_approval_reuse.approval_reuse_decide_native(
            "review",
            "allow",
            saved_decision_present=True,
            validation_reason=None,
            fresh_local_approval=False,
            durable_exact_approval=False,
            guard_home=tmp_path,
            deadline_monotonic=caller_deadline,
        )
        is None
    )
