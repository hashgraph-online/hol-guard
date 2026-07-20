from __future__ import annotations

import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition, PositiveProof
from codex_plugin_scanner.guard.runtime.github_capability_interaction import GITHUB_MAINTENANCE_ACTION_CLASS
from codex_plugin_scanner.guard.runtime.github_workflow_authorization import (
    GitHubWorkflowAuthorization,
    GitHubWorkflowBindingContext,
    claim_github_workflow_authorization,
    github_repository_sha256,
    issue_github_workflow_capability,
)
from codex_plugin_scanner.guard.runtime.github_workflow_operations import (
    GitHubWorkflowOperation,
    parse_github_workflow_operation,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_workflow_capability_common import WORKFLOW_CAPABILITY_STORE_CLOCK
from codex_plugin_scanner.guard.workflow_capabilities import (
    WorkflowCapabilityError,
    WorkflowCapabilityRuleBinding,
    format_utc_timestamp,
)

_KEY = b"w" * 32
_KEY_ID = "guard-policy-integrity-key:github-workflow-test"
_ISSUED = datetime(2026, 7, 20, 12, tzinfo=timezone.utc)
_COMMAND = (
    "gh api graphql -f "
    "query='mutation($threadId:ID!){resolveReviewThread(input:{threadId:$threadId}){thread{id}}}' "
    "-f threadId=THREAD_1"
)


@pytest.fixture(autouse=True)
def fixed_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    def secret_material(_store: GuardStore, *, create: bool) -> tuple[bytes | None, str | None]:
        del create
        return _KEY, _KEY_ID

    def fixed_now() -> str:
        return format_utc_timestamp(_ISSUED)

    monkeypatch.setattr(GuardStore, "_policy_integrity_secret_material", secret_material)
    monkeypatch.setattr(WORKFLOW_CAPABILITY_STORE_CLOCK, "now", fixed_now)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _context(**changes: object) -> GitHubWorkflowBindingContext:
    context = GitHubWorkflowBindingContext(
        repository_sha256=github_repository_sha256("example/repo"),
        workspace_sha256=_digest("workspace"),
        executable_sha256=_digest("executable"),
        cwd_sha256=_digest("cwd"),
        environment_sha256=_digest("environment"),
        configuration_sha256=_digest("configuration"),
        manifest_sha256=_digest("manifest"),
        lockfile_sha256=_digest("lockfile"),
        sandbox_sha256=_digest("sandbox"),
        policy_id="guard.command-policy",
        policy_version="policy.v1",
        effect_id="github.maintain-remote",
        effect_version="effect.v1",
        decision_id="github.workflow-authorized",
        decision_version="decision.v1",
        rules=(WorkflowCapabilityRuleBinding("github.maintain-remote", "rule.v1"),),
    )
    return replace(context, **changes)


def _operation(command: str = _COMMAND, *, repository: str = "example/repo") -> GitHubWorkflowOperation:
    parsed = parse_github_workflow_operation(
        parse_shell_command(command, cwd=Path("workspace"), home_dir=Path("home")),
        repository=repository,
    )
    assert parsed is not None
    return parsed


def _issue(
    store: GuardStore,
    context: GitHubWorkflowBindingContext,
    *,
    command: str = _COMMAND,
    max_uses: int = 1,
) -> None:
    _ = issue_github_workflow_capability(
        store,
        _operation(command),
        context,
        capability_id="wc-github-thread-1",
        approval_provenance_id="approval-thread-1",
        task_id="task-pr-review-1",
        nonce="1" * 32,
        issuer_id="guard.local",
        subject_id="codex.session-1",
        issued_at=format_utc_timestamp(_ISSUED - timedelta(seconds=1)),
        not_before=format_utc_timestamp(_ISSUED - timedelta(seconds=1)),
        expires_at=format_utc_timestamp(_ISSUED + timedelta(minutes=10)),
        max_uses=max_uses,
        key=_KEY,
        key_id=_KEY_ID,
    )


def _claim(
    store: GuardStore,
    context: GitHubWorkflowBindingContext,
    *,
    command: str = _COMMAND,
    invocation_id: str = "tool-call-1",
    subject_id: str = "codex.session-1",
    task_id: str = "task-pr-review-1",
    issuer_id: str = "guard.local",
    approval_provenance_id: str = "approval-thread-1",
) -> GitHubWorkflowAuthorization:
    return claim_github_workflow_authorization(
        store,
        "wc-github-thread-1",
        _operation(command),
        context,
        invocation_id=invocation_id,
        subject_id=subject_id,
        task_id=task_id,
        issuer_id=issuer_id,
        approval_provenance_id=approval_provenance_id,
    )


@pytest.mark.parametrize(
    "command",
    (
        _COMMAND,
        "gh api graphql -f query='mutation($threadId:ID!){unresolveReviewThread"
        + "(input:{threadId:$threadId}){thread{id}}}' -f threadId=T2",
        "gh issue lock 17 --repo example/repo",
        "gh issue unlock 17 -R example/repo",
        "gh issue pin 17 --repo example/repo",
        "gh issue unpin 17 --repo example/repo",
        "gh pr lock 17 --repo example/repo",
        "gh pr unlock 17 --repo example/repo",
    ),
)
def test_exact_static_maintenance_operations_are_eligible(command: str) -> None:
    assert parse_github_workflow_operation(parse_shell_command(command), repository="example/repo") is not None


@pytest.mark.parametrize(
    "command",
    (
        "gh pr ready 17 --repo example/repo",
        "gh pr ready 17 --undo --repo example/repo",
    ),
)
def test_exact_bounded_pr_metadata_operations_are_eligible(command: str) -> None:
    assert parse_github_workflow_operation(parse_shell_command(command), repository="example/repo") is not None


@pytest.mark.parametrize(
    "command",
    (
        "gh pr merge 17 --repo example/repo --squash",
        "gh pr review 17 --approve --repo example/repo",
        "gh workflow run ci.yml --repo example/repo",
        "gh repo delete example/repo --yes",
        "gh secret set TOKEN --body value --repo example/repo",
        "gh issue lock $ISSUE --repo example/repo",
        "./gh issue lock 17 --repo example/repo",
        "GH issue lock 17 --repo example/repo",
        "gh issue lock 17",
        "gh issue lock 17 --repo example/repo > result.txt",
        "gh issue lock 17 --repo example/repo &",
        "sh -c 'gh issue lock 17 --repo example/repo'",
        'gh api graphql -f query=\'mutation{resolveReviewThread(input:{threadId:"T"}){thread{id}} '
        + 'deletePackageVersion(input:{packageVersionId:"P"}){success}}\' -f threadId=T',
        "gh pr edit 17 --title changed --repo example/repo",
        "gh pr edit 17 --body changed --repo example/repo",
        "gh pr edit 17 --add-label safe --repo example/repo",
        "gh pr edit 17 --milestone sprint-1 --repo example/repo",
    ),
)
def test_dynamic_mixed_and_high_impact_operations_are_ineligible(command: str) -> None:
    assert parse_github_workflow_operation(parse_shell_command(command), repository="example/repo") is None


def test_atomic_claim_produces_workflow_authorized_decision(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    context = _context()
    _issue(store, context)
    authorization = _claim(store, context)

    evaluation = evaluate_command(
        _COMMAND,
        compatibility_action_class=GITHUB_MAINTENANCE_ACTION_CLASS,
        compatibility_reason="Exact GitHub maintenance requires review without task proof.",
        workflow_authorization=authorization,
    )

    assert evaluation.decision_plane.action == "allow"
    assert evaluation.decision_plane.disposition is FinalDisposition.WORKFLOW_AUTHORIZED


def test_bounded_pr_metadata_claim_produces_workflow_authorized_decision(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    command = "gh pr ready 17 --undo --repo example/repo"
    context = _context()
    _issue(store, context, command=command)
    authorization = _claim(store, context, command=command)

    evaluation = evaluate_command(
        command,
        compatibility_action_class=GITHUB_MAINTENANCE_ACTION_CLASS,
        workflow_authorization=authorization,
    )

    assert evaluation.decision_plane.action == "allow"
    assert evaluation.decision_plane.disposition is FinalDisposition.WORKFLOW_AUTHORIZED


def test_graphql_operation_requires_guard_derived_repository() -> None:
    assert parse_github_workflow_operation(parse_shell_command(_COMMAND)) is None


def test_operation_record_rejects_resource_type_and_digest_forgery() -> None:
    operation = _operation()

    with pytest.raises(ValueError, match="resource type mismatch"):
        _ = replace(operation, resource_type="github-pr")
    with pytest.raises(ValueError, match="digest mismatch"):
        _ = replace(operation, command_identity=f"command-security-v2:{_digest('forged')}")


@pytest.mark.parametrize(
    "query",
    (
        'mutation($threadId:ID!){resolveReviewThread(input:{threadId:"VICTIM"}){thread{id}}}',
        "mutation($threadId:ID!,$other:ID!){resolveReviewThread(input:{threadId:$other}){thread{id}}}",
        "mutation($threadId:ID!){resolveReviewThread(input:{threadId:$other}){thread{id}}}",
        "mutation($threadId:ID!){resolveReviewThread(input:{threadId:$threadId}){thread{id}}} # hidden",
        (
            "mutation($threadId:ID!){resolveReviewThread(input:{threadId:$threadId}){thread{id}} "
            'resolveReviewThread(input:{threadId:"OTHER"}){thread{id}}}'
        ),
    ),
)
def test_graphql_resource_field_cannot_lie_about_executed_target(query: str) -> None:
    command = f"gh api graphql -f query='{query}' -f threadId=APPROVED"
    assert parse_github_workflow_operation(parse_shell_command(command), repository="example/repo") is None


def test_context_repository_digest_must_match_operation_repository(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    mismatched = replace(_context(), repository_sha256=github_repository_sha256("other/repo"))

    with pytest.raises(WorkflowCapabilityError, match="github_workflow_repository_mismatch"):
        _issue(store, mismatched)


@pytest.mark.parametrize(
    ("changes", "expected_error"),
    (
        ({"effect_id": "github.content-remote"}, "github_workflow_effect_mismatch"),
        ({"decision_id": "github.other-decision"}, "github_workflow_decision_mismatch"),
        (
            {"rules": (WorkflowCapabilityRuleBinding("github.content-remote", "rule.v1"),)},
            "github_workflow_rule_mismatch",
        ),
    ),
)
def test_operation_semantics_cannot_use_wrong_effect_or_rule_binding(
    tmp_path: Path,
    changes: dict[str, object],
    expected_error: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)

    with pytest.raises(WorkflowCapabilityError, match=expected_error):
        _issue(store, _context(**changes))


@pytest.mark.parametrize(
    "field",
    (
        "repository_sha256",
        "workspace_sha256",
        "executable_sha256",
        "cwd_sha256",
        "environment_sha256",
        "configuration_sha256",
        "manifest_sha256",
        "lockfile_sha256",
        "sandbox_sha256",
    ),
)
def test_every_context_digest_drift_fails_without_consuming_capability(tmp_path: Path, field: str) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    context = _context()
    _issue(store, context)

    expected_error = (
        "github_workflow_repository_mismatch" if field == "repository_sha256" else "capability_context_mismatch"
    )
    with pytest.raises(WorkflowCapabilityError, match=expected_error):
        _ = _claim(store, replace(context, **{field: _digest(f"drift-{field}")}))

    assert _claim(store, context) is not None


def test_invocation_replay_and_operation_drift_fail_closed(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    context = _context()
    _issue(store, context, max_uses=2)
    authorization = _claim(store, context)
    with pytest.raises(WorkflowCapabilityError, match="capability_invocation_replayed"):
        _ = _claim(store, context)

    drifted = evaluate_command(
        "gh issue lock 17 --repo example/repo",
        compatibility_action_class=GITHUB_MAINTENANCE_ACTION_CLASS,
        workflow_authorization=authorization,
    )
    assert drifted.decision_plane.action == "review"


def test_expired_and_revoked_capabilities_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    expired_store = GuardStore(tmp_path / "expired", prime_policy_integrity=False)
    context = _context()
    _issue(expired_store, context)
    monkeypatch.setattr(
        WORKFLOW_CAPABILITY_STORE_CLOCK,
        "now",
        lambda: format_utc_timestamp(_ISSUED + timedelta(minutes=11)),
    )
    with pytest.raises(WorkflowCapabilityError, match="capability_expired"):
        _ = _claim(expired_store, context)

    monkeypatch.setattr(WORKFLOW_CAPABILITY_STORE_CLOCK, "now", lambda: format_utc_timestamp(_ISSUED))
    revoked_store = GuardStore(tmp_path / "revoked", prime_policy_integrity=False)
    _issue(revoked_store, context)
    assert revoked_store.revoke_workflow_capability("wc-github-thread-1", reason_code="operator.revoked")
    with pytest.raises(WorkflowCapabilityError, match="capability_revoked"):
        _ = _claim(revoked_store, context)


def test_resource_and_repository_drift_fail_without_consuming_capability(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    context = _context()
    _issue(store, context)
    resource_drift = _COMMAND.replace("THREAD_1", "THREAD_2")

    with pytest.raises(WorkflowCapabilityError, match="capability_context_mismatch"):
        _ = _claim(store, context, command=resource_drift)
    with pytest.raises(WorkflowCapabilityError, match="github_workflow_repository_mismatch"):
        _ = claim_github_workflow_authorization(
            store,
            "wc-github-thread-1",
            _operation(repository="other/repo"),
            context,
            invocation_id="tool-call-other-repo",
            subject_id="codex.session-1",
            task_id="task-pr-review-1",
            issuer_id="guard.local",
            approval_provenance_id="approval-thread-1",
        )

    assert _claim(store, context) is not None


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("subject_id", "codex.session-2"),
        ("task_id", "task-pr-review-2"),
        ("issuer_id", "guard.other"),
        ("approval_provenance_id", "approval-thread-2"),
    ),
)
def test_authority_identity_drift_fails_without_consuming_capability(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    context = _context()
    _issue(store, context)

    with pytest.raises(WorkflowCapabilityError, match="capability_"):
        _ = _claim(store, context, **{field: value})

    assert _claim(store, context) is not None


def test_only_one_concurrent_claim_can_consume_last_use(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    context = _context()
    _issue(store, context)
    start = threading.Barrier(2)

    def claim_once(invocation_id: str) -> str:
        _ = start.wait(timeout=5)
        try:
            _ = _claim(store, context, invocation_id=invocation_id)
        except WorkflowCapabilityError as error:
            return str(error)
        return "authorized"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(claim_once, ("tool-call-a", "tool-call-b")))

    assert results.count("authorized") == 1
    assert len([result for result in results if result != "authorized"]) == 1


def test_public_constructor_and_uninitialized_object_cannot_invent_proof() -> None:
    with pytest.raises(TypeError, match="atomic Guard claim"):
        _ = GitHubWorkflowAuthorization(
            authority_token=object(),
            operation=_operation(),
            proof=cast(PositiveProof, object()),
            receipt_sha256=_digest("forged"),
        )
    forged = object.__new__(GitHubWorkflowAuthorization)

    evaluation = evaluate_command(
        _COMMAND,
        compatibility_action_class=GITHUB_MAINTENANCE_ACTION_CLASS,
        workflow_authorization=forged,
    )

    assert evaluation.decision_plane.action == "review"
    assert evaluation.decision_plane.disposition is FinalDisposition.REVIEW


def test_binding_and_receipt_do_not_expose_raw_remote_identity(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    context = _context()
    _issue(store, context)
    authorization = _claim(store, context)
    assert "THREAD_1" not in repr(authorization)
    assert "example/repo" not in repr(authorization)
