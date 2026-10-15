from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.native_command_model import _canonical_command_from_native
from codex_plugin_scanner.guard.runtime.command_evaluation import CompositeCommandEvaluation, evaluate_command
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition, PositiveProof
from codex_plugin_scanner.guard.runtime.github_capability_interaction import GITHUB_MAINTENANCE_ACTION_CLASS
from codex_plugin_scanner.guard.runtime.github_workflow_authorization import (
    GitHubWorkflowAuthorization,
    claim_github_workflow_authorization,
    issue_github_workflow_capability_binding,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_workflow_capability_common import WORKFLOW_CAPABILITY_STORE_CLOCK
from codex_plugin_scanner.guard.workflow_capabilities import (
    WorkflowCapabilityBinding,
    WorkflowCapabilityError,
    format_utc_timestamp,
)
from tests.github_workflow_test_support import THREAD_COMMAND, binding, digest
from tests.native_command_test_support import real_native_review_fixture

_KEY = b"w" * 32
_KEY_ID = "guard-policy-integrity-key:github-workflow-test"
_ISSUED = datetime(2026, 7, 20, 12, tzinfo=timezone.utc)
_COMMAND = THREAD_COMMAND
_THREAD_BINDING = {
    "operation": "resolve-review-thread",
    "resource_type": "github-review-thread",
    "resource": "THREAD_1",
}


def _evaluate_native(
    command: str,
    *,
    compatibility_action_class: str,
    workflow_authorization: GitHubWorkflowAuthorization,
    compatibility_reason: str | None = None,
    controls: tuple[tuple[str, str, str], ...] = (),
    managed_controls: tuple[tuple[str, str, str], ...] = (),
) -> CompositeCommandEvaluation:
    fixture = real_native_review_fixture(command, controls=controls, managed_controls=managed_controls)
    canonical = _canonical_command_from_native(command, fixture.payload["command_model"])
    assert canonical is not None
    return evaluate_command(
        command,
        canonical_command=canonical,
        native_extension_evidence=fixture.payload,
        extension_control_snapshot=fixture.snapshot,
        compatibility_action_class=compatibility_action_class,
        compatibility_reason=compatibility_reason,
        workflow_authorization=workflow_authorization,
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


_PR_READY_BINDING = {"operation": "mark-pr-draft", "resource_type": "github-pr", "resource": "17"}


def _binding(**changes: object) -> WorkflowCapabilityBinding:
    return binding(**{**_THREAD_BINDING, **changes})


def _issue(store: GuardStore, bound: WorkflowCapabilityBinding, *, max_uses: int = 1) -> None:
    _ = issue_github_workflow_capability_binding(
        store,
        bound,
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
    bound: WorkflowCapabilityBinding,
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
        bound,
        parse_shell_command(command).security_identity,
        invocation_id=invocation_id,
        subject_id=subject_id,
        task_id=task_id,
        issuer_id=issuer_id,
        approval_provenance_id=approval_provenance_id,
    )


def test_atomic_claim_authorizes_a_review_thread_resolution_native_attributes_exactly(tmp_path: Path) -> None:
    # Native now attributes the static resolution to its GitHub maintenance
    # owner without uncertainty, so the exact claim can discharge its review.
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    bound = _binding()
    _issue(store, bound)
    authorization = _claim(store, bound)
    command = parse_shell_command(_COMMAND)
    assert authorization.evidence(command_identity=command.security_identity) is not None

    evaluation = _evaluate_native(
        _COMMAND,
        compatibility_action_class=GITHUB_MAINTENANCE_ACTION_CLASS,
        compatibility_reason="Exact GitHub maintenance requires review without task proof.",
        workflow_authorization=authorization,
    )

    assert not evaluation.extension_observations[0].uncertainty_reasons
    assert evaluation.decision_plane.action == "allow"
    assert evaluation.decision_plane.disposition is FinalDisposition.WORKFLOW_AUTHORIZED


def test_bounded_pr_metadata_claim_produces_workflow_authorized_decision(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    command = "gh pr ready 17 --undo --repo example/repo"
    bound = _binding(**_PR_READY_BINDING)
    _issue(store, bound)
    authorization = _claim(store, bound, command=command)

    evaluation = _evaluate_native(
        command,
        compatibility_action_class=GITHUB_MAINTENANCE_ACTION_CLASS,
        workflow_authorization=authorization,
    )

    assert evaluation.decision_plane.action == "allow"
    assert evaluation.decision_plane.disposition is FinalDisposition.WORKFLOW_AUTHORIZED
    assert evaluation.minimum_action == "allow"


def test_workflow_proof_cannot_discharge_managed_extension_disable(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    command = "gh pr ready 17 --undo --repo example/repo"
    bound = _binding(**_PR_READY_BINDING)
    _issue(store, bound)
    authorization = _claim(store, bound, command=command)

    evaluation = _evaluate_native(
        command,
        compatibility_action_class=GITHUB_MAINTENANCE_ACTION_CLASS,
        workflow_authorization=authorization,
        managed_controls=(("extension", "command.github", "disabled"),),
    )

    assert evaluation.control_resolution.blocked
    assert evaluation.decision_plane.action == "block"
    assert evaluation.minimum_action == "block"


@pytest.mark.parametrize(
    "field",
    ("repository_sha256", "workspace_sha256", "executable_sha256", "launch_sha256", "resource_sha256"),
)
def test_every_binding_digest_drift_fails_without_consuming_capability(tmp_path: Path, field: str) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    bound = _binding()
    _issue(store, bound)

    with pytest.raises(WorkflowCapabilityError, match="capability_context_mismatch"):
        _ = _claim(store, _binding(**{field: digest(f"drift-{field}")}))

    assert _claim(store, bound) is not None


def test_invocation_replay_and_operation_drift_fail_closed(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    bound = _binding()
    _issue(store, bound, max_uses=2)
    authorization = _claim(store, bound)
    with pytest.raises(WorkflowCapabilityError, match="capability_invocation_replayed"):
        _ = _claim(store, bound)

    drifted = _evaluate_native(
        "gh issue lock 17 --repo example/repo",
        compatibility_action_class=GITHUB_MAINTENANCE_ACTION_CLASS,
        workflow_authorization=authorization,
    )
    assert drifted.decision_plane.action == "review"


def test_expired_and_revoked_capabilities_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    expired_store = GuardStore(tmp_path / "expired", prime_policy_integrity=False)
    bound = _binding()
    _issue(expired_store, bound)
    monkeypatch.setattr(
        WORKFLOW_CAPABILITY_STORE_CLOCK,
        "now",
        lambda: format_utc_timestamp(_ISSUED + timedelta(minutes=11)),
    )
    with pytest.raises(WorkflowCapabilityError, match="capability_expired"):
        _ = _claim(expired_store, bound)

    monkeypatch.setattr(WORKFLOW_CAPABILITY_STORE_CLOCK, "now", lambda: format_utc_timestamp(_ISSUED))
    revoked_store = GuardStore(tmp_path / "revoked", prime_policy_integrity=False)
    _issue(revoked_store, bound)
    assert revoked_store.revoke_workflow_capability("wc-github-thread-1", reason_code="operator.revoked")
    with pytest.raises(WorkflowCapabilityError, match="capability_revoked"):
        _ = _claim(revoked_store, bound)


def test_resource_drift_fails_without_consuming_capability(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    bound = _binding()
    _issue(store, bound)

    with pytest.raises(WorkflowCapabilityError, match="capability_context_mismatch"):
        _ = _claim(store, _binding(resource="THREAD_2"))

    assert _claim(store, bound) is not None


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
    bound = _binding()
    _issue(store, bound)

    with pytest.raises(WorkflowCapabilityError, match="capability_"):
        _ = _claim(store, bound, **{field: value})

    assert _claim(store, bound) is not None


def test_only_one_concurrent_claim_can_consume_last_use(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    bound = _binding()
    _issue(store, bound)
    start = threading.Barrier(2)

    def claim_once(invocation_id: str) -> str:
        _ = start.wait(timeout=5)
        try:
            _ = _claim(store, bound, invocation_id=invocation_id)
        except WorkflowCapabilityError as error:
            return str(error)
        return "authorized"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(claim_once, ("tool-call-a", "tool-call-b")))

    assert results.count("authorized") == 1
    assert len([result for result in results if result != "authorized"]) == 1


def test_public_constructor_and_uninitialized_object_cannot_invent_proof_or_relax_native_uncertainty() -> None:
    with pytest.raises(TypeError, match="atomic Guard claim"):
        _ = GitHubWorkflowAuthorization(
            authority_token=object(),
            command_identity=parse_shell_command(_COMMAND).security_identity,
            proof=cast(PositiveProof, object()),
            receipt_sha256=digest("forged"),
        )
    forged = object.__new__(GitHubWorkflowAuthorization)

    evaluation = _evaluate_native(
        _COMMAND,
        compatibility_action_class=GITHUB_MAINTENANCE_ACTION_CLASS,
        workflow_authorization=forged,
    )

    assert evaluation.decision_plane.action == "review"
    assert evaluation.decision_plane.disposition is FinalDisposition.REVIEW


def test_binding_and_receipt_do_not_expose_raw_remote_identity(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    bound = _binding()
    _issue(store, bound)
    authorization = _claim(store, bound)
    assert "THREAD_1" not in repr(authorization)
    assert "example/repo" not in repr(authorization)
