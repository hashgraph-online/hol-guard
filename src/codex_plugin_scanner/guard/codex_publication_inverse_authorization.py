"""Exact lifecycle authorization for a reviewed Codex publication inverse.

This module grants no journal retirement or native completion. Forward
authorization claims live in the resident (one use per grant) and never renew the
caller's deadline.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .approval_gate import ApprovalGateError, ApprovalGateGrant, validate_grant
from .cli.commands_lifecycle_gate import LifecycleGateRequirement, lifecycle_authority_home
from .codex_hook_file_integrity import hook_validation_deadline
from .codex_publication_inverse_plan import PUBLICATION_INVERSE_ACTION, PreparedCodexPublicationInverse
from .native_context import _resolve_existing_digest_home, native_context_digest
from .native_owned import CodexInstallOwner, require_codex_install_owner
from .native_transition_files import authorize_plan, require_deadline
from .runtime_transition import TransitionError, inverse_recovery_budget


def _claim_call(
    action: str,
    plan: PreparedCodexPublicationInverse,
    *,
    grant_id: str,
    subject: str,
    owner: tuple[str, int],
    deadline: float,
    retirement_seconds: float = 0.0,
) -> None:
    """Ask the resident, which holds every claim, to spend or confirm one.

    A claim has to outlive the step that made it, so the registry is resident
    state. Without a resident that answers, no authorization can be claimed or
    confirmed: the proof fails closed.
    """

    result = native_context_digest(
        "publication_inverse_claim",
        {
            "action": action,
            "grant_id": grant_id,
            "subject": subject,
            "operation_id": owner[0],
            "owner_pid": owner[1],
            "deadline": repr(float(deadline)),
            "retirement_seconds": retirement_seconds,
        },
        guard_home=_resolve_existing_digest_home(plan.guard_home),
    )
    outcome = result.get("publication_inverse_claim") if isinstance(result, dict) else None
    if outcome is None:
        raise TransitionError("publication_inverse_authorization_unavailable")
    if outcome != "ok":
        raise TransitionError(str(outcome))


def _owner(plan: PreparedCodexPublicationInverse) -> CodexInstallOwner:
    owner = require_codex_install_owner(plan.guard_home)
    if owner.actor != PUBLICATION_INVERSE_ACTION:
        raise TransitionError("publication_inverse_owner_mismatch")
    if plan.native_runtime is None or plan.verification_workspace is None:
        raise TransitionError("publication_inverse_native_binding_missing")
    return owner


@dataclass(frozen=True, slots=True, repr=False)
class CodexPublicationInverseAuthorization:
    plan: PreparedCodexPublicationInverse
    authority_home: Path
    grant: ApprovalGateGrant
    owner_operation_id: str
    owner_pid: int
    deadline_monotonic: float
    approved_subject: str

    def check(self) -> None:
        require_deadline(self.deadline_monotonic)
        owner = _owner(self.plan)
        if owner.operation_id != self.owner_operation_id or owner.pid != self.owner_pid:
            raise TransitionError("publication_inverse_owner_mismatch")
        expected = lifecycle_authority_home(
            self.plan.guard_home,
            requirement=LifecycleGateRequirement(PUBLICATION_INVERSE_ACTION, self.approved_subject),
        ).resolve(strict=False)
        if expected != self.authority_home:
            raise TransitionError("approval_authority_mismatch")
        if self.plan.subject() != self.approved_subject:
            raise TransitionError("publication_inverse_authorization_invalid")
        _claim_call(
            "check",
            self.plan,
            grant_id=self.grant.grant_id,
            subject=self.approved_subject,
            owner=(self.owner_operation_id, self.owner_pid),
            deadline=self.deadline_monotonic,
        )
        validate_grant(
            expected,
            self.grant,
            purpose="protection_lifecycle",
            strict=True,
            action=PUBLICATION_INVERSE_ACTION,
            scope="local-protection",
            subject=self.approved_subject,
            session_nonce=self.owner_operation_id,
        )

    def compare_before(self) -> None:
        self.check()
        with inverse_recovery_budget(self.deadline_monotonic), hook_validation_deadline(self.deadline_monotonic):
            self.plan.compare_before()
        self.check()


def authorize_codex_publication_inverse(
    plan: PreparedCodexPublicationInverse,
    *,
    authority_home: Path,
    grant: ApprovalGateGrant | None,
    deadline_monotonic: float,
) -> CodexPublicationInverseAuthorization:
    require_deadline(deadline_monotonic)
    owner = _owner(plan)
    subject = plan.subject()
    expected = lifecycle_authority_home(
        plan.guard_home,
        requirement=LifecycleGateRequirement(PUBLICATION_INVERSE_ACTION, subject),
    ).resolve(strict=False)
    if authority_home.resolve(strict=False) != expected:
        raise TransitionError("approval_authority_mismatch")
    if grant is None:
        raise ApprovalGateError("approval_gate_required", "Exact local approval is required for publication inverse.")
    validate_grant(
        expected,
        grant,
        purpose="protection_lifecycle",
        strict=True,
        action=PUBLICATION_INVERSE_ACTION,
        scope="local-protection",
        subject=subject,
        session_nonce=owner.operation_id,
    )
    timing = authorize_plan("inverse", grant.expires_at, deadline_monotonic)
    deadline = cast(float, timing["deadline"])
    # Claim before file comparison: restoring old bytes cannot replay a proof
    # whose first attempted use observed a different generation.
    _claim_call(
        "claim",
        plan,
        grant_id=grant.grant_id,
        subject=subject,
        owner=(owner.operation_id, owner.pid),
        deadline=deadline,
        retirement_seconds=cast(float, timing["retirement_seconds"]),
    )
    authorization = CodexPublicationInverseAuthorization(
        plan,
        expected,
        grant,
        owner.operation_id,
        owner.pid,
        deadline,
        subject,
    )
    authorization.compare_before()
    return authorization
