"""Exact lifecycle authorization for a reviewed Codex publication inverse.

This module grants no journal retirement or native completion. Forward
authorization stays in process memory and never renews the caller's deadline.
"""

from __future__ import annotations

import math
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .approval_gate import ApprovalGateError, ApprovalGateGrant, validate_grant
from .cli.commands_lifecycle_gate import LifecycleGateRequirement, lifecycle_authority_home
from .codex_hook_file_integrity import hook_validation_deadline
from .codex_install_transaction import CodexInstallOwner, require_codex_install_owner
from .codex_publication_inverse_plan import PUBLICATION_INVERSE_ACTION, PreparedCodexPublicationInverse
from .runtime_transition import TransitionError, inverse_recovery_budget

_claims: dict[str, tuple[str, str, int, float, float]] = {}
_claims_guard = threading.RLock()
_MAX_CLAIMS = 128


def _after_fork_child() -> None:
    global _claims, _claims_guard
    _claims = {}
    _claims_guard = threading.RLock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_child)


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
        if time.monotonic() >= self.deadline_monotonic:
            raise TransitionError("deadline_exceeded")
        owner = _owner(self.plan)
        if owner.operation_id != self.owner_operation_id or owner.pid != self.owner_pid:
            raise TransitionError("publication_inverse_owner_mismatch")
        expected = lifecycle_authority_home(
            self.plan.guard_home,
            requirement=LifecycleGateRequirement(PUBLICATION_INVERSE_ACTION, self.approved_subject),
        ).resolve(strict=False)
        if expected != self.authority_home:
            raise TransitionError("approval_authority_mismatch")
        with _claims_guard:
            claim = _claims.get(self.grant.grant_id)
        if (
            self.plan.subject() != self.approved_subject
            or claim is None
            or claim[:4]
            != (
                self.approved_subject,
                self.owner_operation_id,
                self.owner_pid,
                self.deadline_monotonic,
            )
        ):
            raise TransitionError("publication_inverse_authorization_invalid")
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
    if (
        isinstance(deadline_monotonic, bool)
        or not isinstance(deadline_monotonic, (int, float))
        or not math.isfinite(deadline_monotonic)
        or time.monotonic() >= deadline_monotonic
    ):
        raise TransitionError("deadline_exceeded")
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
    now = time.monotonic()
    expires_at = datetime.fromisoformat(grant.expires_at.replace("Z", "+00:00")).timestamp()
    retirement = now + max(0.0, expires_at - time.time())
    deadline = min(deadline_monotonic, now + 60.0, retirement)
    # Claim before file comparison: restoring old bytes cannot replay a proof
    # whose first attempted use observed a different generation.
    with _claims_guard:
        for identifier, claim in tuple(_claims.items()):
            if claim[4] <= now:
                del _claims[identifier]
        if grant.grant_id in _claims:
            raise TransitionError("publication_inverse_authorization_claimed")
        if len(_claims) >= _MAX_CLAIMS:
            raise TransitionError("publication_inverse_authorization_capacity")
        _claims[grant.grant_id] = (subject, owner.operation_id, owner.pid, deadline, retirement)
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
