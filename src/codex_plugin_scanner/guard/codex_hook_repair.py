"""Exact, owner-bound authorization for missing Codex authority repair.

Publication is provisional and retains a durable inverse. This module cannot
commit protection without native proof. No approval factor or forward grant is
persisted.
"""

from __future__ import annotations

import math
import os
import threading
import time
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from .approval_gate import ApprovalGateGrant, validate_grant
from .cli.commands_lifecycle_gate import LifecycleGateRequirement, lifecycle_authority_home
from .codex_hook_file_integrity import hook_validation_deadline
from .codex_hook_integrity import atomic_write_bytes
from .codex_hook_manifest import CODEX_AUTHORITY_REPAIR_ACTION, PreparedCodexHookRepair
from .codex_hook_recovery import (
    _commit_verified_hook_repair_publication,
    assert_owned_hook_repair_publication,
    hook_publication_pending,
    load_hook_authority_receipt,
    prepare_hook_publication,
    recover_hook_publication,
)
from .codex_install_transaction import CodexInstallOwner, record_codex_mutation, require_codex_install_owner
from .native_runtime import NativeRuntimeIdentity
from .runtime_transition import (
    RuntimeTransition,
    TransitionError,
    assert_transition_mutation_allowed,
    inverse_recovery_budget,
    merge_transition_dependency,
)

if TYPE_CHECKING:
    from .runtime_transition_admission import NativeProtectionAdmission
    from .store import GuardStore

_claims: dict[str, tuple[str, str, int, float, float]] = {}
_publications: dict[str, float] = {}
_claims_guard = threading.RLock()
_MAX_CLAIMS = 128
_FORWARD_CAP_SECONDS = 60.0


def prepare_codex_hook_repair_verification(
    plan: PreparedCodexHookRepair,
    *,
    expected_runtime: NativeRuntimeIdentity,
    workspace: Path,
    deadline_monotonic: float,
) -> PreparedCodexHookRepair:
    """Pin a native comparison identity before exact approval; never launch it.

    The caller derives this comparison identity from its validated Core
    inspection. A path alone conveys no runtime selection or native proof.
    The configured-hook observer must subsequently prove the actual digest.
    """
    from .runtime_transition_prepare import _pin_executable

    if (
        isinstance(deadline_monotonic, bool)
        or not math.isfinite(deadline_monotonic)
        or time.monotonic() >= deadline_monotonic
    ):
        raise TransitionError("deadline_exceeded")
    if plan.native_runtime is not None or plan.verification_workspace is not None:
        raise TransitionError("authority_repair_native_binding_already_prepared")
    plan.payload()
    native = {
        "path": str(expected_runtime.path),
        "size": expected_runtime.size,
        "mtime_ns": expected_runtime.mtime_ns,
        "sha256": expected_runtime.sha256,
    }
    with inverse_recovery_budget(deadline_monotonic), hook_validation_deadline(deadline_monotonic):
        RuntimeTransition._compare(plan.payload(), "before")
        dependency = _pin_executable(expected_runtime.path, deadline=deadline_monotonic, expected=native)
        files = {item.path: item for item in plan.files}
        previous = files.get(dependency.path)
        files[dependency.path] = (
            merge_transition_dependency(previous, dependency) if previous is not None else dependency
        )
        prepared = replace(
            plan, files=tuple(files.values()), native_runtime=expected_runtime, verification_workspace=workspace
        )
        RuntimeTransition._compare(prepared.payload(), "before")
    if time.monotonic() >= deadline_monotonic:
        raise TransitionError("deadline_exceeded")
    return prepared


class CodexHookRepairError(TransitionError):
    def __init__(self, first_error: Exception, rollback_error: Exception):
        super().__init__("authority_repair_inverse_failed")
        self.first_error = first_error
        self.rollback_error = rollback_error


def _after_fork_child() -> None:
    global _claims, _claims_guard, _publications
    _claims = {}
    _publications = {}
    _claims_guard = threading.RLock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_child)


def _owner_and_pending(
    plan: PreparedCodexHookRepair,
    publication: PendingCodexHookRepair | None = None,
) -> CodexInstallOwner:
    owner = require_codex_install_owner(plan.guard_home)
    if owner.actor != CODEX_AUTHORITY_REPAIR_ACTION:
        raise TransitionError("authority_repair_owner_mismatch")
    assert_transition_mutation_allowed(plan.guard_home)
    if publication is not None:
        assert_owned_hook_repair_publication(
            plan.guard_home,
            plan.config_path,
            repair_plan=plan.payload(),
            config_bytes=publication.config_bytes,
            manifest_bytes=publication.manifest_bytes,
            receipt_bytes=publication.receipt_bytes,
            publication_monotonic=publication.publication_monotonic,
        )
    elif hook_publication_pending(plan.guard_home):
        raise TransitionError("authority_repair_publication_pending")
    return owner


@dataclass(frozen=True, slots=True, repr=False)
class CodexHookRepairAuthorization:
    plan: PreparedCodexHookRepair
    authority_home: Path
    grant: ApprovalGateGrant
    owner_operation_id: str
    owner_pid: int
    deadline_monotonic: float
    approved_subject: str

    def check(self) -> None:
        self._check()

    def _check(self, publication: PendingCodexHookRepair | None = None) -> None:
        if time.monotonic() >= self.deadline_monotonic:
            raise TransitionError("deadline_exceeded")
        if publication is not None and publication.authorization is not self:
            raise TransitionError("authority_repair_authorization_invalid")
        owner = _owner_and_pending(self.plan, publication)
        if owner.operation_id != self.owner_operation_id or owner.pid != self.owner_pid:
            raise TransitionError("authority_repair_owner_mismatch")
        expected_home = lifecycle_authority_home(
            self.plan.guard_home,
            requirement=LifecycleGateRequirement(CODEX_AUTHORITY_REPAIR_ACTION, self.approved_subject),
        ).resolve(strict=False)
        if expected_home != self.authority_home:
            raise TransitionError("approval_authority_mismatch")
        with _claims_guard:
            claim = _claims.get(self.grant.grant_id)
            publication_time = _publications.get(self.grant.grant_id)
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
            raise TransitionError("authority_repair_authorization_invalid")
        if publication is not None and publication_time != publication.publication_monotonic:
            raise TransitionError("authority_repair_authorization_invalid")
        validate_grant(
            self.authority_home,
            self.grant,
            purpose="protection_lifecycle",
            strict=True,
            action=CODEX_AUTHORITY_REPAIR_ACTION,
            scope="local-protection",
            subject=self.approved_subject,
            session_nonce=self.owner_operation_id,
        )

    def compare_before(self) -> None:
        self.check()
        with inverse_recovery_budget(self.deadline_monotonic), hook_validation_deadline(self.deadline_monotonic):
            RuntimeTransition._compare(self.plan.payload(), "before")
        self.check()


def authorize_codex_hook_repair(
    plan: PreparedCodexHookRepair,
    *,
    authority_home: Path,
    grant: ApprovalGateGrant | None,
    deadline_monotonic: float,
) -> CodexHookRepairAuthorization:
    if (
        isinstance(deadline_monotonic, bool)
        or not math.isfinite(deadline_monotonic)
        or time.monotonic() >= deadline_monotonic
    ):
        raise TransitionError("deadline_exceeded")
    owner = _owner_and_pending(plan)
    subject = plan.subject()
    expected_home = lifecycle_authority_home(
        plan.guard_home,
        requirement=LifecycleGateRequirement(CODEX_AUTHORITY_REPAIR_ACTION, subject),
    ).resolve(strict=False)
    if authority_home.resolve(strict=False) != expected_home:
        raise TransitionError("approval_authority_mismatch")
    validate_grant(
        expected_home,
        grant,
        purpose="protection_lifecycle",
        strict=True,
        action=CODEX_AUTHORITY_REPAIR_ACTION,
        scope="local-protection",
        subject=subject,
        session_nonce=owner.operation_id,
    )
    assert grant is not None
    now = time.monotonic()
    expires_epoch = datetime.fromisoformat(grant.expires_at.replace("Z", "+00:00")).timestamp()
    claim_retirement = now + max(0.0, expires_epoch - time.time())
    deadline = min(deadline_monotonic, now + _FORWARD_CAP_SECONDS, claim_retirement)
    # Claim before checking files: a failed generation comparison must not
    # become a forward replay with the same proof after an inverse or edit.
    with _claims_guard:
        for identifier, claim in tuple(_claims.items()):
            if claim[4] <= now:
                del _claims[identifier]
                _publications.pop(identifier, None)
        if grant.grant_id in _claims:
            raise TransitionError("authority_repair_authorization_claimed")
        if len(_claims) >= _MAX_CLAIMS:
            raise TransitionError("authority_repair_capacity")
        _claims[grant.grant_id] = (subject, owner.operation_id, owner.pid, deadline, claim_retirement)
    authorization = CodexHookRepairAuthorization(
        plan, expected_home, grant, owner.operation_id, owner.pid, deadline, subject
    )
    authorization.compare_before()
    return authorization


@dataclass(frozen=True, slots=True, repr=False)
class PendingCodexHookRepair:
    authorization: CodexHookRepairAuthorization
    config_bytes: bytes
    manifest_bytes: bytes
    receipt_bytes: bytes
    publication_monotonic: float

    def compare(self, generation: str) -> None:
        if generation not in ("before", "after"):
            raise TransitionError("generation_invalid")
        authorization = self.authorization
        authorization._check(self)
        with (
            inverse_recovery_budget(authorization.deadline_monotonic),
            hook_validation_deadline(
                authorization.deadline_monotonic,
            ),
        ):
            RuntimeTransition._compare(authorization.plan.payload(), generation)
        authorization._check(self)


def verify_and_commit_codex_hook_repair(
    pending: PendingCodexHookRepair,
    *,
    receipt_store: GuardStore | None = None,
) -> NativeProtectionAdmission:
    """Run the configured hook; commit only fresh sealed native protection."""
    from .runtime_transition_codex_observer import observe_configured_codex_hook

    pending.compare("after")
    authorization, plan = pending.authorization, pending.authorization.plan
    if plan.native_runtime is None or plan.verification_workspace is None:
        raise TransitionError("authority_repair_native_binding_missing")
    started = time.monotonic()
    generation = "codex-authority-repair-" + plan.subject().rsplit(":", 1)[1]
    try:
        with (
            inverse_recovery_budget(authorization.deadline_monotonic),
            hook_validation_deadline(
                authorization.deadline_monotonic,
            ),
        ):
            proof = observe_configured_codex_hook(
                operation_id=plan.operation_id,
                artifact_generation=generation,
                expected_runtime=plan.native_runtime,
                guard_home=plan.guard_home,
                config_path=plan.config_path,
                workspace=plan.verification_workspace,
                deadline_monotonic=authorization.deadline_monotonic,
                receipt_store=receipt_store,
            )
            _commit_verified_hook_repair_publication(pending, proof=proof, started_monotonic=started)
    except Exception as first_error:
        _inverse_failed_publication(authorization, first_error)
        raise
    return proof


def _inverse_failed_publication(authorization: CodexHookRepairAuthorization, first_error: Exception) -> None:
    try:
        with (
            inverse_recovery_budget(authorization.deadline_monotonic),
            hook_validation_deadline(
                authorization.deadline_monotonic,
            ),
        ):
            recover_hook_publication(authorization.plan.guard_home)
    except Exception as rollback_error:
        raise CodexHookRepairError(first_error, rollback_error) from first_error


def publish_codex_hook_repair(authorization: CodexHookRepairAuthorization) -> PendingCodexHookRepair:
    """Publish once under the approved owner; retain inverse until native proof."""
    authorization.compare_before()
    plan = authorization.plan
    with hook_validation_deadline(authorization.deadline_monotonic):
        receipt = load_hook_authority_receipt(plan.guard_home, plan.config_path)
    if receipt.manifest_bytes != plan.manifest_change.after:
        raise TransitionError("generation_changed")
    authorization.compare_before()
    with _claims_guard:
        if authorization.grant.grant_id in _publications:
            raise TransitionError("authority_repair_publication_claimed")
        publication_time = time.monotonic()
        _publications[authorization.grant.grant_id] = publication_time
    with (
        inverse_recovery_budget(authorization.deadline_monotonic),
        hook_validation_deadline(
            authorization.deadline_monotonic,
        ),
    ):
        prepare_hook_publication(
            plan.guard_home,
            plan.config_path,
            before_config=receipt.config_bytes,
            after_config=receipt.config_bytes,
            before_manifest=None,
            after_manifest=receipt.manifest_bytes,
            key_created=False,
            before_receipt=receipt.receipt_bytes,
            after_receipt=receipt.receipt_bytes,
            repair_plan=plan.payload(),
            repair_publication_monotonic=publication_time,
        )
    pending = PendingCodexHookRepair(
        authorization, receipt.config_bytes, receipt.manifest_bytes, receipt.receipt_bytes, publication_time
    )
    try:
        pending.compare("before")
        atomic_write_bytes(plan.manifest_change.path, receipt.manifest_bytes, mode=0o600, private=True)
        record_codex_mutation("repair_manifest_provisional", plan.manifest_change.path, None, receipt.manifest_bytes)
        pending.compare("after")
    except Exception as first_error:
        _inverse_failed_publication(authorization, first_error)
        raise
    return pending
