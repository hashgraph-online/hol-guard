"""Exact, owner-bound authorization for missing Codex authority repair.

Publication is provisional and retains a durable inverse. This module cannot
commit protection without native proof. No approval factor or forward grant is
persisted.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, cast

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
from .native_owned import CodexInstallOwner, record_codex_mutation, require_codex_install_owner
from .native_runtime import NativeRuntimeIdentity
from .native_transition_files import artifact_generation, authorize_plan, require_deadline
from .native_transition_files import publication as publication_record
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

    require_deadline(deadline_monotonic)
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
    require_deadline(deadline_monotonic)
    return prepared


class CodexHookRepairError(TransitionError):
    def __init__(self, first_error: Exception, rollback_error: Exception):
        super().__init__("authority_repair_inverse_failed")
        self.first_error = first_error
        self.rollback_error = rollback_error


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
        require_deadline(self.deadline_monotonic)
        if publication is not None and publication.authorization is not self:
            raise TransitionError("authority_repair_authorization_invalid")
        owner = _owner_and_pending(self.plan, publication)
        expected_home = lifecycle_authority_home(
            self.plan.guard_home,
            requirement=LifecycleGateRequirement(CODEX_AUTHORITY_REPAIR_ACTION, self.approved_subject),
        ).resolve(strict=False)
        # The runtime judges the owner, then the authority home, then the claim:
        # it must be this grant's, for this subject (still the one the plan
        # derives), owner and deadline, and for the one publication named here.
        publication_record(
            "repair_claim_check",
            self.plan.guard_home,
            grant_id=self.grant.grant_id,
            subject=self.approved_subject,
            current_subject=self.plan.subject(),
            owner_operation_id=self.owner_operation_id,
            owner_pid=self.owner_pid,
            current_owner_operation_id=owner.operation_id,
            current_owner_pid=owner.pid,
            authority_home=str(self.authority_home),
            current_authority_home=str(expected_home),
            deadline=self.deadline_monotonic,
            publication=None if publication is None else publication.publication_monotonic,
        )
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
    require_deadline(deadline_monotonic)
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
    timing = authorize_plan("repair", grant.expires_at, deadline_monotonic)
    deadline = cast(float, timing["deadline"])
    # Claim before checking files: a failed generation comparison must not
    # become a forward replay with the same proof after an inverse or edit.
    publication_record(
        "repair_claim",
        plan.guard_home,
        grant_id=grant.grant_id,
        subject=subject,
        owner_operation_id=owner.operation_id,
        owner_pid=owner.pid,
        deadline=deadline,
        retirement=timing["retirement"],
        now=time.monotonic(),
    )
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
    generation = artifact_generation(
        "repair",
        plan.subject(),
        bound=plan.native_runtime is not None and plan.verification_workspace is not None,
    )
    native_runtime, workspace = plan.native_runtime, plan.verification_workspace
    if native_runtime is None or workspace is None:
        raise TransitionError("authority_repair_native_binding_missing")
    started = time.monotonic()
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
                expected_runtime=native_runtime,
                guard_home=plan.guard_home,
                config_path=plan.config_path,
                workspace=workspace,
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
        receipt = load_hook_authority_receipt(
            plan.guard_home, plan.config_path, require_manifest=(plan.manifest_change.after, "generation_changed")
        )
    authorization.compare_before()
    publication_time = time.monotonic()
    publication_record(
        "repair_publish", plan.guard_home, grant_id=authorization.grant.grant_id, publication=publication_time
    )
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
