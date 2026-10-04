"""One Core owner for complete binding, selection and runtime transitions.

CLI drivers provide bounded process lifecycle and active-hook observations;
the durable protocol owns all planned file and managed-install publication.
"""

from __future__ import annotations

import math
import time
from collections.abc import Generator, Mapping
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Protocol

from .adapters.codex_lifecycle_lock import codex_publication_locks
from .approval_gate import ApprovalGateGrant
from .codex_install_transaction import codex_install_transaction
from .runtime_transition import (
    RuntimeTransition,
    TransitionError,
    TransitionPlan,
    TransitionStatus,
    inverse_recovery_budget,
)
from .runtime_transition_admission import NativeProtectionAdmission


class TransitionRuntimeDriver(Protocol):
    def stop(self, artifact: Mapping[str, object], *, deadline_monotonic: float) -> None: ...
    def start(self, artifact: Mapping[str, object], *, deadline_monotonic: float) -> None: ...
    def observe_protection(
        self,
        artifact: Mapping[str, object],
        operation_id: str,
        *,
        deadline_monotonic: float,
    ) -> NativeProtectionAdmission: ...


class RuntimeTransitionCoordinator:
    runtime: RuntimeTransition
    driver: TransitionRuntimeDriver

    def __init__(self, runtime: RuntimeTransition, driver: TransitionRuntimeDriver):
        self.runtime = runtime
        self.driver = driver

    @staticmethod
    def _check_deadline(deadline: float) -> None:
        if time.monotonic() >= deadline:
            raise TransitionError("deadline_exceeded")

    @contextmanager
    def _publication_owner(self, plan: TransitionPlan, deadline: float) -> Generator[None, None, None]:
        with ExitStack() as stack:
            try:
                stack.enter_context(
                    codex_publication_locks(
                        (change.path for change in plan.files),
                        deadline=deadline,
                    )
                )
            except RuntimeError as error:
                if str(error).startswith("codex_lifecycle_busy:"):
                    raise TransitionError("configuration_target_busy") from error
                if str(error).startswith("codex_lifecycle_lock_invalid:"):
                    raise TransitionError("configuration_target_unavailable") from error
                raise
            # Caller exceptions retain their original cause, including I/O.
            yield

    def recover(self, operation_id: str, *, deadline_monotonic: float) -> TransitionStatus:
        """A new bounded inverse attempt, never a replay of forward authority.

        Retire the exact candidate before restoring or launching its predecessor.
        A caller supplies one deadline for lock admission, restoration and proof.
        """
        deadline = deadline_monotonic
        if (
            isinstance(deadline, bool)
            or not isinstance(deadline, (int, float))
            or not math.isfinite(deadline)
            or deadline - time.monotonic() > 60
        ):
            raise TransitionError("deadline_invalid")
        self._check_deadline(deadline)
        with (
            codex_install_transaction(
                self.runtime.home, self.runtime.path, actor="runtime-transition-recovery", deadline=deadline
            ),
            inverse_recovery_budget(deadline),
        ):
            self._check_deadline(deadline)
            plan = self.runtime.recovery_plan(operation_id)
            with self._publication_owner(plan, deadline):
                return self._recover_owned(plan, deadline)

    def _recover_owned(self, plan: TransitionPlan, deadline: float) -> TransitionStatus:
        operation_id = plan.operation_id
        status = self.runtime.status(operation_id)
        if status.phase in {"Committed", "FailedWithVerifiedRollback"}:
            raise TransitionError("terminal_transition")
        if set(plan.native_runtimes or {}) != {"candidate", "predecessor"}:
            raise TransitionError("native_runtime_bindings_missing")
        cause = status.first_cause or "interrupted_transition"
        self._check_deadline(deadline)
        persistence_error: Exception | None = None
        try:
            self.runtime.prepare_recovery(operation_id, first_cause=cause)
        except Exception as error:
            persistence_error = error
        inverse_attempted = False
        inverse_completed = False
        try:
            self._check_deadline(deadline)
            self.driver.stop(plan.candidate, deadline_monotonic=deadline)
            if persistence_error is not None:
                raise persistence_error
            self._check_deadline(deadline)
            inverse_attempted = True
            self.runtime.restore_files(operation_id, first_cause=cause)
            inverse_completed = True
            self._check_deadline(deadline)
            self.driver.start(plan.predecessor, deadline_monotonic=deadline)
            self._check_deadline(deadline)
            observation = self.driver.observe_protection(
                plan.predecessor,
                operation_id,
                deadline_monotonic=deadline,
            )
            self._check_deadline(deadline)
            self.runtime.finish_rollback(operation_id, functional_proof=observation)
        except Exception as error:
            try:
                if persistence_error is not None and persistence_error is not error:
                    self.runtime.record_recovery_failure(operation_id, first_cause=cause, error=persistence_error)
                if (
                    not inverse_attempted
                    or inverse_completed
                    or self.runtime.status(operation_id).phase != "RecoveryRequired"
                ):
                    self.runtime.record_recovery_failure(operation_id, first_cause=cause, error=error)
            except Exception as recording_error:
                if persistence_error is not None:
                    raise persistence_error from recording_error
                raise
        return self.runtime.status(operation_id)

    def activate(
        self,
        plan: TransitionPlan,
        *,
        authority_home: Path,
        grant: ApprovalGateGrant | None,
        deadline_monotonic: float | None = None,
    ) -> TransitionStatus:
        if set(plan.native_runtimes or {}) != {"candidate", "predecessor"}:
            raise TransitionError("native_runtime_bindings_missing")
        # Capture once before owner admission; waiting for the lock consumes
        # this same operation budget. Begin validates the signed exact subject.
        deadline = time.monotonic() + max(0.0, plan.deadline_epoch - time.time())
        if deadline_monotonic is not None:
            if isinstance(deadline_monotonic, bool) or not math.isfinite(deadline_monotonic):
                raise TransitionError("deadline_invalid")
            deadline = min(deadline, deadline_monotonic)
        self._check_deadline(deadline)
        with (
            self._publication_owner(plan, deadline),
            codex_install_transaction(
                self.runtime.home, self.runtime.path, actor="runtime-transition-coordinator", deadline=deadline
            ),
            inverse_recovery_budget(deadline),
        ):
            self._check_deadline(deadline)
            self.runtime.begin(plan, authority_home=authority_home, grant=grant, deadline_monotonic=deadline)
            candidate_may_be_running = False
            try:
                _ = self.runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
                self._check_deadline(deadline)
                self.runtime.authorize_runtime_step(plan.operation_id, "HooksPrepared")
                self.driver.stop(plan.predecessor, deadline_monotonic=deadline)
                self._check_deadline(deadline)
                _ = self.runtime.publish(plan.operation_id, "HooksPrepared")
                self._check_deadline(deadline)
                self.runtime.authorize_runtime_step(plan.operation_id, "Switching")
                candidate_may_be_running = True
                self.driver.start(plan.candidate, deadline_monotonic=deadline)
                self._check_deadline(deadline)
                observation = self.driver.observe_protection(
                    plan.candidate,
                    plan.operation_id,
                    deadline_monotonic=deadline,
                )
                self._check_deadline(deadline)
                _ = self.runtime.advance(plan.operation_id, "Switching", functional_proof=observation)
                _ = self.runtime.advance(plan.operation_id, "CandidateFunctional", functional_proof=observation)
            except Exception as first_error:
                cause = first_error.reason if isinstance(first_error, TransitionError) else type(first_error).__name__
                persistence_error: Exception | None = None
                try:
                    self.runtime.prepare_recovery(plan.operation_id, first_cause=cause)
                except Exception as error:
                    persistence_error = error
                retirement_error: Exception | None = None
                if candidate_may_be_running:
                    try:
                        self._check_deadline(deadline)
                        self.driver.stop(plan.candidate, deadline_monotonic=deadline)
                    except Exception as error:
                        retirement_error = error
                inverse_attempted = False
                inverse_completed = False
                try:
                    if persistence_error is not None:
                        raise persistence_error
                    if retirement_error is not None:
                        # Keep selection and bindings coherent for a candidate
                        # whose process retirement is still unconfirmed.
                        raise retirement_error
                    self._check_deadline(deadline)
                    inverse_attempted = True
                    self.runtime.restore_files(plan.operation_id, first_cause=cause)
                    inverse_completed = True
                    self._check_deadline(deadline)
                    self.driver.start(plan.predecessor, deadline_monotonic=deadline)
                    observation = self.driver.observe_protection(
                        plan.predecessor,
                        plan.operation_id,
                        deadline_monotonic=deadline,
                    )
                    self._check_deadline(deadline)
                    self.runtime.finish_rollback(plan.operation_id, functional_proof=observation)
                except Exception as recovery_error:
                    try:
                        if retirement_error is not None and retirement_error is not recovery_error:
                            self.runtime.record_recovery_failure(
                                plan.operation_id,
                                first_cause=cause,
                                error=retirement_error,
                            )
                        if persistence_error is not None and persistence_error is not recovery_error:
                            self.runtime.record_recovery_failure(
                                plan.operation_id,
                                first_cause=cause,
                                error=persistence_error,
                            )
                        # The inverse writer already records its own failures.
                        # Lifecycle failures need their own durable observation.
                        if (
                            not inverse_attempted
                            or inverse_completed
                            or self.runtime.status(plan.operation_id).phase != "RecoveryRequired"
                        ):
                            self.runtime.record_recovery_failure(
                                plan.operation_id, first_cause=cause, error=recovery_error
                            )
                    except Exception as recording_error:
                        if persistence_error is not None:
                            raise persistence_error from recording_error
                        raise
            return self.runtime.status(plan.operation_id)
