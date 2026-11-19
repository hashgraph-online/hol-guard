"""One Core owner for complete binding, selection and runtime transitions.

CLI drivers provide bounded process lifecycle and active-hook observations;
the durable protocol owns all planned file and managed-install publication.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Generator, Mapping
from contextlib import ExitStack, contextmanager
from itertools import count
from pathlib import Path
from typing import Protocol, cast

from .approval_gate import ApprovalGateGrant
from .native_owned import codex_install_transaction, codex_publication_locks
from .native_transition_files import coordinate, prepare_request, require_deadline
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
        require_deadline(deadline)

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
        prepare_request("recovery", deadline=deadline, now=time.monotonic())
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
        prepare_request("bindings", native=dict(plan.native_runtimes or {}))
        cause = status.first_cause or "interrupted_transition"
        self._check_deadline(deadline)
        return self._run("recover", plan, deadline, cause=cause)

    def _run(self, flow: str, plan: TransitionPlan, deadline: float, *, cause: str = "") -> TransitionStatus:
        """Run the runtime's step protocol: it names each effect in order, this process performs it."""
        errors: dict[int, BaseException] = {}
        numbers = count(1)
        state: object = None
        outcome: dict[str, object] | None = None
        observation: NativeProtectionAdmission | None = None

        def caught(identifier: object) -> BaseException:
            known = errors.get(cast(int, identifier))
            if known is None:
                known = errors[cast(int, identifier)] = TransitionError("deadline_exceeded")
            return known

        while True:
            answer = coordinate(flow, deadline=deadline, state=state, outcome=outcome, cause=cause)
            state, action = answer.get("state"), cast(Mapping[str, object], answer["action"])
            if action["do"] == "done":
                return self.runtime.status(plan.operation_id)
            if action["do"] == "raise":
                error, chained = caught(action["error"]), action.get("cause")
                if chained is None:
                    raise error
                raise error from caught(chained)
            try:
                result = self._perform(action, plan, deadline, observation, caught)
            except Exception as error:
                identifier = next(numbers)
                errors[identifier] = error
                outcome = {
                    "ok": False,
                    "id": identifier,
                    "cause": error.reason if isinstance(error, TransitionError) else type(error).__name__,
                }
                continue
            outcome = {"ok": True}
            if action["do"] == "drive" and action["op"] == "observe":
                observation = cast(NativeProtectionAdmission, result)
            elif action["do"] == "call" and action["method"] == "phase":
                outcome["phase"] = result

    def _perform(
        self,
        action: Mapping[str, object],
        plan: TransitionPlan,
        deadline: float,
        observation: NativeProtectionAdmission | None,
        caught: Callable[[object], BaseException],
    ) -> object:
        """One effect the runtime named: a lifecycle step of the driver or a method of the journal."""
        operation_id = plan.operation_id
        if action["do"] == "drive":
            artifact = plan.candidate if action["side"] == "candidate" else plan.predecessor
            if action["op"] == "stop":
                return self.driver.stop(artifact, deadline_monotonic=deadline)
            if action["op"] == "start":
                return self.driver.start(artifact, deadline_monotonic=deadline)
            return self.driver.observe_protection(artifact, operation_id, deadline_monotonic=deadline)
        method, phase, cause = str(action["method"]), str(action.get("phase", "")), str(action.get("cause", ""))
        runtime = self.runtime
        if method == "publish":
            return runtime.publish(operation_id, phase)
        if method == "authorize":
            return runtime.authorize_runtime_step(operation_id, phase)
        if method == "advance":
            return runtime.advance(operation_id, phase, functional_proof=observation)
        if method == "prepare_recovery":
            return runtime.prepare_recovery(operation_id, first_cause=cause)
        if method == "restore_files":
            return runtime.restore_files(operation_id, first_cause=cause)
        if method == "finish_rollback":
            return runtime.finish_rollback(operation_id, functional_proof=observation)
        if method == "record_failure":
            error = cast(Exception, caught(action["error"]))
            return runtime.record_recovery_failure(operation_id, first_cause=cause, error=error)
        if method == "phase":
            return runtime.status(operation_id).phase
        raise TransitionError("record_invalid")

    def activate(
        self,
        plan: TransitionPlan,
        *,
        authority_home: Path,
        grant: ApprovalGateGrant | None,
        deadline_monotonic: float | None = None,
    ) -> TransitionStatus:
        prepare_request("bindings", native=dict(plan.native_runtimes or {}))
        # Capture once before owner admission; waiting for the lock consumes
        # this same operation budget. Begin validates the signed exact subject.
        deadline = cast(
            float,
            prepare_request(
                "activation",
                deadline_epoch=plan.deadline_epoch,
                wall=time.time(),
                now=time.monotonic(),
                deadline=deadline_monotonic,
            ).get("deadline"),
        )
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
            return self._run("activate", plan, deadline)
